#!/usr/bin/env node
// SBOMHub MCP server (stdio, read-only).
//
// WHAT THE CONFIGURED API KEY CAN REACH (M50 W2/W3)
// -------------------------------------------------
// An API key minted at POST /api/v1/projects/:id/apikeys is PROJECT-SCOPED and
// the server enforces that. A key minted at POST /api/v1/apikeys is
// tenant-level and reaches everything below. The difference is visible to the
// model only through these tool descriptions, so they state it — an LLM that
// believes "list projects" returned the whole tenant when it returned one
// project will draw wrong conclusions and report them as fact.
//
// With a project-scoped key:
//   - sbomhub_list_projects returns exactly that one project.
//   - sbomhub_get_dashboard / sbomhub_search_cve / sbomhub_search_component /
//     sbomhub_diff are REFUSED with 403. They are tenant-wide by construction:
//     narrowing them would silently redefine what their fields mean (a
//     per-project count reported as a tenant posture, or "this CVE is not
//     present" when it is present in a project the key cannot see), so the
//     server refuses instead of answering narrowly. The refusal surfaces here
//     as an isError result.
//   - The per-project tools answer for the key's own project and 404 for any
//     other.
//
// Built on the current @modelcontextprotocol/sdk high-level API:
// McpServer.registerTool with zod raw-shape input schemas. The SDK validates
// tool arguments against the schema before the callback runs and answers
// invalid calls with a protocol-level InvalidParams error, so every callback
// below receives typed, already-validated args. Tool *execution* failures
// (API errors, missing SBOMs, ...) are returned in-band as
// `isError: true` results per the MCP tool contract.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { ApiClient } from "./client/api.js";

const apiUrl = process.env.SBOMHUB_API_URL || "http://localhost:8080";
const apiKey = process.env.SBOMHUB_API_KEY || "";

if (!apiKey) {
  console.error("SBOMHUB_API_KEY is required");
  process.exit(1);
}

const client = new ApiClient(apiUrl, apiKey);

const server = new McpServer({
  name: "sbomhub-mcp",
  version: "0.1.0",
});

function jsonResult(value: unknown): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
  };
}

function errorResult(err: unknown): CallToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return {
    content: [{ type: "text", text: `Error: ${message}` }],
    isError: true,
  };
}

const projectIdSchema = z.string().uuid().describe("プロジェクトID (UUID)");

server.registerTool(
  "sbomhub_list_projects",
  {
    description:
      "この資格情報が参照できるプロジェクトの一覧を取得。" +
      "テナント単位のAPIキーではテナントの全プロジェクト、" +
      "プロジェクトスコープのAPIキーではそのプロジェクト1件のみが返る。" +
      "件数からテナントの規模を推測しないこと",
  },
  async () => {
    try {
      return jsonResult(await client.listProjects());
    } catch (err) {
      return errorResult(err);
    }
  }
);

// Tenant summary and per-project dashboard are separate tools on purpose:
// a single tool with an all-optional raw-shape schema would reject calls
// that omit `params.arguments` entirely (spec-legal; SDK 1.29 validates
// `undefined` against the object schema → InvalidParams), and non-raw-shape
// wrappers (preprocess/default) fall back to an empty inputSchema in
// tools/list, hiding project_id from clients.
server.registerTool(
  "sbomhub_get_dashboard",
  {
    description:
      "テナント全体のダッシュボードサマリーを取得。" +
      "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは" +
      "403で拒否される (絞り込むと集計値の意味が変わるため、" +
      "サーバーは狭い答えを返さず拒否する)",
  },
  async () => {
    try {
      return jsonResult(await client.getDashboardSummary());
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_get_project_dashboard",
  {
    description:
      "プロジェクト別ダッシュボードを取得 (脆弱性サマリー/コンプライアンス/SBOM状況)",
    inputSchema: {
      project_id: projectIdSchema,
    },
  },
  async ({ project_id }) => {
    try {
      return jsonResult(await client.getProjectDashboard(project_id));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_list_sboms",
  {
    description: "プロジェクトのSBOM一覧を取得 (新しい順)",
    inputSchema: {
      project_id: projectIdSchema,
    },
  },
  async ({ project_id }) => {
    try {
      return jsonResult(await client.listSboms(project_id));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_search_cve",
  {
    description:
      "CVE IDでテナントの全プロジェクトを横断検索。" +
      "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは" +
      "403で拒否される。「見つからない」と「見る権限が無い」を" +
      "区別できなくなるため、絞り込みではなく拒否する",
    inputSchema: {
      cve_id: z
        .string()
        // Flag-free pattern: the SDK's JSON-schema conversion drops regex
        // flags, so an /i regex would be ADVERTISED as case-sensitive in
        // tools/list even though the server accepts both. Spell out the
        // accepted prefixes instead so schema and behavior agree.
        .regex(/^(?:CVE|cve)-\d{4}-\d{4,}$/, "CVE-YYYY-NNNN 形式で指定してください")
        .describe("CVE ID (例: CVE-2021-44228)"),
    },
  },
  async ({ cve_id }) => {
    try {
      return jsonResult(await client.searchCVE(cve_id));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_search_component",
  {
    description:
      "コンポーネント名でテナントの全プロジェクトを横断検索。" +
      "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは" +
      "403で拒否される (理由は sbomhub_search_cve と同じ)",
    inputSchema: {
      name: z.string().min(1).describe("コンポーネント名 (例: log4j)"),
      version: z.string().optional().describe("バージョン (任意)"),
    },
  },
  async ({ name, version }) => {
    try {
      return jsonResult(await client.searchComponent(name, version));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_diff",
  {
    description:
      "2つのSBOMを比較して差分を取得。バージョン省略時は最新2つを比較。" +
      "テナント単位のAPIキーが必要 — プロジェクトスコープのAPIキーでは" +
      "自分のプロジェクトのSBOMであっても403で拒否される " +
      "(対象SBOMをbodyのUUIDで選ぶため、どのプロジェクトのものかが" +
      "判明するのが両行の読み込み後になる)",
    inputSchema: {
      project_id: projectIdSchema,
      base_version: z.string().optional().describe("比較元SBOMのバージョン (省略時: 2番目に新しいSBOM)"),
      target_version: z.string().optional().describe("比較先SBOMのバージョン (省略時: 最新SBOM)"),
    },
  },
  async ({ project_id, base_version, target_version }) => {
    try {
      return jsonResult(await client.diff(project_id, base_version, target_version));
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_get_vulnerabilities",
  {
    description:
      "プロジェクトの脆弱性一覧を取得 (CVSS/EPSS順、最大500件、severityで絞り込み可)",
    inputSchema: {
      project_id: projectIdSchema,
      severity: z
        .string()
        // Flag-free pattern (see cve_id note): both canonical spellings are
        // listed explicitly so the advertised tools/list schema matches the
        // actually-accepted inputs. Backend severity values are uppercase.
        .regex(
          /^(?:critical|high|medium|low|CRITICAL|HIGH|MEDIUM|LOW)$/,
          "critical / high / medium / low のいずれかを指定してください"
        )
        .optional()
        .describe(
          "severity で絞り込み (任意): critical / high / medium / low (小文字または大文字)"
        ),
      sort: z
        .enum(["cvss", "epss"])
        .optional()
        .describe("並び順 (デフォルト: cvss)"),
    },
  },
  async ({ project_id, severity, sort }) => {
    try {
      return jsonResult(
        await client.getVulnerabilities(project_id, severity, sort ?? "cvss")
      );
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_get_compliance",
  {
    description: "コンプライアンススコアを取得 (経産省ガイドライン準拠チェック)",
    inputSchema: {
      project_id: projectIdSchema,
    },
  },
  async ({ project_id }) => {
    try {
      return jsonResult(await client.getCompliance(project_id));
    } catch (err) {
      return errorResult(err);
    }
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`sbomhub-mcp: connected (API: ${apiUrl})`);
