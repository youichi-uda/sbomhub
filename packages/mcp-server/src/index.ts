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
//   - sbomhub_list_projects returns exactly that one project — or nothing,
//     when that project is not visible under the request's own tenant.
//   - sbomhub_get_dashboard / sbomhub_search_cve / sbomhub_search_component /
//     sbomhub_diff are REFUSED with 403. They are tenant-wide by construction:
//     narrowing them would silently redefine what their fields mean (a
//     per-project count reported as a tenant posture, or "this CVE is not
//     present" when it is present in a project the key cannot see), so the
//     server refuses instead of answering narrowly. The refusal surfaces here
//     as an isError result.
//   - The per-project tools answer for the key's own project and 403 for any
//     other.
//
// Every refusal above is the same 403, from the same place: every project-scope
// violation goes through middleware.RespondProjectScopeDenied. It is not the
// not-found status, deliberately — project_scope.go's "Response: 403, not the
// M47 W1 404 sentinel" section argues that reporting a project as absent when
// it is merely unseen makes a mis-scoped CI job indistinguishable from a
// deleted project, which in a compliance product means silently missing
// evidence. test/tool-inventory.test.mjs re-reads that status out of the Go
// source and fails if the block above quotes a different one, because this
// paragraph is a claim about someone else's code.
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
import { SCOPE_NOTE } from "./scope-notes.js";

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

// What every counts-reporting tool says about the asynchronous scan behind its
// numbers.
//
// The backend starts the NVD/JVN scan in a goroutine after an SBOM upload, so a
// project whose scan is still running answers `0 vulnerabilities` in exactly the
// shape a scanned-and-clean project does. This server now READS that state
// (`GET /api/v1/projects/:id/sboms/:sbom_id/scan-status`, per SBOM) instead of
// only warning that it cannot — but the state is only ever evidence in one
// direction, and the note has to say which:
//
//   counts_final=true   the scan for `scanned_sbom_id` reported completed.
//   counts_final=false  everything else, and the reasons are not equivalent —
//                       running (wait), failed / no_sbom / unknown /
//                       unavailable (the count is not an answer at all).
//
// Stated once and shared, for the reason SCOPE_NOTE is: a per-tool rewording is
// a per-tool opportunity to describe a payload the tool does not produce. Every
// field named here is asserted to exist in what the tools actually return
// (test/tool-contract.test.mjs).
const SCAN_STATE_NOTE =
  "件数は非同期スキャンの途中経過のことがある。" +
  "counts_final=true のときだけ確定値で、false のときは scan_state を見ること " +
  "(completed=完了、running=走査中、failed=失敗、unknown=状態不明、" +
  "changed=読み取り中にスキャンかSBOMが変わった、" +
  "unavailable=状態を取得できず。これ以外の値が返ることもあり、" +
  "その場合も確定値ではない)。" +
  "どのSBOMに対する件数かは scanned_sbom_id。" +
  "counts_final=false のときの0件や極端に少ない件数を「脆弱性なし」と断定しないこと。";

// The per-project tools all take this. The refusal a project-scoped key gets
// for someone ELSE's project is stated on the argument that causes it, because
// that is where the model can connect the status to a cause: the tool surfaces
// `API error 403: {"error":"forbidden"}` verbatim, and on its own that is
// indistinguishable from the tenant-wide tools' refusal — same status, same
// body, different reason. (An invalid or expired key is 401, not 403.)
//
// What the note must NOT say is that the project exists. project_scope.go
// answers the same 403 with the same body for a sibling project, another
// tenant's project and a UUID that was never allocated
// (TestM50W2PathParamDenialIsIndistinguishable asserts byte equality), so a
// description promising "it exists, you just cannot see it" would hand the
// model an inference the status does not support (Codex R1, Medium).
const projectIdSchema = z
  .string()
  .uuid()
  .describe(
    "プロジェクトID (UUID)。" +
      "プロジェクトスコープのAPIキーでは、そのキー自身のプロジェクト以外を" +
      "指定すると403で拒否される。この403は「このキーではそのIDを扱えない」" +
      "という意味だけで、そのプロジェクトが存在するかどうかは判断できない"
  );

server.registerTool(
  "sbomhub_list_projects",
  {
    description:
      "この資格情報が参照できるプロジェクトの一覧を取得。" +
      SCOPE_NOTE.projectListNarrowed +
      "。件数からテナントの規模を推測しないこと",
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
      SCOPE_NOTE.tenantWide +
      " (絞り込むと集計値の意味が変わるため、サーバーは狭い答えを返さず拒否する)",
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
      "プロジェクト別ダッシュボードを取得 (脆弱性サマリー/コンプライアンス/SBOM状況)。" +
      "脆弱性は最大5000件まで走査し、超える場合は " +
      "vulnerabilities.scan_truncated=true になる。そのとき by_severity と " +
      "top_by_cvss は走査した analyzed 件の集計であって、" +
      "プロジェクトの全件を数えた値ではない (全体の件数は total)。" +
      SCAN_STATE_NOTE +
      "これらは vulnerabilities の下に入る",
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
    description:
      "プロジェクトのSBOM一覧を取得 (新しい順)。" +
      "version はSBOM仕様のバージョン (CycloneDX/SPDX) であってアップロードの" +
      "版数ではないため、同じ値が並ぶのが普通。個々のSBOMを指すには id を使うこと",
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
      SCOPE_NOTE.tenantWide +
      "。「見つからない」と「見る権限が無い」を区別できなくなるため、" +
      "絞り込みではなく拒否する",
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
      SCOPE_NOTE.tenantWide +
      " (理由は sbomhub_search_cve と同じ)",
    inputSchema: {
      name: z.string().min(1).describe("コンポーネント名 (例: log4j)"),
      // min(1) for the same reason as sbomhub_diff's version selectors: an
      // empty string would pass the schema and then silently widen the search.
      version: z.string().min(1).optional().describe("バージョン (任意)"),
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
      SCOPE_NOTE.tenantWide +
      " — 自分のプロジェクトのSBOM同士であっても拒否される " +
      "(対象SBOMをbodyのUUIDで選ぶため、どのプロジェクトのものかが" +
      "判明するのが両行の読み込み後になる)",
    inputSchema: {
      project_id: projectIdSchema,
      // Ids first: they are the only selector that identifies one snapshot.
      base_sbom_id: z
        .string()
        .uuid()
        .optional()
        .describe(
          "比較元SBOMのID (sbomhub_list_sboms の id。任意。指定すると base_version より優先)"
        ),
      target_sbom_id: z
        .string()
        .uuid()
        .optional()
        .describe(
          "比較先SBOMのID (sbomhub_list_sboms の id。任意。指定すると target_version より優先)"
        ),
      base_version: z
        .string()
        // An empty string is not "omitted": without min(1) it passes the
        // advertised schema and is then falsy in the resolver, so
        // `base_version: ""` would quietly diff the newest two SBOMs and
        // present the result as the comparison the caller asked for
        // (Codex R7).
        .min(1)
        .optional()
        .describe(
          "比較元SBOMの仕様バージョン (省略時: 2番目に新しいSBOM)。" +
            "これはCycloneDX/SPDXの仕様バージョンでアップロードの版数ではないため、" +
            "同じ値のSBOMが複数あるのが普通で、その場合はエラーになる — base_sbom_id を使うこと"
        ),
      target_version: z
        .string()
        .min(1)
        .optional()
        .describe(
          "比較先SBOMの仕様バージョン (省略時: 最新SBOM)。base_version と同じ注意点"
        ),
    },
  },
  async ({
    project_id,
    base_version,
    target_version,
    base_sbom_id,
    target_sbom_id,
  }) => {
    try {
      return jsonResult(
        await client.diff(project_id, {
          baseVersion: base_version,
          targetVersion: target_version,
          baseSbomId: base_sbom_id,
          targetSbomId: target_sbom_id,
        })
      );
    } catch (err) {
      return errorResult(err);
    }
  }
);

server.registerTool(
  "sbomhub_get_vulnerabilities",
  {
    description:
      "プロジェクトの脆弱性一覧を取得 (CVSS/EPSS順、最大500件、severityで絞り込み可)。" +
      "内部の走査は最大5000件までで、それを超えるプロジェクトでは " +
      "scan_truncated=true が返る。その場合 matched と returned は" +
      "走査した範囲での件数なので、プロジェクト全体の値として報告しないこと " +
      "(全体の件数は total_in_project)。" +
      SCAN_STATE_NOTE,
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
