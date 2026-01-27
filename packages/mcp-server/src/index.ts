import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

import { ApiClient } from "./client/api.js";

const apiUrl = process.env.SBOMHUB_API_URL || "http://localhost:8080";
const apiKey = process.env.SBOMHUB_API_KEY || "";

if (!apiKey) {
  throw new Error("SBOMHUB_API_KEY is required");
}

const client = new ApiClient(apiUrl, apiKey);

const server = new Server(
  {
    name: "sbomhub-mcp",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "sbomhub_list_projects",
        description: "プロジェクト一覧を取得",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "sbomhub_get_dashboard",
        description: "ダッシュボード情報を取得",
        inputSchema: {
          type: "object",
          properties: {
            project_id: { type: "string" },
          },
        },
      },
      {
        name: "sbomhub_search_cve",
        description: "CVE IDで全プロジェクトを横断検索",
        inputSchema: {
          type: "object",
          properties: {
            cve_id: { type: "string" },
          },
          required: ["cve_id"],
        },
      },
      {
        name: "sbomhub_search_component",
        description: "コンポーネント名でプロジェクトを検索",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string" },
            version: { type: "string" },
          },
          required: ["name"],
        },
      },
      {
        name: "sbomhub_diff",
        description: "2つのSBOMを比較して差分を取得",
        inputSchema: {
          type: "object",
          properties: {
            project_id: { type: "string" },
            base_version: { type: "string" },
            target_version: { type: "string" },
          },
          required: ["project_id"],
        },
      },
      {
        name: "sbomhub_get_vulnerabilities",
        description: "脆弱性一覧を取得",
        inputSchema: {
          type: "object",
          properties: {
            project_id: { type: "string" },
            severity: { type: "string" },
            status: { type: "string" },
          },
          required: ["project_id"],
        },
      },
      {
        name: "sbomhub_get_compliance",
        description: "コンプライアンススコアを取得",
        inputSchema: {
          type: "object",
          properties: {
            project_id: { type: "string" },
          },
          required: ["project_id"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    switch (name) {
      case "sbomhub_list_projects": {
        const result = await client.listProjects();
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_get_dashboard": {
        const result = await client.getDashboard(args?.project_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_search_cve": {
        const result = await client.searchCVE(args.cve_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_search_component": {
        const result = await client.searchComponent(args.name, args.version);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_diff": {
        const result = await client.diff(args.project_id, args.base_version, args.target_version);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_get_vulnerabilities": {
        const result = await client.getVulnerabilities(args.project_id, args.severity, args.status);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "sbomhub_get_compliance": {
        const result = await client.getCompliance(args.project_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${err?.message || String(err)}`,
        },
      ],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
