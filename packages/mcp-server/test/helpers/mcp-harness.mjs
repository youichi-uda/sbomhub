// Drives the BUILT server (dist/index.js) as a real MCP client over stdio.
//
// Why the built artifact and not the TypeScript source: dist/index.js is what
// Claude Desktop / Cursor actually launch (package.json `bin`), and what the
// tool descriptions are read from. Testing an in-process re-implementation of
// the registration would test a copy of the thing under test.
//
// Why a real MCP client and not a hand-rolled JSON-RPC harness: `tools/list`
// through the SDK returns the tool set EXACTLY as an LLM receives it —
// descriptions, and zod compiled down to the advertised JSON Schema. That
// makes "what the model is told" an observable, which is the whole point of
// these tests. It also means the enumeration in tool-inventory.test.mjs is the
// server's own answer rather than a grep over the source.
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export const PACKAGE_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const SERVER_ENTRY = fileURLToPath(
  new URL("../../dist/index.js", import.meta.url)
);
export const SERVER_SOURCE = fileURLToPath(
  new URL("../../src/index.ts", import.meta.url)
);

// Not a real credential; the stub API accepts anything. Assertions check that
// this exact value is what leaves the process in X-API-Key.
export const API_KEY = "sbh_test_key_not_a_real_credential";

export async function startMcpServer({ apiUrl, apiKey = API_KEY, env = {} } = {}) {
  if (!existsSync(SERVER_ENTRY)) {
    throw new Error(
      `${SERVER_ENTRY} is missing — run \`pnpm --filter @sbomhub/mcp-server build\` first ` +
        "(the test script builds it; this message is for a direct `node --test` run)"
    );
  }

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [SERVER_ENTRY],
    // StdioClientTransport passes only what is given here plus a small default
    // set, so the child cannot pick up a developer's real SBOMHUB_* values.
    env: { SBOMHUB_API_URL: apiUrl, SBOMHUB_API_KEY: apiKey, ...env },
    stderr: "pipe",
  });

  const client = new Client({
    name: "sbomhub-mcp-contract-tests",
    version: "0.0.0",
  });
  await client.connect(transport);
  // The server prints a one-line banner to stderr on connect. Drain it so the
  // pipe cannot fill, and keep it out of the test reporter.
  transport.stderr?.resume();

  return {
    client,
    async listTools() {
      const { tools } = await client.listTools();
      return tools;
    },
    async callTool(name, args = {}) {
      return client.callTool({ name, arguments: args });
    },
    async close() {
      await client.close();
    },
  };
}

export function textOf(result) {
  return (result.content ?? [])
    .filter((c) => c.type === "text")
    .map((c) => c.text)
    .join("\n");
}

export function jsonOf(result) {
  return JSON.parse(textOf(result));
}
