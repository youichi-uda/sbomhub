// Pins the tool INPUT contract across the zod 3 → 4 migration
// (GHSA-mrhx-c7xc-m3w5, zod >= 4.6.6).
//
// Two halves, both observed through a real MCP client against dist/index.js:
//
//   1. What clients are TOLD — the tools/list answer. fixtures/tools-list.zod3.json
//      is the byte-for-byte tools/list output captured from the server while it
//      still ran on zod 3.25.76 (the SDK's vendored zod-to-json-schema path).
//      Under zod 4 the SDK switches to zod's own toJSONSchema, whose defaults
//      differ (input-mode objects drop `additionalProperties: false`, uuid()
//      gains a `pattern`). The advertised schema is the contract MCP clients
//      generate calls from, so it is compared EXACTLY (deepStrictEqual: every
//      key and value; JSON object key ORDER is not part of the comparison —
//      under zod 4 `$schema` is emitted before `additionalProperties` instead of
//      after it, which RFC 8259 objects do not distinguish). Any other
//      difference has to be a deliberate edit of the fixture, not drift.
//
//   2. What the server DOES with arguments — accept/reject per argument, and
//      which request (if any) reaches the API. Written green against zod 3
//      first. Notably pins that zod 3's uuid() accepted ANY 8-4-4-4-12 hex id
//      (zod 4's uuid() enforces RFC 9562 version/variant bits) and that unknown
//      keys were stripped, not refused.
//
// Error TEXT for rejected arguments is not pinned beyond the schema's own
// custom messages: the SDK renders zod's default messages, which zod 4
// reworded ("Expected string, received number" → "Invalid input: expected
// string, received number"). That text is prose for the model, not a
// machine contract; the JSON-RPC shape (isError + "-32602 Input validation
// error") is what is pinned.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, test } from "node:test";

import { K, PROJECT_ID, SBOMS } from "./helpers/contract-table.mjs";
import { startMcpServer, textOf } from "./helpers/mcp-harness.mjs";
import { startStubApi } from "./helpers/stub-api.mjs";

const GOLDEN = JSON.parse(
  readFileSync(new URL("./fixtures/tools-list.zod3.json", import.meta.url), "utf8")
);

// Valid under every uuid reading (RFC 4122 v4, variant 10).
const RFC_UUID = PROJECT_ID;
// Accepted by zod 3's uuid() (any hex in 8-4-4-4-12), rejected by zod 4's
// strict z.uuid(): version nibble 1, variant nibble 1. Postgres' uuid type
// stores it happily, so it is a real id shape, not a theoretical one.
const NON_RFC_GUID = "12345678-1234-1234-1234-123456789012";
const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const UPPER_UUID = RFC_UUID.toUpperCase();

let stub;
let mcp;
let tools;

before(async () => {
  stub = await startStubApi();
  mcp = await startMcpServer({ apiUrl: stub.url });
  tools = await mcp.listTools();
}, { timeout: 60_000 });

after(async () => {
  await mcp?.close();
  await stub?.close();
});

describe("tools/list is unchanged from the zod 3 build", () => {
  test("same tool names, in the same order", () => {
    assert.deepEqual(
      tools.map((t) => t.name),
      GOLDEN.map((t) => t.name)
    );
  });

  for (const golden of GOLDEN) {
    test(`${golden.name}: inputSchema identical`, () => {
      const live = tools.find((t) => t.name === golden.name);
      assert.ok(live, `${golden.name} missing from tools/list`);
      assert.deepEqual(live.inputSchema, golden.inputSchema);
    });
  }

  test("whole tools/list answer identical (descriptions, annotations, output schemas)", () => {
    assert.deepEqual(JSON.parse(JSON.stringify(tools)), GOLDEN);
  });
});

/** Calls a tool and classifies the outcome without caring what the API said. */
async function call(tool, args) {
  stub.reset();
  stub.use(() => ({ status: 200, body: [] }));
  const result = await mcp.callTool(tool, args);
  await stub.quiet();
  const text = textOf(result);
  const rejected = result.isError === true && /-32602|Input validation error/.test(text);
  return { rejected, text, requests: stub.requests.map((r) => `${r.method} ${r.path}`) };
}

async function assertAccepted(tool, args) {
  const r = await call(tool, args);
  assert.equal(r.rejected, false, `${tool} rejected ${JSON.stringify(args)}: ${r.text}`);
  assert.ok(r.requests.length > 0, `${tool} accepted ${JSON.stringify(args)} but sent nothing`);
  return r;
}

async function assertRejected(tool, args, mustMention) {
  const r = await call(tool, args);
  assert.equal(r.rejected, true, `${tool} accepted ${JSON.stringify(args)}: ${r.text}`);
  assert.deepEqual(r.requests, [], `${tool} reached the API with ${JSON.stringify(args)}`);
  if (mustMention) {
    assert.ok(r.text.includes(mustMention), `expected "${mustMention}" in: ${r.text}`);
  }
}

describe("argument validation is unchanged from the zod 3 build", () => {
  test("project_id: any 8-4-4-4-12 hex id is accepted (zod 3 uuid())", async () => {
    for (const id of [RFC_UUID, UPPER_UUID, NON_RFC_GUID, NIL_UUID]) {
      const r = await assertAccepted("sbomhub_list_sboms", { project_id: id });
      assert.deepEqual(r.requests, [`GET /api/v1/mcp/projects/${id}/sboms`]);
    }
  });

  test("project_id: non-uuid shapes are rejected", async () => {
    for (const project_id of [
      "not-a-uuid",
      "",
      `{${RFC_UUID}}`,
      RFC_UUID.replaceAll("-", ""),
      `${RFC_UUID} `,
      "3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b9g",
      5,
      null,
    ]) {
      await assertRejected("sbomhub_get_compliance", { project_id });
    }
    await assertRejected("sbomhub_get_compliance", {});
  });

  test("unknown argument keys are stripped, not refused", async () => {
    const r = await assertAccepted("sbomhub_get_compliance", {
      project_id: RFC_UUID,
      bogus: "x",
    });
    assert.deepEqual(r.requests, [`GET /api/v1/mcp/projects/${RFC_UUID}/compliance`]);
  });

  test("tools without arguments accept omitted and empty arguments", async () => {
    await assertAccepted("sbomhub_list_projects", undefined);
    await assertAccepted("sbomhub_list_projects", {});
    await assertAccepted("sbomhub_get_dashboard", undefined);
  });

  test("cve_id: flag-free CVE pattern with its custom message", async () => {
    for (const cve_id of ["CVE-2021-44228", "cve-2021-44228", "CVE-1999-0001", "CVE-2024-1234567"]) {
      await assertAccepted("sbomhub_search_cve", { cve_id });
    }
    for (const cve_id of ["Cve-2021-44228", "CVE-2021-123", "CVE-21-44228", "CVE-2021-44228x", " CVE-2021-44228", ""]) {
      await assertRejected("sbomhub_search_cve", { cve_id }, "CVE-YYYY-NNNN 形式で指定してください");
    }
    await assertRejected("sbomhub_search_cve", {});
  });

  test("search_component: name required non-empty, version optional non-empty", async () => {
    await assertAccepted("sbomhub_search_component", { name: "log4j" });
    await assertAccepted("sbomhub_search_component", { name: "log4j", version: "2.14.1" });
    await assertRejected("sbomhub_search_component", { name: "" });
    await assertRejected("sbomhub_search_component", { name: "log4j", version: "" });
    await assertRejected("sbomhub_search_component", { version: "1" });
    await assertRejected("sbomhub_search_component", { name: "log4j", version: null });
  });

  test("get_vulnerabilities: severity pattern + sort enum", async () => {
    for (const severity of ["critical", "high", "medium", "low", "CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
      await assertAccepted("sbomhub_get_vulnerabilities", { project_id: RFC_UUID, severity });
    }
    for (const severity of ["Critical", "", "info", "critical "]) {
      await assertRejected(
        "sbomhub_get_vulnerabilities",
        { project_id: RFC_UUID, severity },
        "critical / high / medium / low のいずれかを指定してください"
      );
    }
    for (const sort of ["cvss", "epss"]) {
      await assertAccepted("sbomhub_get_vulnerabilities", { project_id: RFC_UUID, sort });
    }
    for (const sort of ["EPSS", "epss-desc", "", null]) {
      await assertRejected("sbomhub_get_vulnerabilities", { project_id: RFC_UUID, sort });
    }
  });

  test("diff: sbom id selectors take any hex id; version selectors must be non-empty", async () => {
    await assertAccepted("sbomhub_diff", {
      project_id: RFC_UUID,
      base_sbom_id: NON_RFC_GUID,
      target_sbom_id: NIL_UUID,
    });
    await assertRejected("sbomhub_diff", { project_id: RFC_UUID, base_sbom_id: "x" });
    await assertRejected("sbomhub_diff", { project_id: RFC_UUID, target_sbom_id: "" });
    await assertRejected("sbomhub_diff", { project_id: RFC_UUID, base_version: "" });
    await assertRejected("sbomhub_diff", { project_id: RFC_UUID, target_version: "" });
  });
});

describe("response parsing (client/api.ts) is unchanged from the zod 3 build", () => {
  test("an SBOM id that is not RFC-variant still parses, and unknown fields pass through", async () => {
    stub.reset();
    const rows = [
      { ...SBOMS[0], id: NON_RFC_GUID, format: "cyclonedx", extra: { nested: true } },
      { ...SBOMS[1], id: NIL_UUID },
    ];
    stub.routes({ [K.sboms]: { status: 200, body: rows } });
    const result = await mcp.callTool("sbomhub_list_sboms", { project_id: RFC_UUID });
    await stub.quiet();
    assert.notEqual(result.isError, true, textOf(result));
    assert.deepEqual(JSON.parse(textOf(result)), rows);
  });

  test("a non-uuid SBOM id is still refused", async () => {
    stub.reset();
    stub.routes({ [K.sboms]: { status: 200, body: [{ ...SBOMS[0], id: "sbom-1" }] } });
    const result = await mcp.callTool("sbomhub_list_sboms", { project_id: RFC_UUID });
    await stub.quiet();
    assert.equal(result.isError, true, textOf(result));
  });

  test("a JSON null list is read as empty", async () => {
    stub.reset();
    stub.routes({ [K.sboms]: { status: 200, body: null } });
    const result = await mcp.callTool("sbomhub_list_sboms", { project_id: RFC_UUID });
    await stub.quiet();
    assert.notEqual(result.isError, true, textOf(result));
    assert.deepEqual(JSON.parse(textOf(result)), []);
  });
});
