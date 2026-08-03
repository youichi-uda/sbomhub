// What the model is told when the call does NOT work.
//
// The dangerous outcome for a compliance product is not an error — it is an
// answer that is byte-shaped like a good one. A tool that swallowed a 403 and
// returned `[]` would let an LLM report "no vulnerabilities" for a project it
// was never allowed to read. So every failure path below is asserted to
//
//   (a) come back with isError: true, and
//   (b) NOT be parseable as JSON — the model cannot mistake it for data, and
//   (c) name the HTTP status, so "refused" and "absent" stay distinguishable.
//
// (c) is the same principle project_scope.go states for choosing 403 over 404:
// reporting "not found" for something you merely cannot see is a false claim.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { CONTRACT_CASES, K, P, PROJECT_ID, SBOMS } from "./helpers/contract-table.mjs";
import { jsonOf, startMcpServer, textOf } from "./helpers/mcp-harness.mjs";
import { startStubApi } from "./helpers/stub-api.mjs";

let stub;
let mcp;

before(async () => {
  stub = await startStubApi();
  mcp = await startMcpServer({ apiUrl: stub.url });
});

after(async () => {
  await mcp?.close();
  await stub?.close();
});

// One representative invocation per tool, reused for every failure mode.
const INVOCATIONS = [];
for (const c of CONTRACT_CASES) {
  if (!INVOCATIONS.some((i) => i.tool === c.tool)) {
    INVOCATIONS.push({ tool: c.tool, args: c.args });
  }
}

function assertLoudFailure(result, { status } = {}) {
  const text = textOf(result);
  assert.equal(result.isError, true, `expected isError, got: ${text}`);
  assert.throws(
    () => JSON.parse(text),
    `the failure came back as parseable JSON, which a model can read as data: ${text}`
  );
  if (status !== undefined) {
    assert.match(
      text,
      new RegExp(`\\b${status}\\b`),
      `the failure does not name HTTP ${status}: ${text}`
    );
  }
}

for (const status of [401, 403, 404, 500]) {
  for (const { tool, args } of INVOCATIONS) {
    test(`${tool} surfaces HTTP ${status} as a loud in-band error`, async () => {
      stub.reset();
      stub.use(() => ({ status, body: { error: "denied" } }));

      const result = await mcp.callTool(tool, args);
      assertLoudFailure(result, { status });
      assert.equal(
        stub.requests.length > 0,
        true,
        "the tool did not call the API at all"
      );
    });
  }
}

test("a failure part-way through a fan-out fails the whole tool, not silently", async () => {
  // sbomhub_get_project_dashboard reads three routes concurrently. If the
  // compliance leg is refused, a partial answer would present a dashboard with
  // a missing section as if the project had none.
  stub.reset();
  stub.routes({
    [K.vulns]: { status: 200, body: [], headers: { "X-Total-Count": "0" } },
    [K.sboms]: { status: 200, body: SBOMS },
    [K.compliance]: { status: 403, body: { error: "forbidden" } },
  });

  const result = await mcp.callTool("sbomhub_get_project_dashboard", {
    project_id: PROJECT_ID,
  });
  assertLoudFailure(result, { status: 403 });
});

test("sbomhub_diff refuses to invent a comparison when there are fewer than two SBOMs", async () => {
  stub.reset();
  stub.routes({
    [K.sboms]: { status: 200, body: [SBOMS[0]] },
    [K.diff]: { status: 200, body: { added: [] } },
  });

  const result = await mcp.callTool("sbomhub_diff", { project_id: PROJECT_ID });
  assert.equal(result.isError, true);
  assert.match(textOf(result), /Not enough SBOMs to diff/);
  // And it must not have asked the API to diff anything.
  assert.deepEqual(
    stub.requests.map((r) => r.path),
    [P.sboms]
  );
});

test("sbomhub_diff reports an unknown version instead of falling back to another SBOM", async () => {
  stub.reset();
  stub.routes({
    [K.sboms]: { status: 200, body: SBOMS },
    [K.diff]: { status: 200, body: { added: [] } },
  });

  const result = await mcp.callTool("sbomhub_diff", {
    project_id: PROJECT_ID,
    base_version: "0.0.1-does-not-exist",
  });
  assert.equal(result.isError, true);
  assert.match(textOf(result), /SBOM version not found/);
  assert.deepEqual(
    stub.requests.map((r) => r.path),
    [P.sboms]
  );
});

test("a 200 whose body is not the documented shape is an error, not an empty result", async () => {
  // A proxy or a misrouted request can answer 200 with something else. The
  // response schemas in client/api.ts exist so that becomes a refusal rather
  // than "this project has no SBOMs".
  stub.reset();
  stub.routes({ [K.sboms]: { status: 200, body: { error: "forbidden" } } });

  const result = await mcp.callTool("sbomhub_list_sboms", {
    project_id: PROJECT_ID,
  });
  assert.equal(result.isError, true);
  assert.throws(() => JSON.parse(textOf(result)));
});

test("a 200 with malformed JSON is an error", async () => {
  stub.reset();
  stub.routes({ [K.compliance]: { status: 200, raw: "not json at all" } });

  const result = await mcp.callTool("sbomhub_get_compliance", {
    project_id: PROJECT_ID,
  });
  assert.equal(result.isError, true);
});

test("the API key is never followed to a redirect target", async () => {
  // client/api.ts sets redirect: "error" because Node's fetch forwards custom
  // headers (X-API-Key) across a cross-origin redirect while stripping
  // Authorization. A redirecting or open-redirect-abused endpoint would
  // otherwise exfiltrate the credential.
  const attacker = await startStubApi();
  try {
    attacker.use(() => ({ status: 200, body: { pwned: true } }));
    stub.reset();
    stub.use(() => ({
      status: 302,
      headers: { Location: `${attacker.url}/api/v1/mcp/projects` },
      body: {},
    }));

    const result = await mcp.callTool("sbomhub_list_projects", {});
    assert.equal(result.isError, true, textOf(result));
    assert.deepEqual(
      attacker.requests,
      [],
      "the client followed a redirect and handed the API key to another origin"
    );
  } finally {
    await attacker.close();
  }
});

test("arguments that violate the advertised schema are rejected before any API call", async () => {
  // The header comment in src/index.ts states that the SDK validates arguments
  // against the schema before the callback runs. If it did not, a bad project
  // id would reach the API as a path segment.
  stub.reset();
  stub.use(() => ({ status: 200, body: [] }));

  for (const [tool, args] of [
    ["sbomhub_get_compliance", { project_id: "not-a-uuid" }],
    ["sbomhub_search_cve", { cve_id: "log4shell" }],
    ["sbomhub_get_vulnerabilities", { project_id: PROJECT_ID, severity: "Critical" }],
    ["sbomhub_get_vulnerabilities", { project_id: PROJECT_ID, sort: "epss-desc" }],
    ["sbomhub_search_component", { name: "" }],
    ["sbomhub_list_sboms", {}],
  ]) {
    const result = await mcp.callTool(tool, args);
    assert.equal(result.isError, true, `${tool} accepted ${JSON.stringify(args)}`);
    assert.deepEqual(
      stub.requests,
      [],
      `${tool} sent a request for invalid arguments ${JSON.stringify(args)}`
    );
  }
});

test("an empty project list is reported as empty data, not as an error", async () => {
  // The mirror image of the checks above: a legitimately empty answer must NOT
  // be dressed up as a failure either.
  stub.reset();
  stub.routes({ [K.projects]: { status: 200, body: [] } });

  const result = await mcp.callTool("sbomhub_list_projects", {});
  assert.notEqual(result.isError, true, textOf(result));
  assert.deepEqual(jsonOf(result), []);
});
