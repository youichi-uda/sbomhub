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

import {
  COMPLIANCE,
  CONTRACT_CASES,
  K,
  P,
  PROJECT_ID,
  SBOMS,
  SPEC_VERSION_SBOMS,
  scanProbe,
} from "./helpers/contract-table.mjs";

import { jsonOf, startMcpServer, textOf } from "./helpers/mcp-harness.mjs";
import { startStubApi } from "./helpers/stub-api.mjs";

let stub;
let mcp;

// A generous per-hook timeout: a server that fails to come up should fail the
// run with a legible message rather than sit there until the job's own limit.
before(async () => {
  stub = await startStubApi();
  mcp = await startMcpServer({ apiUrl: stub.url });
}, { timeout: 60_000 });

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
      await stub.quiet();
      assertLoudFailure(result, { status });
      assert.equal(
        stub.requests.length > 0,
        true,
        "the tool did not call the API at all"
      );
    });
  }
}

// ---------------------------------------------------------------------------
// Failures that are NOT on the first request.
//
// The matrix above fails everything, so for a multi-request tool it only ever
// exercises the first leg: sbomhub_diff never reaches its POST, the paging walk
// never fails on page two, and two of the dashboard's three legs are never the
// one that breaks. Those are exactly the places where a partial answer could be
// assembled and returned as if it were whole (Codex R1, High).
// ---------------------------------------------------------------------------
const ok = (body, headers) => ({ status: 200, body, headers });
const page = (n, total) => {
  const rows = [];
  for (let i = 0; i < n; i += 1) {
    rows.push({ cve_id: `CVE-2026-${20000 + i}`, severity: "HIGH", cvss_score: 7 });
  }
  return ok(rows, { "X-Total-Count": String(total) });
};

const DOWNSTREAM_CASES = [
  {
    title: "sbomhub_diff: the diff POST itself is refused",
    tool: "sbomhub_diff",
    args: { project_id: PROJECT_ID },
    routes: (status) => ({
      [K.sboms]: ok(SBOMS),
      [K.diff]: { status, body: { error: "denied" } },
    }),
    expectedRequests: 2,
  },
  {
    title: "sbomhub_get_vulnerabilities: page two fails after page one succeeded",
    tool: "sbomhub_get_vulnerabilities",
    args: { project_id: PROJECT_ID },
    routes: (status) => ({
      [K.vulns]: (req) =>
        req.query.offset === "0"
          ? page(500, 1200)
          : { status, body: { error: "denied" } },
    }),
    expectedRequests: 2,
  },
  {
    title: "sbomhub_get_project_dashboard: the vulnerabilities leg fails",
    tool: "sbomhub_get_project_dashboard",
    args: { project_id: PROJECT_ID },
    routes: (status) => ({
      [K.vulns]: { status, body: { error: "denied" } },
      [K.compliance]: ok(COMPLIANCE),
      [K.sboms]: ok(SBOMS),
    }),
    expectedRequests: 3,
  },
  {
    title: "sbomhub_get_project_dashboard: the compliance leg fails",
    tool: "sbomhub_get_project_dashboard",
    args: { project_id: PROJECT_ID },
    routes: (status) => ({
      [K.vulns]: page(2, 2),
      [K.compliance]: { status, body: { error: "denied" } },
      [K.sboms]: ok(SBOMS),
      ...scanProbe("completed"),
    }),
    // Five, not three: the vulnerabilities leg SUCCEEDS here, and a successful
    // walk is followed by the two-request scan-state probe. The failure the
    // tool reports is still the compliance leg's — the point of this case is
    // that a legible refusal survives the other legs completing.
    expectedRequests: 5,
  },
  {
    title: "sbomhub_get_project_dashboard: the SBOM leg fails",
    tool: "sbomhub_get_project_dashboard",
    args: { project_id: PROJECT_ID },
    routes: (status) => ({
      [K.vulns]: page(2, 2),
      [K.compliance]: ok(COMPLIANCE),
      [K.sboms]: { status, body: { error: "denied" } },
      ...scanProbe("completed"),
    }),
    // Five, for the same reason as the compliance case above.
    expectedRequests: 5,
  },
];

for (const status of [403, 500]) {
  for (const c of DOWNSTREAM_CASES) {
    test(`${c.title} (HTTP ${status})`, async () => {
      stub.reset();
      stub.routes(c.routes(status));

      const result = await mcp.callTool(c.tool, c.args);
      // All legs are issued before the tool can answer; wait for them so the
      // count below is meaningful and nothing leaks into the next test.
      await stub.waitFor(c.expectedRequests);
      await stub.quiet();

      assertLoudFailure(result, { status });
      assert.equal(
        stub.requests.length,
        c.expectedRequests,
        `expected ${c.expectedRequests} requests, saw ${stub.requests
          .map((r) => r.routeKey)
          .join(", ")}`
      );
    });
  }
}

// ---------------------------------------------------------------------------
// The pagination header is load-bearing: without it the client cannot tell how
// much of a project it saw. Falling back to "what I got is all there is" turned
// one 500-row page of a 1200-row project into `total_in_project: 500,
// scan_truncated: false` — a partial answer wearing a complete answer's shape
// (Codex R3, High). Every one of these must be a loud error instead.
// ---------------------------------------------------------------------------
const HEADERLESS_CASES = [
  { title: "absent on the first page", headers: {}, rows: 1200, onPage: 0 },
  { title: "empty on the first page", headers: { "X-Total-Count": "" }, rows: 1200, onPage: 0 },
  { title: "not a number", headers: { "X-Total-Count": "many" }, rows: 1200, onPage: 0 },
  { title: "negative", headers: { "X-Total-Count": "-1" }, rows: 1200, onPage: 0 },
  { title: "absent on a later page", headers: {}, rows: 1200, onPage: 1 },
];

for (const c of HEADERLESS_CASES) {
  test(`sbomhub_get_vulnerabilities refuses a scan whose X-Total-Count is ${c.title}`, async () => {
    stub.reset();
    stub.routes({
      [K.vulns]: (req) => {
        const offset = Number(req.query.offset ?? "0");
        const size = Math.max(0, Math.min(500, c.rows - offset));
        const rows = Array.from({ length: size }, (_, i) => ({
          cve_id: `CVE-2026-${30000 + offset + i}`,
          severity: "HIGH",
          cvss_score: 7,
        }));
        const broken = offset === c.onPage * 500;
        return {
          status: 200,
          body: rows,
          headers: broken ? c.headers : { "X-Total-Count": String(c.rows) },
        };
      },
    });

    const result = await mcp.callTool("sbomhub_get_vulnerabilities", {
      project_id: PROJECT_ID,
    });
    await stub.quiet();
    assert.equal(result.isError, true, textOf(result));
    assert.match(textOf(result), /X-Total-Count/);
    // And it must not have answered with the rows it did manage to read.
    assert.throws(() => JSON.parse(textOf(result)));
  });
}

test("the project dashboard inherits that refusal", async () => {
  stub.reset();
  stub.routes({
    [K.vulns]: { status: 200, body: [] },
    [K.compliance]: { status: 200, body: COMPLIANCE },
    [K.sboms]: { status: 200, body: SBOMS },
  });

  const result = await mcp.callTool("sbomhub_get_project_dashboard", {
    project_id: PROJECT_ID,
  });
  await stub.quiet();
  assert.equal(result.isError, true, textOf(result));
  assert.match(textOf(result), /X-Total-Count/);
});

test("sbomhub_diff refuses to invent a comparison when there are fewer than two SBOMs", async () => {
  stub.reset();
  stub.routes({
    [K.sboms]: { status: 200, body: [SBOMS[0]] },
    [K.diff]: { status: 200, body: { added: [] } },
  });

  const result = await mcp.callTool("sbomhub_diff", { project_id: PROJECT_ID });
  await stub.quiet();
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
  await stub.quiet();
  assert.equal(result.isError, true);
  assert.match(textOf(result), /SBOM version not found/);
  assert.deepEqual(
    stub.requests.map((r) => r.path),
    [P.sboms]
  );
});

// ---------------------------------------------------------------------------
// Selecting the wrong SBOM is worse than failing to select one: a diff of a
// snapshot against itself comes back empty, and "no changes since the last
// SBOM" is a statement a compliance report can be built on. `version` cannot
// disambiguate — it is the CycloneDX/SPDX spec version, identical across a
// project's uploads (Codex R4).
// ---------------------------------------------------------------------------
const AMBIGUOUS_DIFF_CASES = [
  {
    title: "an ambiguous base_version names two snapshots",
    args: { project_id: PROJECT_ID, base_version: "1.5" },
    expect: /matches 2 SBOMs/,
  },
  {
    title: "both sides given the same (duplicated) spec version",
    args: { project_id: PROJECT_ID, base_version: "1.5", target_version: "1.5" },
    expect: /matches 2 SBOMs/,
  },
  {
    title: "the two selectors resolve to one SBOM",
    args: {
      project_id: PROJECT_ID,
      base_sbom_id: SPEC_VERSION_SBOMS[0].id,
      target_sbom_id: SPEC_VERSION_SBOMS[0].id,
    },
    expect: /same SBOM/,
  },
  {
    title: "an id that is not one of this project's SBOMs",
    args: {
      project_id: PROJECT_ID,
      base_sbom_id: "99999999-9999-4999-8999-999999999999",
    },
    expect: /not one of this project's SBOMs/,
  },
];

for (const c of AMBIGUOUS_DIFF_CASES) {
  test(`sbomhub_diff refuses when ${c.title}`, async () => {
    stub.reset();
    stub.routes({
      [K.sboms]: { status: 200, body: SPEC_VERSION_SBOMS },
      [K.diff]: { status: 200, body: { added: [], removed: [], changed: [] } },
    });

    const result = await mcp.callTool("sbomhub_diff", c.args);
    await stub.quiet();
    assert.equal(result.isError, true, textOf(result));
    assert.match(textOf(result), c.expect);
    // Critically: no diff was requested, so no empty result can be reported.
    assert.deepEqual(
      stub.requests.map((r) => r.path),
      [P.sboms]
    );
  });
}

test("the vulnerability walk refuses to blend two SBOM snapshots", async () => {
  // Each page is answered against whatever is latest at that moment. If an
  // upload lands mid-walk, page 2 comes from a different snapshot and the
  // concatenation never existed as a state of the project.
  stub.reset();
  stub.routes({
    [K.vulns]: (req) => {
      const offset = Number(req.query.offset ?? "0");
      const rows = Array.from({ length: offset === 0 ? 500 : 100 }, (_, i) => ({
        cve_id: `CVE-2026-${40000 + offset + i}`,
        severity: "HIGH",
        cvss_score: 7,
      }));
      return {
        status: 200,
        body: rows,
        // The second page is answered from a newer, smaller snapshot.
        headers: { "X-Total-Count": offset === 0 ? "1200" : "600" },
      };
    },
  });

  const result = await mcp.callTool("sbomhub_get_vulnerabilities", {
    project_id: PROJECT_ID,
  });
  await stub.quiet();
  assert.equal(result.isError, true, textOf(result));
  assert.match(textOf(result), /changed while it was being read/);
  assert.throws(() => JSON.parse(textOf(result)));
});

test("rows that come back twice mean the list moved, and are refused", async () => {
  // Two ways the ground moves under a multi-request walk without the row
  // COUNT changing: a replacement SBOM snapshot with the same number of rows,
  // and an EPSS sync rewriting the `?sort=epss` key while the walk is between
  // pages (Codex R9/R10). Both shift rows across offsets, and a shifted row
  // shows up as one the walk has already seen — the backend returns each
  // vulnerability at most once per consistent walk.
  stub.reset();
  stub.routes({
    [K.vulns]: (req) => {
      const offset = Number(req.query.offset ?? "0");
      // The second page re-serves rows the first page already returned.
      const base = offset === 0 ? 0 : 0;
      const size = offset === 0 ? 500 : 100;
      return {
        status: 200,
        body: Array.from({ length: size }, (_, i) => ({
          id: `00000000-0000-4000-8000-${String(base + i).padStart(12, "0")}`,
          cve_id: `CVE-2026-${50000 + base + i}`,
          severity: "HIGH",
          cvss_score: 7,
        })),
        headers: { "X-Total-Count": "600" },
      };
    },
  });

  const result = await mcp.callTool("sbomhub_get_vulnerabilities", {
    project_id: PROJECT_ID,
  });
  await stub.quiet();
  assert.equal(result.isError, true, textOf(result));
  assert.match(textOf(result), /shifted while it was being read/);
  assert.throws(() => JSON.parse(textOf(result)));
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
    await stub.quiet();
    // Give a followed redirect time to land before declaring it never happened.
    await attacker.quiet();
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
    // An empty selector is not an omitted one: accepting it would silently
    // fall back to "the newest two SBOMs" and present that as the comparison
    // the caller asked for (Codex R7).
    ["sbomhub_diff", { project_id: PROJECT_ID, base_version: "" }],
    ["sbomhub_diff", { project_id: PROJECT_ID, target_version: "" }],
    ["sbomhub_search_component", { name: "log4j", version: "" }],
    ["sbomhub_list_sboms", {}],
  ]) {
    const result = await mcp.callTool(tool, args);
    await stub.quiet();
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
