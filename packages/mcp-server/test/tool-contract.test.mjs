// Contract tests: what each tool's description PROMISES vs what the tool DOES.
//
// The failure mode being defended against (commit bad1b8c) is not a crash. It
// is a tool that works, returns a plausible payload, and is described to the
// model in terms that make the payload mean something it does not. The model
// has no other source of truth about scope, so a wrong description is a wrong
// answer with evidence attached.
//
// Every assertion here is grounded in something observable:
//   - the request the server actually sent (stub API request log);
//   - the tool set and descriptions the server actually advertises (tools/list);
//   - the backend's classification of the routes that were hit
//     (apps/api/internal/middleware/project_scope.go).
//
// No description string is duplicated into this file. A test that pinned the
// wording would pass just as happily against the pre-bad1b8c wording.
import assert from "node:assert/strict";
import { after, before, test } from "node:test";

import { DENIAL_STATUS, SCOPE_SOURCE, scopeKindOf } from "./helpers/backend-scope.mjs";
import {
  CONTRACT_CASES,
  declaredRouteKeysByTool,
} from "./helpers/contract-table.mjs";
import { scopeClaimViolations } from "./helpers/description-claims.mjs";
import { API_KEY, jsonOf, startMcpServer, textOf } from "./helpers/mcp-harness.mjs";
import { routeKeyOf, startStubApi } from "./helpers/stub-api.mjs";

let stub;
let mcp;
/** @type {Map<string, string>} tool → description, as advertised */
let descriptionByTool = new Map();
/** @type {Map<string, Set<string>>} tool → route keys observed while running its cases */
const observedRouteKeysByTool = new Map();

const UUID_ANYWHERE =
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

// A generous per-hook timeout: a server that fails to come up should fail the
// run with a legible message rather than sit there until the job's own limit.
before(async () => {
  stub = await startStubApi();
  mcp = await startMcpServer({ apiUrl: stub.url });
  const tools = await mcp.listTools();
  descriptionByTool = new Map(tools.map((t) => [t.name, t.description ?? ""]));
}, { timeout: 60_000 });

after(async () => {
  await mcp?.close();
  await stub?.close();
});

const shape = (r) => ({ method: r.method, path: r.path, query: r.query });
const sortKey = (r) => JSON.stringify([r.method, r.path, r.query]);

for (const testCase of CONTRACT_CASES) {
  test(`${testCase.tool} — ${testCase.title}`, async () => {
    stub.reset();
    stub.routes(testCase.routes);

    const result = await mcp.callTool(testCase.tool, testCase.args);
    // Wait for the traffic to settle before reading the log: a fan-out leg can
    // still be arriving when the tool has already answered, and an UNEXPECTED
    // extra request needs a chance to show up before "exactly these requests"
    // is asserted.
    await stub.waitFor(testCase.expect.length);
    await stub.quiet();
    const requests = stub.requests;

    if (testCase.expectError) {
      assert.equal(result.isError, true, "expected an in-band tool error");
      assert.match(textOf(result), testCase.expectError);
    } else {
      assert.notEqual(
        result.isError,
        true,
        `tool reported an error: ${textOf(result)}`
      );
    }

    // Credential handling is part of the contract: the client documents
    // X-API-Key as the primary header, and nothing else may carry the key.
    for (const r of requests) {
      assert.equal(
        r.headers["x-api-key"],
        API_KEY,
        `${r.routeKey} did not carry the configured key in X-API-Key`
      );
      assert.equal(
        r.headers.authorization,
        undefined,
        `${r.routeKey} sent an Authorization header the client does not use`
      );
    }

    const actual = requests.map(shape);
    const expected = testCase.expect;
    if (testCase.unordered) {
      assert.deepEqual(
        [...actual].sort((a, b) => sortKey(a).localeCompare(sortKey(b))),
        [...expected].sort((a, b) => sortKey(a).localeCompare(sortKey(b)))
      );
    } else {
      assert.deepEqual(actual, expected);
    }

    const observed =
      observedRouteKeysByTool.get(testCase.tool) ?? new Set();
    for (const r of requests) observed.add(r.routeKey);
    observedRouteKeysByTool.set(testCase.tool, observed);

    if (testCase.check) {
      testCase.check({
        result,
        requests,
        payload: testCase.expectError ? undefined : jsonOf(result),
      });
    }
  });
}

// ---------------------------------------------------------------------------
// The bad1b8c layer.
//
// For each tool: take the routes it was OBSERVED to call above, ask
// project_scope.go what a project-scoped API key may do with those routes, and
// require the LIVE description to state it. The rules are in
// helpers/description-claims.mjs.
// ---------------------------------------------------------------------------
test("every description states the scope the backend actually enforces", () => {
  // Guard against a vacuous pass: if the cases above failed before issuing
  // any request, this test would have nothing to check and would go green.
  assert.deepEqual(
    [...observedRouteKeysByTool.keys()].sort(),
    [...new Set(CONTRACT_CASES.map((c) => c.tool))].sort(),
    "some tool produced no observed traffic — the cases above did not all run"
  );

  const failures = [];
  for (const [tool, routeKeys] of observedRouteKeysByTool) {
    const routeKindByKey = new Map(
      [...routeKeys].map((k) => [k, scopeKindOf(k)])
    );
    failures.push(
      ...scopeClaimViolations({
        tool,
        description: descriptionByTool.get(tool) ?? "",
        routeKindByKey,
        denialStatus: DENIAL_STATUS,
      })
    );
  }

  assert.deepEqual(
    failures,
    [],
    `tool descriptions disagree with ${SCOPE_SOURCE}:\n\n- ${failures.join("\n\n- ")}\n`
  );
});

test("a tool whose routes are all tenant-wide never sends a project id", () => {
  for (const [tool, routeKeys] of observedRouteKeysByTool) {
    const kinds = new Set([...routeKeys].map(scopeKindOf));
    const allTenantWide =
      kinds.size === 1 && kinds.has("scopeTenantWide");
    if (!allTenantWide) continue;
    for (const key of routeKeys) {
      assert.equal(
        UUID_ANYWHERE.test(key),
        false,
        `${tool} is described as tenant-wide but addressed ${key}, which names a resource id`
      );
    }
  }
});

// README.md and the file banner both call this server read-only. The MCP route
// group is GET-only apart from one read-via-POST (the diff selects two SBOMs by
// id in the body). Anything else — a PUT, a DELETE, a POST anywhere else —
// would make that claim false, and would be reachable by any model that can
// call the tool.
test("the server only ever issues read requests", () => {
  const READ_VIA_POST = "POST /api/v1/mcp/sbom/diff";
  for (const [tool, routeKeys] of observedRouteKeysByTool) {
    for (const key of routeKeys) {
      if (key.startsWith("GET ") || key === READ_VIA_POST) continue;
      assert.fail(
        `${tool} issued ${key}; this server is documented as read-only and the only ` +
          `non-GET route it may use is ${READ_VIA_POST}`
      );
    }
  }
});

// Keeps the static table honest: the descriptions above are judged against the
// routes DECLARED in contract-table.mjs (via the same keys), so the declared
// set has to be the set the server really uses. A declared-but-never-called
// route would let a description claim a scope no request ever exercises.
test("the declared route table is exactly the traffic observed", () => {
  const declared = declaredRouteKeysByTool();
  const asObject = (m) =>
    Object.fromEntries([...m].map(([k, v]) => [k, [...v].sort()]));
  assert.deepEqual(asObject(declared), asObject(observedRouteKeysByTool));
});

// A route the MCP server calls that project_scope.go does not classify is
// default-DENIED for a project-scoped key by the backend, so it can never work
// for such a key. scopeKindOf throws on those; this test states the property
// explicitly rather than leaving it to a helper's side effect.
test("every route the server calls is one the backend classifies", () => {
  for (const routeKeys of observedRouteKeysByTool.values()) {
    for (const key of routeKeys) assert.doesNotThrow(() => scopeKindOf(key));
  }
});

test("route pattern folding maps a concrete project path back to the registered route", () => {
  // Guards the mechanism the two tests above depend on: if this stopped
  // folding, every per-project route would look unclassified.
  assert.equal(
    routeKeyOf("GET", "/api/v1/mcp/projects/3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b90/sboms"),
    "GET /api/v1/mcp/projects/:id/sboms"
  );
  assert.equal(
    routeKeyOf("GET", "/api/v1/mcp/projects"),
    "GET /api/v1/mcp/projects"
  );
});
