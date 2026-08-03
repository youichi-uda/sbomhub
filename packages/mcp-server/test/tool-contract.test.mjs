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

import {
  DENIAL_STATUS,
  SCAN_LIFECYCLE,
  SCOPE_SOURCE,
  scopeKindOf,
} from "./helpers/backend-scope.mjs";
import {
  CONTRACT_CASES,
  declaredRouteKeysByTool,
} from "./helpers/contract-table.mjs";
import { scopeClaimViolations } from "./helpers/description-claims.mjs";
import { API_KEY, jsonOf, startMcpServer, textOf } from "./helpers/mcp-harness.mjs";
import { routeKeyOf, startStubApi } from "./helpers/stub-api.mjs";
// The clauses the SERVER ships, imported from the built artifact. Not a copy of
// the description: the source composes each description from these same
// strings, so "the tool says the right thing" becomes an exact check instead of
// a pattern match over prose (Codex R2, High).
import {
  PROJECT_SCOPE_DENIAL_STATUS,
  SCOPE_NOTE,
} from "../dist/scope-notes.js";

let stub;
let mcp;
/** @type {Map<string, string>} tool → description, as advertised */
let descriptionByTool = new Map();
/** @type {Map<string, Set<string>>} tool → route keys observed while running its cases */
const observedRouteKeysByTool = new Map();
/** tools observed returning a deliberately incomplete answer */
const toolsObservedTruncating = new Set();
/** @type {Map<string, Set<string>>} tool → every field name seen in its payloads */
const payloadKeysByTool = new Map();

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

// `scan_truncated` is not always at the root: sbomhub_get_project_dashboard
// nests the same flag under `vulnerabilities`. Looking only at the top level
// let a truncated dashboard pass the disclosure rule below (Codex R2, High),
// so the whole payload is searched.
function collectKeys(value, into) {
  if (value === null || typeof value !== "object") return into;
  if (Array.isArray(value)) {
    for (const item of value) collectKeys(item, into);
    return into;
  }
  for (const [key, child] of Object.entries(value)) {
    into.add(key);
    collectKeys(child, into);
  }
  return into;
}

function declaresTruncation(value) {
  if (value === null || typeof value !== "object") return false;
  if (value.scan_truncated === true) return true;
  return Object.values(value).some(declaresTruncation);
}

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

    if (!testCase.expectError) {
      const payload = jsonOf(result);
      if (declaresTruncation(payload)) toolsObservedTruncating.add(testCase.tool);
      collectKeys(
        payload,
        payloadKeysByTool.get(testCase.tool) ??
          payloadKeysByTool.set(testCase.tool, new Set()).get(testCase.tool)
      );
    }

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

// ---------------------------------------------------------------------------
// The canonical-clause layer.
//
// The rules in helpers/description-claims.mjs read prose with regular
// expressions; that is necessarily incomplete (a false claim can always be
// phrased outside the vocabulary). This layer is not:
//   - the clause for each classification is ONE string, shipped in
//     src/scope-notes.ts and validated here against the Go source and against
//     the same claim rules;
//   - every tool of that classification must contain it VERBATIM, and must not
//     contain the clause of another classification.
// A description can still be padded with contradictory prose — the heuristic
// layer above is what looks for that — but it can no longer simply omit or
// reword the load-bearing claim.
// ---------------------------------------------------------------------------
test("the shipped scope clauses agree with the backend", () => {
  assert.equal(
    PROJECT_SCOPE_DENIAL_STATUS,
    DENIAL_STATUS,
    `src/scope-notes.ts quotes HTTP ${PROJECT_SCOPE_DENIAL_STATUS} for a project-scope ` +
      `refusal; ${SCOPE_SOURCE} answers ${DENIAL_STATUS}`
  );

  // Each clause must satisfy, on its own, the rules its classification implies.
  const forKind = {
    scopeTenantWide: SCOPE_NOTE.tenantWide,
    scopeProjectListNarrowed: SCOPE_NOTE.projectListNarrowed,
  };
  for (const [kind, clause] of Object.entries(forKind)) {
    assert.deepEqual(
      scopeClaimViolations({
        tool: "sbomhub_canonical_clause",
        description: clause,
        routeKindByKey: new Map([["GET /api/v1/mcp/canonical", kind]]),
        denialStatus: DENIAL_STATUS,
      }),
      [],
      `the canonical clause for ${kind} does not satisfy its own rules: ${clause}`
    );
  }
});

test("every tool embeds the canonical clause for its classification, verbatim", () => {
  const clauseForKinds = (kinds) => {
    if (kinds.has("scopeTenantWide")) return SCOPE_NOTE.tenantWide;
    if (kinds.has("scopeProjectListNarrowed")) return SCOPE_NOTE.projectListNarrowed;
    return null;
  };

  let checked = 0;
  for (const [tool, routeKeys] of observedRouteKeysByTool) {
    const kinds = new Set([...routeKeys].map(scopeKindOf));
    const description = descriptionByTool.get(tool) ?? "";
    const expected = clauseForKinds(kinds);

    if (expected) {
      checked += 1;
      assert.equal(
        description.includes(expected),
        true,
        `${tool} calls ${[...routeKeys].join(", ")} but its description does not contain the ` +
          `clause every tool of that classification ships:\n  expected: ${expected}\n  got: ${description}`
      );
    }
    for (const [name, clause] of Object.entries(SCOPE_NOTE)) {
      if (clause === expected) continue;
      assert.equal(
        description.includes(clause),
        false,
        `${tool} carries the "${name}" scope clause, which is not what its routes ` +
          `(${[...routeKeys].join(", ")}) do`
      );
    }

    if (expected) {
      // The clause must be ASSERTED, not quoted and then disputed. A review
      // round produced 「<clause>」という説明は誤りである — the clause present
      // verbatim, every other check satisfied, and the sentence saying the
      // opposite (Codex R3). Two structural requirements close that shape:
      // the clause may not sit inside quotation marks, and the sentence it
      // belongs to may not carry a disclaimer.
      const at = description.indexOf(expected);
      const before = description.slice(0, at);
      const after = description.slice(at + expected.length);
      assert.equal(
        /[「『"']\s*$/.test(before) || /^\s*[」』"']/.test(after),
        false,
        `${tool} quotes the scope clause instead of stating it. A quoted claim is one the ` +
          `sentence can then disown; the model cannot tell which reading is meant.`
      );
      assert.doesNotMatch(
        after,
        /誤り|間違い|正しくない|正確ではない|無視して|実際には|事実ではない/,
        `${tool} states the scope clause and then disclaims it. Whatever follows the clause ` +
          `may explain WHY it holds, not that it does not.`
      );
    }

    // Credentials are named ONLY inside the canonical clause. Otherwise a
    // description could embed the correct clause and then contradict it in
    // free prose ("...ただし実際にはプロジェクトスコープのAPIキーで利用でき、
    // テナント単位のAPIキーが403で拒否される") — a review round produced
    // exactly that (Codex R2). The surrounding prose may explain WHY; it may
    // not restate WHO.
    const remainder = Object.values(SCOPE_NOTE).reduce(
      (acc, clause) => acc.split(clause).join(""),
      description
    );
    assert.doesNotMatch(
      remainder,
      /プロジェクトスコープのAPIキー|テナント単位のAPIキー/,
      `${tool} names an API key kind outside the canonical clause. Whatever it says there ` +
        `cannot be checked against the backend, and if it disagrees with the clause the model ` +
        `has two answers:\n  ${remainder}`
    );
  }
  assert.equal(checked > 0, true, "no tool needed a scope clause — the check is vacuous");
});

// A tool that can answer with less than it was asked for has to say so where
// the model reads. This one is not about scope but about the same failure: a
// partial answer that is byte-shaped like a complete one. The client caps its
// own walk at 5000 rows (VULNS_SCAN_CAP) so one tool call cannot issue 20+
// requests, and reports the cut in `scan_truncated` — but a model that was
// never told the cap exists has no reason to look at that field before
// reporting `matched` as the project's count.
test("a tool that can truncate its own answer says so in its description", () => {
  assert.equal(
    toolsObservedTruncating.size > 0,
    true,
    "no case produced scan_truncated=true — this rule is checking nothing"
  );
  for (const tool of toolsObservedTruncating) {
    assert.match(
      descriptionByTool.get(tool) ?? "",
      /scan_truncated|5000/,
      `${tool} returned scan_truncated=true for a project it could not walk fully, but its ` +
        "description never mentions the cap. The model will read the partial counts as the " +
        "project's totals."
    );
  }
});

// A description that tells the model to read `by_severity` from a payload that
// has no such field is the same defect in miniature: the model is told
// something about the answer that is not true of the answer. Field names are
// checkable against what the tool actually returned.
test("every response field a description names exists in what the tool returns", () => {
  // snake_case tokens only — prose and tool names (sbomhub_*) are not fields.
  const FIELD_TOKEN = /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/g;
  let checked = 0;
  for (const [tool, keys] of payloadKeysByTool) {
    const description = descriptionByTool.get(tool) ?? "";
    for (const [token] of description.matchAll(FIELD_TOKEN)) {
      if (token.startsWith("sbomhub_")) continue;
      checked += 1;
      assert.equal(
        keys.has(token),
        true,
        `${tool}'s description names the field "${token}", which appears nowhere in the ` +
          `payloads it produced. Fields seen: ${[...keys].sort().join(", ")}`
      );
    }
  }
  assert.equal(checked > 0, true, "no description named a field — the check is vacuous");
});

// The counts come from an asynchronous scan the MCP group cannot query the
// state of (there is no scan-status route under /api/v1/mcp). A project whose
// scan is still running answers in exactly the shape a finished one does, so
// "0 vulnerabilities" from a just-uploaded SBOM is indistinguishable from
// "this project is clean" (Codex R5). Until the state is reachable, the only
// honest place to put that is the description.
test("a tool reporting scan counts warns that the scan may not have finished", () => {
  assert.equal(
    SCAN_LIFECYCLE.canBePartial,
    true,
    "the backend no longer has a running/completed scan lifecycle — revisit this rule " +
      "instead of demanding a caveat that is no longer true"
  );
  assert.equal(
    toolsObservedTruncating.size > 0,
    true,
    "no tool was observed reporting scan counts — the check is vacuous"
  );
  for (const tool of toolsObservedTruncating) {
    const description = descriptionByTool.get(tool) ?? "";
    assert.match(
      description,
      /未完了/,
      `${tool} reports vulnerability counts from an asynchronous scan whose state this ` +
        "server cannot see, and does not say so"
    );
    assert.match(
      description,
      /断定しないこと/,
      `${tool} does not tell the model what NOT to conclude from a low or zero count`
    );
  }
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
