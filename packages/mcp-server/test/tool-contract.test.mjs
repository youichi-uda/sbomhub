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
// The scan-state vocabulary the SHIPPED client can produce: the backend's own
// lifecycle plus the two states the client generates when the backend gives it
// no answer at all. Imported rather than transcribed for the same reason
// SCOPE_NOTE is.
import {
  SCAN_STATE_CHANGED,
  SCAN_STATE_FINAL,
  SCAN_STATE_UNAVAILABLE,
} from "../dist/client/api.js";

// Everything `scan_state` may read. A description enumerating the states is
// making a claim about this set, not about whichever states a particular
// contract case happened to exercise — so the set, not the observed payloads,
// is what the claim is checked against.
const SCAN_STATE_VOCABULARY = new Set([
  ...SCAN_LIFECYCLE.states,
  SCAN_STATE_CHANGED,
  SCAN_STATE_UNAVAILABLE,
]);

let stub;
let mcp;
/** @type {Map<string, string>} tool → description, as advertised */
let descriptionByTool = new Map();
/** @type {Map<string, Set<string>>} tool → route keys observed while running its cases */
const observedRouteKeysByTool = new Map();
/** tools observed returning a deliberately incomplete answer */
const toolsObservedTruncating = new Set();
/**
 * Tools observed reporting vulnerability SCAN COUNTS at all — the population
 * the scan-state rules apply to. Membership is by the presence of the
 * `scan_truncated` KEY (not its value): that key marks a payload whose numbers
 * came from the capped walk over the asynchronous scan's results, which is
 * exactly the set that has to say whether the scan had finished.
 */
const toolsCarryingScanCounts = new Set();
/** every {scan_state, counts_final} pair any tool emitted, in observation order */
const scanStatePairs = [];
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

/**
 * Collect every {scan_state, counts_final} pair, at whatever depth it sits.
 * sbomhub_get_project_dashboard nests the vulnerability answer one level down,
 * the same way it nests scan_truncated, so a root-only read would let the
 * dashboard escape the rule (the shape Codex R2 caught for truncation).
 */
function collectScanStatePairs(value, into) {
  if (value === null || typeof value !== "object") return into;
  if (Array.isArray(value)) {
    for (const item of value) collectScanStatePairs(item, into);
    return into;
  }
  if (typeof value.scan_state === "string" && "counts_final" in value) {
    into.push({ scan_state: value.scan_state, counts_final: value.counts_final });
  }
  for (const child of Object.values(value)) collectScanStatePairs(child, into);
  return into;
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
      if (collectKeys(payload, new Set()).has("scan_truncated")) {
        toolsCarryingScanCounts.add(testCase.tool);
      }
      collectScanStatePairs(payload, scanStatePairs);
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
  for (const [tool, fields] of payloadKeysByTool) {
    // A tool that reports scan_state may also NAME the states that field can
    // take. Those are enumerated values, not fields, and they are checked
    // against the closed vocabulary the client can produce (see
    // SCAN_STATE_VOCABULARY) rather than against whatever strings happened to
    // appear in a payload — admitting every string value as evidence would let
    // a nonexistent field name pass whenever it collided with payload data
    // (Codex R1, Low).
    const keys = fields.has("scan_state")
      ? new Set([...fields, ...SCAN_STATE_VOCABULARY])
      : fields;
    const description = descriptionByTool.get(tool) ?? "";
    for (const [token] of description.matchAll(FIELD_TOKEN)) {
      if (token.startsWith("sbomhub_")) continue;
      checked += 1;
      assert.equal(
        keys.has(token),
        true,
        `${tool}'s description names "${token}", which appears in the payloads it produced ` +
          `neither as a field nor as a value. Seen: ${[...keys].sort().join(", ")}`
      );
    }
  }
  assert.equal(checked > 0, true, "no description named a field — the check is vacuous");
});

// The counts come from an asynchronous scan (service.ScanTracker: running /
// completed / failed / unknown, per SBOM). A project whose scan is still
// running answers in exactly the shape a finished one does, so "0
// vulnerabilities" from a just-uploaded SBOM used to be indistinguishable from
// "this project is clean" (Codex R5).
//
// That was disclosed in prose and left unfixed because the state was believed
// unreachable from this server. It is reachable — GET
// /api/v1/projects/:id/sboms/:sbom_id/scan-status, classified
// scopeProjectPathParam, authenticating with the same X-API-Key this client
// already sends (apps/api e84142c) — so the rule is no longer "warn about it"
// but "report it", with the description explaining what the report means.
test("a tool reporting scan counts reports whether the scan had finished", () => {
  assert.equal(
    SCAN_LIFECYCLE.canBePartial,
    true,
    "the backend no longer has a running/completed scan lifecycle — revisit this rule " +
      "instead of demanding a report that is no longer meaningful"
  );
  assert.equal(
    toolsCarryingScanCounts.size > 0,
    true,
    "no tool was observed reporting scan counts — the check is vacuous"
  );
  for (const tool of toolsCarryingScanCounts) {
    const keys = payloadKeysByTool.get(tool) ?? new Set();
    assert.equal(
      keys.has("counts_final"),
      true,
      `${tool} reports vulnerability counts from an asynchronous scan and never says whether ` +
        "that scan had finished. The state is readable; a payload that omits it hands the " +
        "model a provisional count shaped exactly like a settled one."
    );
    assert.equal(
      keys.has("scan_state"),
      true,
      `${tool} reports counts_final without the state it was derived from, so a model cannot ` +
        "tell 'the scan is still running' from 'nobody knows'"
    );
    const description = descriptionByTool.get(tool) ?? "";
    assert.match(
      description,
      /counts_final/,
      `${tool} carries counts_final in its payload but never names it where the model reads. ` +
        "A field nobody was told to look at is not a disclosure."
    );
    assert.match(
      description,
      /断定しないこと/,
      `${tool} does not tell the model what NOT to conclude from a low or zero count`
    );
  }
});

// The other half, and the one that reproduces the original defect: whatever the
// mapping from backend state to counts_final is, `running` must not land on
// true. Stated over the OBSERVED payloads rather than over the client source,
// so an implementation that computes counts_final some other way is judged the
// same.
test("no observed payload called a non-completed scan's counts final", () => {
  // The literal the SHIPPED client compares against, checked against the Go
  // source rather than against a copy of itself. If service.ScanStateCompleted
  // were renamed, counts_final would silently become a constant false — a safe
  // direction, but one that would make the field useless without anything
  // failing.
  assert.equal(
    SCAN_STATE_FINAL,
    SCAN_LIFECYCLE.finalState,
    `the client treats "${SCAN_STATE_FINAL}" as the finished state; the Go lifecycle's is ` +
      `"${SCAN_LIFECYCLE.finalState}"`
  );
  assert.equal(
    scanStatePairs.length > 0,
    true,
    "no payload carried a scan_state / counts_final pair — the check is vacuous"
  );
  const finals = new Set(
    scanStatePairs.filter((p) => p.counts_final === true).map((p) => p.scan_state)
  );
  assert.deepEqual(
    [...finals],
    [SCAN_LIFECYCLE.finalState],
    `counts_final=true was reported for scan states ${[...finals].join(", ")}. Only ` +
      `"${SCAN_LIFECYCLE.finalState}" is evidence that the background scan is done; every ` +
      "other state (running, failed, unknown, and anything this client could not read) " +
      "leaves the counts provisional."
  );
  // And the positive pole: at least one case must have produced a final answer,
  // or a client hardcoding `false` would satisfy the assertion above.
  assert.equal(
    scanStatePairs.some((p) => p.counts_final === true),
    true,
    "no case observed counts_final=true — a client that always reports 'not final' would " +
      "pass this rule while telling the model nothing"
  );
  // A state OUTSIDE the vocabulary is not forbidden — the client relays an
  // unrecognised backend status verbatim, and the description says so. What is
  // forbidden is certifying one: an unknown state is not evidence of anything
  // (Codex R3, Low — the previous rule banned the pass-through outright, so the
  // promised behaviour could not be tested without failing this assertion).
  for (const pair of scanStatePairs) {
    if (SCAN_STATE_VOCABULARY.has(pair.scan_state)) continue;
    assert.equal(
      pair.counts_final,
      false,
      `a payload reported scan_state="${pair.scan_state}" — neither a ` +
        `service.ScanState (${SCAN_LIFECYCLE.states.join(", ")}) nor one of the client's ` +
        `own states (${SCAN_STATE_CHANGED}, ${SCAN_STATE_UNAVAILABLE}) — and called its ` +
        "counts final. A state this client does not recognise cannot be evidence that a " +
        "scan finished."
    );
  }
  assert.equal(
    scanStatePairs.some((p) => SCAN_STATE_VOCABULARY.has(p.scan_state)),
    true,
    "no observed state was in the known vocabulary — the rule above is checking nothing"
  );
  assert.equal(
    scanStatePairs.some((p) => !SCAN_STATE_VOCABULARY.has(p.scan_state)),
    true,
    "no case exercised an UNRECOGNISED backend state, which the description promises is " +
      "relayed and treated as non-final. An untested promise is the shape this suite exists " +
      "to catch."
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
  // Two parameters, with DIFFERENT names. A shape-only fold ("a uuid segment is
  // `:id`") produces `/api/v1/projects/:id/sboms/:id/scan-status`, which
  // project_scope.go does not carry — so the route the scan-state probe uses
  // would be reported as unclassified, i.e. as default-denied for a
  // project-scoped key, when it is in fact classified scopeProjectPathParam.
  assert.equal(
    routeKeyOf(
      "GET",
      "/api/v1/projects/3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b90" +
        "/sboms/aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa/scan-status"
    ),
    "GET /api/v1/projects/:id/sboms/:sbom_id/scan-status"
  );
  // The fold may not invent a match: a non-uuid in a parameter position is not
  // that route, and reporting it as one would hide a client sending garbage.
  assert.notEqual(
    routeKeyOf("GET", "/api/v1/projects/not-a-uuid/sboms/also-not/scan-status"),
    "GET /api/v1/projects/:id/sboms/:sbom_id/scan-status"
  );
  // Method is part of the key: a POST to a GET-only registered path must not
  // borrow that path's classification.
  assert.equal(
    routeKeyOf("POST", "/api/v1/projects/3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b90/sbom"),
    "POST /api/v1/projects/:id/sbom"
  );
});
