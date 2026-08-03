// The enumeration: which tools exist, and are they all under contract?
//
// A contract suite that only checks the tools it knows about degrades silently
// — the tenth tool ships with no coverage and nothing goes red. So the tool set
// is taken from the SERVER (tools/list, i.e. the same answer an LLM gets) and
// compared against the set the contract table covers.
//
// Scope of the enumeration, stated explicitly because "I enumerated everything"
// is easy to claim and easy to get wrong: the unit of enumeration here is
// **every tool the built dist/index.js registers**, obtained by asking it, not
// by reading src/index.ts. Anything registered conditionally, from another
// module, or by a future refactor is included by construction. It does NOT
// enumerate MCP resources or prompts — this server registers none, and that is
// asserted below so the day it registers one, this file has to be revisited.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

import { DENIAL_STATUS, scopeKindOf } from "./helpers/backend-scope.mjs";
import { CONTRACT_CASES, declaredRouteKeysByTool } from "./helpers/contract-table.mjs";
import {
  ANTI_MARKERS,
  EVASIONS,
  MARKERS,
  refusalMarker,
  scopeClaimViolations,
} from "./helpers/description-claims.mjs";
import { SERVER_SOURCE, startMcpServer } from "./helpers/mcp-harness.mjs";
import { startStubApi } from "./helpers/stub-api.mjs";

const README = fileURLToPath(new URL("../README.md", import.meta.url));

let stub;
let mcp;
let tools;

// A generous per-hook timeout: a server that fails to come up should fail the
// run with a legible message rather than sit there until the job's own limit.
before(async () => {
  stub = await startStubApi();
  mcp = await startMcpServer({ apiUrl: stub.url });
  tools = await mcp.listTools();
}, { timeout: 60_000 });

after(async () => {
  await mcp?.close();
  await stub?.close();
});

test("every registered tool has a contract case (and vice versa)", () => {
  const registered = new Set(tools.map((t) => t.name));
  const covered = new Set(CONTRACT_CASES.map((c) => c.tool));

  const uncovered = [...registered].filter((n) => !covered.has(n)).sort();
  const stale = [...covered].filter((n) => !registered.has(n)).sort();

  assert.deepEqual(
    uncovered,
    [],
    `these tools are advertised to the model with no contract case: ${uncovered.join(", ")}. ` +
      "Add one to test/helpers/contract-table.mjs — a tool with no case has no " +
      "check that its description matches what it does."
  );
  assert.deepEqual(
    stale,
    [],
    `contract-table.mjs covers tools that are no longer registered: ${stale.join(", ")}`
  );
});

test("the server registers no resources or prompts this suite would be missing", async () => {
  // listResources / listPrompts throw MethodNotFound when the capability is not
  // declared, which is the state this suite assumes.
  await assert.rejects(() => mcp.client.listResources());
  await assert.rejects(() => mcp.client.listPrompts());
});

test("every tool advertises a usable description and an object schema", () => {
  for (const tool of tools) {
    assert.equal(
      typeof tool.description === "string" && tool.description.length >= 10,
      true,
      `${tool.name} has no meaningful description; it is the only thing the model reads`
    );
    assert.equal(tool.inputSchema?.type, "object", `${tool.name} inputSchema`);
  }
});

test("optional and required arguments are described as such", () => {
  // Drift in either direction misleads the model: a required argument
  // described as optional produces InvalidParams it cannot explain, and an
  // optional one described as required suppresses calls that would work.
  const OPTIONAL_MARKER = /任意|省略時|デフォルト/;
  for (const tool of tools) {
    const properties = tool.inputSchema.properties ?? {};
    const required = new Set(tool.inputSchema.required ?? []);
    for (const [name, prop] of Object.entries(properties)) {
      const described = prop.description ?? "";
      assert.equal(
        OPTIONAL_MARKER.test(described),
        !required.has(name),
        `${tool.name}.${name} is ${required.has(name) ? "REQUIRED" : "OPTIONAL"} in the schema ` +
          `but described as the opposite: "${described}"`
      );
    }
  }
});

test("argument schemas match the scope of the routes each tool calls", () => {
  const declared = declaredRouteKeysByTool();
  const byName = new Map(tools.map((t) => [t.name, t]));

  for (const [tool, routeKeys] of declared) {
    const kinds = new Set([...routeKeys].map(scopeKindOf));
    const properties = byName.get(tool).inputSchema.properties ?? {};
    const required = new Set(byName.get(tool).inputSchema.required ?? []);

    if (kinds.size === 1 && kinds.has("scopeTenantWide")) {
      assert.equal(
        "project_id" in properties,
        false,
        `${tool} only calls tenant-wide routes, so a project_id argument would be a lie: ` +
          "the value could not narrow anything"
      );
    }
    if (kinds.has("scopeProjectPathParam")) {
      assert.equal(
        required.has("project_id"),
        true,
        `${tool} addresses a per-project route, so project_id must be a required argument`
      );
      assert.equal(properties.project_id.format, "uuid");
      // The refusal a project-scoped key gets for someone else's project is
      // stated where the model will look for it — on the argument that causes
      // it. Without this, a 403 from a per-project tool is indistinguishable
      // from "the whole credential is broken".
      assert.match(
        properties.project_id.description ?? "",
        new RegExp(`${DENIAL_STATUS}`),
        `${tool}.project_id must say what happens when a project-scoped API key names ` +
          "another project (the backend answers " + DENIAL_STATUS + ")"
      );
      // ...and must not turn that status into a claim about existence. The
      // backend answers the same 403 for a project that exists, one in another
      // tenant, and a UUID that was never allocated.
      assert.doesNotMatch(
        properties.project_id.description ?? "",
        /存在する(?!かどうか)/,
        `${tool}.project_id implies the named project exists; a scope refusal reveals nothing ` +
          "about existence"
      );
    }
  }
});

test("src/index.ts quotes the status the backend really answers a scope violation with", () => {
  // The header block enumerates what a project-scoped key gets. Every HTTP
  // status named there is a claim about apiKeyProjectScopeAllowed, which has
  // exactly one refusal (RespondProjectScopeDenied). A different number in
  // that block is a false claim about the product's authorization behaviour.
  const src = readFileSync(SERVER_SOURCE, "utf8");
  const MARKER = "With a project-scoped key:";
  const start = src.indexOf(MARKER);
  assert.notEqual(
    start,
    -1,
    `${SERVER_SOURCE} no longer contains the "${MARKER}" block. It is the only place the ` +
      "difference between a tenant-level and a project-scoped key is written down for " +
      "maintainers; restore it or move this check with it."
  );

  const block = [];
  for (const line of src.slice(start).split("\n")) {
    if (line.trim() === "//") break;
    block.push(line);
  }
  const statuses = [...block.join("\n").matchAll(/\b(\d{3})\b/g)].map((m) => m[1]);
  assert.notEqual(statuses.length, 0, "the block names no status at all");
  for (const status of statuses) {
    assert.equal(
      Number(status),
      DENIAL_STATUS,
      `the "${MARKER}" block claims HTTP ${status}, but every project-scope refusal in ` +
        `apps/api/internal/middleware/project_scope.go is ${DENIAL_STATUS} ` +
        "(RespondProjectScopeDenied). project_scope.go documents the choice of 403 over " +
        "404 deliberately: 404 would claim the resource is absent when it is only unseen."
    );
  }
});

test("descriptions quote that same status", () => {
  for (const tool of tools) {
    for (const [, status] of (tool.description ?? "").matchAll(/(\d{3})で拒否/g)) {
      assert.equal(
        Number(status),
        DENIAL_STATUS,
        `${tool.name}'s description tells the model to expect ${status} on refusal; the ` +
          `backend answers ${DENIAL_STATUS}`
      );
    }
  }
});

test("every claim marker still matches some real description", () => {
  // Anti-vacuity guard for helpers/description-claims.mjs. Its rules are
  // phrased as "the description must contain X". A marker that matches nothing
  // anywhere (a typo, a phrase the product stopped using) would keep the
  // must-NOT-contain rules green forever while checking nothing, and would turn
  // the must-contain rules into an unsatisfiable demand nobody can read. Each
  // marker is expected to be live vocabulary — matched by at least one tool.
  const descriptions = tools.map((t) => t.description ?? "");
  const live = { ...MARKERS, refusal: refusalMarker(DENIAL_STATUS) };
  for (const [name, marker] of Object.entries(live)) {
    assert.equal(
      descriptions.some((d) => marker.test(d)),
      true,
      `MARKERS.${name} (${marker}) matches none of the advertised descriptions. ` +
        "Either the wording it looks for was replaced — in which case update the " +
        "marker deliberately — or the rule it backs is now checking nothing."
    );
  }
  // The mirror: the negated phrasings must match nothing. If one ever does,
  // some description is denying a refusal the backend performs.
  for (const [name, marker] of Object.entries(ANTI_MARKERS)) {
    const offenders = tools.filter((t) => marker.test(t.description ?? ""));
    assert.deepEqual(
      offenders.map((t) => t.name),
      [],
      `ANTI_MARKERS.${name} (${marker}) matched a live description`
    );
  }
});

test("the rules still catch every evasion previously found", () => {
  // Regression corpus. Each entry was accepted with zero violations by some
  // earlier version of helpers/description-claims.mjs.
  for (const { label, kind, description } of EVASIONS) {
    const violations = scopeClaimViolations({
      tool: "sbomhub_get_dashboard",
      description,
      routeKindByKey: new Map([["GET /api/v1/mcp/pretend", kind]]),
      denialStatus: DENIAL_STATUS,
    });
    assert.equal(
      violations.length > 0,
      true,
      `a description that "${label}" produced no violation for a ${kind} route. ` +
        `This evasion was found and closed once; the rules have regressed.\n  ${description}`
    );
  }
});

test("the scope rules react to the classification, not only to the wording", () => {
  // The join being tested elsewhere is description ⟷ route ⟷ backend policy.
  // The wording side is exercised by every run; this exercises the POLICY side
  // without a live Go server: take a live description and ask what the rules
  // would say if the backend classified its route differently. Each case must
  // produce at least one violation — if none does, the rules are insensitive to
  // the classification and the join is decorative.
  const live = new Map(tools.map((t) => [t.name, t.description ?? ""]));
  const cases = [
    // Claims tenant-wide coverage; would be false for a per-project route.
    ["sbomhub_get_dashboard", "scopeProjectPathParam"],
    // Says nothing about a tenant-level key; would be missing for a refused route.
    ["sbomhub_get_compliance", "scopeTenantWide"],
    // Describes the narrowing, not a refusal.
    ["sbomhub_list_projects", "scopeTenantWide"],
  ];

  for (const [tool, pretendKind] of cases) {
    const violations = scopeClaimViolations({
      tool,
      description: live.get(tool),
      routeKindByKey: new Map([["GET /pretend", pretendKind]]),
      denialStatus: DENIAL_STATUS,
    });
    assert.equal(
      violations.length > 0,
      true,
      `reclassifying ${tool}'s route as ${pretendKind} would make its description wrong, ` +
        "but the rules in helpers/description-claims.mjs reported nothing"
    );
  }
});

test("README.md documents exactly the tools the server registers", () => {
  const readme = readFileSync(README, "utf8");
  const documented = new Set(
    [...readme.matchAll(/^\|\s*`(sbomhub_[a-z_]+)`\s*\|/gm)].map((m) => m[1])
  );
  const registered = new Set(tools.map((t) => t.name));

  assert.deepEqual(
    [...registered].filter((n) => !documented.has(n)).sort(),
    [],
    "tools missing from the README tool table"
  );
  assert.deepEqual(
    [...documented].filter((n) => !registered.has(n)).sort(),
    [],
    "the README tool table documents tools that do not exist"
  );
});

test("README.md tells the operator which tools a project-scoped key cannot use", () => {
  // Same claim as the tool descriptions, aimed at the human who mints the key.
  // The key is minted from a project's "API Keys" tab, so the operator's
  // default is the scoped one — the table has to say what it will not reach.
  const readme = readFileSync(README, "utf8");
  const rows = new Map(
    [...readme.matchAll(/^\|\s*`(sbomhub_[a-z_]+)`\s*\|([^\n]*)$/gm)].map((m) => [
      m[1],
      m[2],
    ])
  );
  const declared = declaredRouteKeysByTool();

  for (const [tool, routeKeys] of declared) {
    const kinds = new Set([...routeKeys].map(scopeKindOf));
    if (!kinds.has("scopeTenantWide") && !kinds.has("scopeProjectListNarrowed")) {
      continue;
    }
    const row = rows.get(tool) ?? "";
    // Same shape of rule as the tool descriptions, and for the same reason a
    // bare 「プロジェクトスコープ」 substring is not enough: the row has to say
    // WHAT that key gets, affirmatively.
    const required = kinds.has("scopeTenantWide")
      ? new RegExp(`${DENIAL_STATUS}で拒否`)
      : /そのプロジェクト.*1件/;

    assert.match(
      row,
      /プロジェクトスコープ/,
      `README's row for ${tool} does not mention the project-scoped API key at all. ` +
        "That key is what the documented mint flow (a project's API Keys tab) produces."
    );
    assert.match(
      row,
      required,
      `README's row for ${tool} does not say what a project-scoped key gets ` +
        `(expected ${required}): "${row.trim()}"`
    );
    assert.doesNotMatch(
      row,
      ANTI_MARKERS.negatedRefusal,
      `README's row for ${tool} denies a refusal the backend does perform`
    );
  }
});
