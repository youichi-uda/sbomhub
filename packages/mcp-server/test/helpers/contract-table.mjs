// The contract: for every registered tool, what the SBOMHub API must see when
// an LLM calls it, and what the caller must get back.
//
// This table is data, shared by two tests that check each other:
//   - tool-contract.test.mjs runs each case against the stub API and asserts
//     the requests observed are EXACTLY the ones declared here (and, at the
//     end, that the union of declared routes is the union of observed ones);
//   - tool-inventory.test.mjs asserts the set of tools appearing here is
//     exactly the set the server registers, so a new tool cannot be added
//     without a contract case.
//
// The `expect` entries are also what tool-contract.test.mjs feeds to the
// backend scope table (project_scope.go) to decide what the tool's description
// is REQUIRED to say. That is the bad1b8c layer: description ⟷ route ⟷ policy.
import assert from "node:assert/strict";

// Valid v4 UUIDs — the input schemas use z.string().uuid(), so the SDK would
// reject anything else before the callback runs.
export const PROJECT_ID = "3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b90";
export const SBOM_NEWEST = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
export const SBOM_MIDDLE = "bbbbbbbb-2222-4222-9222-bbbbbbbbbbbb";
export const SBOM_OLDEST = "cccccccc-3333-4333-a333-cccccccccccc";

// apps/api/internal/repository/sbom.go ListByProject: ORDER BY created_at DESC.
// The client relies on that order (diff takes [0] and [1]) and the
// sbomhub_list_sboms description states it ("新しい順").
export const SBOMS = [
  { id: SBOM_NEWEST, version: "2.0.0", created_at: "2026-08-01T00:00:00Z" },
  { id: SBOM_MIDDLE, version: "1.5.0", created_at: "2026-07-01T00:00:00Z" },
  { id: SBOM_OLDEST, version: "1.0.0", created_at: "2026-06-01T00:00:00Z" },
];

export const PROJECTS = [
  { id: PROJECT_ID, name: "my-app" },
  { id: "7c9e6679-7425-40de-944b-e07fc1f90ae7", name: "other-app" },
];

export const DASHBOARD = {
  total_projects: 2,
  total_vulnerabilities: 41,
  critical: 3,
};

export const COMPLIANCE = { score: 82, level: "B", meti_items: 12 };

const vuln = (cve, severity, cvss) => ({
  cve_id: cve,
  severity,
  cvss_score: cvss,
});

export const VULNS = [
  vuln("CVE-2021-44228", "CRITICAL", 10.0),
  vuln("CVE-2022-22965", "CRITICAL", 9.8),
  vuln("CVE-2023-1111", "HIGH", 7.5),
  vuln("CVE-2023-2222", "MEDIUM", 5.3),
  vuln("CVE-2023-3333", "LOW", 3.1),
];

// What the SBOM list really looks like: `version` is the document's own spec
// version (apps/api/internal/service/sbom.go detectFormatAndVersion), so a
// project uploading CycloneDX repeatedly has the same string on every row.
export const SPEC_VERSION_SBOMS = [
  { id: SBOM_NEWEST, version: "1.5", created_at: "2026-08-01T00:00:00Z" },
  { id: SBOM_MIDDLE, version: "1.5", created_at: "2026-07-01T00:00:00Z" },
  { id: SBOM_OLDEST, version: "1.4", created_at: "2026-06-01T00:00:00Z" },
];

export const DIFF_RESULT = { added: ["log4j-core@2.17.1"], removed: [], changed: [] };

// Registered ("<METHOD> <echo path>") route keys — the form project_scope.go
// is keyed by.
export const K = {
  projects: "GET /api/v1/mcp/projects",
  dashboard: "GET /api/v1/mcp/dashboard/summary",
  searchCve: "GET /api/v1/mcp/search/cve",
  searchComponent: "GET /api/v1/mcp/search/component",
  diff: "POST /api/v1/mcp/sbom/diff",
  sboms: "GET /api/v1/mcp/projects/:id/sboms",
  vulns: "GET /api/v1/mcp/projects/:id/vulnerabilities",
  compliance: "GET /api/v1/mcp/projects/:id/compliance",
};

// Concrete paths for the project used by these cases.
export const P = {
  projects: "/api/v1/mcp/projects",
  dashboard: "/api/v1/mcp/dashboard/summary",
  searchCve: "/api/v1/mcp/search/cve",
  searchComponent: "/api/v1/mcp/search/component",
  diff: "/api/v1/mcp/sbom/diff",
  sboms: `/api/v1/mcp/projects/${PROJECT_ID}/sboms`,
  vulns: `/api/v1/mcp/projects/${PROJECT_ID}/vulnerabilities`,
  compliance: `/api/v1/mcp/projects/${PROJECT_ID}/compliance`,
};

const ok = (body, headers) => ({ status: 200, body, headers });

// A vulnerabilities endpoint carrying `total` rows, paged the way
// apps/api/internal/handler/sbom.go does (limit/offset + X-Total-Count).
export const pagedVulns = (total, severityAt = () => "CRITICAL") => (req) => {
  const offset = Number(req.query.offset ?? "0");
  const limit = Number(req.query.limit ?? "500");
  const rows = [];
  for (let i = offset; i < Math.min(offset + limit, total); i += 1) {
    rows.push(vuln(`CVE-2026-${10000 + i}`, severityAt(i), 9.1));
  }
  return ok(rows, { "X-Total-Count": String(total) });
};

const vulnsQuery = (offset, sort = "cvss") => ({
  limit: "500",
  offset: String(offset),
  sort,
});

/**
 * Every case: one tools/call, the stub routes it may use, and the exact
 * requests it must produce.
 *
 *   tool        registered tool name
 *   title       what this case pins
 *   args        tools/call arguments
 *   routes      stub responder, keyed by route key
 *   expect      ordered list of {method, path, query} that must be observed
 *   unordered   compare `expect` as a set (concurrent fan-out)
 *   expectError RegExp the error text must match (default: must NOT be an error)
 *   check       extra assertions over {payload, requests, result}
 */
export const CONTRACT_CASES = [
  {
    tool: "sbomhub_list_projects",
    title: "reads the project enumeration and returns it verbatim",
    args: {},
    routes: { [K.projects]: ok(PROJECTS) },
    expect: [{ method: "GET", path: P.projects, query: {} }],
    check({ payload }) {
      // Verbatim: the tool must not re-shape, count or summarise the list.
      // "件数からテナントの規模を推測しないこと" is only honest if the model
      // sees the same rows the API returned.
      assert.deepEqual(payload, PROJECTS);
    },
  },

  {
    tool: "sbomhub_get_dashboard",
    title: "reads the tenant-wide summary route and nothing else",
    args: {},
    routes: { [K.dashboard]: ok(DASHBOARD) },
    expect: [{ method: "GET", path: P.dashboard, query: {} }],
    check({ payload }) {
      assert.deepEqual(payload, DASHBOARD);
    },
  },

  {
    tool: "sbomhub_get_project_dashboard",
    title: "composes the per-project view from three project-scoped routes",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      [K.compliance]: ok(COMPLIANCE),
      [K.sboms]: ok(SBOMS),
    },
    // Promise.all fan-out: assert the SET, not the order.
    unordered: true,
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.compliance, query: {} },
      { method: "GET", path: P.sboms, query: {} },
    ],
    check({ payload }) {
      assert.equal(payload.project_id, PROJECT_ID);
      assert.equal(payload.sboms.count, SBOMS.length);
      // Newest-first is load-bearing: `latest` is just [0].
      assert.equal(payload.sboms.latest.id, SBOM_NEWEST);
      assert.equal(payload.vulnerabilities.total, VULNS.length);
      assert.equal(payload.vulnerabilities.analyzed, VULNS.length);
      assert.equal(payload.vulnerabilities.scan_truncated, false);
      assert.deepEqual(payload.vulnerabilities.by_severity, {
        CRITICAL: 2,
        HIGH: 1,
        MEDIUM: 1,
        LOW: 1,
      });
      assert.deepEqual(payload.compliance, COMPLIANCE);
    },
  },

  {
    tool: "sbomhub_get_project_dashboard",
    title: "a project too large to walk fully reports the truncation it inherits",
    args: { project_id: PROJECT_ID },
    routes: {
      // The dashboard runs the SAME capped walk as sbomhub_get_vulnerabilities,
      // and surfaces the flag one level down (vulnerabilities.scan_truncated).
      // A truncation that is only visible at a nested path is still a partial
      // answer shaped like a whole one (Codex R2, High).
      [K.vulns]: pagedVulns(6000, (i) => (i % 3 === 0 ? "CRITICAL" : "HIGH")),
      [K.compliance]: ok(COMPLIANCE),
      [K.sboms]: ok(SBOMS),
    },
    unordered: true,
    expect: [
      ...Array.from({ length: 10 }, (_, i) => ({
        method: "GET",
        path: P.vulns,
        query: vulnsQuery(i * 500),
      })),
      { method: "GET", path: P.compliance, query: {} },
      { method: "GET", path: P.sboms, query: {} },
    ],
    check({ payload }) {
      assert.equal(payload.vulnerabilities.total, 6000);
      assert.equal(payload.vulnerabilities.analyzed, 5000);
      assert.equal(payload.vulnerabilities.scan_truncated, true);
      // by_severity counts the ANALYZED rows, not the project.
      const counted = Object.values(payload.vulnerabilities.by_severity).reduce(
        (a, b) => a + b,
        0
      );
      assert.equal(counted, 5000);
    },
  },

  {
    tool: "sbomhub_list_sboms",
    title: "returns the project's SBOMs in the order the API served them",
    args: { project_id: PROJECT_ID },
    routes: { [K.sboms]: ok(SBOMS) },
    expect: [{ method: "GET", path: P.sboms, query: {} }],
    check({ payload }) {
      // The description says 「新しい順」. The client does not sort, so what it
      // must not do is REORDER: the order it emits is the order the backend's
      // `ORDER BY created_at DESC` produced.
      assert.deepEqual(payload, SBOMS);
    },
  },

  {
    tool: "sbomhub_list_sboms",
    title: "a nil slice (JSON null) becomes an empty list, not the string null",
    args: { project_id: PROJECT_ID },
    routes: { [K.sboms]: ok(null) },
    expect: [{ method: "GET", path: P.sboms, query: {} }],
    check({ payload }) {
      assert.deepEqual(payload, []);
    },
  },

  {
    tool: "sbomhub_search_cve",
    title: "searches tenant-wide by CVE id in ?q=, with no project filter",
    args: { cve_id: "CVE-2021-44228" },
    routes: { [K.searchCve]: ok({ cve_id: "CVE-2021-44228", affected_projects: [] }) },
    expect: [
      { method: "GET", path: P.searchCve, query: { q: "CVE-2021-44228" } },
    ],
  },

  {
    tool: "sbomhub_search_cve",
    title: "the lowercase spelling the schema advertises reaches the API unchanged",
    args: { cve_id: "cve-2021-44228" },
    routes: { [K.searchCve]: ok({ affected_projects: [] }) },
    expect: [
      { method: "GET", path: P.searchCve, query: { q: "cve-2021-44228" } },
    ],
  },

  {
    tool: "sbomhub_search_component",
    title: "searches tenant-wide by name; version is omitted when not given",
    args: { name: "log4j" },
    routes: { [K.searchComponent]: ok({ matches: [] }) },
    expect: [
      { method: "GET", path: P.searchComponent, query: { name: "log4j" } },
    ],
  },

  {
    tool: "sbomhub_search_component",
    title: "passes the optional version through as ?version=",
    args: { name: "log4j", version: "2.14.1" },
    routes: { [K.searchComponent]: ok({ matches: [] }) },
    expect: [
      {
        method: "GET",
        path: P.searchComponent,
        query: { name: "log4j", version: "2.14.1" },
      },
    ],
  },

  {
    tool: "sbomhub_diff",
    title: "with versions omitted, diffs the newest two SBOMs (base = 2nd newest)",
    args: { project_id: PROJECT_ID },
    routes: { [K.sboms]: ok(SBOMS), [K.diff]: ok(DIFF_RESULT) },
    expect: [
      { method: "GET", path: P.sboms, query: {} },
      { method: "POST", path: P.diff, query: {} },
    ],
    check({ requests, payload }) {
      // 「バージョン省略時は最新2つを比較」 — and in the right direction:
      // target is the newest, base the one before it.
      assert.deepEqual(requests[1].body, {
        base_sbom_id: SBOM_MIDDLE,
        target_sbom_id: SBOM_NEWEST,
      });
      assert.deepEqual(payload, DIFF_RESULT);
    },
  },

  {
    tool: "sbomhub_diff",
    title: "explicit SBOM ids select the snapshots, ignoring their versions",
    args: {
      project_id: PROJECT_ID,
      base_sbom_id: SBOM_OLDEST,
      target_sbom_id: SBOM_MIDDLE,
    },
    // The realistic shape: `version` is the CycloneDX/SPDX SPEC version, so
    // every snapshot of a project reads the same. Ids are the only selector
    // that identifies one (Codex R4).
    routes: { [K.sboms]: ok(SPEC_VERSION_SBOMS), [K.diff]: ok(DIFF_RESULT) },
    expect: [
      { method: "GET", path: P.sboms, query: {} },
      { method: "POST", path: P.diff, query: {} },
    ],
    check({ requests }) {
      assert.deepEqual(requests[1].body, {
        base_sbom_id: SBOM_OLDEST,
        target_sbom_id: SBOM_MIDDLE,
      });
    },
  },

  {
    tool: "sbomhub_diff",
    title: "named versions are resolved to SBOM ids before the diff POST",
    args: { project_id: PROJECT_ID, base_version: "1.0.0", target_version: "2.0.0" },
    routes: { [K.sboms]: ok(SBOMS), [K.diff]: ok(DIFF_RESULT) },
    expect: [
      { method: "GET", path: P.sboms, query: {} },
      { method: "POST", path: P.diff, query: {} },
    ],
    check({ requests }) {
      assert.deepEqual(requests[1].body, {
        base_sbom_id: SBOM_OLDEST,
        target_sbom_id: SBOM_NEWEST,
      });
      // The description explains the refusal by "対象SBOMをbodyのUUIDで選ぶ":
      // the body must carry SBOM ids and no project id.
      assert.equal(requests[1].rawBody.includes(PROJECT_ID), false);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "one page, default sort=cvss, no server-side severity parameter",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
    },
    expect: [{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
    check({ payload }) {
      assert.equal(payload.total_in_project, VULNS.length);
      assert.equal(payload.scanned, VULNS.length);
      assert.equal(payload.scan_truncated, false);
      assert.equal(payload.sort, "cvss");
      assert.equal(payload.severity_filter, null);
      assert.equal(payload.matched, VULNS.length);
      assert.equal(payload.returned, VULNS.length);
      assert.deepEqual(payload.vulnerabilities, VULNS);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "severity narrows the RESULT client-side and says so in the payload",
    args: { project_id: PROJECT_ID, severity: "critical" },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
    },
    // The backend has no severity parameter — the query must stay untouched.
    expect: [{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
    check({ payload }) {
      assert.equal(payload.severity_filter, "CRITICAL");
      assert.equal(payload.scanned, VULNS.length);
      assert.equal(payload.matched, 2);
      assert.equal(payload.returned, 2);
      assert.equal(
        payload.vulnerabilities.every((v) => v.severity === "CRITICAL"),
        true
      );
      // The narrowing is visible: the model can still see how much was scanned.
      assert.equal(payload.total_in_project, VULNS.length);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "sort=epss reaches the API as ?sort=epss",
    args: { project_id: PROJECT_ID, sort: "epss" },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
    },
    expect: [{ method: "GET", path: P.vulns, query: vulnsQuery(0, "epss") }],
    check({ payload }) {
      assert.equal(payload.sort, "epss");
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "pages at 500 and returns at most 500 rows (「最大500件」)",
    args: { project_id: PROJECT_ID, severity: "critical" },
    routes: {
      [K.vulns]: pagedVulns(1200, (i) => (i % 2 === 0 ? "CRITICAL" : "HIGH")),
    },
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ],
    check({ payload }) {
      assert.equal(payload.total_in_project, 1200);
      assert.equal(payload.scanned, 1200);
      assert.equal(payload.scan_truncated, false);
      assert.equal(payload.matched, 600);
      // The cap is on what is ECHOED; `matched` still covers the whole scan,
      // so a model reading `returned` as the count would be wrong and the
      // payload gives it the means to notice.
      assert.equal(payload.returned, 500);
      assert.equal(payload.vulnerabilities.length, 500);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "stops at the 5000-row scan cap and flags the truncation",
    args: { project_id: PROJECT_ID },
    routes: { [K.vulns]: pagedVulns(6000) },
    expect: Array.from({ length: 10 }, (_, i) => ({
      method: "GET",
      path: P.vulns,
      query: vulnsQuery(i * 500),
    })),
    check({ payload }) {
      assert.equal(payload.total_in_project, 6000);
      assert.equal(payload.scanned, 5000);
      // Silence here would be the same defect class as bad1b8c: an answer
      // covering 5000 of 6000 rows that reads as the whole project.
      assert.equal(payload.scan_truncated, true);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title:
      "a row count that is an exact multiple of the page size still needs a short page",
    args: { project_id: PROJECT_ID },
    // The walk stops on a SHORT page, not when the header's count is reached:
    // a header that under-reports must not be able to cut the scan short. The
    // price is one extra request here.
    routes: { [K.vulns]: pagedVulns(1000) },
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ],
    check({ payload }) {
      assert.equal(payload.scanned, 1000);
      assert.equal(payload.total_in_project, 1000);
      assert.equal(payload.scan_truncated, false);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "an X-Total-Count that under-reports cannot end the scan early",
    args: { project_id: PROJECT_ID },
    routes: {
      // 1200 rows, but every page claims the project has 500.
      [K.vulns]: (req) => {
        const reply = pagedVulns(1200)(req);
        return { ...reply, headers: { "X-Total-Count": "500" } };
      },
    },
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ],
    check({ payload }) {
      assert.equal(payload.scanned, 1200);
      // Report what is known to exist, not the smaller claim.
      assert.equal(payload.total_in_project, 1200);
      assert.equal(payload.scan_truncated, false);
    },
  },

  {
    tool: "sbomhub_get_compliance",
    title: "reads the project's compliance route",
    args: { project_id: PROJECT_ID },
    routes: { [K.compliance]: ok(COMPLIANCE) },
    expect: [{ method: "GET", path: P.compliance, query: {} }],
    check({ payload }) {
      assert.deepEqual(payload, COMPLIANCE);
    },
  },
];

/** tool name → the route keys its cases declare. */
export function declaredRouteKeysByTool() {
  const byTool = new Map();
  for (const c of CONTRACT_CASES) {
    const keys = byTool.get(c.tool) ?? new Set();
    for (const e of c.expect) {
      keys.add(`${e.method} ${routePatternOf(e.path)}`);
    }
    byTool.set(c.tool, keys);
  }
  return byTool;
}

function routePatternOf(path) {
  return path.replace(PROJECT_ID, ":id");
}
