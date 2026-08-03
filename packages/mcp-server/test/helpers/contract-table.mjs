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

import { registeredPathFor } from "./backend-scope.mjs";

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

/**
 * The per-severity buckets apps/api would report for a set of rows.
 *
 * The client compares the WHOLE summary across the walk, so a fixture whose
 * probe reports zero in every bucket while the pages return five rows of four
 * severities is evidence that cannot describe the walk it certifies (Codex R5,
 * Low) — the same shape as the `total: 0` default that preceded it.
 */
export const bucketsOf = (rows) => {
  const out = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, kev: 0 };
  for (const r of rows) {
    const key = (r.severity ?? "unknown").toLowerCase();
    if (key in out) out[key] += 1;
    else out.unknown += 1;
  }
  return out;
};

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
//
// `latestSbom` / `scanStatus` are NOT under /api/v1/mcp/. They are canonical
// (MultiAuth) routes, classified scopeProjectPathParam like every other
// per-project route here, and they are what lets a tool say whether the counts
// it just read came from a finished scan.
export const K = {
  projects: "GET /api/v1/mcp/projects",
  dashboard: "GET /api/v1/mcp/dashboard/summary",
  searchCve: "GET /api/v1/mcp/search/cve",
  searchComponent: "GET /api/v1/mcp/search/component",
  diff: "POST /api/v1/mcp/sbom/diff",
  sboms: "GET /api/v1/mcp/projects/:id/sboms",
  vulns: "GET /api/v1/mcp/projects/:id/vulnerabilities",
  compliance: "GET /api/v1/mcp/projects/:id/compliance",
  latestSbom: "GET /api/v1/projects/:id/sbom",
  scanStatus: "GET /api/v1/projects/:id/sboms/:sbom_id/scan-status",
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
  latestSbom: `/api/v1/projects/${PROJECT_ID}/sbom`,
  scanStatus: `/api/v1/projects/${PROJECT_ID}/sboms/${SBOM_NEWEST}/scan-status`,
};

const ok = (body, headers) => ({ status: 200, body, headers });

// apps/api/internal/handler/sbom.go ScanStatusResponse. `status` is
// service.ScanState: running | completed | failed | unknown. `total` is a COUNT
// over the same join the vulnerability pages come from, which is what the
// client compares across the walk to notice a scan that moved.
export const scanStatusBody = (
  status,
  { total = 0, sbomId = SBOM_NEWEST, buckets = {} } = {}
) => ({
  status,
  sbom_id: sbomId,
  project_id: PROJECT_ID,
  // The client compares this WHOLE object across the walk, not just `total`: a
  // vulnerability relabelled LOW -> CRITICAL mid-walk leaves the total untouched
  // while making by_severity and any severity filter stale (Codex R4, High).
  // `buckets` lets a case move one without moving the total.
  vulnerabilities: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
    kev: 0,
    ...buckets,
    total,
  },
});

/**
 * The scan-state probe, as the stub sees it.
 *
 * The client BRACKETS the page walk: it reads the state before the first page
 * and, only if that read said `completed`, again after the last one. Two probes
 * x two requests each (resolve the project's latest SBOM, then ask for that
 * SBOM's scan state) = four requests when the answer can be final, two when it
 * cannot.
 *
 * `scanProbe(state, opts)` answers both probes identically, which is the
 * "nothing moved" case. `scanProbeChanging` answers them differently.
 * `withProbes` / `LATEST_SBOM_ONLY` are the matching observed sides. Shared
 * rather than repeated so a change to the probe cannot be applied to some cases
 * and forgotten in others.
 */
export const scanProbe = (state = "completed", { total, ...rest } = {}) => {
  // `total` is required for a case whose walk returns rows (Codex R3, Low): the
  // probe's count is a COUNT over the same join the pages come from, so a probe
  // saying 0 while the pages return five rows certifies an answer with evidence
  // that cannot describe it. Defaulting it silently to 0 hid that.
  if (total === undefined) {
    throw new Error(
      "scanProbe requires an explicit `total` — it must match the row count the " +
        "case's vulnerability route serves, or the fixture certifies a walk with a " +
        "probe that contradicts it"
    );
  }
  return {
    [K.latestSbom]: ok(SBOMS[0]),
    [K.scanStatus]: ok(scanStatusBody(state, { total, ...rest })),
  };
};

/**
 * A probe whose two readings differ: `first` is served until the walk's pages
 * have been requested, `second` afterwards. Keyed off the arrival index the stub
 * records, so it does not need to know how many pages the case walks.
 */
export const scanProbeChanging = (first, second) => {
  // `first` / `second` are {state, total, sbomId?, buckets?}.
  let latestReads = 0;
  let statusReads = 0;
  const at = (n, side) => (n === 0 ? first : second)[side];
  return {
    [K.latestSbom]: () => {
      const id = at(latestReads, "sbomId") ?? SBOM_NEWEST;
      latestReads += 1;
      return ok({ ...SBOMS[0], id });
    },
    [K.scanStatus]: (req) => {
      const which = statusReads === 0 ? first : second;
      statusReads += 1;
      // Echo back the sbom_id that was asked for, as the handler does — so the
      // client's own "did the backend answer about the SBOM I named" check
      // passes and the case tests what it says it tests.
      const asked = req.path.split("/").at(-2);
      return ok(
        scanStatusBody(which.state, {
          total: which.total ?? 0,
          sbomId: asked,
          buckets: which.buckets ?? {},
        })
      );
    },
  };
};

const probeRequests = () => [
  { method: "GET", path: P.latestSbom, query: {} },
  { method: "GET", path: P.scanStatus, query: {} },
];

/**
 * The observed request list for a tool call: the BEFORE probe, the page walk,
 * then the AFTER probe.
 *
 * `after: false` is the shape of every case whose first reading was not
 * `completed` — no second reading is taken, because nothing it could say would
 * make a non-completed answer final.
 */
export const withProbes = (pages, { after = true } = {}) => [
  ...probeRequests(),
  ...pages,
  ...(after ? probeRequests() : []),
];

/** The BEFORE probe alone, for a case where resolving the latest SBOM fails. */
export const LATEST_SBOM_ONLY = [{ method: "GET", path: P.latestSbom, query: {} }];

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
      ...scanProbe("completed", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    // Promise.all fan-out: assert the SET, not the order.
    unordered: true,
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.compliance, query: {} },
      { method: "GET", path: P.sboms, query: {} },
      ...withProbes([]),
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
      // The finality fields are part of this payload too, and asserting them
      // here is what makes the probe fixture load-bearing rather than decorative.
      assert.equal(payload.vulnerabilities.scan_state, "completed");
      assert.equal(payload.vulnerabilities.counts_final, true);
      assert.equal(payload.vulnerabilities.scanned_sbom_id, SBOM_NEWEST);
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
      ...scanProbe("completed", { total: 6000 }),
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
      ...withProbes([]),
    ],
    check({ payload }) {
      assert.equal(payload.vulnerabilities.total, 6000);
      assert.equal(payload.vulnerabilities.analyzed, 5000);
      assert.equal(payload.vulnerabilities.scan_truncated, true);
      // The dashboard inherits the same rule, one level down.
      assert.equal(payload.vulnerabilities.counts_final, false);
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
      ...scanProbe("completed", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }]),
    check({ payload }) {
      assert.equal(payload.total_in_project, VULNS.length);
      assert.equal(payload.scanned, VULNS.length);
      assert.equal(payload.scan_truncated, false);
      assert.equal(payload.sort, "cvss");
      assert.equal(payload.severity_filter, null);
      assert.equal(payload.matched, VULNS.length);
      assert.equal(payload.returned, VULNS.length);
      assert.deepEqual(payload.vulnerabilities, VULNS);
      // The positive pole of the scan-state rule. Without a case that observes
      // counts_final=true, a client hardcoding `false` would satisfy every
      // "must not claim final" assertion below.
      assert.equal(payload.scan_state, "completed");
      assert.equal(payload.counts_final, true);
      assert.equal(payload.scanned_sbom_id, SBOM_NEWEST);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "severity narrows the RESULT client-side and says so in the payload",
    args: { project_id: PROJECT_ID, severity: "critical" },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      ...scanProbe("completed", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    // The backend has no severity parameter — the query must stay untouched.
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }]),
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
      ...scanProbe("completed", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0, "epss") }]),
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
      ...scanProbe("completed", { total: 1200 }),
    },
    expect: withProbes([
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ]),
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
    routes: { [K.vulns]: pagedVulns(6000), ...scanProbe("completed", { total: 6000 }) },
    expect: withProbes(
      Array.from({ length: 10 }, (_, i) => ({
        method: "GET",
        path: P.vulns,
        query: vulnsQuery(i * 500),
      }))
    ),
    check({ payload }) {
      assert.equal(payload.total_in_project, 6000);
      assert.equal(payload.scanned, 5000);
      // Silence here would be the same defect class as bad1b8c: an answer
      // covering 5000 of 6000 rows that reads as the whole project.
      assert.equal(payload.scan_truncated, true);
      // ...and a settled SCAN is not enough to call those numbers final: they
      // are a prefix of the project. Under ?sort=epss the prefix is not even
      // stable — an EPSS sync can demote rows past the cap between pages, so
      // rows inside the intended range are never requested and no per-page
      // guard fires (Codex R2, Medium). The scan-status probe says `completed`
      // in this case; counts_final must still be false.
      assert.equal(payload.scan_state, "completed");
      assert.equal(payload.counts_final, false);
      assert.equal(payload.scanned_sbom_id, null);
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
    routes: { [K.vulns]: pagedVulns(1000), ...scanProbe("completed", { total: 1000 }) },
    expect: withProbes([
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ]),
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
      ...scanProbe("completed", { total: 1200 }),
    },
    expect: withProbes([
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.vulns, query: vulnsQuery(500) },
      { method: "GET", path: P.vulns, query: vulnsQuery(1000) },
    ]),
    check({ payload }) {
      assert.equal(payload.scanned, 1200);
      // Report what is known to exist, not the smaller claim.
      assert.equal(payload.total_in_project, 1200);
      assert.equal(payload.scan_truncated, false);
    },
  },

  // -------------------------------------------------------------------------
  // The asynchronous scan.
  //
  // apps/api starts the NVD/JVN scan in a goroutine after an SBOM upload and
  // tracks its state per SBOM (service.ScanTracker). Until this wave the MCP
  // server could not see that state, so a project whose scan was still running
  // answered with exactly the payload a finished one produces — "0
  // vulnerabilities" from a just-uploaded SBOM was byte-identical to "this
  // project is clean". The cases below pin the four shapes the tool must
  // distinguish, and in every one of them the requirement is the same: the
  // model must not be able to read a non-final count as a final one.
  // -------------------------------------------------------------------------
  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a scan still RUNNING is reported as running, and its counts as not final",
    args: { project_id: PROJECT_ID },
    routes: {
      // The dangerous shape: an empty result set from a scan that has barely
      // started. Byte-identical to a clean project unless the state is read.
      [K.vulns]: ok([], { "X-Total-Count": "0" }),
      ...scanProbe("running", { total: 0 }),
    },
    // One probe, not two: the first reading already settles the answer, so the
    // client does not spend two more requests confirming a `false` it has.
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload }) {
      assert.equal(payload.total_in_project, 0);
      assert.equal(payload.scan_state, "running");
      assert.equal(
        payload.counts_final,
        false,
        "a running scan's counts were reported as final — this is the defect the " +
          "whole scan-status probe exists to close"
      );
      // The model needs to know WHICH snapshot the counts describe, not just
      // that they are provisional: two uploads in flight produce two answers.
      assert.equal(payload.scanned_sbom_id, SBOM_NEWEST);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a scan the tracker no longer remembers (unknown) is not reported as final",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      ...scanProbe("unknown", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload }) {
      // ScanTracker is in-process with a 1h retention, so `unknown` is what an
      // API restart or any upload older than an hour produces. It means "no
      // record", which is not evidence of completion — mapping it to final
      // would make the common steady-state case the unsafe one.
      assert.equal(payload.scan_state, "unknown");
      assert.equal(payload.counts_final, false);
      assert.equal(payload.scanned, VULNS.length);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a FAILED scan is reported as failed, not as a finished one",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      ...scanProbe("failed", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload }) {
      assert.equal(payload.scan_state, "failed");
      assert.equal(payload.counts_final, false);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a project whose latest SBOM cannot be resolved does not let 0 read as clean",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok([], { "X-Total-Count": "0" }),
      // apps/api answers 404 here for a project that has no SBOM, for a project
      // that does not exist, AND for any repository error on the way — the
      // handler maps every failure to that one status. So the client reports
      // `unavailable` rather than naming one of the three (Codex R1, Low): a
      // state called "no SBOM" would be a claim this response cannot support.
      [K.latestSbom]: { status: 404, body: { error: "sbom not found" } },
    },
    expect: [
      // Only the latest-SBOM lookup: it failed, so there is no sbom_id to ask
      // scan-status about, and the answer is already non-final.
      ...LATEST_SBOM_ONLY,
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
    ],
    check({ payload }) {
      assert.equal(payload.scan_state, "unavailable");
      assert.equal(payload.counts_final, false);
      assert.equal(payload.scanned_sbom_id, null);
      assert.equal(payload.total_in_project, 0);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "an unreachable scan-status degrades to 'unavailable', never to 'finished'",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      [K.latestSbom]: ok(SBOMS[0]),
      // A backend that predates e84142c answers 401 here, because it does not
      // read X-API-Key on the canonical routes. That is the realistic failure
      // and it must not silently become a claim of completeness — the tool
      // still answers with the vulnerabilities, it just cannot vouch for them.
      [K.scanStatus]: { status: 401, body: { error: "missing authorization header" } },
    },
    // The BEFORE probe already failed, so there is no second one.
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload, result }) {
      assert.notEqual(result.isError, true, "the vulnerability data is still usable");
      assert.equal(payload.scan_state, "unavailable");
      assert.equal(payload.counts_final, false);
      assert.equal(payload.scanned, VULNS.length);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a scan that FINISHES during the walk does not certify the rows already read",
    args: { project_id: PROJECT_ID },
    routes: {
      // The rows are what a still-running scan had matched: none.
      [K.vulns]: ok([], { "X-Total-Count": "0" }),
      // ...and the scan completes while they are being read. A client that only
      // probed AFTERWARDS would see `completed` and stamp counts_final on an
      // empty answer — the original defect with a smaller window (Codex R1,
      // High). Bracketing the walk is what catches it: the first reading was
      // not `completed`, so nothing later can make the answer final.
      ...scanProbeChanging(
        { state: "running", total: 0 },
        { state: "completed", total: 41 }
      ),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload }) {
      assert.equal(payload.total_in_project, 0);
      assert.equal(
        payload.counts_final,
        false,
        "an empty answer read from a scan that was still running was reported as final"
      );
      assert.equal(payload.scan_state, "running");
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a rescan that moves the count during the walk is reported as changed",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      // Both readings say `completed`, and that is exactly the case the state
      // alone cannot resolve: apps/api's manual rescan path never marks the
      // ScanTracker, and entries are kept an hour, so an SBOM being rescanned
      // still reads `completed`. The COUNT is what moves — it is a COUNT over
      // the same join the pages come from.
      ...scanProbeChanging(
        { state: "completed", total: VULNS.length, buckets: bucketsOf(VULNS) },
        { state: "completed", total: VULNS.length + 3, buckets: bucketsOf(VULNS) }
      ),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }]),
    check({ payload }) {
      assert.equal(payload.scan_state, "changed");
      assert.equal(
        payload.counts_final,
        false,
        "the vulnerability set moved while it was being read, and the answer was still " +
          "reported as settled"
      );
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "an upload that becomes the latest SBOM during the walk is reported as changed",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      // Both readings say `completed` with the same count — but of DIFFERENT
      // SBOMs. Every vulnerability page is answered against whatever is latest
      // at that moment, so the rows cannot be attributed to either snapshot.
      ...scanProbeChanging(
        { state: "completed", total: VULNS.length, sbomId: SBOM_NEWEST, buckets: bucketsOf(VULNS) },
        { state: "completed", total: VULNS.length, sbomId: SBOM_MIDDLE, buckets: bucketsOf(VULNS) }
      ),
    },
    expect: [
      { method: "GET", path: P.latestSbom, query: {} },
      { method: "GET", path: P.scanStatus, query: {} },
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.latestSbom, query: {} },
      {
        method: "GET",
        path: `/api/v1/projects/${PROJECT_ID}/sboms/${SBOM_MIDDLE}/scan-status`,
        query: {},
      },
    ],
    check({ payload }) {
      assert.equal(payload.scan_state, "changed");
      assert.equal(payload.counts_final, false);
      // NULL, not either id: the two readings named different SBOMs and the
      // pages were answered somewhere in between, so naming one would assert an
      // origin for rows that may have come from the other (Codex R2, Medium).
      assert.equal(payload.scanned_sbom_id, null);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a scan-status body missing the severity buckets is unreadable, not final",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      [K.latestSbom]: { status: 200, body: SBOMS[0] },
      // handler.VulnerabilitySummaryCount marshals all seven fields
      // unconditionally, so a body without them did not come from this API. If
      // the schema required only `total`, this would parse, compare equal across
      // both readings, and be certified — having compared no per-severity
      // summary at all (Codex R5, Medium). Refusing to read it is fail-closed.
      [K.scanStatus]: {
        status: 200,
        body: {
          status: "completed",
          sbom_id: SBOM_NEWEST,
          project_id: PROJECT_ID,
          vulnerabilities: { total: VULNS.length },
        },
      },
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload }) {
      assert.equal(payload.scan_state, "unavailable");
      assert.equal(payload.counts_final, false);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a severity rewritten during the walk is caught even though the total holds",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      // Same state, same SBOM, same TOTAL — one row moved from LOW to CRITICAL.
      // A KEV or CVSS sync does exactly this, and comparing only the total would
      // certify `by_severity` / a severity filter computed from the old labels
      // (Codex R4, High). The whole summary is compared, so it is caught.
      ...scanProbeChanging(
        { state: "completed", total: VULNS.length, buckets: { critical: 2, low: 1 } },
        { state: "completed", total: VULNS.length, buckets: { critical: 3, low: 0 } }
      ),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }]),
    check({ payload }) {
      assert.equal(payload.scan_state, "changed");
      assert.equal(payload.counts_final, false);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a backend state this client has never heard of is relayed, not certified",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      // Not one of service.ScanState's four. The client does not narrow the
      // status to an enum on purpose: a state added to apps/api later must
      // reach the model as itself rather than be rejected — and must not be
      // read as "finished", because only one literal is evidence of that.
      ...scanProbe("queued", { total: VULNS.length, buckets: bucketsOf(VULNS) }),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }],
      { after: false }),
    check({ payload, result }) {
      assert.notEqual(result.isError, true, "an unknown state is not a failure");
      assert.equal(payload.scan_state, "queued");
      assert.equal(payload.counts_final, false);
      assert.equal(payload.scanned, VULNS.length);
    },
  },

  {
    tool: "sbomhub_get_vulnerabilities",
    title: "a second probe that cannot be read leaves the answer uncertified",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok(VULNS, { "X-Total-Count": String(VULNS.length) }),
      [K.latestSbom]: ok(SBOMS[0]),
      // First reading fine, second unreachable. "It was finished when I started
      // and I cannot tell whether it still is" is not evidence that it is.
      [K.scanStatus]: (() => {
        let n = 0;
        return () => {
          n += 1;
          return n === 1
            ? {
                status: 200,
                body: scanStatusBody("completed", {
                  total: VULNS.length,
                  buckets: bucketsOf(VULNS),
                }),
              }
            : { status: 500, body: { error: "boom" } };
        };
      })(),
    },
    expect: withProbes([{ method: "GET", path: P.vulns, query: vulnsQuery(0) }]),
    check({ payload }) {
      assert.equal(payload.scan_state, "unavailable");
      assert.equal(payload.counts_final, false);
    },
  },

  {
    tool: "sbomhub_get_project_dashboard",
    title: "the dashboard carries the same scan state, one level down",
    args: { project_id: PROJECT_ID },
    routes: {
      [K.vulns]: ok([], { "X-Total-Count": "0" }),
      [K.compliance]: ok(COMPLIANCE),
      [K.sboms]: ok(SBOMS),
      ...scanProbe("running", { total: 0 }),
    },
    unordered: true,
    expect: [
      { method: "GET", path: P.vulns, query: vulnsQuery(0) },
      { method: "GET", path: P.compliance, query: {} },
      { method: "GET", path: P.sboms, query: {} },
      ...withProbes([], { after: false }),
    ],
    check({ payload }) {
      // Nested, for the same reason scan_truncated is: this tool composes the
      // vulnerability answer into a sub-object, and a flag that only exists at
      // the root would be lost exactly where the counts are shown.
      assert.equal(payload.vulnerabilities.scan_state, "running");
      assert.equal(payload.vulnerabilities.counts_final, false);
      assert.deepEqual(payload.vulnerabilities.by_severity, {});
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
  // Same fold the stub applies to observed traffic (stub-api.mjs), so the
  // DECLARED and OBSERVED route keys are produced by the same rule. A local
  // `.replace(PROJECT_ID, ":id")` would leave the scan-status path carrying a
  // raw SBOM uuid and the two sets could never compare equal.
  return registeredPathFor("GET", path) ?? path.replace(PROJECT_ID, ":id");
}
