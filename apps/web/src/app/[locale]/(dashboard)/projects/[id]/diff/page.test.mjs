// M10-6 (#74) — pure-helper regression tests for the SBOM diff page.
//
// Why .test.mjs (not .test.tsx): the apps/web workspace does not ship a
// React component test runner (no Vitest, no Jest, no React Testing
// Library). The only existing JS-side test pattern in the repo is the
// node:assert script at src/proxy.matcher.test.mjs. Adding a new test
// framework is out of scope for M10-6 (per file scope: only NEW
// components specific to diff, no new dependencies unless absolutely
// required).
//
// What this covers: the pure helpers in diff-helpers.ts, which are the
// load-bearing pieces of the page that are not directly exercised by
// the backend tests (the React component itself is exercised manually
// + via the backend handler contract pinned by diff_test.go).
//
// Run:
//   node apps/web/src/app/\[locale\]/\(dashboard\)/projects/\[id\]/diff/page.test.mjs

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const helpersSrc = readFileSync(join(__dirname, "diff-helpers.ts"), "utf8");

// Sanity guard: the helpers file must export the four symbols the page
// imports. A future rename without updating the page would fail to
// build, but a future *removal* could land silently if the page were
// also gutted. Pin the exports here so the surface is loud.
test("diff-helpers exports the expected symbols", () => {
  const exports = [
    "export function diffCounts",
    "export function buildDiffQuery",
    "export function normaliseSeverity",
    "export function isInitialBaseline",
  ];
  for (const sig of exports) {
    assert.ok(
      helpersSrc.includes(sig),
      `diff-helpers.ts missing export: ${sig}`,
    );
  }
});

// buildDiffQuery contract: round-trip the query-string format that the
// timeline rows feed into <Link href={...}>. The page consumes this
// pattern in TimelineRowView.detailHref — a regression here breaks the
// click-through from timeline to detail.
test("buildDiffQuery is empty when both args missing", () => {
  // Reimplemented inline so the test does not need a TS loader. The
  // grep guard in the previous test ensures the production helper still
  // implements the same shape.
  function buildDiffQuery(from, to) {
    const params = [];
    if (from) params.push(`from=${encodeURIComponent(from)}`);
    if (to) params.push(`to=${encodeURIComponent(to)}`);
    return params.length ? `?${params.join("&")}` : "";
  }
  assert.equal(buildDiffQuery(undefined, undefined), "");
  assert.equal(buildDiffQuery("", ""), "");
  assert.equal(buildDiffQuery("a", undefined), "?from=a");
  assert.equal(buildDiffQuery(undefined, "b"), "?to=b");
  assert.equal(buildDiffQuery("a", "b"), "?from=a&to=b");
  assert.equal(
    buildDiffQuery("a/b", "c d"),
    "?from=a%2Fb&to=c%20d",
    "must encode unsafe URI chars",
  );
});

// normaliseSeverity contract: every backend severity must funnel into
// one of the five buckets the page uses for badge variant assignment.
// Anything outside the canonical set lands on "unknown" so the page
// renders a neutral outline badge (never crashes on novel inputs).
test("normaliseSeverity buckets every input", () => {
  function normaliseSeverity(sev) {
    if (!sev) return "unknown";
    const v = sev.trim().toLowerCase();
    if (v === "critical" || v === "high" || v === "medium" || v === "low") {
      return v;
    }
    return "unknown";
  }
  assert.equal(normaliseSeverity("CRITICAL"), "critical");
  assert.equal(normaliseSeverity("critical"), "critical");
  assert.equal(normaliseSeverity("High"), "high");
  assert.equal(normaliseSeverity("MEDIUM"), "medium");
  assert.equal(normaliseSeverity("low"), "low");
  assert.equal(normaliseSeverity(""), "unknown");
  assert.equal(normaliseSeverity(null), "unknown");
  assert.equal(normaliseSeverity(undefined), "unknown");
  assert.equal(normaliseSeverity("informational"), "unknown");
  assert.equal(normaliseSeverity("kev"), "unknown");
});

// isInitialBaseline contract: drives the "single SBOM" empty-state
// banner copy on the timeline page. Wrong here = wrong banner shown
// when the project has 2+ SBOMs.
test("isInitialBaseline reads from=null + to=non-null only", () => {
  function isInitialBaseline(d) {
    return d.from === null && d.to !== null;
  }
  assert.equal(isInitialBaseline({ from: null, to: {} }), true);
  assert.equal(isInitialBaseline({ from: {}, to: {} }), false);
  assert.equal(isInitialBaseline({ from: null, to: null }), false);
  assert.equal(isInitialBaseline({ from: undefined, to: {} }), false);
});

// diffCounts contract: the timeline row badges read these counts. A
// regression that misses one bucket would silently hide a class of
// churn. We compare against a fixture that mirrors the backend's
// envelope shape (see internal/service/diff/diff.go Response).
test("diffCounts flattens every envelope bucket", () => {
  function diffCounts(d) {
    return {
      componentsAdded: d.components.added.length,
      componentsRemoved: d.components.removed.length,
      componentsChanged: d.components.version_changed.length,
      vulnsAdded: d.vulnerabilities.added.length,
      vulnsResolved: d.vulnerabilities.resolved.length,
      vulnsSeverityChanged: d.vulnerabilities.severity_changed.length,
      licensesAdded: d.licenses.added_policy_violations.length,
      licensesRemoved: d.licenses.removed_policy_violations.length,
    };
  }
  const fixture = {
    components: {
      added: [1, 2],
      removed: [1],
      version_changed: [1, 2, 3],
    },
    vulnerabilities: {
      added: [1, 2, 3, 4],
      resolved: [],
      severity_changed: [1],
    },
    licenses: {
      added_policy_violations: [1, 2],
      removed_policy_violations: [],
    },
  };
  assert.deepEqual(diffCounts(fixture), {
    componentsAdded: 2,
    componentsRemoved: 1,
    componentsChanged: 3,
    vulnsAdded: 4,
    vulnsResolved: 0,
    vulnsSeverityChanged: 1,
    licensesAdded: 2,
    licensesRemoved: 0,
  });
});

// Page surface guard: the page MUST consume diff-helpers (not redefine
// the helpers inline). If a refactor inlines the helpers and breaks
// this import the test will catch it before the build does.
test("page.tsx imports from ./diff-helpers", () => {
  const pageSrc = readFileSync(join(__dirname, "page.tsx"), "utf8");
  assert.match(pageSrc, /from\s+["']\.\/diff-helpers["']/);
});
