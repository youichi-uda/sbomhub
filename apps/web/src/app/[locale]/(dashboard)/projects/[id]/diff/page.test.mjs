// M10-6 (#74) — pure-helper regression tests for the SBOM diff page.
//
// Why .test.mjs (not .test.tsx): the apps/web workspace does not ship a
// React component test runner (no Vitest, no Jest, no React Testing
// Library). diff-helpers.ts is plain TypeScript with no imports, so Node's
// built-in type stripping (Node >= 22.18) loads it directly — the same
// mechanism the form-schema pins use.
//
// 2026-11: until this revision the file re-implemented each helper inline
// and only grep-checked that diff-helpers.ts still exported the names, so
// the assertions exercised copies, never the production code. It was also
// never wired into CI, and `node --test <path>` with this path collects 0
// tests: node --test treats its arguments as glob patterns, and `[locale]`
// / `[id]` are glob character classes that do not match the literal
// directory names. It now imports the real helpers and runs as part of
// `pnpm --filter web test` (a `src/**/*.test.mjs` glob, which matches the
// bracketed directories as ordinary path segments).
//
// Run:
//   pnpm --filter web test
//   node "apps/web/src/app/[locale]/(dashboard)/projects/[id]/diff/page.test.mjs"

import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildDiffQuery,
  diffCounts,
  isInitialBaseline,
  normaliseSeverity,
} from "./diff-helpers.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));

// buildDiffQuery contract: round-trip the query-string format that the
// timeline rows feed into <Link href={...}>. The page consumes this
// pattern in TimelineRowView.detailHref — a regression here breaks the
// click-through from timeline to detail.
test("buildDiffQuery is empty when both args missing", () => {
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
  assert.equal(normaliseSeverity("CRITICAL"), "critical");
  assert.equal(normaliseSeverity("critical"), "critical");
  assert.equal(normaliseSeverity("High"), "high");
  assert.equal(normaliseSeverity("MEDIUM"), "medium");
  assert.equal(normaliseSeverity("low"), "low");
  assert.equal(normaliseSeverity("  High "), "high", "trims whitespace");
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

// Codex R1 Medium (react-query migration): within detail mode the previous
// diff stays on screen while a new (from, to) pair loads and after it fails
// — what the state-based loader did — but it is dropped on leaving detail
// mode and never shown for another project.
test("retainDetail keeps the last diff across pair changes inside detail mode only", async () => {
  const { retainDetail } = await import("./diff-helpers.ts");
  const A = { id: "A" };
  const B = { id: "B" };
  let r = retainDetail(null, { detailMode: true, projectId: "p1", data: A });
  assert.deepEqual(r, { projectId: "p1", data: A });
  // pair change: new key has no data yet (loading) or failed -> keep A
  assert.equal(retainDetail(r, { detailMode: true, projectId: "p1", data: undefined }), r);
  // new pair resolves -> B
  r = retainDetail(r, { detailMode: true, projectId: "p1", data: B });
  assert.deepEqual(r, { projectId: "p1", data: B });
  // leaving detail mode clears
  assert.equal(retainDetail(r, { detailMode: false, projectId: "p1", data: undefined }), null);
  // another project never inherits it
  assert.equal(
    retainDetail({ projectId: "p1", data: A }, { detailMode: true, projectId: "p2", data: undefined }),
    null,
  );
});
