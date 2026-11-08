// Pins src/lib/query/cra-report-cache.ts (Codex R1 Medium on M65 bug 2):
// optimistic edits and rollbacks touch only their own report, so a failed
// older action can never resurrect a row a newer action removed.
//
// Run: node --test src/lib/query/__tests__/cra-report-cache.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import { withoutReport, withReportRestored, withReportState } from "../cra-report-cache.ts";

const A = { id: "A", state: "draft" };
const B = { id: "B", state: "draft" };
const C = { id: "C", state: "draft" };
const ids = (p) => p.data.map((r) => r.id);

test("A fails after B succeeded: B stays removed, A comes back at its index", () => {
  let page = { data: [A, B, C], totalCount: 3 };
  const aIndex = page.data.findIndex((r) => r.id === "A");
  page = withoutReport(page, "A"); // approve A (in flight)
  page = withoutReport(page, "B"); // approve B (succeeds)
  // B's refetch: server now has A (still pending server-side) and C.
  page = { data: [A, C], totalCount: 2 };
  page = withReportRestored(page, A, aIndex); // A fails -> already present
  assert.deepEqual(ids(page), ["A", "C"]);
  assert.equal(page.totalCount, 2);
});

test("A fails before any refetch: only A is restored, B's removal is kept", () => {
  let page = { data: [A, B, C], totalCount: 3 };
  page = withoutReport(page, "A");
  page = withoutReport(page, "B");
  page = withReportRestored(page, A, 0);
  assert.deepEqual(ids(page), ["A", "C"]);
  assert.equal(page.totalCount, 2);
});

test("restore index is clamped and undefined pages pass through", () => {
  assert.deepEqual(ids(withReportRestored({ data: [B], totalCount: 1 }, A, 5)), ["B", "A"]);
  assert.equal(withReportRestored(undefined, A, 0), undefined);
  assert.equal(withoutReport(undefined, "A"), undefined);
  const p = { data: [B], totalCount: 1 };
  assert.equal(withoutReport(p, "A"), p, "removing an absent row is a no-op");
});

test("state edit touches one row only", () => {
  const page = withReportState({ data: [A, B], totalCount: 2 }, "B", "submitted");
  assert.deepEqual(page.data.map((r) => r.state), ["draft", "submitted"]);
  assert.equal(withReportState(undefined, "B", "x"), undefined);
});
