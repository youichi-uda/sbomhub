// Pins src/lib/query/cra-report-cache.ts (Codex R1 Medium on M65 bug 2):
// optimistic edits and rollbacks touch only their own report, so a failed
// older action can never resurrect a row a newer action removed.
//
// Run: node --test src/lib/query/__tests__/cra-report-cache.test.mjs
import assert from "node:assert/strict";
import { test } from "node:test";

import { applyPendingOps, withoutReport, withReportState } from "../cra-report-cache.ts";

const A = { id: "A", state: "draft" };
const B = { id: "B", state: "draft" };
const C = { id: "C", state: "draft" };
const ids = (p) => p.data.map((r) => r.id);

test("A fails after B succeeded: B stays hidden, A is shown again", () => {
  // Overlay while both are in flight.
  const server = { data: [A, B, C], totalCount: 3 };
  let ops = new Map([["A", { kind: "remove" }], ["B", { kind: "remove" }]]);
  assert.deepEqual(ids(applyPendingOps(server, ops)), ["C"]);
  // B succeeds; its refetch says the server still has A (pending) and C.
  const afterB = { data: [A, C], totalCount: 2 };
  ops = new Map([["A", { kind: "remove" }]]);
  assert.deepEqual(ids(applyPendingOps(afterB, ops)), ["C"]);
  // A fails: its op is dropped, nothing else changes.
  ops = new Map();
  assert.deepEqual(ids(applyPendingOps(afterB, ops)), ["A", "C"]);
});

test("removing an absent row is a no-op; undefined pages pass through", () => {
  assert.equal(withoutReport(undefined, "A"), undefined);
  const p = { data: [B], totalCount: 1 };
  assert.equal(withoutReport(p, "A"), p);
  assert.deepEqual(withoutReport({ data: [A, B], totalCount: 2 }, "A"), { data: [B], totalCount: 1 });
});

test("state edit touches one row only", () => {
  const page = withReportState({ data: [A, B], totalCount: 2 }, "B", "submitted");
  assert.deepEqual(page.data.map((r) => r.state), ["draft", "submitted"]);
  assert.equal(withReportState(undefined, "B", "x"), undefined);
});

// Codex R2 Medium: a refresh (or another action's invalidation) that lands
// while an action is in flight returns the pre-action rows. The page keeps
// in-flight actions as an overlay applied to every fetched page, so such a
// response can never resurrect a decided row or revert "submitted".
test("pending overlay is re-applied to a stale refetch", async () => {
  const stale = { data: [A, B, C], totalCount: 3 };
  const ops = new Map([
    ["A", { kind: "remove" }],
    ["C", { kind: "state", state: "submitted" }],
  ]);
  const shown = applyPendingOps(stale, ops);
  assert.deepEqual(ids(shown), ["B", "C"]);
  assert.equal(shown.totalCount, 2);
  assert.equal(shown.data[1].state, "submitted");
  // Settled (op dropped) -> the server's answer is shown as is.
  assert.equal(applyPendingOps(stale, new Map()), stale);
  assert.equal(applyPendingOps(undefined, ops), undefined);
});
