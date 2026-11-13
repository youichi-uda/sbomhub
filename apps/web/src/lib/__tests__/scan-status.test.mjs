// The project page's view of the background scan (src/lib/scan-status.ts).
//
// Run: pnpm --filter web test
//
// What is pinned and why (integration Codex review, 2026-11-13, High): the
// project page rendered "No vulnerabilities found." whenever the list was
// empty, although right after an upload the scan may still be running, may
// have failed (MyJVN suspended: fetch_failed + source_unavailable), or may
// have completed without a source (SBOMHUB_JVN=off: skipped_sources ["jvn"]).
//   - only a `completed` scan of the latest SBOM may produce the plain
//     "no vulnerabilities" empty state; every other state (running, failed,
//     unknown, a status that could not be loaded, no SBOM, still checking)
//     has its own message;
//   - completed with skipped_sources is "partial", never plain clean;
//   - an unrecognised status string is unknown, never completed;
//   - reasons map to human messages, an unrecognised code is kept (as
//     "other") rather than dropped, and source_unavailable is recognised;
//   - polling runs only while running, and backs off;
//   - a settled status triggers a vulnerability refetch exactly when the
//     list on screen was requested before that status was.

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  countQualifierKey,
  emptyStateKey,
  latestAfterListRead,
  sameScanAnswer,
  parseScanStatus,
  pollIntervalMs,
  reasonItems,
  scanView,
  settleNeedsListRefetch,
  skippedSourceLabel,
} from "../scan-status.ts";

const FRESH = { failed: false, fresh: true };
const sbom = (id = "s1") => ({ pending: false, error: false, id });
const status = (data) => ({
  pending: false,
  error: false,
  data: parseScanStatus({ vulnerabilities: { total: 0 }, ...data }),
});

describe("parseScanStatus", () => {
  test("reads the API shape", () => {
    const s = parseScanStatus({
      status: "failed",
      sbom_id: "s1",
      project_id: "p1",
      error: "jvn: scan failed (fetch_failed, source_unavailable)",
      reasons: ["fetch_failed", "source_unavailable"],
      skipped_sources: [],
      vulnerabilities: { total: 3 },
    });
    assert.equal(s.status, "failed");
    assert.deepEqual(s.reasons, ["fetch_failed", "source_unavailable"]);
    assert.deepEqual(s.skippedSources, []);
    assert.equal(s.error, "jvn: scan failed (fetch_failed, source_unavailable)");
    assert.equal(s.total, 3);
  });
  // Codex R6: a settled answer without a usable total cannot be paired
  // with a list (and used to never settle): it reads as unknown.
  test("a completed / failed answer without a usable total is unknown", () => {
    for (const vulnerabilities of [undefined, {}, { total: "3" }, { total: -1 }, { total: 1.5 }]) {
      const c = parseScanStatus({ status: "completed", vulnerabilities, skipped_sources: ["jvn"] });
      assert.equal(c.status, "unknown", JSON.stringify(vulnerabilities));
      assert.equal(c.total, null);
      assert.deepEqual(c.skippedSources, []);
      assert.equal(parseScanStatus({ status: "failed", vulnerabilities, reasons: ["x"] }).status, "unknown");
    }
    assert.equal(parseScanStatus({ status: "running" }).status, "running");
  });
  test("an unrecognised or missing status is unknown, never completed", () => {
    assert.equal(parseScanStatus({ status: "done" }).status, "unknown");
    assert.equal(parseScanStatus({}).status, "unknown");
    assert.equal(parseScanStatus(null).status, "unknown");
    assert.equal(parseScanStatus("completed").status, "unknown");
  });
  test("non-string members of reasons / skipped_sources are dropped, absent lists are empty", () => {
    const s = parseScanStatus({ status: "failed", reasons: ["x", 3, null], skipped_sources: "jvn", vulnerabilities: { total: 0 } });
    assert.deepEqual(s.reasons, ["x"]);
    assert.deepEqual(s.skippedSources, []);
    assert.deepEqual(parseScanStatus({ status: "completed", vulnerabilities: { total: 0 } }).skippedSources, []);
  });
  test("reasons and error are ignored unless failed, as the API documents", () => {
    const s = parseScanStatus({ status: "completed", reasons: ["fetch_failed"], error: "x", vulnerabilities: { total: 0 } });
    assert.deepEqual(s.reasons, []);
    assert.equal(s.error, undefined);
  });
  test("skipped_sources is kept for completed and failed only", () => {
    assert.deepEqual(parseScanStatus({ status: "completed", skipped_sources: ["jvn"], vulnerabilities: { total: 0 } }).skippedSources, ["jvn"]);
    assert.deepEqual(parseScanStatus({ status: "failed", skipped_sources: ["jvn"], vulnerabilities: { total: 0 } }).skippedSources, ["jvn"]);
    assert.deepEqual(parseScanStatus({ status: "running", skipped_sources: ["jvn"] }).skippedSources, []);
  });
});

describe("scanView", () => {
  test("latest SBOM still loading, or the status still loading: checking", () => {
    assert.equal(scanView({ sbom: { pending: true, error: false, id: null }, status: { pending: true, error: false } }).kind, "checking");
    assert.equal(scanView({ sbom: sbom(), status: { pending: true, error: false } }).kind, "checking");
  });
  test("no SBOM: no-sbom (nothing was scanned)", () => {
    assert.equal(scanView({ sbom: sbom(null), status: { pending: true, error: false } }).kind, "no-sbom");
  });
  test("the latest SBOM or its status could not be loaded: unavailable", () => {
    assert.equal(scanView({ sbom: { pending: false, error: true, id: null }, status: { pending: true, error: false } }).kind, "unavailable");
    assert.equal(scanView({ sbom: sbom(), status: { pending: false, error: true } }).kind, "unavailable");
  });
  test("a failed poll after a running answer is unavailable, not a stale running", () => {
    const v = scanView({ sbom: sbom(), status: { pending: false, error: true, data: parseScanStatus({ status: "running" }) } });
    assert.equal(v.kind, "unavailable");
  });
  test("each API state maps to its own view", () => {
    assert.equal(scanView({ sbom: sbom(), status: status({ status: "running" }) }).kind, "running");
    assert.equal(scanView({ sbom: sbom(), status: status({ status: "unknown" }) }).kind, "unknown");
    const failed = scanView({ sbom: sbom(), status: status({ status: "failed", reasons: ["fetch_failed", "source_unavailable"], skipped_sources: ["jvn"] }) });
    assert.equal(failed.kind, "failed");
    assert.deepEqual(failed.reasons.map((r) => r.code), ["fetch_failed", "source_unavailable"]);
    assert.deepEqual(failed.skippedSources, ["jvn"]);
    const done = scanView({ sbom: sbom(), status: status({ status: "completed" }) });
    assert.equal(done.kind, "completed");
    assert.deepEqual(done.skippedSources, []);
    const partial = scanView({ sbom: sbom(), status: status({ status: "completed", skipped_sources: ["jvn"] }) });
    assert.equal(partial.kind, "completed");
    assert.deepEqual(partial.skippedSources, ["jvn"]);
  });
});

describe("emptyStateKey", () => {
  // Codex R1 Critical: "completed" is the API's "nothing escalated", not
  // "every source and component was checked" (offline mode, a manual
  // ?sources=nvd scan and the scheduled scan complete without JVN and do not
  // report it as skipped). So even that state gets a scoped message
  // (emptyCompleted), never the bare "No vulnerabilities found.".
  test("only a completed scan with nothing skipped gets the scoped 'none recorded by the completed scan'", () => {
    const all = [
      [{ kind: "checking" }, "emptyChecking"],
      [{ kind: "no-sbom" }, "emptyNoSbom"],
      [{ kind: "unavailable" }, "emptyUnavailable"],
      [{ kind: "running" }, "emptyRunning"],
      [{ kind: "unknown" }, "emptyUnknown"],
      [{ kind: "failed", reasons: [], skippedSources: [] }, "emptyFailed"],
      [{ kind: "completed", skippedSources: ["jvn"] }, "emptyPartial"],
      [{ kind: "completed", skippedSources: [] }, "emptyCompleted"],
    ];
    for (const [view, key] of all) assert.equal(emptyStateKey(view, true), key, view.kind);
    assert.equal(all.filter(([, k]) => k === "emptyCompleted").length, 1);
  });
  // Codex R2 High: a list still loading (a new sort, a refresh) must not be
  // read as the empty result of the scan.
  test("a list that is not fresh is 'checking' whatever the scan state", () => {
    for (const view of [{ kind: "completed", skippedSources: [] }, { kind: "failed", reasons: [], skippedSources: [] }, { kind: "running" }]) {
      assert.equal(emptyStateKey(view, false), "emptyChecking", view.kind);
    }
    // no SBOM: there is nothing to wait for
    assert.equal(emptyStateKey({ kind: "no-sbom" }, false), "emptyNoSbom");
  });
});

describe("reasonItems", () => {
  test("every documented reason has its own message", () => {
    const codes = [
      "deadline_exceeded", "cancelled", "fetch_failed", "source_unavailable", "truncated",
      "write_refused", "distro_data_failed", "queue_full", "scan_error", "interrupted",
    ];
    const items = reasonItems(codes);
    assert.equal(items.length, codes.length);
    for (const it of items) assert.notEqual(it.key, "reasonOther", it.code);
    assert.equal(new Set(items.map((i) => i.key)).size, codes.length);
    assert.equal(items.find((i) => i.code === "source_unavailable").key, "reasonSourceUnavailable");
  });
  test("an unrecognised code is shown as 'other', not dropped; duplicates collapse", () => {
    assert.deepEqual(reasonItems(["new_reason", "fetch_failed", "fetch_failed"]), [
      { code: "new_reason", key: "reasonOther" },
      { code: "fetch_failed", key: "reasonFetchFailed" },
    ]);
  });
  test("a failed scan without reasons still says why it is incomplete", () => {
    assert.deepEqual(reasonItems([]), []);
  });
});

describe("skippedSourceLabel", () => {
  test("known sources are named, others shown as given", () => {
    assert.equal(skippedSourceLabel("jvn"), "JVN");
    assert.equal(skippedSourceLabel("nvd"), "NVD");
    assert.equal(skippedSourceLabel("osv"), "osv");
  });
});

describe("pollIntervalMs", () => {
  test("polls only while running, and backs off after the first minute", () => {
    assert.equal(pollIntervalMs("running", 0), 3000);
    assert.equal(pollIntervalMs("running", 19), 3000);
    assert.equal(pollIntervalMs("running", 20), 10000);
    assert.equal(pollIntervalMs(undefined, 0), false);
  });
  // Codex R2 High: a later scan of the same SBOM (manual, scheduled) or a
  // new upload must not stay hidden behind a settled state forever.
  test("a settled state is re-read once a minute (visible tabs only, react-query)", () => {
    for (const s of ["completed", "failed", "unknown"]) assert.equal(pollIntervalMs(s, 0), 60000);
  });
});

// Codex R1 High: client request-start times do not order server work, and
// react-query v5 reuses an in-flight request that has no data yet. The list
// is refetched (fresh, after the status answer arrived) whenever the status
// settles into a state it was not in before.
// Codex R4 High: two answers agree only if everything the page shows from
// them agrees — not just state and total (skipped sources, reasons, error).
describe("sameScanAnswer", () => {
  const base = { status: "completed", total: 0, reasons: [], skippedSources: [] };
  test("identical answers agree", () => {
    assert.equal(sameScanAnswer(base, { ...base }), true);
    assert.equal(sameScanAnswer({ ...base, status: "failed", reasons: ["a", "b"], error: "x" }, { ...base, status: "failed", reasons: ["a", "b"], error: "x" }), true);
  });
  test("any shown difference disagrees", () => {
    assert.equal(sameScanAnswer(base, { ...base, status: "failed" }), false);
    assert.equal(sameScanAnswer(base, { ...base, total: 1 }), false);
    assert.equal(sameScanAnswer(base, { ...base, skippedSources: ["jvn"] }), false);
    assert.equal(sameScanAnswer({ ...base, status: "failed", reasons: ["a"] }, { ...base, status: "failed", reasons: ["a", "b"] }), false);
    assert.equal(sameScanAnswer({ ...base, status: "failed", error: "x" }, { ...base, status: "failed", error: "y" }), false);
    // A null total only occurs for running / unknown (a settled answer
    // without one parses as unknown), where agreement claims nothing.
    assert.equal(sameScanAnswer({ ...base, status: "unknown", total: null }, { ...base, status: "unknown", total: null }), true);
  });
});

describe("settleNeedsListRefetch", () => {
  const st = (status, total = 0) => ({ status, total, reasons: [], skippedSources: [] });
  test("a settled state the page did not have before refetches the list", () => {
    for (const prev of [undefined, st("running"), st("completed"), st("unknown")]) {
      assert.equal(settleNeedsListRefetch(prev, st("failed")), true, String(prev?.status));
    }
    assert.equal(settleNeedsListRefetch(undefined, st("completed")), true);
    assert.equal(settleNeedsListRefetch(st("running"), st("completed")), true);
    assert.equal(settleNeedsListRefetch(st("running"), st("unknown")), true);
  });
  // Codex R2 High: a rescan of the same SBOM that finished between two
  // reads reads completed → completed; its findings changed the SBOM's total.
  test("the same settled state with a different total refetches the list", () => {
    assert.equal(settleNeedsListRefetch(st("completed", 2), st("completed", 3)), true);
    assert.equal(settleNeedsListRefetch(st("completed", 2), st("unknown", null)), true);
    assert.equal(settleNeedsListRefetch(st("unknown", null), st("unknown", null)), false, "Codex R6: unknown settles");
  });
  test("a changed coverage (skipped sources) also refetches (Codex R4)", () => {
    assert.equal(settleNeedsListRefetch(st("completed", 2), { ...st("completed", 2), skippedSources: ["jvn"] }), true);
  });
  test("not while running, and not when state and total are unchanged", () => {
    assert.equal(settleNeedsListRefetch(undefined, st("running")), false);
    assert.equal(settleNeedsListRefetch(st("completed"), st("running")), false);
    assert.equal(settleNeedsListRefetch(st("completed", 2), st("completed", 2)), false);
  });
});

// Codex R1 High: the tab counter showed a bare number in every state but
// running, so a failed / unknown / partial scan (or a failed list load on the
// default tab) read as a final count.
describe("countQualifierKey", () => {
  test("a bare count only for a completed scan with nothing skipped", () => {
    assert.equal(countQualifierKey({ kind: "completed", skippedSources: [] }, FRESH), null);
  });
  test("every other state qualifies the count", () => {
    assert.equal(countQualifierKey({ kind: "running" }, FRESH), "tabCountRunning");
    assert.equal(countQualifierKey({ kind: "checking" }, FRESH), "tabCountChecking");
    assert.equal(countQualifierKey({ kind: "failed", reasons: [], skippedSources: [] }, FRESH), "tabCountIncomplete");
    assert.equal(countQualifierKey({ kind: "unknown" }, FRESH), "tabCountUnconfirmed");
    assert.equal(countQualifierKey({ kind: "unavailable" }, FRESH), "tabCountUnconfirmed");
    assert.equal(countQualifierKey({ kind: "completed", skippedSources: ["jvn"] }, FRESH), "tabCountPartial");
  });
  // Codex R2 High: a failed refresh keeps the old rows on screen (banner);
  // their count is not current either.
  test("a failed list load (with or without rows kept) wins over every scan state", () => {
    for (const view of [{ kind: "completed", skippedSources: [] }, { kind: "running" }, { kind: "no-sbom" }]) {
      assert.equal(countQualifierKey(view, { failed: true, fresh: false }), "tabCountLoadFailed", view.kind);
      assert.equal(countQualifierKey(view, { failed: true, fresh: true }), "tabCountLoadFailed", view.kind);
    }
  });
  // Codex R2 High: the list for the current sort still loading shows the
  // previous rows; their count is not the settled one.
  test("a list that is not fresh is 'checking', even for a completed scan", () => {
    assert.equal(countQualifierKey({ kind: "completed", skippedSources: [] }, { failed: false, fresh: false }), "tabCountChecking");
    // Codex R6: no SBOM is "not scanned", never a bare 0.
    assert.equal(countQualifierKey({ kind: "no-sbom" }, { failed: false, fresh: false }), "tabCountNotScanned");
    assert.equal(countQualifierKey({ kind: "no-sbom" }, FRESH), "tabCountNotScanned");
  });
});

// Codex R7 Medium: a list read for SBOM A that saw B as latest must not move
// the page back to B when it has meanwhile moved on to C.
describe("latestAfterListRead", () => {
  test("moves to what the list read saw only while the page is still on the list's SBOM", () => {
    assert.equal(latestAfterListRead("A", "A", "B"), "B");
    assert.equal(latestAfterListRead(null, null, "B"), "B");
  });
  test("never moves backwards or sideways once the page moved on", () => {
    assert.equal(latestAfterListRead("C", "A", "B"), "C");
    assert.equal(latestAfterListRead("C", null, "B"), "C");
  });
  test("no change when the list read saw the same SBOM", () => {
    assert.equal(latestAfterListRead("A", "A", "A"), "A");
  });
});
