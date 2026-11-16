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
  sameScanAnswer,
  parseScanStatus,
  pollIntervalMs,
  reasonItems,
  scanCoverage,
  scanView,
  SCAN_SOURCES,
  sourceLabelKey,
} from "../scan-status.ts";

const FRESH = { failed: false, fresh: true };
const ALL = ["nvd", "jvn", "distro"];
/** A completed view as scanView builds it (coverage derived from the lists). */
const done = (skippedSources = [], checkedSources = ALL) => ({
  kind: "completed",
  skippedSources,
  checkedSources,
  coverage: scanCoverage(skippedSources, checkedSources),
});
const failedView = (skippedSources = [], checkedSources = null) => ({
  kind: "failed",
  reasons: [],
  skippedSources,
  checkedSources,
  coverage: scanCoverage(skippedSources, checkedSources),
});
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
    const completed = scanView({ sbom: sbom(), status: status({ status: "completed" }) });
    assert.equal(completed.kind, "completed");
    assert.deepEqual(completed.skippedSources, []);
    assert.equal(completed.checkedSources, null);
    assert.deepEqual(completed.coverage, { kind: "unknown" });
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
      [failedView(), "emptyFailed"],
      [failedView([], ALL), "emptyFailed"],
      [done(["jvn"], ["nvd", "distro"]), "emptyPartial"],
      [done(["jvn"], null), "emptyPartial"],
      [done([], ["nvd", "distro"]), "emptyPartial"],
      [done(ALL, []), "emptyPartial"],
      [done([], null), "emptyCoverageUnknown"],
      [done([], ALL), "emptyCompleted"],
    ];
    for (const [view, key] of all) assert.equal(emptyStateKey(view, true), key, view.kind);
    assert.equal(all.filter(([, k]) => k === "emptyCompleted").length, 1);
  });
  // Codex R2 High: a list still loading (a new sort, a refresh) must not be
  // read as the empty result of the scan.
  test("a list that is not fresh is 'checking' whatever the scan state", () => {
    for (const view of [done(), failedView(), { kind: "running" }]) {
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

describe("sourceLabelKey", () => {
  test("the three API sources have their own label, others are shown as given (null)", () => {
    assert.equal(sourceLabelKey("jvn"), "sourceJvn");
    assert.equal(sourceLabelKey("nvd"), "sourceNvd");
    assert.equal(sourceLabelKey("distro"), "sourceDistro");
    assert.equal(sourceLabelKey("osv"), null);
    assert.equal(sourceLabelKey("toString"), null);
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

// Codex R4 High: two answers agree only if everything the page shows from
// them agrees — not just state and total (skipped sources, reasons, error).
describe("sameScanAnswer", () => {
  const base = { status: "completed", total: 0, reasons: [], skippedSources: [], checkedSources: ["nvd", "jvn", "distro"] };
  test("identical answers agree", () => {
    assert.equal(sameScanAnswer(base, { ...base }), true);
    assert.equal(sameScanAnswer({ ...base, status: "failed", reasons: ["a", "b"], error: "x" }, { ...base, status: "failed", reasons: ["a", "b"], error: "x" }), true);
  });
  test("any shown difference disagrees", () => {
    assert.equal(sameScanAnswer(base, { ...base, status: "failed" }), false);
    assert.equal(sameScanAnswer(base, { ...base, total: 1 }), false);
    assert.equal(sameScanAnswer(base, { ...base, skippedSources: ["jvn"] }), false);
    // §31 checked_sources: a coverage change between the two reads, including
    // "reported" vs "not reported" (null) and "none" ([]) vs not reported.
    assert.equal(sameScanAnswer(base, { ...base, checkedSources: ["nvd", "distro"] }), false);
    assert.equal(sameScanAnswer(base, { ...base, checkedSources: null }), false);
    assert.equal(sameScanAnswer({ ...base, checkedSources: [] }, { ...base, checkedSources: null }), false);
    assert.equal(sameScanAnswer({ ...base, checkedSources: null }, { ...base, checkedSources: null }), true);
    assert.equal(sameScanAnswer({ ...base, status: "failed", reasons: ["a"] }, { ...base, status: "failed", reasons: ["a", "b"] }), false);
    assert.equal(sameScanAnswer({ ...base, status: "failed", error: "x" }, { ...base, status: "failed", error: "y" }), false);
    // A null total only occurs for running / unknown (a settled answer
    // without one parses as unknown), where agreement claims nothing.
    assert.equal(sameScanAnswer({ ...base, status: "unknown", total: null }, { ...base, status: "unknown", total: null }), true);
  });
});

// Codex R1 High: the tab counter showed a bare number in every state but
// running, so a failed / unknown / partial scan (or a failed list load on the
// default tab) read as a final count.
describe("countQualifierKey", () => {
  test("a bare count only for a completed scan that checked NVD, JVN and distro and skipped nothing", () => {
    assert.equal(countQualifierKey(done([], ALL), FRESH), null);
    // order of checked_sources does not matter, extra (future) sources neither
    assert.equal(countQualifierKey(done([], ["distro", "jvn", "nvd", "osv"]), FRESH), null);
  });
  test("every other state qualifies the count", () => {
    assert.equal(countQualifierKey({ kind: "running" }, FRESH), "tabCountRunning");
    assert.equal(countQualifierKey({ kind: "checking" }, FRESH), "tabCountChecking");
    assert.equal(countQualifierKey(failedView(), FRESH), "tabCountIncomplete");
    assert.equal(countQualifierKey(failedView([], ALL), FRESH), "tabCountIncomplete");
    assert.equal(countQualifierKey({ kind: "unknown" }, FRESH), "tabCountUnconfirmed");
    assert.equal(countQualifierKey({ kind: "unavailable" }, FRESH), "tabCountUnconfirmed");
    assert.equal(countQualifierKey(done(["jvn"], ["nvd", "distro"]), FRESH), "tabCountPartial");
    assert.equal(countQualifierKey(done(["jvn"], null), FRESH), "tabCountPartial");
    assert.equal(countQualifierKey(done(ALL, []), FRESH), "tabCountPartial");
    assert.equal(countQualifierKey(done([], ["nvd"]), FRESH), "tabCountPartial");
    // §31: absent checked_sources = coverage unknown, never "none" or "all"
    assert.equal(countQualifierKey(done([], null), FRESH), "tabCountCoverageUnknown");
  });
  // Codex R2 High: a failed refresh keeps the old rows on screen (banner);
  // their count is not current either.
  test("a failed list load (with or without rows kept) wins over every scan state", () => {
    for (const view of [done(), { kind: "running" }, { kind: "no-sbom" }]) {
      assert.equal(countQualifierKey(view, { failed: true, fresh: false }), "tabCountLoadFailed", view.kind);
      assert.equal(countQualifierKey(view, { failed: true, fresh: true }), "tabCountLoadFailed", view.kind);
    }
  });
  // Codex R2 High: the list for the current sort still loading shows the
  // previous rows; their count is not the settled one.
  test("a list that is not fresh is 'checking', even for a completed scan", () => {
    assert.equal(countQualifierKey(done(), { failed: false, fresh: false }), "tabCountChecking");
    // Codex R6: no SBOM is "not scanned", never a bare 0.
    assert.equal(countQualifierKey({ kind: "no-sbom" }, { failed: false, fresh: false }), "tabCountNotScanned");
    assert.equal(countQualifierKey({ kind: "no-sbom" }, FRESH), "tabCountNotScanned");
  });
});

// Integration Codex review (Medium, UPGRADE §31): the API reports which
// sources a terminal scan checked (checked_sources). The page read only
// skipped_sources, so a completed answer with neither list (an older replica,
// status lost in Redis) rendered a bare count, and the unqualified / clean
// presentation did not require proven coverage.
describe("checked_sources (UPGRADE §31)", () => {
  test("SCAN_SOURCES is the API's order", () => {
    assert.deepEqual([...SCAN_SOURCES], ["nvd", "jvn", "distro"]);
  });
  test("parse: kept for completed / failed; absent or malformed is null (unknown), [] is kept as none", () => {
    const p = (extra, st = "completed") => parseScanStatus({ status: st, vulnerabilities: { total: 0 }, ...extra });
    assert.deepEqual(p({ checked_sources: ["nvd", "jvn", "distro"] }).checkedSources, ["nvd", "jvn", "distro"]);
    assert.deepEqual(p({ checked_sources: ["nvd"] }, "failed").checkedSources, ["nvd"]);
    assert.deepEqual(p({ checked_sources: [] }).checkedSources, []);
    assert.equal(p({}).checkedSources, null);
    assert.equal(p({ checked_sources: null }).checkedSources, null);
    assert.equal(p({ checked_sources: "nvd" }).checkedSources, null);
    assert.deepEqual(p({ checked_sources: ["nvd", 3, "", null] }).checkedSources, ["nvd"]);
    assert.equal(parseScanStatus({ status: "running", checked_sources: ["nvd"] }).checkedSources, null);
    assert.equal(parseScanStatus({ status: "unknown", checked_sources: ["nvd"] }).checkedSources, null);
  });
  test("coverage: full only with all three checked and nothing skipped", () => {
    assert.deepEqual(scanCoverage([], ALL), { kind: "full" });
    assert.deepEqual(scanCoverage([], ["distro", "nvd", "jvn"]), { kind: "full" });
    // an unknown extra skipped source is still a gap
    assert.deepEqual(scanCoverage(["osv"], ALL), { kind: "partial", notChecked: ["osv"], checked: ALL });
    // contradictory answer (the API never overlaps the lists): not checked wins
    assert.deepEqual(scanCoverage(["jvn"], ALL), { kind: "partial", notChecked: ["jvn"], checked: ["nvd", "distro"] });
  });
  test("coverage: known gaps list every source not checked, in API order", () => {
    // offline: checked [], skipped all three
    assert.deepEqual(scanCoverage(ALL, []), { kind: "partial", notChecked: ALL, checked: [] });
    // scheduled scan: skipped jvn
    assert.deepEqual(scanCoverage(["jvn"], ["nvd", "distro"]), { kind: "partial", notChecked: ["jvn"], checked: ["nvd", "distro"] });
    // failed with a checked subset: nvd failed (neither list), jvn skipped
    assert.deepEqual(scanCoverage(["jvn"], ["distro"]), { kind: "partial", notChecked: ["nvd", "jvn"], checked: ["distro"] });
    assert.deepEqual(scanCoverage([], ["nvd"]), { kind: "partial", notChecked: ["jvn", "distro"], checked: ["nvd"] });
  });
  test("coverage: checked not reported — skipped ones are known gaps, the rest unknown; none skipped is unknown", () => {
    assert.deepEqual(scanCoverage([], null), { kind: "unknown" });
    assert.deepEqual(scanCoverage(["jvn"], null), { kind: "partial", notChecked: ["jvn"], checked: null });
  });
  test("scanView carries checked sources and coverage for completed and failed", () => {
    const full = scanView({ sbom: sbom(), status: status({ status: "completed", checked_sources: ALL }) });
    assert.deepEqual(full.coverage, { kind: "full" });
    assert.deepEqual(full.checkedSources, ALL);
    const f = scanView({ sbom: sbom(), status: status({ status: "failed", reasons: ["fetch_failed"], checked_sources: ["nvd"] }) });
    assert.equal(f.kind, "failed");
    assert.deepEqual(f.checkedSources, ["nvd"]);
    assert.deepEqual(f.coverage, { kind: "partial", notChecked: ["jvn", "distro"], checked: ["nvd"] });
  });
  test("only full coverage gets the unqualified count and the 'checked, none recorded' empty state", () => {
    const views = [done([], ALL), done([], null), done(["jvn"], ["nvd", "distro"]), done(ALL, []), done([], ["nvd", "jvn"])];
    assert.deepEqual(views.map((v) => countQualifierKey(v, FRESH)), [null, "tabCountCoverageUnknown", "tabCountPartial", "tabCountPartial", "tabCountPartial"]);
    assert.deepEqual(views.map((v) => emptyStateKey(v, true)), ["emptyCompleted", "emptyCoverageUnknown", "emptyPartial", "emptyPartial", "emptyPartial"]);
  });
});
