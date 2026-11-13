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
  parseScanStatus,
  pollIntervalMs,
  reasonItems,
  scanView,
  settleNeedsListRefetch,
  skippedSourceLabel,
} from "../scan-status.ts";

const sbom = (id = "s1") => ({ pending: false, error: false, id });
const status = (data) => ({ pending: false, error: false, data: parseScanStatus(data) });

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
  });
  test("an unrecognised or missing status is unknown, never completed", () => {
    assert.equal(parseScanStatus({ status: "done" }).status, "unknown");
    assert.equal(parseScanStatus({}).status, "unknown");
    assert.equal(parseScanStatus(null).status, "unknown");
    assert.equal(parseScanStatus("completed").status, "unknown");
  });
  test("non-string members of reasons / skipped_sources are dropped, absent lists are empty", () => {
    const s = parseScanStatus({ status: "failed", reasons: ["x", 3, null], skipped_sources: "jvn" });
    assert.deepEqual(s.reasons, ["x"]);
    assert.deepEqual(s.skippedSources, []);
    assert.deepEqual(parseScanStatus({ status: "completed" }).skippedSources, []);
  });
  test("reasons and error are ignored unless failed, as the API documents", () => {
    const s = parseScanStatus({ status: "completed", reasons: ["fetch_failed"], error: "x" });
    assert.deepEqual(s.reasons, []);
    assert.equal(s.error, undefined);
  });
  test("skipped_sources is kept for completed and failed only", () => {
    assert.deepEqual(parseScanStatus({ status: "completed", skipped_sources: ["jvn"] }).skippedSources, ["jvn"]);
    assert.deepEqual(parseScanStatus({ status: "failed", skipped_sources: ["jvn"] }).skippedSources, ["jvn"]);
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
    for (const [view, key] of all) assert.equal(emptyStateKey(view), key, view.kind);
    assert.equal(all.filter(([, k]) => k === "emptyCompleted").length, 1);
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
    for (const s of ["completed", "failed", "unknown", undefined]) assert.equal(pollIntervalMs(s, 0), false);
  });
});

// Codex R1 High: client request-start times do not order server work, and
// react-query v5 reuses an in-flight request that has no data yet. The list
// is refetched (fresh, after the status answer arrived) whenever the status
// settles into a state it was not in before.
describe("settleNeedsListRefetch", () => {
  test("a settled state the page did not have before refetches the list", () => {
    for (const prev of [undefined, "running", "completed", "unknown"]) {
      assert.equal(settleNeedsListRefetch(prev, "failed"), true, String(prev));
    }
    assert.equal(settleNeedsListRefetch(undefined, "completed"), true);
    assert.equal(settleNeedsListRefetch("running", "completed"), true);
    assert.equal(settleNeedsListRefetch("running", "unknown"), true);
  });
  test("not while running, and not when the state is unchanged", () => {
    assert.equal(settleNeedsListRefetch(undefined, "running"), false);
    assert.equal(settleNeedsListRefetch("completed", "running"), false);
    assert.equal(settleNeedsListRefetch("completed", "completed"), false);
  });
});

// Codex R1 High: the tab counter showed a bare number in every state but
// running, so a failed / unknown / partial scan (or a failed list load on the
// default tab) read as a final count.
describe("countQualifierKey", () => {
  test("a bare count only for a completed scan with nothing skipped, or no SBOM", () => {
    assert.equal(countQualifierKey({ kind: "completed", skippedSources: [] }, false), null);
    assert.equal(countQualifierKey({ kind: "no-sbom" }, false), null);
  });
  test("every other state qualifies the count", () => {
    assert.equal(countQualifierKey({ kind: "running" }, false), "tabCountRunning");
    assert.equal(countQualifierKey({ kind: "checking" }, false), "tabCountChecking");
    assert.equal(countQualifierKey({ kind: "failed", reasons: [], skippedSources: [] }, false), "tabCountIncomplete");
    assert.equal(countQualifierKey({ kind: "unknown" }, false), "tabCountUnconfirmed");
    assert.equal(countQualifierKey({ kind: "unavailable" }, false), "tabCountUnconfirmed");
    assert.equal(countQualifierKey({ kind: "completed", skippedSources: ["jvn"] }, false), "tabCountPartial");
  });
  test("a failed list load wins over every scan state", () => {
    for (const view of [{ kind: "completed", skippedSources: [] }, { kind: "running" }, { kind: "no-sbom" }]) {
      assert.equal(countQualifierKey(view, true), "tabCountLoadFailed", view.kind);
    }
  });
});
