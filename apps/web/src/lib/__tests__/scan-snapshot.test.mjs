// One consistent read of latest SBOM + scan state + list (src/lib/scan-snapshot.ts).
//
// Run: pnpm --filter web test
//
// The fakes below answer each call from a script, so every interleaving the
// Codex review rounds found can be replayed deterministically:
//   - the list is requested only after the scan state was read, and the
//     latest SBOM and the state are read again after it (R1, R2, R3, R8);
//   - an SBOM uploaded while the list is read restarts the read on the new
//     SBOM — never the old state with the new SBOM's list (R2, R4, R5, R9);
//   - a state that moved while the list was read restarts the read; one that
//     keeps moving is returned as running (not final) (R3, R4);
//   - a state that cannot be read still returns the list, marked (R2);
//   - a running poll of the same SBOM keeps the previous list (two requests);
//   - an aborted read starts no further requests (R6).

import assert from "node:assert/strict";
import { describe, test } from "node:test";

import { readSnapshot, SnapshotError, SNAPSHOT_ATTEMPTS } from "../scan-snapshot.ts";

const st = (status, total = 0, extra = {}) => ({ status, total, reasons: [], skippedSources: [], ...extra });
const page = (n) => ({ data: Array.from({ length: n }, (_, i) => `v${i}`), totalCount: n });

/** Scripted fetchers: each call takes the next answer (an Error is thrown). */
function fake({ latest = [], status = [], list = [] }) {
  const log = [];
  const next = (name, q) => async (arg) => {
    log.push(arg === undefined ? name : `${name}(${arg})`);
    if (q.length === 0) throw new Error(`unexpected ${name} call`);
    const v = q.shift();
    if (v instanceof Error) throw v;
    return typeof v === "function" ? v() : v;
  };
  return {
    log,
    deps: { latestSbomId: next("latest", latest), scanStatus: next("status", status), list: next("list", list) },
  };
}

describe("readSnapshot: order and agreement", () => {
  test("settled: latest → status → list → latest → status, and they agree", async () => {
    const f = fake({ latest: ["A", "A"], status: [st("completed", 4), st("completed", 4)], list: [page(4)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.deepEqual(f.log, ["latest", "status(A)", "list", "latest", "status(A)"]);
    assert.equal(s.sbomId, "A");
    assert.equal(s.status.status, "completed");
    assert.equal(s.statusFailed, false);
    assert.equal(s.list.totalCount, 4);
  });

  test("running: the list is read (provisional), no second state read", async () => {
    const f = fake({ latest: ["A", "A"], status: [st("running")], list: [page(1)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.deepEqual(f.log, ["latest", "status(A)", "list", "latest"]);
    assert.equal(s.status.status, "running");
  });

  test("a running poll of the same SBOM keeps the previous list (two requests)", async () => {
    const prev = { sbomId: "A", status: st("running", 1), statusFailed: false, list: page(1) };
    const f = fake({ latest: ["A"], status: [st("running", 2)] });
    const s = await readSnapshot(f.deps, prev);
    assert.deepEqual(f.log, ["latest", "status(A)"]);
    assert.equal(s.list, prev.list);
    assert.equal(s.status.total, 2);
  });

  test("a running poll after a settled answer reads the list again", async () => {
    const prev = { sbomId: "A", status: st("completed", 1), statusFailed: false, list: page(1) };
    const f = fake({ latest: ["A", "A"], status: [st("running")], list: [page(0)] });
    const s = await readSnapshot(f.deps, prev);
    assert.deepEqual(f.log, ["latest", "status(A)", "list", "latest"]);
    assert.equal(s.list.totalCount, 0);
  });
});

describe("readSnapshot: races", () => {
  test("an SBOM uploaded while the list was read: start over on the new SBOM (R2/R4/R5/R9)", async () => {
    const f = fake({
      latest: ["A", "B", "B", "B"],
      status: [st("completed", 0), st("running")],
      list: [page(4) /* B's rows, read as if A's */, page(4)],
    });
    const s = await readSnapshot(f.deps, undefined);
    assert.deepEqual(f.log, ["latest", "status(A)", "list", "latest", "latest", "status(B)", "list", "latest"]);
    assert.equal(s.sbomId, "B");
    assert.equal(s.status.status, "running", "never A's completed with B's list");
  });

  test("the state moved while the list was read: read again (R3)", async () => {
    const f = fake({
      latest: ["A", "A", "A", "A"],
      status: [st("completed", 0), st("completed", 4), st("completed", 4), st("completed", 4)],
      list: [page(0), page(4)],
    });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.list.totalCount, 4);
    assert.equal(s.status.total, 4);
  });

  test("a coverage change while the list was read also reads again (R4)", async () => {
    const f = fake({
      latest: ["A", "A", "A", "A"],
      status: [st("completed", 0), st("completed", 0, { skippedSources: ["jvn"] }), st("completed", 0, { skippedSources: ["jvn"] }), st("completed", 0, { skippedSources: ["jvn"] })],
      list: [page(0), page(0)],
    });
    const s = await readSnapshot(f.deps, undefined);
    assert.deepEqual(s.status.skippedSources, ["jvn"]);
  });

  test("a rescan that starts while the list is read (R8/R9): not returned as the earlier settled state", async () => {
    const f = fake({
      latest: ["A", "A", "A", "A"],
      status: [st("completed", 4), st("running", 4), st("running", 4)],
      list: [page(0), page(0)],
    });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.status.status, "running");
  });

  test("a state that keeps moving is returned as running, not final", async () => {
    const statuses = [];
    for (let i = 0; i < SNAPSHOT_ATTEMPTS; i++) statuses.push(st("completed", i * 2), st("completed", i * 2 + 1));
    const f = fake({
      latest: Array(SNAPSHOT_ATTEMPTS * 2).fill("A"),
      status: statuses,
      list: Array.from({ length: SNAPSHOT_ATTEMPTS }, () => page(0)),
    });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.status.status, "running");
  });

  test("an SBOM that keeps changing is an error (nothing consistent to show)", async () => {
    const latest = [];
    for (let i = 0; i < SNAPSHOT_ATTEMPTS; i++) latest.push(`S${i}`, `S${i + 1}`);
    const f = fake({
      latest,
      status: Array.from({ length: SNAPSHOT_ATTEMPTS }, () => st("completed")),
      list: Array.from({ length: SNAPSHOT_ATTEMPTS }, () => page(0)),
    });
    await assert.rejects(readSnapshot(f.deps, undefined), (e) => e instanceof SnapshotError && e.stage === "latest");
  });
});

describe("readSnapshot: no SBOM, failures, abort", () => {
  test("no SBOM: the list, and a second look for a first upload", async () => {
    const f = fake({ latest: [null, null], list: [page(0)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.deepEqual(f.log, ["latest", "list", "latest"]);
    assert.equal(s.sbomId, null);
    assert.equal(s.status, null);
  });

  test("a first SBOM uploaded meanwhile: start over on it", async () => {
    const f = fake({ latest: [null, "A", "A", "A"], status: [st("running")], list: [page(0), page(0)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.sbomId, "A");
    assert.equal(s.status.status, "running");
  });

  test("the state cannot be read: the list is still returned, marked", async () => {
    const f = fake({ latest: ["A", "A"], status: [new Error("500")], list: [page(2)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.statusFailed, true);
    assert.equal(s.status, null);
    assert.equal(s.list.totalCount, 2);
  });

  test("the second state read fails: marked, not the first answer as final", async () => {
    const f = fake({ latest: ["A", "A"], status: [st("completed"), new Error("500")], list: [page(0)] });
    const s = await readSnapshot(f.deps, undefined);
    assert.equal(s.statusFailed, true);
  });

  test("the list or the latest SBOM cannot be read: an error naming the stage", async () => {
    const a = fake({ latest: ["A"], status: [st("completed")], list: [new Error("500")] });
    await assert.rejects(readSnapshot(a.deps, undefined), (e) => e instanceof SnapshotError && e.stage === "list");
    const b = fake({ latest: [new Error("500")] });
    await assert.rejects(readSnapshot(b.deps, undefined), (e) => e instanceof SnapshotError && e.stage === "latest");
  });

  test("an aborted read starts no further requests (R6)", async () => {
    const ctrl = new AbortController();
    const f = fake({ latest: ["A"], status: [() => { ctrl.abort(); return st("completed"); }], list: [page(0)] });
    await assert.rejects(readSnapshot(f.deps, undefined, ctrl.signal), (e) => e.name === "AbortError");
    assert.deepEqual(f.log, ["latest", "status(A)"]);
  });
});
