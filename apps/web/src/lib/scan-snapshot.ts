// One consistent read of "the latest SBOM, its scan state and its
// vulnerability list" for the project page. Pure (fetchers are injected) so
// node:test can drive every interleaving: src/lib/__tests__/scan-snapshot.test.mjs.
//
// Why one read instead of three queries (Codex review rounds 1–9): the page
// used to keep the latest SBOM id, the scan status and the list in separate
// react-query entries and stitch them together; every round found another
// interleaving in which they disagreed (a list served for another SBOM, a
// status read before a rescan, an old latest-SBOM answer overwriting a newer
// one, ...). Here the three are read in a fixed order inside one query, and
// an answer is only returned when the reads agree:
//
//   1. latest SBOM id                         (A)
//   2. scan status of A                       (s1)
//   3. the vulnerability list                 — the API answers for the
//                                               latest SBOM at that moment
//   4. latest SBOM id again                   must still be A: SBOMs are only
//                                               added, so the list was A's
//   5. scan status of A again (settled s1)    must equal s1: no other scan
//                                               of A changed what the page
//                                               shows while the list was read
//
// A settled s1 (completed / failed / unknown) is published by the API only
// after the scan's findings committed (handler/sbom.go ScanStatus), and the
// list is requested after s1 arrived, so the list includes them. If 4 or 5
// disagree the read starts over (a few times at most; a state that keeps
// moving is returned as running — not final — so the page keeps polling).
//
// While the scan runs, the list is provisional anyway (every count is
// qualified), so a poll that finds the same SBOM still running keeps the
// previous list and costs two requests (latest id, status).
//
// Residual (the API has no scan generation): a whole scan of the same SBOM
// that starts AND ends between reads 2 and 5 without changing anything the
// status shows (state, finding total, skipped sources, reasons, error) is
// not detectable.

import { sameScanAnswer, type ScanStatus } from "./scan-status.ts";

export interface ListPage<T> {
  data: T[];
  totalCount: number;
}

export interface Snapshot<T> {
  /** Latest SBOM id; null = the project has no SBOM. */
  sbomId: string | null;
  /** Its scan state; null when there is no SBOM or it could not be read. */
  status: ScanStatus | null;
  /** The scan state could not be read (the list is shown unconfirmed). */
  statusFailed: boolean;
  list: ListPage<T>;
  /**
   * Consecutive running answers for this SBOM before this one (0 = the first
   * running answer, or not running) — the poll back-off counts these, not the
   * query's lifetime updates (Codex R11).
   */
  runningPolls: number;
}

export interface SnapshotDeps<T> {
  latestSbomId(): Promise<string | null>;
  scanStatus(sbomId: string): Promise<ScanStatus>;
  list(): Promise<ListPage<T>>;
}

export type SnapshotStage = "latest" | "list";

/** A read that produced nothing to show; `stage` says which request failed. */
export class SnapshotError extends Error {
  readonly stage: SnapshotStage;
  constructor(stage: SnapshotStage, cause: unknown) {
    super(`scan snapshot: ${stage} failed`, { cause });
    this.name = "SnapshotError";
    this.stage = stage;
  }
}

/** How many times a read whose answers disagree is started over. */
export const SNAPSHOT_ATTEMPTS = 3;

async function at<R>(stage: SnapshotStage, fn: () => Promise<R>): Promise<R> {
  try {
    return await fn();
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw error;
    throw new SnapshotError(stage, error);
  }
}

function checkAbort(signal: AbortSignal | undefined) {
  signal?.throwIfAborted();
}

/**
 * Reads a consistent snapshot. `prev` is the query's previous answer (same
 * project, same sort), used only for the light running poll.
 */
export async function readSnapshot<T>(
  deps: SnapshotDeps<T>,
  prev: Snapshot<T> | undefined,
  signal?: AbortSignal,
): Promise<Snapshot<T>> {
  const s = await readOnce(deps, prev, signal);
  const continuing =
    s.status?.status === "running" &&
    prev !== undefined &&
    prev.sbomId === s.sbomId &&
    prev.status?.status === "running";
  return { ...s, runningPolls: continuing ? (prev.runningPolls ?? 0) + 1 : 0 };
}

async function readOnce<T>(
  deps: SnapshotDeps<T>,
  prev: Snapshot<T> | undefined,
  signal?: AbortSignal,
): Promise<Omit<Snapshot<T>, "runningPolls">> {
  let last: Omit<Snapshot<T>, "runningPolls"> | undefined;
  for (let attempt = 0; attempt < SNAPSHOT_ATTEMPTS; attempt++) {
    checkAbort(signal);
    const sbomId = await at("latest", () => deps.latestSbomId());
    checkAbort(signal);

    if (sbomId === null) {
      const list = await at("list", () => deps.list());
      checkAbort(signal);
      const again = await at("latest", () => deps.latestSbomId());
      if (again !== null) {
        last = undefined; // a first SBOM arrived meanwhile
        continue;
      }
      return { sbomId: null, status: null, statusFailed: false, list };
    }

    let s1: ScanStatus | null;
    try {
      s1 = await deps.scanStatus(sbomId);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") throw error;
      s1 = null;
    }
    checkAbort(signal);

    // Light poll: same SBOM, still running, previous answer was running.
    if (
      s1 !== null &&
      s1.status === "running" &&
      prev !== undefined &&
      prev.sbomId === sbomId &&
      !prev.statusFailed &&
      prev.status?.status === "running"
    ) {
      return { sbomId: prev.sbomId, status: s1, statusFailed: false, list: prev.list };
    }

    const list = await at("list", () => deps.list());
    checkAbort(signal);
    const again = await at("latest", () => deps.latestSbomId());
    checkAbort(signal);
    if (again !== sbomId) {
      last = undefined; // another SBOM arrived: start over on it
      continue;
    }

    if (s1 === null) return { sbomId, status: null, statusFailed: true, list };
    if (s1.status === "running") return { sbomId, status: s1, statusFailed: false, list };

    let s2: ScanStatus;
    try {
      s2 = await deps.scanStatus(sbomId);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") throw error;
      return { sbomId, status: null, statusFailed: true, list };
    }
    checkAbort(signal);
    if (sameScanAnswer(s1, s2)) return { sbomId, status: s1, statusFailed: false, list };
    // The state moved while the list was read: read again.
    last = { sbomId, status: { ...s2, status: "running" }, statusFailed: false, list };
  }
  if (last) return last;
  // Every attempt was overtaken by a newer SBOM: nothing consistent to show.
  // The page reports the state as not loadable (with Retry) rather than
  // pairing an SBOM's state with another SBOM's list.
  throw new SnapshotError("latest", new Error("the latest SBOM kept changing"));
}
