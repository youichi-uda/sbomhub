// The project page's view of the background vulnerability scan of the
// project's latest SBOM. Pure (no React, no imports) so node:test can pin it:
// src/lib/__tests__/scan-status.test.mjs.
//
// Why it exists (integration Codex review 2026-11-13, High): the page said
// "No vulnerabilities found." whenever the list was empty. Scans run in the
// background after an upload, so an empty list can also mean
//   - the scan is still running (counts are provisional: each scanner commits
//     its links at the end of its sweep, UPGRADE.md §15);
//   - the scan failed — e.g. MyJVN has been suspended since 2026-10-22, so
//     every online scan with JVN on reads failed with reasons
//     fetch_failed + source_unavailable (§26.1);
//   - the scan completed without consulting a source the operator switched
//     off (SBOMHUB_JVN=off → skipped_sources ["jvn"], §26.2);
//   - the status is unknown — the API keeps a scan's status for about an hour
//     (max(1h, SBOMHUB_SCAN_DEADLINE + 15m)), and reads unknown when Redis
//     cannot be read (§25.3).
// Even a completed scan does not prove that every source and component was
// checked: offline mode, components without a usable name, a manual
// `?sources=nvd` scan and the scheduled scan (NVD + distro only) all complete
// without reporting the sources they did not consult (handler/sbom.go
// runScan godoc, UPGRADE.md §26.2). The API offers no positive coverage
// signal, so the page never says a bare "no vulnerabilities": a completed
// scan with nothing skipped gets a message scoped to what that scan could
// look up (core principle: never imply something is safe that was not
// checked; Codex R1 Critical).
//
// API: GET /api/v1/projects/:id/sboms/:sbom_id/scan-status
// (apps/api/internal/handler/sbom.go ScanStatusResponse):
//   { status: running|completed|failed|unknown, sbom_id, project_id,
//     error?: string (failed only), reasons?: string[] (failed only),
//     skipped_sources?: string[] (completed / failed only),
//     vulnerabilities: { critical, high, medium, low, unknown, kev, total } }

export type ScanState = "running" | "completed" | "failed" | "unknown";

export interface ScanStatus {
  status: ScanState;
  /** The API's generic failure marker (e.g. "jvn: scan failed (fetch_failed, source_unavailable)"). */
  error?: string;
  reasons: string[];
  skippedSources: string[];
  /**
   * vulnerabilities.total of the response: this SBOM's committed findings.
   * Used only to notice that findings changed between two settled answers
   * (a rescan of the same SBOM); it is not comparable to the list's
   * X-Total-Count, which counts differently.
   */
  total: number | null;
}

const STATES: readonly ScanState[] = ["running", "completed", "failed", "unknown"];

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x !== "") : [];
}

/**
 * Normalises a scan-status body. Anything the page does not recognise as a
 * state reads as unknown — never as completed.
 */
export function parseScanStatus(raw: unknown): ScanStatus {
  const o = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  let status = STATES.includes(o.status as ScanState) ? (o.status as ScanState) : "unknown";
  const v = o.vulnerabilities !== null && typeof o.vulnerabilities === "object"
    ? (o.vulnerabilities as Record<string, unknown>)
    : {};
  const total = typeof v.total === "number" && Number.isInteger(v.total) && v.total >= 0 ? v.total : null;
  // A settled answer without a usable finding total cannot be checked
  // against the list (and could never be seen to settle): unknown, not
  // completed / failed (Codex R6). The API always sends it.
  if ((status === "completed" || status === "failed") && total === null) status = "unknown";
  const out: ScanStatus = { status, reasons: [], skippedSources: [], total };
  if (status === "failed") {
    out.reasons = stringList(o.reasons);
    if (typeof o.error === "string" && o.error !== "") out.error = o.error;
  }
  if (status === "completed" || status === "failed") {
    out.skippedSources = stringList(o.skipped_sources);
  }
  return out;
}

/** next-intl keys under "ScanStatus" for the reason codes. */
export type ReasonKey =
  | "reasonDeadlineExceeded"
  | "reasonCancelled"
  | "reasonFetchFailed"
  | "reasonSourceUnavailable"
  | "reasonTruncated"
  | "reasonWriteRefused"
  | "reasonDistroDataFailed"
  | "reasonQueueFull"
  | "reasonScanError"
  | "reasonInterrupted"
  | "reasonOther";

const REASON_KEYS: Record<string, ReasonKey> = {
  deadline_exceeded: "reasonDeadlineExceeded",
  cancelled: "reasonCancelled",
  fetch_failed: "reasonFetchFailed",
  source_unavailable: "reasonSourceUnavailable",
  truncated: "reasonTruncated",
  write_refused: "reasonWriteRefused",
  distro_data_failed: "reasonDistroDataFailed",
  queue_full: "reasonQueueFull",
  scan_error: "reasonScanError",
  interrupted: "reasonInterrupted",
};

export interface ReasonItem {
  code: string;
  key: ReasonKey;
}

/** Reason codes in the API's order, deduplicated; an unrecognised code is kept as "other". */
export function reasonItems(reasons: readonly string[]): ReasonItem[] {
  const seen = new Set<string>();
  const out: ReasonItem[] = [];
  for (const code of reasons) {
    if (seen.has(code)) continue;
    seen.add(code);
    out.push({ code, key: Object.hasOwn(REASON_KEYS, code) ? REASON_KEYS[code] : "reasonOther" });
  }
  return out;
}

const SOURCE_LABELS: Record<string, string> = { jvn: "JVN", nvd: "NVD" };

/** Display name of a skipped source; unknown ones are shown as the API names them. */
export function skippedSourceLabel(source: string): string {
  return Object.hasOwn(SOURCE_LABELS, source) ? SOURCE_LABELS[source] : source;
}

export type ScanView =
  | { kind: "checking" }
  | { kind: "no-sbom" }
  | { kind: "unavailable" }
  | { kind: "running" }
  | { kind: "unknown" }
  | { kind: "failed"; reasons: ReasonItem[]; skippedSources: string[]; error?: string }
  | { kind: "completed"; skippedSources: string[] };

export interface ScanViewInput {
  /** The latest-SBOM lookup: id null = the project has no SBOM. */
  sbom: { pending: boolean; error: boolean; id: string | null };
  /** The scan-status query of that SBOM. */
  status: { pending: boolean; error: boolean; data?: ScanStatus };
}

export function scanView({ sbom, status }: ScanViewInput): ScanView {
  if (sbom.error) return { kind: "unavailable" };
  if (sbom.pending) return { kind: "checking" };
  if (sbom.id === null) return { kind: "no-sbom" };
  // A failed poll makes the last answer stale: a "running" we can no longer
  // follow must not keep claiming the scan is in progress (nor, once it has
  // settled, keep a terminal state we cannot confirm is still current).
  if (status.error) return { kind: "unavailable" };
  if (status.pending || !status.data) return { kind: "checking" };
  const d = status.data;
  switch (d.status) {
    case "running":
      return { kind: "running" };
    case "failed":
      return {
        kind: "failed",
        reasons: reasonItems(d.reasons),
        skippedSources: d.skippedSources,
        ...(d.error ? { error: d.error } : {}),
      };
    case "completed":
      return { kind: "completed", skippedSources: d.skippedSources };
    default:
      return { kind: "unknown" };
  }
}

export type EmptyStateKey =
  | "emptyChecking"
  | "emptyNoSbom"
  | "emptyUnavailable"
  | "emptyRunning"
  | "emptyUnknown"
  | "emptyFailed"
  | "emptyPartial"
  | "emptyCompleted";

/**
 * The "ScanStatus" message for an empty vulnerability list. `listFresh` is
 * false while the list for the current sort is still loading or being
 * refreshed: an empty list then is not the scan's result yet (Codex R2).
 */
export function emptyStateKey(view: ScanView, listFresh: boolean): EmptyStateKey {
  if (!listFresh && view.kind !== "no-sbom") return "emptyChecking";
  switch (view.kind) {
    case "checking":
      return "emptyChecking";
    case "no-sbom":
      return "emptyNoSbom";
    case "unavailable":
      return "emptyUnavailable";
    case "running":
      return "emptyRunning";
    case "unknown":
      return "emptyUnknown";
    case "failed":
      return "emptyFailed";
    case "completed":
      return view.skippedSources.length > 0 ? "emptyPartial" : "emptyCompleted";
  }
}

/**
 * react-query refetchInterval for the scan-status query: while the scan runs
 * every 3s for the first 20 answers (about a minute), then every 10s (a cold
 * scan can take many minutes); once settled, once a minute, so a later scan
 * of the same SBOM (manual, scheduled) or a newly uploaded SBOM does not stay
 * hidden behind a settled state (Codex R2). react-query does not poll a
 * hidden tab (refetchIntervalInBackground stays false), so background tabs
 * add no load.
 */
export function pollIntervalMs(state: ScanState | undefined, answers: number): number | false {
  if (state === undefined) return false;
  if (state !== "running") return 60000;
  return answers < 20 ? 3000 : 10000;
}

/**
 * Whether a scan-status answer must be followed by a fresh vulnerability
 * list before the page shows it: the scan has settled (completed / failed /
 * unknown) into a state the page did not already have.
 *
 * The page then cancels any list request in flight and fetches the list
 * again, AFTER this answer arrived, before the answer is committed. The API
 * publishes a terminal state only after the scan's findings committed
 * (handler/sbom.go ScanStatus), so a list requested after the answer was
 * received includes them. Client request-start times cannot establish that
 * order (Codex R1 High), and react-query v5 hands back an in-flight request
 * that has no data yet instead of starting a new one, hence the cancel.
 */
export function settleNeedsListRefetch(prev: ScanStatus | undefined, next: ScanStatus): boolean {
  if (next.status === "running") return false;
  if (prev === undefined) return true;
  // Any difference the page would show — e.g. the same settled state with a
  // different total or coverage: another scan of this SBOM ran between the
  // two answers (Codex R2 / R4).
  return !sameScanAnswer(prev, next);
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * Whether two scan-status answers agree on everything the page shows from
 * them: state, finding total, skipped sources, reasons and failure marker
 * (Codex R4: agreeing on state and total alone let a changed coverage
 * through). A null total only occurs for running / unknown answers
 * (parseScanStatus), where agreement claims nothing final.
 */
export function sameScanAnswer(a: ScanStatus, b: ScanStatus): boolean {
  return (
    a.status === b.status &&
    a.total === b.total &&
    sameList(a.skippedSources, b.skippedSources) &&
    sameList(a.reasons, b.reasons) &&
    (a.error ?? "") === (b.error ?? "")
  );
}

/** "ScanStatus" message keys that qualify the vulnerability count. */
export type CountQualifierKey =
  | "tabCountRunning"
  | "tabCountChecking"
  | "tabCountIncomplete"
  | "tabCountUnconfirmed"
  | "tabCountPartial"
  | "tabCountNotScanned"
  | "tabCountLoadFailed";

export interface ListState {
  /** The last load of the list failed (rows of an earlier load may still be shown). */
  failed: boolean;
  /** The list for the current sort is loaded and no refresh is in flight. */
  fresh: boolean;
}

/**
 * How the vulnerability count is qualified (tab counter, card header). null =
 * a bare number: only a completed scan with nothing skipped and a fresh list.
 * A failed list load wins — its count
 * is not current, even when earlier rows are still on screen — then a list
 * still loading (Codex R2).
 */
export function countQualifierKey(view: ScanView, list: ListState): CountQualifierKey | null {
  if (list.failed) return "tabCountLoadFailed";
  // No SBOM: nothing was scanned, so a bare 0 would read as clean (Codex R6).
  if (view.kind === "no-sbom") return "tabCountNotScanned";
  if (!list.fresh) return "tabCountChecking";
  switch (view.kind) {
    case "completed":
      return view.skippedSources.length > 0 ? "tabCountPartial" : null;
    case "running":
      return "tabCountRunning";
    case "checking":
      return "tabCountChecking";
    case "failed":
      return "tabCountIncomplete";
    case "unknown":
    case "unavailable":
      return "tabCountUnconfirmed";
  }
}
