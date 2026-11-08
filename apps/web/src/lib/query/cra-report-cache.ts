// Optimistic cache edits for the CRA report queue (one react-query entry per
// filter, queryKeys.projects.craReports). Pure, so node --test can pin them
// (src/lib/query/__tests__/cra-report-cache.test.mjs).
//
// Codex R1 Medium: rolling back by restoring a whole-page snapshot let a
// failed older action (approve A) overwrite a newer one (approve B, already
// confirmed by the server), bringing B back. Codex R2 Medium: a refresh that
// answered with pre-action rows overwrote an optimistic edit. So in-flight
// actions are kept as an overlay (applyPendingOps) applied to every fetched
// page, and every edit touches only the one report it is about.

export interface ReportRow {
  id: string;
  state: string;
}

export interface ReportPageData<R extends ReportRow> {
  data: R[];
  totalCount: number;
}

/** Optimistically drop one report (decision taken). */
export function withoutReport<R extends ReportRow>(
  page: ReportPageData<R> | undefined,
  reportId: string,
): ReportPageData<R> | undefined {
  if (!page || !page.data.some((r) => r.id === reportId)) return page;
  return {
    data: page.data.filter((r) => r.id !== reportId),
    totalCount: Math.max(0, page.totalCount - 1),
  };
}

/** Set one report's state (optimistic submission / its rollback). */
export function withReportState<R extends ReportRow>(
  page: ReportPageData<R> | undefined,
  reportId: string,
  state: string,
): ReportPageData<R> | undefined {
  if (!page) return page;
  return { ...page, data: page.data.map((r) => (r.id === reportId ? { ...r, state } : r)) };
}

/** An action in flight on one report (Codex R2). */
export type PendingOp = { kind: "remove" } | { kind: "state"; state: string };

/**
 * Overlay of in-flight actions applied to whatever page is in the cache —
 * including a refresh or another action's refetch that answered with the
 * pre-action rows (Codex R2: such a response resurrected a decided row /
 * reverted "submitted" while its PUT/POST was still pending). Returns the
 * page itself when nothing is pending.
 */
export function applyPendingOps<R extends ReportRow>(
  page: ReportPageData<R> | undefined,
  ops: ReadonlyMap<string, PendingOp>,
): ReportPageData<R> | undefined {
  if (!page || ops.size === 0) return page;
  let out: ReportPageData<R> = page;
  for (const [reportId, op] of ops) {
    out = (op.kind === "remove"
      ? withoutReport(out, reportId)
      : withReportState(out, reportId, op.state)) as ReportPageData<R>;
  }
  return out;
}
