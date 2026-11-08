// Optimistic cache edits for the CRA report queue (one react-query entry per
// filter, queryKeys.projects.craReports). Pure, so node --test can pin them
// (src/lib/query/__tests__/cra-report-cache.test.mjs).
//
// Codex R1 Medium: rolling back by restoring a whole-page snapshot let a
// failed older action (approve A) overwrite a newer one (approve B, already
// confirmed by the server), bringing B back. Every edit here touches only
// the one report it is about, so concurrent actions on different rows
// compose in any order.

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

/**
 * Undo withoutReport for that report only: put it back at its old index
 * (clamped) unless it is already there again (e.g. a refetch brought it
 * back). Other rows — including other actions' optimistic removals — are
 * left as they are now.
 */
export function withReportRestored<R extends ReportRow>(
  page: ReportPageData<R> | undefined,
  report: R,
  index: number,
): ReportPageData<R> | undefined {
  if (!page || page.data.some((r) => r.id === report.id)) return page;
  const data = [...page.data];
  data.splice(Math.max(0, Math.min(index, data.length)), 0, report);
  return { data, totalCount: page.totalCount + 1 };
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
