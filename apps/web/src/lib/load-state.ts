// Which error UI a react-query backed screen shows (M65 bug 10, M71).
//
//   "none"   — the last load succeeded (or is still pending).
//   "full"   — it failed and there is nothing to show: the LoadError card
//              replaces the content, never an empty / default state.
//   "banner" — a refetch failed but the last good answer is still on
//              screen: a compact LoadError above it.
//
// `hasData` is the caller's "is there something worth keeping on screen"
// (rows for a list, a settings object for a form).
export type LoadErrorState = "none" | "full" | "banner";

export function loadErrorState(isError: boolean, hasData: boolean): LoadErrorState {
  if (!isError) return "none";
  return hasData ? "banner" : "full";
}

// What a tab counter ("Components (n)") shows for a react-query list.
//
//   "loading" — first load still running: no number yet (it is not 0).
//   "failed"  — the load failed and nothing was ever loaded: never "(0)".
//   "stale"   — a refetch failed; the number is the last good answer's,
//               marked as such.
//   "count"   — the last load succeeded.
//
// `hasData` is whether the query holds an answer at all (data !== undefined),
// not whether the list is non-empty: an empty list that loaded is a real 0.
export type TabCountState = "loading" | "failed" | "stale" | "count";

export function tabCountState(q: { isError: boolean; isPending: boolean }, hasData: boolean): TabCountState {
  if (q.isError) return hasData ? "stale" : "failed";
  if (!hasData) return "loading";
  return "count";
}
