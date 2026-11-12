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
