// Single "error banner" slot shared by a query and the page's imperative
// actions.
//
// The pre-react-query pages kept ONE `error` state that several writers
// shared: some loaders cleared it when a load started, every loader set it
// when the load failed (a successful load never touched it), and the page's
// actions (export, download, generate, sync, save) set it to their own
// message or cleared it when they started. The banner always showed the
// most recent writer.
//
// With the load moved into react-query the load side of that state no
// longer exists as a variable, so this module recomputes "most recent
// writer wins":
//   - action writes AND the "load started, clear the banner" writes go into
//     the slot. Pages whose loader cleared the banner on start write
//     `errorSlot(null, key, client)` in the handler that triggers the reload
//     (page / filter change, refresh button);
//   - each write records WHICH query (key hash) it was written against and
//     how many times that query had failed at that moment, read from the
//     cache at write time — not from a render snapshot, so an async action
//     completing after a concurrent failure is still the latest writer
//     (Codex R4);
//   - a load failure is newer than the write if the same query has failed
//     more times since, or — when the page has moved on to another key
//     (react-query failure counts are per key, Codex R4) — if the current
//     key has failed at all: the write happened before the current key
//     existed.
// Ordering is causal, never by clock (millisecond timestamps tie, Codex
// R2/R3). An earlier version hid the slot while a load was in flight, which
// swallowed an action error raised during the load (Codex R1).
//
// Pinned by src/lib/query/__tests__/query.test.mjs (against a real
// QueryClient).

import { hashKey, type QueryClient, type QueryKey } from "@tanstack/react-query";

export interface ErrorSlot {
  /** Message an action wrote, or null when the banner was cleared. */
  message: string | null;
  /** hashKey() of the query current when it was written. */
  lineage: string;
  /** That query's errorUpdateCount when it was written. */
  afterFailures: number;
}

export function errorSlot(message: string | null, queryKey: QueryKey, client: QueryClient): ErrorSlot {
  return {
    message,
    lineage: hashKey(queryKey),
    afterFailures: client.getQueryState(queryKey)?.errorUpdateCount ?? 0,
  };
}

/**
 * @param queryKey         the page's CURRENT load key
 * @param errorUpdateCount that query's errorUpdateCount (from useQuery)
 */
export function resolveErrorSlot(
  slot: ErrorSlot | null,
  queryKey: QueryKey,
  errorUpdateCount: number,
  loadErrorMessage: string,
): string | null {
  const failuresBefore = slot && slot.lineage === hashKey(queryKey) ? slot.afterFailures : 0;
  // A load failure writes the banner; a successful load never clears it (as
  // with the old loaders) — only a slot write does.
  if (errorUpdateCount > failuresBefore) return loadErrorMessage;
  return slot ? slot.message : null;
}
