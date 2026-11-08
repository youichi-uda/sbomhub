// react-query client defaults for apps/web.
//
// The data loaders migrated onto @tanstack/react-query used to be
// `useEffect` + `useState` fetches (the 2026-11 react-hooks 7.1 lint
// residual). These defaults are chosen so the migration is
// behaviour-preserving rather than "react-query defaults":
//
//   - retry: false — the hand-written loaders made exactly one request and
//     surfaced the failure immediately. react-query's default of 3 retries
//     with exponential back-off would hold a spinner for ~7 s before the
//     page showed its (i18n) error message, and would triple the load on
//     an API that is already failing.
//   - refetchOnWindowFocus / refetchOnReconnect: false — nothing refetched
//     on tab focus before. Turning it on would, among other things, wipe a
//     half-edited settings form that is re-seeded from server data.
//   - gcTime: 0 — no data outlives the component that asked for it. A
//     remount (navigating back to a page) shows the same loading state it
//     always did instead of a cached copy, and nothing fetched under one
//     Clerk organisation is ever rendered from cache under another (the
//     query keys are not org-scoped; the API client injects the org).
//   - staleTime: 0 — every mount / key change fetches, as the effects did.
//
// Pinned by src/lib/query/__tests__/query.test.mjs.

import { QueryClient, type DefaultOptions } from "@tanstack/react-query";

export const queryDefaults = {
  queries: {
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    staleTime: 0,
    gcTime: 0,
  },
  mutations: {
    retry: false,
  },
} as const satisfies DefaultOptions;

export function makeQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: queryDefaults });
}
