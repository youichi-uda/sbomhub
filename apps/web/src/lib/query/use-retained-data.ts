"use client";

import { useState } from "react";
import { nextRetained, type Retained } from "./retain";

/**
 * Returns `data`, or — while `data` is undefined — the last defined value
 * this hook has seen FOR THE SAME `scope`.
 *
 * The pre-react-query loaders kept their result in `useState`, so a page
 * whose query parameter changed (audit page/filter, report list page,
 * analytics period, vulnerability sort) kept showing the previous result
 * while the new request was in flight AND after it failed (the error banner
 * appeared above the previous rows). react-query's `keepPreviousData`
 * covers the in-flight half only — once the new key errors, `data` becomes
 * undefined. This hook covers both halves.
 *
 * `scope` names the entity the data belongs to (e.g. the project id): when
 * it changes, nothing is retained (Codex R3), so one project's rows are
 * never shown on another project's page.
 *
 * Uses the "store information from previous renders" pattern from the React
 * docs (a guarded setState during render), not an effect, so no extra
 * committed frame shows the empty state.
 */
export function useRetainedData<T>(data: T | undefined, scope: string): T | undefined {
  const [retained, setRetained] = useState<Retained<T> | null>(null);
  const next = nextRetained(retained, scope, data);
  if (next !== retained) {
    setRetained(next);
  }
  return next?.data;
}
