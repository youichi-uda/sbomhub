// Pure core of useRetainedData (see use-retained-data.ts). Kept free of
// React so node --test can pin it.

export interface Retained<T> {
  scope: string;
  data: T;
}

/**
 * What to retain after this render: the new data when there is some,
 * otherwise the previous value — but only if it belongs to the same scope
 * (Codex R3: retaining across a project change showed Project A's rows on
 * Project B's page). Returns `prev` itself when nothing changes, so callers
 * can use it as an identity guard for a render-time setState.
 */
export function nextRetained<T>(
  prev: Retained<T> | null,
  scope: string,
  data: T | undefined,
): Retained<T> | null {
  if (data !== undefined) {
    return prev && prev.scope === scope && prev.data === data ? prev : { scope, data };
  }
  return prev && prev.scope === scope ? prev : null;
}
