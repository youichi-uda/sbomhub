// Organisation scoping for the react-query cache (Codex R1 + R2 Critical).
//
// Query keys are not org-scoped: the API client injects the Clerk org (via
// the token template and X-Clerk-Org-ID) at request time. So the dashboard
// subtree gets ONE QueryClient PER ORGANISATION, mounted under a React key
// derived from the org (ApiAuthProvider). Switching organisation therefore
//   - unmounts the whole subtree: no query data, no retained data
//     (useRetainedData), no drafts or saved-response state survive;
//   - drops the old QueryClient: a mutation started under Org A that
//     resolves after the switch can only write (setQueryData /
//     invalidateQueries) into the discarded client, never into Org B's.
// A reset of a shared client (R1's first fix) was not enough: mounted
// component state kept Org A's data, and late Org A mutations could
// repopulate the reset cache (R2).
//
// orgScopeKey() is also the gate: while Clerk reports an org the token
// getter has not been re-wired to yet (between the org change and the
// wiring effect), it returns null and nothing is rendered, so no request
// can go out with one org's token from a component holding the other's data.

/**
 * @param wiredOrg  org the API client's getters are wired to; undefined
 *                  until the first wiring.
 * @param currentOrg org Clerk currently reports (null = no org).
 * @returns the React key for the org-scoped subtree, or null to render
 *          nothing yet.
 */
export function orgScopeKey(
  wiredOrg: string | null | undefined,
  currentOrg: string | null,
): string | null {
  if (wiredOrg === undefined || wiredOrg !== currentOrg) return null;
  return wiredOrg === null ? "no-org" : `org:${wiredOrg}`;
}
