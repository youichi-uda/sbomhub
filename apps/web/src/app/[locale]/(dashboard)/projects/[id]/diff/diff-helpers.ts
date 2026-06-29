// M10-6 (#74) — pure helpers used by the SBOM diff page.
//
// Extracted into a tiny TS module so they can be unit-tested with the
// project's existing node:test pattern (see proxy.matcher.test.mjs)
// without standing up a React renderer / Vitest / Jest dependency just
// for one page. The page itself is interactive (Client Component) and
// its rendering surface is exercised manually + via the API contract
// tests on the backend.

export interface DiffCountsLike {
  components: {
    added: unknown[];
    removed: unknown[];
    version_changed: unknown[];
  };
  vulnerabilities: {
    added: unknown[];
    resolved: unknown[];
    severity_changed: unknown[];
  };
  licenses: {
    added_policy_violations: unknown[];
    removed_policy_violations: unknown[];
  };
}

/**
 * Summarises the three diff envelopes as a flat count map. Used by the
 * timeline row badges. Zero-length sections are surfaced as `0` (not
 * undefined) so the caller can decide whether to render a badge based on
 * a single >0 check.
 */
export function diffCounts(d: DiffCountsLike) {
  return {
    componentsAdded: d.components.added.length,
    componentsRemoved: d.components.removed.length,
    componentsChanged: d.components.version_changed.length,
    vulnsAdded: d.vulnerabilities.added.length,
    vulnsResolved: d.vulnerabilities.resolved.length,
    vulnsSeverityChanged: d.vulnerabilities.severity_changed.length,
    licensesAdded: d.licenses.added_policy_violations.length,
    licensesRemoved: d.licenses.removed_policy_violations.length,
  };
}

/**
 * Builds the `?from=<from>&to=<to>` query string for a diff link. Both
 * args are optional — omitting either lets the server fall back to its
 * own defaulting rules (see backend service/diff/diff.go godoc).
 *
 * Returns an empty string when neither id is provided (i.e. "use the
 * server's default-newest behaviour").
 */
export function buildDiffQuery(from?: string, to?: string): string {
  const params: string[] = [];
  if (from) params.push(`from=${encodeURIComponent(from)}`);
  if (to) params.push(`to=${encodeURIComponent(to)}`);
  return params.length ? `?${params.join("&")}` : "";
}

/**
 * Normalised severity for badge colouring. Mirrors the backend's
 * canonical bucket names so the colour assignment is deterministic
 * regardless of upstream casing.
 */
export function normaliseSeverity(sev: string | undefined | null): string {
  if (!sev) return "unknown";
  const v = sev.trim().toLowerCase();
  if (v === "critical" || v === "high" || v === "medium" || v === "low") {
    return v;
  }
  return "unknown";
}

/**
 * Returns true when the response represents the "initial baseline"
 * single-SBOM case. The backend signals this by setting `from: null`
 * while `to` is populated and components.added contains everything.
 */
export function isInitialBaseline(d: { from: unknown; to: unknown }): boolean {
  return d.from === null && d.to !== null;
}
