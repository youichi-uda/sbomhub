// M70 distro labels on the vulnerability list: the pure mapping from the
// API's match_method / match_evidence to what the UI shows. Kept free of
// React so node:test can pin it (src/lib/__tests__/match-method.test.mjs).
//
// The API (apps/api/internal/model/match_method.go, match_evidence.go;
// docs/UPGRADE.md §21) returns, per CVE, the strongest match_method among the
// SBOM's links to it and — only for a distro label — the evidence stored with
// that link, projected through its public fields. Three labels exist:
//
//   distro_affected  the distro released a fix above the installed version
//                    (high confidence; evidence.fixed is the version to
//                    upgrade to)
//   distro_unfixed   affected, no fix released (high confidence)
//   distro_fixed     the distro's data says the installed version already
//                    contains the fix. The link is KEPT and still counted:
//                    it is NOT not_affected. A human reviews the evidence
//                    and, if it holds, records a VEX statement ("SBOMHub
//                    drafts, humans approve").
//
// Every other method (the M60 NVD / JVN labels) is not rendered by this
// module: distroBadge / distroEvidenceView return null for it.

export type DistroMatchMethod = "distro_affected" | "distro_unfixed" | "distro_fixed";

/** The public fields of model.DistroEvidence as the API returns them. */
export interface DistroEvidence {
  source?: string;
  source_url?: string;
  status?: string;
  basis?: string;
  release?: string;
  ecosystems?: string[];
  package?: string;
  installed?: string;
  fixed?: string;
  records?: string[];
  fetched_at?: string;
  data_modified?: string;
}

export function isDistroMatchMethod(m: unknown): m is DistroMatchMethod {
  return m === "distro_affected" || m === "distro_unfixed" || m === "distro_fixed";
}

/** next-intl key under the "MatchMethod" namespace. */
export type DistroBadgeLabel = "distroAffected" | "distroAffectedUpgrade" | "distroUnfixed" | "distroFixed";

export interface DistroBadge {
  method: DistroMatchMethod;
  /** "affected": the CVE applies; "review": fixed per the distro, a human confirms. */
  tone: "affected" | "review";
  label: DistroBadgeLabel;
  /** The version to upgrade to; only for distro_affected with a known fix. */
  upgradeTo?: string;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

function strList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    const s = str(x);
    if (s !== undefined && !out.includes(s)) out.push(s);
  }
  return out;
}

/**
 * Evidence arrives as JSON from the API; nothing in it is trusted to have the
 * declared shape. Anything that is not a plain object reads as "no evidence".
 */
export function parseDistroEvidence(raw: unknown): DistroEvidence | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  return {
    source: str(o.source),
    source_url: str(o.source_url),
    status: str(o.status),
    basis: str(o.basis),
    release: str(o.release),
    ecosystems: strList(o.ecosystems),
    package: str(o.package),
    installed: str(o.installed),
    fixed: str(o.fixed),
    records: strList(o.records),
    fetched_at: str(o.fetched_at),
    data_modified: str(o.data_modified),
  };
}

export function distroBadge(method: unknown, evidence: unknown): DistroBadge | null {
  if (!isDistroMatchMethod(method)) return null;
  if (method === "distro_fixed") {
    return { method, tone: "review", label: "distroFixed" };
  }
  if (method === "distro_unfixed") {
    return { method, tone: "affected", label: "distroUnfixed" };
  }
  const fixed = parseDistroEvidence(evidence)?.fixed;
  return fixed !== undefined
    ? { method, tone: "affected", label: "distroAffectedUpgrade", upgradeTo: fixed }
    : { method, tone: "affected", label: "distroAffected" };
}

// OSV ids are short ASCII tokens ("DEBIAN-CVE-2021-3449", "DSA-4875-1",
// "UBUNTU-CVE-2021-3449", "ALSA-2023:1234", "RLSA-2023:1234"). Only such a
// token becomes a link; anything else is shown as text, never as an href.
const OSV_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function osvRecordUrl(id: string): string | null {
  if (!OSV_ID.test(id)) return null;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

export interface DistroEvidenceRecord {
  id: string;
  url: string | null;
}

export interface DistroEvidenceView {
  method: DistroMatchMethod;
  /** false when the API sent no (usable) evidence for the label. */
  hasEvidence: boolean;
  source?: string;
  release?: string;
  /** "release" | "later_releases" | another value the API may add later. */
  basis?: string;
  /** basis = later_releases: the verdict was inferred for an end-of-life Debian release. */
  inferredFromLaterReleases: boolean;
  /** The later releases whose data decided a later_releases verdict. */
  laterReleases: string[];
  package?: string;
  installed?: string;
  fixed?: string;
  records: DistroEvidenceRecord[];
  fetchedAt?: string;
  /** The endpoint ORIGIN the data came from (the API never sends more). */
  sourceUrl?: string;
  /** The data's own revision (newest OSV `modified` of the package). */
  dataModified?: string;
  /**
   * true when the data came from OSV's public API (or the API did not say):
   * the osv.dev record links then show the records the verdict used. false
   * for a configured mirror, whose records may differ from osv.dev's.
   */
  publicOsv: boolean;
}

const PUBLIC_OSV_ORIGIN = "https://api.osv.dev";

const DISTRO_STATUSES = new Set(["affected", "unfixed", "fixed"]);

/**
 * Evidence is usable only when it is recognisably DistroEvidence: a known
 * status, a release and at least one record. Anything less (an empty object,
 * a partial or corrupted document) is shown as "no evidence recorded" rather
 * than as a table of dashes that looks like a verdict's basis.
 */
function coherent(ev: DistroEvidence): boolean {
  return (
    ev.status !== undefined &&
    DISTRO_STATUSES.has(ev.status) &&
    ev.release !== undefined &&
    (ev.records?.length ?? 0) > 0
  );
}

export function distroEvidenceView(method: unknown, evidence: unknown): DistroEvidenceView | null {
  if (!isDistroMatchMethod(method)) return null;
  const ev = parseDistroEvidence(evidence);
  if (!ev || !coherent(ev)) {
    return { method, hasEvidence: false, inferredFromLaterReleases: false, laterReleases: [], records: [], publicOsv: true };
  }
  return {
    method,
    hasEvidence: true,
    source: ev.source,
    release: ev.release,
    basis: ev.basis,
    inferredFromLaterReleases: ev.basis === "later_releases",
    laterReleases: ev.ecosystems ?? [],
    package: ev.package,
    installed: ev.installed,
    fixed: ev.fixed,
    records: (ev.records ?? []).map((id) => ({ id, url: osvRecordUrl(id) })),
    fetchedAt: ev.fetched_at,
    sourceUrl: ev.source_url,
    dataModified: ev.data_modified,
    publicOsv: ev.source_url === undefined || ev.source_url.replace(/\/+$/, "") === PUBLIC_OSV_ORIGIN,
  };
}
