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
  // Upgrade advice only from evidence that validates for THIS label (Codex
  // R2 Medium-1): a stray `fixed` in a partial or contradicting document is
  // not a version to recommend.
  const fixed = validDistroEvidence(method, evidence)?.fixed;
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
   * true only when the evidence names OSV's public API as its endpoint: the
   * osv.dev record links then show the records the verdict used. false for a
   * configured mirror or an unrecorded endpoint, whose records may differ.
   */
  publicOsv: boolean;
}

const PUBLIC_OSV_ORIGIN = "https://api.osv.dev";

/**
 * Whether an evidence endpoint is OSV's public API, compared as a URL origin
 * (scheme, lower-cased host, effective port), so `https://API.osv.dev:443/`
 * matches and `https://api.osv.dev.example` or a credentialed URL does not.
 */
export function isPublicOsvOrigin(sourceUrl: string | undefined): boolean {
  if (sourceUrl === undefined) return false;
  try {
    const u = new URL(sourceUrl);
    return u.username === "" && u.password === "" && u.origin === PUBLIC_OSV_ORIGIN;
  } catch {
    return false;
  }
}

const STATUS_FOR: Record<DistroMatchMethod, string> = {
  distro_affected: "affected",
  distro_unfixed: "unfixed",
  distro_fixed: "fixed",
};

/**
 * The ONE validator the badge and the evidence view share. Evidence is usable
 * only when it is recognisably the DistroEvidence of THIS label: its status
 * is the label's own (affected / unfixed / fixed), it names a release and at
 * least one record, and basis = later_releases appears only with "fixed" (the
 * only status the API infers that way). Anything less (an empty object, a
 * partial, corrupted or contradicting document) is "no evidence recorded",
 * never a table of dashes or a version to upgrade to. For "unfixed" a stray
 * fixed version is dropped: no fix is released by definition.
 */
export function validDistroEvidence(method: unknown, raw: unknown): DistroEvidence | null {
  if (!isDistroMatchMethod(method)) return null;
  const ev = parseDistroEvidence(raw);
  if (
    !ev ||
    ev.status !== STATUS_FOR[method] ||
    ev.release === undefined ||
    ev.package === undefined ||
    ev.installed === undefined ||
    (ev.records?.length ?? 0) === 0 ||
    (ev.basis === "later_releases" && (ev.status !== "fixed" || (ev.ecosystems?.length ?? 0) === 0))
  ) {
    return null;
  }
  return ev.status === "unfixed" ? { ...ev, fixed: undefined } : ev;
}

export function distroEvidenceView(method: unknown, evidence: unknown): DistroEvidenceView | null {
  if (!isDistroMatchMethod(method)) return null;
  const ev = validDistroEvidence(method, evidence);
  if (!ev) {
    return { method, hasEvidence: false, inferredFromLaterReleases: false, laterReleases: [], records: [], publicOsv: false };
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
    // Only an explicit public endpoint is public; an unrecorded one is
    // unknown and gets the same "osv.dev may differ" note as a mirror (Codex
    // R2 Medium-2).
    publicOsv: isPublicOsvOrigin(ev.source_url),
  };
}
