import { z } from "zod";

// ---------------------------------------------------------------------------
// Response schemas
//
// Only the fields this client needs to introspect are declared; everything
// else is preserved via .passthrough() so the full backend payload still
// reaches the MCP client. Shapes mirror apps/api/internal/model:
//   - model.Sbom          (id / version / created_at, ORDER BY created_at DESC)
//   - model.Vulnerability (severity is "CRITICAL" | "HIGH" | "MEDIUM" | "LOW")
// ---------------------------------------------------------------------------

const SbomSummarySchema = z
  .object({
    id: z.string().uuid(),
    version: z.string(),
    created_at: z.string(),
  })
  .passthrough();

// The Go handlers marshal a nil slice as JSON `null`, so accept null → [].
const SbomListSchema = z
  .array(SbomSummarySchema)
  .nullable()
  .transform((v) => v ?? []);

const VulnerabilitySchema = z
  .object({
    severity: z.string(),
  })
  .passthrough();

const VulnerabilityListSchema = z
  .array(VulnerabilitySchema)
  .nullable()
  .transform((v) => v ?? []);

// apps/api/internal/handler/sbom.go ScanStatusResponse. `status` is
// service.ScanState — running | completed | failed | unknown — and is NOT
// narrowed to an enum here: an unrecognised state must reach the caller as
// itself so it is reported as "not final" rather than rejected outright.
const ScanStatusSchema = z
  .object({
    status: z.string(),
    sbom_id: z.string(),
  })
  .passthrough();

export type SbomSummary = z.infer<typeof SbomSummarySchema>;
export type VulnerabilityEntry = z.infer<typeof VulnerabilitySchema>;

export type VulnSort = "cvss" | "epss";

// The ONE backend state under which the vulnerability counts are settled
// (service.ScanStateCompleted). Everything else — running, failed, unknown, a
// state this client has never heard of, or a scan-status request that could not
// be made at all — leaves them provisional.
//
// The asymmetry is deliberate and is the whole point: reporting a finished scan
// as unfinished costs a caveat, reporting an unfinished one as finished turns
// "the scan has matched nothing YET" into "this project is clean".
export const SCAN_STATE_FINAL = "completed";

// States this client generates itself, for the two ways the probe can fail to
// produce a backend answer. Both are non-final.
//
//   no_sbom     — the project has no SBOM at all, so nothing was ever scanned.
//                 A zero count here means "nothing uploaded", not "nothing
//                 found", and those are different answers to a compliance
//                 question.
//   unavailable — the scan state could not be read (the request failed, the
//                 body did not parse). Notably what a backend older than the
//                 X-API-Key fix answers, since it 401s the canonical routes for
//                 this client's header.
export const SCAN_STATE_NO_SBOM = "no_sbom";
export const SCAN_STATE_UNAVAILABLE = "unavailable";

/**
 * What the tool reports about the asynchronous scan behind the counts it just
 * read.
 *
 * `counts_final` is the field a model is expected to read; `scan_state` is why.
 * They travel together so "provisional" can be told apart from "provisional
 * because nobody knows", which call for different next steps (wait and retry
 * vs. check the deployment).
 */
export type ScanReport = {
  scan_state: string;
  counts_final: boolean;
  scanned_sbom_id: string | null;
};

// GET /mcp/projects/:id/vulnerabilities caps `?limit=` at 500 and
// `?offset=` at 10000 (apps/api/internal/handler/sbom.go VulnsMaxLimit /
// VulnsMaxOffset). We page through with the max page size and surface
// truncation explicitly instead of silently dropping rows.
const VULNS_PAGE_LIMIT = 500;
// Client-side scan cap so a pathological project cannot make one tool call
// issue 20+ requests / hold megabytes in memory. 10 pages x 500 = 5000 rows;
// results carry `scan_truncated` when the cap (or the backend offset cap)
// cuts the scan short.
const VULNS_SCAN_CAP = 5000;
// Upper bound on how many vulnerability entries a single tool response
// embeds. Counts (`matched`, `by_severity`) still cover the full scanned
// set; only the echoed array is capped to keep MCP responses usable.
const VULNS_RETURN_CAP = 500;

type RequestOptions = {
  method?: string;
  body?: unknown;
  /** Statuses to return instead of throwing (see requestRaw). */
  allowStatus?: number[];
};

// How the caller names the two SBOMs to compare. Ids win over versions; both
// sides default to the newest two snapshots.
export type DiffSelector = {
  baseVersion?: string;
  targetVersion?: string;
  baseSbomId?: string;
  targetSbomId?: string;
};

export class ApiClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey;
  }

  private async requestRaw(
    path: string,
    options: RequestOptions = {}
  ): Promise<{ data: unknown; headers: Headers; status: number }> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: options.method ?? "GET",
      headers: {
        "Content-Type": "application/json",
        // apps/api accepts the key in X-API-Key on every route an API key can
        // reach: APIKeyAuth (/api/v1/{cli,mcp}/*) always did, and MultiAuth
        // (the canonical /api/v1/projects/:id/... routes this client uses for
        // the scan-status probe) does since e84142c — before that it read only
        // Authorization and silently served the request as the self-hosted
        // default identity.
        "X-API-Key": this.apiKey,
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
      // Never follow redirects: Node's fetch strips Authorization on
      // cross-origin redirects but forwards custom headers like X-API-Key,
      // so a redirecting (or open-redirect-abused) endpoint could exfiltrate
      // the key. The SBOMHub API never redirects, so failing loud is safe.
      redirect: "error",
    });

    // `allowStatus` is a narrow escape hatch for ONE case: a 404 that is an
    // answer rather than a failure (a project with no SBOM). It is opt-in per
    // call so no other path can start treating an error status as data.
    if (!res.ok && !options.allowStatus?.includes(res.status)) {
      const text = await res.text();
      throw new Error(`API error ${res.status}: ${text}`);
    }
    return {
      data: (await res.json()) as unknown,
      headers: res.headers,
      status: res.status,
    };
  }

  async request(path: string, options: RequestOptions = {}): Promise<unknown> {
    const { data } = await this.requestRaw(path, options);
    return data;
  }

  // GET /api/v1/mcp/projects
  listProjects(): Promise<unknown> {
    return this.request("/api/v1/mcp/projects");
  }

  // GET /api/v1/mcp/projects/:id/sboms — newest first (created_at DESC).
  async listSboms(projectId: string): Promise<SbomSummary[]> {
    const data = await this.request(
      `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/sboms`
    );
    return SbomListSchema.parse(data);
  }

  // GET /api/v1/mcp/dashboard/summary — tenant-wide dashboard.
  getDashboardSummary(): Promise<unknown> {
    return this.request("/api/v1/mcp/dashboard/summary");
  }

  // Per-project dashboard, composed client-side from the three
  // project-scoped MCP routes. The backend MCP group deliberately has no
  // per-project dashboard route (dashboardService.GetSummary is tenant-wide
  // only), so the old `GET /mcp/projects/:id` call was a guaranteed 404.
  async getProjectDashboard(projectId: string): Promise<unknown> {
    const [scan, compliance, sboms] = await Promise.all([
      this.fetchVulnerabilities(projectId, "cvss"),
      this.getCompliance(projectId),
      this.listSboms(projectId),
    ]);

    const bySeverity: Record<string, number> = {};
    for (const v of scan.vulnerabilities) {
      const key = v.severity ? v.severity.toUpperCase() : "UNKNOWN";
      bySeverity[key] = (bySeverity[key] ?? 0) + 1;
    }

    return {
      project_id: projectId,
      sboms: {
        count: sboms.length,
        latest: sboms[0] ?? null,
      },
      vulnerabilities: {
        total: scan.total,
        // by_severity / top_by_cvss cover the highest-CVSS `analyzed` rows;
        // analyzed < total only when the scan cap cut the walk short
        // (scan_truncated, see VULNS_SCAN_CAP).
        analyzed: scan.vulnerabilities.length,
        scan_truncated: scan.truncated,
        // Nested with the counts they qualify, not at the root: this tool
        // composes the vulnerability answer into a sub-object, and a flag
        // sitting one level away from the numbers is a flag the model reads
        // separately from them (the shape that let a truncated dashboard pass
        // the disclosure rule, Codex R2).
        ...scan.report,
        by_severity: bySeverity,
        top_by_cvss: scan.vulnerabilities.slice(0, 10),
      },
      compliance,
    };
  }

  // GET /api/v1/mcp/search/cve?q=<cve-id>
  searchCVE(cveId: string): Promise<unknown> {
    return this.request(`/api/v1/mcp/search/cve?q=${encodeURIComponent(cveId)}`);
  }

  // GET /api/v1/mcp/search/component?name=<name>[&version=<version>]
  searchComponent(name: string, version?: string): Promise<unknown> {
    let url = `/api/v1/mcp/search/component?name=${encodeURIComponent(name)}`;
    if (version) {
      url += `&version=${encodeURIComponent(version)}`;
    }
    return this.request(url);
  }

  // POST /api/v1/mcp/sbom/diff with { base_sbom_id, target_sbom_id },
  // resolved from the project's SBOM list (newest first).
  //
  // `version` is NOT an upload version. apps/api/internal/service/sbom.go
  // fills model.Sbom.Version from the document's own spec version
  // (CycloneDX `specVersion`, SPDX `spdxVersion`), so a project that keeps
  // uploading CycloneDX 1.5 has every row reading "1.5". Selecting by version
  // used to take the first match — the NEWEST — which meant
  // `base_version: "1.5", target_version: "1.5"` silently diffed the newest
  // SBOM against itself and reported "no changes" (Codex R4). Ambiguity is now
  // an error, and `*_sbom_id` gives the model a selector that actually selects.
  async diff(projectId: string, selector: DiffSelector = {}): Promise<unknown> {
    const sboms = await this.listSboms(projectId);
    if (sboms.length < 2) {
      throw new Error("Not enough SBOMs to diff");
    }

    const pick = (
      side: "base" | "target",
      id?: string,
      version?: string
    ): SbomSummary | null => {
      // Explicit undefined checks, not truthiness: "" reaching here would
      // otherwise fall through to the default (the newest two SBOMs) and
      // return a comparison nobody asked for.
      if (id !== undefined) {
        if (id === "") {
          throw new Error(`${side}_sbom_id was empty; omit it or pass an SBOM id`);
        }
        const found = sboms.find((s) => s.id === id);
        if (!found) {
          throw new Error(
            `${side}_sbom_id ${id} is not one of this project's SBOMs`
          );
        }
        return found;
      }
      if (version !== undefined) {
        if (version === "") {
          throw new Error(
            `${side}_version was empty; omit it to default to the newest SBOMs`
          );
        }
        const matches = sboms.filter(
          (s) => s.version.toLowerCase() === version.toLowerCase()
        );
        if (matches.length === 0) {
          throw new Error("SBOM version not found");
        }
        if (matches.length > 1) {
          throw new Error(
            `${side}_version "${version}" matches ${matches.length} SBOMs ` +
              `(${matches.map((m) => `${m.id} @ ${m.created_at}`).join(", ")}). ` +
              "`version` is the SBOM spec version (CycloneDX/SPDX), not a unique " +
              `identifier — pass ${side}_sbom_id to choose one`
          );
        }
        return matches[0];
      }
      return null;
    };

    const target =
      pick("target", selector.targetSbomId, selector.targetVersion) ?? sboms[0];
    const base =
      pick("base", selector.baseSbomId, selector.baseVersion) ?? sboms[1];

    if (base.id === target.id) {
      throw new Error(
        `base and target resolved to the same SBOM (${base.id}); a diff of an ` +
          "SBOM against itself is empty by construction, which would read as " +
          "'nothing changed'"
      );
    }

    return this.request("/api/v1/mcp/sbom/diff", {
      method: "POST",
      body: {
        base_sbom_id: base.id,
        target_sbom_id: target.id,
      },
    });
  }

  // GET /api/v1/mcp/projects/:id/vulnerabilities?limit=500&offset=N&sort=<cvss|epss>
  //
  // The backend supports limit / offset / sort only — it has no severity
  // query param (and model.Vulnerability has no status field at all), so the
  // severity filter is applied client-side over the scanned rows and the
  // response says explicitly how much of the project it covers.
  async getVulnerabilities(
    projectId: string,
    severity?: string,
    sort: VulnSort = "cvss"
  ): Promise<unknown> {
    const scan = await this.fetchVulnerabilities(projectId, sort);
    const severityFilter = severity ? severity.toUpperCase() : null;
    const matched = severityFilter
      ? scan.vulnerabilities.filter(
          (v) => v.severity.toUpperCase() === severityFilter
        )
      : scan.vulnerabilities;
    const returned = matched.slice(0, VULNS_RETURN_CAP);

    return {
      total_in_project: scan.total,
      scanned: scan.vulnerabilities.length,
      scan_truncated: scan.truncated,
      ...scan.report,
      sort,
      severity_filter: severityFilter,
      matched: matched.length,
      returned: returned.length,
      vulnerabilities: returned,
    };
  }

  // GET /api/v1/mcp/projects/:id/compliance
  getCompliance(projectId: string): Promise<unknown> {
    return this.request(
      `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/compliance`
    );
  }

  // Walks the paginated endpoint page by page (500 rows each) until the
  // project is exhausted or VULNS_SCAN_CAP is hit. `truncated` is true when
  // rows beyond the scan remain on the server, OR when the walk stopped at the
  // cap without ever seeing the end.
  //
  // Two ways this used to report a partial scan as a complete one:
  //
  //   1. A missing or unparseable X-Total-Count fell back to
  //      `total = vulnerabilities.length`, which immediately satisfied the
  //      `vulnerabilities.length >= total` break. One 500-row page out of a
  //      1200-row project came back as `total_in_project: 500,
  //      scan_truncated: false` — a partial answer that reads as the whole
  //      project. The header is now REQUIRED and strictly parsed: absent,
  //      empty, non-integer or negative is a loud error, because in a
  //      compliance product an unanswerable question must not look like an
  //      answered one.
  //   2. The walk trusted that same header to decide it was finished. It now
  //      continues while pages come back FULL and stops on a short page, which
  //      is evidence from the data rather than from a header. A header that
  //      under-reports therefore cannot cut the scan short; it costs one extra
  //      request when the row count is an exact multiple of the page size.
  private async fetchVulnerabilities(
    projectId: string,
    sort: VulnSort
  ): Promise<{
    total: number;
    vulnerabilities: VulnerabilityEntry[];
    truncated: boolean;
    report: ScanReport;
  }> {
    const vulnerabilities: VulnerabilityEntry[] = [];
    let reportedTotal = 0;
    let sawEnd = false;
    // Row identities seen so far. The backend returns each vulnerability at
    // most once per walk (the paginated query dedupes by vulnerability id),
    // so a repeat means the rows moved between requests — a replacement SBOM
    // snapshot, or an EPSS sync rewriting the sort key under `?sort=epss`.
    // Either way offsets no longer address a stable sequence and the pages
    // cannot be concatenated.
    const seen = new Set<string>();

    for (let offset = 0; offset < VULNS_SCAN_CAP; offset += VULNS_PAGE_LIMIT) {
      const { data, headers } = await this.requestRaw(
        `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/vulnerabilities?limit=${VULNS_PAGE_LIMIT}&offset=${offset}&sort=${sort}`
      );
      const page = VulnerabilityListSchema.parse(data);
      const pageTotal = parseTotalCount(headers, offset);

      // Every page is answered against whatever is the project's LATEST SBOM
      // at that moment — the handler resolves it per request. If an upload (or
      // a rescan) lands mid-walk, the pages come from different snapshots and
      // concatenating them produces a vulnerability set that never existed.
      // The per-request count is the cheapest evidence of that: it is a
      // COUNT(*) over the same snapshot the page came from, so a change means
      // the ground moved (Codex R4). Refuse rather than blend.
      if (offset > 0 && pageTotal !== reportedTotal) {
        throw new Error(
          `the project's vulnerability set changed while it was being read ` +
            `(X-Total-Count went from ${reportedTotal} to ${pageTotal} at offset ${offset}); ` +
            "the pages come from different SBOM snapshots and cannot be combined — retry"
        );
      }

      for (const row of page) {
        const key = rowIdentity(row);
        if (seen.has(key)) {
          throw new Error(
            `the project's vulnerability list shifted while it was being read ` +
              `(row ${key} came back twice, at offset ${offset}); the pages no longer form ` +
              "one consistent list — retry"
          );
        }
        seen.add(key);
      }

      vulnerabilities.push(...page);
      reportedTotal = pageTotal;

      // Short page = the server has no more rows. This is the ONLY evidence
      // accepted for "the scan is complete".
      if (page.length < VULNS_PAGE_LIMIT) {
        sawEnd = true;
        break;
      }

    }

    // A header that claims fewer rows than were actually read is not evidence
    // that rows are missing; report what is known to exist.
    const total = Math.max(reportedTotal, vulnerabilities.length);

    return {
      total,
      vulnerabilities,
      // Stopping at the cap without a short page leaves the end unproven, so
      // it is reported as truncated even if the header says otherwise. The
      // conservative direction: over-reporting truncation costs a caveat,
      // under-reporting it costs a wrong compliance answer.
      truncated: !sawEnd || total > vulnerabilities.length,
      // AFTER the walk, deliberately. See probeScanState.
      report: await this.probeScanState(projectId),
    };
  }

  /**
   * Ask whether the background scan behind the counts just read has finished.
   *
   * # Why this exists
   *
   * apps/api answers `GET /mcp/projects/:id/vulnerabilities` from whatever the
   * asynchronous NVD/JVN scan has matched SO FAR. A project whose scan is still
   * running therefore answers `[]` with `X-Total-Count: 0` — byte-identical to a
   * project that was scanned and found clean. Every field of this client's
   * response would then be individually true and the answer as a whole wrong, in
   * the direction that matters most in a compliance product.
   *
   * # Why the probe runs AFTER the page walk
   *
   * Each page is answered against whatever is the project's LATEST SBOM at that
   * moment (SbomService.GetVulnerabilitiesPaginated → sbomRepo.GetLatest), so an
   * upload landing mid-walk moves the ground under the pages. Resolving the
   * latest SBOM afterwards means such a walk is attributed to the NEW snapshot,
   * whose scan was marked running synchronously by the upload handler before its
   * goroutine started — so the race resolves to "not final", which is the
   * conservative direction. Probing first would have the opposite bias: a
   * `completed` answer captured before an upload would be reported for pages
   * read after it.
   *
   * `GET /api/v1/projects/:id/sbom` is the SAME resolution the vulnerability
   * pages use — not `/mcp/projects/:id/sboms` ordered newest-first, which would
   * be an inference about which row that resolution picks.
   *
   * # Why a failure here is not a tool failure
   *
   * The vulnerabilities were read successfully; only the ability to vouch for
   * them is missing. Refusing the whole call would make the tool unusable
   * against, for instance, a backend that predates the X-API-Key fix (it 401s
   * these routes for this client's header). So the failure is reported in-band
   * as a non-final state, never swallowed into an implied "finished".
   */
  private async probeScanState(projectId: string): Promise<ScanReport> {
    const unavailable = (sbomId: string | null): ScanReport => ({
      scan_state: SCAN_STATE_UNAVAILABLE,
      counts_final: false,
      scanned_sbom_id: sbomId,
    });

    let sbomId: string;
    try {
      const { data, status } = await this.requestRaw(
        `/api/v1/projects/${encodeURIComponent(projectId)}/sbom`,
        { allowStatus: [404] }
      );
      if (status === 404) {
        // No SBOM was ever uploaded. Nothing was scanned, so a count of zero
        // says nothing about the project's exposure — which is exactly the
        // conclusion a model would otherwise draw from it.
        return {
          scan_state: SCAN_STATE_NO_SBOM,
          counts_final: false,
          scanned_sbom_id: null,
        };
      }
      sbomId = SbomSummarySchema.parse(data).id;
    } catch {
      return unavailable(null);
    }

    try {
      const data = await this.request(
        `/api/v1/projects/${encodeURIComponent(projectId)}` +
          `/sboms/${encodeURIComponent(sbomId)}/scan-status`
      );
      const state = ScanStatusSchema.parse(data).status;
      return {
        scan_state: state,
        // Equality against ONE literal, not a list of "bad" states: a state
        // this client has never heard of is then non-final by construction
        // rather than by having been enumerated.
        counts_final: state === SCAN_STATE_FINAL,
        scanned_sbom_id: sbomId,
      };
    } catch {
      return unavailable(sbomId);
    }
  }
}

// ---------------------------------------------------------------------------

// Identity of one vulnerability row. model.Vulnerability carries a uuid `id`;
// cve_id and then the whole row are fallbacks so a shape change degrades the
// check rather than silently disabling it.
function rowIdentity(row: VulnerabilityEntry): string {
  const record = row as Record<string, unknown>;
  if (typeof record.id === "string" && record.id !== "") return record.id;
  if (typeof record.cve_id === "string" && record.cve_id !== "") {
    return record.cve_id;
  }
  return JSON.stringify(row);
}

// apps/api/internal/handler/sbom.go always sets X-Total-Count on the success
// path (it is what the Web UI pages with). Its absence means something else
// answered — a proxy, an error page, a future backend that dropped it — and
// the honest response to "I cannot tell how much of this project I saw" is to
// say so, not to assume the first page was all of it.
function parseTotalCount(headers: Headers, offset: number): number {
  const raw = headers.get("X-Total-Count");
  if (raw === null || raw.trim() === "") {
    throw new Error(
      `vulnerabilities page at offset ${offset} carried no X-Total-Count header; ` +
        "refusing to report a possibly partial scan as the whole project"
    );
  }
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(
      `vulnerabilities page at offset ${offset} carried an invalid X-Total-Count ` +
        `("${raw}"); refusing to report a possibly partial scan as the whole project`
    );
  }
  return value;
}
