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
    // handler.VulnerabilitySummaryCount: per-severity buckets plus `kev` and
    // `total`, all computed over the same join the vulnerability pages are drawn
    // from. The WHOLE summary is compared before and after the walk, not just
    // `total` — a vulnerability whose severity is rewritten mid-walk (a KEV or
    // CVSS sync relabelling LOW as CRITICAL) leaves the total untouched while
    // making `by_severity` and any severity filter stale (Codex R4, High).
    // Every bucket is REQUIRED, not optional (Codex R5, Medium): with only
    // `total` required, a response omitting the severity buckets would parse,
    // compare equal across both readings, and be certified — having compared no
    // per-severity summary at all. handler.VulnerabilitySummaryCount marshals
    // all seven fields unconditionally, so a body without them did not come from
    // this API, and refusing to read it (-> SCAN_STATE_UNAVAILABLE) is the
    // fail-closed direction. .passthrough() keeps a bucket added later inside
    // the compared value.
    vulnerabilities: z
      .object({
        critical: z.number(),
        high: z.number(),
        medium: z.number(),
        low: z.number(),
        unknown: z.number(),
        kev: z.number(),
        total: z.number(),
      })
      .passthrough(),
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

// States this client generates itself. Both are non-final.
//
//   unavailable — the scan state could not be read at all: the request failed,
//                 the project or its latest SBOM could not be resolved, or the
//                 body did not parse. Notably what a backend older than the
//                 X-API-Key fix answers, since it 401s the canonical routes for
//                 this client's header.
//
//                 This deliberately does NOT distinguish "the project has no
//                 SBOM" (Codex R1 Low): GET /api/v1/projects/:id/sbom answers
//                 404 for a project that has no SBOM, for a project that does
//                 not exist, and for any repository error on the way — the
//                 handler maps every failure to that one status. A state named
//                 for one of those three would be a claim the response cannot
//                 support.
//
//   changed     — the scan, or the SBOM it belongs to, moved between the two
//                 probes taken around the page walk. The rows that were read
//                 cannot be attributed to a settled scan; see probeScanState.
export const SCAN_STATE_UNAVAILABLE = "unavailable";
export const SCAN_STATE_CHANGED = "changed";

/**
 * What the tool reports about the asynchronous scan behind the counts it just
 * read.
 *
 * `counts_final` is the field a model is expected to read; `scan_state` is why.
 * They travel together so "provisional" can be told apart from "provisional
 * because nobody knows", which call for different next steps (wait and retry
 * vs. check the deployment).
 *
 * `scanned_sbom_id` names the SBOM the STATE was read for. It is the source of
 * the counts only when `counts_final` is true — that is the case in which both
 * readings agreed on one SBOM. When they disagreed the field is null, because
 * naming either would assert an origin for rows that may have come from the
 * other or from both (Codex R2, Medium).
 */
/** One reading of the scan state, as taken by readScanState. */
type ScanProbe = {
  state: string;
  sbomId: string | null;
  /**
   * The whole per-severity summary, serialised, so two readings can be compared
   * as one value. Null when the state could not be read.
   */
  counts: string | null;
};

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
  /** Abort the in-flight request; see getProjectDashboard. */
  signal?: AbortSignal;
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
  ): Promise<{ data: unknown; headers: Headers }> {
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
      signal: options.signal,
      // Never follow redirects: Node's fetch strips Authorization on
      // cross-origin redirects but forwards custom headers like X-API-Key,
      // so a redirecting (or open-redirect-abused) endpoint could exfiltrate
      // the key. The SBOMHub API never redirects, so failing loud is safe.
      redirect: "error",
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`API error ${res.status}: ${text}`);
    }
    return { data: (await res.json()) as unknown, headers: res.headers };
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
  async listSboms(projectId: string, signal?: AbortSignal): Promise<SbomSummary[]> {
    const data = await this.request(
      `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/sboms`,
      { signal }
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
  //
  // NOT aborted when one leg fails (Codex R2, Low). Promise.all rejects on the
  // first rejection but leaves the other legs running, so a capped project keeps
  // issuing page requests after the tool has already answered with an error, and
  // those land on the per-API-key rate-limit counter the next call needs. An
  // AbortController fixes that and was written — and reverted, because the
  // number of requests a failing dashboard makes then depends on when the abort
  // lands relative to the in-flight fetches. Every case in the contract suite
  // asserts the EXACT request list, and that exactness is what makes the suite
  // able to catch a tool talking to a route it should not. Trading it for a
  // bounded amount of wasted quota on an error path is the wrong way round.
  // Recorded in docs/UPGRADE.md §7.2.
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
  getCompliance(projectId: string, signal?: AbortSignal): Promise<unknown> {
    return this.request(
      `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/compliance`,
      { signal }
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
    sort: VulnSort,
    signal?: AbortSignal
  ): Promise<{
    total: number;
    vulnerabilities: VulnerabilityEntry[];
    truncated: boolean;
    report: ScanReport;
  }> {
    // BEFORE the walk. See probeScanState for why one probe on either side is
    // not enough and this one has to be taken first.
    const before = await this.readScanState(projectId, signal);

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
        `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/vulnerabilities?limit=${VULNS_PAGE_LIMIT}&offset=${offset}&sort=${sort}`,
        { signal }
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
    // Stopping at the cap without a short page leaves the end unproven, so it
    // is reported as truncated even if the header says otherwise. The
    // conservative direction: over-reporting truncation costs a caveat,
    // under-reporting it costs a wrong compliance answer.
    const truncated = !sawEnd || total > vulnerabilities.length;

    return {
      total,
      vulnerabilities,
      truncated,
      // The walk is bracketed by two probes; this closes the pair.
      report: await this.probeScanState(projectId, before, !truncated, signal),
    };
  }

  /**
   * Read the state of the asynchronous scan behind a project's vulnerability
   * counts, ONCE.
   *
   * apps/api answers `GET /mcp/projects/:id/vulnerabilities` from whatever the
   * background NVD/JVN scan has matched SO FAR, so a project whose scan is still
   * running answers `[]` with `X-Total-Count: 0` — byte-identical to a project
   * that was scanned and found clean. This is what tells the two apart.
   *
   * `GET /api/v1/projects/:id/sbom` is the SAME resolution the vulnerability
   * pages use (SbomService.GetVulnerabilitiesPaginated -> sbomRepo.GetLatest),
   * not `/mcp/projects/:id/sboms` ordered newest-first, which would be an
   * inference about which row that resolution picks.
   *
   * The per-severity summary comes back too: every bucket is computed over the
   * same join the pages are drawn from, and comparing the WHOLE summary across
   * the walk is what probeScanState uses to detect a scan that moved. The
   * response's own `sbom_id` is checked against the one asked for, so an answer
   * about a different SBOM is reported as unreadable rather than accepted
   * (Codex R1).
   *
   * Never throws: a failure here must not turn a usable vulnerability answer
   * into a tool error, and must not be mistaken for "finished" either. It
   * becomes SCAN_STATE_UNAVAILABLE, which is non-final.
   */
  private async readScanState(
    projectId: string,
    signal?: AbortSignal
  ): Promise<ScanProbe> {
    const unreadable: ScanProbe = {
      state: SCAN_STATE_UNAVAILABLE,
      sbomId: null,
      counts: null,
    };

    try {
      const latest = SbomSummarySchema.parse(
        await this.request(
          `/api/v1/projects/${encodeURIComponent(projectId)}/sbom`,
          { signal }
        )
      );
      const status = ScanStatusSchema.parse(
        await this.request(
          `/api/v1/projects/${encodeURIComponent(projectId)}` +
            `/sboms/${encodeURIComponent(latest.id)}/scan-status`,
          { signal }
        )
      );
      if (status.sbom_id !== latest.id) {
        return unreadable;
      }
      return {
        state: status.status,
        sbomId: status.sbom_id,
        // Serialised with sorted keys so the comparison is over VALUES and not
        // over the backend's field order.
        counts: JSON.stringify(
          Object.fromEntries(
            Object.entries(status.vulnerabilities).sort(([a], [b]) =>
              a < b ? -1 : a > b ? 1 : 0
            )
          )
        ),
      };
    } catch {
      return unreadable;
    }
  }

  /**
   * Decide whether the rows just read may be reported as settled.
   *
   * # What "settled" has to mean (Codex R1, High)
   *
   * A single probe AFTER the walk is not enough, and a single probe BEFORE it is
   * not either. The scan can finish DURING the walk: pages read while it was
   * still matching return stale — possibly empty — rows, and a probe taken
   * afterwards then reports `completed` and certifies them. That is the original
   * defect with a smaller window, which is not a fix.
   *
   * So the walk is bracketed. `counts_final` requires all of:
   *
   *   - the scan was already `completed` when the walk STARTED, and
   *   - it is still `completed` now, and
   *   - it is the same SBOM (no upload made a different snapshot the latest), and
   *   - that SBOM's vulnerability count is unchanged.
   *
   * The last one is what covers the untracked rescan. apps/api's manual rescan
   * path does not mark the shared ScanTracker at all, so a rescan of an SBOM
   * whose entry still reads `completed` (entries are kept an hour) is invisible
   * in the STATE. It is visible in the SUMMARY when that summary MOVES BETWEEN
   * THE TWO READINGS — and because VulnerabilityHandler.runScan commits NVD and
   * JVN in ONE transaction, a reader sees the whole rescan or none of it, so
   * "between the two readings" is the only window in which a rescan can affect
   * the walk without being reported. What remains is a rescan whose new summary
   * equals the old, which is the replacement case below.
   *
   * Two earlier versions of this comment were wrong about this and are corrected
   * rather than softened: it does NOT catch a rescan "once it has written
   * something" (Codex R2), and the rescan does NOT write in phases that a reader
   * could observe half of (Codex R6 — the transaction is what rules that out).
   *
   * That window cannot be closed from here: nothing the API exposes distinguishes
   * "no rescan running" from "a rescan running that has not written yet". Closing
   * it means marking the tracker on the manual rescan path in apps/api, which is
   * a backend change; it is recorded in docs/UPGRADE.md §7.2 rather than papered
   * over, because `counts_final` has to mean what it says.
   *
   * So what `counts_final: true` asserts, exactly: the scan apps/api TRACKS for
   * this SBOM reported completed both before and after the read, its count did
   * not move, and the walk covered the whole project. It is the strongest
   * statement the API supports, not a guarantee that no write is in flight.
   *
   * # Cost, and why the cheap case is the common one
   *
   * The second probe is only issued when the first said `completed`, because
   * nothing the second could say would make a non-completed answer final. A
   * just-uploaded project (`running`) and any project whose tracker entry has
   * aged out (`unknown`, the steady state after an hour or a restart) therefore
   * cost two requests, not four.
   *
   * The request COUNT is unchanged by any of this, and is worth stating exactly
   * because it is easy to read the paragraph below as though it were smaller. A
   * one-page walk over a `completed` scan issues five requests: two for the
   * probe before the walk, one page, and two for the probe after it. Each
   * additional page is one more. A non-completed scan issues three, because the
   * second probe is skipped.
   *
   * What DID change is where those requests are charged, and two earlier
   * versions of this comment were written against the old behaviour.
   * RateLimitByAPIKey once keyed its Redis counter on the API key and the
   * minute alone (`mcp:ratelimit:<key id>:<window>`), so every rate-limited
   * route on the server advanced ONE integer and these probes were charged to
   * the same bucket as the vulnerability walk. Since M51 the counter is named by
   * a BUDGET — `ratelimit:apikey:v2:<key id>:<budget>:<window>` — and the three
   * ROUTES this method's caller touches sit in three different buckets:
   *
   *   GET /api/v1/mcp/projects/:id/vulnerabilities   budget `mcp`       60/min
   *   GET /api/v1/projects/:id/sbom                  budget `standard`  60/min
   *   GET .../sboms/:sbom_id/scan-status             budget `poll`     300/min
   *
   * So the probe no longer eats the walk's budget, and the polling half of it
   * runs against the 300/min ceiling that exists for polling. What it DOES share
   * is `standard` with SBOM upload and `GET .../vulnerabilities`, so a client
   * that both uploads and probes in the same minute spends one 60/min bucket on
   * the pair. The route is still not part of the key: two routes on one budget
   * still share a counter, by design (see the Budget doc comment in
   * apps/api/internal/middleware/ratelimit.go for why per-route buckets were
   * rejected). Recorded in docs/UPGRADE.md §8.
   *
   * # Why a failure here is not a tool failure
   *
   * The vulnerabilities were read successfully; only the ability to vouch for
   * them is missing. Refusing the whole call would make the tool unusable
   * against, for instance, a backend that predates the X-API-Key fix (it 401s
   * these routes for this client's header). So a failure is reported in-band as
   * a non-final state, never swallowed into an implied "finished".
   *
   * # What this still does not prove (honest limitations)
   *
   *   - the untracked-rescan window described above;
   *   - a REPLACEMENT that keeps the whole summary the same — including a
   *     rescan whose result happens to be summary-identical. The per-page
   *     X-Total-Count guard fires only when the count MOVES, and the
   *     row-identity guard only when a row is seen twice, so an interleaving
   *     that swaps one row for another can slip past both: read rows 0-499,
   *     have row 0 replaced by a row that sorts last, and page two returns
   *     501-599 plus the replacement — 600 distinct rows, none repeated, the
   *     count unchanged, and row 500 never read (Codex R3, Medium; reproduced
   *     against the stub). Ordering the walk over a snapshot is what would
   *     close this, and the API offers no snapshot token to walk against.
   *
   * An earlier version of this comment claimed the multi-page guards caught the
   * equal-cardinality case. They do not, and the claim is removed rather than
   * softened: a false statement about what is guarded is worse than no
   * statement, because it is the one a reader would rely on.
   */
  private async probeScanState(
    projectId: string,
    before: ScanProbe,
    walkCovered: boolean,
    signal?: AbortSignal
  ): Promise<ScanReport> {
    if (before.state !== SCAN_STATE_FINAL) {
      return {
        scan_state: before.state,
        counts_final: false,
        scanned_sbom_id: before.sbomId,
      };
    }

    const after = await this.readScanState(projectId, signal);
    if (after.state === SCAN_STATE_UNAVAILABLE) {
      // The walk began on a finished scan, but whether it still is cannot be
      // read — which is not evidence that it is.
      return {
        scan_state: SCAN_STATE_UNAVAILABLE,
        counts_final: false,
        scanned_sbom_id: before.sbomId,
      };
    }

    const settled =
      after.state === SCAN_STATE_FINAL &&
      after.sbomId === before.sbomId &&
      after.counts === before.counts;

    if (!settled) {
      return {
        scan_state: SCAN_STATE_CHANGED,
        counts_final: false,
        // Neither reading can be named as the origin of the rows: they
        // disagree about which SBOM (or about its contents), and the pages
        // were answered somewhere in between.
        scanned_sbom_id: after.sbomId === before.sbomId ? before.sbomId : null,
      };
    }

    return {
      scan_state: SCAN_STATE_FINAL,
      // A settled scan is not enough: the walk must also have COVERED the
      // project (Codex R2, Medium). A truncated walk read a prefix, and under
      // ?sort=epss that prefix is not even stable — an EPSS sync can demote
      // rows past the 5000-row cap between pages, so rows that belong in the
      // scanned range are never requested and no per-page guard fires. Calling
      // such counts final would be the same claim this field exists to stop:
      // "these are the project's numbers" about numbers that are not.
      counts_final: walkCovered,
      scanned_sbom_id: walkCovered ? before.sbomId : null,
    };
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
