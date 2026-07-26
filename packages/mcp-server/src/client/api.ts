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

export type SbomSummary = z.infer<typeof SbomSummarySchema>;
export type VulnerabilityEntry = z.infer<typeof VulnerabilitySchema>;

export type VulnSort = "cvss" | "epss";

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
        // apps/api/internal/middleware/apikey.go accepts X-API-Key (primary)
        // or Authorization: Bearer. We send the documented primary header.
        "X-API-Key": this.apiKey,
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
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
  async diff(
    projectId: string,
    baseVersion?: string,
    targetVersion?: string
  ): Promise<unknown> {
    const sboms = await this.listSboms(projectId);
    if (sboms.length < 2) {
      throw new Error("Not enough SBOMs to diff");
    }

    const findByVersion = (version: string) =>
      sboms.find((s) => s.version.toLowerCase() === version.toLowerCase());

    const target = targetVersion ? findByVersion(targetVersion) : sboms[0];
    const base = baseVersion ? findByVersion(baseVersion) : sboms[1];

    if (!target || !base) {
      throw new Error("SBOM version not found");
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
  // rows beyond the scan remain on the server.
  private async fetchVulnerabilities(
    projectId: string,
    sort: VulnSort
  ): Promise<{
    total: number;
    vulnerabilities: VulnerabilityEntry[];
    truncated: boolean;
  }> {
    const vulnerabilities: VulnerabilityEntry[] = [];
    let total = 0;

    for (let offset = 0; offset < VULNS_SCAN_CAP; offset += VULNS_PAGE_LIMIT) {
      const { data, headers } = await this.requestRaw(
        `/api/v1/mcp/projects/${encodeURIComponent(projectId)}/vulnerabilities?limit=${VULNS_PAGE_LIMIT}&offset=${offset}&sort=${sort}`
      );
      const page = VulnerabilityListSchema.parse(data);
      vulnerabilities.push(...page);

      const totalHeader = headers.get("X-Total-Count");
      const parsed = totalHeader
        ? Number.parseInt(totalHeader, 10)
        : Number.NaN;
      total = Number.isNaN(parsed) ? vulnerabilities.length : parsed;

      // Short page = no more rows on the server.
      if (page.length < VULNS_PAGE_LIMIT || vulnerabilities.length >= total) {
        break;
      }
    }

    return {
      total,
      vulnerabilities,
      truncated: total > vulnerabilities.length,
    };
  }
}
