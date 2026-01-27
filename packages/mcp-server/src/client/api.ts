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

  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: options.method ?? "GET",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`API error ${res.status}: ${text}`);
    }
    return res.json() as Promise<T>;
  }

  listProjects() {
    return this.request("/api/v1/mcp/projects");
  }

  listSboms(projectId: string) {
    return this.request(`/api/v1/mcp/projects/${projectId}/sboms`);
  }

  getDashboard(projectId?: string) {
    if (projectId) {
      return this.request(`/api/v1/mcp/projects/${projectId}`);
    }
    return this.request("/api/v1/mcp/dashboard/summary");
  }

  searchCVE(cveId: string) {
    return this.request(`/api/v1/mcp/search/cve?q=${encodeURIComponent(cveId)}`);
  }

  searchComponent(name: string, version?: string) {
    let url = `/api/v1/mcp/search/component?name=${encodeURIComponent(name)}`;
    if (version) {
      url += `&version=${encodeURIComponent(version)}`;
    }
    return this.request(url);
  }

  async diff(projectId: string, baseVersion?: string, targetVersion?: string) {
    const sboms: Array<{ id: string; version?: string; created_at: string }> = await this.listSboms(projectId);
    if (!sboms || sboms.length < 2) {
      throw new Error("Not enough SBOMs to diff");
    }

    const findByVersion = (version?: string) =>
      sboms.find((s) => (s.version || "").toLowerCase() === (version || "").toLowerCase());

    const target = targetVersion ? findByVersion(targetVersion) : sboms[0];
    const base = baseVersion ? findByVersion(baseVersion) : sboms[1];

    if (!target || !base) {
      throw new Error("SBOM version not found");
    }

    return this.request(`/api/v1/mcp/sbom/diff`, {
      method: "POST",
      body: {
        base_sbom_id: base.id,
        target_sbom_id: target.id,
      },
    });
  }

  getVulnerabilities(projectId: string, severity?: string, status?: string) {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    const qs = params.toString();
    return this.request(`/api/v1/mcp/projects/${projectId}/vulnerabilities${qs ? `?${qs}` : ""}`);
  }

  getCompliance(projectId: string) {
    return this.request(`/api/v1/mcp/projects/${projectId}/compliance`);
  }
}
