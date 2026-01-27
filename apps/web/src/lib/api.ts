const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Component {
  id: string;
  sbom_id: string;
  name: string;
  version: string;
  type: string;
  purl: string;
  license: string;
  created_at: string;
}

export interface Sbom {
  id: string;
  project_id: string;
  format: string;
  version: string | null;
  created_at: string;
}

export interface PublicLink {
  id: string;
  tenant_id: string;
  project_id: string;
  sbom_id?: string | null;
  token: string;
  name: string;
  expires_at: string;
  is_active: boolean;
  allowed_downloads?: number | null;
  view_count: number;
  download_count: number;
  created_at: string;
  updated_at: string;
}

export interface PublicSbomView {
  project_name: string;
  sbom: Sbom;
  components: Component[];
  link: {
    name: string;
    expires_at: string;
    view_count: number;
    download_count: number;
  };
}

export interface Vulnerability {
  id: string;
  cve_id: string;
  description: string;
  severity: string;
  cvss_score: number;
  epss_score?: number;
  epss_percentile?: number;
  source: string; // NVD or JVN
  published_at: string;
}

export interface Stats {
  projects: number;
  components: number;
  vulnerabilities: number;
}

export type VEXStatus = "not_affected" | "affected" | "fixed" | "under_investigation";

export type VEXJustification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export interface VEXStatement {
  id: string;
  project_id: string;
  vulnerability_id: string;
  component_id?: string;
  status: VEXStatus;
  justification?: VEXJustification;
  action_statement?: string;
  impact_statement?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface VEXStatementWithDetails extends VEXStatement {
  vulnerability_cve_id: string;
  vulnerability_severity: string;
  component_name?: string;
  component_version?: string;
}

export type LicensePolicyType = "allowed" | "denied" | "review";

export interface LicensePolicy {
  id: string;
  project_id: string;
  license_id: string;
  license_name: string;
  policy_type: LicensePolicyType;
  reason?: string;
  created_at: string;
  updated_at: string;
}

export interface LicenseViolation {
  component_id: string;
  component_name: string;
  version: string;
  license: string;
  policy_type: LicensePolicyType;
  reason?: string;
}

export interface APIKey {
  id: string;
  project_id: string;
  name: string;
  key_prefix: string;
  permissions: string;
  last_used_at?: string;
  expires_at?: string;
  created_at: string;
}

export interface APIKeyWithSecret extends APIKey {
  key: string; // Only returned on creation
}

// Dashboard types
export interface VulnerabilityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TopRisk {
  cve_id: string;
  epss_score: number;
  cvss_score: number;
  severity: string;
  project_id: string;
  project_name: string;
  component_name: string;
  component_version: string;
}

export interface ProjectScore {
  project_id: string;
  project_name: string;
  risk_score: number;
  severity: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardSummary {
  total_projects: number;
  total_components: number;
  vulnerabilities: VulnerabilityCounts;
  top_risks: TopRisk[];
  project_scores: ProjectScore[];
  trend: TrendPoint[];
}

// SBOM Diff types
export interface SbomDiffSummary {
  added_count: number;
  removed_count: number;
  updated_count: number;
  new_vulnerabilities_count: number;
}

export interface SbomDiffComponent {
  name: string;
  version: string;
  license?: string;
  vulnerabilities?: Vulnerability[];
}

export interface SbomDiffUpdated {
  name: string;
  old_version: string;
  new_version: string;
  vulnerabilities_fixed?: string[];
}

export interface SbomDiffVulnerability {
  cve_id: string;
  severity: string;
  component: string;
  version: string;
}

export interface SbomDiffResponse {
  summary: SbomDiffSummary;
  added: SbomDiffComponent[];
  removed: SbomDiffComponent[];
  updated: SbomDiffUpdated[];
  new_vulnerabilities: SbomDiffVulnerability[];
}

// Search types
export interface AffectedComponent {
  id: string;
  name: string;
  version: string;
  fixed_version?: string;
}

export interface AffectedProject {
  project_id: string;
  project_name: string;
  affected_components: AffectedComponent[];
}

export interface UnaffectedProject {
  project_id: string;
  project_name: string;
}

export interface CVESearchResult {
  cve_id: string;
  description: string;
  cvss_score: number;
  epss_score: number;
  severity: string;
  affected_projects: AffectedProject[];
  unaffected_projects: UnaffectedProject[];
}

export interface ComponentSearchMatch {
  project_id: string;
  project_name: string;
  component: {
    id: string;
    name: string;
    version: string;
    license?: string;
  };
  vulnerabilities: Vulnerability[];
}

export interface ComponentSearchResult {
  query: {
    name: string;
    version_constraint?: string;
  };
  matches: ComponentSearchMatch[];
}

// Notification types
export interface NotificationSettings {
  id?: string;
  project_id: string;
  slack_webhook_url?: string;
  discord_webhook_url?: string;
  notify_critical: boolean;
  notify_high: boolean;
  notify_medium: boolean;
  notify_low: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface NotificationLog {
  id: string;
  project_id: string;
  channel: "slack" | "discord";
  payload: string;
  status: "sent" | "failed";
  error_message?: string;
  created_at: string;
}

// Compliance types
export interface ComplianceCheck {
  id: string;
  label: string;
  passed: boolean;
  details?: string;
}

export interface ComplianceCategory {
  name: string;
  label: string;
  score: number;
  max_score: number;
  checks: ComplianceCheck[];
}

export interface ComplianceResult {
  project_id: string;
  score: number;
  max_score: number;
  categories: ComplianceCategory[];
}

// Token getter function - will be set by AuthProvider
let getAuthToken: (() => Promise<string | null>) | null = null;

export function setAuthTokenGetter(getter: () => Promise<string | null>) {
  getAuthToken = getter;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };

  // Add auth token if available
  if (getAuthToken) {
    const token = await getAuthToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }

  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }

  return res.json();
}

export const api = {
  stats: () => request<Stats>("/api/v1/stats"),

  // Dashboard
  dashboard: {
    getSummary: () => request<DashboardSummary>("/api/v1/dashboard/summary"),
  },

  // Search
  search: {
    byCVE: (cveId: string) =>
      request<CVESearchResult>(`/api/v1/search/cve?q=${encodeURIComponent(cveId)}`),
    byComponent: (name: string, version?: string) => {
      let url = `/api/v1/search/component?name=${encodeURIComponent(name)}`;
      if (version) {
        url += `&version=${encodeURIComponent(version)}`;
      }
      return request<ComponentSearchResult>(url);
    },
  },

  // EPSS
  epss: {
    sync: () => request<{ status: string }>("/api/v1/vulnerabilities/sync-epss", { method: "POST" }),
    getScore: (cveId: string) =>
      request<{ cve_id: string; score: number; percentile: number }>(`/api/v1/vulnerabilities/epss/${cveId}`),
  },

  projects: {
    list: () => request<Project[]>("/api/v1/projects"),
    get: (id: string) => request<Project>(`/api/v1/projects/${id}`),
    create: (data: { name: string; description: string }) =>
      request<Project>("/api/v1/projects", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      request<void>(`/api/v1/projects/${id}`, { method: "DELETE" }),
    uploadSbom: (id: string, sbom: string) =>
      request<void>(`/api/v1/projects/${id}/sbom`, {
        method: "POST",
        body: sbom,
      }),
    getComponents: (id: string) =>
      request<Component[]>(`/api/v1/projects/${id}/components`),
    getVulnerabilities: (id: string) =>
      request<Vulnerability[]>(`/api/v1/projects/${id}/vulnerabilities`),
    getSboms: (id: string) =>
      request<Sbom[]>(`/api/v1/projects/${id}/sboms`),
    // VEX methods
    getVEXStatements: (id: string) =>
      request<VEXStatementWithDetails[]>(`/api/v1/projects/${id}/vex`),
    createVEXStatement: (
      projectId: string,
      data: {
        vulnerability_id: string;
        component_id?: string;
        status: VEXStatus;
        justification?: VEXJustification;
        action_statement?: string;
        impact_statement?: string;
      }
    ) =>
      request<VEXStatement>(`/api/v1/projects/${projectId}/vex`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    updateVEXStatement: (
      projectId: string,
      vexId: string,
      data: {
        status: VEXStatus;
        justification?: VEXJustification;
        action_statement?: string;
        impact_statement?: string;
      }
    ) =>
      request<VEXStatement>(`/api/v1/projects/${projectId}/vex/${vexId}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    deleteVEXStatement: (projectId: string, vexId: string) =>
      request<void>(`/api/v1/projects/${projectId}/vex/${vexId}`, {
        method: "DELETE",
      }),
    exportVEX: (projectId: string) =>
      `${API_URL}/api/v1/projects/${projectId}/vex/export`,
    // License policy methods
    getLicensePolicies: (id: string) =>
      request<LicensePolicy[]>(`/api/v1/projects/${id}/licenses`),
    createLicensePolicy: (
      projectId: string,
      data: {
        license_id: string;
        license_name?: string;
        policy_type: LicensePolicyType;
        reason?: string;
      }
    ) =>
      request<LicensePolicy>(`/api/v1/projects/${projectId}/licenses`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    updateLicensePolicy: (
      projectId: string,
      policyId: string,
      data: {
        policy_type: LicensePolicyType;
        reason?: string;
      }
    ) =>
      request<LicensePolicy>(`/api/v1/projects/${projectId}/licenses/${policyId}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    deleteLicensePolicy: (projectId: string, policyId: string) =>
      request<void>(`/api/v1/projects/${projectId}/licenses/${policyId}`, {
        method: "DELETE",
      }),
    checkLicenseViolations: (projectId: string, sbomId: string) =>
      request<LicenseViolation[]>(`/api/v1/projects/${projectId}/licenses/violations?sbom_id=${sbomId}`),
    // API key methods
    getAPIKeys: (id: string) =>
      request<APIKey[]>(`/api/v1/projects/${id}/apikeys`),
    createAPIKey: (
      projectId: string,
      data: {
        name: string;
        permissions?: string;
        expires_in_days?: number;
      }
    ) =>
      request<APIKeyWithSecret>(`/api/v1/projects/${projectId}/apikeys`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    deleteAPIKey: (projectId: string, keyId: string) =>
      request<void>(`/api/v1/projects/${projectId}/apikeys/${keyId}`, {
        method: "DELETE",
      }),
    // Notification methods
    getNotificationSettings: (id: string) =>
      request<NotificationSettings>(`/api/v1/projects/${id}/notifications`),
    updateNotificationSettings: (
      projectId: string,
      data: {
        slack_webhook_url?: string;
        discord_webhook_url?: string;
        notify_critical: boolean;
        notify_high: boolean;
        notify_medium: boolean;
        notify_low: boolean;
      }
    ) =>
      request<NotificationSettings>(`/api/v1/projects/${projectId}/notifications`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    testNotification: (projectId: string) =>
      request<{ status: string }>(`/api/v1/projects/${projectId}/notifications/test`, {
        method: "POST",
      }),
    getNotificationLogs: (projectId: string) =>
      request<NotificationLog[]>(`/api/v1/projects/${projectId}/notifications/logs`),
    // Compliance methods
    getCompliance: (id: string) =>
      request<ComplianceResult>(`/api/v1/projects/${id}/compliance`),
    exportComplianceReport: (projectId: string, format: "json" | "pdf" | "xlsx" = "json") =>
      `${API_URL}/api/v1/projects/${projectId}/compliance/report?format=${format}`,
  },
  licenses: {
    getCommon: () => request<Record<string, string>>("/api/v1/licenses/common"),
  },
  sbom: {
    diff: (data: { base_sbom_id: string; target_sbom_id: string }) =>
      request<SbomDiffResponse>("/api/v1/sbom/diff", {
        method: "POST",
        body: JSON.stringify(data),
      }),
  },
  publicLinks: {
    list: (projectId: string) =>
      request<PublicLink[]>(`/api/v1/projects/${projectId}/public-links`),
    create: (
      projectId: string,
      data: {
        name: string;
        sbom_id?: string;
        expires_at: string;
        is_active: boolean;
        allowed_downloads?: number;
        password?: string;
      }
    ) =>
      request<PublicLink>(`/api/v1/projects/${projectId}/public-links`, {
        method: "POST",
        body: JSON.stringify(data),
      }),
    update: (
      linkId: string,
      data: {
        name: string;
        sbom_id?: string;
        expires_at: string;
        is_active: boolean;
        allowed_downloads?: number;
        password?: string | null;
      }
    ) =>
      request<PublicLink>(`/api/v1/public-links/${linkId}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    delete: (linkId: string) =>
      request<void>(`/api/v1/public-links/${linkId}`, { method: "DELETE" }),
    publicView: (token: string, password?: string) => {
      const url = password
        ? `/api/v1/public/${token}?password=${encodeURIComponent(password)}`
        : `/api/v1/public/${token}`;
      return request<PublicSbomView>(url);
    },
  },
};

// useApi hook for components that need direct API access with auth
export function useApi() {
  return {
    async get<T>(path: string): Promise<T> {
      return request<T>(path);
    },
    async post<T>(path: string, data?: unknown): Promise<T> {
      return request<T>(path, {
        method: "POST",
        body: data ? JSON.stringify(data) : undefined,
      });
    },
    async put<T>(path: string, data?: unknown): Promise<T> {
      return request<T>(path, {
        method: "PUT",
        body: data ? JSON.stringify(data) : undefined,
      });
    },
    async delete<T>(path: string): Promise<T> {
      return request<T>(path, {
        method: "DELETE",
      });
    },
  };
}
