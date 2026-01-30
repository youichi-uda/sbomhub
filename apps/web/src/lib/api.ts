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
  tenant_id: string;
  project_id?: string; // Deprecated: project-level keys
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

export interface CreateAPIKeyInput {
  name: string;
  permissions?: string;
  expires_in_days?: number;
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
  email_addresses?: string;
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
  channel: "slack" | "discord" | "email";
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

// METI Checklist types
export type ChecklistPhase = "setup" | "creation" | "operation";

export interface ChecklistItem {
  id: string;
  phase: ChecklistPhase;
  label: string;
  label_ja: string;
  description?: string;
  auto_verify: boolean;
}

export interface ChecklistItemResult extends ChecklistItem {
  passed: boolean;
  response?: boolean;
  note?: string;
  auto_result?: boolean;
}

export interface ChecklistPhaseResult {
  phase: ChecklistPhase;
  label: string;
  label_ja: string;
  items: ChecklistItemResult[];
  score: number;
  max_score: number;
}

export interface ChecklistResult {
  project_id: string;
  phases: ChecklistPhaseResult[];
  score: number;
  max_score: number;
}

export interface ChecklistResponseInput {
  response: boolean;
  note?: string;
}

// Visualization Framework types
export interface VisualizationOption {
  value: string;
  label: string;
  label_ja: string;
}

export interface VisualizationOptions {
  sbom_author_scope: VisualizationOption[];
  dependency_scope: VisualizationOption[];
  generation_method: VisualizationOption[];
  data_format: VisualizationOption[];
  utilization_scope: VisualizationOption[];
  utilization_actor: VisualizationOption[];
}

export interface VisualizationSettings {
  id?: string;
  project_id: string;
  sbom_author_scope: string;
  dependency_scope: string;
  generation_method: string;
  data_format: string;
  utilization_scope: string[];
  utilization_actor: string;
  created_at?: string;
  updated_at?: string;
}

export interface VisualizationFramework {
  settings?: VisualizationSettings;
  options: VisualizationOptions;
}

// Audit log types
export interface AuditLog {
  id: string;
  tenant_id?: string;
  user_id?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  details?: Record<string, unknown>;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  user_email?: string;
  user_name?: string;
}

export interface AuditListResponse {
  logs: AuditLog[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface AuditFilter {
  action?: string;
  resource_type?: string;
  user_id?: string;
  start_date?: string;
  end_date?: string;
  page?: number;
  limit?: number;
}

export interface ActionInfo {
  action: string;
  label: string;
  category: string;
}

export interface ResourceTypeInfo {
  type: string;
  label: string;
}

export interface ActionCount {
  action: string;
  count: number;
}

export interface AuditStatistics {
  period: number;
  action_counts: ActionCount[];
  daily_counts: Array<{ date: string; action: string; count: number }>;
}

// Analytics types
export interface MTTRResult {
  severity: string;
  mttr_hours: number;
  count: number;
  target_hours: number;
  on_target: boolean;
}

export interface VulnerabilityTrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  resolved: number;
}

export interface SLOAchievement {
  severity: string;
  total_count: number;
  on_target_count: number;
  achievement_pct: number;
  target_hours: number;
  average_mttr_hours: number;
}

export interface ComplianceTrendPoint {
  date: string;
  score: number;
  max_score: number;
  percentage: number;
  sbom_score?: number;
  vulnerability_score?: number;
  license_score?: number;
}

export interface AnalyticsQuickStats {
  total_open_vulnerabilities: number;
  resolved_last_30_days: number;
  average_mttr_hours: number;
  overall_slo_achievement_pct: number;
  current_compliance_score: number;
  compliance_max_score: number;
}

export interface AnalyticsSummary {
  period: number;
  mttr: MTTRResult[];
  vulnerability_trend: VulnerabilityTrendPoint[];
  slo_achievement: SLOAchievement[];
  compliance_trend: ComplianceTrendPoint[];
  summary: AnalyticsQuickStats;
}

export interface SLOTarget {
  id: string;
  tenant_id?: string;
  severity: string;
  target_hours: number;
}

// Report types
export interface ReportSettings {
  id: string;
  tenant_id: string;
  enabled: boolean;
  report_type: string;
  schedule_type: string;
  schedule_day: number;
  schedule_hour: number;
  format: string;
  email_enabled: boolean;
  email_recipients: string[];
  include_sections: string[];
  created_at?: string;
  updated_at?: string;
}

export interface GeneratedReport {
  id: string;
  tenant_id: string;
  settings_id?: string;
  report_type: string;
  format: string;
  title: string;
  period_start: string;
  period_end: string;
  file_path: string;
  file_size: number;
  status: string;
  error_message?: string;
  generated_by?: string;
  email_sent_at?: string;
  email_recipients?: string[];
  created_at: string;
  completed_at?: string;
}

export interface ReportListResponse {
  reports: GeneratedReport[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

export interface GenerateReportInput {
  report_type: string;
  format: string;
  period_start?: string;
  period_end?: string;
}

// IPA types
export interface IPAAnnouncement {
  id: string;
  ipa_id: string;
  title: string;
  title_ja?: string;
  description?: string;
  category: string;
  severity?: string;
  source_url: string;
  related_cves?: string[];
  published_at: string;
  created_at: string;
  updated_at: string;
}

export interface IPAAnnouncementListResponse {
  announcements: IPAAnnouncement[];
  total: number;
  limit: number;
  offset: number;
}

export interface IPASyncSettings {
  id?: string;
  tenant_id: string;
  enabled: boolean;
  notify_on_new: boolean;
  notify_severity: string[];
  last_sync_at?: string;
  created_at?: string;
  updated_at?: string;
}

export interface IPASyncResult {
  new_announcements: number;
  updated_announcements: number;
  total_processed: number;
}

// Issue Tracker types
export type TrackerType = "jira" | "backlog";

export interface IssueTrackerConnection {
  id: string;
  tenant_id: string;
  tracker_type: TrackerType;
  name: string;
  base_url: string;
  auth_type: string;
  auth_email?: string;
  default_project_key?: string;
  default_issue_type?: string;
  is_active: boolean;
  last_sync_at?: string;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityTicket {
  id: string;
  tenant_id: string;
  vulnerability_id: string;
  project_id: string;
  connection_id: string;
  external_ticket_id: string;
  external_ticket_key?: string;
  external_ticket_url: string;
  local_status: "open" | "in_progress" | "resolved" | "closed";
  external_status?: string;
  priority?: string;
  assignee?: string;
  summary?: string;
  last_synced_at?: string;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityTicketWithDetails extends VulnerabilityTicket {
  cve_id: string;
  severity: string;
  tracker_type: string;
  tracker_name: string;
  project_name: string;
  component_name?: string;
}

export interface CreateConnectionInput {
  tracker_type: TrackerType;
  name: string;
  base_url: string;
  email?: string;
  api_token: string;
  default_project_key?: string;
  default_issue_type?: string;
}

export interface CreateTicketInput {
  vulnerability_id: string;
  project_id: string;
  connection_id: string;
  project_key?: string;
  issue_type?: string;
  priority?: string;
  summary?: string;
  description?: string;
  labels?: string[];
}

export interface TicketListResponse {
  tickets: VulnerabilityTicketWithDetails[];
  total: number;
  limit: number;
  offset: number;
}

// Billing types
export interface PlanLimits {
  plan: string;
  max_projects: number;
  max_users: number;
  max_components: number;
  max_vulnerabilities: number;
  monthly_api_calls: number;
  features: Record<string, boolean>;
}

export interface Subscription {
  id: string;
  tenant_id: string;
  ls_subscription_id: string;
  ls_customer_id: string;
  ls_product_id: string;
  ls_variant_id: string;
  status: string;
  plan: string;
  billing_anchor?: number;
  current_period_start?: string;
  current_period_end?: string;
  trial_ends_at?: string;
  renews_at?: string;
  ends_at?: string;
  cancelled_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SubscriptionResponse {
  has_subscription: boolean;
  subscription?: Subscription;
  plan: string;
  limits: PlanLimits;
  billing_enabled: boolean;
  is_self_hosted: boolean;
}

export interface UsageResponse {
  users: { current: number; limit: number };
  projects: { current: number; limit: number };
  plan: string;
  isSelfHosted: boolean;
}

// Token getter function - will be set by AuthProvider
let getAuthToken: (() => Promise<string | null>) | null = null;
let getOrgId: (() => string | null) | null = null;

export function setAuthTokenGetter(getter: () => Promise<string | null>) {
  getAuthToken = getter;
}

export function setOrgIdGetter(getter: () => string | null) {
  getOrgId = getter;
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

  // Add organization ID header if available
  if (getOrgId) {
    const orgId = getOrgId();
    if (orgId) {
      headers["X-Clerk-Org-ID"] = orgId;
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
        email_addresses?: string;
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
    // METI Checklist methods
    getChecklist: (id: string) =>
      request<ChecklistResult>(`/api/v1/projects/${id}/checklist`),
    updateChecklistResponse: (
      projectId: string,
      checkId: string,
      data: ChecklistResponseInput
    ) =>
      request<{ status: string }>(`/api/v1/projects/${projectId}/checklist/${checkId}`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    deleteChecklistResponse: (projectId: string, checkId: string) =>
      request<void>(`/api/v1/projects/${projectId}/checklist/${checkId}`, {
        method: "DELETE",
      }),
    // Visualization Framework methods
    getVisualization: (id: string) =>
      request<VisualizationFramework>(`/api/v1/projects/${id}/visualization`),
    updateVisualization: (
      projectId: string,
      data: Partial<VisualizationSettings>
    ) =>
      request<VisualizationSettings>(`/api/v1/projects/${projectId}/visualization`, {
        method: "PUT",
        body: JSON.stringify(data),
      }),
    deleteVisualization: (projectId: string) =>
      request<void>(`/api/v1/projects/${projectId}/visualization`, {
        method: "DELETE",
      }),
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
  // Report methods
  reports: {
    getSettings: (type?: string) => {
      const query = type ? `?type=${type}` : "";
      return request<ReportSettings | ReportSettings[]>(`/api/v1/reports/settings${query}`);
    },
    updateSettings: (settings: Partial<ReportSettings> & { report_type: string }) =>
      request<ReportSettings>("/api/v1/reports/settings", {
        method: "PUT",
        body: JSON.stringify(settings),
      }),
    generate: (input: GenerateReportInput) =>
      request<GeneratedReport>("/api/v1/reports/generate", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    list: (page?: number, limit?: number) => {
      const params = new URLSearchParams();
      if (page) params.set("page", page.toString());
      if (limit) params.set("limit", limit.toString());
      const query = params.toString();
      return request<ReportListResponse>(`/api/v1/reports${query ? `?${query}` : ""}`);
    },
    get: (id: string) => request<GeneratedReport>(`/api/v1/reports/${id}`),
    downloadUrl: (id: string) => `${API_URL}/api/v1/reports/${id}/download`,
  },
  // Analytics methods
  analytics: {
    getSummary: (days?: number) =>
      request<AnalyticsSummary>(`/api/v1/analytics/summary${days ? `?days=${days}` : ""}`),
    getMTTR: (days?: number) =>
      request<MTTRResult[]>(`/api/v1/analytics/mttr${days ? `?days=${days}` : ""}`),
    getVulnerabilityTrend: (days?: number) =>
      request<VulnerabilityTrendPoint[]>(`/api/v1/analytics/vulnerability-trend${days ? `?days=${days}` : ""}`),
    getSLOAchievement: (days?: number) =>
      request<SLOAchievement[]>(`/api/v1/analytics/slo-achievement${days ? `?days=${days}` : ""}`),
    getComplianceTrend: (days?: number) =>
      request<ComplianceTrendPoint[]>(`/api/v1/analytics/compliance-trend${days ? `?days=${days}` : ""}`),
    getSLOTargets: () => request<SLOTarget[]>("/api/v1/analytics/slo-targets"),
    updateSLOTarget: (severity: string, targetHours: number) =>
      request<{ status: string }>("/api/v1/analytics/slo-targets", {
        method: "PUT",
        body: JSON.stringify({ severity, target_hours: targetHours }),
      }),
  },
  // Audit log methods
  auditLogs: {
    list: (filter?: AuditFilter) => {
      const params = new URLSearchParams();
      if (filter?.action) params.set("action", filter.action);
      if (filter?.resource_type) params.set("resource_type", filter.resource_type);
      if (filter?.user_id) params.set("user_id", filter.user_id);
      if (filter?.start_date) params.set("start_date", filter.start_date);
      if (filter?.end_date) params.set("end_date", filter.end_date);
      if (filter?.page) params.set("page", filter.page.toString());
      if (filter?.limit) params.set("limit", filter.limit.toString());
      const query = params.toString();
      return request<AuditListResponse>(`/api/v1/audit-logs${query ? `?${query}` : ""}`);
    },
    exportUrl: (filter?: AuditFilter) => {
      const params = new URLSearchParams();
      if (filter?.action) params.set("action", filter.action);
      if (filter?.resource_type) params.set("resource_type", filter.resource_type);
      if (filter?.user_id) params.set("user_id", filter.user_id);
      if (filter?.start_date) params.set("start_date", filter.start_date);
      if (filter?.end_date) params.set("end_date", filter.end_date);
      const query = params.toString();
      return `${API_URL}/api/v1/audit-logs/export${query ? `?${query}` : ""}`;
    },
    getStatistics: (days?: number) =>
      request<AuditStatistics>(`/api/v1/audit-logs/statistics${days ? `?days=${days}` : ""}`),
    getActions: () => request<ActionInfo[]>("/api/v1/audit-logs/actions"),
    getResourceTypes: () => request<ResourceTypeInfo[]>("/api/v1/audit-logs/resource-types"),
  },
  // IPA methods
  ipa: {
    listAnnouncements: (category?: string, limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (category) params.set("category", category);
      if (limit) params.set("limit", limit.toString());
      if (offset) params.set("offset", offset.toString());
      const query = params.toString();
      return request<IPAAnnouncementListResponse>(`/api/v1/ipa/announcements${query ? `?${query}` : ""}`);
    },
    getAnnouncementsByCVE: (cveId: string) =>
      request<{ announcements: IPAAnnouncement[]; cve_id: string }>(`/api/v1/vulnerabilities/${cveId}/ipa`),
    getSettings: () => request<IPASyncSettings>("/api/v1/settings/ipa"),
    updateSettings: (settings: { enabled: boolean; notify_on_new: boolean; notify_severity: string[] }) =>
      request<IPASyncSettings>("/api/v1/settings/ipa", {
        method: "PUT",
        body: JSON.stringify(settings),
      }),
    sync: () => request<IPASyncResult>("/api/v1/ipa/sync", { method: "POST" }),
  },
  // Issue Tracker methods
  integrations: {
    list: () =>
      request<{ connections: IssueTrackerConnection[] }>("/api/v1/integrations"),
    get: (id: string) => request<IssueTrackerConnection>(`/api/v1/integrations/${id}`),
    create: (input: CreateConnectionInput) =>
      request<IssueTrackerConnection>("/api/v1/integrations", {
        method: "POST",
        body: JSON.stringify(input),
      }),
    delete: (id: string) =>
      request<void>(`/api/v1/integrations/${id}`, { method: "DELETE" }),
  },
  tickets: {
    list: (status?: string, limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (status) params.set("status", status);
      if (limit) params.set("limit", limit.toString());
      if (offset) params.set("offset", offset.toString());
      const query = params.toString();
      return request<TicketListResponse>(`/api/v1/tickets${query ? `?${query}` : ""}`);
    },
    getByVulnerability: (vulnId: string) =>
      request<{ tickets: VulnerabilityTicketWithDetails[] }>(`/api/v1/vulnerabilities/${vulnId}/tickets`),
    create: (vulnId: string, input: Omit<CreateTicketInput, "vulnerability_id">) =>
      request<VulnerabilityTicket>(`/api/v1/vulnerabilities/${vulnId}/ticket`, {
        method: "POST",
        body: JSON.stringify({ ...input, vulnerability_id: vulnId }),
      }),
    sync: (ticketId: string) =>
      request<{ status: string }>(`/api/v1/tickets/${ticketId}/sync`, { method: "POST" }),
  },
  // Billing methods
  billing: {
    getSubscription: () => request<SubscriptionResponse>("/api/v1/subscription"),
    createCheckout: (plan: string) =>
      request<{ url: string }>("/api/v1/subscription/checkout", {
        method: "POST",
        body: JSON.stringify({ plan }),
      }),
    getPortalUrl: () => request<{ url: string }>("/api/v1/subscription/portal"),
    syncSubscription: (lsSubscriptionId?: string) =>
      request<{ status: string; plan?: string; message?: string; help?: string }>("/api/v1/subscription/sync", {
        method: "POST",
        body: lsSubscriptionId ? JSON.stringify({ ls_subscription_id: lsSubscriptionId }) : undefined,
      }),
    getUsage: () => request<UsageResponse>("/api/v1/plan/usage"),
    selectFreePlan: () =>
      request<{ status: string; plan: string }>("/api/v1/plan/select-free", {
        method: "POST",
      }),
  },
  // Tenant-level API key methods (recommended)
  apiKeys: {
    list: () => request<APIKey[]>("/api/v1/apikeys"),
    create: (data: CreateAPIKeyInput) =>
      request<APIKeyWithSecret>("/api/v1/apikeys", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    delete: (keyId: string) =>
      request<void>(`/api/v1/apikeys/${keyId}`, { method: "DELETE" }),
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
