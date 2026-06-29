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
  // EOL (End of Life) fields
  eol_status?: EOLStatus;
  eol_product_id?: string;
  eol_cycle_id?: string;
  eol_date?: string;
  eos_date?: string;
  eol_product_name?: string;
  eol_cycle_version?: string;
}

// EOL types
export type EOLStatus = "active" | "eol" | "eos" | "unknown";

export interface EOLProduct {
  id: string;
  name: string;
  title: string;
  category?: string;
  link?: string;
  total_cycles: number;
  created_at: string;
  updated_at: string;
}

export interface EOLProductCycle {
  id: string;
  product_id: string;
  cycle: string;
  release_date?: string;
  eol_date?: string;
  eos_date?: string;
  latest_version?: string;
  is_lts: boolean;
  is_eol: boolean;
  discontinued: boolean;
  link?: string;
  support_end_date?: string;
  created_at: string;
  updated_at: string;
}

export interface EOLSyncResult {
  products_synced: number;
  cycles_synced: number;
  components_updated: number;
}

export interface EOLSummary {
  project_id: string;
  total_components: number;
  active: number;
  eol: number;
  eos: number;
  unknown: number;
}

export interface EOLStats {
  total_products: number;
  total_cycles: number;
  last_sync_at?: string;
}

export interface ComponentEOLInfo {
  status: EOLStatus;
  product_id?: string;
  product_name?: string;
  cycle_id?: string;
  cycle_version?: string;
  eol_date?: string;
  eos_date?: string;
  latest_version?: string;
  is_lts: boolean;
  release_date?: string;
  support_end_date?: string;
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
  // KEV (Known Exploited Vulnerabilities) fields
  in_kev?: boolean;
  kev_date_added?: string;
  kev_due_date?: string;
  kev_ransomware_use?: boolean;
  source: string; // NVD or JVN
  published_at: string;
}

// KEV types
export interface KEVEntry {
  id: string;
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  short_description?: string;
  required_action?: string;
  date_added: string;
  due_date: string;
  known_ransomware_use: boolean;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface KEVSyncResult {
  new_entries: number;
  updated_entries: number;
  total_processed: number;
  catalog_version: string;
}

export interface KEVStats {
  total_entries: number;
  last_sync_at?: string;
  catalog_version?: string;
}

export interface KEVCheckResult {
  cve_id: string;
  in_kev: boolean;
  date_added?: string;
  due_date?: string;
  known_ransomware_use?: boolean;
  vendor_project?: string;
  product?: string;
  required_action?: string;
}

// SSVC (Stakeholder-Specific Vulnerability Categorization) types
export type SSVCExploitation = "none" | "poc" | "active";
export type SSVCAutomatable = "yes" | "no";
export type SSVCTechnicalImpact = "partial" | "total";
export type SSVCMissionPrevalence = "minimal" | "support" | "essential";
export type SSVCSafetyImpact = "minimal" | "significant";
export type SSVCDecision = "defer" | "scheduled" | "out_of_cycle" | "immediate";

export interface SSVCProjectDefaults {
  id?: string;
  project_id: string;
  tenant_id?: string;
  mission_prevalence: SSVCMissionPrevalence;
  safety_impact: SSVCSafetyImpact;
  system_exposure: string;
  auto_assess_enabled: boolean;
  auto_assess_exploitation: boolean;
  auto_assess_automatable: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface SSVCAssessment {
  id: string;
  project_id: string;
  tenant_id?: string;
  vulnerability_id: string;
  cve_id: string;
  exploitation: SSVCExploitation;
  automatable: SSVCAutomatable;
  technical_impact: SSVCTechnicalImpact;
  mission_prevalence: SSVCMissionPrevalence;
  safety_impact: SSVCSafetyImpact;
  decision: SSVCDecision;
  exploitation_auto: boolean;
  automatable_auto: boolean;
  assessed_by?: string;
  assessed_at: string;
  notes?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SSVCAssessmentWithVuln extends SSVCAssessment {
  vulnerability_severity: string;
  vulnerability_cvss_score: number;
  vulnerability_in_kev: boolean;
  vulnerability_epss_score?: number;
}

export interface SSVCAssessmentInput {
  exploitation: SSVCExploitation;
  automatable: SSVCAutomatable;
  technical_impact: SSVCTechnicalImpact;
  mission_prevalence: SSVCMissionPrevalence;
  safety_impact: SSVCSafetyImpact;
  notes?: string;
}

export interface SSVCSummary {
  project_id: string;
  total_assessed: number;
  immediate: number;
  out_of_cycle: number;
  scheduled: number;
  defer: number;
  unassessed: number;
}

export interface SSVCAssessmentHistory {
  id: string;
  assessment_id: string;
  prev_exploitation?: SSVCExploitation;
  prev_automatable?: SSVCAutomatable;
  prev_technical_impact?: SSVCTechnicalImpact;
  prev_mission_prevalence?: SSVCMissionPrevalence;
  prev_safety_impact?: SSVCSafetyImpact;
  prev_decision?: SSVCDecision;
  new_exploitation: SSVCExploitation;
  new_automatable: SSVCAutomatable;
  new_technical_impact: SSVCTechnicalImpact;
  new_mission_prevalence: SSVCMissionPrevalence;
  new_safety_impact: SSVCSafetyImpact;
  new_decision: SSVCDecision;
  changed_by?: string;
  changed_at: string;
  change_reason?: string;
}

export interface SSVCCalculateResult {
  decision: SSVCDecision;
  exploitation: SSVCExploitation;
  automatable: SSVCAutomatable;
  technical_impact: SSVCTechnicalImpact;
  mission_prevalence: SSVCMissionPrevalence;
  safety_impact: SSVCSafetyImpact;
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

// ----------------------------------------------------------------------------
// M10-6 (#74) — project-scoped diff (supply-chain churn observability).
// GET /api/v1/projects/:id/diff?from=<sbom_id>&to=<sbom_id>
//
// The legacy POST /api/v1/sbom/diff types above are kept for back-compat;
// the new richer envelope below is what /[locale]/projects/[id]/diff
// renders.
// ----------------------------------------------------------------------------

export interface ProjectDiffSbomRef {
  sbom_id: string;
  format: string;
  version?: string;
  created_at: string;
}

export interface ProjectDiffComponentChange {
  name: string;
  version: string;
  purl?: string;
  license?: string;
}

export interface ProjectDiffComponentVersionChange {
  name: string;
  from_version: string;
  to_version: string;
  purl?: string;
}

export interface ProjectDiffVulnerabilityAdded {
  cve_id: string;
  severity: string;
  component_name: string;
  component_version: string;
}

export interface ProjectDiffVulnerabilityResolved {
  cve_id: string;
  severity: string;
}

export interface ProjectDiffVulnerabilitySeverityChange {
  cve_id: string;
  from_severity: string;
  to_severity: string;
}

export interface ProjectDiffLicenseViolation {
  component_name: string;
  license: string;
  policy_name: string;
}

export interface ProjectDiffResponse {
  project_id: string;
  from: ProjectDiffSbomRef | null;
  to: ProjectDiffSbomRef | null;
  components: {
    added: ProjectDiffComponentChange[];
    removed: ProjectDiffComponentChange[];
    version_changed: ProjectDiffComponentVersionChange[];
  };
  vulnerabilities: {
    added: ProjectDiffVulnerabilityAdded[];
    resolved: ProjectDiffVulnerabilityResolved[];
    severity_changed: ProjectDiffVulnerabilitySeverityChange[];
  };
  licenses: {
    added_policy_violations: ProjectDiffLicenseViolation[];
    removed_policy_violations: ProjectDiffLicenseViolation[];
  };
}

// M11-4 (#79) — AI summary envelope returned by
// POST /api/v1/projects/:id/diff/summary.
//
// `ai_disabled = true` indicates the backend wrote a deterministic
// placeholder (no BYOK configured). The UI should still render
// Confidence / Evidence / Approve controls so the audit shape is
// uniform across configured / unconfigured deployments.
export interface ProjectDiffSummaryEvidence {
  kind: string;
  ref: string;
}

export interface ProjectDiffSummaryResponse {
  project_id: string;
  from: ProjectDiffSbomRef | null;
  to: ProjectDiffSbomRef | null;
  summary: string;
  highlights: string[];
  confidence: number;
  evidence: ProjectDiffSummaryEvidence[];
  provider: string;
  model: string;
  lang: string;
  generated_at: string;
  ai_disabled: boolean;
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
  locale?: string;
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

// -----------------------------------------------------------------------------
// VEX draft (AI triage, M1-6, issue #28) types
// -----------------------------------------------------------------------------
//
// The Go side (apps/api/internal/handler/vex_drafts.go) returns
// repository.VEXDraft, which has no `json:` tags — so wire field names are
// PascalCase. The inner Evidence array is a JSONB column whose items use the
// snake_case tags declared on triage.EvidencePointer in
// apps/api/internal/service/triage/types.go.
//
// Keep these in sync with the Go side; if either drifts the triage UI breaks
// silently.

export type VexDraftState =
  | "not_affected"
  | "affected"
  | "under_investigation"
  | "resolved";

export type VexDraftDecision = "pending" | "approved" | "edited" | "rejected";

/**
 * VEX draft justification (CycloneDX VEX 1.5 names, per
 * triage.types.Justification). Empty string means "no justification" (valid
 * for state=affected / state=under_investigation).
 */
export type VexDraftJustification =
  | ""
  | "code_not_present"
  | "code_not_reachable"
  | "requires_configuration"
  | "requires_dependency"
  | "requires_environment"
  | "protected_by_compiler"
  | "protected_at_perimeter"
  | "protected_at_runtime"
  | "inline_mitigations_already_exist";

export type VexDraftEvidenceKind =
  | "import_path"
  | "symbol_ref"
  | "advisory_excerpt"
  | "llm_rationale"
  | "analyzer_error"
  | string;

export interface VexDraftEvidence {
  kind: VexDraftEvidenceKind;
  file_path?: string;
  line?: number;
  column?: number;
  symbol?: string;
  import_path?: string;
  description?: string;
  raw_snippet?: string;
  source?: string;
  note?: string;
}

/** PascalCase mirrors Go's default JSON marshalling for repository.VEXDraft. */
export interface VexDraft {
  ID: string;
  TenantID: string;
  ProjectID: string;
  SBOMID?: string | null;
  ComponentID: string;
  VulnerabilityID: string;
  CVEID: string;
  State: VexDraftState;
  Justification: VexDraftJustification;
  Detail: string;
  Confidence?: number | null;
  Provider: string;
  Model: string;
  PromptHash: string;
  ResponseHash: string;
  Evidence: VexDraftEvidence[] | null;
  AdvisoryExcerptID?: string | null;
  ReachabilityResultID?: string | null;
  LLMCallID?: string | null;
  Decision: VexDraftDecision;
  DecisionBy?: string | null;
  DecisionAt?: string | null;
  DecisionNote: string;
  CreatedBy?: string | null;
  CreatedAt: string;
  UpdatedAt: string;
}

export interface VexDraftListResponse {
  drafts: VexDraft[];
}

export interface VexDraftListFilter {
  cve_id?: string;
  decision?: VexDraftDecision;
  limit?: number;
  offset?: number;
}

export interface VexDraftDecisionInput {
  decision: "approved" | "edited" | "rejected";
  edited_state?: VexDraftState;
  edited_justification?: VexDraftJustification;
  edited_detail?: string;
  note?: string;
}

export interface RunTriageInput {
  vulnerability_id: string;
  cve_id: string;
  component_id?: string;
}

export interface ParsedDecision {
  state: VexDraftState;
  justification?: VexDraftJustification;
  detail?: string;
  confidence: number;
  evidence?: VexDraftEvidence[];
}

export interface RunTriageResponse {
  draft: VexDraft;
  llm_call_id: string;
  parsed_decision: ParsedDecision;
  clamped: boolean;
  threshold: number;
}

// -----------------------------------------------------------------------------
// CRA report (AI drafting, M2-4 issue #36 + M2-5 issue #32) types
// -----------------------------------------------------------------------------
//
// Unlike the M1 vex_drafts wire shape (PascalCase — Go struct has no json
// tags), repository.CRAReport DOES declare snake_case `json:` tags on every
// field, so the wire shape is snake_case. See
// apps/api/internal/repository/cra_reports.go header comment for the
// rationale (M1 #F28 lessons → lock JSON shape at struct definition).
//
// Keep these types in sync with that struct; if either drifts the CRA UI
// silently breaks the same way the M1 triage UI did before #F28.

/** CRA reporting milestone (matches DB CHECK constraint). */
export type CRAReportType =
  | "early_warning" // 24h notice
  | "detailed_notification" // 72h follow-up
  | "final_report";

/** CRA report language allow-list. */
export type CRAReportLang = "ja" | "en";

/** Publication lifecycle, independent of `decision`. */
export type CRAReportState =
  | "draft"
  | "under_investigation" // future state for highlight; backend may emit
  | "approved"
  | "submitted"
  | "archived"
  | string;

/** Human decision lifecycle, independent of `state`. */
export type CRAReportDecision = "pending" | "approved" | "edited" | "rejected";

/**
 * One evidence pointer attached to a CRA report. The CRA runner emits
 * objects shaped `{kind, ref, ...}` where `ref` typically links back to
 * the source VEX draft id, the LLM call id, or an advisory excerpt id.
 * The exact shape is open-ended (jsonb), so we keep the type permissive.
 * ※要確認: lock the shape once cra.Runner stabilises which keys the UI
 * is meant to surface (`source_vex_draft` deep link in particular).
 */
export interface CRAReportEvidence {
  kind: string;
  ref?: string;
  description?: string;
  note?: string;
  [key: string]: unknown;
}

/**
 * CRA report wire shape (snake_case — repository.CRAReport `json:` tags).
 * Evidence is unmarshalled as an array; the backend stores it as JSONB.
 */
export interface CRAReport {
  id: string;
  tenant_id: string;
  project_id: string;
  vulnerability_id: string;
  cve_id: string;
  report_type: CRAReportType | string;
  lang: CRAReportLang | string;
  state: CRAReportState;
  draft_text: string;
  provider?: string;
  model?: string;
  prompt_hash?: string;
  response_hash?: string;
  // Evidence is JSONB on the wire. Treat null defensively for forward
  // compatibility — the UI fail-safe per F4 hides cards with 0 evidence.
  evidence: CRAReportEvidence[] | null;
  source_vex_draft_id?: string | null;
  llm_call_id?: string | null;
  decision: CRAReportDecision;
  decision_by?: string | null;
  decision_at?: string | null;
  decision_note?: string;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CRAReportListResponse {
  reports: CRAReport[];
}

export interface CRAReportListFilter {
  cve_id?: string;
  report_type?: CRAReportType | string;
  lang?: CRAReportLang | string;
  state?: string;
  decision?: CRAReportDecision;
  limit?: number;
  offset?: number;
}

/** PUT decision body — see handler/cra_reports.go.craDecisionRequest. */
export interface CRAReportDecisionInput {
  decision: "approved" | "edited" | "rejected";
  decision_note?: string;
  /**
   * Pointer-nullable in the backend: omitted → preserve AI draft_text;
   * set (even to "") → overwrite. Use undefined to omit.
   */
  edited_draft_text?: string;
}

/** POST run body — handler/cra_reports.go.runReportRequest. */
export interface RunCRAReportInput {
  vulnerability_id: string;
  cve_id: string;
  source_vex_draft_id?: string;
  report_type: CRAReportType | string;
  lang: CRAReportLang | string;
  product_name?: string;
  product_version?: string;
  vendor_name?: string;
  reporter_name?: string;
  reporter_role?: string;
  contact_email?: string;
  contact_phone?: string;
  awareness_time?: string;
  report_id?: string;
}

/** POST run / reanalyse response. */
export interface RunCRAReportResponse {
  report: CRAReport | null;
  llm_call_id?: string;
  ai_disabled?: boolean;
}

// -----------------------------------------------------------------------------
// METI assessment (M3-4 / M3-5, issue #37 + #38) types
// -----------------------------------------------------------------------------
//
// Wire shape: snake_case — repository.MetiAssessment declares `json:` tags on
// every field (see apps/api/internal/repository/meti_assessments.go header
// comment, M3-1 / #41 rationale). Same lesson as CRA reports: locking the
// JSON shape at the struct definition prevents the M1 #F28-class
// repository/handler drift that silently broke the triage UI.
//
// Keep these types in sync with that struct and with the handler request /
// response DTOs in apps/api/internal/handler/meti.go; if either drifts the
// METI matrix UI silently breaks.

/** METI 手引 ver 2.0 phase allow-list (DB CHECK on meti_assessments.criterion_phase). */
export type METIPhase = "env_setup" | "sbom_creation" | "sbom_operation";

/**
 * METI assessment status allow-list (DB CHECK on meti_assessments.status +
 * override_status, see apps/api/internal/service/meti/criteria/criteria.go
 * Status* constants).
 */
export type METIStatus =
  | "achieved"
  | "not_achieved"
  | "needs_review"
  | "not_applicable";

/**
 * One evidence pointer attached to a METI assessment. The evaluator emits
 * `{kind, value}` objects (see criteria.evidenceEntry); operator overrides
 * may augment with `{kind, ref}` or note fields. The shape is open-ended
 * (jsonb), so we keep the type permissive — the UI surfaces `kind` as a
 * badge and stringifies `value`/`ref`/`description` for display.
 * ※要確認: lock the exact key set once operator-overridden evidence shape
 * stabilises (M4 follow-up).
 */
export interface METIAssessmentEvidence {
  kind: string;
  value?: unknown;
  ref?: string;
  description?: string;
  note?: string;
  [key: string]: unknown;
}

/**
 * MetiAssessment wire shape (snake_case — repository.MetiAssessment
 * `json:` tags). Evidence is jsonb on the server and is unmarshalled to an
 * array on the wire; we treat null defensively for forward compatibility.
 */
export interface MetiAssessment {
  id: string;
  tenant_id: string;
  project_id: string;
  criterion_id: string;
  criterion_phase: METIPhase | string;
  status: METIStatus | string;
  evidence: METIAssessmentEvidence[] | null;
  evaluator_version?: string;
  evaluated_at: string;
  override_status?: METIStatus | string;
  override_by?: string | null;
  override_at?: string | null;
  override_note?: string;
  improvement_action?: string;
  created_at: string;
  updated_at: string;
}

/** GET /meti/assessment list envelope. */
export interface MetiAssessmentListResponse {
  assessments: MetiAssessment[];
}

/** POST /meti/assessment/refresh response — handler.metiRefreshResponse. */
export interface MetiRefreshResponse {
  assessments: MetiAssessment[];
  evaluator_version: string;
  refreshed: number;
}

/** Query-param filter for ListAssessments (mirrors handler.parseListFilter). */
export interface MetiAssessmentListFilter {
  phase?: METIPhase | string;
  status?: METIStatus | string;
  has_override?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * PUT override body — handler.metiOverrideRequest. improvement_action is
 * pointer-nullable on the backend: omit to preserve the existing value,
 * pass an explicit (possibly empty) string to overwrite. The TS shape uses
 * `string | null | undefined` so `undefined` = omit and `""` = overwrite,
 * mirroring the CRA EditedDraftText contract.
 */
export interface MetiAssessmentOverrideInput {
  override_status: METIStatus;
  override_note?: string;
  improvement_action?: string | null;
}

/**
 * DELETE override body — handler.metiClearOverrideRequest (M3 Codex
 * review #F33 + #F35). The note is the operator's rationale for the
 * clear ("re-evaluated, the original override was wrong") and is
 * persisted in the audit_logs row so an auditor can reconstruct the
 * correction. Server enforces 1..4096 chars after trim — anything
 * shorter / longer returns 400 with `"override_note is required and
 * must be 1-4096 characters"`.
 */
export interface MetiAssessmentClearOverrideInput {
  note: string;
}

/**
 * One row of the improvement-actions response (handler.metiImprovementAction).
 * effective_status is server-computed: override_status when set, otherwise
 * status. The catalog title (ja/en) is denormalised here so the UI does
 * not have to re-fetch the catalog.
 */
export interface MetiImprovementAction {
  criterion_id: string;
  criterion_phase: METIPhase | string;
  criterion_title_ja?: string;
  criterion_title_en?: string;
  status: METIStatus | string;
  override_status?: METIStatus | string;
  effective_status: METIStatus | string;
  evidence: METIAssessmentEvidence[] | null;
  improvement_action?: string;
}

export interface MetiImprovementActionsResponse {
  actions: MetiImprovementAction[];
}

/**
 * APIError surfaces non-2xx responses from the backend with the parsed JSON
 * body (when present). Triage callers need to differentiate
 * 503 + {"error":"AI features are disabled","reason":...} from generic
 * failures so the AIDisabledBanner can render the backend's reason verbatim
 * (LLM_PROVIDER_DESIGN.md §4.1).
 */
export class APIError extends Error {
  status: number;
  body?: Record<string, unknown>;

  constructor(status: number, body?: Record<string, unknown>) {
    super(
      typeof body?.error === "string"
        ? (body.error as string)
        : `API error: ${status}`
    );
    this.name = "APIError";
    this.status = status;
    this.body = body;
  }

  /** True when the backend reports llm.IsDisabled (LLM_PROVIDER_DESIGN.md §4.1). */
  isAIDisabled(): boolean {
    return (
      this.status === 503 &&
      typeof this.body?.error === "string" &&
      (this.body.error as string).toLowerCase().includes("ai")
    );
  }

  /** Backend-supplied reason for llm.DisabledError (never a secret). */
  disabledReason(): string | undefined {
    if (!this.isAIDisabled()) return undefined;
    const r = this.body?.reason;
    return typeof r === "string" ? r : undefined;
  }
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
    } else {
      console.warn(`[API] No auth token returned for ${path}`);
    }
  } else {
    console.warn(`[API] Auth token getter not initialized for ${path}`);
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
    // Log more details for debugging auth issues
    if (res.status === 401) {
      console.error(`[API] 401 Unauthorized for ${path}`, {
        hasAuthGetter: !!getAuthToken,
        hasAuthHeader: !!headers["Authorization"],
        hasOrgHeader: !!headers["X-Clerk-Org-ID"],
      });
    }
    // Parse the error body so callers (notably the triage UI, which needs
    // to differentiate 503 "AI features are disabled" from generic 5xx) can
    // act on the backend's structured error. Older call sites only check
    // `err.message`, which APIError still populates via its super(...) call.
    let body: Record<string, unknown> | undefined;
    try {
      const text = await res.text();
      if (text) body = JSON.parse(text);
    } catch {
      // body is left undefined; APIError falls back to "API error: <status>".
    }
    throw new APIError(res.status, body);
  }

  // Handle 204 No Content and empty responses
  if (res.status === 204 || res.headers.get("content-length") === "0") {
    return undefined as T;
  }

  const text = await res.text();
  if (!text) {
    return undefined as T;
  }

  return JSON.parse(text);
}

/**
 * Build URLSearchParams for CRAReportListFilter. Centralised so list()
 * and listWithMeta() emit identical query strings — drift between the
 * two would surface as "the count says N but the page shows M" which
 * is the exact bug class M1 #F28 chased down.
 */
function cleanCRAReportFilter(filter?: CRAReportListFilter): URLSearchParams {
  const params = new URLSearchParams();
  if (!filter) return params;
  if (filter.cve_id) params.set("cve_id", filter.cve_id);
  if (filter.report_type) params.set("report_type", filter.report_type);
  if (filter.lang) params.set("lang", filter.lang);
  if (filter.state) params.set("state", filter.state);
  if (filter.decision) params.set("decision", filter.decision);
  if (typeof filter.limit === "number") params.set("limit", String(filter.limit));
  if (typeof filter.offset === "number") params.set("offset", String(filter.offset));
  return params;
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
    // getVulnerabilitiesWithMeta returns the visible page plus the
    // authoritative server-side total (X-Total-Count). M1 Codex review
    // #F28: the bare getVulnerabilities path silently treats the
    // default 100-row response as the complete set — tab counts and
    // per-row actions for vulnerabilities past that page are dropped
    // without warning. Callers that render a visible count or trip a
    // truncation warning MUST use this method so they read the
    // server-side total rather than the visible page length.
    //
    // The server emits X-Total-Count via the SbomService.CountVulnerabilities
    // SQL COUNT(*) over the same join the page query uses, and the
    // header is in the CORS ExposeHeaders allow-list so cross-origin
    // fetches can read it. If the header is absent (older server, or
    // a future CORS misconfiguration), totalCount falls back to the
    // visible page length so existing UI does not crash — but the
    // truncation banner will silently disappear, which is the visible
    // regression signal.
    getVulnerabilitiesWithMeta: async (
      id: string,
      opts?: { limit?: number; offset?: number },
    ): Promise<{ data: Vulnerability[]; totalCount: number }> => {
      const params = new URLSearchParams();
      if (opts?.limit !== undefined) params.set("limit", String(opts.limit));
      if (opts?.offset !== undefined) params.set("offset", String(opts.offset));
      const qs = params.toString();
      const path = `/api/v1/projects/${id}/vulnerabilities${qs ? `?${qs}` : ""}`;

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (getAuthToken) {
        const token = await getAuthToken();
        if (token) headers["Authorization"] = `Bearer ${token}`;
      }
      if (getOrgId) {
        const orgId = getOrgId();
        if (orgId) headers["X-Clerk-Org-ID"] = orgId;
      }

      const res = await fetch(`${API_URL}${path}`, { headers });
      if (!res.ok) {
        let body: Record<string, unknown> | undefined;
        try {
          const text = await res.text();
          if (text) body = JSON.parse(text);
        } catch {
          // body left undefined
        }
        throw new APIError(res.status, body);
      }
      const data: Vulnerability[] = res.status === 204 ? [] : await res.json();
      const headerVal = res.headers.get("X-Total-Count");
      const totalCount =
        headerVal !== null && !Number.isNaN(parseInt(headerVal, 10))
          ? parseInt(headerVal, 10)
          : data.length;
      return { data, totalCount };
    },
    getSboms: (id: string) =>
      request<Sbom[]>(`/api/v1/projects/${id}/sboms`),
    /**
     * M10-6 (#74) — GET /api/v1/projects/:id/diff?from=<sbom_id>&to=<sbom_id>.
     *
     * Both from and to are optional. Resolution rules (see backend
     * service/diff/diff.go godoc):
     *   - neither set: defaults to the 2 most-recent SBOMs (newest = to,
     *     previous = from)
     *   - only to set: from defaults to the SBOM immediately preceding to
     *   - only from set: to defaults to the SBOM immediately following from
     *   - both set: passes through, validates both belong to the project
     *
     * Single-SBOM projects: the server returns `from: null` and treats every
     * component in `to` as added — the "initial baseline" representation.
     */
    getDiff: async (
      id: string,
      opts?: { from?: string; to?: string },
    ): Promise<ProjectDiffResponse> => {
      const params = new URLSearchParams();
      if (opts?.from) params.set("from", opts.from);
      if (opts?.to) params.set("to", opts.to);
      const qs = params.toString();
      const raw = await request<ProjectDiffResponse>(
        `/api/v1/projects/${id}/diff${qs ? `?${qs}` : ""}`,
      );
      // M11-1 #76 / F164: the Go backend marshals a nil bucket slice as
      // JSON `null`, not `[]` (uninitialised `[]LicensePolicyViolation`
      // in service/diff/diff.go::LicensesDiff hits this in the common
      // baseline path where no licence policy is configured). The
      // TypeScript ProjectDiffResponse declares each bucket as a
      // non-nullable array; the page (e.g. useMemo badges, ComponentBucket
      // rows.length) calls `.length` / `.map` on them unconditionally,
      // which throws "Cannot read properties of null (reading 'length')"
      // at hydration and trips the Next.js "Application error: a
      // client-side exception has occurred" boundary. Normalise here so
      // every consumer of the typed shape gets the invariant the type
      // promises. Cheaper than scattering `?? []` across the page and
      // closer to the source of the polymorphism.
      return {
        ...raw,
        components: {
          added: raw.components?.added ?? [],
          removed: raw.components?.removed ?? [],
          version_changed: raw.components?.version_changed ?? [],
        },
        vulnerabilities: {
          added: raw.vulnerabilities?.added ?? [],
          resolved: raw.vulnerabilities?.resolved ?? [],
          severity_changed: raw.vulnerabilities?.severity_changed ?? [],
        },
        licenses: {
          added_policy_violations: raw.licenses?.added_policy_violations ?? [],
          removed_policy_violations:
            raw.licenses?.removed_policy_violations ?? [],
        },
      };
    },
    /**
     * M11-4 (#79) — POST /api/v1/projects/:id/diff/summary?from=&to=&lang=.
     *
     * Generates an AI natural-language summary of the diff. Non-idempotent
     * (LLM call has cost), hence POST. The backend persists an llm_calls
     * row + an audit_logs row (diff_summary_ai_generated | ai_disabled |
     * ai_failed) per request — see internal/service/diff_summary godoc.
     *
     * `ai_disabled = true` means BYOK is not configured server-side; the
     * caller should still render the placeholder envelope (the backend
     * supplies a deterministic mechanical summary so the audit UI shape
     * stays uniform).
     */
    getDiffSummary: async (
      id: string,
      opts?: { from?: string; to?: string; lang?: string },
    ): Promise<ProjectDiffSummaryResponse> => {
      const params = new URLSearchParams();
      if (opts?.from) params.set("from", opts.from);
      if (opts?.to) params.set("to", opts.to);
      if (opts?.lang) params.set("lang", opts.lang);
      const qs = params.toString();
      const raw = await request<ProjectDiffSummaryResponse>(
        `/api/v1/projects/${id}/diff/summary${qs ? `?${qs}` : ""}`,
        { method: "POST" },
      );
      // Defensive normalisation in the spirit of the M11-1 fix for
      // getDiff: the Go backend marshals nil slices as JSON `null`,
      // and consumers call `.map` on highlights / evidence
      // unconditionally.
      return {
        ...raw,
        highlights: raw.highlights ?? [],
        evidence: raw.evidence ?? [],
      };
    },
    /**
     * M11-4 (#79) — build a CSV download URL for the diff.
     *
     * Returns a string the UI can hand to a hidden <a download> anchor
     * or open in a new tab. We do NOT call the endpoint through the
     * shared request() helper because that path assumes JSON; download
     * endpoints need the browser's native blob handling.
     */
    getDiffCsvUrl: (
      id: string,
      opts?: { from?: string; to?: string },
    ): string => {
      const params = new URLSearchParams();
      if (opts?.from) params.set("from", opts.from);
      if (opts?.to) params.set("to", opts.to);
      const qs = params.toString();
      return `${API_URL}/api/v1/projects/${id}/diff.csv${qs ? `?${qs}` : ""}`;
    },
    /**
     * M11-4 (#79) — PDF download URL companion to getDiffCsvUrl.
     */
    getDiffPdfUrl: (
      id: string,
      opts?: { from?: string; to?: string; lang?: string },
    ): string => {
      const params = new URLSearchParams();
      if (opts?.from) params.set("from", opts.from);
      if (opts?.to) params.set("to", opts.to);
      if (opts?.lang) params.set("lang", opts.lang);
      const qs = params.toString();
      return `${API_URL}/api/v1/projects/${id}/diff.pdf${qs ? `?${qs}` : ""}`;
    },
    /**
     * M11-4 (#79) — fetch the CSV / PDF as a blob through the
     * authenticated request chain. Use this variant when the call needs
     * to go through the same auth/org headers the rest of the API
     * receives (the URL builders above produce raw URLs which assume
     * the browser is logged in via a cookie + Clerk session).
     */
    fetchDiffExport: async (
      id: string,
      format: "csv" | "pdf",
      opts?: { from?: string; to?: string; lang?: string },
    ): Promise<{ blob: Blob; filename: string }> => {
      const params = new URLSearchParams();
      if (opts?.from) params.set("from", opts.from);
      if (opts?.to) params.set("to", opts.to);
      if (format === "pdf" && opts?.lang) params.set("lang", opts.lang);
      const qs = params.toString();
      const path = `/api/v1/projects/${id}/diff.${format}${qs ? `?${qs}` : ""}`;

      const headers: Record<string, string> = {};
      if (getAuthToken) {
        const token = await getAuthToken();
        if (token) headers["Authorization"] = `Bearer ${token}`;
      }
      if (getOrgId) {
        const orgId = getOrgId();
        if (orgId) headers["X-Clerk-Org-ID"] = orgId;
      }
      const res = await fetch(`${API_URL}${path}`, { headers });
      if (!res.ok) {
        throw new APIError(res.status, undefined);
      }
      const blob = await res.blob();
      // Parse the Content-Disposition `filename=...` for a friendly download.
      const cd = res.headers.get("Content-Disposition") ?? "";
      const m = cd.match(/filename=\"?([^\";]+)\"?/);
      const filename = m?.[1] ?? `sbomhub-diff.${format}`;
      return { blob, filename };
    },
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
    // Evidence Pack download (Wave M2-6 / issue #34). POSTs to the
    // sync builder and triggers a browser-native file download via a
    // dynamic anchor with the Content-Disposition filename.
    //
    // We deliberately use fetch() + Blob() here rather than the shared
    // request() helper because:
    //   - the response body is text/markdown, not JSON
    //   - we want the server's Content-Disposition filename
    //   - request() throws APIError on non-2xx; we want to surface the
    //     error text to the operator without losing the response body
    buildEvidencePack: async (
      projectId: string,
      opts?: {
        includeVEXApproved?: boolean;
        includeCRAApproved?: boolean;
        includeMETIPlaceholder?: boolean;
      }
    ): Promise<{ filename: string; sizeBytes: number; vexCount: number; craCount: number }> => {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (getAuthToken) {
        const token = await getAuthToken();
        if (token) headers["Authorization"] = `Bearer ${token}`;
      }
      if (getOrgId) {
        const orgId = getOrgId();
        if (orgId) headers["X-Clerk-Org-ID"] = orgId;
      }
      const body: Record<string, unknown> = {};
      if (opts?.includeVEXApproved !== undefined) {
        body.include_vex_approved = opts.includeVEXApproved;
      }
      if (opts?.includeCRAApproved !== undefined) {
        body.include_cra_approved = opts.includeCRAApproved;
      }
      if (opts?.includeMETIPlaceholder !== undefined) {
        body.include_meti_placeholder = opts.includeMETIPlaceholder;
      }
      const res = await fetch(
        `${API_URL}/api/v1/projects/${projectId}/evidence-pack/build`,
        {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        },
      );
      if (!res.ok) {
        let errBody: Record<string, unknown> | undefined;
        try {
          const txt = await res.text();
          if (txt) errBody = JSON.parse(txt);
        } catch {
          // fall through
        }
        throw new APIError(res.status, errBody);
      }
      // Parse the server-supplied filename out of Content-Disposition
      // ("attachment; filename=\"evidence-pack-<id>-<ts>.md\""). Falling
      // back to a sensible default if the header is missing keeps the
      // UI working but loses the timestamped name.
      const cd = res.headers.get("Content-Disposition") || "";
      const match = cd.match(/filename="([^"]+)"/i);
      const filename = match ? match[1] : `evidence-pack-${projectId}.md`;
      const vexCount = parseInt(res.headers.get("X-Evidence-Pack-VEX-Count") || "0", 10) || 0;
      const craCount = parseInt(res.headers.get("X-Evidence-Pack-CRA-Count") || "0", 10) || 0;
      const blob = await res.blob();
      // Browser-native download via dynamic anchor. typeof check
      // guards SSR — Next.js bundles this module for both server and
      // client and any module-load reference to `window` would crash
      // SSR.
      if (typeof window !== "undefined" && typeof document !== "undefined") {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        // Defer revoke to next tick so the browser has time to start
        // the download before the URL is invalidated.
        setTimeout(() => window.URL.revokeObjectURL(url), 0);
      }
      return { filename, sizeBytes: blob.size, vexCount, craCount };
    },
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
  // AI VEX triage (M1-6, issue #28). Maps to the five endpoints wired by
  // apps/api/cmd/server/main.go around line 596:
  //   POST   /api/v1/projects/:id/triage/run
  //   GET    /api/v1/projects/:id/vex-drafts
  //   GET    /api/v1/projects/:id/vex-drafts/:draft_id
  //   PUT    /api/v1/projects/:id/vex-drafts/:draft_id/decision
  //   POST   /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse
  triage: {
    listDrafts: (projectId: string, filter?: VexDraftListFilter) => {
      const params = new URLSearchParams();
      if (filter?.cve_id) params.set("cve_id", filter.cve_id);
      if (filter?.decision) params.set("decision", filter.decision);
      if (typeof filter?.limit === "number") params.set("limit", String(filter.limit));
      if (typeof filter?.offset === "number") params.set("offset", String(filter.offset));
      const query = params.toString();
      return request<VexDraftListResponse>(
        `/api/v1/projects/${projectId}/vex-drafts${query ? `?${query}` : ""}`
      );
    },
    getDraft: (projectId: string, draftId: string) =>
      request<VexDraft>(
        `/api/v1/projects/${projectId}/vex-drafts/${draftId}`
      ),
    run: (projectId: string, input: RunTriageInput) =>
      request<RunTriageResponse>(`/api/v1/projects/${projectId}/triage/run`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    decide: (projectId: string, draftId: string, input: VexDraftDecisionInput) =>
      request<VexDraft>(
        `/api/v1/projects/${projectId}/vex-drafts/${draftId}/decision`,
        {
          method: "PUT",
          body: JSON.stringify(input),
        }
      ),
    reanalyse: (
      projectId: string,
      draftId: string,
      input?: Partial<RunTriageInput>
    ) =>
      request<RunTriageResponse>(
        `/api/v1/projects/${projectId}/vex-drafts/${draftId}/reanalyse`,
        {
          method: "POST",
          body: JSON.stringify(input ?? {}),
        }
      ),
  },
  // AI CRA report drafting (M2-4 / M2-5, issues #36 + #32). Maps to the
  // five endpoints wired by apps/api/cmd/server/main.go around the
  // /cra-reports route group:
  //   POST   /api/v1/projects/:id/cra-reports/run
  //   GET    /api/v1/projects/:id/cra-reports
  //   GET    /api/v1/projects/:id/cra-reports/:report_id
  //   PUT    /api/v1/projects/:id/cra-reports/:report_id/decision
  //   POST   /api/v1/projects/:id/cra-reports/:report_id/reanalyse
  craReports: {
    /**
     * GET list — returns the JSON envelope only. The X-Total-Count
     * header is dropped here, so paginated UIs MUST use listWithMeta
     * instead (M1 #F28 lesson re-applied for the CRA queue UI).
     */
    list: (projectId: string, filter?: CRAReportListFilter) => {
      const params = cleanCRAReportFilter(filter);
      const query = params.toString();
      return request<CRAReportListResponse>(
        `/api/v1/projects/${projectId}/cra-reports${query ? `?${query}` : ""}`,
      );
    },
    /**
     * GET list + total count from X-Total-Count (M1 #F28 pattern, see
     * projects.getVulnerabilitiesWithMeta). totalCount falls back to
     * the visible page length when the header is absent (older API or
     * CORS misconfig); the truncation banner silently disappears in
     * that case — same visible-regression contract as F28.
     */
    listWithMeta: async (
      projectId: string,
      filter?: CRAReportListFilter,
    ): Promise<{ data: CRAReport[]; totalCount: number }> => {
      const params = cleanCRAReportFilter(filter);
      const query = params.toString();
      const path = `/api/v1/projects/${projectId}/cra-reports${query ? `?${query}` : ""}`;

      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (getAuthToken) {
        const token = await getAuthToken();
        if (token) headers["Authorization"] = `Bearer ${token}`;
      }
      if (getOrgId) {
        const orgId = getOrgId();
        if (orgId) headers["X-Clerk-Org-ID"] = orgId;
      }
      const res = await fetch(`${API_URL}${path}`, { headers });
      if (!res.ok) {
        let body: Record<string, unknown> | undefined;
        try {
          const text = await res.text();
          if (text) body = JSON.parse(text);
        } catch {
          // body left undefined
        }
        throw new APIError(res.status, body);
      }
      const envelope: CRAReportListResponse =
        res.status === 204 ? { reports: [] } : await res.json();
      const data = Array.isArray(envelope?.reports) ? envelope.reports : [];
      const headerVal = res.headers.get("X-Total-Count");
      const totalCount =
        headerVal !== null && !Number.isNaN(parseInt(headerVal, 10))
          ? parseInt(headerVal, 10)
          : data.length;
      return { data, totalCount };
    },
    get: (projectId: string, reportId: string) =>
      request<CRAReport>(
        `/api/v1/projects/${projectId}/cra-reports/${reportId}`,
      ),
    run: (projectId: string, input: RunCRAReportInput) =>
      request<RunCRAReportResponse>(
        `/api/v1/projects/${projectId}/cra-reports/run`,
        {
          method: "POST",
          body: JSON.stringify(input),
        },
      ),
    decide: (
      projectId: string,
      reportId: string,
      input: CRAReportDecisionInput,
    ) =>
      request<CRAReport>(
        `/api/v1/projects/${projectId}/cra-reports/${reportId}/decision`,
        {
          method: "PUT",
          body: JSON.stringify(input),
        },
      ),
    reanalyse: (
      projectId: string,
      reportId: string,
      input?: Partial<RunCRAReportInput>,
    ) =>
      request<RunCRAReportResponse>(
        `/api/v1/projects/${projectId}/cra-reports/${reportId}/reanalyse`,
        {
          method: "POST",
          body: JSON.stringify(input ?? {}),
        },
      ),
  },
  // METI self-assessment (M3-4 + M3-5, issues #37 + #38). Maps to the
  // four endpoints wired by apps/api/cmd/server/main.go around
  // /meti/assessment:
  //   GET    /api/v1/projects/:id/meti/assessment
  //   POST   /api/v1/projects/:id/meti/assessment/refresh
  //   PUT    /api/v1/projects/:id/meti/assessment/:criterion_id/override
  //   GET    /api/v1/projects/:id/meti/improvement-actions
  //
  // The catalog ships with 27 criteria (3 phases × ~9 items) so the
  // matrix page never paginates in practice. We still expose limit /
  // offset on the filter shape for parity with the handler's F24/F27
  // bounds — see comment on handler.parseListFilter.
  meti: {
    /**
     * GET assessment list (server returns the full per-criterion matrix
     * for the project). The X-Total-Count header is emitted by the
     * handler but the matrix page renders the whole catalog at once, so
     * we expose only the envelope here. If a paginated view lands
     * later, mirror the cra-reports.listWithMeta shape.
     */
    getAssessment: (
      projectId: string,
      filter?: MetiAssessmentListFilter,
    ) => {
      const params = new URLSearchParams();
      if (filter?.phase) params.set("phase", filter.phase);
      if (filter?.status) params.set("status", filter.status);
      if (typeof filter?.has_override === "boolean") {
        params.set("has_override", filter.has_override ? "true" : "false");
      }
      if (typeof filter?.limit === "number") params.set("limit", String(filter.limit));
      if (typeof filter?.offset === "number") params.set("offset", String(filter.offset));
      const query = params.toString();
      return request<MetiAssessmentListResponse>(
        `/api/v1/projects/${projectId}/meti/assessment${query ? `?${query}` : ""}`,
      );
    },
    /**
     * POST /refresh — re-runs the evaluator fan-out (27 criteria) and
     * returns the persisted rows + evaluator version. Operator-applied
     * overrides are preserved by the repository (Upsert does NOT touch
     * override_*). Failures here include 503 AI-disabled (M3 is
     * deliberately AI-free, but the env may still surface upstream
     * outages — APIError.isAIDisabled() is harmless here, it just falls
     * through to the generic flash error path).
     */
    refreshAssessment: (projectId: string) =>
      request<MetiRefreshResponse>(
        `/api/v1/projects/${projectId}/meti/assessment/refresh`,
        { method: "POST" },
      ),
    /**
     * PUT /override — applies one operator override to a single criterion
     * row. Server enforces F31 state-machine guard: re-overriding an
     * already-overridden row returns 409 ("clear the existing override
     * first"). UI surfaces that as a flash error rather than swallowing
     * it, so an operator sees the explicit re-override workflow.
     */
    overrideCriterion: (
      projectId: string,
      criterionId: string,
      input: MetiAssessmentOverrideInput,
    ) =>
      request<MetiAssessment>(
        `/api/v1/projects/${projectId}/meti/assessment/${encodeURIComponent(criterionId)}/override`,
        {
          method: "PUT",
          body: JSON.stringify(input),
        },
      ),
    /**
     * DELETE /override — clears a prior operator override on a single
     * criterion row (M3 Codex review #F33 + #F35). The body carries a
     * required clear rationale note (1..4096 chars after trim) that is
     * persisted in the audit_logs row. Server returns the post-clear
     * MetiAssessment (override_* fields nulled) so the UI can patch
     * the row in place without a follow-up GET. Common failure modes:
     *   - 400 "override_note is required and must be 1-4096 characters"
     *   - 404 "meti assessment override not found" (no override to clear)
     *   - 409 TOCTOU race (concurrent clear / re-override)
     *   - 403 user identity required (no authenticated user on the request)
     * Surface them through the standard handleError flash channel; the
     * APIError.message carries the server-side reason verbatim.
     */
    clearOverrideCriterion: (
      projectId: string,
      criterionId: string,
      input: MetiAssessmentClearOverrideInput,
    ) =>
      request<MetiAssessment>(
        `/api/v1/projects/${projectId}/meti/assessment/${encodeURIComponent(criterionId)}/override`,
        {
          method: "DELETE",
          body: JSON.stringify(input),
        },
      ),
    /**
     * GET /improvement-actions — server-side filter for "effective
     * status != achieved" rows. The endpoint accepts an optional ?phase
     * filter but intentionally NOT ?status (the whole point is "not
     * achieved"). The page uses this as the "改善 actions のみ" toggle
     * data source.
     */
    getImprovementActions: (
      projectId: string,
      filter?: { phase?: METIPhase | string },
    ) => {
      const params = new URLSearchParams();
      if (filter?.phase) params.set("phase", filter.phase);
      const query = params.toString();
      return request<MetiImprovementActionsResponse>(
        `/api/v1/projects/${projectId}/meti/improvement-actions${query ? `?${query}` : ""}`,
      );
    },
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
  // EOL methods
  eol: {
    sync: () =>
      request<EOLSyncResult>("/api/v1/eol/sync", { method: "POST" }),
    getProducts: (limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (limit) params.set("limit", limit.toString());
      if (offset) params.set("offset", offset.toString());
      const query = params.toString();
      return request<{ products: EOLProduct[]; total: number }>(`/api/v1/eol/products${query ? `?${query}` : ""}`);
    },
    getProduct: (name: string) =>
      request<{ product: EOLProduct; cycles: EOLProductCycle[] }>(`/api/v1/eol/products/${name}`),
    getStats: () => request<EOLStats>("/api/v1/eol/stats"),
    checkComponent: (name: string, version?: string, purl?: string) => {
      const params = new URLSearchParams();
      params.set("name", name);
      if (version) params.set("version", version);
      if (purl) params.set("purl", purl);
      return request<ComponentEOLInfo>(`/api/v1/eol/check?${params.toString()}`);
    },
    getProjectEOLSummary: (projectId: string) =>
      request<EOLSummary>(`/api/v1/projects/${projectId}/eol-summary`),
    updateProjectComponents: (projectId: string) =>
      request<{ message: string; components_updated: number }>(`/api/v1/projects/${projectId}/eol-check`, { method: "POST" }),
  },
  // KEV methods
  kev: {
    sync: () =>
      request<KEVSyncResult>("/api/v1/kev/sync", { method: "POST" }),
    getCatalog: (limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (limit) params.set("limit", limit.toString());
      if (offset) params.set("offset", offset.toString());
      const query = params.toString();
      return request<{ entries: KEVEntry[]; total: number }>(`/api/v1/kev/catalog${query ? `?${query}` : ""}`);
    },
    getStats: () => request<KEVStats>("/api/v1/kev/stats"),
    getByCVE: (cveId: string) =>
      request<{ in_kev: boolean; cve_id: string; entry?: KEVEntry }>(`/api/v1/kev/${cveId}`),
    checkCVE: (cveId: string) =>
      request<KEVCheckResult>(`/api/v1/vulnerabilities/${cveId}/kev`),
    getProjectKEV: (projectId: string) =>
      request<{ vulnerabilities: Vulnerability[]; count: number }>(`/api/v1/projects/${projectId}/kev`),
  },
  // SSVC methods
  ssvc: {
    getDefaults: (projectId: string) =>
      request<SSVCProjectDefaults>(`/api/v1/projects/${projectId}/ssvc/defaults`),
    updateDefaults: (projectId: string, defaults: Partial<SSVCProjectDefaults>) =>
      request<SSVCProjectDefaults>(`/api/v1/projects/${projectId}/ssvc/defaults`, {
        method: "PUT",
        body: JSON.stringify(defaults),
      }),
    getSummary: (projectId: string) =>
      request<SSVCSummary>(`/api/v1/projects/${projectId}/ssvc/summary`),
    listAssessments: (projectId: string, decision?: SSVCDecision, limit?: number, offset?: number) => {
      const params = new URLSearchParams();
      if (decision) params.set("decision", decision);
      if (limit) params.set("limit", limit.toString());
      if (offset) params.set("offset", offset.toString());
      const query = params.toString();
      return request<{ assessments: SSVCAssessmentWithVuln[]; total: number; limit: number; offset: number }>(
        `/api/v1/projects/${projectId}/ssvc/assessments${query ? `?${query}` : ""}`
      );
    },
    getAssessment: (projectId: string, vulnId: string) =>
      request<SSVCAssessment>(`/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc`),
    getAssessmentByCVE: (projectId: string, cveId: string) =>
      request<SSVCAssessment>(`/api/v1/projects/${projectId}/ssvc/cve/${cveId}`),
    assess: (projectId: string, vulnId: string, cveId: string, input: SSVCAssessmentInput) =>
      request<SSVCAssessment>(`/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc?cve_id=${encodeURIComponent(cveId)}`, {
        method: "POST",
        body: JSON.stringify(input),
      }),
    autoAssess: (projectId: string, vulnId: string, cveId: string) =>
      request<SSVCAssessment>(`/api/v1/projects/${projectId}/vulnerabilities/${vulnId}/ssvc/auto?cve_id=${encodeURIComponent(cveId)}`, {
        method: "POST",
      }),
    deleteAssessment: (projectId: string, assessmentId: string) =>
      request<void>(`/api/v1/projects/${projectId}/ssvc/assessments/${assessmentId}`, {
        method: "DELETE",
      }),
    getHistory: (projectId: string, assessmentId: string) =>
      request<SSVCAssessmentHistory[]>(`/api/v1/projects/${projectId}/ssvc/assessments/${assessmentId}/history`),
    getImmediateAssessments: () =>
      request<SSVCAssessmentWithVuln[]>("/api/v1/ssvc/immediate"),
    calculate: (input: SSVCAssessmentInput) =>
      request<SSVCCalculateResult>("/api/v1/ssvc/calculate", {
        method: "POST",
        body: JSON.stringify(input),
      }),
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
