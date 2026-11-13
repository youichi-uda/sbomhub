// Query key factory for apps/web (react-query).
//
// One place defines every key so that
//   - two components reading the same endpoint share a cache entry (and a
//     single in-flight request): e.g. IPAAlert + IPAAlertBadge for one CVE,
//     TicketStatus + TicketBadge for one vulnerability, the project SBOM list
//     used by both the share page and the diff timeline;
//   - every project-scoped key starts with `queryKeys.projects.byId(id)`, so
//     `invalidateQueries({ queryKey: queryKeys.projects.byId(id) })` reaches
//     all of a project's data at once;
//   - keys that differ only by a parameter (sort, page, period, filter,
//     from/to) are distinct, so a slow response for an old parameter can never
//     be shown for a new one (this replaces the hand-rolled request-sequence
//     guard the loaders used to need).
//
// Pure module (no imports) so node --test can load it directly.
// Pinned by src/lib/query/__tests__/query.test.mjs.

type KeyScalar = string | number | boolean;

// Drop undefined / empty members so `{ action: undefined }` and `{}` are the
// same key (react-query hashes undefined members away too; doing it here
// keeps the key that tests and devtools see identical to the one that is
// hashed), and fix the member order.
function compact(filter: object): Record<string, KeyScalar> {
  const out: Record<string, KeyScalar> = {};
  const entries = Object.entries(filter).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [k, v] of entries) {
    if (typeof v === "string" ? v !== "" : typeof v === "number" || typeof v === "boolean") {
      out[k] = v as KeyScalar;
    }
  }
  return out;
}

const projectRoot = ["projects"] as const;
const byId = (projectId: string) => [...projectRoot, "by-id", projectId] as const;

export const queryKeys = {
  projects: {
    all: projectRoot,
    list: () => [...projectRoot, "list"] as const,
    byId,
    detail: (projectId: string) => [...byId(projectId), "detail"] as const,
    components: (projectId: string) => [...byId(projectId), "components"] as const,
    // `sbomId` is the latest SBOM the page knows of (null: none, or not
    // known): the list endpoint answers for the latest SBOM, so a new one
    // (an upload, CI) is a new list — never the previous SBOM's rows under
    // the new SBOM's scan state (Codex R4).
    vulnerabilities: (projectId: string, sort: "cvss" | "epss", sbomId: string | null) =>
      [...byId(projectId), "vulnerabilities", { sort, sbomId }] as const,
    // Prefix of every sort's entry: a scan reaching a terminal state
    // invalidates all of them (src/lib/scan-status.ts needsVulnRefetch).
    vulnerabilitiesAll: (projectId: string) => [...byId(projectId), "vulnerabilities"] as const,
    vex: (projectId: string) => [...byId(projectId), "vex"] as const,
    licensePolicies: (projectId: string) => [...byId(projectId), "license-policies"] as const,
    licenseViolations: (projectId: string, sbomId: string | null) =>
      [...byId(projectId), "license-violations", { sbomId }] as const,
    latestSbomId: (projectId: string) => [...byId(projectId), "latest-sbom-id"] as const,
    scanStatus: (projectId: string, sbomId: string | null) =>
      [...byId(projectId), "scan-status", { sbomId }] as const,
    // Prefix of every SBOM's scan-status entry.
    scanStatusAll: (projectId: string) => [...byId(projectId), "scan-status"] as const,
    sboms: (projectId: string) => [...byId(projectId), "sboms"] as const,
    notificationSettings: (projectId: string) =>
      [...byId(projectId), "notification-settings"] as const,
    notificationLogs: (projectId: string) => [...byId(projectId), "notification-logs"] as const,
    apiKeys: (projectId: string) => [...byId(projectId), "api-keys"] as const,
    compliance: (projectId: string) => [...byId(projectId), "compliance"] as const,
    checklist: (projectId: string) => [...byId(projectId), "checklist"] as const,
    visualization: (projectId: string) => [...byId(projectId), "visualization"] as const,
    publicLinks: (projectId: string) => [...byId(projectId), "public-links"] as const,
    diff: (projectId: string, from: string | undefined, to: string | undefined) =>
      [...byId(projectId), "diff", { from: from ?? null, to: to ?? null }] as const,
    diffGraph: (projectId: string, from: string | undefined, to: string | undefined) =>
      [...byId(projectId), "diff-graph", { from: from ?? null, to: to ?? null }] as const,
    componentPaths: (projectId: string, componentId: string, sbomId: string | undefined) =>
      [...byId(projectId), "component-paths", { componentId, sbomId: sbomId ?? null }] as const,
    // CRA report queue, one entry per filter (M65 bug 2: the page used to
    // apply list responses in arrival order, so a late answer for an old
    // filter overwrote the current filter's rows).
    craReports: (projectId: string, filter: object) =>
      [...byId(projectId), "cra-reports", compact(filter)] as const,
    // Prefix of every filter's entry: a decision moves a report between
    // filters, so mutations invalidate all of them (Codex R1).
    craReportsAll: (projectId: string) => [...byId(projectId), "cra-reports"] as const,
    craSubmissions: (projectId: string, reportId: string) =>
      [...byId(projectId), "cra-submissions", reportId] as const,
  },
  dashboard: {
    summary: () => ["dashboard", "summary"] as const,
  },
  analytics: {
    summary: (days: number) => ["analytics", "summary", { days }] as const,
  },
  audit: {
    logs: (filter: object, page: number) =>
      ["audit", "logs", { ...compact(filter), page }] as const,
    filterOptions: () => ["audit", "filter-options"] as const,
  },
  billing: {
    subscription: () => ["billing", "subscription"] as const,
    overview: () => ["billing", "overview"] as const,
  },
  reports: {
    list: (page: number) => ["reports", "list", { page }] as const,
    settings: () => ["reports", "settings"] as const,
  },
  apiKeys: {
    list: () => ["api-keys", "list"] as const,
  },
  integrations: {
    list: () => ["integrations", "list"] as const,
  },
  ipa: {
    settings: () => ["ipa", "settings"] as const,
    byCve: (cveId: string) => ["ipa", "by-cve", cveId] as const,
  },
  tickets: {
    byVulnerability: (vulnerabilityId: string) =>
      ["tickets", "by-vulnerability", vulnerabilityId] as const,
  },
  kev: {
    check: (cveId: string) => ["kev", "check", cveId] as const,
  },
  publicView: (token: string, attempt: number) => ["public-view", token, { attempt }] as const,
  tenantSettings: {
    diffWebhook: () => ["tenant-settings", "diff-webhook"] as const,
    llm: () => ["tenant-settings", "llm"] as const,
  },
} as const;
