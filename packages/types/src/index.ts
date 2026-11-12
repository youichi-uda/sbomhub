export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Sbom {
  id: string;
  project_id: string;
  format: SbomFormat;
  version: string;
  created_at: string;
}

export type SbomFormat = "cyclonedx" | "spdx";

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

export interface Vulnerability {
  id: string;
  cve_id: string;
  description: string;
  severity: Severity;
  /**
   * Absent when the CVE has not been scored (NVD "Awaiting Analysis",
   * JVN-only matches). Deliberately NOT 0 — CVSS 0.0 is a real "None"
   * score, and rendering un-scored as 0.0 would make an un-triaged
   * Critical look safe (M46 B2).
   */
  cvss_score?: number;
  /**
   * The CVSS version cvss_score / severity were taken from (M67 rule, exposed
   * in M71). Absent when unknown: no usable assessment, an unrecognised feed
   * version, or a row not re-derived since migration 069. May be present
   * without cvss_score (a rating stated without a usable score).
   */
  cvss_version?: "3.1" | "3.0" | "4.0" | "2.0";
  /** Absent when the upstream feed carried no timestamp (M46 B2). */
  published_at?: string;
  /** Absent when the upstream feed carried no timestamp (M46 B2). */
  updated_at?: string;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface CreateProjectRequest {
  name: string;
  description: string;
}

export interface ApiError {
  error: string;
}
