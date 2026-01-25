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
  cvss_score: number;
  published_at: string;
  updated_at: string;
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface CreateProjectRequest {
  name: string;
  description: string;
}

export interface ApiError {
  error: string;
}
