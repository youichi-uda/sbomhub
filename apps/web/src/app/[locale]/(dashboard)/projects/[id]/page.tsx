"use client";

import { useTranslations } from "next-intl";
import { useState, useEffect, useCallback } from "react";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, Project, Component, Vulnerability, VEXStatementWithDetails, VEXStatus, VEXJustification, LicensePolicy, LicensePolicyType, LicenseViolation, APIKey, APIKeyWithSecret } from "@/lib/api";
import { Upload, Package, AlertTriangle, ArrowLeft, Shield, Download, FileCheck, Key, Copy, Check } from "lucide-react";
import Link from "next/link";

type Tab = "upload" | "components" | "vulnerabilities" | "vex" | "licenses" | "apikeys";

export default function ProjectDetailPage() {
  const params = useParams();
  const projectId = params.id as string;
  const t = useTranslations();

  const [project, setProject] = useState<Project | null>(null);
  const [components, setComponents] = useState<Component[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [vexStatements, setVexStatements] = useState<VEXStatementWithDetails[]>([]);
  const [licensePolicies, setLicensePolicies] = useState<LicensePolicy[]>([]);
  const [licenseViolations, setLicenseViolations] = useState<LicenseViolation[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("upload");
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [showVexForm, setShowVexForm] = useState(false);
  const [selectedVulnForVex, setSelectedVulnForVex] = useState<Vulnerability | null>(null);
  const [showLicenseForm, setShowLicenseForm] = useState(false);
  const [sbomId, setSbomId] = useState<string | null>(null);
  const [apiKeys, setApiKeys] = useState<APIKey[]>([]);
  const [showApiKeyForm, setShowApiKeyForm] = useState(false);
  const [newApiKey, setNewApiKey] = useState<APIKeyWithSecret | null>(null);

  const loadProject = useCallback(async () => {
    try {
      const data = await api.projects.get(projectId);
      setProject(data);
    } catch (error) {
      console.error("Failed to load project:", error);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  const loadComponents = useCallback(async () => {
    try {
      const data = await api.projects.getComponents(projectId);
      setComponents(data || []);
    } catch (error) {
      console.error("Failed to load components:", error);
    }
  }, [projectId]);

  const loadVulnerabilities = useCallback(async () => {
    try {
      const data = await api.projects.getVulnerabilities(projectId);
      setVulnerabilities(data || []);
    } catch (error) {
      console.error("Failed to load vulnerabilities:", error);
    }
  }, [projectId]);

  const loadVexStatements = useCallback(async () => {
    try {
      const data = await api.projects.getVEXStatements(projectId);
      setVexStatements(data || []);
    } catch (error) {
      console.error("Failed to load VEX statements:", error);
    }
  }, [projectId]);

  const loadLicensePolicies = useCallback(async () => {
    try {
      const data = await api.projects.getLicensePolicies(projectId);
      setLicensePolicies(data || []);
    } catch (error) {
      console.error("Failed to load license policies:", error);
    }
  }, [projectId]);

  const loadLicenseViolations = useCallback(async () => {
    if (!sbomId) return;
    try {
      const data = await api.projects.checkLicenseViolations(projectId, sbomId);
      setLicenseViolations(data || []);
    } catch (error) {
      console.error("Failed to load license violations:", error);
    }
  }, [projectId, sbomId]);

  const loadSbomId = useCallback(async () => {
    try {
      const sbom = await fetch(`${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080"}/api/v1/projects/${projectId}/sbom`);
      if (sbom.ok) {
        const data = await sbom.json();
        setSbomId(data.id);
      }
    } catch (error) {
      console.error("Failed to load SBOM ID:", error);
    }
  }, [projectId]);

  const loadApiKeys = useCallback(async () => {
    try {
      const data = await api.projects.getAPIKeys(projectId);
      setApiKeys(data || []);
    } catch (error) {
      console.error("Failed to load API keys:", error);
    }
  }, [projectId]);

  useEffect(() => {
    loadProject();
    loadComponents();
    loadVulnerabilities();
    loadVexStatements();
    loadLicensePolicies();
    loadSbomId();
    loadApiKeys();
  }, [loadProject, loadComponents, loadVulnerabilities, loadVexStatements, loadLicensePolicies, loadSbomId, loadApiKeys]);

  useEffect(() => {
    if (activeTab === "components") loadComponents();
    if (activeTab === "vulnerabilities") loadVulnerabilities();
    if (activeTab === "vex") loadVexStatements();
    if (activeTab === "licenses") {
      loadLicensePolicies();
      loadLicenseViolations();
    }
    if (activeTab === "apikeys") loadApiKeys();
  }, [activeTab, loadComponents, loadVulnerabilities, loadVexStatements, loadLicensePolicies, loadLicenseViolations, loadApiKeys]);

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      const content = await file.text();
      await api.projects.uploadSbom(projectId, content);
      alert("SBOM uploaded successfully!");
      loadComponents();
      setActiveTab("components");
    } catch (error) {
      console.error("Failed to upload SBOM:", error);
      alert("Failed to upload SBOM");
    } finally {
      setUploading(false);
    }
  }

  function getSeverityVariant(severity: string) {
    switch (severity.toUpperCase()) {
      case "CRITICAL": return "critical";
      case "HIGH": return "high";
      case "MEDIUM": return "medium";
      case "LOW": return "low";
      default: return "secondary";
    }
  }

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  if (!project) {
    return <div className="flex items-center justify-center h-64">Project not found</div>;
  }

  return (
    <div>
      <div className="mb-6">
        <Link href="/projects" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2">
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Projects
        </Link>
        <h1 className="text-3xl font-bold">{project.name}</h1>
        <p className="text-muted-foreground">{project.description}</p>
      </div>

      <div className="flex gap-2 mb-6">
        <Button
          variant={activeTab === "upload" ? "default" : "outline"}
          onClick={() => setActiveTab("upload")}
        >
          <Upload className="h-4 w-4 mr-2" />
          {t("Projects.upload")}
        </Button>
        <Button
          variant={activeTab === "components" ? "default" : "outline"}
          onClick={() => setActiveTab("components")}
        >
          <Package className="h-4 w-4 mr-2" />
          {t("Components.title")} ({components.length})
        </Button>
        <Button
          variant={activeTab === "vulnerabilities" ? "default" : "outline"}
          onClick={() => setActiveTab("vulnerabilities")}
        >
          <AlertTriangle className="h-4 w-4 mr-2" />
          {t("Vulnerabilities.title")} ({vulnerabilities.length})
        </Button>
        <Button
          variant={activeTab === "vex" ? "default" : "outline"}
          onClick={() => setActiveTab("vex")}
        >
          <Shield className="h-4 w-4 mr-2" />
          VEX ({vexStatements.length})
        </Button>
        <Button
          variant={activeTab === "licenses" ? "default" : "outline"}
          onClick={() => setActiveTab("licenses")}
        >
          <FileCheck className="h-4 w-4 mr-2" />
          Licenses ({licensePolicies.length})
        </Button>
        <Button
          variant={activeTab === "apikeys" ? "default" : "outline"}
          onClick={() => setActiveTab("apikeys")}
        >
          <Key className="h-4 w-4 mr-2" />
          API Keys ({apiKeys.length})
        </Button>
      </div>

      {activeTab === "upload" && (
        <Card>
          <CardHeader>
            <CardTitle>{t("Projects.upload")}</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="border-2 border-dashed rounded-lg p-8 text-center">
              <Upload className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground mb-4">
                Upload a CycloneDX or SPDX JSON file
              </p>
              <label className="cursor-pointer">
                <input
                  type="file"
                  accept=".json"
                  onChange={handleFileUpload}
                  className="hidden"
                  disabled={uploading}
                />
                <Button disabled={uploading}>
                  {uploading ? "Uploading..." : "Select File"}
                </Button>
              </label>
            </div>
          </CardContent>
        </Card>
      )}

      {activeTab === "components" && (
        <Card>
          <CardHeader>
            <CardTitle>{t("Components.title")}</CardTitle>
          </CardHeader>
          <CardContent>
            {components.length === 0 ? (
              <p className="text-center text-muted-foreground py-8">
                No components found. Upload an SBOM first.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b">
                      <th className="text-left py-3 px-4">{t("Components.name")}</th>
                      <th className="text-left py-3 px-4">{t("Components.version")}</th>
                      <th className="text-left py-3 px-4">{t("Components.type")}</th>
                      <th className="text-left py-3 px-4">{t("Components.license")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {components.map((comp) => (
                      <tr key={comp.id} className="border-b hover:bg-gray-50">
                        <td className="py-3 px-4 font-medium">{comp.name}</td>
                        <td className="py-3 px-4">{comp.version || "-"}</td>
                        <td className="py-3 px-4">{comp.type || "-"}</td>
                        <td className="py-3 px-4">{comp.license || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "vulnerabilities" && (
        <Card>
          <CardHeader>
            <CardTitle>{t("Vulnerabilities.title")}</CardTitle>
          </CardHeader>
          <CardContent>
            {vulnerabilities.length === 0 ? (
              <p className="text-center text-muted-foreground py-8">
                No vulnerabilities found.
              </p>
            ) : (
              <div className="space-y-4">
                {vulnerabilities.map((vuln) => (
                  <div key={vuln.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold">{vuln.cve_id}</span>
                        <Badge
                          variant={getSeverityVariant(vuln.severity) as any}
                        >
                          {vuln.severity}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {vuln.source || "NVD"}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-muted-foreground">
                          CVSS: {vuln.cvss_score}
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            setSelectedVulnForVex(vuln);
                            setShowVexForm(true);
                            setActiveTab("vex");
                          }}
                        >
                          <Shield className="h-3 w-3 mr-1" />
                          Add VEX
                        </Button>
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {vuln.description}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "vex" && (
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
              <CardTitle>VEX Statements</CardTitle>
              <div className="flex gap-2">
                <a
                  href={api.projects.exportVEX(projectId)}
                  download="vex.json"
                  className="inline-flex"
                >
                  <Button variant="outline" size="sm">
                    <Download className="h-4 w-4 mr-2" />
                    Export VEX
                  </Button>
                </a>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {showVexForm && selectedVulnForVex && (
              <VEXForm
                vulnerability={selectedVulnForVex}
                projectId={projectId}
                onSuccess={() => {
                  setShowVexForm(false);
                  setSelectedVulnForVex(null);
                  loadVexStatements();
                }}
                onCancel={() => {
                  setShowVexForm(false);
                  setSelectedVulnForVex(null);
                }}
              />
            )}

            {vexStatements.length === 0 && !showVexForm ? (
              <p className="text-center text-muted-foreground py-8">
                No VEX statements found. Add VEX statements from the Vulnerabilities tab.
              </p>
            ) : (
              <div className="space-y-4">
                {vexStatements.map((vex) => (
                  <div key={vex.id} className="border rounded-lg p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold">{vex.vulnerability_cve_id}</span>
                        <Badge variant={getVexStatusVariant(vex.status)}>
                          {vex.status.replace("_", " ")}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {vex.vulnerability_severity}
                        </Badge>
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-red-500 hover:text-red-700"
                        onClick={async () => {
                          if (confirm("Delete this VEX statement?")) {
                            await api.projects.deleteVEXStatement(projectId, vex.id);
                            loadVexStatements();
                          }
                        }}
                      >
                        Delete
                      </Button>
                    </div>
                    {vex.justification && (
                      <p className="text-sm text-muted-foreground mb-1">
                        <strong>Justification:</strong> {vex.justification.replace(/_/g, " ")}
                      </p>
                    )}
                    {vex.impact_statement && (
                      <p className="text-sm text-muted-foreground">
                        <strong>Impact:</strong> {vex.impact_statement}
                      </p>
                    )}
                    {vex.component_name && (
                      <p className="text-xs text-muted-foreground mt-2">
                        Component: {vex.component_name} {vex.component_version}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "licenses" && (
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
              <CardTitle>License Policies</CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowLicenseForm(true)}
              >
                Add Policy
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {showLicenseForm && (
              <LicensePolicyForm
                projectId={projectId}
                onSuccess={() => {
                  setShowLicenseForm(false);
                  loadLicensePolicies();
                  loadLicenseViolations();
                }}
                onCancel={() => setShowLicenseForm(false)}
              />
            )}

            {licenseViolations.length > 0 && (
              <div className="mb-6">
                <h3 className="font-semibold mb-3 text-red-600">License Violations ({licenseViolations.length})</h3>
                <div className="space-y-2">
                  {licenseViolations.map((v) => (
                    <div key={v.component_id} className="border border-red-200 rounded-lg p-3 bg-red-50">
                      <div className="flex items-center justify-between">
                        <div>
                          <span className="font-medium">{v.component_name}</span>
                          <span className="text-muted-foreground ml-2">{v.version}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={v.policy_type === "denied" ? "destructive" : "outline"}>
                            {v.license}
                          </Badge>
                          <Badge variant={v.policy_type === "denied" ? "destructive" : "secondary"}>
                            {v.policy_type}
                          </Badge>
                        </div>
                      </div>
                      {v.reason && (
                        <p className="text-sm text-muted-foreground mt-1">{v.reason}</p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <h3 className="font-semibold mb-3">Configured Policies</h3>
            {licensePolicies.length === 0 && !showLicenseForm ? (
              <p className="text-center text-muted-foreground py-8">
                No license policies configured. Add policies to check component licenses.
              </p>
            ) : (
              <div className="space-y-2">
                {licensePolicies.map((policy) => (
                  <div key={policy.id} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-medium">{policy.license_name}</span>
                        <span className="text-muted-foreground text-sm ml-2">({policy.license_id})</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={getLicensePolicyVariant(policy.policy_type)}>
                          {policy.policy_type}
                        </Badge>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-red-500 hover:text-red-700"
                          onClick={async () => {
                            if (confirm("Delete this license policy?")) {
                              await api.projects.deleteLicensePolicy(projectId, policy.id);
                              loadLicensePolicies();
                              loadLicenseViolations();
                            }
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    </div>
                    {policy.reason && (
                      <p className="text-sm text-muted-foreground mt-1">{policy.reason}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeTab === "apikeys" && (
        <Card>
          <CardHeader>
            <div className="flex justify-between items-center">
              <CardTitle>API Keys</CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowApiKeyForm(true)}
              >
                Create API Key
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {newApiKey && (
              <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                <p className="font-semibold text-green-800 mb-2">API Key Created!</p>
                <p className="text-sm text-green-700 mb-2">
                  Copy this key now. You won&apos;t be able to see it again.
                </p>
                <div className="flex items-center gap-2 bg-white p-2 rounded border font-mono text-sm">
                  <code className="flex-1 break-all">{newApiKey.key}</code>
                  <CopyButton text={newApiKey.key} />
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-2"
                  onClick={() => setNewApiKey(null)}
                >
                  Done
                </Button>
              </div>
            )}

            {showApiKeyForm && !newApiKey && (
              <APIKeyForm
                projectId={projectId}
                onSuccess={(key) => {
                  setNewApiKey(key);
                  setShowApiKeyForm(false);
                  loadApiKeys();
                }}
                onCancel={() => setShowApiKeyForm(false)}
              />
            )}

            <div className="mb-4 p-4 bg-blue-50 border border-blue-200 rounded-lg">
              <p className="font-semibold text-blue-800 mb-2">GitHub Actions Integration</p>
              <p className="text-sm text-blue-700">
                Use API keys to authenticate CI/CD workflows. Add your key as a secret named{" "}
                <code className="bg-blue-100 px-1 rounded">SBOMHUB_API_KEY</code> in your repository settings.
              </p>
            </div>

            {apiKeys.length === 0 && !showApiKeyForm ? (
              <p className="text-center text-muted-foreground py-8">
                No API keys created. Create a key to enable CI/CD integration.
              </p>
            ) : (
              <div className="space-y-2">
                {apiKeys.map((key) => (
                  <div key={key.id} className="border rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-medium">{key.name}</span>
                        <span className="text-muted-foreground text-sm ml-2">
                          ({key.key_prefix}...)
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline">{key.permissions}</Badge>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="text-red-500 hover:text-red-700"
                          onClick={async () => {
                            if (confirm("Delete this API key? This action cannot be undone.")) {
                              await api.projects.deleteAPIKey(projectId, key.id);
                              loadApiKeys();
                            }
                          }}
                        >
                          Delete
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      Created: {new Date(key.created_at).toLocaleDateString()}
                      {key.last_used_at && (
                        <span className="ml-4">
                          Last used: {new Date(key.last_used_at).toLocaleDateString()}
                        </span>
                      )}
                      {key.expires_at && (
                        <span className="ml-4">
                          Expires: {new Date(key.expires_at).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
    </Button>
  );
}

interface APIKeyFormProps {
  projectId: string;
  onSuccess: (key: APIKeyWithSecret) => void;
  onCancel: () => void;
}

function APIKeyForm({ projectId, onSuccess, onCancel }: APIKeyFormProps) {
  const [name, setName] = useState("");
  const [expiresInDays, setExpiresInDays] = useState(0);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const key = await api.projects.createAPIKey(projectId, {
        name,
        expires_in_days: expiresInDays > 0 ? expiresInDays : undefined,
      });
      onSuccess(key);
    } catch (error) {
      console.error("Failed to create API key:", error);
      alert("Failed to create API key");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="border rounded-lg p-4 mb-4 bg-muted/50">
      <h3 className="font-bold mb-4">Create API Key</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full border rounded px-3 py-2"
            placeholder="e.g., GitHub Actions CI"
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Expires In (Days)</label>
          <select
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(Number(e.target.value))}
            className="w-full border rounded px-3 py-2"
          >
            <option value="0">Never expires</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="365">1 year</option>
          </select>
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || !name}>
            {submitting ? "Creating..." : "Create Key"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </form>
  );
}

function getLicensePolicyVariant(type: LicensePolicyType): "default" | "secondary" | "destructive" | "outline" {
  switch (type) {
    case "allowed":
      return "default";
    case "denied":
      return "destructive";
    case "review":
      return "secondary";
    default:
      return "outline";
  }
}

function getVexStatusVariant(status: VEXStatus): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "not_affected":
      return "secondary";
    case "affected":
      return "destructive";
    case "fixed":
      return "default";
    case "under_investigation":
      return "outline";
    default:
      return "outline";
  }
}

interface VEXFormProps {
  vulnerability: Vulnerability;
  projectId: string;
  onSuccess: () => void;
  onCancel: () => void;
}

function VEXForm({ vulnerability, projectId, onSuccess, onCancel }: VEXFormProps) {
  const [status, setStatus] = useState<VEXStatus>("under_investigation");
  const [justification, setJustification] = useState<VEXJustification | "">("");
  const [impactStatement, setImpactStatement] = useState("");
  const [actionStatement, setActionStatement] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.projects.createVEXStatement(projectId, {
        vulnerability_id: vulnerability.id,
        status,
        justification: justification || undefined,
        impact_statement: impactStatement || undefined,
        action_statement: actionStatement || undefined,
      });
      onSuccess();
    } catch (error) {
      console.error("Failed to create VEX statement:", error);
      alert("Failed to create VEX statement");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="border rounded-lg p-4 mb-4 bg-muted/50">
      <h3 className="font-bold mb-4">Create VEX Statement for {vulnerability.cve_id}</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Status</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as VEXStatus)}
            className="w-full border rounded px-3 py-2"
          >
            <option value="under_investigation">Under Investigation</option>
            <option value="not_affected">Not Affected</option>
            <option value="affected">Affected</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>

        {status === "not_affected" && (
          <div>
            <label className="block text-sm font-medium mb-1">Justification (required)</label>
            <select
              value={justification}
              onChange={(e) => setJustification(e.target.value as VEXJustification)}
              className="w-full border rounded px-3 py-2"
              required
            >
              <option value="">Select justification...</option>
              <option value="component_not_present">Component not present</option>
              <option value="vulnerable_code_not_present">Vulnerable code not present</option>
              <option value="vulnerable_code_not_in_execute_path">Vulnerable code not in execute path</option>
              <option value="vulnerable_code_cannot_be_controlled_by_adversary">Vulnerable code cannot be controlled by adversary</option>
              <option value="inline_mitigations_already_exist">Inline mitigations already exist</option>
            </select>
          </div>
        )}

        <div>
          <label className="block text-sm font-medium mb-1">Impact Statement</label>
          <textarea
            value={impactStatement}
            onChange={(e) => setImpactStatement(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder="Describe the impact of this vulnerability..."
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Action Statement</label>
          <textarea
            value={actionStatement}
            onChange={(e) => setActionStatement(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder="Describe actions taken or planned..."
          />
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting}>
            {submitting ? "Creating..." : "Create VEX Statement"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </form>
  );
}

interface LicensePolicyFormProps {
  projectId: string;
  onSuccess: () => void;
  onCancel: () => void;
}

const COMMON_LICENSES = [
  { id: "MIT", name: "MIT License" },
  { id: "Apache-2.0", name: "Apache License 2.0" },
  { id: "GPL-3.0-only", name: "GNU GPL v3.0" },
  { id: "GPL-2.0-only", name: "GNU GPL v2.0" },
  { id: "LGPL-3.0-only", name: "GNU LGPL v3.0" },
  { id: "BSD-2-Clause", name: "BSD 2-Clause" },
  { id: "BSD-3-Clause", name: "BSD 3-Clause" },
  { id: "ISC", name: "ISC License" },
  { id: "MPL-2.0", name: "Mozilla Public License 2.0" },
  { id: "AGPL-3.0-only", name: "GNU AGPL v3.0" },
  { id: "Unlicense", name: "The Unlicense" },
  { id: "CC0-1.0", name: "Creative Commons Zero" },
];

function LicensePolicyForm({ projectId, onSuccess, onCancel }: LicensePolicyFormProps) {
  const [licenseId, setLicenseId] = useState("");
  const [customLicenseId, setCustomLicenseId] = useState("");
  const [policyType, setPolicyType] = useState<LicensePolicyType>("allowed");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    const finalLicenseId = licenseId === "custom" ? customLicenseId : licenseId;
    const licenseName = COMMON_LICENSES.find(l => l.id === finalLicenseId)?.name;

    try {
      await api.projects.createLicensePolicy(projectId, {
        license_id: finalLicenseId,
        license_name: licenseName,
        policy_type: policyType,
        reason: reason || undefined,
      });
      onSuccess();
    } catch (error) {
      console.error("Failed to create license policy:", error);
      alert("Failed to create license policy");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="border rounded-lg p-4 mb-4 bg-muted/50">
      <h3 className="font-bold mb-4">Add License Policy</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">License</label>
          <select
            value={licenseId}
            onChange={(e) => setLicenseId(e.target.value)}
            className="w-full border rounded px-3 py-2"
            required
          >
            <option value="">Select a license...</option>
            {COMMON_LICENSES.map((lic) => (
              <option key={lic.id} value={lic.id}>
                {lic.name} ({lic.id})
              </option>
            ))}
            <option value="custom">Other (custom)</option>
          </select>
        </div>

        {licenseId === "custom" && (
          <div>
            <label className="block text-sm font-medium mb-1">Custom License ID (SPDX)</label>
            <input
              type="text"
              value={customLicenseId}
              onChange={(e) => setCustomLicenseId(e.target.value)}
              className="w-full border rounded px-3 py-2"
              placeholder="e.g., Proprietary, EUPL-1.2"
              required
            />
          </div>
        )}

        <div>
          <label className="block text-sm font-medium mb-1">Policy Type</label>
          <select
            value={policyType}
            onChange={(e) => setPolicyType(e.target.value as LicensePolicyType)}
            className="w-full border rounded px-3 py-2"
          >
            <option value="allowed">Allowed - This license is approved</option>
            <option value="denied">Denied - This license is prohibited</option>
            <option value="review">Review - Requires manual review</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">Reason (optional)</label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder="Explain why this policy was set..."
          />
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || (!licenseId || (licenseId === "custom" && !customLicenseId))}>
            {submitting ? "Creating..." : "Add Policy"}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
        </div>
      </div>
    </form>
  );
}
