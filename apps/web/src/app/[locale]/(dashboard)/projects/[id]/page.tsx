"use client";

import { useTranslations } from "next-intl";
import { useState, useEffect, useCallback } from "react";
import { useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, Project, Component, Vulnerability, VEXStatementWithDetails, VEXStatus, VEXJustification, LicensePolicy, LicensePolicyType, LicenseViolation, APIKey, APIKeyWithSecret, NotificationSettings, NotificationLog } from "@/lib/api";
import { Upload, Package, AlertTriangle, ArrowLeft, Shield, Download, FileCheck, Key, Copy, Check, Bell } from "lucide-react";
import Link from "next/link";

type Tab = "upload" | "components" | "vulnerabilities" | "vex" | "licenses" | "apikeys" | "notifications";

export default function ProjectDetailPage() {
  const params = useParams();
  const projectId = params.id as string;
  const t = useTranslations();
  const tp = useTranslations("ProjectDetail");
  const tc = useTranslations("Common");
  const tv = useTranslations("VexForm");
  const ta = useTranslations("ApiKeyForm");
  const tl = useTranslations("LicenseForm");

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
  const [notificationSettings, setNotificationSettings] = useState<NotificationSettings | null>(null);
  const [notificationLogs, setNotificationLogs] = useState<NotificationLog[]>([]);

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

  const loadNotificationSettings = useCallback(async () => {
    try {
      const data = await api.projects.getNotificationSettings(projectId);
      setNotificationSettings(data);
    } catch (error) {
      console.error("Failed to load notification settings:", error);
    }
  }, [projectId]);

  const loadNotificationLogs = useCallback(async () => {
    try {
      const data = await api.projects.getNotificationLogs(projectId);
      setNotificationLogs(data || []);
    } catch (error) {
      console.error("Failed to load notification logs:", error);
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
    loadNotificationSettings();
  }, [loadProject, loadComponents, loadVulnerabilities, loadVexStatements, loadLicensePolicies, loadSbomId, loadApiKeys, loadNotificationSettings]);

  useEffect(() => {
    if (activeTab === "components") loadComponents();
    if (activeTab === "vulnerabilities") loadVulnerabilities();
    if (activeTab === "vex") loadVexStatements();
    if (activeTab === "licenses") {
      loadLicensePolicies();
      loadLicenseViolations();
    }
    if (activeTab === "apikeys") loadApiKeys();
    if (activeTab === "notifications") {
      loadNotificationSettings();
      loadNotificationLogs();
    }
  }, [activeTab, loadComponents, loadVulnerabilities, loadVexStatements, loadLicensePolicies, loadLicenseViolations, loadApiKeys, loadNotificationSettings, loadNotificationLogs]);

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      const content = await file.text();
      await api.projects.uploadSbom(projectId, content);
      alert(tp("uploadSuccess"));
      loadComponents();
      setActiveTab("components");
    } catch (error) {
      console.error("Failed to upload SBOM:", error);
      alert(tp("uploadFailed"));
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
    return <div className="flex items-center justify-center h-64">{tc("loading")}</div>;
  }

  if (!project) {
    return <div className="flex items-center justify-center h-64">{tc("projectNotFound")}</div>;
  }

  return (
    <div>
      <div className="mb-6">
        <Link href="/projects" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2">
          <ArrowLeft className="h-4 w-4 mr-1" />
          {tp("backToProjects")}
        </Link>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">{project.name}</h1>
            <p className="text-muted-foreground">{project.description}</p>
          </div>
          <div className="flex items-center gap-2">
            <Link href={`/projects/${projectId}/diff`}>
              <Button variant="outline">{tp("sbomDiff")}</Button>
            </Link>
            <Link href={`/projects/${projectId}/share`}>
              <Button variant="outline">{tp("share")}</Button>
            </Link>
          </div>
        </div>
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
          {t("Components.license")} ({licensePolicies.length})
        </Button>
        <Button
          variant={activeTab === "apikeys" ? "default" : "outline"}
          onClick={() => setActiveTab("apikeys")}
        >
          <Key className="h-4 w-4 mr-2" />
          {tp("apiKeys")} ({apiKeys.length})
        </Button>
        <Button
          variant={activeTab === "notifications" ? "default" : "outline"}
          onClick={() => setActiveTab("notifications")}
        >
          <Bell className="h-4 w-4 mr-2" />
          {tp("notifications")}
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
                {tp("uploadDescription")}
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
                  {uploading ? tp("uploading") : tp("selectFile")}
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
                {tp("noComponents")}
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
                {tp("noVulnerabilities")}
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
                          {tp("addVex")}
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
              <CardTitle>{tp("vexStatements")}</CardTitle>
              <div className="flex gap-2">
                <a
                  href={api.projects.exportVEX(projectId)}
                  download="vex.json"
                  className="inline-flex"
                >
                  <Button variant="outline" size="sm">
                    <Download className="h-4 w-4 mr-2" />
                    {tp("exportVex")}
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
                {tp("noVexStatements")}
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
                          if (confirm(tp("deleteVexConfirm"))) {
                            await api.projects.deleteVEXStatement(projectId, vex.id);
                            loadVexStatements();
                          }
                        }}
                      >
                        {tc("delete")}
                      </Button>
                    </div>
                    {vex.justification && (
                      <p className="text-sm text-muted-foreground mb-1">
                        <strong>{tp("justification")}:</strong> {vex.justification.replace(/_/g, " ")}
                      </p>
                    )}
                    {vex.impact_statement && (
                      <p className="text-sm text-muted-foreground">
                        <strong>{tp("impact")}:</strong> {vex.impact_statement}
                      </p>
                    )}
                    {vex.component_name && (
                      <p className="text-xs text-muted-foreground mt-2">
                        {tp("component")}: {vex.component_name} {vex.component_version}
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
              <CardTitle>{tp("licensePolicies")}</CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowLicenseForm(true)}
              >
                {tp("addPolicy")}
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
                <h3 className="font-semibold mb-3 text-red-600">{tp("licenseViolations")} ({licenseViolations.length})</h3>
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

            <h3 className="font-semibold mb-3">{tp("configuredPolicies")}</h3>
            {licensePolicies.length === 0 && !showLicenseForm ? (
              <p className="text-center text-muted-foreground py-8">
                {tp("noLicensePolicies")}
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
                            if (confirm(tp("deleteLicenseConfirm"))) {
                              await api.projects.deleteLicensePolicy(projectId, policy.id);
                              loadLicensePolicies();
                              loadLicenseViolations();
                            }
                          }}
                        >
                          {tc("delete")}
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
              <CardTitle>{tp("apiKeys")}</CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowApiKeyForm(true)}
              >
                {tp("createApiKey")}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {newApiKey && (
              <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
                <p className="font-semibold text-green-800 mb-2">{tp("apiKeyCreated")}</p>
                <p className="text-sm text-green-700 mb-2">
                  {tp("apiKeyCopyWarning")}
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
                  {tp("done")}
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
              <p className="font-semibold text-blue-800 mb-2">{tp("apiKeyUseCases")}</p>
              <p className="text-sm text-blue-700 mb-2">{tp("apiKeyUseCasesDescription")}</p>
              <ul className="text-sm text-blue-700 space-y-1 list-disc list-inside">
                <li>{tp("apiKeyUseCli")}</li>
                <li>
                  {tp("apiKeyUseMcp")}{" "}
                  <a href="/docs/mcp" className="underline hover:text-blue-900">
                    {tp("mcpDocsLink")}
                  </a>
                </li>
                <li>{tp("apiKeyUseCicd")}</li>
              </ul>
              <p className="text-sm text-blue-600 mt-2">
                {tp("apiKeyEnvDescription")}: <code className="bg-blue-100 px-1 rounded">{tp("apiKeyEnvName")}</code>
              </p>
            </div>

            {apiKeys.length === 0 && !showApiKeyForm ? (
              <p className="text-center text-muted-foreground py-8">
                {tp("noApiKeys")}
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
                            if (confirm(tp("deleteApiKeyConfirm"))) {
                              await api.projects.deleteAPIKey(projectId, key.id);
                              loadApiKeys();
                            }
                          }}
                        >
                          {tc("delete")}
                        </Button>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {tp("created")}: {new Date(key.created_at).toLocaleDateString()}
                      {key.last_used_at && (
                        <span className="ml-4">
                          {tp("lastUsed")}: {new Date(key.last_used_at).toLocaleDateString()}
                        </span>
                      )}
                      {key.expires_at && (
                        <span className="ml-4">
                          {tp("expires")}: {new Date(key.expires_at).toLocaleDateString()}
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

      {activeTab === "notifications" && (
        <Card>
          <CardHeader>
            <CardTitle>{tp("notifications")}</CardTitle>
          </CardHeader>
          <CardContent>
            <NotificationSettingsForm
              projectId={projectId}
              settings={notificationSettings}
              onSuccess={() => {
                loadNotificationSettings();
              }}
            />

            {notificationLogs.length > 0 && (
              <div className="mt-6">
                <h3 className="font-semibold mb-3">{tp("notificationHistory")}</h3>
                <div className="space-y-2">
                  {notificationLogs.map((log) => (
                    <div key={log.id} className="border rounded-lg p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge variant={log.status === "sent" ? "default" : "destructive"}>
                            {log.status}
                          </Badge>
                          <span className="text-sm font-medium capitalize">{log.channel}</span>
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {new Date(log.created_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

interface NotificationSettingsFormProps {
  projectId: string;
  settings: NotificationSettings | null;
  onSuccess: () => void;
}

function NotificationSettingsForm({ projectId, settings, onSuccess }: NotificationSettingsFormProps) {
  const tp = useTranslations("ProjectDetail");
  const tc = useTranslations("Common");
  const tv = useTranslations("Vulnerabilities");
  const [slackWebhookUrl, setSlackWebhookUrl] = useState(settings?.slack_webhook_url || "");
  const [discordWebhookUrl, setDiscordWebhookUrl] = useState(settings?.discord_webhook_url || "");
  const [notifyCritical, setNotifyCritical] = useState(settings?.notify_critical ?? true);
  const [notifyHigh, setNotifyHigh] = useState(settings?.notify_high ?? true);
  const [notifyMedium, setNotifyMedium] = useState(settings?.notify_medium ?? false);
  const [notifyLow, setNotifyLow] = useState(settings?.notify_low ?? false);
  const [submitting, setSubmitting] = useState(false);
  const [testingNotification, setTestingNotification] = useState(false);

  useEffect(() => {
    if (settings) {
      setSlackWebhookUrl(settings.slack_webhook_url || "");
      setDiscordWebhookUrl(settings.discord_webhook_url || "");
      setNotifyCritical(settings.notify_critical);
      setNotifyHigh(settings.notify_high);
      setNotifyMedium(settings.notify_medium);
      setNotifyLow(settings.notify_low);
    }
  }, [settings]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.projects.updateNotificationSettings(projectId, {
        slack_webhook_url: slackWebhookUrl || undefined,
        discord_webhook_url: discordWebhookUrl || undefined,
        notify_critical: notifyCritical,
        notify_high: notifyHigh,
        notify_medium: notifyMedium,
        notify_low: notifyLow,
      });
      onSuccess();
      alert(tp("settingsSaved"));
    } catch (error) {
      console.error("Failed to save notification settings:", error);
      alert(tp("settingsFailed"));
    } finally {
      setSubmitting(false);
    }
  };

  const handleTestNotification = async () => {
    setTestingNotification(true);
    try {
      await api.projects.testNotification(projectId);
      alert(tp("testSent"));
    } catch (error) {
      console.error("Failed to send test notification:", error);
      alert(tp("testFailed"));
    } finally {
      setTestingNotification(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div>
        <h3 className="font-semibold mb-3">{tp("webhookUrls")}</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">{tp("slackWebhookUrl")}</label>
            <input
              type="url"
              name="slack_webhook"
              value={slackWebhookUrl}
              onChange={(e) => setSlackWebhookUrl(e.target.value)}
              className="w-full border rounded px-3 py-2"
              placeholder="https://hooks.slack.com/services/..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">{tp("discordWebhookUrl")}</label>
            <input
              type="url"
              name="discord_webhook"
              value={discordWebhookUrl}
              onChange={(e) => setDiscordWebhookUrl(e.target.value)}
              className="w-full border rounded px-3 py-2"
              placeholder="https://discord.com/api/webhooks/..."
            />
          </div>
        </div>
      </div>

      <div>
        <h3 className="font-semibold mb-3">{tp("severityThresholds")}</h3>
        <p className="text-sm text-muted-foreground mb-3">
          {tp("severityThresholdsDescription")}
        </p>
        <div className="space-y-2">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={notifyCritical}
              onChange={(e) => setNotifyCritical(e.target.checked)}
              className="rounded"
            />
            <span>{tv("critical")}</span>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={notifyHigh}
              onChange={(e) => setNotifyHigh(e.target.checked)}
              className="rounded"
            />
            <span>{tv("high")}</span>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={notifyMedium}
              onChange={(e) => setNotifyMedium(e.target.checked)}
              className="rounded"
            />
            <span>{tv("medium")}</span>
          </label>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={notifyLow}
              onChange={(e) => setNotifyLow(e.target.checked)}
              className="rounded"
            />
            <span>{tv("low")}</span>
          </label>
        </div>
      </div>

      <div className="flex gap-2">
        <Button type="submit" disabled={submitting}>
          {submitting ? tc("saving") : tc("save")}
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={handleTestNotification}
          disabled={testingNotification || (!slackWebhookUrl && !discordWebhookUrl)}
        >
          {testingNotification ? tp("sendingTest") : tp("testNotification")}
        </Button>
      </div>
    </form>
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
  const ta = useTranslations("ApiKeyForm");
  const tc = useTranslations("Common");
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
      <h3 className="font-bold mb-4">{ta("title")}</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">{ta("name")}</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full border rounded px-3 py-2"
            placeholder={ta("namePlaceholder")}
            required
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">{ta("expiresIn")}</label>
          <select
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(Number(e.target.value))}
            className="w-full border rounded px-3 py-2"
          >
            <option value="0">{ta("neverExpires")}</option>
            <option value="30">{ta("days30")}</option>
            <option value="90">{ta("days90")}</option>
            <option value="365">{ta("year1")}</option>
          </select>
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || !name}>
            {submitting ? ta("creating") : ta("createKey")}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            {tc("cancel")}
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
  const tv = useTranslations("VexForm");
  const tc = useTranslations("Common");
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
      <h3 className="font-bold mb-4">{tv("createFor", { cveId: vulnerability.cve_id })}</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">{tv("status")}</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value as VEXStatus)}
            className="w-full border rounded px-3 py-2"
          >
            <option value="under_investigation">{tv("underInvestigation")}</option>
            <option value="not_affected">{tv("notAffected")}</option>
            <option value="affected">{tv("affected")}</option>
            <option value="fixed">{tv("fixed")}</option>
          </select>
        </div>

        {status === "not_affected" && (
          <div>
            <label className="block text-sm font-medium mb-1">{tv("justificationRequired")}</label>
            <select
              value={justification}
              onChange={(e) => setJustification(e.target.value as VEXJustification)}
              className="w-full border rounded px-3 py-2"
              required
            >
              <option value="">{tv("selectJustification")}</option>
              <option value="component_not_present">{tv("componentNotPresent")}</option>
              <option value="vulnerable_code_not_present">{tv("vulnerableCodeNotPresent")}</option>
              <option value="vulnerable_code_not_in_execute_path">{tv("vulnerableCodeNotInExecutePath")}</option>
              <option value="vulnerable_code_cannot_be_controlled_by_adversary">{tv("vulnerableCodeCannotBeControlled")}</option>
              <option value="inline_mitigations_already_exist">{tv("inlineMitigationsExist")}</option>
            </select>
          </div>
        )}

        <div>
          <label className="block text-sm font-medium mb-1">{tv("impactStatement")}</label>
          <textarea
            value={impactStatement}
            onChange={(e) => setImpactStatement(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder={tv("impactPlaceholder")}
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">{tv("actionStatement")}</label>
          <textarea
            value={actionStatement}
            onChange={(e) => setActionStatement(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder={tv("actionPlaceholder")}
          />
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting}>
            {submitting ? tv("creating") : tv("createVexStatement")}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            {tc("cancel")}
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
  const tl = useTranslations("LicenseForm");
  const tc = useTranslations("Common");
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
      <h3 className="font-bold mb-4">{tl("title")}</h3>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">{tl("license")}</label>
          <select
            value={licenseId}
            onChange={(e) => setLicenseId(e.target.value)}
            className="w-full border rounded px-3 py-2"
            required
          >
            <option value="">{tl("selectLicense")}</option>
            {COMMON_LICENSES.map((lic) => (
              <option key={lic.id} value={lic.id}>
                {lic.name} ({lic.id})
              </option>
            ))}
            <option value="custom">{tl("otherCustom")}</option>
          </select>
        </div>

        {licenseId === "custom" && (
          <div>
            <label className="block text-sm font-medium mb-1">{tl("customLicenseId")}</label>
            <input
              type="text"
              value={customLicenseId}
              onChange={(e) => setCustomLicenseId(e.target.value)}
              className="w-full border rounded px-3 py-2"
              placeholder={tl("customPlaceholder")}
              required
            />
          </div>
        )}

        <div>
          <label className="block text-sm font-medium mb-1">{tl("policyType")}</label>
          <select
            value={policyType}
            onChange={(e) => setPolicyType(e.target.value as LicensePolicyType)}
            className="w-full border rounded px-3 py-2"
          >
            <option value="allowed">{tl("allowed")}</option>
            <option value="denied">{tl("denied")}</option>
            <option value="review">{tl("review")}</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium mb-1">{tl("reason")}</label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full border rounded px-3 py-2"
            rows={2}
            placeholder={tl("reasonPlaceholder")}
          />
        </div>

        <div className="flex gap-2">
          <Button type="submit" disabled={submitting || (!licenseId || (licenseId === "custom" && !customLicenseId))}>
            {submitting ? tl("creating") : tl("addPolicy")}
          </Button>
          <Button type="button" variant="outline" onClick={onCancel}>
            {tc("cancel")}
          </Button>
        </div>
      </div>
    </form>
  );
}
