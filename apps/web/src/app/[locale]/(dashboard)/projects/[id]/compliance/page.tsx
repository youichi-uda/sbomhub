"use client";

import { useState } from "react";
import { useLocale, useTranslations } from "next-intl";
import { useQuery } from "@tanstack/react-query";
import { queryKeys } from "@/lib/query/keys";
import { categoryLabelKey, checkLabelKey, detailMessage, localizedLabel } from "@/lib/compliance-labels";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  api,
  ComplianceResult,
  ComplianceCategory,
  ComplianceCheck,
  ChecklistResult,
  ChecklistPhaseResult,
  ChecklistItemResult,
  VisualizationFramework,
  VisualizationSettings,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import {
  CheckCircle,
  XCircle,
  AlertCircle,
  ArrowLeft,
  FileText,
  Download,
  Shield,
  ClipboardCheck,
  Settings2,
  Zap,
  Loader2,
  Save,
} from "lucide-react";

function ScoreCircle({ score, maxScore }: { score: number; maxScore: number }) {
  const percentage = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  let color = "text-green-700";
  if (percentage < 50) color = "text-red-500";
  else if (percentage < 80) color = "text-yellow-700";

  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 transform -rotate-90">
        <circle
          cx="64"
          cy="64"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="none"
          className="text-muted"
        />
        <circle
          cx="64"
          cy="64"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className={color}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={`text-2xl font-bold ${color}`}>{percentage}%</span>
      </div>
    </div>
  );
}

function CheckItem({ check }: { check: ComplianceCheck }) {
  const t = useTranslations("Compliance");
  const labelKey = checkLabelKey(check.id);
  const detail = check.details ? detailMessage(check.details) : null;
  return (
    <div className="flex items-start gap-3 py-2">
      {check.passed ? (
        <CheckCircle className="h-5 w-5 text-green-700 mt-0.5 shrink-0" />
      ) : (
        <XCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
      )}
      <div>
        <p className={check.passed ? "text-foreground" : "text-muted-foreground"}>
          {labelKey ? t(labelKey) : check.label}
        </p>
        {check.details && (
          <p className="text-sm text-muted-foreground mt-1">
            └─ {detail ? t(detail.key, detail.values) : check.details}
          </p>
        )}
      </div>
    </div>
  );
}

function CategoryCard({ category }: { category: ComplianceCategory }) {
  const t = useTranslations("Compliance");
  const labelKey = categoryLabelKey(category.name);
  const percentage = category.max_score > 0
    ? Math.round((category.score / category.max_score) * 100)
    : 0;

  let statusIcon;
  let statusColor;
  if (percentage === 100) {
    statusIcon = <CheckCircle className="h-5 w-5 text-green-700" />;
    statusColor = "text-green-700";
  } else if (percentage >= 50) {
    statusIcon = <AlertCircle className="h-5 w-5 text-yellow-700" />;
    statusColor = "text-yellow-700";
  } else {
    statusIcon = <XCircle className="h-5 w-5 text-red-500" />;
    statusColor = "text-red-500";
  }

  return (
    <AccordionItem value={category.name} className="border rounded-lg px-4">
      <AccordionTrigger className="hover:no-underline">
        <div className="flex items-center justify-between w-full pr-4">
          <div className="flex items-center gap-3">
            {statusIcon}
            <span className="font-medium">{labelKey ? t(labelKey) : category.label}</span>
          </div>
          <span className={`text-sm ${statusColor}`}>
            {category.score}/{category.max_score}
          </span>
        </div>
      </AccordionTrigger>
      <AccordionContent>
        <div className="pl-8 pb-2">
          {category.checks.map((check) => (
            <CheckItem key={check.id} check={check} />
          ))}
        </div>
      </AccordionContent>
    </AccordionItem>
  );
}

// METI Checklist Item Component
function ChecklistItemComponent({
  item,
  projectId,
  onUpdate,
}: {
  item: ChecklistItemResult;
  projectId: string;
  onUpdate: () => void;
}) {
  const t = useTranslations("Compliance");
  const locale = useLocale();
  const [note, setNote] = useState(item.note || "");
  const [saving, setSaving] = useState(false);
  const [localResponse, setLocalResponse] = useState(item.response ?? false);

  const handleToggle = async (checked: boolean) => {
    setLocalResponse(checked);
    setSaving(true);
    try {
      await api.projects.updateChecklistResponse(projectId, item.id, {
        response: checked,
        note: note || undefined,
      });
      onUpdate();
    } catch (err) {
      console.error("Failed to update checklist response:", err);
      setLocalResponse(!checked);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveNote = async () => {
    setSaving(true);
    try {
      await api.projects.updateChecklistResponse(projectId, item.id, {
        response: localResponse,
        note: note || undefined,
      });
      onUpdate();
    } catch (err) {
      console.error("Failed to save note:", err);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 flex-1">
          {item.auto_verify ? (
            // Auto-verified item
            item.auto_result ? (
              <CheckCircle className="h-5 w-5 text-green-700 mt-0.5 shrink-0" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
            )
          ) : (
            // Manual item with checkbox
            <Checkbox
              checked={localResponse}
              onCheckedChange={handleToggle}
              disabled={saving}
              className="mt-0.5"
            />
          )}
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <p className="font-medium">{localizedLabel(item, locale)}</p>
              {item.auto_verify && (
                <Badge variant="secondary" className="text-xs">
                  <Zap className="h-3 w-3 mr-1" />
                  {t("autoVerified")}
                </Badge>
              )}
            </div>
            {/* /ja keeps the English original as a secondary line, as before. */}
            {locale === "ja" && <p className="text-sm text-muted-foreground mt-1">{item.label}</p>}
          </div>
        </div>
        {item.passed ? (
          <Badge variant="default" className="bg-green-700 hover:bg-green-800">
            {t("done")}
          </Badge>
        ) : (
          <Badge variant="outline">{t("notDone")}</Badge>
        )}
      </div>

      {/* Note field for manual items */}
      {!item.auto_verify && (
        <div className="pl-8 space-y-2">
          <Label className="text-sm text-muted-foreground">{t("note")}</Label>
          <div className="flex gap-2">
            <Textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={t("notePlaceholder")}
              aria-label={t("note")}
              className="min-h-[60px] text-sm"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleSaveNote}
              disabled={saving}
              aria-label={t("saveNote")}
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// METI Checklist Phase Component
function ChecklistPhaseCard({
  phase,
  projectId,
  onUpdate,
}: {
  phase: ChecklistPhaseResult;
  projectId: string;
  onUpdate: () => void;
}) {
  const t = useTranslations("Compliance");
  const locale = useLocale();
  const percentage = phase.max_score > 0
    ? Math.round((phase.score / phase.max_score) * 100)
    : 0;

  let statusIcon;
  let statusColor;
  if (percentage === 100) {
    statusIcon = <CheckCircle className="h-5 w-5 text-green-700" />;
    statusColor = "text-green-700";
  } else if (percentage >= 50) {
    statusIcon = <AlertCircle className="h-5 w-5 text-yellow-700" />;
    statusColor = "text-yellow-700";
  } else {
    statusIcon = <XCircle className="h-5 w-5 text-red-500" />;
    statusColor = "text-red-500";
  }

  const phaseNumber =
    phase.phase === "setup" ? 1 : phase.phase === "creation" ? 2 : 3;

  return (
    <AccordionItem value={phase.phase} className="border rounded-lg">
      <AccordionTrigger className="px-4 hover:no-underline">
        <div className="flex items-center justify-between w-full pr-4">
          <div className="flex items-center gap-3">
            {statusIcon}
            <span className="font-medium">
              {t("phase", { number: String(phaseNumber), label: localizedLabel(phase, locale) })}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <Progress value={percentage} className="w-20 h-2" />
            <span className={`text-sm ${statusColor}`}>
              {phase.score}/{phase.max_score}
            </span>
          </div>
        </div>
      </AccordionTrigger>
      <AccordionContent className="px-4 pb-4">
        <div className="space-y-3">
          {phase.items.map((item) => (
            <ChecklistItemComponent
              key={item.id}
              item={item}
              projectId={projectId}
              onUpdate={onUpdate}
            />
          ))}
        </div>
      </AccordionContent>
    </AccordionItem>
  );
}

// Visualization Settings Component
function VisualizationSettingsComponent({
  framework,
  projectId,
  onUpdate,
}: {
  framework: VisualizationFramework;
  projectId: string;
  onUpdate: () => void;
}) {
  const [settings, setSettings] = useState<Partial<VisualizationSettings>>(
    framework.settings || {
      sbom_author_scope: "supplier",
      dependency_scope: "direct",
      generation_method: "auto",
      data_format: "cyclonedx",
      utilization_scope: ["vulnerability"],
      utilization_actor: "development",
    }
  );
  const t = useTranslations("Compliance");
  const locale = useLocale();
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.projects.updateVisualization(projectId, settings);
      onUpdate();
    } catch (err) {
      console.error("Failed to save visualization settings:", err);
    } finally {
      setSaving(false);
    }
  };

  const handleUtilizationScopeChange = (value: string, checked: boolean) => {
    const current = settings.utilization_scope || [];
    if (checked) {
      setSettings({ ...settings, utilization_scope: [...current, value] });
    } else {
      setSettings({
        ...settings,
        utilization_scope: current.filter((v) => v !== value),
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* (a) SBOM作成主体 */}
        <div className="space-y-2">
          <Label>{t("authorScope")}</Label>
          <Select
            value={settings.sbom_author_scope}
            onValueChange={(v) =>
              setSettings({ ...settings, sbom_author_scope: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder={t("selectPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {framework.options.sbom_author_scope.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {localizedLabel(opt, locale)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (b) 依存関係 */}
        <div className="space-y-2">
          <Label>{t("dependencyScope")}</Label>
          <Select
            value={settings.dependency_scope}
            onValueChange={(v) =>
              setSettings({ ...settings, dependency_scope: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder={t("selectPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {framework.options.dependency_scope.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {localizedLabel(opt, locale)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (c) 生成手段 */}
        <div className="space-y-2">
          <Label>{t("generationMethod")}</Label>
          <Select
            value={settings.generation_method}
            onValueChange={(v) =>
              setSettings({ ...settings, generation_method: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder={t("selectPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {framework.options.generation_method.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {localizedLabel(opt, locale)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (d) データ様式 */}
        <div className="space-y-2">
          <Label>{t("dataFormat")}</Label>
          <Select
            value={settings.data_format}
            onValueChange={(v) => setSettings({ ...settings, data_format: v })}
          >
            <SelectTrigger>
              <SelectValue placeholder={t("selectPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {framework.options.data_format.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {localizedLabel(opt, locale)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (f) 活用主体 */}
        <div className="space-y-2">
          <Label>{t("utilizationActor")}</Label>
          <Select
            value={settings.utilization_actor}
            onValueChange={(v) =>
              setSettings({ ...settings, utilization_actor: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder={t("selectPlaceholder")} />
            </SelectTrigger>
            <SelectContent>
              {framework.options.utilization_actor.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {localizedLabel(opt, locale)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* (e) 活用範囲 - Multiple selection */}
      <div className="space-y-2">
        <Label>{t("utilizationScope")}</Label>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {framework.options.utilization_scope.map((opt) => (
            <div key={opt.value} className="flex items-center space-x-2">
              <Checkbox
                id={`util-${opt.value}`}
                checked={(settings.utilization_scope || []).includes(opt.value)}
                onCheckedChange={(checked) =>
                  handleUtilizationScopeChange(opt.value, checked as boolean)
                }
              />
              <Label htmlFor={`util-${opt.value}`} className="text-sm">
                {localizedLabel(opt, locale)}
              </Label>
            </div>
          ))}
        </div>
      </div>

      <Button onClick={handleSave} disabled={saving}>
        {saving ? (
          <>
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            {t("saving")}
          </>
        ) : (
          <>
            <Save className="h-4 w-4 mr-2" />
            {t("saveSettings")}
          </>
        )}
      </Button>
    </div>
  );
}

export default function CompliancePage() {
  const params = useParams();
  const projectId = params.id as string;
  const [activeTab, setActiveTab] = useState("overview");
  const t = useTranslations("Compliance");
  const locale = useLocale();

  const complianceQuery = useQuery({
    queryKey: queryKeys.projects.compliance(projectId),
    queryFn: async (): Promise<ComplianceResult> => {
      try {
        return await api.projects.getCompliance(projectId);
      } catch (err) {
        console.error(err);
        throw err;
      }
    },
  });
  // The checklist and the visualization settings are optional extras: a
  // failure leaves them null (first load) or keeps the previous copy (a
  // reload after an edit), exactly like the `.catch(() => null)` /
  // reloadChecklist pair this replaces.
  const checklistQuery = useQuery({
    queryKey: queryKeys.projects.checklist(projectId),
    queryFn: async (): Promise<ChecklistResult> => {
      try {
        return await api.projects.getChecklist(projectId);
      } catch (err) {
        console.error("Failed to load checklist:", err);
        throw err;
      }
    },
  });
  const visualizationQuery = useQuery({
    queryKey: queryKeys.projects.visualization(projectId),
    queryFn: async (): Promise<VisualizationFramework> => {
      try {
        return await api.projects.getVisualization(projectId);
      } catch (err) {
        console.error("Failed to load visualization:", err);
        throw err;
      }
    },
  });
  const result = complianceQuery.data ?? null;
  const checklist = checklistQuery.data ?? null;
  const visualization = visualizationQuery.data ?? null;
  // The old loader was a Promise.all: the skeleton stayed up until all three
  // settled, except that a compliance failure rejected it immediately.
  const loading =
    complianceQuery.isPending ||
    (complianceQuery.isSuccess && (checklistQuery.isPending || visualizationQuery.isPending));
  const error = complianceQuery.isError ? t("loadFailed") : null;

  const checklistItemCount = checklist ? checklist.phases.reduce((n, p) => n + p.items.length, 0) : 0;

  const reloadChecklist = async () => {
    await checklistQuery.refetch();
  };

  const reloadVisualization = async () => {
    await visualizationQuery.refetch();
  };

  if (loading) {
    return (
      <div className="container mx-auto py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-muted rounded w-1/4" />
          <div className="h-64 bg-muted rounded" />
        </div>
      </div>
    );
  }

  if (error || !result) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-red-500">
              <AlertCircle className="h-5 w-5" />
              <span>{error || t("loadFailed")}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8 space-y-6">
      <div className="flex items-center gap-4">
        <Link href={`/${locale}/projects/${projectId}`} aria-label={t("back")}>
          <Button variant="ghost" size="icon" tabIndex={-1}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8" />
            {t("title")}
          </h1>
          <p className="text-muted-foreground">
            {t("subtitle")}
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            {t("tabOverview")}
          </TabsTrigger>
          <TabsTrigger value="checklist" className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4" />
            {t("tabChecklist")}
          </TabsTrigger>
          <TabsTrigger value="visualization" className="flex items-center gap-2">
            <Settings2 className="h-4 w-4" />
            {t("tabVisualization")}
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Score Card */}
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle>{t("totalScore")}</CardTitle>
                <CardDescription>{t("totalScoreDescription")}</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <ScoreCircle score={result.score} maxScore={result.max_score} />
                <p className="mt-4 text-center text-sm text-muted-foreground">
                  {t("points", { score: String(result.score), max: String(result.max_score) })}
                </p>
              </CardContent>
            </Card>

            {/* Categories */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>{t("checkItems")}</CardTitle>
                <CardDescription>{t("checkItemsDescription")}</CardDescription>
              </CardHeader>
              <CardContent>
                <Accordion type="multiple" className="space-y-2">
                  {result.categories.map((category) => (
                    <CategoryCard key={category.name} category={category} />
                  ))}
                </Accordion>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Checklist Tab */}
        <TabsContent value="checklist" className="space-y-6">
          {checklist ? (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <Card className="lg:col-span-1">
                  <CardHeader>
                    <CardTitle>{t("checklistProgress")}</CardTitle>
                    <CardDescription>{t("checklistProgressDescription", { count: String(checklistItemCount) })}</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col items-center">
                    <ScoreCircle
                      score={checklist.score}
                      maxScore={checklist.max_score}
                    />
                    <p className="mt-4 text-center text-sm text-muted-foreground">
                      {t("itemsDone", { score: String(checklist.score), max: String(checklist.max_score) })}
                    </p>
                  </CardContent>
                </Card>

                <Card className="lg:col-span-3">
                  <CardHeader>
                    <CardTitle>{t("checklistTitle")}</CardTitle>
                    <CardDescription>
                      {t("checklistDescription", {
                        phases: String(checklist.phases.length),
                        count: String(checklistItemCount),
                      })}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Accordion
                      type="multiple"
                      defaultValue={["setup", "creation", "operation"]}
                      className="space-y-2"
                    >
                      {checklist.phases.map((phase) => (
                        <ChecklistPhaseCard
                          key={phase.phase}
                          phase={phase}
                          projectId={projectId}
                          onUpdate={reloadChecklist}
                        />
                      ))}
                    </Accordion>
                  </CardContent>
                </Card>
              </div>
            </>
          ) : (
            <Card>
              <CardContent className="py-8">
                <div className="text-center text-muted-foreground">
                  <ClipboardCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{t("checklistLoadFailed")}</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Visualization Tab */}
        <TabsContent value="visualization" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>{t("visualizationTitle")}</CardTitle>
              <CardDescription>
                {t("visualizationDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {visualization ? (
                <VisualizationSettingsComponent
                  framework={visualization}
                  projectId={projectId}
                  onUpdate={reloadVisualization}
                />
              ) : (
                <div className="text-center text-muted-foreground py-8">
                  <Settings2 className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>{t("visualizationLoadFailed")}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Disclaimer */}
      <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-md">
        <p>{t("disclaimer")}</p>
      </div>

      {/* Export Buttons */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            {t("exportTitle")}
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-4">
          <a
            href={api.projects.exportComplianceReport(projectId, "json")}
            download
            className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"
          >
            <Download className="h-4 w-4 mr-2" />
            JSON
          </a>
          <a
            href={api.projects.exportComplianceReport(projectId, "pdf")}
            download
            className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"
          >
            <Download className="h-4 w-4 mr-2" />
            PDF
          </a>
          <a
            href={api.projects.exportComplianceReport(projectId, "xlsx")}
            download
            className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"
          >
            <Download className="h-4 w-4 mr-2" />
            Excel
          </a>
        </CardContent>
      </Card>
    </div>
  );
}
