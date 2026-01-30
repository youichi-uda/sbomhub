"use client";

import { useEffect, useState } from "react";
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

  let color = "text-green-500";
  if (percentage < 50) color = "text-red-500";
  else if (percentage < 80) color = "text-yellow-500";

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
  return (
    <div className="flex items-start gap-3 py-2">
      {check.passed ? (
        <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
      ) : (
        <XCircle className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
      )}
      <div>
        <p className={check.passed ? "text-foreground" : "text-muted-foreground"}>
          {check.label}
        </p>
        {check.details && (
          <p className="text-sm text-muted-foreground mt-1">
            └─ {check.details}
          </p>
        )}
      </div>
    </div>
  );
}

function CategoryCard({ category }: { category: ComplianceCategory }) {
  const percentage = category.max_score > 0
    ? Math.round((category.score / category.max_score) * 100)
    : 0;

  let statusIcon;
  let statusColor;
  if (percentage === 100) {
    statusIcon = <CheckCircle className="h-5 w-5 text-green-500" />;
    statusColor = "text-green-500";
  } else if (percentage >= 50) {
    statusIcon = <AlertCircle className="h-5 w-5 text-yellow-500" />;
    statusColor = "text-yellow-500";
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
            <span className="font-medium">{category.label}</span>
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
              <CheckCircle className="h-5 w-5 text-green-500 mt-0.5 flex-shrink-0" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500 mt-0.5 flex-shrink-0" />
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
              <p className="font-medium">{item.label_ja}</p>
              {item.auto_verify && (
                <Badge variant="secondary" className="text-xs">
                  <Zap className="h-3 w-3 mr-1" />
                  自動検証
                </Badge>
              )}
            </div>
            <p className="text-sm text-muted-foreground mt-1">{item.label}</p>
          </div>
        </div>
        {item.passed ? (
          <Badge variant="default" className="bg-green-500 hover:bg-green-600">
            完了
          </Badge>
        ) : (
          <Badge variant="outline">未完了</Badge>
        )}
      </div>

      {/* Note field for manual items */}
      {!item.auto_verify && (
        <div className="pl-8 space-y-2">
          <Label className="text-sm text-muted-foreground">備考</Label>
          <div className="flex gap-2">
            <Textarea
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="対応状況や詳細を記入..."
              className="min-h-[60px] text-sm"
            />
            <Button
              variant="outline"
              size="sm"
              onClick={handleSaveNote}
              disabled={saving}
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
  const percentage = phase.max_score > 0
    ? Math.round((phase.score / phase.max_score) * 100)
    : 0;

  let statusIcon;
  let statusColor;
  if (percentage === 100) {
    statusIcon = <CheckCircle className="h-5 w-5 text-green-500" />;
    statusColor = "text-green-500";
  } else if (percentage >= 50) {
    statusIcon = <AlertCircle className="h-5 w-5 text-yellow-500" />;
    statusColor = "text-yellow-500";
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
              Phase {phaseNumber}: {phase.label_ja}
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
          <Label>(a) SBOM作成主体 (Who)</Label>
          <Select
            value={settings.sbom_author_scope}
            onValueChange={(v) =>
              setSettings({ ...settings, sbom_author_scope: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="選択してください" />
            </SelectTrigger>
            <SelectContent>
              {framework.options.sbom_author_scope.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label_ja}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (b) 依存関係 */}
        <div className="space-y-2">
          <Label>(b) 依存関係 (What, Where)</Label>
          <Select
            value={settings.dependency_scope}
            onValueChange={(v) =>
              setSettings({ ...settings, dependency_scope: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="選択してください" />
            </SelectTrigger>
            <SelectContent>
              {framework.options.dependency_scope.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label_ja}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (c) 生成手段 */}
        <div className="space-y-2">
          <Label>(c) 生成手段 (How)</Label>
          <Select
            value={settings.generation_method}
            onValueChange={(v) =>
              setSettings({ ...settings, generation_method: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="選択してください" />
            </SelectTrigger>
            <SelectContent>
              {framework.options.generation_method.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label_ja}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (d) データ様式 */}
        <div className="space-y-2">
          <Label>(d) データ様式 (What)</Label>
          <Select
            value={settings.data_format}
            onValueChange={(v) => setSettings({ ...settings, data_format: v })}
          >
            <SelectTrigger>
              <SelectValue placeholder="選択してください" />
            </SelectTrigger>
            <SelectContent>
              {framework.options.data_format.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label_ja}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* (f) 活用主体 */}
        <div className="space-y-2">
          <Label>(f) 活用主体 (Who)</Label>
          <Select
            value={settings.utilization_actor}
            onValueChange={(v) =>
              setSettings({ ...settings, utilization_actor: v })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="選択してください" />
            </SelectTrigger>
            <SelectContent>
              {framework.options.utilization_actor.map((opt) => (
                <SelectItem key={opt.value} value={opt.value}>
                  {opt.label_ja}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* (e) 活用範囲 - Multiple selection */}
      <div className="space-y-2">
        <Label>(e) 活用範囲 (Why) - 複数選択可</Label>
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
                {opt.label_ja}
              </Label>
            </div>
          ))}
        </div>
      </div>

      <Button onClick={handleSave} disabled={saving}>
        {saving ? (
          <>
            <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            保存中...
          </>
        ) : (
          <>
            <Save className="h-4 w-4 mr-2" />
            設定を保存
          </>
        )}
      </Button>
    </div>
  );
}

export default function CompliancePage() {
  const params = useParams();
  const projectId = params.id as string;
  const [result, setResult] = useState<ComplianceResult | null>(null);
  const [checklist, setChecklist] = useState<ChecklistResult | null>(null);
  const [visualization, setVisualization] =
    useState<VisualizationFramework | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("overview");

  useEffect(() => {
    loadAllData();
  }, [projectId]);

  const loadAllData = async () => {
    try {
      setLoading(true);
      const [complianceData, checklistData, visualizationData] =
        await Promise.all([
          api.projects.getCompliance(projectId),
          api.projects.getChecklist(projectId).catch(() => null),
          api.projects.getVisualization(projectId).catch(() => null),
        ]);
      setResult(complianceData);
      setChecklist(checklistData);
      setVisualization(visualizationData);
    } catch (err) {
      setError("コンプライアンスチェックの読み込みに失敗しました");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const reloadChecklist = async () => {
    try {
      const data = await api.projects.getChecklist(projectId);
      setChecklist(data);
    } catch (err) {
      console.error("Failed to reload checklist:", err);
    }
  };

  const reloadVisualization = async () => {
    try {
      const data = await api.projects.getVisualization(projectId);
      setVisualization(data);
    } catch (err) {
      console.error("Failed to reload visualization:", err);
    }
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
              <span>{error || "データの読み込みに失敗しました"}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8 space-y-6">
      <div className="flex items-center gap-4">
        <Link href={`/ja/projects/${projectId}`}>
          <Button variant="ghost" size="icon">
            <ArrowLeft className="h-5 w-5" />
          </Button>
        </Link>
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Shield className="h-8 w-8" />
            コンプライアンス対応状況
          </h1>
          <p className="text-muted-foreground">
            経産省SBOMガイドライン自己評価
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            概要
          </TabsTrigger>
          <TabsTrigger value="checklist" className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4" />
            チェックリスト
          </TabsTrigger>
          <TabsTrigger value="visualization" className="flex items-center gap-2">
            <Settings2 className="h-4 w-4" />
            可視化フレームワーク
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Score Card */}
            <Card className="lg:col-span-1">
              <CardHeader>
                <CardTitle>総合スコア</CardTitle>
                <CardDescription>経産省ガイドライン対応度</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <ScoreCircle score={result.score} maxScore={result.max_score} />
                <p className="mt-4 text-center text-sm text-muted-foreground">
                  {result.score} / {result.max_score} ポイント
                </p>
              </CardContent>
            </Card>

            {/* Categories */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>チェック項目</CardTitle>
                <CardDescription>各カテゴリの対応状況</CardDescription>
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
                    <CardTitle>チェックリスト進捗</CardTitle>
                    <CardDescription>18項目の対応状況</CardDescription>
                  </CardHeader>
                  <CardContent className="flex flex-col items-center">
                    <ScoreCircle
                      score={checklist.score}
                      maxScore={checklist.max_score}
                    />
                    <p className="mt-4 text-center text-sm text-muted-foreground">
                      {checklist.score} / {checklist.max_score} 項目完了
                    </p>
                  </CardContent>
                </Card>

                <Card className="lg:col-span-3">
                  <CardHeader>
                    <CardTitle>経産省SBOMガイドライン チェックリスト</CardTitle>
                    <CardDescription>
                      3フェーズ・18項目の自己評価チェックリスト
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
                  <p>チェックリストを読み込めませんでした</p>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Visualization Tab */}
        <TabsContent value="visualization" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>SBOM可視化フレームワーク設定</CardTitle>
              <CardDescription>
                経産省ガイドラインに基づく5W1H観点での可視化設定
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
                  <p>可視化設定を読み込めませんでした</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Disclaimer */}
      <div className="text-xs text-muted-foreground bg-muted/50 p-3 rounded-md">
        <p>
          ※本機能は経済産業省「ソフトウェア管理に向けたSBOM導入に関する手引ver2.0」に基づく
          自己評価を支援するものであり、公式な準拠認定を行うものではありません。
        </p>
      </div>

      {/* Export Buttons */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            レポート出力
          </CardTitle>
        </CardHeader>
        <CardContent className="flex gap-4">
          <a
            href={api.projects.exportComplianceReport(projectId, "json")}
            download
            className="inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring border border-input bg-background hover:bg-accent hover:text-accent-foreground h-10 px-4 py-2"
          >
            <Download className="h-4 w-4 mr-2" />
            JSON
          </a>
          <Button variant="outline" disabled>
            <Download className="h-4 w-4 mr-2" />
            PDF (準備中)
          </Button>
          <Button variant="outline" disabled>
            <Download className="h-4 w-4 mr-2" />
            Excel (準備中)
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
