"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { api, ComplianceResult, ComplianceCategory, ComplianceCheck } from "@/lib/api";
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
import {
  CheckCircle,
  XCircle,
  AlertCircle,
  ArrowLeft,
  FileText,
  Download,
  Shield,
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

export default function CompliancePage() {
  const params = useParams();
  const projectId = params.id as string;
  const [result, setResult] = useState<ComplianceResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadCompliance();
  }, [projectId]);

  const loadCompliance = async () => {
    try {
      setLoading(true);
      const data = await api.projects.getCompliance(projectId);
      setResult(data);
    } catch (err) {
      setError("コンプライアンスチェックの読み込みに失敗しました");
      console.error(err);
    } finally {
      setLoading(false);
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
            コンプライアンススコア
          </h1>
          <p className="text-muted-foreground">
            経産省SBOMガイドライン準拠度
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Score Card */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>総合スコア</CardTitle>
            <CardDescription>
              経産省ガイドライン準拠度
            </CardDescription>
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
            <CardDescription>
              各カテゴリの準拠状況
            </CardDescription>
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
