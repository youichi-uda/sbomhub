"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, DashboardSummary, TopRisk, ProjectScore, TrendPoint } from "@/lib/api";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { AlertCircle, Shield, Package, FolderOpen, TrendingUp } from "lucide-react";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500 hover:bg-red-600",
    critical: "bg-red-500 hover:bg-red-600",
    HIGH: "bg-orange-500 hover:bg-orange-600",
    high: "bg-orange-500 hover:bg-orange-600",
    MEDIUM: "bg-yellow-500 hover:bg-yellow-600",
    medium: "bg-yellow-500 hover:bg-yellow-600",
    LOW: "bg-green-500 hover:bg-green-600",
    low: "bg-green-500 hover:bg-green-600",
    none: "bg-gray-500 hover:bg-gray-600",
  };
  return (
    <Badge className={colors[severity] || "bg-gray-500"}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function VulnerabilityCard({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardDescription>{label}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className={`text-3xl font-bold ${color}`}>{count}</div>
      </CardContent>
    </Card>
  );
}

function TopRisksTable({ risks }: { risks: TopRisk[] }) {
  if (risks.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        脆弱性は検出されていません
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>#</TableHead>
          <TableHead>CVE ID</TableHead>
          <TableHead>EPSS</TableHead>
          <TableHead>CVSS</TableHead>
          <TableHead>プロジェクト</TableHead>
          <TableHead>コンポーネント</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {risks.map((risk, index) => (
          <TableRow key={risk.cve_id + risk.project_id}>
            <TableCell>{index + 1}</TableCell>
            <TableCell className="font-mono">{risk.cve_id}</TableCell>
            <TableCell>
              <span className={risk.epss_score > 0.5 ? "text-red-500 font-bold" : ""}>
                {(risk.epss_score * 100).toFixed(1)}%
              </span>
            </TableCell>
            <TableCell>
              <SeverityBadge severity={risk.severity} />
              <span className="ml-2">{risk.cvss_score.toFixed(1)}</span>
            </TableCell>
            <TableCell>
              <Link href={`/ja/projects/${risk.project_id}`} className="text-blue-500 hover:underline">
                {risk.project_name}
              </Link>
            </TableCell>
            <TableCell>
              {risk.component_name}@{risk.component_version}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

function ProjectScoresList({ scores }: { scores: ProjectScore[] }) {
  if (scores.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        プロジェクトがありません
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scores.map((score) => (
        <div key={score.project_id} className="space-y-2">
          <div className="flex justify-between items-center">
            <Link href={`/ja/projects/${score.project_id}`} className="font-medium hover:underline">
              {score.project_name}
            </Link>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">{score.risk_score}/100</span>
              <SeverityBadge severity={score.severity} />
            </div>
          </div>
          <Progress value={score.risk_score} className="h-2" />
          <div className="flex gap-4 text-xs text-muted-foreground">
            <span className="text-red-500">Critical: {score.critical}</span>
            <span className="text-orange-500">High: {score.high}</span>
            <span className="text-yellow-600">Medium: {score.medium}</span>
            <span className="text-green-500">Low: {score.low}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function TrendChart({ trend }: { trend: TrendPoint[] }) {
  if (trend.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        トレンドデータがありません
      </div>
    );
  }

  const maxValue = Math.max(
    ...trend.map((t) => t.critical + t.high + t.medium + t.low)
  );

  return (
    <div className="flex items-end gap-1 h-40">
      {trend.map((point, index) => {
        const total = point.critical + point.high + point.medium + point.low;
        const height = maxValue > 0 ? (total / maxValue) * 100 : 0;
        return (
          <div
            key={index}
            className="flex-1 flex flex-col justify-end"
            title={`${new Date(point.date).toLocaleDateString("ja-JP")}: ${total}件`}
          >
            <div
              className="bg-gradient-to-t from-red-500 via-orange-400 to-yellow-300 rounded-t"
              style={{ height: `${height}%`, minHeight: total > 0 ? "4px" : "0" }}
            />
          </div>
        );
      })}
    </div>
  );
}

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      setLoading(true);
      const data = await api.dashboard.getSummary();
      setSummary(data);
    } catch (err) {
      setError("ダッシュボードの読み込みに失敗しました");
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
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 bg-muted rounded" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error || !summary) {
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
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">ダッシュボード</h1>
        <div className="flex gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <FolderOpen className="h-4 w-4" />
            <span>{summary.total_projects} プロジェクト</span>
          </div>
          <div className="flex items-center gap-1">
            <Package className="h-4 w-4" />
            <span>{summary.total_components} コンポーネント</span>
          </div>
        </div>
      </div>

      {/* Vulnerability Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <VulnerabilityCard
          label="Critical"
          count={summary.vulnerabilities.critical}
          color="text-red-500"
        />
        <VulnerabilityCard
          label="High"
          count={summary.vulnerabilities.high}
          color="text-orange-500"
        />
        <VulnerabilityCard
          label="Medium"
          count={summary.vulnerabilities.medium}
          color="text-yellow-600"
        />
        <VulnerabilityCard
          label="Low"
          count={summary.vulnerabilities.low}
          color="text-green-500"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Risks Table */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-500" />
              要対応 TOP10 - EPSS順
            </CardTitle>
            <CardDescription>
              悪用される可能性が高い脆弱性
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TopRisksTable risks={summary.top_risks} />
          </CardContent>
        </Card>

        {/* Project Scores */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              プロジェクト別リスクスコア
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ProjectScoresList scores={summary.project_scores} />
          </CardContent>
        </Card>

        {/* Trend Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              脆弱性トレンド（過去30日）
            </CardTitle>
          </CardHeader>
          <CardContent>
            <TrendChart trend={summary.trend} />
            <div className="flex justify-between text-xs text-muted-foreground mt-2">
              <span>30日前</span>
              <span>今日</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
