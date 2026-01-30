"use client";

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { useLocale } from "next-intl";
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

function TopRisksTable({ risks, noDataMessage, locale }: { risks: TopRisk[]; noDataMessage: string; locale: string }) {
  const t = useTranslations("Navigation");
  if (risks.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        {noDataMessage}
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
          <TableHead>{t("projects")}</TableHead>
          <TableHead>{t("components")}</TableHead>
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
              <Link href={`/${locale}/projects/${risk.project_id}`} className="text-blue-500 hover:underline">
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

function ProjectScoresList({ scores, noDataMessage, locale }: { scores: ProjectScore[]; noDataMessage: string; locale: string }) {
  const tv = useTranslations("Vulnerabilities");
  if (scores.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        {noDataMessage}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scores.map((score) => (
        <div key={score.project_id} className="space-y-2">
          <div className="flex justify-between items-center">
            <Link href={`/${locale}/projects/${score.project_id}`} className="font-medium hover:underline">
              {score.project_name}
            </Link>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">{score.risk_score}/100</span>
              <SeverityBadge severity={score.severity} />
            </div>
          </div>
          <Progress value={score.risk_score} className="h-2" />
          <div className="flex gap-4 text-xs text-muted-foreground">
            <span className="text-red-500">{tv("critical")}: {score.critical}</span>
            <span className="text-orange-500">{tv("high")}: {score.high}</span>
            <span className="text-yellow-600">{tv("medium")}: {score.medium}</span>
            <span className="text-green-500">{tv("low")}: {score.low}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function TrendChart({ trend, noDataMessage }: { trend: TrendPoint[]; noDataMessage?: string }) {
  if (trend.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        {noDataMessage || "No trend data"}
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
  const t = useTranslations("Dashboard");
  const tc = useTranslations("Common");
  const locale = useLocale();
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
      setError(tc("error"));
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
              <span>{error || tc("error")}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">{t("title")}</h1>
        <div className="flex gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <FolderOpen className="h-4 w-4" />
            <span>{summary.total_projects} {t("projects")}</span>
          </div>
          <div className="flex items-center gap-1">
            <Package className="h-4 w-4" />
            <span>{summary.total_components} {t("components")}</span>
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
              {t("topEpss")}
            </CardTitle>
            <CardDescription>
              {t("topEpssDescription")}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TopRisksTable risks={summary.top_risks} noDataMessage={t("noVulnerabilities")} locale={locale} />
          </CardContent>
        </Card>

        {/* Project Scores */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              {t("projectRiskScore")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ProjectScoresList scores={summary.project_scores} noDataMessage={t("noProjects")} locale={locale} />
          </CardContent>
        </Card>

        {/* Trend Chart */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-5 w-5" />
              {t("vulnerabilityTrend")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <TrendChart trend={summary.trend} noDataMessage={t("noTrendData")} />
            <div className="flex justify-between text-xs text-muted-foreground mt-2">
              <span>30 {t("daysAgo")}</span>
              <span>{t("today")}</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
