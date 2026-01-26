"use client";

import { useState } from "react";
import Link from "next/link";
import { api, CVESearchResult, ComponentSearchResult } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Search, AlertCircle, CheckCircle, XCircle, Loader2 } from "lucide-react";

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    CRITICAL: "bg-red-500 hover:bg-red-600",
    HIGH: "bg-orange-500 hover:bg-orange-600",
    MEDIUM: "bg-yellow-500 hover:bg-yellow-600",
    LOW: "bg-green-500 hover:bg-green-600",
  };
  return (
    <Badge className={colors[severity] || "bg-gray-500"}>
      {severity}
    </Badge>
  );
}

function CVESearchResults({ result }: { result: CVESearchResult }) {
  return (
    <div className="space-y-6">
      {/* CVE Info */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span className="font-mono">{result.cve_id}</span>
            <SeverityBadge severity={result.severity} />
          </CardTitle>
          <CardDescription>
            CVSS: {result.cvss_score.toFixed(1)} | EPSS: {(result.epss_score * 100).toFixed(1)}%
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{result.description}</p>
        </CardContent>
      </Card>

      {/* Affected Projects */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <XCircle className="h-5 w-5 text-red-500" />
            影響を受けるプロジェクト ({result.affected_projects.length}件)
          </CardTitle>
        </CardHeader>
        <CardContent>
          {result.affected_projects.length === 0 ? (
            <p className="text-muted-foreground">影響を受けるプロジェクトはありません</p>
          ) : (
            <div className="space-y-4">
              {result.affected_projects.map((project) => (
                <div key={project.project_id} className="border rounded-lg p-4">
                  <Link
                    href={`/ja/projects/${project.project_id}`}
                    className="font-medium text-blue-500 hover:underline"
                  >
                    {project.project_name}
                  </Link>
                  <div className="mt-2 space-y-1">
                    {project.affected_components.map((comp) => (
                      <div key={comp.id} className="flex items-center gap-2 text-sm">
                        <span className="text-red-500">●</span>
                        <span className="font-mono">{comp.name}@{comp.version}</span>
                        {comp.fixed_version && (
                          <span className="text-muted-foreground">
                            → {comp.fixed_version}にアップデート推奨
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Unaffected Projects */}
      {result.unaffected_projects.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              影響なしのプロジェクト ({result.unaffected_projects.length}件)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {result.unaffected_projects.map((project) => (
                <Link
                  key={project.project_id}
                  href={`/ja/projects/${project.project_id}`}
                  className="text-sm text-muted-foreground hover:text-foreground"
                >
                  {project.project_name}
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function ComponentSearchResults({ result }: { result: ComponentSearchResult }) {
  return (
    <div className="space-y-4">
      <p className="text-muted-foreground">
        「{result.query.name}」
        {result.query.version_constraint && ` (${result.query.version_constraint})`}
        の検索結果: {result.matches.length}件
      </p>

      {result.matches.length === 0 ? (
        <Card>
          <CardContent className="pt-6">
            <p className="text-center text-muted-foreground">
              該当するコンポーネントが見つかりませんでした
            </p>
          </CardContent>
        </Card>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>プロジェクト</TableHead>
              <TableHead>コンポーネント</TableHead>
              <TableHead>バージョン</TableHead>
              <TableHead>ライセンス</TableHead>
              <TableHead>脆弱性</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {result.matches.map((match) => (
              <TableRow key={`${match.project_id}-${match.component.id}`}>
                <TableCell>
                  <Link
                    href={`/ja/projects/${match.project_id}`}
                    className="text-blue-500 hover:underline"
                  >
                    {match.project_name}
                  </Link>
                </TableCell>
                <TableCell className="font-mono">{match.component.name}</TableCell>
                <TableCell>{match.component.version}</TableCell>
                <TableCell>{match.component.license || "-"}</TableCell>
                <TableCell>
                  {match.vulnerabilities.length > 0 ? (
                    <div className="flex gap-1">
                      {match.vulnerabilities.slice(0, 3).map((v) => (
                        <SeverityBadge key={v.id} severity={v.severity} />
                      ))}
                      {match.vulnerabilities.length > 3 && (
                        <Badge variant="outline">+{match.vulnerabilities.length - 3}</Badge>
                      )}
                    </div>
                  ) : (
                    <span className="text-green-500">なし</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

export default function SearchPage() {
  const [activeTab, setActiveTab] = useState("cve");
  const [cveQuery, setCveQuery] = useState("");
  const [componentQuery, setComponentQuery] = useState("");
  const [versionQuery, setVersionQuery] = useState("");
  const [cveResult, setCveResult] = useState<CVESearchResult | null>(null);
  const [componentResult, setComponentResult] = useState<ComponentSearchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCVESearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!cveQuery.trim()) return;

    setLoading(true);
    setError(null);
    setCveResult(null);

    try {
      const result = await api.search.byCVE(cveQuery.trim());
      setCveResult(result);
    } catch (err) {
      setError("CVEが見つかりませんでした");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleComponentSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!componentQuery.trim()) return;

    setLoading(true);
    setError(null);
    setComponentResult(null);

    try {
      const result = await api.search.byComponent(
        componentQuery.trim(),
        versionQuery.trim() || undefined
      );
      setComponentResult(result);
    } catch (err) {
      setError("検索に失敗しました");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto py-8 space-y-6">
      <h1 className="text-3xl font-bold flex items-center gap-2">
        <Search className="h-8 w-8" />
        横断検索
      </h1>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="cve">CVE検索</TabsTrigger>
          <TabsTrigger value="component">コンポーネント検索</TabsTrigger>
        </TabsList>

        <TabsContent value="cve" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>CVE横断検索</CardTitle>
              <CardDescription>
                特定のCVE IDで全プロジェクトを検索し、影響範囲を特定します
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleCVESearch} className="flex gap-2">
                <Input
                  placeholder="CVE-2021-44228"
                  value={cveQuery}
                  onChange={(e) => setCveQuery(e.target.value)}
                  className="font-mono"
                />
                <Button type="submit" disabled={loading}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "検索"}
                </Button>
              </form>
            </CardContent>
          </Card>

          {error && (
            <Card className="border-red-200">
              <CardContent className="pt-6">
                <div className="flex items-center gap-2 text-red-500">
                  <AlertCircle className="h-5 w-5" />
                  <span>{error}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {cveResult && <CVESearchResults result={cveResult} />}
        </TabsContent>

        <TabsContent value="component" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>コンポーネント検索</CardTitle>
              <CardDescription>
                コンポーネント名とバージョンで全プロジェクトを検索します
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleComponentSearch} className="flex gap-2">
                <Input
                  placeholder="コンポーネント名 (例: lodash)"
                  value={componentQuery}
                  onChange={(e) => setComponentQuery(e.target.value)}
                />
                <Input
                  placeholder="バージョン制約 (例: <4.17.21)"
                  value={versionQuery}
                  onChange={(e) => setVersionQuery(e.target.value)}
                  className="w-48"
                />
                <Button type="submit" disabled={loading}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "検索"}
                </Button>
              </form>
            </CardContent>
          </Card>

          {error && (
            <Card className="border-red-200">
              <CardContent className="pt-6">
                <div className="flex items-center gap-2 text-red-500">
                  <AlertCircle className="h-5 w-5" />
                  <span>{error}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {componentResult && <ComponentSearchResults result={componentResult} />}
        </TabsContent>
      </Tabs>
    </div>
  );
}
