"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { api, Sbom, SbomDiffResponse } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft } from "lucide-react";

export default function ProjectDiffPage() {
  const params = useParams();
  const projectId = params.id as string;

  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [baseSbomId, setBaseSbomId] = useState("");
  const [targetSbomId, setTargetSbomId] = useState("");
  const [diff, setDiff] = useState<SbomDiffResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const list = await api.projects.getSboms(projectId);
        setSboms(list || []);
        if (list.length >= 2) {
          setTargetSbomId(list[0].id);
          setBaseSbomId(list[1].id);
        }
      } catch (err) {
        setError("Failed to load SBOM history.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [projectId]);

  const handleDiff = async () => {
    if (!baseSbomId || !targetSbomId) return;
    setRunning(true);
    setError(null);
    try {
      const result = await api.sbom.diff({
        base_sbom_id: baseSbomId,
        target_sbom_id: targetSbomId,
      });
      setDiff(result);
    } catch (err) {
      setError("Failed to compute diff.");
    } finally {
      setRunning(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  return (
    <div>
      <div className="mb-6">
        <Link href={`/projects/${projectId}`} className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-2">
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Project
        </Link>
        <h1 className="text-3xl font-bold">SBOM Diff</h1>
        <p className="text-muted-foreground">Compare two SBOM versions.</p>
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Diff Selector</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {sboms.length < 2 ? (
            <p className="text-muted-foreground">At least two SBOMs are required to compare.</p>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label className="block text-sm font-medium mb-1">Base (older)</label>
                <select
                  className="w-full border rounded px-3 py-2"
                  value={baseSbomId}
                  onChange={(e) => setBaseSbomId(e.target.value)}
                >
                  <option value="">Select SBOM</option>
                  {sboms.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.version || "unknown"} ({new Date(s.created_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Target (newer)</label>
                <select
                  className="w-full border rounded px-3 py-2"
                  value={targetSbomId}
                  onChange={(e) => setTargetSbomId(e.target.value)}
                >
                  <option value="">Select SBOM</option>
                  {sboms.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.version || "unknown"} ({new Date(s.created_at).toLocaleDateString()})
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
          <div>
            <Button onClick={handleDiff} disabled={!baseSbomId || !targetSbomId || running}>
              {running ? "Comparing..." : "Compare"}
            </Button>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </CardContent>
      </Card>

      {diff && (
        <>
          <div className="grid gap-4 md:grid-cols-4 mb-6">
            <SummaryCard label="Added" value={diff.summary.added_count} />
            <SummaryCard label="Removed" value={diff.summary.removed_count} />
            <SummaryCard label="Updated" value={diff.summary.updated_count} />
            <SummaryCard label="New Vulns" value={diff.summary.new_vulnerabilities_count} />
          </div>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Added Components</CardTitle>
            </CardHeader>
            <CardContent>
              {diff.added.length === 0 ? (
                <p className="text-muted-foreground">No additions.</p>
              ) : (
                <ul className="space-y-2">
                  {diff.added.map((c) => (
                    <li key={`${c.name}:${c.version}`} className="flex items-center justify-between border rounded px-3 py-2">
                      <span className="font-medium">{c.name}@{c.version}</span>
                      {c.license && <Badge variant="outline">{c.license}</Badge>}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Removed Components</CardTitle>
            </CardHeader>
            <CardContent>
              {diff.removed.length === 0 ? (
                <p className="text-muted-foreground">No removals.</p>
              ) : (
                <ul className="space-y-2">
                  {diff.removed.map((c) => (
                    <li key={`${c.name}:${c.version}`} className="flex items-center justify-between border rounded px-3 py-2">
                      <span className="font-medium">{c.name}@{c.version}</span>
                      {c.license && <Badge variant="outline">{c.license}</Badge>}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="mb-6">
            <CardHeader>
              <CardTitle>Updated Components</CardTitle>
            </CardHeader>
            <CardContent>
              {diff.updated.length === 0 ? (
                <p className="text-muted-foreground">No updates.</p>
              ) : (
                <ul className="space-y-2">
                  {diff.updated.map((u) => (
                    <li key={`${u.name}:${u.old_version}:${u.new_version}`} className="flex items-center justify-between border rounded px-3 py-2">
                      <span className="font-medium">{u.name}</span>
                      <span className="text-sm text-muted-foreground">
                        {u.old_version} → {u.new_version}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>New Vulnerabilities</CardTitle>
            </CardHeader>
            <CardContent>
              {diff.new_vulnerabilities.length === 0 ? (
                <p className="text-muted-foreground">No new vulnerabilities.</p>
              ) : (
                <ul className="space-y-2">
                  {diff.new_vulnerabilities.map((v) => (
                    <li key={`${v.cve_id}:${v.component}:${v.version}`} className="flex items-center justify-between border rounded px-3 py-2">
                      <div>
                        <span className="font-mono font-bold">{v.cve_id}</span>
                        <span className="ml-2 text-sm text-muted-foreground">{v.component}@{v.version}</span>
                      </div>
                      <Badge variant="destructive">{v.severity}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: number }) {
  return (
    <Card>
      <CardContent className="py-4">
        <div className="text-sm text-muted-foreground">{label}</div>
        <div className="text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  );
}
