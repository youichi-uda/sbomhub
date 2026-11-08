"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { api, PublicSbomView } from "@/lib/api";
import { queryKeys } from "@/lib/query/keys";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FormatBadge } from "@/components/sbom/format-badge";

export default function PublicSbomPage() {
  const params = useParams();
  const token = params.token as string;
  const [password, setPassword] = useState("");
  // Each "Access" click is a new attempt. The password travels in this
  // state (read by the queryFn) rather than in the query key, so it never
  // ends up in the cache key.
  const [attempt, setAttempt] = useState<{ n: number; password?: string }>({ n: 0 });

  const viewQuery = useQuery({
    queryKey: queryKeys.publicView(token, attempt.n),
    queryFn: (): Promise<PublicSbomView> => api.publicLinks.publicView(token, attempt.password),
  });
  const view = viewQuery.data ?? null;
  const loading = viewQuery.isFetching;
  const error = viewQuery.isError ? "Access denied. Password may be required." : null;
  const load = (pwd: string) => setAttempt((prev) => ({ n: prev.n + 1, password: pwd }));

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  if (error && !view) {
    return (
      <div className="max-w-md mx-auto mt-12">
        <Card>
          <CardHeader>
            <CardTitle>Public SBOM Access</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">{error}</p>
            <input
              type="password"
              className="w-full border rounded px-3 py-2"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
            />
            <Button onClick={() => load(password)} disabled={!password}>
              Access
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!view) {
    return <div className="flex items-center justify-center h-64">SBOM not found</div>;
  }

  return (
    <div className="max-w-5xl mx-auto py-10">
      <div className="mb-6">
        <h1 className="text-3xl font-bold">SBOMHub</h1>
        <p className="text-muted-foreground">Project: {view.project_name}</p>
        <p className="text-muted-foreground">
          SBOM Date: {new Date(view.sbom.created_at).toLocaleDateString()}
        </p>
        <p className="text-muted-foreground flex items-center gap-2">
          Format: <FormatBadge format={view.sbom.format} version={view.sbom.version} />
        </p>
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>Components ({view.components.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-2 px-3">Name</th>
                  <th className="text-left py-2 px-3">Version</th>
                  <th className="text-left py-2 px-3">License</th>
                </tr>
              </thead>
              <tbody>
                {view.components.map((c) => (
                  <tr key={c.id} className="border-b">
                    <td className="py-2 px-3 font-medium">{c.name}</td>
                    <td className="py-2 px-3">{c.version || "-"}</td>
                    <td className="py-2 px-3">{c.license || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      <div className="mb-6">
        <a href={`/api/v1/public/${token}/download?format=cyclonedx`}>
          <Button variant="outline">Download SBOM</Button>
        </a>
      </div>

      <div className="text-xs text-muted-foreground">
        This link expires on {new Date(view.link.expires_at).toLocaleDateString()}.
      </div>
    </div>
  );
}
