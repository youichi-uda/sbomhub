"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, PublicSbomView } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function PublicSbomPage() {
  const params = useParams();
  const token = params.token as string;
  const [view, setView] = useState<PublicSbomView | null>(null);
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = async (pwd?: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.publicLinks.publicView(token, pwd);
      setView(data);
    } catch (err: any) {
      setError("Access denied. Password may be required.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [token]);

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
        <p className="text-muted-foreground">Format: {view.sbom.format}</p>
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
