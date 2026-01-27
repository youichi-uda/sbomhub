"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { api, PublicLink, Sbom } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Copy, Check, Plus, Trash } from "lucide-react";

const BASE_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

export default function ProjectSharePage() {
  const params = useParams();
  const projectId = params.id as string;
  const locale = params.locale as string | undefined;
  const publicBaseUrl = locale ? `${BASE_URL}/${locale}/public` : `${BASE_URL}/public`;

  const [links, setLinks] = useState<PublicLink[]>([]);
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  const [name, setName] = useState("");
  const [sbomId, setSbomId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [allowedDownloads, setAllowedDownloads] = useState<number | undefined>(undefined);
  const [password, setPassword] = useState("");
  const [isActive, setIsActive] = useState(true);

  const load = async () => {
    setLoading(true);
    try {
      const [linkList, sbomList] = await Promise.all([
        api.publicLinks.list(projectId),
        api.projects.getSboms(projectId),
      ]);
      setLinks(linkList || []);
      setSboms(sbomList || []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [projectId]);

  const handleCreate = async () => {
    if (!name || !expiresAt) return;
    setCreating(true);
    try {
      await api.publicLinks.create(projectId, {
        name,
        sbom_id: sbomId || undefined,
        expires_at: new Date(expiresAt).toISOString(),
        is_active: isActive,
        allowed_downloads: allowedDownloads,
        password: password || undefined,
      });
      setName("");
      setSbomId("");
      setExpiresAt("");
      setAllowedDownloads(undefined);
      setPassword("");
      setIsActive(true);
      await load();
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this public link?")) return;
    await api.publicLinks.delete(id);
    await load();
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Create Public Link</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Name</label>
            <input
              className="w-full border rounded px-3 py-2"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Customer A"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">SBOM (optional)</label>
            <select
              className="w-full border rounded px-3 py-2"
              value={sbomId}
              onChange={(e) => setSbomId(e.target.value)}
            >
              <option value="">Latest</option>
              {sboms.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.version || "unknown"} ({new Date(s.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Expires At</label>
              <input
                type="date"
                className="w-full border rounded px-3 py-2"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Allowed Downloads (optional)</label>
              <input
                type="number"
                className="w-full border rounded px-3 py-2"
                value={allowedDownloads ?? ""}
                onChange={(e) => setAllowedDownloads(e.target.value ? Number(e.target.value) : undefined)}
                min={1}
              />
            </div>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="block text-sm font-medium mb-1">Password (optional)</label>
              <input
                type="password"
                className="w-full border rounded px-3 py-2"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2 pt-6">
              <input
                id="is-active"
                type="checkbox"
                checked={isActive}
                onChange={(e) => setIsActive(e.target.checked)}
              />
              <label htmlFor="is-active" className="text-sm">Active</label>
            </div>
          </div>
          <Button onClick={handleCreate} disabled={!name || !expiresAt || creating}>
            <Plus className="h-4 w-4 mr-2" />
            {creating ? "Creating..." : "Create Link"}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Public Links</CardTitle>
        </CardHeader>
        <CardContent>
          {links.length === 0 ? (
            <p className="text-muted-foreground">No public links created yet.</p>
          ) : (
            <div className="space-y-3">
              {links.map((link) => (
                <div key={link.id} className="border rounded p-3 flex items-start justify-between gap-4">
                  <div>
                    <div className="font-medium">{link.name}</div>
                    <div className="text-sm text-muted-foreground">
                      Expires: {new Date(link.expires_at).toLocaleDateString()}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Views: {link.view_count} / Downloads: {link.download_count}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Status: {link.is_active ? "Active" : "Inactive"}
                    </div>
                    <div className="mt-2 flex items-center gap-2">
                      <code className="text-xs bg-muted px-2 py-1 rounded">
                        {publicBaseUrl}/{link.token}
                      </code>
                      <CopyButton text={`${publicBaseUrl}/${link.token}`} />
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {link.allowed_downloads ? (
                      <Badge variant="outline">Limit {link.allowed_downloads}</Badge>
                    ) : (
                      <Badge variant="secondary">Unlimited</Badge>
                    )}
                    <Button variant="ghost" size="sm" onClick={() => handleDelete(link.id)}>
                      <Trash className="h-4 w-4 text-red-500" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <Button variant="ghost" size="sm" onClick={handleCopy}>
      {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
    </Button>
  );
}
