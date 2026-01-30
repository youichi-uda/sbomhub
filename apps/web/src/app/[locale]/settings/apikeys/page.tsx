"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { api, APIKey, APIKeyWithSecret } from "@/lib/api";
import { Plus, Trash2, RefreshCw, Copy, Check, Key, Terminal, Server } from "lucide-react";
import { useTranslations } from "next-intl";

export default function APIKeysPage() {
  const t = useTranslations("Settings.APIKeys");
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<APIKeyWithSecret | null>(null);
  const [copied, setCopied] = useState(false);

  // Form state
  const [name, setName] = useState("");
  const [permissions, setPermissions] = useState("write");
  const [expiresInDays, setExpiresInDays] = useState<string>("");

  useEffect(() => {
    loadKeys();
  }, []);

  const loadKeys = async () => {
    try {
      const data = await api.apiKeys.list();
      setKeys(data || []);
    } catch (error) {
      console.error("Failed to load API keys:", error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setName("");
    setPermissions("write");
    setExpiresInDays("");
    setError(null);
    setNewKey(null);
    setCopied(false);
  };

  const handleCreate = async () => {
    setError(null);
    setSaving(true);

    try {
      const result = await api.apiKeys.create({
        name,
        permissions,
        expires_in_days: expiresInDays ? parseInt(expiresInDays, 10) : undefined,
      });

      setNewKey(result);
      await loadKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("createError"));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.apiKeys.delete(id);
      await loadKeys();
    } catch (error) {
      console.error("Failed to delete API key:", error);
    }
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error("Failed to copy:", error);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return "-";
    return new Date(dateString).toLocaleDateString("ja-JP");
  };

  const isExpired = (expiresAt?: string) => {
    if (!expiresAt) return false;
    return new Date(expiresAt) < new Date();
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground">
            {t("description")}
          </p>
        </div>

        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open);
          if (!open) resetForm();
        }}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              {t("createButton")}
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            {newKey ? (
              <>
                <DialogHeader>
                  <DialogTitle>{t("keyCreated")}</DialogTitle>
                  <DialogDescription>
                    {t("keyCreatedDescription")}
                  </DialogDescription>
                </DialogHeader>
                <div className="py-4 space-y-4">
                  <div className="p-4 bg-muted rounded-lg font-mono text-sm break-all">
                    {newKey.key}
                  </div>
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={() => handleCopy(newKey.key)}
                  >
                    {copied ? (
                      <>
                        <Check className="h-4 w-4 mr-2" />
                        {t("copied")}
                      </>
                    ) : (
                      <>
                        <Copy className="h-4 w-4 mr-2" />
                        {t("copyKey")}
                      </>
                    )}
                  </Button>
                  <div className="p-3 bg-amber-50 border border-amber-200 rounded-md text-sm text-amber-800">
                    {t("keyWarning")}
                  </div>
                </div>
                <DialogFooter>
                  <Button onClick={() => {
                    setIsDialogOpen(false);
                    resetForm();
                  }}>
                    {t("close")}
                  </Button>
                </DialogFooter>
              </>
            ) : (
              <>
                <DialogHeader>
                  <DialogTitle>{t("createTitle")}</DialogTitle>
                  <DialogDescription>
                    {t("createDescription")}
                  </DialogDescription>
                </DialogHeader>

                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">{t("nameLabel")}</Label>
                    <Input
                      id="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder={t("namePlaceholder")}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="permissions">{t("permissionsLabel")}</Label>
                    <Select value={permissions} onValueChange={setPermissions}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="read">{t("permissionRead")}</SelectItem>
                        <SelectItem value="write">{t("permissionWrite")}</SelectItem>
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      {t("permissionsHelp")}
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="expires">{t("expiresLabel")}</Label>
                    <Select value={expiresInDays} onValueChange={setExpiresInDays}>
                      <SelectTrigger>
                        <SelectValue placeholder={t("noExpiration")} />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="">{t("noExpiration")}</SelectItem>
                        <SelectItem value="30">{t("expires30Days")}</SelectItem>
                        <SelectItem value="90">{t("expires90Days")}</SelectItem>
                        <SelectItem value="365">{t("expires1Year")}</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  {error && (
                    <div className="text-sm text-destructive bg-destructive/10 p-3 rounded-md">
                      {error}
                    </div>
                  )}
                </div>

                <DialogFooter>
                  <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
                    {t("cancel")}
                  </Button>
                  <Button onClick={handleCreate} disabled={saving || !name}>
                    {saving ? t("creating") : t("create")}
                  </Button>
                </DialogFooter>
              </>
            )}
          </DialogContent>
        </Dialog>
      </div>

      {keys.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Key className="h-12 w-12 text-muted-foreground mb-4" />
            <div className="text-center space-y-3">
              <h3 className="text-lg font-medium">{t("noKeys")}</h3>
              <p className="text-muted-foreground text-sm max-w-sm">
                {t("noKeysDescription")}
              </p>
              <Button onClick={() => setIsDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                {t("createFirstKey")}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {keys.map((key) => (
            <Card key={key.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-muted">
                      <Key className="h-5 w-5" />
                    </div>
                    <div>
                      <CardTitle className="text-base flex items-center gap-2">
                        {key.name}
                        {isExpired(key.expires_at) && (
                          <Badge variant="destructive">{t("expired")}</Badge>
                        )}
                      </CardTitle>
                      <CardDescription className="flex items-center gap-2 mt-1">
                        <code className="text-xs bg-muted px-2 py-0.5 rounded">
                          {key.key_prefix}...
                        </code>
                        <Badge variant="secondary">
                          {key.permissions === "read" ? t("permissionRead") : t("permissionWrite")}
                        </Badge>
                      </CardDescription>
                    </div>
                  </div>

                  <AlertDialog>
                    <AlertDialogTrigger asChild>
                      <Button variant="ghost" size="icon">
                        <Trash2 className="h-4 w-4 text-muted-foreground hover:text-destructive" />
                      </Button>
                    </AlertDialogTrigger>
                    <AlertDialogContent>
                      <AlertDialogHeader>
                        <AlertDialogTitle>{t("deleteTitle")}</AlertDialogTitle>
                        <AlertDialogDescription>
                          {t("deleteDescription")}
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => handleDelete(key.id)}
                          className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        >
                          {t("delete")}
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">{t("created")}:</span>
                    <span className="ml-2 font-medium">{formatDate(key.created_at)}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t("expires")}:</span>
                    <span className="ml-2 font-medium">
                      {key.expires_at ? formatDate(key.expires_at) : t("never")}
                    </span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">{t("lastUsed")}:</span>
                    <span className="ml-2 font-medium">
                      {key.last_used_at ? formatDate(key.last_used_at) : t("never")}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Usage Guide */}
      <Card>
        <CardHeader>
          <CardTitle>{t("usageTitle")}</CardTitle>
          <CardDescription>{t("usageDescription")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              <h4 className="font-medium">{t("usageCLI")}</h4>
            </div>
            <div className="bg-muted p-3 rounded-md font-mono text-sm">
              sbomhub-cli upload --api-key &lt;YOUR_API_KEY&gt; --project &lt;PROJECT_ID&gt;
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              <h4 className="font-medium">{t("usageMCP")}</h4>
            </div>
            <div className="bg-muted p-3 rounded-md font-mono text-sm overflow-x-auto">
              <pre>{`{
  "mcpServers": {
    "sbomhub": {
      "command": "npx",
      "args": ["@sbomhub/mcp-server"],
      "env": {
        "SBOMHUB_API_KEY": "<YOUR_API_KEY>"
      }
    }
  }
}`}</pre>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <svg className="h-5 w-5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.446 1.394c-.14.18-.357.295-.6.295-.002 0-.003 0-.005 0l.213-3.054 5.56-5.022c.24-.213-.054-.334-.373-.121l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.538-.196 1.006.128.832.942z"/>
              </svg>
              <h4 className="font-medium">{t("usageCI")}</h4>
            </div>
            <div className="bg-muted p-3 rounded-md font-mono text-sm overflow-x-auto">
              <pre>{`# GitHub Actions
- name: Upload SBOM
  run: |
    curl -X POST \\
      -H "X-API-Key: \${{ secrets.SBOMHUB_API_KEY }}" \\
      -H "Content-Type: application/json" \\
      -d @sbom.json \\
      https://api.sbomhub.app/api/v1/cli/upload`}</pre>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
