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
import { api, IssueTrackerConnection, TrackerType } from "@/lib/api";
import { Plus, Trash2, RefreshCw, ExternalLink, CheckCircle2 } from "lucide-react";

export default function IntegrationsPage() {
  const [connections, setConnections] = useState<IssueTrackerConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form state
  const [trackerType, setTrackerType] = useState<TrackerType>("jira");
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [email, setEmail] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [defaultProjectKey, setDefaultProjectKey] = useState("");
  const [defaultIssueType, setDefaultIssueType] = useState("");

  useEffect(() => {
    loadConnections();
  }, []);

  const loadConnections = async () => {
    try {
      const data = await api.integrations.list();
      setConnections(data.connections || []);
    } catch (error) {
      console.error("Failed to load connections:", error);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setTrackerType("jira");
    setName("");
    setBaseUrl("");
    setEmail("");
    setApiToken("");
    setDefaultProjectKey("");
    setDefaultIssueType("");
    setError(null);
  };

  const handleCreate = async () => {
    setError(null);
    setSaving(true);

    try {
      await api.integrations.create({
        tracker_type: trackerType,
        name,
        base_url: baseUrl,
        email: trackerType === "jira" ? email : undefined,
        api_token: apiToken,
        default_project_key: defaultProjectKey || undefined,
        default_issue_type: defaultIssueType || undefined,
      });

      await loadConnections();
      setIsDialogOpen(false);
      resetForm();
    } catch (err) {
      setError(err instanceof Error ? err.message : "接続の作成に失敗しました");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.integrations.delete(id);
      await loadConnections();
    } catch (error) {
      console.error("Failed to delete connection:", error);
    }
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
          <h1 className="text-2xl font-bold tracking-tight">外部連携設定</h1>
          <p className="text-muted-foreground">
            Jira, Backlog などの課題管理システムとの連携を設定します
          </p>
        </div>

        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open);
          if (!open) resetForm();
        }}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="h-4 w-4 mr-2" />
              連携を追加
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>新しい連携を追加</DialogTitle>
              <DialogDescription>
                課題管理システムへの接続情報を入力してください
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="tracker_type">サービス</Label>
                <Select value={trackerType} onValueChange={(v) => setTrackerType(v as TrackerType)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="jira">Jira</SelectItem>
                    <SelectItem value="backlog">Backlog</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="name">接続名</Label>
                <Input
                  id="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="例: 本番環境 Jira"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="base_url">ベースURL</Label>
                <Input
                  id="base_url"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={trackerType === "jira" ? "https://your-domain.atlassian.net" : "https://your-space.backlog.com"}
                />
              </div>

              {trackerType === "jira" && (
                <div className="space-y-2">
                  <Label htmlFor="email">メールアドレス</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="your-email@example.com"
                  />
                </div>
              )}

              <div className="space-y-2">
                <Label htmlFor="api_token">APIトークン</Label>
                <Input
                  id="api_token"
                  type="password"
                  value={apiToken}
                  onChange={(e) => setApiToken(e.target.value)}
                  placeholder="APIトークンを入力"
                />
                <p className="text-xs text-muted-foreground">
                  {trackerType === "jira" ? (
                    <a
                      href="https://id.atlassian.com/manage-profile/security/api-tokens"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      Atlassian API トークンを取得 →
                    </a>
                  ) : (
                    <a
                      href="https://support-ja.backlog.com/hc/ja/articles/360035641754"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary hover:underline"
                    >
                      Backlog API キーを取得 →
                    </a>
                  )}
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="default_project">デフォルトプロジェクト（オプション）</Label>
                <Input
                  id="default_project"
                  value={defaultProjectKey}
                  onChange={(e) => setDefaultProjectKey(e.target.value)}
                  placeholder="プロジェクトキー (例: PROJ)"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="default_issue_type">デフォルト課題タイプ（オプション）</Label>
                <Input
                  id="default_issue_type"
                  value={defaultIssueType}
                  onChange={(e) => setDefaultIssueType(e.target.value)}
                  placeholder="例: Bug, Task"
                />
              </div>

              {error && (
                <div className="text-sm text-destructive bg-destructive/10 p-3 rounded-md">
                  {error}
                </div>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setIsDialogOpen(false)}>
                キャンセル
              </Button>
              <Button onClick={handleCreate} disabled={saving || !name || !baseUrl || !apiToken}>
                {saving ? "接続テスト中..." : "接続を追加"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {connections.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <div className="text-center space-y-3">
              <h3 className="text-lg font-medium">連携がありません</h3>
              <p className="text-muted-foreground text-sm max-w-sm">
                Jira や Backlog と連携することで、脆弱性から直接チケットを作成できます
              </p>
              <Button onClick={() => setIsDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                最初の連携を追加
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4">
          {connections.map((conn) => (
            <Card key={conn.id}>
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-muted">
                      {conn.tracker_type === "jira" ? (
                        <svg className="h-6 w-6" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.005 1.005 0 0 0 23.013 0z"/>
                        </svg>
                      ) : (
                        <svg className="h-6 w-6" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm0 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10zm-1-15H9v6h2V7zm4 0h-2v6h2V7zm-2 8H9v2h4v-2z"/>
                        </svg>
                      )}
                    </div>
                    <div>
                      <CardTitle className="text-base flex items-center gap-2">
                        {conn.name}
                        {conn.is_active && (
                          <Badge variant="outline" className="text-green-600 border-green-600">
                            <CheckCircle2 className="h-3 w-3 mr-1" />
                            接続済み
                          </Badge>
                        )}
                      </CardTitle>
                      <CardDescription className="flex items-center gap-2">
                        <Badge variant="secondary">
                          {conn.tracker_type === "jira" ? "Jira" : "Backlog"}
                        </Badge>
                        <a
                          href={conn.base_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs hover:underline flex items-center gap-1"
                        >
                          {conn.base_url}
                          <ExternalLink className="h-3 w-3" />
                        </a>
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
                        <AlertDialogTitle>連携を削除しますか？</AlertDialogTitle>
                        <AlertDialogDescription>
                          この操作は取り消せません。この連携を使用して作成されたチケットは影響を受けませんが、新しいチケットを作成できなくなります。
                        </AlertDialogDescription>
                      </AlertDialogHeader>
                      <AlertDialogFooter>
                        <AlertDialogCancel>キャンセル</AlertDialogCancel>
                        <AlertDialogAction
                          onClick={() => handleDelete(conn.id)}
                          className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                        >
                          削除
                        </AlertDialogAction>
                      </AlertDialogFooter>
                    </AlertDialogContent>
                  </AlertDialog>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  {conn.default_project_key && (
                    <div>
                      <span className="text-muted-foreground">デフォルトプロジェクト:</span>
                      <span className="ml-2 font-medium">{conn.default_project_key}</span>
                    </div>
                  )}
                  {conn.default_issue_type && (
                    <div>
                      <span className="text-muted-foreground">デフォルト課題タイプ:</span>
                      <span className="ml-2 font-medium">{conn.default_issue_type}</span>
                    </div>
                  )}
                  {conn.last_sync_at && (
                    <div>
                      <span className="text-muted-foreground">最終同期:</span>
                      <span className="ml-2 font-medium">
                        {new Date(conn.last_sync_at).toLocaleString("ja-JP")}
                      </span>
                    </div>
                  )}
                  <div>
                    <span className="text-muted-foreground">作成日:</span>
                    <span className="ml-2 font-medium">
                      {new Date(conn.created_at).toLocaleDateString("ja-JP")}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* 使い方説明 */}
      <Card>
        <CardHeader>
          <CardTitle>使い方</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <h4 className="font-medium">1. 連携を設定</h4>
            <p className="text-sm text-muted-foreground">
              上のフォームから Jira または Backlog への接続を設定します。APIトークンが必要です。
            </p>
          </div>
          <div className="space-y-2">
            <h4 className="font-medium">2. 脆弱性からチケットを作成</h4>
            <p className="text-sm text-muted-foreground">
              脆弱性一覧や詳細ページから「チケットを作成」ボタンをクリックして、課題を作成できます。
            </p>
          </div>
          <div className="space-y-2">
            <h4 className="font-medium">3. ステータスを同期</h4>
            <p className="text-sm text-muted-foreground">
              作成されたチケットのステータスは自動的に同期されます。課題が解決されると、脆弱性のステータスも更新されます。
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
