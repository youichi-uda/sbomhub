"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Shield,
  ExternalLink,
  CheckCircle2,
  Settings,
  Users,
  Key,
  Building2,
  Info,
} from "lucide-react";

const SSO_PROVIDERS = [
  {
    id: "azure-ad",
    name: "Microsoft Entra ID (Azure AD)",
    description: "Microsoft 365 や Azure との統合認証",
    logo: (
      <svg className="h-8 w-8" viewBox="0 0 23 23">
        <path fill="#f3f3f3" d="M0 0h23v23H0z"/>
        <path fill="#f35325" d="M1 1h10v10H1z"/>
        <path fill="#81bc06" d="M12 1h10v10H12z"/>
        <path fill="#05a6f0" d="M1 12h10v10H1z"/>
        <path fill="#ffba08" d="M12 12h10v10H12z"/>
      </svg>
    ),
  },
  {
    id: "okta",
    name: "Okta",
    description: "エンタープライズ向けアイデンティティ管理",
    logo: (
      <svg className="h-8 w-8" viewBox="0 0 200 200">
        <circle cx="100" cy="100" r="100" fill="#007dc1"/>
        <circle cx="100" cy="100" r="50" fill="#fff"/>
      </svg>
    ),
  },
  {
    id: "google",
    name: "Google Workspace",
    description: "Google アカウントによる認証",
    logo: (
      <svg className="h-8 w-8" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
    ),
  },
  {
    id: "saml",
    name: "SAML 2.0",
    description: "カスタム SAML プロバイダーとの連携",
    logo: (
      <div className="h-8 w-8 bg-gray-200 rounded flex items-center justify-center">
        <Key className="h-5 w-5 text-gray-600" />
      </div>
    ),
  },
];

export default function SSOSettingsPage() {
  const [isEnterprise] = useState(false); // This would be fetched from the subscription status

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">シングルサインオン (SSO)</h1>
        <p className="text-muted-foreground">
          企業のアイデンティティプロバイダーと連携して、セキュアな認証を実現
        </p>
      </div>

      {!isEnterprise && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Enterprise プランが必要です</AlertTitle>
          <AlertDescription>
            SSO 機能は Enterprise プランでご利用いただけます。
            プランのアップグレードについては、
            <a href="/settings/billing" className="text-primary hover:underline ml-1">
              料金プラン
            </a>
            をご確認ください。
          </AlertDescription>
        </Alert>
      )}

      {/* 現在の状態 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            認証設定
          </CardTitle>
          <CardDescription>
            現在の認証方式とSSO設定の状態
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 rounded-lg border">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-100 text-green-600">
                <CheckCircle2 className="h-5 w-5" />
              </div>
              <div>
                <h4 className="font-medium">標準認証</h4>
                <p className="text-sm text-muted-foreground">
                  メールアドレスとパスワードによる認証が有効
                </p>
              </div>
            </div>
            <Badge variant="secondary">有効</Badge>
          </div>

          <div className="flex items-center justify-between p-4 rounded-lg border">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-muted text-muted-foreground">
                <Building2 className="h-5 w-5" />
              </div>
              <div>
                <h4 className="font-medium">Enterprise SSO</h4>
                <p className="text-sm text-muted-foreground">
                  組織のアイデンティティプロバイダーと連携
                </p>
              </div>
            </div>
            <Badge variant="outline">未設定</Badge>
          </div>
        </CardContent>
      </Card>

      {/* 対応プロバイダー */}
      <Card>
        <CardHeader>
          <CardTitle>対応アイデンティティプロバイダー</CardTitle>
          <CardDescription>
            以下のプロバイダーと SSO 連携が可能です
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2">
            {SSO_PROVIDERS.map((provider) => (
              <div
                key={provider.id}
                className="flex items-center gap-4 p-4 rounded-lg border"
              >
                <div className="flex-shrink-0">{provider.logo}</div>
                <div className="flex-1 min-w-0">
                  <h4 className="font-medium">{provider.name}</h4>
                  <p className="text-sm text-muted-foreground truncate">
                    {provider.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* 設定手順 */}
      <Card>
        <CardHeader>
          <CardTitle>SSO 設定手順</CardTitle>
          <CardDescription>
            Enterprise SSO を設定するには、以下の手順に従ってください
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                1
              </div>
              <div>
                <h4 className="font-medium">Enterprise プランにアップグレード</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  SSO 機能を利用するには Enterprise プランが必要です。
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                2
              </div>
              <div>
                <h4 className="font-medium">Clerk ダッシュボードで SSO を設定</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Clerk の管理画面から Enterprise SSO 接続を作成し、
                  アイデンティティプロバイダーの情報を入力します。
                </p>
                <Button variant="outline" size="sm" className="mt-2" asChild>
                  <a
                    href="https://dashboard.clerk.com"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <ExternalLink className="h-4 w-4 mr-2" />
                    Clerk ダッシュボードを開く
                  </a>
                </Button>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                3
              </div>
              <div>
                <h4 className="font-medium">IdP でアプリケーションを登録</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  Azure AD、Okta、または使用する IdP で SAML/OIDC アプリケーションを作成し、
                  Clerk から提供される情報を設定します。
                </p>
              </div>
            </div>

            <div className="flex gap-4">
              <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-medium">
                4
              </div>
              <div>
                <h4 className="font-medium">ドメイン検証とテスト</h4>
                <p className="text-sm text-muted-foreground mt-1">
                  組織のドメインを検証し、SSO ログインが正常に動作することを確認します。
                </p>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ドキュメントリンク */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            参考ドキュメント
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2">
            <a
              href="https://clerk.com/docs/authentication/enterprise-connections"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted transition-colors"
            >
              <ExternalLink className="h-4 w-4 text-muted-foreground" />
              <div>
                <h4 className="font-medium text-sm">Clerk Enterprise SSO ガイド</h4>
                <p className="text-xs text-muted-foreground">
                  詳細な設定手順とトラブルシューティング
                </p>
              </div>
            </a>

            <a
              href="https://clerk.com/docs/authentication/saml"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted transition-colors"
            >
              <ExternalLink className="h-4 w-4 text-muted-foreground" />
              <div>
                <h4 className="font-medium text-sm">SAML 設定ガイド</h4>
                <p className="text-xs text-muted-foreground">
                  SAML 2.0 プロバイダーとの連携方法
                </p>
              </div>
            </a>

            <a
              href="https://learn.microsoft.com/en-us/entra/identity/saas-apps/tutorial-list"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted transition-colors"
            >
              <ExternalLink className="h-4 w-4 text-muted-foreground" />
              <div>
                <h4 className="font-medium text-sm">Azure AD 統合ガイド</h4>
                <p className="text-xs text-muted-foreground">
                  Microsoft Entra ID との連携設定
                </p>
              </div>
            </a>

            <a
              href="https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted transition-colors"
            >
              <ExternalLink className="h-4 w-4 text-muted-foreground" />
              <div>
                <h4 className="font-medium text-sm">Okta 統合ガイド</h4>
                <p className="text-xs text-muted-foreground">
                  Okta との SAML 連携設定
                </p>
              </div>
            </a>
          </div>
        </CardContent>
      </Card>

      {/* サポート */}
      <Card>
        <CardContent className="py-6">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-lg bg-primary/10">
              <Users className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
              <h4 className="font-medium">SSO 設定のサポートが必要ですか？</h4>
              <p className="text-sm text-muted-foreground">
                Enterprise プランでは、専任のサポートチームが SSO 設定をお手伝いします。
              </p>
            </div>
            <Button variant="outline">
              サポートに問い合わせ
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
