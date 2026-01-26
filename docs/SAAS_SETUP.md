# SBOMHub SaaS Setup Guide

SBOMHubはセルフホストモードとSaaSモードの両方をサポートしています。

## ライセンスについて

SBOMHubは **AGPL-3.0** ライセンスで提供されています。

| 利用形態 | 許可 | 条件 |
|---------|------|------|
| **セルフホスト（社内利用）** | ✅ | ソースコード公開不要 |
| **セルフホスト（改変あり）** | ✅ | 改変部分のソースコード公開必要 |
| **SaaS提供（第三者向け）** | ⚠️ | 全ソースコードをAGPLで公開必要 |
| **公式SBOMHub Cloud** | ✅ | 開発元による提供 |

> **注意**: 第三者がSBOMHubを基にした商用SaaSを提供する場合、AGPLに基づき全ソースコード（改変部分含む）を同じライセンスで公開する義務があります。商用ライセンスが必要な場合はお問い合わせください。

## 動作モード

| モード | 条件 | 認証 | 課金 | マルチテナント |
|--------|------|------|------|---------------|
| **セルフホスト** | 環境変数なし | なし（全機能開放） | なし | シングルテナント |
| **SaaS** | `CLERK_SECRET_KEY` 設定 | Clerk | Lemon Squeezy | マルチテナント |

---

## セルフホストモード

環境変数を設定せずに起動すると、セルフホストモードで動作します。

```bash
# 最小構成で起動
docker compose up -d postgres redis
cd apps/api && go run ./cmd/server
cd apps/web && npm run dev
```

**特徴:**
- 認証不要（全ユーザーが管理者権限）
- 全機能が利用可能（Enterprise相当）
- デフォルトテナントを自動作成
- プラン制限なし

---

## SaaSモード設定

### 1. Clerk設定

#### 1.1 Clerkアカウント作成

1. https://clerk.com でアカウント作成
2. 新規アプリケーション作成（例: SBOMHub）
3. 認証方法を選択:
   - Email/Password
   - Google OAuth
   - GitHub OAuth
4. **Organization機能を有効化**（Settings → Organizations）

#### 1.2 環境変数設定

```bash
# Backend (.env)
CLERK_SECRET_KEY=sk_live_xxxxx          # Dashboard → API Keys
CLERK_WEBHOOK_SECRET=whsec_xxxxx        # Webhooks設定後に取得

# Frontend (.env.local)
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx
CLERK_SECRET_KEY=sk_live_xxxxx
```

#### 1.3 Webhook設定

Clerk Dashboard → Webhooks → Add Endpoint

- **URL**: `https://api.your-domain.com/api/webhooks/clerk`
- **Events**:
  - `user.created`
  - `user.updated`
  - `user.deleted`
  - `organization.created`
  - `organization.updated`
  - `organization.deleted`
  - `organizationMembership.created`
  - `organizationMembership.updated`
  - `organizationMembership.deleted`

---

### 2. Lemon Squeezy設定（課金）

#### 2.1 アカウント・ストア作成

1. https://lemonsqueezy.com でアカウント作成
2. Store作成

#### 2.2 Products作成

| Product名 | 価格 | Variant ID |
|-----------|------|------------|
| SBOMHub Starter | ¥2,500/月 | `LEMONSQUEEZY_STARTER_VARIANT_ID` |
| SBOMHub Pro | ¥8,000/月 | `LEMONSQUEEZY_PRO_VARIANT_ID` |
| SBOMHub Team | ¥20,000/月 | `LEMONSQUEEZY_TEAM_VARIANT_ID` |

#### 2.3 環境変数設定

```bash
LEMONSQUEEZY_API_KEY=xxxxx
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx
LEMONSQUEEZY_STORE_ID=xxxxx
LEMONSQUEEZY_STARTER_VARIANT_ID=xxxxx
LEMONSQUEEZY_PRO_VARIANT_ID=xxxxx
LEMONSQUEEZY_TEAM_VARIANT_ID=xxxxx
```

#### 2.4 Webhook設定

Lemon Squeezy Dashboard → Settings → Webhooks

- **URL**: `https://api.your-domain.com/api/webhooks/lemonsqueezy`
- **Events**:
  - `subscription_created`
  - `subscription_updated`
  - `subscription_cancelled`
  - `subscription_resumed`
  - `subscription_expired`
  - `subscription_paused`
  - `subscription_unpaused`

---

### 3. データベースマイグレーション

SaaS機能を使用するには、追加のマイグレーションが必要です。

```bash
# マイグレーション実行
cd apps/api
go run ./cmd/migrate up

# または手動実行
psql -U sbomhub -d sbomhub -f migrations/006_notification_settings.up.sql
psql -U sbomhub -d sbomhub -f migrations/007_multitenancy.up.sql
psql -U sbomhub -d sbomhub -f migrations/008_subscriptions.up.sql
```

---

## プラン制限

| プラン | ユーザー数 | プロジェクト数 | 主な機能 |
|--------|-----------|---------------|----------|
| Free | 1 | 2 | 基本機能のみ |
| Starter | 3 | 10 | VEX, ライセンスポリシー, Slack/Discord通知 |
| Pro | 10 | 無制限 | 上記 + 優先サポート |
| Team | 30 | 無制限 | 上記 + 無制限SBOMストレージ |
| Enterprise | 無制限 | 無制限 | SSO, カスタム統合, SLA |

---

## APIエンドポイント

### 認証関連

```
GET  /api/v1/me                    # 現在のユーザー情報
GET  /api/v1/subscription          # サブスクリプション情報
POST /api/v1/subscription/checkout # Checkout URL生成
GET  /api/v1/subscription/portal   # Billing Portal URL
GET  /api/v1/plan/usage            # 使用量確認
```

### Webhooks

```
POST /api/webhooks/clerk           # Clerk Webhook
POST /api/webhooks/lemonsqueezy    # Lemon Squeezy Webhook
```

---

## ローカル開発でのSaaSモードテスト

### ngrokを使用したWebhookテスト

```bash
# ngrokでローカルAPIを公開
ngrok http 8080

# 表示されたURLをWebhook設定に使用
# 例: https://xxxx.ngrok.io/api/webhooks/clerk
```

### テスト用環境変数

```bash
# .env.local (開発用)
CLERK_SECRET_KEY=sk_test_xxxxx
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_xxxxx
```

---

## トラブルシューティング

### 認証エラー

```
401 Unauthorized: invalid token
```

→ `CLERK_SECRET_KEY` が正しく設定されているか確認

### Webhookエラー

```
401 Unauthorized: invalid signature
```

→ `CLERK_WEBHOOK_SECRET` / `LEMONSQUEEZY_WEBHOOK_SECRET` を確認

### テナント未検出

```
403 Forbidden: tenant not found
```

→ Clerk Organizationが作成されているか確認
→ Webhookでテナントが同期されているか確認

---

## セキュリティ考慮事項

1. **環境変数**: シークレットキーは絶対にコミットしない
2. **HTTPS**: 本番環境では必ずHTTPSを使用
3. **Webhook署名**: 必ず署名検証を有効化
4. **RLS**: PostgreSQL Row-Level Securityでテナント分離
5. **監査ログ**: 重要な操作は`audit_logs`テーブルに記録
