# 設定

SBOMHubは環境変数で設定できます。

## 環境変数

### 基本設定

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `PORT` | `8080` | APIサーバーポート |
| `DATABASE_URL` | `postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable` | PostgreSQL接続文字列 |
| `REDIS_URL` | `redis://localhost:6379` | Redis接続文字列 |
| `BASE_URL` | `http://localhost:3000` | WebアプリケーションのベースURL |
| `ENVIRONMENT` | `development` | 環境: `development`, `staging`, `production` |

### NVD連携

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `NVD_API_KEY` | (空) | NVD APIキー（レート制限緩和用）。https://nvd.nist.gov/developers/request-an-api-key で取得 |

### 認証（SaaSモード）

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `CLERK_SECRET_KEY` | (空) | Clerk認証用シークレットキー |
| `CLERK_WEBHOOK_SECRET` | (空) | Clerk Webhook署名シークレット |

> `CLERK_SECRET_KEY`を設定すると、SBOMHubはユーザー認証付きのSaaSモードで動作します。

### 課金（SaaSモード）

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `LEMONSQUEEZY_API_KEY` | (空) | Lemon Squeezy APIキー |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | (空) | Lemon Squeezy Webhook署名シークレット |
| `LEMONSQUEEZY_STORE_ID` | (空) | Lemon SqueezyストアID |
| `LEMONSQUEEZY_STARTER_VARIANT_ID` | (空) | Starterプランの製品バリアントID |
| `LEMONSQUEEZY_PRO_VARIANT_ID` | (空) | Proプランの製品バリアントID |
| `LEMONSQUEEZY_TEAM_VARIANT_ID` | (空) | Teamプランの製品バリアントID |

### フロントエンド設定

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | フロントエンド用API URL |
| `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` | (空) | Clerkの公開キー |

## 設定ファイル

### docker-compose.yml

環境変数または`.env`ファイルで設定を上書き：

```yaml
services:
  api:
    environment:
      - DATABASE_URL=postgres://user:pass@postgres:5432/sbomhub
      - REDIS_URL=redis://redis:6379
      - NVD_API_KEY=${NVD_API_KEY}
```

### .envファイル

プロジェクトルートに`.env`ファイルを作成：

```bash
# 基本設定
DATABASE_URL=postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable
REDIS_URL=redis://localhost:6379
ENVIRONMENT=production

# NVD
NVD_API_KEY=your-nvd-api-key

# Clerk（SaaSモードのみ）
CLERK_SECRET_KEY=sk_live_xxxxx
CLERK_WEBHOOK_SECRET=whsec_xxxxx
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_live_xxxxx

# Lemon Squeezy（SaaSモードのみ）
LEMONSQUEEZY_API_KEY=xxxxx
LEMONSQUEEZY_WEBHOOK_SECRET=xxxxx
LEMONSQUEEZY_STORE_ID=xxxxx
```

## デプロイモード

### セルフホストモード

認証が設定されていない場合のデフォルトモード：

- ユーザー認証不要
- シングルテナント運用
- サブスクリプションなしですべての機能が利用可能

```bash
# セルフホスト用の最小限の設定
export DATABASE_URL="postgres://..."
export REDIS_URL="redis://..."
docker compose up -d
```

### SaaSモード

`CLERK_SECRET_KEY`を設定すると有効化：

- Clerk経由のユーザー認証
- Row-Level Securityによるマルチテナント
- サブスクリプションベースの機能アクセス
- Lemon Squeezyによる課金

```bash
# SaaSモード設定
export CLERK_SECRET_KEY="sk_live_xxxxx"
export LEMONSQUEEZY_API_KEY="xxxxx"
docker compose up -d
```

## データベース設定

### PostgreSQL

本番環境の推奨設定：

```sql
-- コネクションプーリング
max_connections = 100
shared_buffers = 256MB

-- パフォーマンス
effective_cache_size = 1GB
maintenance_work_mem = 128MB
```

### Redis

推奨設定：

```
maxmemory 256mb
maxmemory-policy allkeys-lru
```

## セキュリティ推奨事項

### 本番環境チェックリスト

- [ ] 強力なデータベースパスワードを使用
- [ ] データベース接続でSSLを有効化（`sslmode=require`）
- [ ] 有効な証明書でHTTPSを設定
- [ ] `ENVIRONMENT=production`を設定
- [ ] データベースアクセスをアプリケーションサーバーに制限
- [ ] PostgreSQLデータの定期バックアップ
- [ ] セキュリティ問題のログ監視

### シークレット管理

本番デプロイでは以下の使用を検討：

- Docker Secrets
- Kubernetes Secrets
- HashiCorp Vault
- AWS Secrets Manager
- 環境固有のCI/CD変数
