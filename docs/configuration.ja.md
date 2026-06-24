# 設定

SBOMHub は環境変数で設定できます。

> SBOMHub は CRA (EU Cyber Resilience Act 2026/9) 対応の **AI コンプラ成果物レイヤー** として位置付けられ、self-host (Docker Compose) のみがサポート対象です。
> SaaS 版 (`sbomhub.app`) は 2026-06 にサンセットされ、Clerk / Lemon Squeezy 等の SaaS 連携設定は OSS 版では使用しません。

## 環境変数

### 基本設定

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `PORT` | `8080` | APIサーバーポート |
| `DATABASE_URL` | `postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable` | PostgreSQL接続文字列 |
| `REDIS_URL` | `redis://localhost:6379` | Redis接続文字列 |
| `BASE_URL` | `http://localhost:3000` | WebアプリケーションのベースURL |
| `APP_ENV` | `development` | 環境: `development`, `staging`, `production`。旧名 `ENVIRONMENT` は `APP_ENV` 未設定時のフォールバックとして引き続き読まれます (M0 Trust Rescue, codex-r18)。 |

### NVD連携

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `NVD_API_KEY` | (空) | NVD APIキー（レート制限緩和用）。https://nvd.nist.gov/developers/request-an-api-key で取得 |

### LLM プロバイダ (AI 機能・BYOK)

AI VEX トリアージ / CRA 報告書ドラフト / 経産省自己評価プリフィルなどの AI 機能は **完全 BYOK (Bring Your Own Key)** です。バンドルされた鍵はありません。下記いずれか 1 プロバイダを設定すれば AI 機能が有効化されます。未設定の場合は AI 機能が graceful に無効化され、手動 VEX / 手動 CRA 報告 / 手動自己評価などの従来機能はそのまま動作します。

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `SBOMHUB_LLM_PROVIDER` | (空) | `openai` / `anthropic` / `gemini` / `ollama` |
| `SBOMHUB_LLM_MODEL` | (空) | 例: `gpt-5`, `claude-opus-4-7`, `gemini-3.5-flash`, `qwen2.5-coder:7b` |
| `OPENAI_API_KEY` | (空) | `provider=openai` の場合に必須 |
| `ANTHROPIC_API_KEY` | (空) | `provider=anthropic` の場合に必須 |
| `GOOGLE_API_KEY` | (空) | `provider=gemini` の場合に必須 |
| `OLLAMA_HOST` | (空) | `provider=ollama` の場合に必須 (例: `http://localhost:11434`) |

> コードや SBOM を外部に出したくない製造業セルフホスト運用では、Ollama などのローカル LLM を推奨します。

### フロントエンド設定

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | フロントエンド用API URL |

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
APP_ENV=production

# NVD
NVD_API_KEY=your-nvd-api-key

# AI 機能 (BYOK)。未設定なら AI 機能は無効化されます。
# どれか 1 つを設定してください。
SBOMHUB_LLM_PROVIDER=openai          # openai | anthropic | gemini | ollama
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=sk-...

# ローカル LLM の例 (コードを外部に出さない)
# SBOMHUB_LLM_PROVIDER=ollama
# SBOMHUB_LLM_MODEL=qwen2.5-coder:7b
# OLLAMA_HOST=http://localhost:11434
```

## デプロイモード

self-host (Docker Compose) のみがサポート対象です。SaaS 版 (`sbomhub.app`) は 2026-06 にサンセットされました。

- ユーザー認証は self-host 内のシンプルなアカウント管理 (将来) / API キーで運用
- マルチテナントは PostgreSQL Row-Level Security で実現
- AI 機能は BYOK で graceful に有効化 / 無効化

```bash
# self-host の最小限の設定
export DATABASE_URL="postgres://..."
export REDIS_URL="redis://..."
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
- [ ] `APP_ENV=production`を設定
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
