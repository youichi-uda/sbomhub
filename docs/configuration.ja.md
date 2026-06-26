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
| `SBOMHUB_LLM_PROVIDER` | (空) | `openai` / `anthropic` / `gemini` / `azure_openai` / `ollama` |
| `SBOMHUB_LLM_MODEL` | (空) | 例: `gpt-5`, `claude-opus-4-7`, `gemini-3.5-flash`, `qwen2.5-coder:7b`。`azure_openai` の場合は監査ログに記録する canonical なモデル名 (ルーティングは deployment 名で行われ、この値は使われません) |
| `SBOMHUB_LLM_API_KEY` | (空) | 共通の API キー (canonical)。各プロバイダ純正の alias は fall-back として参照されます |
| `OPENAI_API_KEY` | (空) | `provider=openai` で canonical キーが未設定の場合に使用 |
| `ANTHROPIC_API_KEY` | (空) | `provider=anthropic` で canonical キーが未設定の場合に使用 |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | (空) | `provider=gemini` で canonical キーが未設定の場合に使用 |
| `AZURE_OPENAI_API_KEY` | (空) | `provider=azure_openai` で canonical キーが未設定の場合に使用。`OPENAI_API_KEY` への alias は意図的にしていません (混在すると Azure 向けに OpenAI.com のキーを誤って送ってしまうリスクがあるため) |
| `OLLAMA_HOST` | (空) | `provider=ollama` の場合に必須 (例: `http://localhost:11434`) |

> コードや SBOM を外部に出したくない製造業セルフホスト運用では、Ollama などのローカル LLM を推奨します。既に Microsoft の調達契約がある場合は Azure OpenAI も推奨です。

#### Azure OpenAI 設定

`SBOMHUB_LLM_PROVIDER=azure_openai` を選んだ場合、以下の deployment 固有の設定も必要になります。各行は canonical な SBOMHub 環境変数名と、fall-back として参照される provider 純正 alias を precedence 順 (canonical 優先、最初に非空の値が採用される) で列挙しています。

| 変数 (canonical → alias) | デフォルト | 説明 |
|--------------------------|----------|------|
| `SBOMHUB_LLM_AZURE_ENDPOINT` → `AZURE_OPENAI_ENDPOINT` | (空) | Azure リソースのエンドポイント URL (例: `https://my-resource.openai.azure.com`) |
| `SBOMHUB_LLM_AZURE_DEPLOYMENT` → `AZURE_OPENAI_DEPLOYMENT` → `AZURE_OPENAI_DEPLOYMENT_NAME` → `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` | (空) | Azure に登録した deployment 名 (URL パスセグメント)。Microsoft のドキュメントが内部で表記揺れがあるため、Azure 側 3 つの alias すべてを受け付けます。既存の自動化で使っているものをそのまま設定可能 |
| `SBOMHUB_LLM_AZURE_API_VERSION` → `AZURE_OPENAI_API_VERSION` | `2024-10-21` | Azure OpenAI の `api-version` クエリ。デフォルトは現行 GA stable チャネル。deployment が特定の契約バージョンに pin されている場合のみ上書き |

`provider=azure_openai` を選んでも endpoint / deployment / API キーのいずれかが未設定の場合は、 graceful に provider が無効化されます (他の機能はそのまま動作し、AI 機能のみが off になります)。

##### Azure OpenAI embedding deployment (M5-3)

Azure は embedding (`text-embedding-3-small` / `-3-large` / `text-embedding-ada-002` 等) を chat とは **別 deployment** として登録します。 embedding deployment は **任意** で、 未設定の場合は chat (`Complete`) のみ動作し、 embedding (`Embed`) は per-call で `DisabledError` (HTTP 503) を返します (chat-only 製品挙動には影響しません)。

| 変数 (canonical → alias) | デフォルト | 説明 |
|--------------------------|----------|------|
| `SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT` → `AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME` | (空) | embedding deployment 名。 設定すると `Capabilities.SupportsEmbedding` が true になります。 |
| `SBOMHUB_LLM_AZURE_EMBEDDING_API_VERSION` | (chat の `api-version`) | embedding 用 `api-version` 上書き (任意)。 未設定なら chat と同じ値を流用。 |
| `SBOMHUB_LLM_AZURE_EMBEDDING_MODEL` | (deployment 名から推定) | canonical embedding model 名 (任意)。 `Capabilities.EmbeddingDimensions` lookup 用 (1536 = `text-embedding-3-small` / `ada-002`、 3072 = `text-embedding-3-large`)。 未設定時は deployment 名を sniff、 業務命名の場合は 0 にフォールバック。 |

batching: 1 リクエストあたり最大 2,048 inputs (Azure 公式 hard cap)、 それを超える分は **透過的に複数 HTTP に分割**。 1 call あたり最大 16,384 inputs の安全 cap (F25 DoS 防止) で、 超過は HTTP dispatch 前に reject。 途中 chunk 失敗時は完了済 chunk を破棄して error を返します (partial Vectors の silent 切り詰めを避けるため)。

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
SBOMHUB_LLM_PROVIDER=openai          # openai | anthropic | gemini | azure_openai | ollama
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=sk-...

# Azure OpenAI の例 (Microsoft 調達契約経由)
# SBOMHUB_LLM_PROVIDER=azure_openai
# SBOMHUB_LLM_MODEL=gpt-4o                                      # canonical なモデル名 (audit / Capabilities 用)
# SBOMHUB_LLM_AZURE_ENDPOINT=https://my-resource.openai.azure.com
# SBOMHUB_LLM_AZURE_DEPLOYMENT=my-chat-deployment
# SBOMHUB_LLM_AZURE_API_VERSION=2024-10-21                      # optional。 デフォルトは GA stable チャネル
# AZURE_OPENAI_API_KEY=...                                       # または SBOMHUB_LLM_API_KEY
# 任意: reachability / vector search 用の embedding deployment (M5-3)
# SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT=text-embedding-3-small-prod
# SBOMHUB_LLM_AZURE_EMBEDDING_MODEL=text-embedding-3-small      # 任意 canonical embedding model 名 (Capabilities.EmbeddingDimensions)
# SBOMHUB_LLM_AZURE_EMBEDDING_API_VERSION=                      # 任意; 空なら chat の api-version を流用

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
