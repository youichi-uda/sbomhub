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
| `APP_ENV` | (なし・必須) | 環境: `development`, `staging`, `production`。**デフォルトはありません。** 未設定、またはこの 3 値以外の場合、サーバーは起動を拒否します (M48)。起動時ガードはいずれも `development` のときだけ警告に格下げされるため、未設定が最も弱い構成を暗黙に選ぶ状態になっていました。旧名 `ENVIRONMENT` は `APP_ENV` 未設定時のフォールバックとして引き続き読まれます (M0 Trust Rescue, codex-r18)。フォールバックで得た値も同じ検証を受けます。 |
| `ENCRYPTION_KEY` | (なし・`APP_ENV=development` 以外では必須) | DB に保存する秘密情報 (BYOK の LLM API キー、Issue tracker 連携トークン、diff webhook の署名シークレット) を暗号化する AES-256 鍵。32 バイト以上で、既知のプレースホルダ値でないことが必要です。満たさない場合サーバーは起動を拒否し、`APP_ENV=development` のときのみ警告に格下げされます。`openssl rand -base64 32` で生成してください。ローテーション手順: [`encryption-key-rotation.md`](./encryption-key-rotation.md)。 |

### 認証と起動時ガード

`SBOMHUB_AUTH_MODE` は、この deployment がどちらの認証モードを意図しているかを宣言する必須の変数です。`SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` は、開発環境で webhook の署名検証を弱める opt-in です。`anonymous` の宣言は「運用者がそれを意図した」という表明であって、緩和策ではありません。宣言しても deployment が安全になるわけではありません。

| 変数 | デフォルト | 説明 |
|------|---------|------|
| `SBOMHUB_AUTH_MODE` | (なし・必須) | `clerk` または `anonymous`。この deployment の認証モードを宣言します。デフォルトはなく、`CLERK_SECRET_KEY` が届いたかどうかからの推論も行いません。`clerk`: ユーザー認証を Clerk で行う構成。`anonymous`: self-host 構成。Clerk 認証を前提とする API route group が、資格情報なしのリクエストを既定テナントの Owner として処理します (下記「デプロイモード」参照)。次のいずれの場合もサーバーは起動を拒否します: 未設定 (`development` を含む全環境)、この 2 値以外の値、`clerk` と宣言しているが `CLERK_SECRET_KEY` が空、`anonymous` と宣言しているが `CLERK_SECRET_KEY` が設定されている、`anonymous` と宣言しているが SaaS 専用の変数 (`CLERK_WEBHOOK_SECRET`、いずれかの `LEMONSQUEEZY_*`) が設定されている (Clerk のキーだけが欠けた中途半端な構成)。未設定の場合、`docker compose` もコンテナ起動前の変数展開の時点で失敗します。 |
| `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` | `false` | M47 で導入済み。署名シークレットが未設定の Clerk / Lemon Squeezy webhook *受信側* が、署名のない配信を受け入れることを許可します。`APP_ENV=development` のときのみ有効で、それ以外の値では設定されていても無視されます。SaaS モードで `APP_ENV=production` の場合はサーバーが起動を拒否します。 |

推論をやめて宣言を必須にした理由: シークレット注入がまるごと失敗した Clerk deployment は、self-host deployment とバイト単位で同一です (Clerk キーも webhook シークレットも billing キーも残りません)。矛盾を検出する材料が何も残らないため、以前のフェーズから残った「anonymous でよい」という永続的な痕跡があれば、それが認証なしでの起動を承認してしまいます。そうした痕跡を「Clerk キーが存在するときだけ」拒否しても塞げません。初回起動、crash-loop、キーが最初から届かなかったロールアウトについては何も言えないからです。宣言はシークレットストアではなく deployment manifest 側に置かれるため、注入の失敗を生き延び、それを起動拒否に変えます。古くなった場合も安全側に倒れます。古い `clerk` は起動失敗であり、Clerk deployment が持ち得るどの状態も anonymous モードを許可しません。この理由から、宣言はシークレットストアの外に置いてください。なお、このガードの中間ドラフトで使っていた boolean の `SBOMHUB_ALLOW_ANONYMOUS_AUTH` は、alias として残さず削除されました。設定されていること自体が起動拒否になり、メッセージが `SBOMHUB_AUTH_MODE=anonymous` を案内します。

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
| `SBOMHUB_LLM_OPENAI_EMBEDDING_MODEL` | `text-embedding-3-small` | OpenAI embedding model。既知 dimensions: `text-embedding-3-small` / `text-embedding-ada-002` = 1536、`text-embedding-3-large` = 3072。 |
| `SBOMHUB_LLM_GEMINI_EMBEDDING_MODEL` | `gemini-embedding-2` | Gemini embedding model。2026 時点の stable は `gemini-embedding-2`。`gemini-embedding-001` / legacy `text-embedding-004` は明示指定で利用可能。既定 dimensions は `gemini-embedding-*` で 3072。 |
| `SBOMHUB_LLM_OLLAMA_EMBEDDING_MODEL` | `nomic-embed-text` | Ollama `/api/embed` で使う embedding model。代表 dimensions: `nomic-embed-text` = 768、`mxbai-embed-large` / `bge-m3` = 1024。 |

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

#### Azure 以外の embedding provider (M5-7)

OpenAI / Gemini / Ollama も `Embed` を実装しています。Anthropic は、公式 Claude Platform docs が first-party Claude embeddings endpoint ではなく Voyage AI 利用を案内しているため、引き続き非対応です。

| Provider | Endpoint | 既定 embedding model | Dimensions | Batch 挙動 |
|----------|----------|----------------------|------------|------------|
| OpenAI | `POST https://api.openai.com/v1/embeddings` | `text-embedding-3-small` | 1536 | 2,048 inputs/request、16,384 inputs/call safety cap。途中 chunk 失敗時は全 vector 破棄。 |
| Gemini | 1 input は `.../models/{model}:embedContent`、複数は `:batchEmbedContents` | `gemini-embedding-2` | 3072 | sbomhub 側 cap 100 inputs/request、16,384 inputs/call safety cap。途中 chunk 失敗時は全 vector 破棄。 |
| Ollama | `POST {OLLAMA_HOST}/api/embed` | `nomic-embed-text` | 768 | sbomhub 側 cap 2,048 inputs/request、16,384 inputs/call safety cap。途中 chunk 失敗時は全 vector 破棄。 |
| Anthropic | N/A | N/A | N/A | `Embed` は `ErrNotImplemented`。Voyage AI 等を別途利用。 |

### 外向き接続ポリシー (テナントが指定する宛先)

テナント管理者が URL を入力し、サーバーがそこへ接続する設定画面が 4 つあります
(イシュートラッカーのベース URL、Slack / Discord 通知 Webhook、SBOM 差分 Webhook、
テナント別 Azure OpenAI エンドポイント)。これらは信頼できない入力なので、内部
アドレスへの接続は既定で拒否されます。

**運用者が設定する宛先** — `SBOMHUB_*_URL` のフィードミラー、Ollama のベース URL
(`SBOMHUB_LLM_OLLAMA_URL` / `OLLAMA_HOST`、既定 `http://localhost:11434`)、課金
プロバイダ API — は対象外です。

| 変数 | 既定値 | 説明 |
|------|--------|------|
| `SBOMHUB_EGRESS_ALLOW_PRIVATE` | `false` | 上記 4 用途で RFC1918 / ループバック / CGNAT / IPv6 ULA 宛を許可する |
| `SBOMHUB_EGRESS_ALLOWED_INTERNAL` | (空) | 限定的な代替手段。内部宛を許可するホスト名・IP アドレス・CIDR をカンマまたは空白区切りで列挙する。ホスト名はサブドメインにも一致する。書式が不正な場合は起動を拒否する |
| `SBOMHUB_EGRESS_ALLOW_PROXY` | `false` | 上記 4 用途で `HTTP_PROXY` / `HTTPS_PROXY` を有効にする。既定で無効。プロキシ経由ではプロキシのアドレスしか検査できず、実際の宛先はプロキシが決めるため、有効化は宛先ポリシーをプロキシ側に委譲することを意味する |
| `SBOMHUB_EGRESS_NAT64_PREFIXES` | (空) | このネットワークが使う RFC 6052 NAT64 変換プレフィックス (well-known な `64:ff9b::/96` 以外を使う場合)。宣言されたプレフィックス経由の宛先は、内包する IPv4 アドレスで判定される。不正な値は起動を拒否する |

クラウドのインスタンスメタデータ (`169.254.169.254` を含むリンクローカル全体、
Azure の `168.63.129.16`、およびそれらを内包する IPv6 トンネル形式) は、上記を
設定しても拒否されます。ポリシーの詳細と既知の限界は
[docs/security/egress.md](./security/egress.md)、内部サービスを指しているテナントが
いる場合の移行手順は [UPGRADE.md §2c](./UPGRADE.md) を参照してください。

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

# APP_ENV=development 以外では必須。openssl rand -base64 32 で生成
ENCRYPTION_KEY=

# この deployment の認証モードの宣言: anonymous (self-host。ユーザー認証は
# ありません。「デプロイモード」参照) または clerk。development を含む全環境で
# 必須で、未設定ならサーバーは起動を拒否し、docker compose もコンテナ起動前に
# 失敗します。
SBOMHUB_AUTH_MODE=anonymous

# NVD
NVD_API_KEY=your-nvd-api-key

# AI 機能 (BYOK)。未設定なら AI 機能は無効化されます。
# どれか 1 つを設定してください。
SBOMHUB_LLM_PROVIDER=openai          # openai | anthropic | gemini | azure_openai | ollama
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=sk-...
SBOMHUB_LLM_OPENAI_EMBEDDING_MODEL=text-embedding-3-small       # 任意; default

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
# SBOMHUB_LLM_OLLAMA_EMBEDDING_MODEL=nomic-embed-text
# OLLAMA_HOST=http://localhost:11434
```

## デプロイモード

self-host (Docker Compose) のみがサポート対象です。SaaS 版 (`sbomhub.app`) は 2026-06 にサンセットされました。

**self-host にユーザー認証はありません。** self-host モードは `CLERK_SECRET_KEY` が空であることだけで選択され、OSS 版が使う構成はこれのみです。このモードでは `internal/middleware/auth.go` の `handleSelfHostedAuth` がヘッダを一切読まず、資格情報を一切検証せず、リクエストのロールを既定テナントの Owner に設定します。これは Clerk 認証を前提とする route group、つまり `Auth` / `MultiAuth` ミドルウェアの背後にあるすべて (プロジェクト、SBOM、VEX、設定、API キー発行) の挙動です。`/api/v1/cli/*` と `/api/v1/mcp/*` は API キーで認証しており、引き続きキーを要求します。`/api/v1/health` と `/api/v1/public/:token` は、どちらのモードでも設計上 anonymous です。2026-07-29 に実 DB に対して測定した挙動は次のとおりです。`Authorization` ヘッダを一切付けずに `POST /api/v1/projects` が 201、`GET /api/v1/me` が `role=owner plan=enterprise`、admin 権限が必要な `POST /api/v1/apikeys` が 201 を返し、レスポンスボディに実際に使える API キーが含まれていました。そこで発行された API キーは、その後 `CLERK_SECRET_KEY` を設定して SaaS モードで再起動した後も `/api/v1/cli/*` と `/api/v1/mcp/*` に対して有効なままでした (どちらも HTTP 200 を確認)。つまり、後から変数を設定しても、未設定だった間に発行されたキーは無効になりません。

したがって、self-host インスタンスを守っているのはネットワーク到達性だけです。API ポートに到達できる者は誰でも、上記の route group 経由でその deployment の全データに Owner 権限でアクセスできます。実データを扱う前に、VPN / プライベートサブネット / 認証付きリバースプロキシの内側に API を配置してください。[`security/self-host-deployment.md`](./security/self-host-deployment.md) §7 (firewall / network 分離) を参照。

API キー (`POST /api/v1/apikeys`。CLI / GitHub Actions / MCP サーバーが使用) は、機械クライアント向けの*追加*の認証手段です。self-host deployment のアクセス境界ではありません。発行そのものに資格情報が要らないためです。

- 認証: self-host モードでは Clerk 認証を前提とする route group に認証がありません (上記のとおり)。これが意図した構成であることを宣言する `SBOMHUB_AUTH_MODE=anonymous` が `development` を含む全環境で必須で、未設定ならサーバーは起動を拒否します
- マルチテナントは PostgreSQL Row-Level Security で実現 (`DATABASE_URL` が `NOSUPERUSER NOBYPASSRLS` のロールである場合)。これはテナント同士の分離であり、呼び出し元の認証ではありません
- AI 機能は BYOK で graceful に有効化 / 無効化

```bash
# self-host の最小限の設定。
# 先頭 3 つは全環境での起動要件: APP_ENV / ENCRYPTION_KEY / SBOMHUB_AUTH_MODE
# のいずれかが欠けているとサーバーは起動しません。
export APP_ENV=production
export ENCRYPTION_KEY="$(openssl rand -base64 32)"   # 保管必須 (既存行の復号に使う)
export SBOMHUB_AUTH_MODE=anonymous                   # ユーザー認証なしであることの宣言 (上記参照)
export DATABASE_URL="postgres://..."                 # NOSUPERUSER NOBYPASSRLS のロールを使用
export REDIS_URL="redis://..."
docker compose up -d
```

手作業で組み立てたくない場合は `./install.sh` が `.env` を生成します (ランダムな `ENCRYPTION_KEY`、DB ロール等)。

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
- [ ] `APP_ENV=production`を設定 (未設定・綴り違いの場合サーバーは起動を拒否)
- [ ] 実運用用の `ENCRYPTION_KEY` を設定 (`openssl rand -base64 32`)。リポジトリ外で保管
- [ ] `DATABASE_URL` に `NOSUPERUSER NOBYPASSRLS` のロールを指定し、アプリ接続に対して Row-Level Security が効く状態にする
- [ ] self-host の場合: `SBOMHUB_AUTH_MODE=anonymous` を宣言し (production に限らず全環境で必須)、API の前段にネットワーク境界 (VPN / プライベートサブネット / 認証付きリバースプロキシ) を置く — この宣言は Clerk 認証を前提とする route group に認証がないことを記録するものであり、認証を追加するものではありません
- [ ] SaaS / Clerk の場合: `SBOMHUB_AUTH_MODE=clerk` を宣言し、その行をシークレットストアではなく deployment manifest 側に置く (シークレット注入がまるごと失敗しても、認証なしで起動せずに起動拒否になる)
- [ ] `SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS` は設定しない
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
