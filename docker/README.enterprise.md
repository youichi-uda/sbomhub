# SBOMHub Enterprise Self-host (Docker Compose)

> Status: M4-6 で追加された **enterprise 向け 1-file 配布形態**。 OSS の
> [`docker-compose.yml`](docker-compose.yml) (開発者向け) とは独立した
> [`docker-compose.enterprise.yml`](docker-compose.enterprise.yml) を `-f` で
> 明示指定して使用する。
>
> 製造業 IT 部門 / 自社 PSIRT を対象読者とした **セキュリティ運用全般** の
> 詳細は [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md)
> を参照 (M4-4)。 本 README は **本 enterprise compose 固有** の起動 / 運用手順に
> 絞る。

---

## 1. 概要

`docker-compose.enterprise.yml` は以下を OSS 標準の compose に対して
**上乗せではなく独立 file** として提供する:

| 差分 | OSS 標準 (`docker-compose.yml`) | Enterprise (`docker-compose.enterprise.yml`) |
|---|---|---|
| Local LLM (Ollama) | 無 | **同梱** (localhost-only bind、 起動時に model 自動 pull) |
| ENCRYPTION_KEY | dev placeholder hardcode | **Docker secrets** (file mount) |
| DB password | dev hardcode | **Docker secrets** (3 ロール分離: bootstrap superuser / sbomhub_app / sbomhub_migrator) |
| DB ロール分離 (RLS 強制) | OSS は `sbomhub` 単一 (operator が install.sh で切替) | **default で `sbomhub_app` (NOSUPERUSER NOBYPASSRLS) + `sbomhub_migrator` (NOBYPASSRLS)** — `db-bootstrap` one-shot service が起動時に冪等投入 (M4 Codex review #F76 fix) |
| host port bind | `0.0.0.0` で開発者がアクセス | **`127.0.0.1` only** (reverse proxy 前提) |
| ネットワーク分離 | 単一 default network | **backend / frontend** の 2 分離 (※ backend は outbound egress あり、 詳細は下記 1.1) |
| restart policy | なし | `unless-stopped` |
| API server entrypoint | image 標準 (env 直接読み) | wrapper script で secrets file → env var 展開 |

OSS compose は **絶対に override しない**。 両者を同時に動かす場合は
project name を分離する (`docker compose -p sbomhub-dev -f docker-compose.yml ...`
と `docker compose -p sbomhub-prod -f docker-compose.enterprise.yml ...`)。

### 1.1 ネットワーク分離の前提 (※要確認: docs/security/self-host-deployment.md §7 とも整合)

`docker-compose.enterprise.yml` の network 設計は **二段構え** になっている:

1. **Ingress 遮断 (一次防御)**: postgres / redis / ollama / api / web の各
   host port bind を **`127.0.0.1` localhost-only** に固定 (`127.0.0.1:8080:8080`
   等)。 これにより外部 host からこれらの port に直接到達することはできない。
   外部公開は reverse proxy (Caddy / nginx / Cloudflare Tunnel) で TLS 終端
   してから行う (§4.3 / [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) §6)。
2. **Service-to-service 分離 (二次防御)**: `backend` (postgres / redis / ollama
   / api) と `frontend` (api / web) の 2 つの docker network に分け、 web は
   直接 postgres / redis / ollama に到達できない (api 経由のみ)。

> ※要確認: `backend` network は `internal: false` (**container outbound egress
> あり**) で運用する。 これは **container 内** から外部 registry / model hub
> への outbound 接続が必要なためで、 具体的には以下の依存がある:
>
> - **model pull (container egress に依存)**: `ollama-init` container が
>   起動時に `ollama pull` を実行し、 `registry.ollama.ai` から AI model を
>   ダウンロードする。 これは container 内からの outbound 接続なので
>   backend network の egress 設定の影響を受ける。 一度 pull すれば
>   `ollama_data` named volume に永続化されるため以降は不要、 ただし新 model
>   投入や version up 時に再度 outbound が必要になる。
>
> なお **Docker image pull** (`postgres:15-alpine` / `redis:7-alpine` /
> `ollama/ollama:latest` 等を `registry.docker.io` / `ghcr.io` から取得する
> 処理) は **host 側の docker daemon が独立して行う** ため、 container
> network 上の `internal:` 設定の影響を **受けない**。 すなわち
> `backend.internal: true` に切り替えても image pull 自体は成功する。
> 失敗するのは上記の **model pull (container outbound)** のみ。
>
> outbound を厳しく絞りたい環境では、 docker 内部の `internal: true` ではなく
> **host 側 firewall (iptables / nftables) や egress proxy (Squid /
> Cloudflare Gateway)** で `registry.ollama.ai` などの model hub を制御する
> 構成を推奨する (なお image pull の制御は host daemon の HTTP(S) proxy /
> firewall 側で `registry.docker.io` / `ghcr.io` を allowlist する)。
> `ollama-init` が完了した後は ollama container の outbound は不要なので、
> 運用上は init 後に egress を絞り直す手もある。 詳細は
> [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) §7 参照。

---

## 2. 前提

- **Docker Engine 24+ + Docker Compose v2** (`docker compose version` で確認)
- **openssl** (鍵生成、 ほぼ全 distro に default で入っている)
- **age** (推奨、 backup 暗号化用、 https://github.com/FiloSottile/age)
- **GPU 利用時**:
  - NVIDIA: NVIDIA Container Toolkit (`nvidia-container-toolkit`) install + docker daemon に runtime 登録
  - AMD ROCm: `ollama/ollama:rocm` image に書き換え + `/dev/kfd /dev/dri` の device mount を追加
- **メモリ / VRAM**: 推奨 default model `qwen2.5-coder:7b` (4-bit 量子化) は ~6 GB VRAM、 bf16 で ~14 GB。 詳細は [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) §11.1。
- **ディスク**: postgres + redis 数 GB、 Ollama model 4-40 GB (model 次第)、 + backup 保管領域。

---

## 3. 初回セットアップ手順

### 3.1 secrets 生成

M4 Codex review #F76 fix で **default が role-separated** になったため、
PostgreSQL 関連 password は **3 つ** 生成する必要がある:

- `postgres_password.txt`     — POSTGRES_USER=`sbomhub` (bootstrap superuser)、 postgres initdb と `db-bootstrap` の admin 接続専用 (sbomhub-api は触らない)
- `postgres_app_password.txt` — `sbomhub_app` ロール (NOSUPERUSER NOBYPASSRLS)、 sbomhub-api runtime 接続
- `postgres_migrator_password.txt` — `sbomhub_migrator` ロール (NOBYPASSRLS + schema CREATE)、 自動 migration 接続

```bash
cd docker
cp -r secrets.example secrets

# ENCRYPTION_KEY (32 byte 必須、 末尾改行は除く)
openssl rand -base64 32 | tr -d '\n' > secrets/encryption_key.txt

# PostgreSQL password 3 種 (base64 推奨、 special char escape の事故を避ける)
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_app_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_migrator_password.txt

chmod 700 secrets
chmod 600 secrets/*.txt
```

詳細 / rotation 規律は [`secrets.example/README.md`](secrets.example/README.md) 参照。

### 3.2 model 名 (任意)

default は `qwen2.5-coder:7b`。 別の Ollama model を使う場合は環境変数で上書き:

```bash
export SBOMHUB_OLLAMA_MODEL="llama3.1:8b"
# または compose 起動コマンドに inline 指定
SBOMHUB_OLLAMA_MODEL=llama3.1:8b docker compose -f docker-compose.enterprise.yml up -d
```

推奨 model 比較は [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) §11.1 参照。

### 3.3 起動

```bash
docker compose -f docker-compose.enterprise.yml up -d
```

初回は以下が **順番** に走る:

1. `postgres` / `redis` / `ollama` の image pull + 起動 (数十秒〜数分)
2. `ollama-init` が `ollama pull qwen2.5-coder:7b` を実行 (数 GB のダウンロード、 数十分かかる可能性)
3. `db-bootstrap` が postgres healthy 直後に起動し、 `sbomhub_app` /
   `sbomhub_migrator` ロールを冪等作成 + privilege grant + (legacy volume なら)
   ALTER OWNER 移譲を行って exit 0 (数秒〜十数秒、 M4 Codex review #F76 fix)。
4. `sbomhub-api` が `db-bootstrap` 完了 (`service_completed_successfully`) を
   待って起動、 `sbomhub_migrator` で migration 適用 → `sbomhub_app` で server
   起動 (数秒)。 F72 fix の RLS startup guard は `sbomhub_app` の
   `rolsuper=false / rolbypassrls=false` を確認して pass する。
5. `sbomhub-web` が静的アセット展開 + Next.js 起動 (数秒)

進捗確認:

```bash
# 全体の状態 (db-bootstrap は完了後 Exited (0) として残るのが正常)
docker compose -f docker-compose.enterprise.yml ps

# Ollama pull 進捗 (一番時間がかかる)
docker compose -f docker-compose.enterprise.yml logs -f ollama-init

# db-bootstrap 動作 log (role 冪等作成 + privilege grant)
docker compose -f docker-compose.enterprise.yml logs db-bootstrap
# 期待: "[db-bootstrap] role bootstrap complete; sbomhub-api can now start as sbomhub_app"

# API server 起動 log (ENCRYPTION_KEY check + DB role check)
docker compose -f docker-compose.enterprise.yml logs -f sbomhub-api
# 期待: "DB role check passed role=sbomhub_app bypass_rls=false superuser=false"
```

### 3.4 advanced: manual role bootstrap (`install.sh --bootstrap-roles`)

M4 Codex review #F76 fix 以降、 上記 §3.3 default 起動で `db-bootstrap`
one-shot service が自動的に `sbomhub_app` / `sbomhub_migrator` ロールを投入する
ため、 **operator が手動で `install.sh --bootstrap-roles` を実行する必要はない**
(旧 M4-6 では manual step が必須だったが、 F72 fix で production / staging の
RLS startup guard が superuser を hard-fail するようになったのに合わせて
default 起動 path も role-separated に切り替えた)。

`install.sh --bootstrap-roles` は **advanced operator 向けに動作を維持** している
(SQL pattern が `db-bootstrap` service と完全に一致しているため、 重複実行
しても両者は冪等で結果は同じ)。 以下のようなケースで使用する:

- enterprise compose ではなく OSS `docker-compose.yml` を使っており、 後付けで
  role 分離を入れたい場合
- `db-bootstrap` が想定外の SQL 失敗で exit 1 し、 手動で再投入 / 復旧したい場合
  (この場合は最初に `docker compose logs db-bootstrap` でエラー原因を確認)
- 既存 sbomhub volume を別ホストへ移行した後など、 role が壊れた状態の復旧

```bash
# host 側 (compose project に attach 済み postgres が起動中であること)
cd ..
./install.sh --bootstrap-roles
cd docker

# 再起動 (sbomhub-api 設定は変更不要、 既に default で sbomhub_app 接続)
docker compose -f docker-compose.enterprise.yml up -d --force-recreate sbomhub-api
```

※注: `install.sh` は OSS compose project 名 (`docker_postgres_1` 等) を前提に
書かれているため、 enterprise compose 上で動かす際は `docker compose ps` で
postgres service 名 / project 名が `install.sh` の想定と一致するか確認のこと。

---

## 4. 動作確認

### 4.1 起動確認

```bash
# API health endpoint
curl -fsS http://127.0.0.1:8080/health

# Web UI
xdg-open http://127.0.0.1:3000   # Linux desktop
# または curl -fsS http://127.0.0.1:3000
```

初回 Web UI アクセス時は admin user 登録 fl が走る。 detail は
`../docs/installation.md` 参照。

### 4.2 LLM 疎通

```bash
# 直接 Ollama に問い合わせ (localhost-only bind なので host で curl 可能)
curl -fsS http://127.0.0.1:11434/api/tags

# 期待: {"models":[{"name":"qwen2.5-coder:7b",...}]}

# SBOMHub API 経由で LLM が呼べるか
# (具体 endpoint は M1 triage / M2 CRA 実装に依存、 sbomhub doctor で代替可)
```

### 4.3 reverse proxy 配線

production では `127.0.0.1:3000` (web) / `127.0.0.1:8080` (api) を Caddy /
nginx / Cloudflare Tunnel で TLS 終端して公開する。 設定例は M4-4 docs §6 参照。

---

## 5. backup / restore 運用

### 5.1 手動 backup

```bash
cd docker
./scripts/backup.sh
# → ./backups/sbomhub-backup-YYYYMMDD-HHMMSS.tar.gz が出力される

# age で暗号化する (推奨):
export AGE_RECIPIENT="age1XXXX..."  # 受信側 public key
./scripts/backup.sh
# → ./backups/sbomhub-backup-...tar.gz.age
```

backup 内容:

- `db.dump` (pg_dump custom format、 `pg_restore` で展開)
- `secrets/` (ENCRYPTION_KEY + DB password の **平文** copy)

**重要**: DB だけ復旧して ENCRYPTION_KEY を失うと `issue_tracker_connections.
auth_token_encrypted` 等の暗号化カラムが復号不能になる。 backup は **必ず
secrets と合わせて** 取得する (本 script はこれを自動化している)。

### 5.2 自動 backup (cron)

```cron
# /etc/cron.d/sbomhub-backup (毎日 02:00 JST 実行)
0 2 * * *  sbomhub  cd /opt/sbomhub/docker && AGE_RECIPIENT=age1XXXX... ./scripts/backup.sh >> /var/log/sbomhub-backup.log 2>&1
```

90 日以上の古い backup を自動削除する場合:

```bash
find /opt/sbomhub/docker/backups -name 'sbomhub-backup-*.tar.gz*' -mtime +90 -delete
```

### 5.3 restore

```bash
# 平文 backup
./scripts/restore.sh /path/to/sbomhub-backup-20260626-031000.tar.gz

# age 暗号化 backup
export AGE_IDENTITY=/path/to/your-age-key.txt   # 秘密鍵
./scripts/restore.sh /path/to/sbomhub-backup-20260626-031000.tar.gz.age
```

restore は **対話確認** ("yes" 入力必須) を要求する。 自動化する場合は
`FORCE=yes` env を渡す (CI / DR 訓練向け、 production では推奨しない)。

restore 後、 script が表示する Next steps に従って sbomhub-api / sbomhub-web を
`--force-recreate` で再起動する。

**fail-safe 動作 (F65 + F79 fix 後)**:

restore.sh は **7 step** 構成 (F79 で 5 step → 7 step に拡張、 F80 で Step 5.5 を追加):

| Step | 内容 | 失敗時の動作 |
|---|---|---|
| 1/7 | age decrypt (`.age` のみ) | exit 1 |
| 2/7 | tar extract | exit 1 |
| 3/7 | pg_restore (`--single-transaction --clean --if-exists --no-owner --no-privileges`) | rollback + exit 1 |
| 4/7 | sanity check (`schema_migrations` 最新 version、 `tenants` count) | exit 1 (secrets 上書き前) |
| 5/7 | secrets 復元 (`docker/secrets/` 上書き、 旧 secrets は `.bak-<utc>` に退避) | exit 1 |
| 5.5/7 | postgres admin role (`sbomhub`) password を restored secret に converge (DR scenario) | exit 1 |
| 6/7 | db-bootstrap 再実行 (`docker compose run --rm db-bootstrap`) | exit 1 |
| 7/7 | sbomhub_app role での `tenants` SELECT 確認 | exit 1 |

- `pg_restore` は `--single-transaction` で実行されるため、 途中 failure 時に
  **全 restore が rollback** され、 DB は restore 開始前の状態に戻る。 部分適用
  による DB と secrets の不整合は発生しない。
- restore 後に **sanity check** (`schema_migrations` 最新 version 取得 +
  `tenants` table の query 可能性確認) が走り、 いずれかが失敗した場合は
  secrets の上書きと完了 message を **出さずに `exit 1`** で abort する。
- **F79 fix**: secrets 復元の後、 **db-bootstrap one-shot service** (`docker
  compose -f docker-compose.enterprise.yml run --rm db-bootstrap`) を再実行
  して、 `pg_restore --no-owner --no-privileges` で落ちた ACL を再付与する
  (`sbomhub_app` への `SELECT/INSERT/UPDATE/DELETE` grant、 既存 owner の
  `sbomhub_migrator` への ALTER OWNER、 ALTER DEFAULT PRIVILEGES 等)。
  これを怠ると sbomhub-api 起動時に `sbomhub_app` が `permission denied for
  table ...` で fail し、 API が serve せず production blocker になる。
  失敗時は **完了 message を出さずに exit 1**。
- **F80 fix (DR scenario)**: `pg_restore` は PostgreSQL role password を
  **復元しない** (DB schema + data のみで `pg_authid` 等の cluster-level role
  情報は対象外)。 このため fresh volume / 別 host への cold restore では:
  postgres image init が新 host の `secrets/postgres_password.txt` で
  `sbomhub` role を作成済み、 一方 Step 5 で `postgres_password.txt` が
  backup 取得時の password に上書きされる → Step 6 db-bootstrap の TCP
  admin 接続が認証失敗で abort する (DR は backup の主目的なので blocker)。
  Step 5.5/7 は `docker compose exec -T postgres psql -U sbomhub` の Unix
  socket trust 経路で `ALTER ROLE sbomhub WITH PASSWORD '<restored>'` を
  実行し、 実 DB admin role password を restored secret に矯正する。
  hot restore (同一 volume / 同一 host) では既存 password = restored secret
  なので ALTER ROLE は実質 no-op。 失敗時の手動 recovery:
  ```bash
  docker compose -f docker-compose.enterprise.yml exec postgres \
      psql -U sbomhub -c "ALTER ROLE sbomhub PASSWORD '<restored postgres_password.txt value>';"
  ```
  この経路は postgres:15-alpine official image の local Unix socket =
  trust auth (default) に依存している。 `POSTGRES_HOST_AUTH_METHOD` を
  trust 以外に上書きしている場合は Step 3-4 sanity check も同様に失敗する
  ため、 同じ前提を共有 (= 通常の enterprise self-host では問題にならない)。
- **F79 fix**: db-bootstrap 後、 **`sbomhub_app` role で実際に `tenants` を
  SELECT** して count が取れることを最終確認する。 db-bootstrap success だけ
  では検出できない drift (table ACL race / restored secrets と postgres role
  password の乖離) を捕捉する。 接続には `docker/secrets/postgres_app_password.txt`
  (Step 5/7 で復元済み) の値を `PGPASSWORD` で渡す。 失敗時は exit 1。
- Step 6/7 と 7/7 は compose file basename に `enterprise` が含まれる場合のみ
  実行される (standalone OSS compose は単一 role 構成のため不要)。
- 成功時は標準出力末尾に `Restore completed successfully` で始まる行
  (現在の完全 string は `Restore completed successfully (pg_restore + sanity +
  db-bootstrap + app role access checks passed).`) が出力される。
- ※要確認: `--single-transaction` は数十 GB 級の大規模 DB で WAL / memory
  圧迫を引き起こす可能性がある。 該当する規模で運用する場合は事前に
  staging で挙動確認のこと (後続 issue で transaction 分割オプションを検討予定)。
- **ENCRYPTION_KEY 復号 smoke test** (M5-5、 issue [#53](https://github.com/youichi-uda/sbomhub/issues/53)):
  `VERIFY_ENCRYPTION=1` と `VERIFY_DB_URL` を渡すと restore は **Step 8** として
  [`./scripts/verify-encryption.sh`](./scripts/verify-encryption.sh) を実行し、 復元された
  `ENCRYPTION_KEY` が DB の暗号化カラムを実際に復号できることを smoke 確認する。
  `VERIFY_DB_URL` には host から到達可能な DSN を明示すること。
  失敗 (exit 1/2/3) は **warning ログのみで restore 全体は continue** する (smoke posture)。
  ```bash
  VERIFY_ENCRYPTION=1 \
  VERIFY_DB_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable" \
      ./scripts/restore.sh /path/to/sbomhub-backup-YYYYMMDD-HHMMSS.tar.gz
  ```
  手動 spot check (restore 後の任意タイミングや、 鍵 rotation 後の最終確認) は:
  ```bash
  ENCRYPTION_KEY="$(cat secrets/encryption_key.txt)" \
      ./scripts/verify-encryption.sh --db-url "$DATABASE_URL"

  ./scripts/verify-encryption.sh \
      --key-file secrets/encryption_key.txt \
      --db-url "$DATABASE_URL"
  ```
  exit code 契約 / SHA256(plaintext)-only 出力 / column 切り替え (BYOK LLM key /
  issue_tracker_connections token) は [`docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) §4.5 を参照。
  plaintext そのものは stdout / log に一切出ない。

**Automation success detection (F68 fix 後)**:

自動化スクリプトが `restore.sh` の成功を判定する場合は、 **prefix-match** で
`Restore completed successfully` を検出すること。 **exact-match は使わない**
(F65 / F79 / F80 以降、 `(pg_restore + sanity + db-bootstrap + app role access
checks passed)` 等の operational detail が末尾に付与されており、 将来の fix で
追加情報が増える可能性もあるため、 exact string-match は false-negative になる)。

```bash
# OK: prefix-match (行頭から始まる success marker を grep)
./scripts/restore.sh /path/to/backup.tar.gz 2>&1 | tee restore.log
grep -q "^\[restore\] Restore completed successfully" restore.log || {
    echo "restore.sh did not emit success marker — abort automation" >&2
    exit 1
}

# NG: exact-match (operational detail で false-negative になる)
# grep -Fxq "[restore] Restore completed successfully." restore.log
```

### 5.4 offsite backup

backup tar (or .age) を S3 / GCS / Azure Blob に転送する場合、 server-side
encryption に頼らず **手元で age / GPG / KMS 暗号化してから** upload する
(二重防御)。 詳細は M4-4 docs §9.4 参照。

### 5.5 リストア訓練

backup を取るだけでは「実際に復元できる」 ことは保証されない。 **四半期に 1 回**
は staging 環境で restore.sh を回し、 復元後に api が起動 + Web UI から既存
データが見えることを確認する。 訓練で発見しがちな問題は M4-4 docs §9.6 参照。

### 5.6 ENCRYPTION_KEY rotation automation

`ENCRYPTION_KEY` rotation の公式手順は
[`../docs/encryption-key-rotation.md`](../docs/encryption-key-rotation.md) が
source of truth。 M6 issue
[#56](https://github.com/youichi-uda/sbomhub/issues/56) で
`apps/api/cmd/migrate-encryption` を実装済み。

enterprise compose での基本 flow:

```bash
export OLD_ENCRYPTION_KEY="$(cat secrets/encryption_key.txt)"
export NEW_ENCRYPTION_KEY="$(openssl rand -base64 32)"

# option 3: docker compose exec api 経由で migrate-encryption 実行 (recommended)
docker compose exec -T api \
  env OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
  /usr/local/bin/migrate-encryption --dry-run --report /tmp/dry-run.json

docker compose exec -T api \
  env OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
  /usr/local/bin/migrate-encryption \
    --apply \
    --report-input /tmp/dry-run.json \
    --report /tmp/apply.json

# docker/secrets/encryption_key.txt を NEW_ENCRYPTION_KEY に置換して api restart 後:
docker compose exec -T api \
  env OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
  /usr/local/bin/migrate-encryption \
    --verify \
    --report-input /tmp/dry-run.json \
    --report /tmp/verify.json
```

host shell から `go run` する場合は、先に `DATABASE_URL` を明示する。

```bash
# option 1: docker compose から env を抽出
DATABASE_URL="$(docker compose exec api printenv DATABASE_URL)"

# option 2: Docker secrets から DSN を組み立て
APP_PW="$(cat secrets/postgres_app_password.txt)"
DATABASE_URL="postgres://sbomhub_app:${APP_PW}@127.0.0.1:5432/sbomhub?sslmode=disable"

cd ../apps/api
export PATH=$PATH:/usr/local/go/bin
go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --dry-run \
  --report ../../migrate-encryption-dry-run.json

go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --apply \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-apply.json

# docker/secrets/encryption_key.txt を NEW_ENCRYPTION_KEY に置換して api restart 後:
go run ./cmd/migrate-encryption \
  --db-url "$DATABASE_URL" \
  --verify \
  --report-input ../../migrate-encryption-dry-run.json \
  --report ../../migrate-encryption-verify.json
```

推奨は option 3 の `docker compose exec -T api` 経由。 host shell の
`DATABASE_URL` は通常 export されていないため、 host で実行する場合だけ
option 1 または 2 を使う。

対象は `tenant_llm_config.encrypted_api_key` と
`issue_tracker_connections.auth_token_encrypted`。 `api_keys.key_hash` は一方向
ハッシュなので対象外。 tool は tenant ごとに
`app.current_tenant_id` を bind し、 FORCE RLS を bypass しない。
plaintext は memory 内だけに保持し、 stdout / log / temp file には出さない。

---

## 6. アップデート手順

```bash
cd /path/to/sbomhub
git pull

cd docker
docker compose -f docker-compose.enterprise.yml pull
docker compose -f docker-compose.enterprise.yml up -d
```

注意:

- **migration は API 起動時に自動適用** される。 但し major version bump や
  destructive migration を伴う release では事前に `./scripts/backup.sh` を取得すること。
- **Ollama image / model**: `docker compose ... pull` は image 更新のみ。
  既 pull 済 model はそのまま残る。 新 model に切り替えたい場合は
  `SBOMHUB_OLLAMA_MODEL` を変えて compose up すると `ollama-init` が新規 pull を行う。
- **secrets file は git に含まれない** ので、 git pull で上書きされる心配はない。

---

## 7. トラブルシューティング

### 7.1 Ollama out of memory

| 症状 | 原因 / 対処 |
|---|---|
| `docker compose logs ollama` に `cuda OOM` / `failed to allocate` | model サイズが VRAM を超えている。 量子化版に切替え (`qwen2.5-coder:7b-q4_K_M` 等) |
| host OOM killer で ollama が死ぬ | CPU-only 推論で system RAM 不足。 swap 追加 or model 縮小 |
| GPU が認識されない | NVIDIA Container Toolkit 未 install。 `docker-compose.enterprise.yml` の `deploy.resources.reservations.devices` を unconment + `nvidia-ctk runtime configure --runtime=docker` |

### 7.2 PostgreSQL connection refused

```bash
# postgres health check が PASS しているか
docker compose -f docker-compose.enterprise.yml ps postgres
# State 列が "healthy" になっているはず

# ログを確認
docker compose -f docker-compose.enterprise.yml logs postgres | tail -50

# 接続テスト (host から)
docker compose -f docker-compose.enterprise.yml exec postgres pg_isready -U sbomhub
```

`sbomhub-api` がまだ起動していない場合、 `depends_on: postgres: condition: service_healthy`
+ `depends_on: db-bootstrap: condition: service_completed_successfully`
で待機しているはず。 30 秒経っても connection refused なら以下の順で原因切り分け:

1. `docker compose ... ps db-bootstrap` で `Exited (0)` か (`Exited (1)` なら
   `docker compose ... logs db-bootstrap` で role 作成 SQL のエラーを確認、
   典型: `postgres_password.txt` の値が postgres initdb 後に変更されて
   bootstrap superuser 認証に失敗、 secrets を再生成して volume を破棄するか
   superuser password を `ALTER USER sbomhub WITH PASSWORD ...` で同期する)
2. postgres data volume の corruption を疑い、 `./scripts/backup.sh` で最新
   backup → volume 再作成 (`docker volume rm docker_postgres_data`) →
   `./scripts/restore.sh` で復元

### 7.3 ENCRYPTION_KEY check failed

```
ENCRYPTION_KEY が未設定または既知デフォルトです (未設定)。
```

- `secrets/encryption_key.txt` が存在するか
- file 末尾に改行が混入していないか (`wc -c secrets/encryption_key.txt` で確認、
  base64 32 byte なら 44 byte ちょうど)
- compose の secrets mount が effective か (`docker compose exec sbomhub-api ls -la /run/secrets/`)

### 7.4 LLM bench (M4-3) から接続失敗

M4-3 比較 bench harness は host から `http://localhost:11434` を叩く想定。

- enterprise compose は `127.0.0.1:11434:11434` で host bind しているので、
  host CLI から直接アクセス可能なはず
- もし bench を別 host から実行している場合、 SSH local-forward が必要
  (`ssh -L 11434:127.0.0.1:11434 sbomhub-host`)

### 7.5 secrets file が読めない

```
[sbomhub-api entrypoint] FATAL: required secret file not readable: /run/secrets/encryption_key
```

- host 側 `docker/secrets/encryption_key.txt` の permission が user(0)
  readable か (`chmod 600` でも root が読めれば OK、 docker daemon は root)
- secrets ディレクトリの owner が host root か (`ls -la docker/secrets/`)
- SELinux / AppArmor で deny されていないか (`audit.log` 参照)

### 7.6 db-bootstrap が Exited (1) で残る

`db-bootstrap` は **one-shot service** (`restart: "no"`) なので、 正常終了したら
`docker compose ps` には `Exited (0)` として残る。 これは正常。

`Exited (1)` で残る場合 (M4 Codex review #F76 関連):

- `docker compose logs db-bootstrap` で原因確認。 典型エラー:
  - `FATAL: required secret file not readable: /run/secrets/postgres_app_password` —
    secrets 不足、 §3.1 に従って 3 種全てを生成する
  - `psql: error: connection to server at "postgres" ... password authentication failed` —
    `postgres_password.txt` の値が initdb 完了後に変更されている。 一度 superuser
    で接続して `ALTER USER sbomhub WITH PASSWORD '<file 内の値>'` で同期するか、
    volume を破棄して再生成 (initdb 時に新 password で再 bootstrap される)
- 手動再実行: `docker compose -f docker-compose.enterprise.yml run --rm db-bootstrap`
- sbomhub-api は `db-bootstrap: condition: service_completed_successfully` に
  block されているため、 db-bootstrap が成功するまで起動しない (= production で
  superuser 接続のまま誤起動する事故が構造的に発生しない、 F72 fix と整合)

### 7.7 ollama-init が ループする / 完了しない

`ollama-init` は **one-shot service** (restart: "no") なので、 正常終了したら
`docker compose ps` には `Exited (0)` として残る。 これは正常。

`Exited (1)` で残る場合:

- `docker compose logs ollama-init` で原因確認 (典型: ネットワーク不通で model pull 失敗)
- 手動再実行: `docker compose -f docker-compose.enterprise.yml run --rm ollama-init`

---

## 8. 詳細 security guide

本 README は enterprise compose 固有の運用手順に絞る。 以下のテーマは
M4-4 の [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) を参照:

| テーマ | 章 |
|---|---|
| 配布形態オプション (Docker Compose / Kubernetes / bare-metal) | §2 |
| PostgreSQL RLS / DB role 分離 | §3 |
| ENCRYPTION_KEY 運用 | §4 |
| Docker Secrets / .env 管理 | §5 |
| TLS termination (Caddy / nginx / Cloudflare Tunnel) | §6 |
| firewall / network 分離 | §7 |
| Log retention / SBOMHUB_LLM_AUDIT_STORE_RESPONSE | §8 |
| backup / restore 詳細 | §9 |
| healthcheck / sbomhub doctor | §10 |
| Local LLM (Ollama) 構成詳細 | §11 |
| インシデント対応 | §12 |

---

## 関連

- [`docker-compose.enterprise.yml`](docker-compose.enterprise.yml) — 本 compose 本体
- [`secrets.example/README.md`](secrets.example/README.md) — secrets 構成詳細
- [`scripts/backup.sh`](scripts/backup.sh) / [`scripts/restore.sh`](scripts/restore.sh) — backup 運用 script
- [`../docs/security/self-host-deployment.md`](../docs/security/self-host-deployment.md) — M4-4 セルフホストセキュリティ運用ガイド
- [`../docs/encryption-key-rotation.md`](../docs/encryption-key-rotation.md) — 鍵 rotation ランブック
- [`../CLAUDE.md`](../CLAUDE.md) — リポジトリ運営ガイドライン + LLM Provider Policy
- 関連 issue: [#49](https://github.com/youichi-uda/sbomhub/issues/49) (M4-6)
