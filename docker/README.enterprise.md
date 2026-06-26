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
| DB password | dev hardcode | **Docker secrets** |
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

> ※要確認: `backend` network は `internal: false` (**outbound egress あり**)
> で運用する。 これは ollama-init が起動時に `ollama pull` で
> `registry.ollama.ai` に到達する必要があるため、 また postgres / redis / api
> の image pull 自体も `registry.docker.io` / `ghcr.io` 等への outbound に
> 依存するため。 `internal: true` (=外部から完全遮断 + 内部から外部も遮断) に
> 切り替えると初回起動が image pull 段階で失敗する。
>
> outbound を厳しく絞りたい環境では、 docker 内部の `internal: true` ではなく
> **host 側 firewall (iptables / nftables) や egress proxy (Squid /
> Cloudflare Gateway)** で `registry.docker.io` / `registry.ollama.ai` /
> `ghcr.io` などのみ allow する構成を推奨する。 詳細は
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

```bash
cd docker
cp -r secrets.example secrets

# ENCRYPTION_KEY (32 byte 必須、 末尾改行は除く)
openssl rand -base64 32 | tr -d '\n' > secrets/encryption_key.txt

# PostgreSQL password (base64 推奨、 special char escape の事故を避ける)
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_password.txt

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
3. `sbomhub-api` が migration 適用 + server 起動 (数秒)
4. `sbomhub-web` が静的アセット展開 + Next.js 起動 (数秒)

進捗確認:

```bash
# 全体の状態
docker compose -f docker-compose.enterprise.yml ps

# Ollama pull 進捗 (一番時間がかかる)
docker compose -f docker-compose.enterprise.yml logs -f ollama-init

# API server 起動 log (ENCRYPTION_KEY / DB role check)
docker compose -f docker-compose.enterprise.yml logs -f sbomhub-api
```

### 3.4 production 向け: RLS ロール分離 (強く推奨)

default 状態では PostgreSQL の `sbomhub` ロール (POSTGRES_USER) を使うが、
M4-4 docs §3 で説明されている **RLS bypass を防ぐための 2 ロール分離**
(`sbomhub_app` / `sbomhub_migrator`) を有効化することを **強く推奨** する。

手順:

```bash
# 1. 追加 secrets を生成
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_app_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_migrator_password.txt
chmod 600 secrets/postgres_*_password.txt

# 2. 既存 postgres コンテナにロールを bootstrap (install.sh を流用)
#    ※要確認: install.sh は OSS compose を前提に書かれているため、 enterprise
#    compose 上で実行する場合は --bootstrap-roles を直接呼び出す前に
#    docker compose の project 名 / postgres service 名が一致しているか確認。
cd ..
./install.sh --bootstrap-roles
cd docker

# 3. docker-compose.enterprise.yml の sbomhub-api.environment を編集:
#      POSTGRES_APP_USER:                "sbomhub_app"
#      POSTGRES_MIGRATOR_USER:           "sbomhub_migrator"
#      POSTGRES_APP_PASSWORD_FILE:       "/run/secrets/postgres_app_password"
#      POSTGRES_MIGRATOR_PASSWORD_FILE:  "/run/secrets/postgres_migrator_password"
#    secrets: ブロックにも postgres_app_password / postgres_migrator_password を追加。

# 4. 再起動
docker compose -f docker-compose.enterprise.yml up -d --force-recreate sbomhub-api

# 5. 起動 log で sbomhub_app の bypass_rls=false を確認
docker compose -f docker-compose.enterprise.yml logs sbomhub-api | grep 'DB role check'
# 期待: "DB role check passed role=sbomhub_app bypass_rls=false"
```

※要確認: 上記 step 3 で `*_PASSWORD_FILE` を 2 種類の secret に振り分ける編集は
M4-6 では手動。 後続 issue で `docker-compose.enterprise.rls.yml` (override 用)
を別 file として用意するか、 単一 compose 内で profile 切替えする案を検討予定。

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

### 5.4 offsite backup

backup tar (or .age) を S3 / GCS / Azure Blob に転送する場合、 server-side
encryption に頼らず **手元で age / GPG / KMS 暗号化してから** upload する
(二重防御)。 詳細は M4-4 docs §9.4 参照。

### 5.5 リストア訓練

backup を取るだけでは「実際に復元できる」 ことは保証されない。 **四半期に 1 回**
は staging 環境で restore.sh を回し、 復元後に api が起動 + Web UI から既存
データが見えることを確認する。 訓練で発見しがちな問題は M4-4 docs §9.6 参照。

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
で待機しているはず。 30 秒経っても connection refused なら postgres data volume
の corruption を疑い、 `./scripts/backup.sh` で最新 backup → volume 再作成
(`docker volume rm docker_postgres_data`) → `./scripts/restore.sh` で復元。

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

### 7.6 ollama-init が ループする / 完了しない

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
