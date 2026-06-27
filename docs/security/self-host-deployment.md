# SBOMHub セルフホスト セキュリティ運用ガイド

> **Status**: M4-4 (Self-host security guide for manufacturers) で作成された初版。
> 対象は SBOMHub OSS (AGPL-3.0) を自社環境で動かす製造業 IT 部門 + 自社 PSIRT。
> 関連 issue: [#46](https://github.com/youichi-uda/sbomhub/issues/46)。
>
> 既存の鍵ローテーション手順は [`../encryption-key-rotation.md`](../encryption-key-rotation.md) に独立した
> ランブックとして存在する。 本ガイドは「初期構築 + 継続運用 + インシデント対応」までを通しで
> 扱い、 鍵ローテーションの詳細はそちらへ送る。

---

## 1. 対象読者

本ガイドは次の 2 つの役割を主読者として想定する。

- **製造業 IT 部門 (Self-host 運用主担当)** — Docker / Linux / PostgreSQL の基礎運用ができる前提。
  SBOMHub を社内ネットワークに立て、 開発チームから SBOM をアップロードさせ、 脆弱性レビューと VEX
  起票を回す日常運用を担う。
- **自社 PSIRT (Product Security Incident Response Team) / セキュリティ責任者** — EU CRA
  (Cyber Resilience Act) 報告義務、 経産省 SBOM 手引、 NIST SSDF への準拠監査と、 インシデント
  発生時の即時対応 (鍵漏洩 / DB 侵害 / LLM 出力異常 等) を担う。

想定する前提知識:

- Docker / Docker Compose の基本操作 (`docker compose up -d`, `docker compose exec`)。
- Linux のサービス管理 (`systemd`, `ufw`, OS user / group 分離)。
- PostgreSQL の役割 / 権限モデル (`CREATE ROLE`, `GRANT`, RLS = Row-Level Security)。
- TLS (Transport Layer Security) 終端、 reverse proxy、 firewall の一般知識。
- BYOK (Bring Your Own Key) の意味 — SBOMHub OSS は LLM API key を **同梱しない**、
  運用者が OpenAI / Anthropic / Google Gemini / Azure OpenAI / Local Ollama いずれかの key を
  自分で設定する方針 ([`../../CLAUDE.md`](../../CLAUDE.md) LLM Provider Policy 参照)。

本ガイドは「製造業 IT 部門の現場担当者がコピペで実行できる」粒度を目指す。 高度な PKI / KMS / Vault
構成は概念紹介 + 公式ドキュメント link に留め、 詳細は別文書化する。

---

## 2. 配布形態オプション

SBOMHub OSS は 3 種類の配布形態に対応する。 製造業現場では **Docker Compose** が圧倒的に推奨される。

### 2.1 Docker Compose (推奨)

- ルート [`docker-compose.yml`](../../docker-compose.yml) を `curl` で取得して `./install.sh --start`
  一発で起動する OSS 標準パス。
- `install.sh` が自動で以下を行う:
  - `.env` 生成 + `openssl rand -base64 32` で `ENCRYPTION_KEY` 払い出し
  - `sbomhub_app` / `sbomhub_migrator` ロール作成 (ランダム password)
  - `docker compose up -d --wait postgres` → ロール bootstrap → 全 service 起動
- 製造業 IT 部門向けには、 OSS 標準 compose とは独立した
  [`../../docker/docker-compose.enterprise.yml`](../../docker/docker-compose.enterprise.yml) を
  M4-6 で同梱済。 Ollama (Local LLM) + Docker secrets + `127.0.0.1` only バインド + backend/frontend
  network 分離を 1 ファイルにまとめた enterprise 向け変種で、 起動 / 運用手順は
  [`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) を参照。
  本ガイド §11.4 にも本書側からの起動例を整理してある。

### 2.2 Kubernetes

- 公式 manifest / Helm chart は **未提供**。 OSS image (`y1uda/sbomhub-api:latest`,
  `y1uda/sbomhub-web:latest`) から自作可能。
- PostgreSQL は managed (RDS / Cloud SQL) または StatefulSet で構築するが、 **§3 の RLS role 分離
  (`sbomhub_migrator` / `sbomhub_app`) は必須**。 これを省くと multi-tenant 分離が崩壊する。
- 鍵 (`ENCRYPTION_KEY`, DB password, BYOK LLM API key) は Kubernetes Secret + KMS (AWS Secrets
  Manager / Google Secret Manager / Azure Key Vault) で管理することを強く推奨する。

  > **TODO**: K8s manifest sample (StatefulSet + Service + Secret) は本ガイドの scope 外。
  > 別 issue で sample を作成し、 ここから link 予約。

### 2.3 bare-metal (Linux 直接インストール)

- Go binary (`apps/api/cmd/server`) と Next.js standalone build を OS service (systemd) として
  起動し、 PostgreSQL / Redis は OS パッケージで構築する形態。
- 利点: Docker レイヤーを挟まないので攻撃面が薄い、 既存の社内 PostgreSQL クラスタを再利用できる。
- 欠点: アップグレードが手動、 dependency drift のリスク、 Ollama 同梱や reverse proxy 配線も
  自前。
- 推奨設定:
  - SBOMHub 用 OS user (`sbomhub:sbomhub`) を作成し、 binary 実行はこの user に閉じる。
  - PostgreSQL は **`pg_hba.conf` で local socket + scram-sha-256** に限定。
  - `.env` は `/etc/sbomhub/env` 配置で `chmod 600`、 owner は `sbomhub:sbomhub`。
- bare-metal で OSS image を再構築する場合、 [Dockerfile](../../apps/api/Dockerfile) と
  [docker-compose.yml](../../docker-compose.yml) を参考に Go build フラグ + 静的リンクの
  確認を行うこと。

---

## 3. PostgreSQL RLS / DB role 分離

SBOMHub は **multi-tenant** 製品で、 同一 DB 内に複数テナントの SBOM / 脆弱性 / VEX が同居する。
テナント分離は PostgreSQL の RLS (Row-Level Security) で強制する。 RLS を効かせるために、
DB role を **2 段** に分離する。

### 3.1 ロール構成 (M0 Trust Rescue 9.1 で導入)

| ロール | 役割 | 権限 | 接続経路 |
|---|---|---|---|
| `sbomhub_migrator` | スキーマ migration (DDL 適用) を行う一時接続 | `CREATEDB`, `CREATEROLE`, テーブル所有者、 RLS bypass **なし** (`NOBYPASSRLS`) | `MIGRATE_DATABASE_URL` (起動時のみ open → migration 後 close) |
| `sbomhub_app` | アプリ runtime の全クエリを行う長期接続 | `SELECT/INSERT/UPDATE/DELETE` のみ、 **`NOSUPERUSER` AND `NOBYPASSRLS` 必須** | `DATABASE_URL` |
| `sbomhub` (POSTGRES_USER) | DB owner / superuser-equivalent | 上記 2 ロールの bootstrap にのみ使う、 runtime では使わない | 通常は使わない (install.sh / `db-bootstrap` が docker compose exec 経由でのみ利用) |

実装根拠:
[apps/api/migrations/023_rls_security_hardening.up.sql](../../apps/api/migrations/023_rls_security_hardening.up.sql)
で RLS policy を全 tenant-scoped テーブルに enable + force し、 `apps/api/cmd/server/main.go` の
`assertAppRoleNotBypassRLS` (decision branch は `evaluateAppRoleRLS`) が起動時に
**`rolbypassrls=false` AND `rolsuper=false`** の両方を確認する (M4 Codex review #F72)。
PostgreSQL superuser は `rolbypassrls` の値に関わらず常に RLS を bypass するため、
**`rolsuper=true` も `rolbypassrls=true` と同等に reject** する必要がある (PostgreSQL 公式
ドキュメント "Superusers and roles with the BYPASSRLS attribute always bypass the row
security system." 準拠)。 production / staging では `rolsuper` または `rolbypassrls` のいずれかが
true だと **起動を拒否** し、 development だけ warning に downgrade する。

ロール属性の自動セットアップは 2 経路あり、 SQL pattern は **byte-for-byte で convergent** に
保たれている (M4 Codex review #F76 / #F77):

- **`docker/docker-compose.enterprise.yml`** の `db-bootstrap` one-shot service が
  enterprise compose 起動時に自動で `sbomhub_app` (`NOSUPERUSER NOBYPASSRLS`) /
  `sbomhub_migrator` (`NOBYPASSRLS`) を冪等作成 + 属性 re-assert する。
- **`./install.sh --bootstrap-roles`** は OSS 標準 compose や手動復旧シナリオ向けの
  advanced recovery path で、 既存ロールの属性が drift していた場合 (例: ad-hoc debugging
  で SUPERUSER に promote されたまま) も `ALTER ROLE ... NOSUPERUSER NOBYPASSRLS` で
  再矯正する。 db-bootstrap と同じ SQL pattern を使うため、 どちらの経路を経由しても
  最終的なロール属性は同一になる。

### 3.2 ロール状態の確認 SQL

self-host を引き継いだ際 (or アップグレード後)、 まず以下で現状確認する。

```sql
-- 1. app / migrator ロールが存在し、 superuser でないこと
SELECT rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
  FROM pg_roles
 WHERE rolname IN ('sbomhub_migrator', 'sbomhub_app', 'sbomhub');

-- 期待:
--   sbomhub_migrator : super=f, bypass=f, createdb=t, createrole=t
--   sbomhub_app      : super=f, bypass=f, createdb=f, createrole=f
--   sbomhub          : super=t (POSTGRES_USER、 bootstrap 用)
```

```sql
-- 2. tenant-scoped テーブルに RLS policy が貼られていること
SELECT schemaname, tablename, policyname, cmd, qual
  FROM pg_policies
 WHERE schemaname = 'public'
 ORDER BY tablename, policyname;

-- 期待: projects / sboms / components / vulnerabilities / vex_statements /
--       llm_calls 等 tenant-aware な主要テーブルに tenant_isolation policy が
--       存在し、 USING 句に current_setting('app.current_tenant_id') の
--       比較が入っていること。
```

```sql
-- 3. RLS が実際に効くこと (sbomhub_app ロールで接続して確認)
-- psql ... -U sbomhub_app ...
BEGIN;
SET LOCAL app.current_tenant_id = '00000000-0000-0000-0000-000000000000';  -- 無効な UUID
SELECT count(*) FROM projects;  -- 0 が返るはず (どのテナントにも一致しない)
ROLLBACK;
```

### 3.3 もし `sbomhub_app` が superuser / BYPASSRLS だったら

これは **即時修正対象** (重大インシデント)。 `rolsuper=true` または `rolbypassrls=true` の
いずれか一方でも該当すれば multi-tenant 分離が崩壊しており (F72 contract に従い production /
staging では起動拒否、 development では warning のみ)、 他テナントの SBOM が見える可能性が
ある。

応急処置 (どちらか一方でも検知したら両方の属性を同時に矯正する):

```sql
-- psql ... -U sbomhub ...  (superuser で接続)
ALTER ROLE sbomhub_app NOSUPERUSER NOBYPASSRLS;
-- ALTER ROLE ... LOGIN は付いていれば残す。
```

もしくは、 `./install.sh --bootstrap-roles` を実行することで上記 `ALTER ROLE` を冪等に
再投入できる (F77 fix 後、 install.sh の SQL pattern は db-bootstrap と一致しており、
既存ロールに対しても `NOSUPERUSER NOBYPASSRLS` を re-assert する)。 enterprise compose
を使っている環境では `db-bootstrap` service を再実行 (`docker compose -f
docker-compose.enterprise.yml up -d --force-recreate db-bootstrap`) しても同じ効果。

その後 API を再起動し、 起動 log に
`DB role check passed role=sbomhub_app bypass_rls=false superuser=false` が出ることを
確認する (`apps/api/cmd/server/main.go` の `assertAppRoleNotBypassRLS` /
`evaluateAppRoleRLS`)。 失敗時は
`RLS startup guard FAIL: current DB user "sbomhub_app" has rolbypassrls=... rolsuper=...`
の形で reject される。

### 3.4 migration とアプリ runtime の分離

OSS 標準 [docker-compose.yml](../../docker-compose.yml) は以下のように 2 つの URL を分けて渡す。

```yaml
environment:
  - DATABASE_URL=postgres://sbomhub_app:${APP_PASSWORD}@postgres:5432/sbomhub?sslmode=disable
  - MIGRATE_DATABASE_URL=postgres://sbomhub_migrator:${MIGRATOR_PASSWORD}@postgres:5432/sbomhub?sslmode=disable
```

bare-metal や Kubernetes でも **必ず両方を設定** し、 migration と runtime で異なる role を使う。
これを 1 本化すると runtime ロールに DDL 権限が漏れて RLS bypass のリスクが上がる。

---

## 4. ENCRYPTION_KEY 運用

`ENCRYPTION_KEY` は SBOMHub が DB 内の機密データを application-level で暗号化する **マスタ鍵**。

### 4.1 用途 (鍵で守られているデータ)

| データ | 用途 | 暗号化スキーム |
|---|---|---|
| `issue_tracker_connections.auth_token_encrypted` | Jira / Backlog 連携トークン | AES-256-GCM (12-byte random nonce、 base64 store) |
| (M1 以降) BYOK LLM API key | OpenAI / Anthropic / Gemini / Azure / Ollama 設定 | 同上 (`LLM_PROVIDER_DESIGN.md` §7.1) |
| (将来) audit_logs の機密フィールド | M0 Trust Rescue 9.2 で議論あり、 段階導入 | 同上 |

参考: [`../encryption-key-rotation.md`](../encryption-key-rotation.md) §2.1 (現時点で暗号化対象の
全カラムを列挙)。

### 4.2 生成

```bash
openssl rand -base64 32
# → 例: V5jgaCSCV/Mdf8JbVX42aWYAB6dG1Dp9G9Bo0Nw+qjY=  (44 文字 base64、 raw 32 byte)
```

raw 32 byte は AES-256 が要求する鍵長。 base64 encode で 44 文字になる。

> **Note: ENCRYPTION_KEY semantics**
>
> `openssl rand -base64 32` は 44 文字の base64 文字列を出力する。 SBOMHub は
> この文字列を **AES key そのもの** として扱い、 base64 decode せずに
> **文字列の先頭 32 raw byte** を使用する。 base64 encoding は shell でコピーしやすくする
> transport convenience であり、 key derivation function ではない。
>
> Operator implications:
> - key を保存する前に base64 decode しない。
> - 32 文字の ASCII string も鍵として動作する (runtime は先頭 32 byte をそのまま使う)。
> - migrate-encryption / decrypt-test も同じ semantics を使うため、 encrypted column は
>   これらの tool 間で同一に再現される。

### 4.3 起動時 refusal

`apps/api/cmd/server/main.go` の `validateEncryptionKey` は以下のいずれかで **起動を拒否** する
(production / staging のみ; development では warning に downgrade):

- `ENCRYPTION_KEY` が **未設定** (`""`)
- 長さが **32 byte 未満**
- 値が `knownDefaultEncryptionKeys` リスト (`changeme`, `default`, 過去に bundled した default 鍵
  3 種等) に **完全一致**

エラーメッセージ例:

```
ENCRYPTION_KEY が未設定または既知デフォルトです (未設定)。
`openssl rand -base64 32` で生成して .env / 環境変数に設定してください
(APP_ENV="production")
```

これは **意図的な fail-loud 設計**。 「うっかり default 鍵のまま production が起動して機密データを
偽暗号化する」 事故を起動時点で潰すための M0 Trust Rescue 9.2 の成果物。

### 4.4 ローテーション

90 日に 1 回の routine rotation、 personnel change 時、 漏洩疑い時の immediate rotation 手順は
[`../encryption-key-rotation.md`](../encryption-key-rotation.md) に独立したランブックがある。
本ガイドからは要点のみ:

- ローテーションには **旧鍵と新鍵の両方** が必要 (旧鍵で復号 → 新鍵で再暗号化)。 旧鍵を失うと
  暗号化済みカラムは復元不能。
- DB dump を **取ってから** 開始すること。
- `install.sh --force` は `.env` 全体 + DB password も rotate するので、 ENCRYPTION_KEY だけ
  rotate したい場合は **`.env` を手編集** する (詳細は ranbook §3 step 4)。
- 一時的に API を停止する短時間メンテナンスウィンドウが必要。

> **Prerequisites for §4.5 and §9.x**
>
> The operational scripts referenced below (`docker/scripts/backup.sh`,
> `docker/scripts/restore.sh`, `docker/scripts/verify-encryption.sh`,
> `docker/scripts/verify-encryption-cron.sh`) are downloaded automatically
> by `./install.sh --start` (M6 #56 F120 fix). If you installed via a
> different path, ensure these scripts are present at the documented
> paths before following the runbook examples.
>
> Manual download example:
>
> ```bash
> mkdir -p docker/scripts
> for s in backup.sh restore.sh verify-encryption.sh verify-encryption-cron.sh; do
>   curl -fsSL "https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker/scripts/$s" \
>     -o "docker/scripts/$s"
>   chmod +x "docker/scripts/$s"
> done
> ```

### 4.5 復号 smoke test (`verify-encryption.sh`)

ENCRYPTION_KEY が **実際に DB を復号できる** ことを確認する smoke test として
[`../../docker/scripts/verify-encryption.sh`](../../docker/scripts/verify-encryption.sh) (M5-5、
issue [#53](https://github.com/youichi-uda/sbomhub/issues/53)) を同梱する。

**使い所**:

| シナリオ | コマンド |
|---|---|
| restore 直後の自動 smoke (Step 8) | `VERIFY_ENCRYPTION=1 VERIFY_DB_URL="$DATABASE_URL" ./docker/scripts/restore.sh backup.tar.gz` |
| 手動 spot check (BYOK LLM key カラム) | `export DATABASE_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable"; ENCRYPTION_KEY="$(cat ./docker/secrets/encryption_key.txt)" ./docker/scripts/verify-encryption.sh` |
| 手動 spot check (key file 経由) | `export DATABASE_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable"; ./docker/scripts/verify-encryption.sh --key-file ./docker/secrets/encryption_key.txt` |
| 手動 spot check (issue tracker token) | `export DATABASE_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable"; ENCRYPTION_KEY="$(cat ./docker/secrets/encryption_key.txt)" ./docker/scripts/verify-encryption.sh --table issue_tracker_connections --column auth_token_encrypted` |
| 日次 drift check | 下記 cron / systemd timer 例のように `DATABASE_URL` と key path を明示して実行する |

cron 環境は通常の login shell と異なり、 `.env` や shell profile を自動では読まない。
[`../../docker/scripts/verify-encryption-cron.sh`](../../docker/scripts/verify-encryption-cron.sh) は
`docker/secrets/postgres_app_password.txt` から `DATABASE_URL` を組み立て、 `--key-file` で
`docker/secrets/encryption_key.txt` を渡す。 stdout/stderr は syslog に記録しつつ、
`verify-encryption.sh` の exit code (1=key mismatch, 2=db error, 3=no rows, 64=usage, 65=prereq) を
cron / systemd timer 側へそのまま返す。

`DATABASE_URL` は既存の `docker/secrets/postgres_app_password.txt` から組み立てる。 専用の DSN secret
file は不要。 password に `+`, `/`, `=`, `@`, `:`, `?`, `#`, `&` などが含まれる場合に備え、 wrapper は
F106 と同じ `urlenc` helper を使う。 Python runtime は不要。

```bash
sudo install -m 755 -o root -g root \
  docker/scripts/verify-encryption-cron.sh \
  /opt/sbomhub/docker/scripts/verify-encryption-cron.sh
```

```cron
# /etc/cron.d/sbomhub-verify-encryption
# Nightly decrypt smoke test. Preserves exit code from
# verify-encryption.sh (1=key mismatch, 2=db error, 3=no rows, 64=usage, 65=prereq).
# Failure surfaces via cron mail + syslog.
0 4 * * * sbomhub /opt/sbomhub/docker/scripts/verify-encryption-cron.sh
```

cron では failure を systemd の非標準通知 subcommand に渡さない。 wrapper は
stdout/stderr を `logger` 経由で syslog に送り、 exit code は cron mail、 exit-code monitoring、 または
監視 agent で拾う。

継続運用では、 cron より systemd timer + service + `OnFailure` handler を推奨する。 systemd では
`.env` 全体を `EnvironmentFile` に指定しない。 `.env` には `MIGRATE_DATABASE_URL`, `APP_PASSWORD`,
`MIGRATOR_PASSWORD`, `ENCRYPTION_KEY` など verify に不要な secrets が含まれ、 同一 user/root から
`/proc/<pid>/environ` 経由で読める可能性がある。 verify 専用の最小 env file を作り、 service の env には
`DATABASE_URL` だけを入れる。 `ENCRYPTION_KEY` は `--key-file` で読み、 process environment へ置かない。

```bash
# 初回 setup (root or sudo)
install -d -m 700 -o sbomhub -g sbomhub /etc/sbomhub

urlenc() {
  printf '%s' "$1" | sed -e 's/%/%25/g' -e 's/+/%2B/g' -e 's|/|%2F|g' -e 's/=/%3D/g' -e 's/@/%40/g' -e 's/:/%3A/g' -e 's/?/%3F/g' -e 's/#/%23/g' -e 's/&/%26/g'
}

APP_PW="$(cat /opt/sbomhub/docker/secrets/postgres_app_password.txt)"
APP_PW_ENC="$(urlenc "$APP_PW")"
echo "DATABASE_URL=postgres://sbomhub_app:${APP_PW_ENC}@127.0.0.1:5432/sbomhub?sslmode=disable" | \
  install -m 600 -o sbomhub -g sbomhub /dev/stdin /etc/sbomhub/verify-encryption.env
```

> Warning: systemd service の `EnvironmentFile` に `/opt/sbomhub/.env` は使わない。 verify に不要な secrets を service の
> environment に載せ、 `/proc/<pid>/environ` exposure を広げる。

```ini
# /etc/systemd/system/sbomhub-verify-encryption.service
[Unit]
Description=SBOMHub ENCRYPTION_KEY smoke test
OnFailure=sbomhub-verify-encryption-failure.service

[Service]
Type=oneshot
WorkingDirectory=/opt/sbomhub
EnvironmentFile=/etc/sbomhub/verify-encryption.env
ExecStart=/opt/sbomhub/docker/scripts/verify-encryption.sh \
  --key-file /opt/sbomhub/docker/secrets/encryption_key.txt
User=sbomhub
```

default の failure handler は、 site-wide monitor agent が拾えるよう syslog へ `daemon.err` で記録する。
通知が必要な site では、下の alternative のように mail、 Slack、 webhook などへ置き換える。

```ini
# /etc/systemd/system/sbomhub-verify-encryption-failure.service
# Default: log to syslog with daemon.err priority for site-wide monitor agents.
# Override for site-specific notify (mail / Slack / webhook) below.
[Service]
Type=oneshot
ExecStart=/usr/bin/logger -p daemon.err -t sbomhub-verify "service failure detected"
```

```ini
# alternative: mail (requires mailutils / bsd-mailx installed)
# ExecStart=/bin/sh -c 'echo "sbomhub verify-encryption failed at $(date)" | mail -s "[sbomhub] verify-encryption fail" oncall@example.com'

# alternative: Slack webhook (requires curl)
# ExecStart=/usr/bin/curl -fsS -X POST -H 'Content-Type: application/json' \
#   -d '{"text": "sbomhub verify-encryption failed"}' \
#   https://hooks.slack.com/services/T000/B000/SECRET_TOKEN

# alternative: generic webhook (requires curl)
# ExecStart=/usr/bin/curl -fsS -X POST -H 'Content-Type: text/plain' \
#   -d 'sbomhub verify-encryption failed' \
#   https://monitor.example.com/sbomhub-verify-failure
```

```ini
# /etc/systemd/system/sbomhub-verify-encryption.timer
[Unit]
Description=Run SBOMHub encryption decrypt smoke test daily

[Timer]
OnCalendar=*-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

実行結果は次で確認する。

```bash
systemctl daemon-reload
systemctl enable --now sbomhub-verify-encryption.timer
journalctl -u sbomhub-verify-encryption.service
```

**動作**:

1. DB に接続して、 対象カラムから encrypted row を 1 件 SELECT。
2. ENCRYPTION_KEY (env or `--key-file`) で AES-256-GCM 復号を試行 (`apps/api/cmd/decrypt-test`
   バイナリ経由、 内部で `internal/service/llm.Decrypt` を呼ぶ — production API 本体と
   **同じ復号ロジック**)。
3. 成功時は **SHA256(plaintext)** だけ stdout に印字し exit 0。 plaintext 本体は
   ログにも stdout にも一切出ない。
4. 失敗時は exit code で分類:

   | exit | 意味 |
   |---|---|
   | 0 | ok (復号成功、 SHA256 印字) |
   | 1 | 鍵不一致 / ciphertext 破損 (GCM auth tag 失敗) |
   | 2 | DB error (DSN, role 権限不足) |
   | 3 | encrypted row 不在 (setup 未完 / 別 table を試すよう案内) |
   | 64 | usage error (flag 不正) |
   | 65 | 事前準備不足 (Go toolchain / DECRYPT_TEST_BIN 不在) |

**security 注意**:

- ENCRYPTION_KEY は env (`ENCRYPTION_KEY=...`) または `--key-file <path>` で渡す。 argv
  (`--key ...`) は `/proc/<pid>/cmdline` / `ps` 経由で見えやすいため deprecated。
  `--key-file` は `decrypt-test` へ path を pass-through し、 Go binary が raw file bytes
  を直接読む。 末尾 newline も key material として保持される。
- plaintext は **印字されない**。 復号成功 / 失敗の判定はこの script の exit code で行う。
  鍵 rotation では、 DB ciphertext を上書きする前に旧鍵で SHA256 を記録し、
  上書き後に新鍵で出した SHA256 と比較する。 Step 5 後の ciphertext は旧鍵で
  復号できないのが正常なので、 旧鍵で post-rotation rerun しない。 詳細な手順は
  [`../encryption-key-rotation.ja.md`](../encryption-key-rotation.ja.md) §3 Step 2.5 / Step 6 を参照。

### 4.6 鍵の保管先

`.env` 平文に書く方式は最も簡単だが、 中長期的には外部 secret store に逃がすことを推奨する。

| 保管先 | 利点 | 欠点 | 適用場面 |
|---|---|---|---|
| **`.env` 平文 (`chmod 600`)** | 設定不要、 install.sh が自動生成 | host disk への直書きでバックアップに紛れ込みやすい | 小規模 PoC / 単一ホスト |
| **Docker Secrets** (`docker-compose.yml` の `secrets:`) | tmpfs マウント、 image レイヤーに残らない | docker swarm 推奨、 単体 compose では一部制限 | compose 運用での標準推奨 |
| **AWS KMS / Secrets Manager** | IAM 統合 + audit 統一、 envelope encryption | AWS lock-in、 起動 wrapper が必要 | AWS で運用する enterprise |
| **GCP Secret Manager / Cloud KMS** | 同上 (GCP) | 同上 | GCP で運用する enterprise |
| **Azure Key Vault** | 同上 (Azure) | 同上 | Azure で運用する enterprise |
| **HashiCorp Vault** | クラウド非依存、 dynamic secret / sidecar 統合 | 自前 Vault クラスタの運用負荷 | マルチホスト、 マルチクラウド |
| **OS keychain** (Linux Secret Service / macOS Keychain) | OS 統合 | container 外、 multi-host 不適 | 開発機 (PoC) のみ |

> **TODO**: KMS 系 (AWS / GCP / Azure) との直接統合コードは現状 SBOMHub 本体には無い。
> 一般的なパターンは「コンテナ起動 entrypoint で KMS から鍵を取得 → `ENCRYPTION_KEY` 環境変数に
> 注入 → api 本体を exec」 という wrapper script を挟む。 別 issue でレシピを作成予定。

---

## 5. Docker Secrets / .env 管理

### 5.1 .env をリポジトリにコミットしない

`sbomhub` リポジトリは `.env.example` のみを公開し、 実 `.env` は git ignore 済み。
clone 後の最初の install で生成されるが、 確認するには:

```bash
git check-ignore -v .env
# → .gitignore:NN:.env    .env
# (が出力されれば ignore 設定済み)

git ls-files .env
# → 何も出力されないこと (= tracked でない)
```

もし誤って `.env` を commit してしまった場合は、 **その時点で鍵漏洩扱い** で
§12 (インシデント対応) の鍵ローテーション + 全 BYOK key revoke を実行する。
git history からの削除 (`git filter-repo` 等) では「他者が clone していない保証」 にはならない。

### 5.2 Docker Secrets パターン

Docker swarm 環境では `secrets:` を使うことで、 鍵を host disk に書かず tmpfs マウントできる。
M4-6 で同梱した [`../../docker/secrets.example/`](../../docker/secrets.example/) に sample file
(`encryption_key.txt.sample` / `postgres_password.txt.sample`) があるので、 `cp -r secrets.example
secrets` → `openssl rand -base64 32 > secrets/encryption_key.txt` の流れで初期化する。 完全な
手順は [`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §3.1 を参照。

```yaml
# docker-compose.yml (swarm mode)
services:
  api:
    image: y1uda/sbomhub-api:latest
    secrets:
      - encryption_key
      - app_db_password
      - openai_api_key
    environment:
      # コンテナ内で /run/secrets/<name> から読む形に entrypoint で展開
      - ENCRYPTION_KEY_FILE=/run/secrets/encryption_key
      - SBOMHUB_LLM_API_KEY_FILE=/run/secrets/openai_api_key

secrets:
  encryption_key:
    file: ./secrets/encryption_key.txt
  app_db_password:
    file: ./secrets/app_db_password.txt
  openai_api_key:
    file: ./secrets/openai_api_key.txt
```

> **Note**: `apps/api` 本体は `*_FILE` パターンを直接サポートしていないが、 M4-6 で同梱した
> [`../../docker/docker-compose.enterprise.yml`](../../docker/docker-compose.enterprise.yml) の
> `api` service が entrypoint wrapper (`sh -c "ENCRYPTION_KEY=$(cat ...) exec /sbomhub-api"`) で
> `*_FILE` → env var 展開を済ませているため、 Docker secrets 経由の運用はそのまま enterprise
> compose で完結する。 アプリ本体へ `*_FILE` ネイティブサポートを入れるかどうかは別 issue 扱い。

### 5.3 SOPS / age / GPG によるチーム間共有

複数オペレーターで `.env` を共有する場合、 平文を Slack / メールで配るのは厳禁。
[SOPS](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age) または GPG
で暗号化したまま git 管理する方式を推奨する。

```bash
# 例: age key を YubiKey 等 HW token で守る
sops --encrypt --age $AGE_RECIPIENT_PUBLIC_KEY .env > .env.enc
# .env.enc は git commit OK、 復号鍵 (age private key) は YubiKey で守る
```

### 5.4 LLM BYOK API key も同様の扱い

`SBOMHUB_LLM_API_KEY` (OpenAI / Anthropic / Gemini / Azure 用) や `OLLAMA_HOST` などの BYOK
設定値も `.env` / Docker secrets の同じ流儀で管理する。 OSS リポジトリには **絶対に bundled
key を含めない** (M0 Trust Rescue 9.2 + §20.2 BYOK 制約)。

### 5.5 LLM Provider embedding 設定 (M5-7)

OpenAI / Gemini / Ollama は `Embed` を実装済み。将来の reachability / vector search 用に、
chat model とは別に embedding model env を持つ。Anthropic は 2026-06 時点で first-party
embedding API がなく、公式 Claude Platform docs も Voyage AI を案内しているため、
`Embed` は `ErrNotImplemented` のまま。

```bash
# OpenAI (default: text-embedding-3-small, 1536 dimensions)
SBOMHUB_LLM_PROVIDER=openai
SBOMHUB_LLM_MODEL=gpt-5
OPENAI_API_KEY=...
SBOMHUB_LLM_OPENAI_EMBEDDING_MODEL=text-embedding-3-small  # 任意; text-embedding-3-large は 3072 dimensions

# Gemini (default: gemini-embedding-2, 3072 dimensions)
SBOMHUB_LLM_PROVIDER=gemini
SBOMHUB_LLM_MODEL=gemini-2.5-flash
GOOGLE_API_KEY=...
SBOMHUB_LLM_GEMINI_EMBEDDING_MODEL=gemini-embedding-2      # 任意

# Ollama (default: nomic-embed-text, 768 dimensions)
SBOMHUB_LLM_PROVIDER=ollama
SBOMHUB_LLM_OLLAMA_URL=http://ollama:11434
SBOMHUB_LLM_MODEL=qwen2.5-coder:7b
SBOMHUB_LLM_OLLAMA_EMBEDDING_MODEL=nomic-embed-text        # 任意; mxbai-embed-large は 1024 dimensions
```

batching:

- OpenAI: 1 HTTP request あたり最大 2,048 inputs、1 call safety cap 16,384 inputs。
- Gemini: sbomhub 側で 100 inputs/request に chunk、1 call safety cap 16,384 inputs。
- Ollama: `/api/embed` を使用し、sbomhub 側で 2,048 inputs/request に chunk、1 call safety cap 16,384 inputs。
- いずれも途中 chunk 失敗時は **完了済 chunk を破棄して error 返却**。

### 5.6 LLM Provider (Azure OpenAI 用の追加 env、 M5-3)

Azure OpenAI を BYOK で使う場合、 chat と embedding は **別々の deployment** として Azure 側で
登録する必要がある (Azure OpenAI 公式仕様、 [Microsoft Learn embeddings guide](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/embeddings))。
sbomhub は両方の deployment 名を別 env で受ける。 embedding deployment は **任意** で、
未設定なら chat 経路 (`Complete`) のみ動き、 embedding 経路 (`Embed`) は per-call で
`DisabledError` (HTTP 503) を返す (chat-only 製品挙動には影響しない)。

```bash
# 必須 (chat) — M4 で既に整備済
SBOMHUB_LLM_PROVIDER=azure_openai
SBOMHUB_LLM_AZURE_ENDPOINT=https://my-resource.openai.azure.com
SBOMHUB_LLM_AZURE_DEPLOYMENT=gpt-4o-prod                   # chat deployment 名 (URL path)
SBOMHUB_LLM_MODEL=gpt-4o                                   # canonical chat model 名 (Capabilities / 監査用)
SBOMHUB_LLM_AZURE_API_VERSION=2024-10-21                   # 任意; 既定は GA stable
AZURE_OPENAI_API_KEY=...                                   # または SBOMHUB_LLM_API_KEY

# 任意 (embedding、 M5-3 で追加)
SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT=text-embed-3-small-prod   # embedding deployment 名 (URL path)
SBOMHUB_LLM_AZURE_EMBEDDING_MODEL=text-embedding-3-small         # 任意 canonical embedding model 名
SBOMHUB_LLM_AZURE_EMBEDDING_API_VERSION=                         # 任意; 空なら chat の api-version を流用
```

Microsoft 公式 doc 互換の alias も認識する (sbomhub canonical env が優先):

- `AZURE_OPENAI_ENDPOINT` (= `SBOMHUB_LLM_AZURE_ENDPOINT`)
- `AZURE_OPENAI_API_VERSION` (= `SBOMHUB_LLM_AZURE_API_VERSION`)
- `AZURE_OPENAI_DEPLOYMENT` / `AZURE_OPENAI_DEPLOYMENT_NAME` / `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` (= `SBOMHUB_LLM_AZURE_DEPLOYMENT`)
- `AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME` (= `SBOMHUB_LLM_AZURE_EMBEDDING_DEPLOYMENT`、 M5-3)

embedding batching:

- 1 リクエストあたり最大 2,048 inputs (Azure 公式 hard cap)、 超過分は **透過的に複数 HTTP に分割**。
- 安全 cap 16,384 inputs/call (F25 DoS 防止)、 超過は HTTP dispatch 前に即 reject。
- 途中 chunk 失敗時は **完了済 chunk を破棄して error 返却** (partial Vectors の silent 切り詰めを避ける)。

embedding deployment を立てる代表例 (Azure Portal / `az` CLI):

```bash
# 1) Azure portal で OpenAI resource に "Deployments" を 2 つ作る:
#    - gpt-4o-prod                  (chat、 base model = gpt-4o)
#    - text-embed-3-small-prod      (embedding、 base model = text-embedding-3-small)
# 2) 両方の deployment が "Active" になるのを確認してから .env を更新
```

未対応 / scope 外:

- per-tenant Azure embedding (`tenant_llm_config` に embedding 列がまだ無いため、 server-wide env で共有)。
  per-tenant が必要なら M5 follow-up migration で `azure_embedding_deployment` 列追加 → repository / handler の対応が必要。
- `dimensions` request パラメータ (text-embedding-3-{small,large} で vector を 256〜3072 で切詰めできる) は未対応。

---

## 6. TLS termination

SBOMHub OSS の web (port 3000) / api (port 8080) は **デフォルトでは HTTP** で listen する。
外部公開する場合は必ず **reverse proxy で TLS 終端** すること。 アプリ本体に TLS を持たせると
証明書の rotation 運用が複雑化するので、 終端は proxy 側に任せるのが業界標準。

### 6.1 推奨: Caddy (Let's Encrypt 自動取得)

最小設定で TLS が動く。 ACME (Automated Certificate Management Environment) で証明書を
自動取得 + 自動更新する。

```caddyfile
# /etc/caddy/Caddyfile
sbomhub.example.com {
    reverse_proxy localhost:3000
}

api.sbomhub.example.com {
    reverse_proxy localhost:8080
}
```

Caddy は公開 DNS が引ければ証明書を自動で取得する。 single-host PoC では最も導入コストが低い。

### 6.2 nginx + certbot

```nginx
server {
    listen 80;
    server_name sbomhub.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name sbomhub.example.com;

    ssl_certificate     /etc/letsencrypt/live/sbomhub.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sbomhub.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
    }
}
```

`certbot --nginx -d sbomhub.example.com` で証明書取得 + nginx 設定自動反映。
90 日ごとの自動更新 (`certbot renew`) は systemd timer で回す。

### 6.3 Cloudflare Tunnel (公開 IP 不要)

工場ネットワークで「インターネット側に listen ポートを開けたくない」 ケースで人気。
SBOMHub host から Cloudflare 側に outbound tunnel を張り、 Cloudflare が TLS 終端 + 公開 URL を
提供する。

```bash
# install cloudflared
sudo apt install cloudflared

# tunnel 作成
cloudflared tunnel login
cloudflared tunnel create sbomhub-prod

# ~/.cloudflared/config.yml
# tunnel: <UUID>
# credentials-file: /home/user/.cloudflared/<UUID>.json
# ingress:
#   - hostname: sbomhub.example.com
#     service: http://localhost:3000
#   - hostname: api.sbomhub.example.com
#     service: http://localhost:8080
#   - service: http_status:404

cloudflared tunnel route dns sbomhub-prod sbomhub.example.com
cloudflared tunnel route dns sbomhub-prod api.sbomhub.example.com
cloudflared tunnel run sbomhub-prod
```

利点: zero-trust 統合 (Cloudflare Access で SAML / Google Workspace 認証を前段に置ける)、
DDoS 緩和、 公開 IP 不要。

> **TODO**: Cloudflare Access による pre-auth レイヤー設定 (SBOMHub の API key auth と併用する
> 場合の流れ) は別 issue でレシピ化。

### 6.4 自己署名証明書の落とし穴

社内ネットワーク内に閉じる場合でも **自己署名 (self-signed) 証明書はおすすめしない**。

- ブラウザの警告ページを毎回スキップする運用は、 中間者攻撃の警告も skip する習慣を植え付ける。
- CLI / CI から `sbomhub scan` する際に証明書 pin が困難、 `INSECURE_SKIP_VERIFY` 相当の運用に
  なりがちで TLS の意味が薄れる。

代案: **社内 ACME (内部 CA)** を立てる。 [step-ca](https://smallstep.com/docs/step-ca) や
[smallstep](https://smallstep.com/) で社内 CA + ACME server を運用すると、 社内ホストが Caddy
同様に自動証明書取得できるようになる。

---

## 7. firewall / network 分離

SBOMHub を構成する service の listen ポートと、 外部公開すべきかどうかを整理する。

### 7.1 公開可否マトリクス

| Service | デフォルト port | 公開可否 | 備考 |
|---|---|---|---|
| web (Next.js) | 3000 | **TLS 終端後の 443 経由のみ可** | reverse proxy 越しに公開、 直接 3000 は閉じる |
| api (Go / Echo) | 8080 | **TLS 終端後の 443 経由のみ可** | CLI / GitHub Actions / MCP からも叩く |
| postgres | 5432 | **絶対に公開禁止** | 同 compose project 内 internal network のみ |
| redis | 6379 | **絶対に公開禁止** | 同上 |
| ollama ([enterprise compose](../../docker/docker-compose.enterprise.yml)) | 11434 | **localhost-only bind 推奨** | 外部からの prompt 投入 / model abuse 防止 |
| (将来) metrics endpoint | TBD | **internal network のみ** | Prometheus scrape は内部 SG / VPC 内に限定 |

### 7.2 Ollama の localhost-only bind

Local LLM (Ollama) を導入する場合、 デフォルトの `0.0.0.0:11434` バインドは絶対に避ける。
インターネット側に Ollama API がそのまま見えると、 第三者が prompt を投入して model を悪用する。

```yaml
# docker-compose.enterprise.yml (M4-6 で merged。 抜粋)
services:
  ollama:
    image: ollama/ollama:latest
    ports:
      - "127.0.0.1:11434:11434"  # localhost-only、 外部 NIC には bind しない
    volumes:
      - ollama_data:/root/.ollama
    restart: unless-stopped
```

api コンテナから ollama にアクセスするのは compose internal network 経由 (DNS 名 `ollama`) で
行うので、 host の 11434 を外に開く必要はない。

### 7.3 ufw / iptables sample

bare-metal で SBOMHub を立てる場合の firewall 例 (Ubuntu / Debian + ufw):

```bash
# デフォルト deny all in
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH (管理用)
sudo ufw allow 22/tcp

# HTTPS (reverse proxy 経由で web/api を公開)
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp   # ACME challenge / HTTP→HTTPS リダイレクト用

# 内部 service は明示 deny (default deny でも念のため)
sudo ufw deny 5432/tcp   # PostgreSQL
sudo ufw deny 6379/tcp   # Redis
sudo ufw deny 11434/tcp  # Ollama
sudo ufw deny 8080/tcp   # api 直アクセス (reverse proxy 越しに限定)
sudo ufw deny 3000/tcp   # web 直アクセス (同上)

sudo ufw enable
sudo ufw status verbose
```

### 7.4 Container network (compose 内)

Docker Compose は同 project 内の service 間に internal network を自動作成する。
api → postgres / redis / ollama の通信はこの internal network 上の DNS 名 (`postgres`, `redis`,
`ollama`) で名前解決される。 host の port は **何も `expose:` しなければ外部から見えない**。

確認:

```bash
docker compose ps
# postgres / redis / ollama の PORTS 列に 0.0.0.0:* が出ていないこと
```

もし開発のために `docker/docker-compose.yml` (port 15432 で postgres 公開) を使っている場合、
**production には絶対持ち込まない**。 dev / staging / production で compose ファイルを明確に
分け、 production では internal network のみで通信する。

### 7.5 公開 instance からの outbound 制限

外部 LLM (OpenAI / Anthropic / Gemini / Azure) を BYOK で使う場合、 SBOMHub host からの outbound
は最小限の allowlist で管理する。

```bash
# 例: api.openai.com への HTTPS のみ許可、 それ以外の outbound は拒否
# (iptables、 NetworkPolicy、 Cloudflare Zero Trust Gateway 等で実装)
```

これにより、 仮にコンテナ内で他のマルウェアが動いても、 第三者の C2 サーバへの outbound を
ブロックできる。 特に LLM prompt に SBOM 内容 (依存ライブラリ名等) を投げる以上、 outbound 先の
ホスト名は厳格に管理する。

---

## 8. Log retention

LLM 呼び出しは `llm_calls` テーブルに監査ログとして保存される
([apps/api/migrations/032_llm_calls.up.sql](../../apps/api/migrations/032_llm_calls.up.sql))。
prompt / response の hash + preview + token / cost が必ず記録される。 retention は運用ポリシー
として明示的に設定する。

### 8.1 SBOMHUB_LLM_AUDIT_STORE_RESPONSE

- **default: `false`** — `llm_calls.response_body` は NULL のまま (hash と最初 500 文字 preview
  のみ保存)、 完全な response 本文は保存しない。 OSS 標準の storage 節約 + 機密漏洩リスク低減
  方針。
- **`true` に設定** — 監査要件で「LLM が返した完全 response を 1 年保管」 が必要なケースで使う。
  storage 消費が増えるので、 §8.3 の retention 設定とセットで運用する。

```bash
# .env
SBOMHUB_LLM_AUDIT_STORE_RESPONSE=false  # default、 hash のみ保存
# または
SBOMHUB_LLM_AUDIT_STORE_RESPONSE=true   # 完全 response を保存
```

> **TODO**: `SBOMHUB_LLM_AUDIT_STORE_RESPONSE` の config.go 側読み込みは
> [migration 032 のコメント](../../apps/api/migrations/032_llm_calls.up.sql) で言及されているが、
> 本ガイド執筆時点で `apps/api/internal/config/config.go` に該当フィールドが実装されているか
> 別 agent で要確認。 実装後に env 変数経由で切替可能。

### 8.2 prompt / response preview のサイズ

`prompt_preview` / `response_preview` は先頭 500 文字。 SBOM component 名 / advisory 抜粋 /
コードスニペットを含むため、 営業秘密 / 顧客機密が紛れ込む可能性がある。 PSIRT は preview を
監査ログとして閲覧する権限を「Admin role」 に限定し、 通常運用者には公開しない設計が望ましい。

### 8.3 retention 設定

監査要件は業界標準で **1 年以上** (経産省 SBOM 手引 ver 2.0、 NIST SP 800-218 SSDF、 ISO 27001
A.12.4.1)。 EU CRA も「detected vulnerability の証跡」 の保管を要求する (第 14 条)。

> **TODO**: SBOMHub UI 側に `llm_calls` retention 設定 (30 / 90 / 365 日 / 無期限) の GUI は
> 現状未提供。 暫定的に DB 側 cron で削除する:

```sql
-- 90 日より古い llm_calls を削除 (PSIRT 監査要件に応じて 365 日 / 無期限 に調整)
DELETE FROM llm_calls
 WHERE created_at < NOW() - INTERVAL '90 days';
```

```bash
# /etc/cron.d/sbomhub-llm-calls-retention (毎日 03:00 JST 実行)
0 3 * * *  postgres  psql -U sbomhub_migrator -d sbomhub -c \
    "DELETE FROM llm_calls WHERE created_at < NOW() - INTERVAL '90 days';"
```

`audit_logs` も同様の retention で管理する (現時点で UI 経由の retention 設定がない場合、 cron
で削除)。 PSIRT 監査要件が「無期限保管」 ならこれらの cron を入れず、 storage 拡張で対応する。

### 8.4 ログ転送 (SIEM 連携)

audit_logs / llm_calls を SIEM (Splunk, Sentinel, Elastic 等) に転送する場合、 PostgreSQL
の logical replication または定期 export (CSV / JSON) を使う。 当該 export には API key /
encrypted token は含まれない (それらは `api_keys.key_hash` / `*_encrypted` で hash / 暗号化
済み) ので、 ログ転送先での再暗号化は標準的な at-rest encryption で十分。

---

## 9. backup / restore

SBOMHub の DB は **`ENCRYPTION_KEY` 込みで** backup しないと意味がない。 DB だけ復旧して鍵を
失うと、 `issue_tracker_connections.auth_token_encrypted` や BYOK LLM API key が **永久に
復号不能** になる。 これは事実上の全データ損失。

### 9.1 pg_dump (DB)

```bash
# custom format (推奨、 pg_restore で柔軟に復元可)
docker compose exec -T postgres \
    pg_dump -U sbomhub_migrator -Fc -d sbomhub \
    > backup-$(date -u +%Y%m%d).dump

# 確認: ファイルサイズが妥当か、 非ゼロか
ls -lh backup-*.dump
```

`sbomhub_migrator` ロールで dump する (`sbomhub_app` は SELECT 権限はあるが、 `pg_dump` 内部で
sequence / schema 情報の取得に owner 権限が必要)。

### 9.2 ENCRYPTION_KEY 同梱

```bash
# .env を同じディレクトリに退避 (ENCRYPTION_KEY が含まれている)
cp .env backup-env-$(date -u +%Y%m%d).env
chmod 600 backup-env-*.env

# 推奨: backup ファイル + .env を tar で 1 つにまとめ、 外部の secret store で暗号化する
tar czf sbomhub-backup-$(date -u +%Y%m%d).tar.gz \
    backup-*.dump backup-env-*.env

# age / GPG / KMS 等で暗号化してから offsite 保管
age -r $RECIPIENT_PUBLIC_KEY \
    -o sbomhub-backup-$(date -u +%Y%m%d).tar.gz.age \
    sbomhub-backup-$(date -u +%Y%m%d).tar.gz

# 平文ファイルは即削除
shred -u sbomhub-backup-$(date -u +%Y%m%d).tar.gz backup-*.dump backup-env-*.env
```

> **Prerequisites for §4.5 and §9.x**
>
> The operational scripts referenced below (`docker/scripts/backup.sh`,
> `docker/scripts/restore.sh`, `docker/scripts/verify-encryption.sh`,
> `docker/scripts/verify-encryption-cron.sh`) are downloaded automatically
> by `./install.sh --start` (M6 #56 F120 fix). If you installed via a
> different path, ensure these scripts are present at the documented
> paths before following the runbook examples.
>
> Manual download example:
>
> ```bash
> mkdir -p docker/scripts
> for s in backup.sh restore.sh verify-encryption.sh verify-encryption-cron.sh; do
>   curl -fsSL "https://raw.githubusercontent.com/youichi-uda/sbomhub/main/docker/scripts/$s" \
>     -o "docker/scripts/$s"
>   chmod +x "docker/scripts/$s"
> done
> ```

### 9.3 restore

> **推奨**: 本 manual 手順は **emergency fallback** であり、 通常運用では §9.5 の
> [`../../docker/scripts/restore.sh`](../../docker/scripts/restore.sh) を canonical path
> として使用すること (F65 fix 以降、 `--single-transaction` + sanity check による
> fail-safe が組み込まれている)。 manual 手順は script が動かない緊急時 (例: tar 破損
> で部分復元が必要、 docker compose 環境が壊れている等) でのみ使う。 そのため以下の
> manual command にも script 同等の fail-safe (`--single-transaction` + 復元後の
> sanity check) を必ず適用すること。

```bash
# Step 1: 復号 + 展開
age -d -i $PRIVATE_KEY \
    -o sbomhub-backup-YYYYMMDD.tar.gz \
    sbomhub-backup-YYYYMMDD.tar.gz.age
tar xzf sbomhub-backup-YYYYMMDD.tar.gz

# Step 2: DB を restore (既存スキーマを drop してから入れ直す形)
# --single-transaction を付けることで、 途中 failure 時に全 restore が rollback され、
# 部分適用による DB と secrets の不整合を防ぐ (F65 fix と同じ fail-safe)。
# ※ この時点で .env (secrets) はまだ触らない。 sanity check が両方 PASS するまで
#    現行の .env を untouched で保持し、 DB と secrets の不整合 window を排除する
#    (F69 fix: 旧 .env を残しておけば sanity FAIL 時に「DB は restore 開始前に rollback、
#    secrets も触れていない」 という clean fail-safe を保てる)。
docker compose -f docker-compose.enterprise.yml exec -T postgres \
    pg_restore -U sbomhub_migrator -d sbomhub \
    --clean --if-exists --single-transaction \
    < backup-YYYYMMDD.dump

# Step 3: Sanity check 1 — migration version が最新まで適用されていることを確認
# (空文字や error が返るなら restore は不完全、 .env を戻さず調査)
docker compose -f docker-compose.enterprise.yml exec -T postgres \
    psql -U sbomhub_migrator -d sbomhub -c \
    "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;"

# Step 4: Sanity check 2 — tenants table が query 可能で、 production data が入っていることを確認
# (production restore のはずなのに count が 0 なら fresh-install 用 backup を誤投入した
# 可能性があり、 要調査)
docker compose -f docker-compose.enterprise.yml exec -T postgres \
    psql -U sbomhub_migrator -d sbomhub -c \
    "SELECT count(*) FROM tenants;"

# Step 5: 上記 sanity check が両方 PASS した場合のみ .env を所定位置に戻す。
# いずれかが FAIL したら本 step に進まず DB volume を rollback (snapshot or
# 旧 dump 再投入) して原因調査する。 旧 .env はこの時点でも untouched なので、
# DB と secrets はそのまま整合した「restore 開始前の状態」 に戻せる。
cp backup-env-YYYYMMDD.env .env
chmod 600 .env

# Step 6: api を再起動 (DB + .env が両方更新された後)
docker compose -f docker-compose.enterprise.yml restart sbomhub-api
docker compose -f docker-compose.enterprise.yml logs -f sbomhub-api | head -50
```

### 9.4 offsite backup

- S3 / GCS / Azure Blob に **server-side encryption + bucket-level audit** で保管する。
- backup tar.gz は **必ず age / GPG / KMS 暗号化を経て** から upload する (server-side encryption
  だけに頼らない、 二重防御)。
- 復号鍵は backup と異なる場所 (HW token, Vault, KMS) で管理する。

### 9.5 backup script の自動化

M4-6 で公式 backup / restore スクリプトを同梱した。 単純な cron に組み合わせて運用できる。
**production の restore はこの script を canonical path として使用し、 §9.3 manual 手順は
script が動かない緊急時の fallback として位置付ける。**

- [`../../docker/scripts/backup.sh`](../../docker/scripts/backup.sh) — `pg_dump` + `.env`/secrets +
  Ollama model list を 1 つの tar.gz に固める。 引数や保存先、 age 暗号化との繋ぎ込みは
  [`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §5.1 / §5.2 を参照。
- [`../../docker/scripts/restore.sh`](../../docker/scripts/restore.sh) — 上記 tar.gz を読み込んで
  PostgreSQL に `pg_restore --clean --if-exists --single-transaction` で投入し、
  `schema_migrations` / `tenants` の sanity check を経た後に secrets を所定位置に戻す
  (F65 fix で fail-safe を組み込み済)。 復元手順全体および fail-safe 動作は
  [`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §5.3 を参照。

```cron
# /etc/cron.d/sbomhub-backup (毎日 02:00 JST 実行)
0 2 * * *  sbomhub  /opt/sbomhub/docker/scripts/backup.sh >> /var/log/sbomhub-backup.log 2>&1
```

### 9.6 ENCRYPTION_KEY 復号 smoke test (`verify-encryption.sh`)

[`../../docker/scripts/verify-encryption.sh`](../../docker/scripts/verify-encryption.sh) は restore
直後 / 鍵 rotation 直後に **「現在の ENCRYPTION_KEY が DB を復号できる」** ことを smoke 確認する
CLI。 issue [#53](https://github.com/youichi-uda/sbomhub/issues/53) (M5-5) で導入。

restore.sh とのインテグレーション (opt-in、 default off):

```bash
# Step 8 として自動実行 (smoke 失敗は warning のみで restore は continue)
VERIFY_ENCRYPTION=1 \
VERIFY_DB_URL="postgres://sbomhub_app:...@127.0.0.1:5432/sbomhub?sslmode=disable" \
  ./docker/scripts/restore.sh /path/to/sbomhub-backup-YYYYMMDD-HHMMSS.tar.gz
```

`restore.sh` は host で実行されるため、 enterprise compose の `postgres` DNS 名には到達できない。
Step 8 を自動実行する場合は `VERIFY_DB_URL` に host から到達可能な DSN を明示する。未指定時は
skip するが、 operator が smoke 未実行を見落とさないよう WARN ログを出力する。

詳細仕様 (exit code 契約、 column 切り替え、 security 注意点) は §4.5 を参照。 §4.5 の `--table
issue_tracker_connections --column auth_token_encrypted` 例は restore 直後の typical な追加
spot check として有用 (BYOK LLM key が未設定でも issue tracker auth_token は最も古くからある
暗号化カラム、 production install ではほぼ常に存在する)。

### 9.7 リストア訓練

backup を取るだけでは「実際に復元できる」 ことは保証されない。 **四半期に 1 回** は staging 環境
への restore 訓練を回すこと。 訓練で発見しがちな問題:

- pg_dump の format mismatch (`-Fc` で取った dump を `psql` で食わせて失敗)
- .env 紛失 (DB は復元できたが鍵が無く `issue_tracker_connections` が復号できない)
- PostgreSQL major version mismatch (15 → 16 アップグレード後に pg_dump 互換性が崩れる)

---

## 10. healthcheck / sbomhub doctor

`sbomhub doctor` は CLI の動作環境セルフチェックコマンド (M0 Trust Rescue で導入、 実装:
[sbomhub-cli/cmd/sbomhub/commands/doctor.go](https://github.com/youichi-uda/sbomhub-cli/blob/main/cmd/sbomhub/commands/doctor.go))。
self-host 環境では起動直後 + nightly cron で実行することを推奨する。

### 10.1 CLI からの実行

```bash
# 既存の login で設定された API URL / key で診断
sbomhub doctor

# 明示指定
sbomhub doctor --api-url https://api.sbomhub.example.com --api-key sbh_xxx

# 詳細ログ
sbomhub doctor --verbose
```

チェック項目 (抜粋):

- API endpoint reachability (HTTP 200 with `auth-verify` 成功)
- API key prefix (`sbh_`) の形式確認
- scanner binary (syft / trivy / cdxgen) の存在確認
- (M4 以降追加予定) RLS / ENCRYPTION_KEY / LLM provider 設定の sanity check

`sbomhub doctor` が PASS なら、 CLI から SBOM upload が通る基本動作は保証される。

### 10.2 API server 側のセルフチェック

API server (`apps/api/cmd/server`) は起動時に以下を行う:

- `validateEncryptionKey` (§4.3)
- `assertAppRoleNotBypassRLS` (§3.1)
- DB migration の整合性確認 (`MIGRATE_DATABASE_URL` で migration 適用後、 runtime URL に切替)

production / staging でこれらが fail すると **起動を拒否** する。 起動 log を確認:

```bash
docker compose logs api | grep -E "ENCRYPTION_KEY check|DB role check|Refusing to start"
# 期待:
#   ENCRYPTION_KEY check passed length=44 app_env=production
#   DB role check passed role=sbomhub_app bypass_rls=false superuser=false
# (M4 Codex review #F72 以降、 superuser フィールドも合わせて出力される)
```

### 10.3 nightly health check の cron 例

```cron
# /etc/cron.d/sbomhub-doctor (毎晩 04:00 JST)
0 4 * * *  sbomhub  sbomhub doctor --api-url https://api.sbomhub.example.com \
                    --api-key $SBOMHUB_API_KEY \
                    || curl -X POST -d "sbomhub doctor FAIL on $(hostname)" $SLACK_WEBHOOK
```

### 10.4 Golden Path E2E nightly (sbomhub repo)

SBOMHub OSS リポジトリ自体には [`.github/workflows/golden-path-e2e.yml`](../../.github/workflows/golden-path-e2e.yml)
が動いており、 managed 環境で「5 分以内に SBOM upload → triage → VEX export」 まで通ることを
nightly で確認している。 self-host 側で同等のシナリオを動かしたい場合、 `scripts/golden-path-e2e.sh`
([sbomhub/scripts/golden-path-e2e.sh](../../scripts/golden-path-e2e.sh)) を staging 環境で走らせると
良い。

---

## 11. Local LLM (Ollama) 構成

「ソースコードや SBOM を外部 LLM API に送りたくない」 製造業 enterprise 要件に対しては、
[Ollama](https://ollama.com/) を同梱した Local LLM 構成を推奨する。

### 11.1 推奨 model

| Model | サイズ | VRAM 要件 (bf16) | 量子化 (q4) VRAM | 用途 |
|---|---|---|---|---|
| `qwen2.5-coder:7b` | 7B | ~14 GB | ~6 GB | コード理解 + 日本語/英語 OK、 cost-effective、 VEX triage の推奨 default |
| `llama3.1:8b` | 8B | ~16 GB | ~7 GB | 汎用、 英語中心、 CRA report 草案 |
| `gemma2:9b` | 9B | ~18 GB | ~8 GB | Google 系、 multilingual |
| `qwen2.5-coder:32b` | 32B | ~64 GB | ~20 GB | より高品質、 GPU 1x A100 / RTX 6000 級 |
| `llama3.1:70b` | 70B | ~140 GB | ~40 GB | enterprise GPU クラスタ (A100 x4 級) |

> **TODO**: 2026 年時点での最新 SOTA Local LLM (例: Qwen3, Llama 4) の比較は M4-3 比較ベンチ
> harness の結果と照合して更新する。 本ガイド初版は Qwen2.5-coder / Llama 3.1 / Gemma 2 を
> baseline とする。

### 11.2 CPU-only fallback

GPU が無い (or VRAM 不足) 環境では、 7B 量子化 (q4) 版を CPU で動かせる。

```bash
ollama pull qwen2.5-coder:7b-q4_K_M
```

latency: 1 件の VEX triage で **10〜30 秒** (Intel Xeon 32-core 級)、 GPU 比で 10〜30 倍遅い。
夜間バッチで triage を回すなら許容範囲。 インタラクティブな UI 操作 (CRA draft 生成等) は GPU を
推奨。

### 11.3 環境変数設定

```bash
# .env
SBOMHUB_LLM_PROVIDER=ollama
SBOMHUB_LLM_OLLAMA_URL=http://ollama:11434     # docker-compose 内部 DNS
SBOMHUB_LLM_MODEL=qwen2.5-coder:7b             # ollama pull 済みの model 名
```

env 設定後、 API server 起動 log で `provider=ollama model=qwen2.5-coder:7b` が出ることを確認。

### 11.4 docker-compose.enterprise.yml (M4-6)

M4-6 で同梱された [`../../docker/docker-compose.enterprise.yml`](../../docker/docker-compose.enterprise.yml)
が、 ollama service + Docker secrets + `127.0.0.1` only バインド + backend/frontend network 分離を
1 ファイルにまとめて提供する。

**※ 重要**: OSS 標準の [`../../docker-compose.yml`](../../docker-compose.yml) と **上乗せ (`-f` 重ね) では
なく独立 file として起動する**。 両者の volume / network / 公開 port が衝突するため、
`-f docker-compose.yml -f docker-compose.enterprise.yml` のような 2 ファイル合成は **しない**。 詳細は
[`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §1 「上乗せではなく独立 file」
を参照。

起動 (enterprise 単独):

```bash
cd docker
docker compose -f docker-compose.enterprise.yml up -d
```

これで `ollama` service が立ち上がり、 `api` service が `SBOMHUB_LLM_OLLAMA_URL=http://ollama:11434`
で参照する。 初回 secrets 生成 (`encryption_key.txt` / `postgres_password.txt`) / model pull /
RLS ロール分離 / reverse proxy 配線等の完全手順は
[`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §3〜§4 を参照。

OSS 標準 compose と enterprise compose を同一 host で並走させたい (例: dev tenant と prod tenant) 場合は、
project name を明示分離する:

```bash
docker compose -p sbomhub-dev  -f docker-compose.yml             up -d
docker compose -p sbomhub-prod -f docker-compose.enterprise.yml  up -d
```

> **TODO**: GPU passthrough 設定例 (`devices: [/dev/dri], runtime: nvidia` 等) は本節と
> [`../../docker/README.enterprise.md`](../../docker/README.enterprise.md) §2 / §7.1 で扱う。
> NVIDIA Container Toolkit / AMD ROCm の distro 別 install 手順は本ガイドの scope 外で、 別 issue で
> 個別ランブック化予定。

### 11.5 model 管理

```bash
# model を pull (初回のみ、 大きいので時間がかかる)
docker compose exec ollama ollama pull qwen2.5-coder:7b

# 利用可能 model 一覧
docker compose exec ollama ollama list

# 動作確認 (chat API 直叩き)
curl http://localhost:11434/api/chat \
    -d '{"model":"qwen2.5-coder:7b","messages":[{"role":"user","content":"hello"}],"stream":false}'
```

§7.2 の通り `127.0.0.1:11434` にバインドし、 公衆 internet には絶対に公開しない。

### 11.6 managed vs local の品質差 (M4-3)

M4-3 で実装される比較ベンチ harness を使うと、 同じサンプル CVE / SBOM に対して
managed (Claude / GPT / Gemini) vs Local (Ollama) の confidence / precision / recall 差を
実測できる。 製造業 PoC では「Local LLM のみで CRA draft 品質が許容ラインに達するか」 が判断軸に
なるので、 PoC 時に必ず動かすことを推奨する。

> **TODO**: M4-3 比較ベンチ harness の結果 (どの workload で local が遜色ないか、 どこで
> managed が圧倒するか) は別レポート化予定。 完了後 link をここに追加する。

---

## 12. インシデント対応

製造業 PSIRT が現場で遭遇しがちな 3 種類のインシデントについて、 **最初の 30 分** で行うべき
即時手順を整理する。

### 12.1 `ENCRYPTION_KEY` 漏洩疑い

兆候: `.env` が誤って git push された、 backup ファイルが流出した、 operator の作業 PC が
malware 感染した、 等。

即時手順:

1. **全 BYOK LLM API key を provider 側で revoke** (UI rotation を待たない)
   - OpenAI: <https://platform.openai.com/api-keys> で該当 key を `Revoke`
   - Anthropic: <https://console.anthropic.com/settings/keys> で `Delete`
   - Google: GCP Console → API & Services → Credentials → `Disable`
   - Azure: Portal → Cognitive Services → Keys and Endpoint → `Regenerate Key`
2. **Jira / Backlog 等の issue tracker 連携トークン** も同様に upstream で revoke
   (`issue_tracker_connections.auth_token_encrypted` 経由で漏洩した token 扱い)
3. 新 `ENCRYPTION_KEY` を生成 ([`../encryption-key-rotation.md`](../encryption-key-rotation.md))
4. `llm_calls` から流出範囲を特定 (prompt_preview / response_preview から、 どの tenant のどの
   CVE / コードが LLM に送信されたかを集計)
5. 影響テナントに通知 (CRA 第 14 条の「significant cybersecurity vulnerability」 該当判定が
   必要)

鍵 rotation の automation は M6 issue
[#56](https://github.com/youichi-uda/sbomhub/issues/56) で実装した
[`apps/api/cmd/migrate-encryption`](../../apps/api/cmd/migrate-encryption) を使用する。
標準手順は [`../encryption-key-rotation.md`](../encryption-key-rotation.md) §3 を参照。
offline / emergency で automation binary が使えない場合のみ、 同 runbook §3.1 の manual SQL
fallback に従う。

### 12.2 DB 侵害疑い

兆候: PostgreSQL の `pg_stat_activity` に身に覚えのない superuser query、 audit log への
書き込みが途切れている、 backup 容量が異常に増減、 等。

即時手順:

1. **`sbomhub_app` ロールの password 変更** (`ALTER ROLE sbomhub_app PASSWORD '...'`) +
   全 active session の forced disconnect
   (`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'sbomhub_app';`)
2. **RLS bypass の痕跡確認**:
   ```sql
   -- superuser ロールでの DML 痕跡
   SELECT * FROM pg_stat_activity
     WHERE usename = 'sbomhub'
       AND state = 'active'
       AND query NOT ILIKE '%pg_stat_activity%';
   -- 期待: 空 (sbomhub は bootstrap 用、 runtime に居てはいけない)
   ```
3. **`audit_logs` の tamper 確認**: 連続する `created_at` に gap が無いか、 同 tenant_id で
   不審な actor_user_id が混ざっていないか
4. `audit_logs` 自体が改ざんされている疑いがあれば、 backup から該当時刻の audit_logs を
   復元して diff
5. **ENCRYPTION_KEY のローテーション** も同時に実施 (DB に直接アクセスできた攻撃者は鍵に
   到達した可能性が高い)
6. インシデント終息後、 DB を最新 backup から restore + migration replay + 全テナントへ通知

### 12.3 LLM prompt injection 検出

兆候: VEX triage の結果に「`not_affected` 判定だが evidence pointer が空」 等の異常出力、
confidence が異常に高い (1.0 連発) のに人間レビューで明らかに誤判定、 等。

即時手順:

1. `llm_calls.prompt_preview` で**異常入力**を確認:
   ```sql
   SELECT id, tenant_id, prompt_preview, response_preview, created_at
     FROM llm_calls
    WHERE purpose = 'vex_triage'
      AND created_at > NOW() - INTERVAL '24 hours'
      AND (
          prompt_preview ILIKE '%ignore previous%'
       OR prompt_preview ILIKE '%system prompt%'
       OR prompt_preview ILIKE '%</user_input>%'
      )
    ORDER BY created_at DESC;
   ```
2. **confidence threshold を一時的に上げる** (例: 0.7 → 0.95) → 閾値以下は強制的に
   `under_investigation` に分類されるので、 自動 `not_affected` 化を止める
3. 該当 tenant の AI 機能を `/settings/llm` UI で一時 **disable** にする
4. injection 元の SBOM upload を特定 (`audit_logs` で「該当 tenant の SBOM upload 時刻」 と
   `llm_calls.created_at` を突合)、 当該 component を quarantine
5. M2 以降の prompt injection 防御 (system prompt と user input の明示分離、 LLM 出力の
   allowlist 検証、 confidence floor) が機能していたか事後検証
   ([`LLM_PROVIDER_DESIGN.md`](../../../sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md)
   §7.4 内部参照)

### 12.4 共通: インシデント報告書化

EU CRA 第 14 条は「悪用された脆弱性」 を 24 時間以内に当局へ早期通知 + 72 時間以内に詳細通知する
義務を課す。 SBOMHub 自身がインシデントを起こした場合 (鍵漏洩 / DB 侵害)、 製造業の自社製品の
脆弱性ではなく **SBOMHub の脆弱性** として ENISA / 各国 CSIRT への報告対象になり得る。

PSIRT は社内で以下を整備しておくこと:

- インシデント報告のドラフトテンプレ (日本語 + 英語)
- ENISA Single Reporting Platform (SRP) のアカウント
- 各国 CSIRT (日本は JPCERT/CC、 EU は ENISA + 加盟国 CSIRT) への連絡経路
- 影響テナント / 取引先 / 当局への 24h / 72h タイマー管理

---

## References

### 内部 docs (sbomhub OSS リポジトリ)

- [`docs/encryption-key-rotation.md`](../encryption-key-rotation.md) — ENCRYPTION_KEY rotation
  ランブック (本ガイド §4 から参照)
- [`docs/encryption-key-rotation.ja.md`](../encryption-key-rotation.ja.md) — 同上 日本語版
- [`docs/installation.md`](../installation.md) / [`docs/installation.ja.md`](../installation.ja.md)
  — 初期セットアップ
- [`docs/configuration.md`](../configuration.md) /
  [`docs/configuration.ja.md`](../configuration.ja.md) — 環境変数リファレンス
- [`docs/DEPLOYMENT.md`](../DEPLOYMENT.md) — 既存デプロイ手順 (本ガイドの上位 doc)
- [`docs/UPGRADE.md`](../UPGRADE.md) — マイナーバージョンアップ + ロール bootstrap 救済手順
- [`CLAUDE.md`](../../CLAUDE.md) — リポジトリ運営ガイドライン + LLM Provider Policy
- [`apps/api/cmd/server/main.go`](../../apps/api/cmd/server/main.go) — `validateEncryptionKey`
  / `assertAppRoleNotBypassRLS` 実装
- [`apps/api/migrations/023_rls_security_hardening.up.sql`](../../apps/api/migrations/023_rls_security_hardening.up.sql)
  — RLS policy + ロール分離 migration
- [`apps/api/migrations/032_llm_calls.up.sql`](../../apps/api/migrations/032_llm_calls.up.sql)
  — `llm_calls` 監査ログテーブル

### 内部 planning docs (sbomhub-internal)

- `sbomhub-internal/planning/PRODUCT_REBOOT_PLAN.md` §9 Trust Rescue / §13 M4 / §20 BYOK 制約
- `sbomhub-internal/planning/LLM_PROVIDER_DESIGN.md` §7 セキュリティ要件
- `sbomhub-internal/planning/M4_AGENT_PROMPT_TEMPLATE.md` §2 M4-4 prompt

### 外部規格 / 規制

- **EU CRA (Regulation (EU) 2024/2847)** 第 14 条 — 製造業の脆弱性 / インシデント報告義務 (悪用
  された脆弱性は 24h 早期通知 + 72h 詳細通知)
  - <https://eur-lex.europa.eu/eli/reg/2024/2847/oj>
- **経産省「ソフトウェア管理に向けた SBOM の導入に関する手引」 ver 2.0** (2024-08)
  - <https://www.meti.go.jp/policy/economy/chizai/chiteki/pdf/sbom_tebiki_ver2_0.pdf>
- **NIST SP 800-218 (Secure Software Development Framework, SSDF) v1.1**
  - <https://csrc.nist.gov/publications/detail/sp/800-218/final>
- **NIST SP 800-161r1 (Cybersecurity Supply Chain Risk Management Practices)**
  - <https://csrc.nist.gov/pubs/sp/800/161/r1/final>
- **ISO/IEC 27001:2022** A.5 / A.8 / A.12 (情報セキュリティマネジメント、 暗号統制、 ログ管理)
- **OWASP Dependency-Track Security Best Practices** (本製品は DT のアップストリームに位置する
  ため、 同等の運用規律を参考にする)
  - <https://docs.dependencytrack.org/usage/security-best-practices/>

### 関連ツール / 外部リソース

- [Caddy](https://caddyserver.com/) — TLS 終端 reverse proxy
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
  — outbound tunnel
- [step-ca](https://smallstep.com/docs/step-ca) — 内部 ACME / 内部 CA
- [SOPS](https://github.com/getsops/sops) + [age](https://github.com/FiloSottile/age) — secrets
  暗号化 git 管理
- [HashiCorp Vault](https://www.vaultproject.io/) — マルチクラウド secret 管理
- [Ollama](https://ollama.com/) — Local LLM ランタイム (§11)
- [Qwen2.5-coder model card](https://ollama.com/library/qwen2.5-coder) — 推奨 default model

---

## 変更履歴

| 日付 | バージョン | 内容 |
|---|---|---|
| 2026-06-26 | v0.1 (初版) | M4-4 (Self-host security guide for manufacturers) で新規作成 |
