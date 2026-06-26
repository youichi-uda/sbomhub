# SBOMHub Enterprise Secrets

`docker-compose.enterprise.yml` (M4-6) が読み込む docker secrets の sample。
**実 secrets はこのディレクトリではなく `docker/secrets/` に置く** (gitignore
済み、 リポジトリには絶対に commit しない)。

## 構成

| File | 用途 | 生成コマンド |
|---|---|---|
| `encryption_key.txt` | アプリ層 AES-256-GCM のマスタ鍵。 `issue_tracker_connections.auth_token_encrypted` 等を守る。 32 byte 必須。 | `openssl rand -base64 32` |
| `postgres_password.txt` | PostgreSQL の **bootstrap superuser** (`sbomhub`、 POSTGRES_USER) の password。 postgres service の initdb と `db-bootstrap` one-shot service の admin 接続専用 (sbomhub-api 本体はこれを使わない)。 | `openssl rand -base64 24` |
| `postgres_app_password.txt` | sbomhub-api runtime 接続用 (`sbomhub_app` ロール、 NOSUPERUSER NOBYPASSRLS)。 M4 Codex review #F76 fix で default 化。 | `openssl rand -base64 24` |
| `postgres_migrator_password.txt` | 自動 migration 接続用 (`sbomhub_migrator` ロール、 NOBYPASSRLS + schema CREATE)。 M4 Codex review #F76 fix で default 化。 | `openssl rand -base64 24` |

> **役割分担 (M4 Codex review #F76 fix 以降)**:
> `postgres_password` は **bootstrap superuser** 専用、 sbomhub-api には渡らない。
> sbomhub-api は `sbomhub_app` (runtime) / `sbomhub_migrator` (migrations) の
> 2 ロールに分離されており、 それぞれ専用 password file を mount する。
> 役割分離は `db-bootstrap` one-shot service が compose 起動時に自動で
> 投入するため、 manual 操作は不要 (詳細: `../README.enterprise.md` §3)。
> 旧構成 (`install.sh --bootstrap-roles` 経由 manual setup) は依然として
> advanced operator 向けに動作する (SQL pattern が完全に一致しているため、
> どちらを実行しても結果は同じ)。

## 初期セットアップ

```bash
# 1. sample をコピーして実 secrets ディレクトリを用意
cd docker
cp -r secrets.example secrets

# 2. それぞれを安全なランダム値で生成 (sample placeholder は使用禁止)
openssl rand -base64 32 | tr -d '\n' > secrets/encryption_key.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_app_password.txt
openssl rand -base64 24 | tr -d '\n' > secrets/postgres_migrator_password.txt

# 3. パーミッションを厳格化 (owner only)
chmod 600 secrets/*
chmod 700 secrets

# 4. 起動 (db-bootstrap が起動時に sbomhub_app / sbomhub_migrator ロールを
#    冪等作成する。 manual install.sh --bootstrap-roles は不要)
docker compose -f docker-compose.enterprise.yml up -d
```

## 重要規律

- **実 secrets を git に commit しない**。 リポジトリ root の
  [`.gitignore`](../../.gitignore) で `docker/secrets/` を除外済み。
  間違って commit した場合は即座に key rotation
  (`docs/encryption-key-rotation.md` 参照)。
- **改行を含めない**。 `openssl rand -base64 32` は末尾に改行を 1 つ付ける。
  docker secrets は file 全体を value として扱うので、 末尾改行があると
  ENCRYPTION_KEY 長が +1 byte (33 byte) になる。 32 byte 厳守なら
  `openssl rand -base64 32 | tr -d '\n' > secrets/encryption_key.txt`
  のほうが安全。 ※要確認: `apps/api/cmd/server/main.go` の
  `validateEncryptionKey` は ≥32 byte で通る (33 byte でも fail しない)、
  ただし整合性のためには改行除去を推奨。
- **password に special char が混じる場合**: docker-compose.enterprise.yml の
  entrypoint wrapper は `+`, `/`, `=`, `@`, `:`, `?`, `#`, `&` を URL escape する
  最小限の処理を行う。 base64 出力ならこの範囲で十分。 raw passphrase を
  使う場合は special char が含まれないことを確認すること。
- **rotation 手順**: M4-4 [`docs/security/self-host-deployment.md`](../../docs/security/self-host-deployment.md)
  §4.4 + [`docs/encryption-key-rotation.md`](../../docs/encryption-key-rotation.md) 参照。
  Docker secrets は standalone compose では tmpfs マウントだが TTL 機能はないので、
  rotation 時は `docker compose -f docker-compose.enterprise.yml up -d --force-recreate sbomhub-api`
  で再起動が必要。

## production への移行 (RLS role 分離) — M4 Codex review #F76 で default 化

このディレクトリの sample は **default で sbomhub_app / sbomhub_migrator の
2 ロール分離** (RLS bypass 禁止) を前提とする。 `docker-compose.enterprise.yml`
の `db-bootstrap` one-shot service が postgres healthy 直後に起動し、
`secrets/postgres_app_password.txt` / `secrets/postgres_migrator_password.txt`
の値で `sbomhub_app` (NOSUPERUSER NOBYPASSRLS) / `sbomhub_migrator`
(NOBYPASSRLS + schema CREATE) ロールを冪等作成 → privilege grant → 必要なら
legacy 所有 tables の ALTER OWNER 移譲、 までを自動で完了する。

sbomhub-api はこの 2 ロール + 各 password file を読んで接続するため、 manual
`install.sh --bootstrap-roles` の実行は **不要** (旧 M4-6 では必須だった、
[#F76](https://github.com/youichi-uda/sbomhub/issues/) で default 起動 path
を修正)。

```bash
# default 起動 (sbomhub_app / sbomhub_migrator は db-bootstrap が自動投入)
docker compose -f docker-compose.enterprise.yml up -d

# 起動 log で sbomhub_app の RLS 強制を確認
docker compose -f docker-compose.enterprise.yml logs db-bootstrap   # 期待: "role bootstrap complete"
docker compose -f docker-compose.enterprise.yml logs sbomhub-api | grep 'DB role check'
# 期待: "DB role check passed role=sbomhub_app bypass_rls=false superuser=false"
```

**advanced operator 向け**: `install.sh --bootstrap-roles` も依然として動作する
(SQL pattern が `db-bootstrap` service と一致しているため重複実行しても無害)。
host から OSS compose を使っていて、 そこに後付けで role 分離を入れたい場合は
従来通り [`../../install.sh`](../../install.sh) を参照。

詳細は [`../README.enterprise.md`](../README.enterprise.md) §3 を参照。

## 参考

- [`../README.enterprise.md`](../README.enterprise.md) — Enterprise compose の運用ガイド
- [`../../docs/security/self-host-deployment.md`](../../docs/security/self-host-deployment.md) — セルフホストセキュリティ運用ガイド (M4-4)
- [`../../docs/encryption-key-rotation.md`](../../docs/encryption-key-rotation.md) — 鍵 rotation ランブック
