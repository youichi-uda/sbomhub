# SBOMHub Enterprise Secrets

`docker-compose.enterprise.yml` (M4-6) が読み込む docker secrets の sample。
**実 secrets はこのディレクトリではなく `docker/secrets/` に置く** (gitignore
済み、 リポジトリには絶対に commit しない)。

## 構成

| File | 用途 | 生成コマンド |
|---|---|---|
| `encryption_key.txt` | アプリ層 AES-256-GCM のマスタ鍵。 `issue_tracker_connections.auth_token_encrypted` 等を守る。 32 byte 必須。 | `openssl rand -base64 32` |
| `postgres_password.txt` | PostgreSQL `sbomhub` ロールの password。 base64 推奨 (URL escape 注意)。 | `openssl rand -base64 24` |

## 初期セットアップ

```bash
# 1. sample をコピーして実 secrets ディレクトリを用意
cd docker
cp -r secrets.example secrets

# 2. それぞれを安全なランダム値で生成 (sample placeholder は使用禁止)
openssl rand -base64 32 > secrets/encryption_key.txt
openssl rand -base64 24 > secrets/postgres_password.txt

# 3. パーミッションを厳格化 (owner only)
chmod 600 secrets/*
chmod 700 secrets

# 4. 起動
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

## production への移行 (RLS role 分離)

このディレクトリの sample は **最小構成** (単一 `sbomhub` ロール) を想定する。
M4-4 §3 で説明される sbomhub_app / sbomhub_migrator の 2 ロール分離
(RLS bypass 禁止) を有効にする場合、 以下を追加する:

```bash
# 追加 secrets
openssl rand -base64 24 > secrets/postgres_app_password.txt
openssl rand -base64 24 > secrets/postgres_migrator_password.txt
chmod 600 secrets/postgres_*_password.txt

# 既存 postgres コンテナにロールを bootstrap
# (本リポジトリの install.sh を流用する)
../install.sh --bootstrap-roles
```

その後 `docker-compose.enterprise.yml` の `sbomhub-api.environment` を編集して
`POSTGRES_APP_USER` / `POSTGRES_MIGRATOR_USER` を `sbomhub_app` / `sbomhub_migrator`
に切り替え、 secrets として `postgres_app_password` / `postgres_migrator_password`
を mount し、 wrapper script が読む `*_PASSWORD_FILE` パスを更新する。

詳細は [`../README.enterprise.md`](../README.enterprise.md) §3 を参照。

## 参考

- [`../README.enterprise.md`](../README.enterprise.md) — Enterprise compose の運用ガイド
- [`../../docs/security/self-host-deployment.md`](../../docs/security/self-host-deployment.md) — セルフホストセキュリティ運用ガイド (M4-4)
- [`../../docs/encryption-key-rotation.md`](../../docs/encryption-key-rotation.md) — 鍵 rotation ランブック
