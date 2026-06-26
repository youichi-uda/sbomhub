#!/usr/bin/env bash
#
# backup.sh — SBOMHub Enterprise self-host backup
#
# pg_dump (custom format) で DB を吸い出し、 ENCRYPTION_KEY を含む
# docker/secrets/ ディレクトリと合わせて 1 つの tar に固める。
#
# 重要: DB だけ復旧して ENCRYPTION_KEY を失うと、 暗号化されたカラム
# (issue_tracker_connections.auth_token_encrypted 等) が永久に復号不能になる。
# 必ず secrets と合わせて backup を取ること。
#
# M4-4 docs/security/self-host-deployment.md §9 に沿って実装。
# 関連 issue: https://github.com/youichi-uda/sbomhub/issues/49 (M4-6)
#
# 使い方:
#   ./scripts/backup.sh [BACKUP_DIR]
#   BACKUP_DIR=/srv/sbomhub/backups ./scripts/backup.sh
#
# 環境変数:
#   BACKUP_DIR    backup 出力先 (default: ./backups)
#   COMPOSE_FILE  enterprise compose file path
#                 (default: docker-compose.enterprise.yml)
#   PG_USER       pg_dump で接続する PostgreSQL role
#                 (default: sbomhub; RLS role 分離後は sbomhub_migrator)
#   PG_DB         dump 対象 database (default: sbomhub)
#   AGE_RECIPIENT age 公開鍵 (推奨)。 設定時は backup を age で暗号化する。
#                 未設定なら平文 tar.gz のまま (外部 storage 側で暗号化する想定)。

set -euo pipefail

# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------

# script の位置から docker ディレクトリへ移動 (どこから呼ばれても動くように)。
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKUP_DIR="${BACKUP_DIR:-${1:-${DOCKER_DIR}/backups}}"
COMPOSE_FILE="${COMPOSE_FILE:-${DOCKER_DIR}/docker-compose.enterprise.yml}"
PG_USER="${PG_USER:-sbomhub}"
PG_DB="${PG_DB:-sbomhub}"
AGE_RECIPIENT="${AGE_RECIPIENT:-}"

TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
WORK_DIR="${BACKUP_DIR}/${TIMESTAMP}"
SECRETS_DIR="${DOCKER_DIR}/secrets"

# ---------------------------------------------------------------------------
# 事前チェック
# ---------------------------------------------------------------------------

# docker compose CLI が使えるか
if ! command -v docker >/dev/null 2>&1; then
    echo "[backup] FATAL: docker CLI not found in PATH" >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "[backup] FATAL: 'docker compose' (v2) not available" >&2
    exit 1
fi

# compose file の存在確認
if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "[backup] FATAL: compose file not found: ${COMPOSE_FILE}" >&2
    exit 1
fi

# postgres が running か (compose 内 service として)
if ! docker compose -f "${COMPOSE_FILE}" ps --status running --services 2>/dev/null \
    | grep -qx 'postgres'; then
    echo "[backup] FATAL: postgres service is not running in ${COMPOSE_FILE}" >&2
    echo "[backup]        docker compose -f ${COMPOSE_FILE} up -d postgres" >&2
    exit 1
fi

# secrets ディレクトリの存在確認 (warning のみ、 fail させない)
if [[ ! -d "${SECRETS_DIR}" ]]; then
    echo "[backup] WARN: secrets directory not found: ${SECRETS_DIR}" >&2
    echo "[backup]       ENCRYPTION_KEY が backup に含まれません。 復号不能リスクあり。" >&2
fi

# age が利用可能か (任意)
AGE_AVAILABLE=0
if [[ -n "${AGE_RECIPIENT}" ]]; then
    if command -v age >/dev/null 2>&1; then
        AGE_AVAILABLE=1
    else
        echo "[backup] WARN: AGE_RECIPIENT is set but 'age' CLI not found in PATH" >&2
        echo "[backup]       平文 tar.gz のまま出力します。 https://github.com/FiloSottile/age" >&2
    fi
fi

# ---------------------------------------------------------------------------
# backup 実行
# ---------------------------------------------------------------------------

echo "[backup] timestamp:    ${TIMESTAMP}"
echo "[backup] backup dir:   ${WORK_DIR}"
echo "[backup] compose file: ${COMPOSE_FILE}"
echo "[backup] pg user:      ${PG_USER}"
echo "[backup] pg db:        ${PG_DB}"

mkdir -p "${WORK_DIR}"

# 1. pg_dump custom format (-Fc): pg_restore で柔軟に復元可能。
echo "[backup] step 1/3: pg_dump"
docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    pg_dump -U "${PG_USER}" -Fc -d "${PG_DB}" \
    > "${WORK_DIR}/db.dump"

DUMP_SIZE="$(stat -c '%s' "${WORK_DIR}/db.dump" 2>/dev/null \
    || stat -f '%z' "${WORK_DIR}/db.dump" 2>/dev/null \
    || echo 'unknown')"
echo "[backup]   db.dump size: ${DUMP_SIZE} bytes"

if [[ "${DUMP_SIZE}" == "0" ]] || [[ "${DUMP_SIZE}" == "unknown" ]]; then
    echo "[backup] FATAL: db.dump is empty or unreadable" >&2
    exit 1
fi

# 2. secrets/ ディレクトリを丸ごと同梱 (ENCRYPTION_KEY + DB password)。
#    docker secrets は file mount なので、 元 file (docker/secrets/*) を
#    そのまま tar に入れれば復元時に同じ場所に展開すれば良い。
if [[ -d "${SECRETS_DIR}" ]]; then
    echo "[backup] step 2/3: copy secrets"
    # secrets ディレクトリの permission を保持して copy
    cp -a "${SECRETS_DIR}" "${WORK_DIR}/secrets"
    # 念のため owner-only に閉じる
    chmod -R go-rwx "${WORK_DIR}/secrets"
else
    echo "[backup] step 2/3: skip secrets (directory not found)"
fi

# 3. tar で 1 file にまとめる。 secrets を含むため permission を保持。
echo "[backup] step 3/3: tar"
TARBALL="${BACKUP_DIR}/sbomhub-backup-${TIMESTAMP}.tar.gz"
tar czf "${TARBALL}" -C "${BACKUP_DIR}" "${TIMESTAMP}"

# 中間ディレクトリは secrets が平文で含まれるため即削除
rm -rf "${WORK_DIR}"

# tar 自体も permission を絞る
chmod 600 "${TARBALL}"

# 4. age で暗号化 (任意)
if [[ "${AGE_AVAILABLE}" -eq 1 ]]; then
    echo "[backup] step 4/4: age encrypt"
    age -r "${AGE_RECIPIENT}" -o "${TARBALL}.age" "${TARBALL}"
    chmod 600 "${TARBALL}.age"
    # 平文 tar を削除 (age 暗号化済みファイルだけ残す)
    rm -f "${TARBALL}"
    echo "[backup] Backup completed: ${TARBALL}.age"
else
    echo "[backup] Backup completed: ${TARBALL}"
    echo "[backup] NOTE: 平文 tar.gz のままです。"
    echo "[backup]       offsite 転送する前に age / GPG / KMS で暗号化することを強く推奨。"
fi

# ---------------------------------------------------------------------------
# 完了通知
# ---------------------------------------------------------------------------
echo "[backup] Done."
