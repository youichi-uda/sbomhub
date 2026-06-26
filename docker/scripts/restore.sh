#!/usr/bin/env bash
#
# restore.sh — SBOMHub Enterprise self-host restore
#
# backup.sh で取得した tar (or tar.age) を展開し、 pg_restore で DB を
# 入れ替え、 secrets/ ディレクトリを所定位置に復元する。
#
# 重要: 既存 DB を **--clean --if-exists で全削除して入れ直す** 破壊的操作。
# 必ず対話確認を経てから実行する。 既存 secrets を上書きするので、
# まだ動いている本番環境への適用は避けること (ロールバック用 backup を
# 別途取ってから restore する)。
#
# M4-4 docs/security/self-host-deployment.md §9.3 に沿って実装。
# 関連 issue: https://github.com/youichi-uda/sbomhub/issues/49 (M4-6)
#
# 使い方:
#   ./scripts/restore.sh BACKUP_TARBALL
#   ./scripts/restore.sh /srv/sbomhub/backups/sbomhub-backup-20260626-031000.tar.gz
#   ./scripts/restore.sh /srv/sbomhub/backups/sbomhub-backup-20260626-031000.tar.gz.age
#
# 環境変数:
#   COMPOSE_FILE      enterprise compose file path
#                     (default: docker-compose.enterprise.yml)
#   PG_USER           pg_restore で接続する PostgreSQL role
#                     (default: sbomhub; RLS role 分離後は sbomhub_migrator)
#   PG_DB             restore 先 database (default: sbomhub)
#   AGE_IDENTITY      age 秘密鍵 file path (.age tarball を解く場合に必須)
#   FORCE             "yes" を渡すと対話確認を skip (CI / 自動運用向け)

set -euo pipefail

# ---------------------------------------------------------------------------
# 引数 / 設定
# ---------------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 BACKUP_TARBALL" >&2
    echo "  BACKUP_TARBALL: backup.sh が出力した tar.gz または tar.gz.age ファイル" >&2
    exit 2
fi

BACKUP_TARBALL="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

COMPOSE_FILE="${COMPOSE_FILE:-${DOCKER_DIR}/docker-compose.enterprise.yml}"
PG_USER="${PG_USER:-sbomhub}"
PG_DB="${PG_DB:-sbomhub}"
AGE_IDENTITY="${AGE_IDENTITY:-}"
FORCE="${FORCE:-no}"

SECRETS_DIR="${DOCKER_DIR}/secrets"

# ---------------------------------------------------------------------------
# 事前チェック
# ---------------------------------------------------------------------------

if [[ ! -f "${BACKUP_TARBALL}" ]]; then
    echo "[restore] FATAL: backup file not found: ${BACKUP_TARBALL}" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[restore] FATAL: docker CLI not found in PATH" >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "[restore] FATAL: 'docker compose' (v2) not available" >&2
    exit 1
fi

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "[restore] FATAL: compose file not found: ${COMPOSE_FILE}" >&2
    exit 1
fi

# .age 暗号化されている場合は age + identity が必要
NEEDS_AGE=0
case "${BACKUP_TARBALL}" in
    *.age)
        NEEDS_AGE=1
        if ! command -v age >/dev/null 2>&1; then
            echo "[restore] FATAL: 'age' CLI not found, but backup is .age encrypted" >&2
            exit 1
        fi
        if [[ -z "${AGE_IDENTITY}" || ! -r "${AGE_IDENTITY}" ]]; then
            echo "[restore] FATAL: AGE_IDENTITY env (age private key file) is required for .age backup" >&2
            exit 1
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# 対話確認
# ---------------------------------------------------------------------------

echo "[restore] backup file:  ${BACKUP_TARBALL}"
echo "[restore] compose file: ${COMPOSE_FILE}"
echo "[restore] pg user:      ${PG_USER}"
echo "[restore] pg db:        ${PG_DB}"
echo "[restore] secrets dir:  ${SECRETS_DIR}"
echo ""
echo "[restore] WARNING: this will run pg_restore with --clean --if-exists,"
echo "[restore]          which DROPS all existing schema objects in '${PG_DB}'"
echo "[restore]          and replaces them with the backup contents."
echo "[restore]          docker/secrets/ will also be OVERWRITTEN from the backup."
echo ""

if [[ "${FORCE}" != "yes" ]]; then
    # bash の read は "yes" 以外を全て abort 扱いにする (no / empty / Ctrl-D)
    read -r -p 'Type "yes" to continue, anything else aborts: ' CONFIRM
    if [[ "${CONFIRM}" != "yes" ]]; then
        echo "[restore] aborted by user (input was: '${CONFIRM:-<empty>}')" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# 一時ディレクトリ
# ---------------------------------------------------------------------------

TMP_DIR="$(mktemp -d -t sbomhub-restore.XXXXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# ---------------------------------------------------------------------------
# 復号 + 展開
# ---------------------------------------------------------------------------

PLAIN_TAR="${TMP_DIR}/backup.tar.gz"

if [[ "${NEEDS_AGE}" -eq 1 ]]; then
    echo "[restore] step 1/4: age decrypt"
    age -d -i "${AGE_IDENTITY}" -o "${PLAIN_TAR}" "${BACKUP_TARBALL}"
    chmod 600 "${PLAIN_TAR}"
else
    PLAIN_TAR="${BACKUP_TARBALL}"
fi

echo "[restore] step 2/4: tar extract"
tar xzf "${PLAIN_TAR}" -C "${TMP_DIR}"

# tar 内構造: <timestamp>/db.dump + <timestamp>/secrets/...
EXTRACTED_DIR="$(find "${TMP_DIR}" -maxdepth 1 -mindepth 1 -type d ! -name 'backup.tar.gz' | head -1)"
if [[ -z "${EXTRACTED_DIR}" ]]; then
    echo "[restore] FATAL: extracted directory not found in tarball" >&2
    exit 1
fi
DB_DUMP="${EXTRACTED_DIR}/db.dump"
BACKUP_SECRETS="${EXTRACTED_DIR}/secrets"

if [[ ! -f "${DB_DUMP}" ]]; then
    echo "[restore] FATAL: db.dump not found in backup: ${DB_DUMP}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# DB restore
# ---------------------------------------------------------------------------

# postgres service が running か
if ! docker compose -f "${COMPOSE_FILE}" ps --status running --services 2>/dev/null \
    | grep -qx 'postgres'; then
    echo "[restore] FATAL: postgres service is not running in ${COMPOSE_FILE}" >&2
    echo "[restore]        docker compose -f ${COMPOSE_FILE} up -d postgres" >&2
    exit 1
fi

echo "[restore] step 3/4: pg_restore (DROP + REPLACE)"
docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    pg_restore -U "${PG_USER}" -d "${PG_DB}" \
    --clean --if-exists --no-owner --no-privileges \
    < "${DB_DUMP}" \
    || {
        echo "[restore] WARN: pg_restore reported errors (non-zero exit)." >&2
        echo "[restore]       restore may have partially applied; check db state." >&2
        # pg_restore は warning でも非ゼロ終了することがあるので、 後続の
        # secrets 復元は止めず、 user に判断させる。
    }

# ---------------------------------------------------------------------------
# Secrets 復元
# ---------------------------------------------------------------------------

if [[ -d "${BACKUP_SECRETS}" ]]; then
    echo "[restore] step 4/4: secrets restore"
    if [[ -d "${SECRETS_DIR}" ]]; then
        # 既存 secrets を上書き前に rename して退避 (rollback 可能に)
        BACKUP_OLD_SECRETS="${SECRETS_DIR}.bak-$(date -u +%Y%m%d-%H%M%S)"
        mv "${SECRETS_DIR}" "${BACKUP_OLD_SECRETS}"
        echo "[restore]   existing secrets moved to: ${BACKUP_OLD_SECRETS}"
    fi
    cp -a "${BACKUP_SECRETS}" "${SECRETS_DIR}"
    chmod -R go-rwx "${SECRETS_DIR}"
    echo "[restore]   secrets restored to: ${SECRETS_DIR}"
else
    echo "[restore] step 4/4: skip secrets (not present in backup)"
    echo "[restore]          既存の docker/secrets/ をそのまま使用します。"
fi

# ---------------------------------------------------------------------------
# 完了通知 + 次手順
# ---------------------------------------------------------------------------

echo ""
echo "[restore] Restore completed."
echo ""
echo "[restore] Next steps:"
echo "  1. sbomhub-api / sbomhub-web を再起動 (secrets / DB が変わったため):"
echo "       docker compose -f ${COMPOSE_FILE} up -d --force-recreate sbomhub-api sbomhub-web"
echo "  2. 起動 log で ENCRYPTION_KEY check / DB role check が PASS することを確認:"
echo "       docker compose -f ${COMPOSE_FILE} logs sbomhub-api | grep -E 'ENCRYPTION_KEY|DB role'"
echo "  3. health endpoint が 200 を返すことを確認:"
echo "       curl -fsS http://localhost:8080/health"
echo ""
