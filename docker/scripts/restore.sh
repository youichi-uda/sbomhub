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
    echo "[restore] step 1/5: age decrypt"
    age -d -i "${AGE_IDENTITY}" -o "${PLAIN_TAR}" "${BACKUP_TARBALL}"
    chmod 600 "${PLAIN_TAR}"
else
    PLAIN_TAR="${BACKUP_TARBALL}"
fi

echo "[restore] step 2/5: tar extract"
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

echo "[restore] step 3/5: pg_restore (DROP + REPLACE, --single-transaction)"
# --single-transaction:
#   全 restore を 1 transaction に閉じ、 途中 failure 時に rollback (DROP も含めて)。
#   部分適用で DB を inconsistent state にしないため必須。 backup.sh は
#   pg_dump -Fc (custom format) で出力しており --single-transaction と互換。
#   ※要確認: 大規模 DB では 1 trx 化により WAL / memory 圧迫リスクがある
#   (数十 GB 級 prod の場合)、 その場合は本 fix の後続 issue で
#   --clean --if-exists のまま transaction を分割する代替案を検討予定。
#   parallel restore (`-j`) との同時利用は禁止 (pg_restore の制約)、 本 script では
#   `-j` を使っていないので衝突なし。
if ! docker compose -f "${COMPOSE_FILE}" exec -T postgres \
        pg_restore -U "${PG_USER}" -d "${PG_DB}" \
        --clean --if-exists --single-transaction --no-owner --no-privileges \
        < "${DB_DUMP}"; then
    echo "[restore] FATAL: pg_restore failed (--single-transaction rolled back the entire restore)." >&2
    echo "[restore]        DB は restore 開始前の状態に戻っている **はず** ですが、" >&2
    echo "[restore]        secrets 復元と API 再起動には進みません。" >&2
    echo "[restore]        詳細: docker compose -f ${COMPOSE_FILE} logs postgres" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# DB sanity checks (post-restore)
# ---------------------------------------------------------------------------
# F65: pg_restore success だけでは partial apply / silent corruption を検出
# できないため、 主要 invariant を SQL で確認する。 失敗時は secrets 復元と
# API 再起動には進まず exit 1 (operator の判断対象とする)。

echo "[restore] step 4/5: post-restore sanity checks"

# Check 1: schema_migrations が存在し latest version が取れること。
# migrate 機構 (apps/api/cmd/migrate, apps/api/internal/database/migrate.go) は
# schema_migrations(version VARCHAR(255) PRIMARY KEY, applied_at TIMESTAMP) を
# 必ず作る。 restore 後にこの table が引けなければ schema 自体が壊れている。
LATEST_MIG_RAW="$(docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    psql -U "${PG_USER}" -d "${PG_DB}" -tA -v ON_ERROR_STOP=1 -c \
    "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1;" 2>&1)" || {
        echo "[restore] FATAL: schema_migrations query failed after restore:" >&2
        awk '{print "[restore]   " $0}' <<< "${LATEST_MIG_RAW}" >&2
        echo "[restore]        restore は schema を完全には流せていない可能性があります。" >&2
        exit 1
    }
LATEST_MIG="$(printf '%s' "${LATEST_MIG_RAW}" | tr -d '[:space:]')"
if [[ -z "${LATEST_MIG}" ]]; then
    echo "[restore] FATAL: schema_migrations is empty after restore" >&2
    echo "[restore]        backup が壊れているか、 別 DB の dump の可能性。" >&2
    exit 1
fi
echo "[restore]   schema_migrations latest version: ${LATEST_MIG}"

# Check 2: tenants table が query 可能なこと。 count は warning までで止める
# (fresh install backup なら 0 件は legitimate なケースがあるため)。
TENANT_COUNT_RAW="$(docker compose -f "${COMPOSE_FILE}" exec -T postgres \
    psql -U "${PG_USER}" -d "${PG_DB}" -tA -v ON_ERROR_STOP=1 -c \
    "SELECT count(*) FROM tenants;" 2>&1)" || {
        echo "[restore] FATAL: tenants query failed after restore:" >&2
        awk '{print "[restore]   " $0}' <<< "${TENANT_COUNT_RAW}" >&2
        echo "[restore]        tenants table が無い / RLS で見えないなど。" >&2
        exit 1
    }
TENANT_COUNT="$(printf '%s' "${TENANT_COUNT_RAW}" | tr -d '[:space:]')"
if ! [[ "${TENANT_COUNT}" =~ ^[0-9]+$ ]]; then
    echo "[restore] FATAL: tenants count is not numeric: '${TENANT_COUNT}'" >&2
    exit 1
fi
if [[ "${TENANT_COUNT}" -eq 0 ]]; then
    echo "[restore]   WARN: tenants table is empty (fresh-install backup の可能性、 production restore なら要調査)" >&2
else
    echo "[restore]   tenants count: ${TENANT_COUNT}"
fi

# ※要確認: ENCRYPTION_KEY を使った復号 smoke test (BYOK token 等の
# round-trip 確認) は別 issue で `verify-encryption.sh` として実装予定。
# 本 fix では sanity check 範囲は migration version + tenants 件数のみとする。

# ---------------------------------------------------------------------------
# Secrets 復元
# ---------------------------------------------------------------------------

if [[ -d "${BACKUP_SECRETS}" ]]; then
    echo "[restore] step 5/5: secrets restore"
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
    echo "[restore] step 5/5: skip secrets (not present in backup)"
    echo "[restore]          既存の docker/secrets/ をそのまま使用します。"
fi

# ---------------------------------------------------------------------------
# 完了通知 + 次手順
# ---------------------------------------------------------------------------
# ここに辿り着くのは pg_restore success + sanity checks pass + secrets 復元
# 完了の **全てが** 通った場合のみ (途中 failure は exit 1 で abort 済)。

echo ""
echo "[restore] Restore completed successfully (pg_restore + sanity checks passed)."
echo ""
echo "[restore] Next steps:"
echo "  1. sbomhub-api / sbomhub-web を再起動 (secrets / DB が変わったため):"
echo "       docker compose -f ${COMPOSE_FILE} up -d --force-recreate sbomhub-api sbomhub-web"
echo "  2. 起動 log で ENCRYPTION_KEY check / DB role check が PASS することを確認:"
echo "       docker compose -f ${COMPOSE_FILE} logs sbomhub-api | grep -E 'ENCRYPTION_KEY|DB role'"
echo "  3. health endpoint が 200 を返すことを確認:"
echo "       curl -fsS http://localhost:8080/health"
echo "  4. ※要確認: ENCRYPTION_KEY 復号 smoke test (BYOK token 等の round-trip)"
echo "     は別 issue で verify-encryption.sh として用意予定。 暫定で API 起動 log の"
echo "     'ENCRYPTION_KEY check passed' と issue_tracker_connections / webhook の"
echo "     既存 record が UI から開けることを手動確認すること。"
echo ""
