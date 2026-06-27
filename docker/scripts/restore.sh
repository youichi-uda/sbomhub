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
# F79: enterprise compose (role-separated sbomhub_app / sbomhub_migrator) では
# pg_restore --no-owner --no-privileges が ACL を落とすため、 secrets 復元後に
# db-bootstrap one-shot service を再実行して GRANT / OWNER を再付与し、
# sbomhub_app 接続で実際に SELECT できることまで確認してから success を返す。
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
#   VERIFY_ENCRYPTION "1" を渡すと post-restore に verify-encryption.sh を
#                     smoke test として実行 (M5-5、 issue #53)。 復号失敗
#                     (exit 1) / DB error (exit 2) / no row (exit 3) は
#                     **warning ログのみで restore 全体は continue** する
#                     (smoke posture; 厳格チェックが要るなら CI 側で
#                     verify-encryption.sh を別ステップで再実行する)。
#   VERIFY_DB_URL     verify-encryption.sh に渡す DSN override
#                     (default: postgres://sbomhub_app:<file>@postgres:5432/...)

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
VERIFY_ENCRYPTION="${VERIFY_ENCRYPTION:-0}"
VERIFY_DB_URL="${VERIFY_DB_URL:-}"

SECRETS_DIR="${DOCKER_DIR}/secrets"

sql_literal_escape() {
    local value=$1
    value=${value//\'/\'\'}
    printf '%s' "${value}"
}

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
    echo "[restore] step 1/7: age decrypt"
    age -d -i "${AGE_IDENTITY}" -o "${PLAIN_TAR}" "${BACKUP_TARBALL}"
    chmod 600 "${PLAIN_TAR}"
else
    PLAIN_TAR="${BACKUP_TARBALL}"
fi

echo "[restore] step 2/7: tar extract"
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

echo "[restore] step 3/7: pg_restore (DROP + REPLACE, --single-transaction)"
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

echo "[restore] step 4/7: post-restore sanity checks"

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

# ENCRYPTION_KEY を使った復号 smoke test (BYOK token 等の round-trip 確認)
# は M5-5 / issue #53 で `./scripts/verify-encryption.sh` として実装済。
# 本 fix の sanity check 範囲は migration version + tenants 件数のみとし、
# 復号 round-trip は opt-in (VERIFY_ENCRYPTION=1) で Step 8 として走らせる。

# ---------------------------------------------------------------------------
# Secrets 復元
# ---------------------------------------------------------------------------

if [[ -d "${BACKUP_SECRETS}" ]]; then
    echo "[restore] step 5/7: secrets restore"
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
    echo "[restore] step 5/7: skip secrets (not present in backup)"
    echo "[restore]          既存の docker/secrets/ をそのまま使用します。"
fi

# ---------------------------------------------------------------------------
# Admin role password convergence (F80 fix — DR scenario blocker)
# ---------------------------------------------------------------------------
# F80: pg_restore は PostgreSQL role password を **復元しない** (DB schema + data
# のみ復元、 `pg_authid` 等の cluster-level role 情報は対象外)。 結果:
#
#   - **production hot restore** (同一 volume / 同一 host): 既存 `sbomhub`
#     role password = 復元される `postgres_password.txt` なので Step 6
#     db-bootstrap の admin TCP 接続は成功する。
#   - **DR / fresh volume / 別 host への cold restore**: postgres image init は
#     新 host の `secrets/postgres_password.txt` (= 新 random password) で
#     `sbomhub` role を作成済み、 一方 Step 5 で `postgres_password.txt` が
#     backup 取得時の password に上書きされる。 結果、 Step 6 db-bootstrap が
#     `psql -h postgres -U sbomhub` で TCP 認証失敗 → exit 1 で restore 不能。
#     DR は backup 運用の主目的なので fix 必須。
#
# Step 5.5 で `ALTER ROLE sbomhub WITH PASSWORD '<restored>'` を実行し、 実 DB
# admin role password を restored secret 値に矯正する。 接続は postgres
# container 内 Unix socket 経由 (`docker compose exec -T postgres psql -U sbomhub`、
# `-h` 不使用)。 postgres:15-alpine official image は local Unix socket 接続に
# **trust auth** を default で設定するため、 password env なしで admin connection
# が成立する (Step 3 pg_restore / Step 4 sanity check も同経路で動作している、
# 同前提を共有)。 これにより pre-restore admin password の取得手段は不要、
# DR scenario / hot restore の両方を同一 path で処理できる。
#
# password 値の SQL embedding は db-bootstrap entrypoint と同じ規律 (stdin
# 先頭の SELECT ... \gset で client-side `:'var'` literal quoting +
# server-side `format('%L', ...)`)。raw password 値は docker compose / psql
# argv に載せず、 single quote escape 済みの SQL literal として stdin 経由で
# 渡す (codex-r8 P2 と同 species)。
#
# standard `docker-compose.yml` (OSS dev 用、 sbomhub superuser 単一ロール) では
# sbomhub-api が `sbomhub` superuser で直接接続する旧構成のため、 admin role
# password の converge は不要 (Step 6 db-bootstrap も非実行)。 enterprise
# compose のみで実行する (compose file 名で判定)。

echo "[restore] step 5.5/7: converge postgres admin role password to restored secret (DR scenario)"
COMPOSE_BASENAME="$(basename "${COMPOSE_FILE}")"
case "${COMPOSE_BASENAME}" in
    *enterprise*)
        if [[ ! -d "${BACKUP_SECRETS}" ]]; then
            echo "[restore]   skip: secrets were not restored (Step 5 was a no-op, admin password unchanged)"
        else
            RESTORED_ADMIN_PASSWORD_FILE="${SECRETS_DIR}/postgres_password.txt"
            if [[ ! -r "${RESTORED_ADMIN_PASSWORD_FILE}" ]]; then
                echo "[restore] FATAL: restored admin password file not readable: ${RESTORED_ADMIN_PASSWORD_FILE}" >&2
                echo "[restore]        secrets restore が壊れている可能性 (backup tarball の secrets/ 配下を確認)。" >&2
                exit 1
            fi
            RESTORED_ADMIN_PASSWORD="$(cat "${RESTORED_ADMIN_PASSWORD_FILE}")"
            if [[ -z "${RESTORED_ADMIN_PASSWORD}" ]]; then
                echo "[restore] FATAL: restored postgres_password.txt is empty" >&2
                exit 1
            fi
            RESTORED_ADMIN_PASSWORD_SQL="$(sql_literal_escape "${RESTORED_ADMIN_PASSWORD}")"
            # Unix socket trust auth で admin 接続 → ALTER ROLE。 `\gexec` は
            # `SELECT format(...)` の結果 1 行を SQL として実行する psql 機能。
            # `2>&1` で stderr を握り、 failure 時に raw 出力を error log に
            # awk 整形して出す。
            ALTER_OUTPUT="$(docker compose -f "${COMPOSE_FILE}" exec -T \
                postgres \
                psql -U sbomhub -d "${PG_DB}" \
                     -tA -v ON_ERROR_STOP=1 2>&1 <<SQL
SELECT '${RESTORED_ADMIN_PASSWORD_SQL}' AS new_admin_pw
\gset
SELECT format('ALTER ROLE %I WITH PASSWORD %L', 'sbomhub', :'new_admin_pw')
\gexec
SQL
            )" || {
                unset RESTORED_ADMIN_PASSWORD RESTORED_ADMIN_PASSWORD_SQL
                echo "[restore] FATAL: failed to converge postgres admin role password:" >&2
                awk '{print "[restore]   " $0}' <<< "${ALTER_OUTPUT}" >&2
                echo "[restore]        Step 6 db-bootstrap は restored postgres_password.txt で TCP 接続するため、" >&2
                echo "[restore]        admin role password が DB 側と一致していないと認証失敗で abort します。" >&2
                echo "[restore]        詳細: docker compose -f ${COMPOSE_FILE} logs postgres" >&2
                echo "[restore]        手動 recovery: docker compose -f ${COMPOSE_FILE} exec postgres \\" >&2
                echo "[restore]                          psql -U sbomhub -c \"ALTER ROLE sbomhub PASSWORD '<value>';\"" >&2
                exit 1
            }
            unset RESTORED_ADMIN_PASSWORD RESTORED_ADMIN_PASSWORD_SQL
            echo "[restore]   admin role 'sbomhub' password converged to restored secret"
        fi
        ;;
    *)
        echo "[restore]   skip: non-enterprise compose (single-role mode, no db-bootstrap re-run)"
        ;;
esac

# ---------------------------------------------------------------------------
# Role grants / ownership re-bootstrap (F79 fix)
# ---------------------------------------------------------------------------
# F79: pg_restore は `--no-owner --no-privileges` で復元しているため、 restored
# objects は `--clean --if-exists` の DROP で削除された後、 接続 user (PG_USER /
# default `sbomhub` superuser) が owner となり ACL は付かない。 enterprise
# compose では F76 fix 後に sbomhub-api が `sbomhub_app` (NOSUPERUSER /
# NOBYPASSRLS) として接続する規律になったため、 ここで db-bootstrap one-shot
# service を再実行して以下を再付与する:
#   - sbomhub_app / sbomhub_migrator role の存在 + password rotation
#   - tables / sequences への GRANT (sbomhub_app: SELECT/INSERT/UPDATE/DELETE,
#     sbomhub_migrator: ALL)
#   - 既存 `sbomhub` owned objects の `sbomhub_migrator` への ALTER OWNER
#   - ALTER DEFAULT PRIVILEGES (将来 migrator が CREATE する table も自動付与)
#
# これを怠ると、 restore は sanity check (PG_USER=sbomhub_migrator/sbomhub で
# 実行) は通るが、 sbomhub-api 起動時に sbomhub_app が table SELECT で
# permission denied になり、 API が serve しない production blocker になる。
#
# standard `docker-compose.yml` (OSS dev 用、 sbomhub superuser 単一ロール) では
# db-bootstrap service 自体が存在しないため skip (compose file 名で判定)。

echo "[restore] step 6/7: re-apply role grants and ownership (db-bootstrap)"
case "${COMPOSE_BASENAME}" in
    *enterprise*)
        if ! docker compose -f "${COMPOSE_FILE}" run --rm db-bootstrap; then
            echo "[restore] FATAL: db-bootstrap failed after restore." >&2
            echo "[restore]        sbomhub_app に table grants が無い状態のため、" >&2
            echo "[restore]        sbomhub-api を起動しても permission denied になります。" >&2
            echo "[restore]        詳細: docker compose -f ${COMPOSE_FILE} logs db-bootstrap" >&2
            exit 1
        fi
        ;;
    *)
        echo "[restore]   skip db-bootstrap: '${COMPOSE_BASENAME}' is not the enterprise compose"
        echo "[restore]   (single-role mode, no sbomhub_app / sbomhub_migrator separation)."
        ;;
esac

# ---------------------------------------------------------------------------
# App role access check (F79 fix)
# ---------------------------------------------------------------------------
# db-bootstrap success だけでは「sbomhub_app が restored data を実際に SELECT
# できる」 ことは保証できない (default privileges drift / table ACL の race 等
# 微小確率の事故を捕捉するため)。 restored secrets file の app password で
# 接続し、 tenants table の count を 1 件取得できることを最終確認する。
# failure 時は API 起動に進まず exit 1 (operator の判断対象)。

echo "[restore] step 7/7: verify sbomhub_app role can read restored data"
case "${COMPOSE_BASENAME}" in
    *enterprise*)
        APP_PASSWORD_FILE="${SECRETS_DIR}/postgres_app_password.txt"
        if [[ ! -r "${APP_PASSWORD_FILE}" ]]; then
            echo "[restore] FATAL: sbomhub_app password file not readable: ${APP_PASSWORD_FILE}" >&2
            echo "[restore]        secrets restore が壊れている可能性。" >&2
            exit 1
        fi
        APP_PASSWORD="$(cat "${APP_PASSWORD_FILE}")"
        APP_CHECK_RAW="$(printf '%s\n' "${APP_PASSWORD}" | \
            docker compose -f "${COMPOSE_FILE}" exec -T \
                postgres \
                sh -c '
                    set -eu
                    PG_DB="$1"
                    IFS= read -r APP_PASSWORD
                    pgpass_escape() {
                        raw="$1"
                        if [ "$(printf "%s" "$raw" | tr -d "\n\r")" != "$raw" ]; then
                            echo "[restore] FATAL: pgpass_escape: password contains newline/CR, refusing (.pgpass is line-based)" >&2
                            exit 1
                        fi
                        printf "%s" "$raw" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/:/\\\\:/g"
                    }
                    cleanup() {
                        shred -u "$PGPASSFILE_CONTAINER" 2>/dev/null || rm -f "$PGPASSFILE_CONTAINER"
                    }
                    PGPASSFILE_CONTAINER="$(mktemp)"
                    trap cleanup EXIT HUP INT TERM
                    umask 077
                    APP_PASSWORD_ESCAPED="$(pgpass_escape "$APP_PASSWORD")"
                    printf "localhost:5432:*:sbomhub_app:%s\n" "$APP_PASSWORD_ESCAPED" > "$PGPASSFILE_CONTAINER"
                    unset APP_PASSWORD
                    unset APP_PASSWORD_ESCAPED
                    chmod 600 "$PGPASSFILE_CONTAINER"
                    PGPASSFILE="$PGPASSFILE_CONTAINER" \
                        psql -h localhost -U sbomhub_app -d "$PG_DB" \
                            -tA -v ON_ERROR_STOP=1 \
                            -c "SELECT count(*) FROM tenants;"
                ' sh "${PG_DB}" 2>&1)" || {
            echo "[restore] FATAL: sbomhub_app cannot SELECT from tenants after restore:" >&2
            awk '{print "[restore]   " $0}' <<< "${APP_CHECK_RAW}" >&2
            echo "[restore]        restored tables に sbomhub_app 用の GRANT が無い可能性。" >&2
            echo "[restore]        db-bootstrap log を確認: docker compose -f ${COMPOSE_FILE} logs db-bootstrap" >&2
            unset APP_PASSWORD
            exit 1
        }
        unset APP_PASSWORD
        APP_TENANT_COUNT="$(printf '%s' "${APP_CHECK_RAW}" | tr -d '[:space:]')"
        if ! [[ "${APP_TENANT_COUNT}" =~ ^[0-9]+$ ]]; then
            echo "[restore] FATAL: sbomhub_app tenants count is not numeric: '${APP_TENANT_COUNT}'" >&2
            exit 1
        fi
        echo "[restore]   sbomhub_app tenants count: ${APP_TENANT_COUNT}"
        ;;
    *)
        echo "[restore]   skip app role check: non-enterprise compose (single-role mode)"
        ;;
esac

# ---------------------------------------------------------------------------
# Optional Step 8: ENCRYPTION_KEY decrypt smoke test (M5-5, issue #53)
# ---------------------------------------------------------------------------
# Explicit opt-in via VERIFY_ENCRYPTION=1 + VERIFY_DB_URL. Runs
# ./verify-encryption.sh against the restored DB to confirm the restored
# ENCRYPTION_KEY actually decrypts the restored ciphertext rows. Posture is
# **smoke / warning-only** — Step 6/7 are the hard gates; this step exists to
# surface the rare class of restore where the secrets directory and the DB came
# from different rotations. Failures are logged but the restore is reported as
# successful so an operator who knows their tarball is consistent can keep
# going.
#
# This step deliberately runs AFTER 5.5 (admin password converge) + 6 + 7 so
# that:
#   - db-bootstrap has finished granting sbomhub_app SELECT on encrypted
#     tables, otherwise verify-encryption.sh would falsely report DB error.
#   - the restored secrets/encryption_key.txt is in place to read from.
#
# Enterprise compose does not publish postgres on the host by default, so this
# script deliberately does not infer postgres://...@postgres:5432 for a host-run
# smoke test. Operators must provide VERIFY_DB_URL for an address that is
# reachable from the host where restore.sh is running.

if [[ "${VERIFY_ENCRYPTION}" == "1" && -n "${VERIFY_DB_URL}" ]]; then
    echo "[restore] step 8/8: verify-encryption.sh smoke test (VERIFY_ENCRYPTION=1, VERIFY_DB_URL provided)"

    ENCRYPTION_KEY_FILE="${SECRETS_DIR}/encryption_key.txt"
    if [[ ! -r "${ENCRYPTION_KEY_FILE}" ]]; then
        echo "[restore]   WARN: ${ENCRYPTION_KEY_FILE} not readable, skipping smoke test (was secrets restore complete?)" >&2
    else
        set +e
        DATABASE_URL="${VERIFY_DB_URL}" \
            "${SCRIPT_DIR}/verify-encryption.sh" --key-file "${ENCRYPTION_KEY_FILE}"
        SMOKE_RC=$?
        set -e
        case "${SMOKE_RC}" in
            0)
                echo "[restore]   verify-encryption.sh PASSED (ENCRYPTION_KEY decrypts restored data)."
                ;;
            1)
                echo "[restore]   WARN: verify-encryption.sh reported key mismatch (exit 1). " \
                     "Restore continues, but the restored ENCRYPTION_KEY may not match the restored DB." >&2
                echo "[restore]         Cross-check: did the secrets tarball and the db.dump come from the same backup run?" >&2
                ;;
            2)
                echo "[restore]   WARN: verify-encryption.sh reported DB error (exit 2). Restore continues, smoke test inconclusive." >&2
                ;;
            3)
                echo "[restore]   INFO: verify-encryption.sh found no encrypted row to test (exit 3). Setup may be incomplete (no BYOK / no issue-tracker connections yet)." >&2
                ;;
            *)
                echo "[restore]   WARN: verify-encryption.sh exit ${SMOKE_RC} (prereq / unexpected). Restore continues." >&2
                ;;
        esac
    fi
elif [[ "${VERIFY_ENCRYPTION}" == "1" ]]; then
    echo "[restore] step 8/8: skip verify-encryption smoke test (VERIFY_ENCRYPTION=1 but VERIFY_DB_URL is unset)"
    echo "[restore]   WARN: ENCRYPTION_KEY verification was requested but VERIFY_DB_URL is not set; skipping smoke (no decryption verified)" >&2
    echo "[restore]         enterprise compose does not expose postgres on the host by default; set VERIFY_DB_URL to a host-reachable DSN to run Step 8." >&2
else
    echo "[restore] step 8/8: skip verify-encryption smoke test (set VERIFY_ENCRYPTION=1 and VERIFY_DB_URL to enable)"
fi

# ---------------------------------------------------------------------------
# 完了通知 + 次手順
# ---------------------------------------------------------------------------
# ここに辿り着くのは pg_restore success + sanity checks pass + secrets 復元 +
# db-bootstrap re-apply + sbomhub_app access check の **全てが** 通った場合のみ
# (途中 failure は exit 1 で abort 済)。

echo ""
echo "[restore] Restore completed successfully (pg_restore + sanity + db-bootstrap + app role access checks passed)."
echo ""
echo "[restore] Next steps:"
echo "  1. sbomhub-api / sbomhub-web を再起動 (secrets / DB が変わったため):"
echo "       docker compose -f ${COMPOSE_FILE} up -d --force-recreate sbomhub-api sbomhub-web"
echo "  2. 起動 log で ENCRYPTION_KEY check / DB role check が PASS することを確認:"
echo "       docker compose -f ${COMPOSE_FILE} logs sbomhub-api | grep -E 'ENCRYPTION_KEY|DB role'"
echo "  3. health endpoint が 200 を返すことを確認:"
echo "       curl -fsS http://localhost:8080/health"
echo "  4. ENCRYPTION_KEY 復号 smoke test (BYOK token / issue tracker auth_token の round-trip):"
echo "       export DATABASE_URL=\"postgres://sbomhub_app:...@localhost:5432/${PG_DB}?sslmode=disable\""
echo "       ENCRYPTION_KEY=\"\$(cat ${SECRETS_DIR}/encryption_key.txt)\" ./scripts/verify-encryption.sh"
echo "     または --key-file ${SECRETS_DIR}/encryption_key.txt を使う。"
echo "     restore.sh 実行時は VERIFY_ENCRYPTION=1 と VERIFY_DB_URL=<host-reachable DSN> の両方を渡せば Step 8 として自動実行される。"
echo "     詳細: docs/security/self-host-deployment.md §4.5 + §9.6 / docker/README.enterprise.md §5.3"
echo ""
