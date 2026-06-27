#!/usr/bin/env sh
# SBOMHub Disaster Recovery Rehearsal (M7-4 #60)
#
# Performs an end-to-end DR rehearsal:
# 1. Start an ephemeral docker compose environment (postgres + redis + api)
# 2. Insert sample tenants with BYOK LLM key + issue tracker token
# 3. Rotate ENCRYPTION_KEY (migrate-encryption --dry-run -> --apply -> --verify)
# 4. Backup -> restore -> verify-encryption smoke (restore Step 8)
# 5. Cleanup the ephemeral environment
#
# Exit code contract:
#   0 = all pass
#   1 = partial fail (one or more steps failed but rehearsal completed)
#   2 = setup error (docker compose / db unreachable)
#
# Usage:
#   ./docker/scripts/dr-rehearsal.sh [--keep-env] [--verbose]
#   --keep-env: do not tear down compose after run (debugging)
#   --verbose: stream all sub-command output

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REHEARSAL_PROJECT="sbomhub-dr-rehearsal-$$"
KEEP_ENV=0
VERBOSE=0
PASS_COUNT=0
FAIL_COUNT=0
FAIL_STEPS=""

COMPOSE_BASE="$REPO_ROOT/docker-compose.yml"
WORK_DIR="${TMPDIR:-/tmp}/sbomhub-dr-rehearsal-$$"
COMPOSE_OVERRIDE="$WORK_DIR/docker-compose.override.yml"
COMPOSE_RENDERED="$WORK_DIR/docker-compose.rendered.yml"
BACKUP_DIR="$WORK_DIR/backups"
SECRETS_DIR="$REPO_ROOT/docker/secrets"
REPORT_DRY="$WORK_DIR/dr-dry-run.json"
REPORT_APPLY="$WORK_DIR/dr-apply.json"
REPORT_VERIFY="$WORK_DIR/dr-verify.json"
HELPER_DIR="$REPO_ROOT/apps/api/.dr-rehearsal-$$"
HELPER_GO="$HELPER_DIR/main.go"
LOG_FILE="$WORK_DIR/dr-rehearsal.log"
SECRETS_CREATED=0

OLD_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef"
NEW_ENCRYPTION_KEY="abcdef0123456789abcdef0123456789"
APP_PASSWORD="sbomhub_app_dev"
MIGRATOR_PASSWORD="sbomhub_migrator_dev"
DATABASE_URL=""
VERIFY_DB_URL=""
BACKUP_TARBALL=""

while [ $# -gt 0 ]; do
    case "$1" in
        --keep-env) KEEP_ENV=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

cleanup() {
    rc=$?
    if [ "$KEEP_ENV" -eq 0 ]; then
        echo "[dr-rehearsal] cleanup: docker compose -p $REHEARSAL_PROJECT down -v"
        if [ -f "$COMPOSE_RENDERED" ]; then
            if [ "$VERBOSE" -eq 1 ]; then
                docker compose -p "$REHEARSAL_PROJECT" -f "$COMPOSE_RENDERED" down -v 2>&1 || true
            else
                docker compose -p "$REHEARSAL_PROJECT" -f "$COMPOSE_RENDERED" down -v 2>&1 | sed -n '1,3p' || true
            fi
        fi
        preserve_failure_reports "$rc"
        cleanup_rehearsal_secrets
        rm -rf "$WORK_DIR" "$HELPER_DIR"
    else
        echo "[dr-rehearsal] --keep-env: leaving compose project $REHEARSAL_PROJECT running"
        echo "[dr-rehearsal] work dir: $WORK_DIR"
    fi
    exit "$rc"
}
trap cleanup EXIT HUP INT TERM

preserve_failure_reports() {
    rc="$1"
    [ "$rc" -ne 0 ] || return 0
    [ -d "$WORK_DIR" ] || return 0
    for file in "$WORK_DIR"/dr-*.json "$LOG_FILE"; do
        [ -f "$file" ] || continue
        cp "$file" "${TMPDIR:-/tmp}/dr-rehearsal-$$-$(basename "$file")" 2>/dev/null || true
    done
}

cleanup_rehearsal_secrets() {
    [ "$SECRETS_CREATED" -eq 1 ] || return 0
    for dir in "$SECRETS_DIR" "$REPO_ROOT"/docker/secrets.bak-*; do
        [ -d "$dir" ] || continue
        key_file="$dir/encryption_key.txt"
        if [ -r "$key_file" ] && [ "$(cat "$key_file")" = "$NEW_ENCRYPTION_KEY" ]; then
            rm -rf "$dir"
        fi
    done
}

log_run() {
    if [ "$VERBOSE" -eq 1 ]; then
        "$@"
    else
        "$@" >>"$LOG_FILE" 2>&1
    fi
}

step() {
    step_name="$1"
    shift
    echo ""
    echo "[dr-rehearsal] === Step: $step_name ==="
    if "$@"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "[dr-rehearsal] PASS: $step_name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAIL_STEPS="${FAIL_STEPS}
  - ${step_name}"
        echo "[dr-rehearsal] FAIL: $step_name" >&2
        if [ "$VERBOSE" -eq 0 ] && [ -f "$LOG_FILE" ]; then
            echo "[dr-rehearsal] last log lines:" >&2
            tail -40 "$LOG_FILE" >&2 || true
        fi
    fi
}

docker_check() {
    command -v docker >/dev/null 2>&1 || return 1
    docker compose version >/dev/null 2>&1 || return 1
}

go_check() {
    command -v go >/dev/null 2>&1 || return 1
}

sql_literal_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

compose() {
    ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
    APP_PASSWORD="$APP_PASSWORD" \
    MIGRATOR_PASSWORD="$MIGRATOR_PASSWORD" \
        docker compose -p "$REHEARSAL_PROJECT" -f "$COMPOSE_RENDERED" "$@"
}

psql_stdin() {
    compose exec -T postgres psql -U sbomhub -d sbomhub -v ON_ERROR_STOP=1
}

prepare_compose() {
    cat >"$COMPOSE_OVERRIDE" <<'YAML'
services:
  postgres:
    ports:
      - "127.0.0.1::5432"
  api:
    environment:
      - APP_ENV=development
YAML
    ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
    APP_PASSWORD="$APP_PASSWORD" \
    MIGRATOR_PASSWORD="$MIGRATOR_PASSWORD" \
        docker compose -p "$REHEARSAL_PROJECT" \
            -f "$COMPOSE_BASE" -f "$COMPOSE_OVERRIDE" config >"$COMPOSE_RENDERED"
}

prepare_rehearsal_secrets() {
    if [ -e "$SECRETS_DIR" ]; then
        echo "[dr-rehearsal] FATAL: $SECRETS_DIR already exists; refusing to overwrite operator secrets" >&2
        echo "[dr-rehearsal]        move existing secrets aside or run in a clean checkout for rehearsal" >&2
        return 1
    fi
    mkdir -p "$SECRETS_DIR"
    umask 077
    printf '%s' "$NEW_ENCRYPTION_KEY" >"$SECRETS_DIR/encryption_key.txt"
    printf '%s' "sbomhub" >"$SECRETS_DIR/postgres_password.txt"
    printf '%s' "$APP_PASSWORD" >"$SECRETS_DIR/postgres_app_password.txt"
    printf '%s' "$MIGRATOR_PASSWORD" >"$SECRETS_DIR/postgres_migrator_password.txt"
    SECRETS_CREATED=1
}

start_compose() {
    mkdir -p "$WORK_DIR" "$BACKUP_DIR" "$HELPER_DIR"
    : >"$LOG_FILE"
    log_run prepare_compose
    log_run compose up -d --wait postgres redis
    host_port="$(compose port postgres 5432 | sed 's/.*://')"
    if [ -z "$host_port" ]; then
        echo "[dr-rehearsal] FATAL: could not resolve postgres published port" >&2
        return 1
    fi
    DATABASE_URL="postgres://sbomhub:sbomhub@127.0.0.1:${host_port}/sbomhub?sslmode=disable"
    VERIFY_DB_URL="$DATABASE_URL"
    export DATABASE_URL VERIFY_DB_URL
}

bootstrap_roles() {
    migrator_password_sql="$(sql_literal_escape "$MIGRATOR_PASSWORD")"
    app_password_sql="$(sql_literal_escape "$APP_PASSWORD")"
    {
        cat <<SQL_VARS
SELECT '${migrator_password_sql}' AS migrator_password,
       '${app_password_sql}' AS app_password
\gset
SQL_VARS
        cat <<'SQL'
SELECT format(
    'CREATE ROLE sbomhub_migrator WITH LOGIN PASSWORD %L CREATEDB CREATEROLE',
    :'migrator_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub_migrator')
\gexec

SELECT format(
    'CREATE ROLE sbomhub_app WITH LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub_app')
\gexec

ALTER ROLE sbomhub_migrator WITH PASSWORD :'migrator_password' NOBYPASSRLS;
ALTER ROLE sbomhub_app      WITH PASSWORD :'app_password'      NOSUPERUSER NOBYPASSRLS;
GRANT CONNECT ON DATABASE sbomhub TO sbomhub_migrator, sbomhub_app;
GRANT USAGE, CREATE ON SCHEMA public TO sbomhub_migrator;
GRANT USAGE ON SCHEMA public TO sbomhub_app;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sbomhub_app;
ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO sbomhub_app;
SQL
    } | log_run psql_stdin
}

run_migrations() {
    (
        cd "$REPO_ROOT/apps/api"
        MIGRATE_DATABASE_URL="$DATABASE_URL" go run ./cmd/migrate up
    )
    {
        cat <<'SQL'
GRANT ALL ON ALL TABLES IN SCHEMA public TO sbomhub_migrator;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sbomhub_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbomhub_migrator, sbomhub_app;
SQL
    } | psql_stdin
}

start_api() {
    log_run compose up -d --wait api
}

write_sample_helper() {
    cat >"$HELPER_GO" <<'GO'
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func main() {
	key := []byte(os.Getenv("OLD_ENCRYPTION_KEY"))
	if len(key) != 32 {
		fmt.Fprintln(os.Stderr, "OLD_ENCRYPTION_KEY must be exactly 32 bytes")
		os.Exit(1)
	}
	llmCipher, err := llm.Encrypt([]byte("dr-rehearsal-openai-key"), key)
	if err != nil {
		panic(err)
	}
	trackerCipher, err := service.EncryptIssueTrackerToken("dr-rehearsal-jira-token", key)
	if err != nil {
		panic(err)
	}
	tenantA := "00000000-0000-4000-8000-0000000000a1"
	tenantB := "00000000-0000-4000-8000-0000000000b2"
	connectionID := "00000000-0000-4000-8000-0000000000c3"
	fmt.Println("BEGIN;")
	fmt.Printf("INSERT INTO tenants (id, clerk_org_id, name, slug, plan) VALUES (%s, 'org_dr_a', 'DR Rehearsal A', 'dr-rehearsal-a', 'free') ON CONFLICT (id) DO NOTHING;\n", sqlQuote(tenantA))
	fmt.Printf("INSERT INTO tenants (id, clerk_org_id, name, slug, plan) VALUES (%s, 'org_dr_b', 'DR Rehearsal B', 'dr-rehearsal-b', 'free') ON CONFLICT (id) DO NOTHING;\n", sqlQuote(tenantB))
	fmt.Printf("INSERT INTO tenant_llm_config (tenant_id, mode, provider, encrypted_api_key, model) VALUES (%s, 'byok', 'openai', decode('%s', 'hex'), 'gpt-4o-mini') ON CONFLICT (tenant_id) DO UPDATE SET encrypted_api_key = EXCLUDED.encrypted_api_key, updated_at = NOW();\n", sqlQuote(tenantA), hex.EncodeToString(llmCipher))
	fmt.Printf("INSERT INTO issue_tracker_connections (id, tenant_id, tracker_type, name, base_url, auth_type, auth_email, auth_token_encrypted, default_project_key, default_issue_type, is_active) VALUES (%s, %s, 'jira', 'DR Jira', 'https://dr-rehearsal.atlassian.net', 'api_token', 'dr@example.com', %s, 'DR', 'Task', true) ON CONFLICT (tenant_id, tracker_type, name) DO UPDATE SET auth_token_encrypted = EXCLUDED.auth_token_encrypted, updated_at = NOW();\n", sqlQuote(connectionID), sqlQuote(tenantA), sqlQuote(base64.StdEncoding.EncodeToString([]byte(trackerCipher))))
	fmt.Println("COMMIT;")
}
GO
}

insert_sample_tenants() {
    log_run write_sample_helper
    (
        cd "$REPO_ROOT/apps/api"
        OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" go run "$HELPER_GO"
    ) | log_run psql_stdin
}

rotate_dry_run() {
    (
        cd "$REPO_ROOT/apps/api"
        OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" \
        NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
        DATABASE_URL="$DATABASE_URL" \
            go run ./cmd/migrate-encryption --dry-run --report "$REPORT_DRY"
    )
}

rotate_apply() {
    (
        cd "$REPO_ROOT/apps/api"
        OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" \
        NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
        DATABASE_URL="$DATABASE_URL" \
            go run ./cmd/migrate-encryption --apply --report-input "$REPORT_DRY" --report "$REPORT_APPLY"
    )
}

rotate_verify() {
    (
        cd "$REPO_ROOT/apps/api"
        OLD_ENCRYPTION_KEY="$OLD_ENCRYPTION_KEY" \
        NEW_ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
        DATABASE_URL="$DATABASE_URL" \
            go run ./cmd/migrate-encryption --verify --report-input "$REPORT_DRY" --report "$REPORT_VERIFY"
    )
}

run_backup() {
    COMPOSE_PROJECT_NAME="$REHEARSAL_PROJECT" \
    COMPOSE_FILE="$COMPOSE_RENDERED" \
    PG_USER="sbomhub" \
    PG_DB="sbomhub" \
        "$SCRIPT_DIR/backup.sh" "$BACKUP_DIR"
    BACKUP_TARBALL="$(find "$BACKUP_DIR" -maxdepth 1 -name 'sbomhub-backup-*.tar.gz' | sort | tail -1)"
    if [ -z "$BACKUP_TARBALL" ] || [ ! -f "$BACKUP_TARBALL" ]; then
        echo "[dr-rehearsal] FATAL: backup tarball not found in $BACKUP_DIR" >&2
        return 1
    fi
    export BACKUP_TARBALL
}

run_restore() {
    if [ -z "$BACKUP_TARBALL" ]; then
        echo "[dr-rehearsal] FATAL: BACKUP_TARBALL is empty" >&2
        return 1
    fi
    COMPOSE_PROJECT_NAME="$REHEARSAL_PROJECT" \
    COMPOSE_FILE="$COMPOSE_RENDERED" \
    PG_USER="sbomhub" \
    PG_DB="sbomhub" \
    FORCE="yes" \
        "$SCRIPT_DIR/restore.sh" "$BACKUP_TARBALL"
}

run_restore_verify_smoke() {
    if [ -z "$BACKUP_TARBALL" ]; then
        echo "[dr-rehearsal] FATAL: BACKUP_TARBALL is empty" >&2
        return 1
    fi
    COMPOSE_PROJECT_NAME="$REHEARSAL_PROJECT" \
    COMPOSE_FILE="$COMPOSE_RENDERED" \
    PG_USER="sbomhub" \
    PG_DB="sbomhub" \
    FORCE="yes" \
    VERIFY_ENCRYPTION="1" \
    VERIFY_DB_URL="$VERIFY_DB_URL" \
    ENCRYPTION_KEY="$NEW_ENCRYPTION_KEY" \
    GO_BIN="${GO_BIN:-go}" \
        "$SCRIPT_DIR/restore.sh" "$BACKUP_TARBALL"
}

if ! docker_check; then
    echo "[dr-rehearsal] FATAL: docker / docker compose not available" >&2
    exit 2
fi
if ! go_check; then
    echo "[dr-rehearsal] FATAL: go not available in PATH; export PATH=\$PATH:/usr/local/go/bin" >&2
    exit 2
fi
if [ ! -f "$COMPOSE_BASE" ]; then
    echo "[dr-rehearsal] FATAL: compose file not found: $COMPOSE_BASE" >&2
    exit 2
fi

cd "$REPO_ROOT"

step "Start ephemeral compose (postgres + redis)" start_compose
if [ -z "$DATABASE_URL" ]; then
    echo "[dr-rehearsal] FATAL: DATABASE_URL was not established" >&2
    exit 2
fi

step "Prepare rehearsal secrets" prepare_rehearsal_secrets
if [ "$SECRETS_CREATED" -ne 1 ]; then
    echo "[dr-rehearsal] FATAL: rehearsal secrets were not created; aborting before backup/restore" >&2
    exit 2
fi
step "Bootstrap DB roles" bootstrap_roles
step "Run API migrations" run_migrations
step "Start sbomhub-api" start_api
step "Insert sample tenants" insert_sample_tenants
step "ENCRYPTION_KEY rotation (dry-run)" rotate_dry_run
step "ENCRYPTION_KEY rotation (apply)" rotate_apply
step "ENCRYPTION_KEY rotation (verify)" rotate_verify
step "Backup" run_backup
step "Restore" run_restore
step "Verify encryption (restore Step 8 smoke)" run_restore_verify_smoke

echo ""
echo "===================================="
echo "[dr-rehearsal] Summary:"
echo "  Pass: $PASS_COUNT"
echo "  Fail: $FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "  Failed steps:"
    printf '%s\n' "$FAIL_STEPS"
    exit 1
fi
echo "[dr-rehearsal] ALL STEPS PASSED"
exit 0
