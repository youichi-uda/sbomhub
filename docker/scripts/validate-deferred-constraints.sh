#!/usr/bin/env sh
# validate-deferred-constraints.sh — VALIDATE the seven 045 composite-FK
# constraints that were installed with NOT VALID (M8 F157 #67 → M10-1 #70).
#
# Background:
#   apps/api/migrations/045_composite_fk_extension.up.sql installs seven
#   composite (tenant_id, project_id) → projects(tenant_id, id) FK constraints
#   on legacy project-child tables. F157 deferred their validation via
#   NOT VALID because FK validation during migrate apply scans rows under
#   FORCE ROW LEVEL SECURITY, and the matching RLS policies (012/013/014/015/
#   021) call current_setting('app.current_tenant_id') without missing_ok=true.
#   With no GUC set during migrate, the validation scan crashed the migrator.
#
#   The constraints already enforce on every new write, and Step 3 of 045 ran
#   a DO $$ block that RAISEs on any pre-existing tenant_id mismatch, so the
#   existing data was effectively pre-validated when 045 ran. This script
#   flips the pg_constraint.convalidated flag from f → t by wrapping the
#   seven VALIDATE statements in a single atomic transaction that mirrors
#   migration 045's Steps 1 and 5: temporarily NO FORCE + DISABLE RLS on the
#   child tables and the projects parent, VALIDATE the constraints under a
#   full-table scan, then restore each table's original RLS posture.
#
#   The per-tenant SET LOCAL app.current_tenant_id approach was considered
#   and rejected: (a) for `public_links` (RLS removed by 030) the FK probe
#   against projects is still RLS-filtered, so VALIDATE raises a false-
#   positive FK violation for any row owned by a tenant other than the GUC
#   value; (b) VALIDATE under RLS only verifies the session-visible row
#   subset, leaving the integrity guarantee incomplete. The DDL approach
#   takes ACCESS EXCLUSIVE locks (so no concurrent reader can observe the
#   briefly-lifted state) and validates every existing row.
#
# Run posture:
#   * Post-deploy one-shot, or periodic (e.g. monthly maintenance window).
#   * Idempotent: VALIDATE on an already-validated constraint is a metadata
#     no-op in PostgreSQL.
#   * Atomic: a failure mid-way rolls back the transaction, restoring the
#     original RLS posture on every touched table.
#   * No DML. Only ALTER TABLE ... DISABLE / VALIDATE / ENABLE / FORCE.
#
# Usage:
#   MIGRATE_DATABASE_URL=postgres://sbomhub_migrator:...@host:5432/sbomhub?sslmode=disable \
#       ./docker/scripts/validate-deferred-constraints.sh
#
# Env contract:
#   MIGRATE_DATABASE_URL   Postgres DSN for the migrator role (DDL-capable,
#                          NOT BYPASSRLS, owner of the eight tables). Required
#                          unless .env at repo root provides it. Passed to
#                          psql via env / connection URI, never argv-secret.
#   PSQL                   psql binary to use (default: psql in PATH).
#
# Exit code:
#   0   all seven constraints are convalidated=true after the run
#   1   one or more constraints stayed convalidated=false (data integrity
#       violation detected during VALIDATE; investigate, do NOT auto-DELETE)
#   2   prerequisite missing (psql not in PATH, MIGRATE_DATABASE_URL unset,
#       tenants table unreachable, DB connection error, etc.)

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- shared helpers ---------------------------------------------------------
# read_env_var (F128-F132 pattern) is used as a fall-back when
# MIGRATE_DATABASE_URL is not exported but is present in the repo root .env.
if [ -f "$SCRIPT_DIR/_env_helpers.sh" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/_env_helpers.sh"
fi

PSQL="${PSQL:-psql}"

# --- prerequisites ----------------------------------------------------------
if ! command -v "$PSQL" >/dev/null 2>&1; then
    echo "[validate-deferred] FATAL: psql not found in PATH (set PSQL=/path/to/psql)" >&2
    exit 2
fi

DB_URL="${MIGRATE_DATABASE_URL:-}"
if [ -z "$DB_URL" ] && [ -f "$REPO_ROOT/.env" ]; then
    # Defensive parse via _env_helpers.read_env_var so duplicates / empty /
    # quoted values fail loudly rather than silently shipping bad URLs.
    if grep -q '^MIGRATE_DATABASE_URL=' "$REPO_ROOT/.env" 2>/dev/null; then
        DB_URL="$(cd "$REPO_ROOT" && read_env_var MIGRATE_DATABASE_URL)"
    fi
fi
if [ -z "$DB_URL" ]; then
    echo "[validate-deferred] FATAL: MIGRATE_DATABASE_URL is required (env or .env)" >&2
    echo "[validate-deferred]        example:" >&2
    printf '[validate-deferred]          MIGRATE_DATABASE_URL=postgres://sbomhub_migrator:PW@localhost:5432/sbomhub?sslmode=disable \\\n' >&2
    printf '[validate-deferred]              ./docker/scripts/validate-deferred-constraints.sh\n' >&2
    exit 2
fi

# --- constraint + table inventory ------------------------------------------
# Source: apps/api/migrations/045_composite_fk_extension.up.sql, Step 6.
# Format: whitespace-separated "<table>:<constraint>" pairs. POSIX-sh's
# `for x in $list` performs unquoted word splitting on IFS, the same idiom
# 045 itself uses for static table lists.
CONSTRAINTS="
sboms:sboms_tenant_project_fk
vex_statements:vex_statements_tenant_project_fk
license_policies:license_policies_tenant_project_fk
notification_settings:notification_settings_tenant_project_fk
notification_logs:notification_logs_tenant_project_fk
public_links:public_links_tenant_project_fk
vulnerability_tickets:vulnerability_tickets_tenant_project_fk
"

# RLS posture must be lifted on both the seven child tables AND the projects
# parent (the FK probe against projects is otherwise RLS-filtered to nothing).
TABLES_TO_TOGGLE="projects sboms vex_statements license_policies notification_settings notification_logs public_links vulnerability_tickets"

# --- DSN → PG* env split (M10-1 #70 Codex F159 + F162) ----------------------
# Passing the full libpq URI as a positional psql argument exposes the
# password in `ps` for the duration of the psql call. The standing
# secret-in-env-not-argv invariant (F84/F107/F134/F136/F137/F140/F145)
# applies. Parse the URI once into PGUSER / PGPASSWORD / PGHOST / PGPORT /
# PGDATABASE + libpq query options, then invoke psql without any DSN argv.
#
# Accepted shapes (libpq URI form, the only form install.sh / docker-compose
# emit):
#   postgres://user:password@host:port/dbname[?key=value&...]
#   postgresql://...
#
# The scheme prefix is stripped; the remainder is split on the first `@`
# (everything left = userinfo, everything right = host/db/opts). Userinfo
# is split on the first `:` (left = user, right = password). The host/db
# portion is split on the first `/` (left = hostport, right = dbname+opts).
#
# Anything outside that shape (e.g. a Unix-socket DSN with %2F-escaped path,
# or libpq key=value pair DSN) is rejected, since the migrator role's URL
# here is always emitted by install.sh / docker-compose.yml.
#
# F162: URI-encoded password / user / database / query values (e.g. the
# .env.example documented `m%40ss%23word`) must be percent-decoded before
# being placed in PG* env vars. libpq would decode them from a URI but
# expects raw bytes from PG* env. urldecode() below handles %XX hex
# decoding via printf %b after sed-converting % → \x.

# urldecode: portable POSIX-sh percent-decoder. `%XX` → byte 0xXX. Other
# characters pass through (a bare `%` not followed by two hex digits
# stays literal). POSIX `printf` accepts octal escapes (`\OOO`) but not
# hex (`\xXX`), so we hex→octal-convert one byte at a time. Walking
# byte-by-byte avoids edge cases with sed's locale-dependent regex
# classes. NB: command substitution strips trailing newlines, but
# DSN tokens never end in `\n`, so that's fine.
urldecode() {
    s=$1
    out=
    while [ -n "$s" ]; do
        case "$s" in
            %[0-9A-Fa-f][0-9A-Fa-f]*)
                hex=$(printf '%s' "$s" | cut -c2-3)
                rest=$(printf '%s' "$s" | cut -c4-)
                out=$out$(printf "\\$(printf '%o' "0x$hex")")
                s=$rest
                ;;
            *)
                first=$(printf '%s' "$s" | cut -c1)
                out=$out$first
                s=$(printf '%s' "$s" | cut -c2-)
                ;;
        esac
    done
    printf '%s' "$out"
}
case "$DB_URL" in
    postgres://*) DSN_REMAINDER=${DB_URL#postgres://} ;;
    postgresql://*) DSN_REMAINDER=${DB_URL#postgresql://} ;;
    *)
        echo "[validate-deferred] FATAL: MIGRATE_DATABASE_URL must be a libpq URI (postgres:// or postgresql://)" >&2
        exit 2
        ;;
esac

case "$DSN_REMAINDER" in
    *@*)
        DSN_USERINFO=${DSN_REMAINDER%%@*}
        DSN_HOSTDB=${DSN_REMAINDER#*@}
        ;;
    *)
        echo "[validate-deferred] FATAL: MIGRATE_DATABASE_URL must include user[:password]@host" >&2
        exit 2
        ;;
esac

case "$DSN_USERINFO" in
    *:*)
        PGUSER_PARSED=${DSN_USERINFO%%:*}
        PGPASSWORD_PARSED=${DSN_USERINFO#*:}
        ;;
    *)
        PGUSER_PARSED=$DSN_USERINFO
        PGPASSWORD_PARSED=
        ;;
esac

case "$DSN_HOSTDB" in
    */*)
        DSN_HOSTPORT=${DSN_HOSTDB%%/*}
        DSN_DBOPTS=${DSN_HOSTDB#*/}
        ;;
    *)
        DSN_HOSTPORT=$DSN_HOSTDB
        DSN_DBOPTS=
        ;;
esac

case "$DSN_HOSTPORT" in
    *:*)
        PGHOST_PARSED=${DSN_HOSTPORT%:*}
        PGPORT_PARSED=${DSN_HOSTPORT##*:}
        ;;
    *)
        PGHOST_PARSED=$DSN_HOSTPORT
        PGPORT_PARSED=5432
        ;;
esac

case "$DSN_DBOPTS" in
    *\?*)
        PGDATABASE_PARSED=${DSN_DBOPTS%%\?*}
        DSN_QUERY=${DSN_DBOPTS#*\?}
        ;;
    *)
        PGDATABASE_PARSED=$DSN_DBOPTS
        DSN_QUERY=
        ;;
esac

# libpq honours PGSSLMODE / PGSSLROOTCERT / PGOPTIONS from env. We forward
# the only query parameter our install.sh / docker-compose emits today,
# `sslmode`, plus anything else we recognise. Unknown query params are
# ignored with a stderr warning so an operator with a custom DSN sees them.
PGSSLMODE_PARSED=
PGSSLROOTCERT_PARSED=
PGOPTIONS_PARSED=
if [ -n "$DSN_QUERY" ]; then
    OLD_IFS=$IFS
    IFS='&'
    # shellcheck disable=SC2086 # word-splitting on & is intentional
    set -- $DSN_QUERY
    IFS=$OLD_IFS
    for kv in "$@"; do
        case "$kv" in
            sslmode=*) PGSSLMODE_PARSED=${kv#sslmode=} ;;
            sslrootcert=*) PGSSLROOTCERT_PARSED=${kv#sslrootcert=} ;;
            options=*) PGOPTIONS_PARSED=${kv#options=} ;;
            *) echo "[validate-deferred] WARN: ignoring unrecognised DSN query param ${kv%%=*}" >&2 ;;
        esac
    done
fi

# F162: percent-decode every URI component before placing it in PG* env
# vars. libpq decodes URI components when given a full DSN, but reads
# PG* env vars as raw bytes, so passwords like the `.env.example`-
# documented `m%40ss%23word` must be decoded here. Host/port are
# excluded because IPv6 addresses can include literal `:` and `%`
# (zone-id) that libpq parses differently in PGHOST; .env.example only
# ships `localhost` / DNS names so that's a non-issue today, but err
# on the side of pass-through there.
PGUSER_DECODED=$(urldecode "$PGUSER_PARSED")
PGPASSWORD_DECODED=$(urldecode "$PGPASSWORD_PARSED")
PGDATABASE_DECODED=$(urldecode "$PGDATABASE_PARSED")
PGSSLMODE_DECODED=$(urldecode "$PGSSLMODE_PARSED")
PGSSLROOTCERT_DECODED=$(urldecode "$PGSSLROOTCERT_PARSED")
PGOPTIONS_DECODED=$(urldecode "$PGOPTIONS_PARSED")

# Export everything libpq reads. PGPASSWORD only takes effect for the
# psql subprocess; the calling shell never sees it in argv.
export PGUSER=$PGUSER_DECODED
[ -n "$PGPASSWORD_DECODED" ] && export PGPASSWORD=$PGPASSWORD_DECODED
export PGHOST=$PGHOST_PARSED
export PGPORT=$PGPORT_PARSED
[ -n "$PGDATABASE_DECODED" ] && export PGDATABASE=$PGDATABASE_DECODED
[ -n "$PGSSLMODE_DECODED" ] && export PGSSLMODE=$PGSSLMODE_DECODED
[ -n "$PGSSLROOTCERT_DECODED" ] && export PGSSLROOTCERT=$PGSSLROOTCERT_DECODED
[ -n "$PGOPTIONS_DECODED" ] && export PGOPTIONS=$PGOPTIONS_DECODED

# DB_URL itself is now redundant for psql but kept in scope for logging
# (without the password — strip it from any future echo).

# --- psql wrappers ----------------------------------------------------------
# DSN is intentionally NOT passed as a positional argument so the password
# stays in env (PGPASSWORD) and never reaches `ps` argv. Keep --no-psqlrc
# so an operator's local ~/.psqlrc cannot mutate behaviour.
#
# psql_query: capture-stdout shape. Stdin redirected from /dev/null so that
# a wrapper such as `docker run -i postgres:15-alpine psql ...` does not
# inherit and consume the calling shell's stdin pipe.
psql_query() {
    "$PSQL" \
        --quiet --no-align --tuples-only --no-psqlrc \
        -v ON_ERROR_STOP=1 "$@" </dev/null
}

# psql_pipe: stdin-pipe shape. ON_ERROR_STOP=1 because the whole VALIDATE
# transaction must abort on any failure (we want ROLLBACK to restore the
# original RLS posture, not commit a partially-lifted state).
# shellcheck disable=SC2120  # called without args in this script
psql_pipe() {
    "$PSQL" \
        --quiet --no-align --no-psqlrc \
        -v ON_ERROR_STOP=1 "$@"
}

# --- pre-flight: DB reachability -------------------------------------------
if ! psql_query -c 'SELECT 1' >/dev/null 2>&1; then
    echo "[validate-deferred] FATAL: cannot connect to MIGRATE_DATABASE_URL" >&2
    echo "[validate-deferred]        verify the role is sbomhub_migrator (NOBYPASSRLS, DDL-capable)" >&2
    exit 2
fi

# --- workdir ---------------------------------------------------------------
WORK_DIR="$(mktemp -d -t sbomhub-validate-fk.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM
PSQL_OUT="$WORK_DIR/psql.out"

# --- initial constraint state ---------------------------------------------
echo "[validate-deferred] Initial constraint state:"
INITIAL_STATE="$(psql_query -c "
SELECT conname || '=' ||
       CASE WHEN convalidated THEN 't' ELSE 'f' END
FROM pg_constraint
WHERE conname IN (
    'sboms_tenant_project_fk',
    'vex_statements_tenant_project_fk',
    'license_policies_tenant_project_fk',
    'notification_settings_tenant_project_fk',
    'notification_logs_tenant_project_fk',
    'public_links_tenant_project_fk',
    'vulnerability_tickets_tenant_project_fk'
)
ORDER BY conname;
")" || {
    echo "[validate-deferred] FATAL: failed to read pg_constraint" >&2
    exit 2
}
if [ -z "$INITIAL_STATE" ]; then
    echo "[validate-deferred] FATAL: none of the seven constraints exist; migration 045 not applied?" >&2
    exit 2
fi
printf '%s\n' "$INITIAL_STATE" | awk '{ print "[validate-deferred]   " $0 }'

# Short-circuit: if everything is already convalidated, do not take DDL
# locks. This is the steady-state for any DB that has run the script once.
NEED_VALIDATE=0
printf '%s\n' "$INITIAL_STATE" | grep -q '=f$' && NEED_VALIDATE=1
if [ "$NEED_VALIDATE" -eq 0 ]; then
    echo "[validate-deferred] All 7 constraints are already convalidated=true; nothing to do."
    exit 0
fi

# --- snapshot RLS posture --------------------------------------------------
# We restore the EXACT state of each table at the end (public_links has had
# RLS removed by migration 030, the rest are ENABLE + FORCE per 023/045). A
# snapshot is more robust than hard-coding the per-table expectation in this
# script, where any future migration that flips RLS on one of these tables
# would otherwise be silently regressed.
echo "[validate-deferred] Snapshotting RLS posture on: ${TABLES_TO_TOGGLE}"
RLS_SNAPSHOT="$(psql_query -c "
SELECT relname || '|' ||
       CASE WHEN relrowsecurity      THEN 't' ELSE 'f' END || '|' ||
       CASE WHEN relforcerowsecurity THEN 't' ELSE 'f' END
FROM pg_class
WHERE relkind = 'r'
  AND relname IN (
    'projects', 'sboms', 'vex_statements', 'license_policies',
    'notification_settings', 'notification_logs', 'public_links',
    'vulnerability_tickets'
  )
ORDER BY relname;
")" || {
    echo "[validate-deferred] FATAL: failed to snapshot RLS state" >&2
    exit 2
}
if [ -z "$RLS_SNAPSHOT" ]; then
    echo "[validate-deferred] FATAL: one of the eight tables is missing from pg_class" >&2
    exit 2
fi
printf '%s\n' "$RLS_SNAPSHOT" | awk -F'|' '{ printf "[validate-deferred]   %-22s enable=%s force=%s\n", $1, $2, $3 }'

# --- build the VALIDATE transaction ----------------------------------------
# The SQL below mirrors migration 045 Steps 1, 5, and a focused Step 6
# (VALIDATE rather than ADD CONSTRAINT NOT VALID). One transaction so any
# failure ROLLBACKs back to the original RLS posture; ACCESS EXCLUSIVE locks
# from each ALTER TABLE block concurrent sessions from observing the
# RLS-lifted window.
SQL_FILE="$WORK_DIR/validate.sql"
{
    printf '\\set QUIET on\n'
    printf '\\timing off\n'
    printf 'BEGIN;\n'

    # Lift RLS on all eight tables (idempotent: NO FORCE + DISABLE on a
    # table whose RLS is already off is a no-op).
    for tbl in $TABLES_TO_TOGGLE; do
        printf 'ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;\n' "$tbl"
        printf 'ALTER TABLE %s DISABLE ROW LEVEL SECURITY;\n' "$tbl"
    done

    # VALIDATE every constraint. PG will not raise on already-validated
    # constraints (metadata no-op).
    for entry in $CONSTRAINTS; do
        table="${entry%:*}"
        cons="${entry#*:}"
        printf 'ALTER TABLE %s VALIDATE CONSTRAINT %s;\n' "$table" "$cons"
    done

    # Restore the snapshotted RLS posture on each table.
    printf '%s\n' "$RLS_SNAPSHOT" | while IFS='|' read -r relname rls force; do
        [ -n "$relname" ] || continue
        if [ "$rls" = "t" ]; then
            printf 'ALTER TABLE %s ENABLE ROW LEVEL SECURITY;\n' "$relname"
        else
            printf 'ALTER TABLE %s DISABLE ROW LEVEL SECURITY;\n' "$relname"
        fi
        if [ "$force" = "t" ]; then
            printf 'ALTER TABLE %s FORCE ROW LEVEL SECURITY;\n' "$relname"
        else
            printf 'ALTER TABLE %s NO FORCE ROW LEVEL SECURITY;\n' "$relname"
        fi
    done

    printf 'COMMIT;\n'
} >"$SQL_FILE"

# --- run -------------------------------------------------------------------
echo "[validate-deferred] Running VALIDATE pass (single atomic transaction)..."
set +e
psql_pipe <"$SQL_FILE" >"$PSQL_OUT" 2>&1
PSQL_RC=$?
set -e

if [ "$PSQL_RC" -ne 0 ]; then
    echo "[validate-deferred] VALIDATE pass FAILED (psql rc=${PSQL_RC}); transaction rolled back." >&2
    echo "[validate-deferred] psql output (last 80 lines):" >&2
    tail -80 "$PSQL_OUT" | awk '{ print "[validate-deferred]   " $0 }' >&2

    # Surface offending FK rows so the operator can fix data without
    # auto-DELETE. The first ERROR line typically includes the exact
    # constraint name; pair it with the parent-orphan inspect query.
    OFFENDING_CONS="$(awk '
        /violates foreign key constraint/ {
            match($0, /"[a-z_]+_tenant_project_fk"/)
            if (RSTART > 0) {
                s = substr($0, RSTART+1, RLENGTH-2)
                if (!(s in seen)) { seen[s]=1; print s }
            }
        }
    ' "$PSQL_OUT")"
    if [ -n "$OFFENDING_CONS" ]; then
        echo "[validate-deferred] Constraint(s) failing VALIDATE:" >&2
        printf '%s\n' "$OFFENDING_CONS" | awk '{ print "[validate-deferred]   " $0 }' >&2
        echo "[validate-deferred] Inspect cross-tenant orphan rows via the queries in" >&2
        echo "[validate-deferred]   apps/api/migrations/045_composite_fk_extension.up.sql Step 3," >&2
        echo "[validate-deferred] and the operator runbook docs/operations/validate-deferred-constraints.md." >&2
    fi
    exit 1
fi

# --- final state ----------------------------------------------------------
echo "[validate-deferred] Final constraint state:"
FINAL_STATE="$(psql_query -c "
SELECT conname || '=' ||
       CASE WHEN convalidated THEN 't' ELSE 'f' END
FROM pg_constraint
WHERE conname IN (
    'sboms_tenant_project_fk',
    'vex_statements_tenant_project_fk',
    'license_policies_tenant_project_fk',
    'notification_settings_tenant_project_fk',
    'notification_logs_tenant_project_fk',
    'public_links_tenant_project_fk',
    'vulnerability_tickets_tenant_project_fk'
)
ORDER BY conname;
")" || {
    echo "[validate-deferred] FATAL: failed to read final pg_constraint state" >&2
    exit 2
}
printf '%s\n' "$FINAL_STATE" | awk '{ print "[validate-deferred]   " $0 }'

# Also re-snapshot RLS to confirm the restore landed.
echo "[validate-deferred] Final RLS posture:"
FINAL_RLS="$(psql_query -c "
SELECT relname || '|' ||
       CASE WHEN relrowsecurity      THEN 't' ELSE 'f' END || '|' ||
       CASE WHEN relforcerowsecurity THEN 't' ELSE 'f' END
FROM pg_class
WHERE relkind = 'r'
  AND relname IN (
    'projects', 'sboms', 'vex_statements', 'license_policies',
    'notification_settings', 'notification_logs', 'public_links',
    'vulnerability_tickets'
  )
ORDER BY relname;
")"
printf '%s\n' "$FINAL_RLS" | awk -F'|' '{ printf "[validate-deferred]   %-22s enable=%s force=%s\n", $1, $2, $3 }'

# Verify restore was faithful — diff snapshot vs final.
if [ "$RLS_SNAPSHOT" != "$FINAL_RLS" ]; then
    echo "[validate-deferred] FATAL: RLS posture drifted from snapshot; investigate immediately" >&2
    echo "[validate-deferred] snapshot:" >&2
    printf '%s\n' "$RLS_SNAPSHOT" | awk '{ print "[validate-deferred]   " $0 }' >&2
    echo "[validate-deferred] final:" >&2
    printf '%s\n' "$FINAL_RLS" | awk '{ print "[validate-deferred]   " $0 }' >&2
    exit 2
fi

# Classify per constraint: validated_now (was f, now t), skipped (was t,
# stays t), failed (was f, still f).
VALIDATED_NOW=0
SKIPPED=0
FAILED=0
for entry in $CONSTRAINTS; do
    cons="${entry#*:}"
    before="$(printf '%s\n' "$INITIAL_STATE" | grep "^${cons}=" | cut -d= -f2)"
    after="$(printf  '%s\n' "$FINAL_STATE"   | grep "^${cons}=" | cut -d= -f2)"
    if [ "$after" = "t" ] && [ "$before" = "f" ]; then
        VALIDATED_NOW=$((VALIDATED_NOW + 1))
    elif [ "$after" = "t" ] && [ "$before" = "t" ]; then
        SKIPPED=$((SKIPPED + 1))
    else
        FAILED=$((FAILED + 1))
        echo "[validate-deferred]   STILL NOT VALID: ${cons}" >&2
    fi
done

# --- summary --------------------------------------------------------------
echo ""
echo "[validate-deferred] Summary:"
echo "[validate-deferred]   constraints validated this run: ${VALIDATED_NOW}"
echo "[validate-deferred]   constraints already validated:  ${SKIPPED}"
echo "[validate-deferred]   constraints still NOT VALID:    ${FAILED}"

if [ "$FAILED" -gt 0 ]; then
    echo ""
    echo "[validate-deferred] FAIL: ${FAILED} constraint(s) remain NOT VALID after this run." >&2
    echo "[validate-deferred]       Cross-tenant integrity violation in existing data is the likely cause." >&2
    echo "[validate-deferred]       Do NOT auto-DELETE; surface the offending rows via the inspect query in" >&2
    echo "[validate-deferred]       apps/api/migrations/045_composite_fk_extension.up.sql Step 3," >&2
    echo "[validate-deferred]       or see docs/operations/validate-deferred-constraints.md." >&2
    exit 1
fi

echo "[validate-deferred] OK: all 7 deferred constraints are convalidated=true."
exit 0
