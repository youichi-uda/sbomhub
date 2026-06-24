#!/bin/sh
# SBOMHub - PostgreSQL role bootstrap (P0 #2 / Trust Rescue 9.1.1)
#
# This script is mounted into postgres at
#   /docker-entrypoint-initdb.d/10-roles.sh
# and runs ONCE on first database initialization (empty data volume).
#
# It creates two LOGIN roles in addition to the POSTGRES_USER (db owner):
#
#   sbomhub_migrator  -- DDL / migrations / backfills. CREATEDB + CREATEROLE,
#                        but NOT BYPASSRLS. Owns tables created by migrations.
#   sbomhub_app       -- Application runtime. SELECT/INSERT/UPDATE/DELETE only,
#                        NOBYPASSRLS so RLS policies are actually enforced.
#
# Passwords come from MIGRATOR_PASSWORD / APP_PASSWORD env vars (with dev
# defaults). For production, set these via a real secret store.
#
# All statements are idempotent (re-running ALTER ROLE is OK) so the script
# is safe to keep mounted even after the first init.

set -e

: "${MIGRATOR_PASSWORD:=sbomhub_migrator_dev}"
: "${APP_PASSWORD:=sbomhub_app_dev}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create migrator role (DDL / migrations). NOT BYPASSRLS.
    DO \$\$
    BEGIN
        CREATE ROLE sbomhub_migrator WITH LOGIN PASSWORD '${MIGRATOR_PASSWORD}' CREATEDB CREATEROLE;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END
    \$\$;

    -- Create app role (runtime). NOBYPASSRLS so policies are enforced.
    DO \$\$
    BEGIN
        CREATE ROLE sbomhub_app WITH LOGIN PASSWORD '${APP_PASSWORD}' NOBYPASSRLS;
    EXCEPTION WHEN duplicate_object THEN
        NULL;
    END
    \$\$;

    -- Idempotent password rotation + NOBYPASSRLS assertion.
    ALTER ROLE sbomhub_migrator WITH PASSWORD '${MIGRATOR_PASSWORD}';
    ALTER ROLE sbomhub_app WITH PASSWORD '${APP_PASSWORD}' NOBYPASSRLS;

    -- Connect / schema usage.
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO sbomhub_migrator, sbomhub_app;
    GRANT USAGE ON SCHEMA public TO sbomhub_migrator, sbomhub_app;

    -- Postgres 15+ revoked the implicit CREATE on the public schema for
    -- non-owners (https://www.postgresql.org/docs/15/release-15.html), so
    -- without this grant the very first migrator-driven statement
    --   CREATE TABLE IF NOT EXISTS schema_migrations ...
    -- fails with "permission denied for schema public" on a fresh
    -- docker compose up. sbomhub_app intentionally does NOT receive CREATE;
    -- DDL is exclusively the migrator's job (Trust Rescue R1 / codex-r1).
    GRANT CREATE ON SCHEMA public TO sbomhub_migrator;

    -- Existing tables (no-op on a fresh DB; needed if init.sh is re-run
    -- against a populated schema).
    GRANT ALL ON ALL TABLES IN SCHEMA public TO sbomhub_migrator;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sbomhub_app;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbomhub_migrator, sbomhub_app;

    -- Future tables created by the migrator role inherit the right grants
    -- for sbomhub_app, so we never have to remember to GRANT after each
    -- new CREATE TABLE in a migration.
    ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sbomhub_app;
    ALTER DEFAULT PRIVILEGES FOR ROLE sbomhub_migrator IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO sbomhub_app;

    -- Existing-volume upgrade fix (codex-r3 P1):
    -- On legacy self-host volumes every table / sequence was created by the
    -- POSTGRES_USER role 'sbomhub' and is therefore owned by it. GRANT ALL
    -- above is insufficient for owner-only operations (ALTER TABLE, DROP,
    -- ALTER COLUMN ... SET NOT NULL etc.), so migrations 027 / 028 / 029
    -- abort with "must be owner of table sboms" when run as sbomhub_migrator.
    --
    -- REASSIGN OWNED transfers every object in the current database owned by
    -- 'sbomhub' to 'sbomhub_migrator'. On a fresh volume the migrator has
    -- not yet created anything as 'sbomhub', so this is a no-op. The
    -- pg_roles guard keeps the script safe if an operator customised
    -- POSTGRES_USER away from the default name.
    DO \$\$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sbomhub') THEN
            EXECUTE 'REASSIGN OWNED BY sbomhub TO sbomhub_migrator';
        END IF;
    END
    \$\$;
EOSQL
