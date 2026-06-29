# Validate deferred composite-FK constraints (migration 045)

> Operator runbook for `docker/scripts/validate-deferred-constraints.sh`.
> Japanese translation: [`validate-deferred-constraints.ja.md`](./validate-deferred-constraints.ja.md).

## 1. Background

Migration
[`apps/api/migrations/045_composite_fk_extension.up.sql`](../../apps/api/migrations/045_composite_fk_extension.up.sql)
installs seven composite `(tenant_id, project_id) → projects(tenant_id, id)`
foreign-key constraints on legacy project-child tables:

| Table | Constraint |
| --- | --- |
| `sboms` | `sboms_tenant_project_fk` |
| `vex_statements` | `vex_statements_tenant_project_fk` |
| `license_policies` | `license_policies_tenant_project_fk` |
| `notification_settings` | `notification_settings_tenant_project_fk` |
| `notification_logs` | `notification_logs_tenant_project_fk` |
| `public_links` | `public_links_tenant_project_fk` |
| `vulnerability_tickets` | `vulnerability_tickets_tenant_project_fk` |

Each constraint is installed with `NOT VALID` (M8 F157, commit
[`9367702`](https://github.com/youichi-uda/sbomhub/commit/9367702)). FK
validation during `migrate apply` would otherwise scan rows under FORCE ROW
LEVEL SECURITY, and the matching RLS policies (012/013/014/015/021) call
`current_setting('app.current_tenant_id')` without `missing_ok=true`. With no
GUC set during migrate, the validation scan crashed the migrator (see
[F156](https://github.com/youichi-uda/sbomhub/commit/047a21e) for the wider
context).

`NOT VALID` skips the initial whole-table scan while still enforcing the
constraint on every subsequent write. Step 3 of migration 045 runs a
`DO $$` block that `RAISE`s on any pre-existing `tenant_id` mismatch, so the
existing data was effectively pre-validated at install time. The flag
`pg_constraint.convalidated` is the only thing left to flip from `f` → `t`.

`docker/scripts/validate-deferred-constraints.sh` performs that flip in a
single atomic transaction that mirrors Steps 1 and 5 of the migration:
briefly `NO FORCE` + `DISABLE` RLS on the seven child tables and on the
`projects` parent, `VALIDATE` the seven constraints under a full-table
scan, then restore the snapshotted RLS posture.

> **Why not a per-tenant `SET LOCAL app.current_tenant_id` loop?**
> `public_links` has had RLS removed (migration 030), so `VALIDATE` sees
> all of its rows, but the FK probe against `projects` is still
> RLS-filtered — every row owned by a tenant other than the GUC value
> raises a false-positive FK violation. `VALIDATE` under RLS also only
> covers the session-visible subset, leaving integrity guarantees
> incomplete. The DDL-wrapped approach takes `ACCESS EXCLUSIVE` locks
> (concurrent readers cannot observe the briefly-lifted RLS) and
> validates every existing row.

## 2. When to run

- **After the first deploy that includes migration 045.** Validation has
  been deferred since M8 F157; new installs will see `convalidated=false`
  on all seven constraints until this script has been run once.
- **Periodically (e.g. monthly maintenance window).** The script is
  idempotent — VALIDATE on an already-validated constraint is a metadata
  no-op in PostgreSQL — so a calendar-driven re-run is cheap and keeps
  the constraint state visible in your operational log.
- **After bulk imports / migrations from third-party SBOM stores.** If an
  external ETL writes directly into a child table while bypassing the
  application-level tenant scoping, this script is the canonical way to
  confirm the import preserved cross-tenant integrity.
- **Before a CRA / METI audit.** A `convalidated=true` flag is the
  PostgreSQL-level evidence that every existing row passes the
  `(tenant_id, project_id)` invariant.

## 3. Expected runtime

`VALIDATE` performs a sequential scan of the table to confirm the FK is
satisfied. Approximate per-table cost:

- `sboms`, `components` parents, `vex_statements`, `vulnerability_tickets`
  scale with project activity (typically the largest)
- `notification_logs` is append-only (can be the largest by row count if
  log retention is long)
- `license_policies`, `notification_settings`, `public_links` are usually
  small

As a rule of thumb the script completes in **under one minute** for an
install with `<100k` rows across the seven tables, and scales roughly
linearly with the largest table's row count. The DDL transaction holds
`ACCESS EXCLUSIVE` on all eight tables (the seven child tables plus
`projects`), so plan to run it during a maintenance window if your
`notification_logs` retention is multi-million rows.

## 4. Invocation

The script reads the migrator DSN from `MIGRATE_DATABASE_URL` (preferred)
or, as a fall-back, parses it from `.env` at the repo root via the
shared `read_env_var` helper.

```bash
export MIGRATE_DATABASE_URL="postgres://sbomhub_migrator:PASSWORD@localhost:5432/sbomhub?sslmode=disable"
./docker/scripts/validate-deferred-constraints.sh
```

The DSN must point at the **migrator** role (DDL-capable, `NOT BYPASSRLS`,
owner of the eight tables — `sbomhub_migrator` on the Enterprise compose).
The application runtime role (`sbomhub_app`, `NOSUPERUSER`,
`NOBYPASSRLS`) does **not** have DDL privileges and will fail at the
first `ALTER TABLE`.

Override the `psql` binary used by setting `PSQL` to the path of a
single executable. Multi-word commands (e.g. `docker run ...`) are NOT
accepted because the script checks the binary with `command -v "$PSQL"`,
which only resolves a single token. If you need a containerised psql,
write a tiny wrapper script:

```bash
# Write a wrapper that invokes psql inside a postgres container,
# forwarding the libpq env vars the script sets.
cat > /usr/local/bin/psql-docker <<'EOF'
#!/bin/sh
exec docker run --rm --network host -i \
    -e PGHOST -e PGPORT -e PGUSER -e PGPASSWORD -e PGDATABASE \
    -e PGSSLMODE -e PGSSLROOTCERT -e PGOPTIONS \
    postgres:15-alpine psql "$@"
EOF
chmod +x /usr/local/bin/psql-docker

# Then point PSQL at the wrapper:
PSQL=/usr/local/bin/psql-docker \
    MIGRATE_DATABASE_URL="postgres://..." \
    ./docker/scripts/validate-deferred-constraints.sh
```

The `-e PG*` flags forward the libpq env vars the script parses out
of `MIGRATE_DATABASE_URL`. Without them the dockerized psql cannot
see the credentials (the script intentionally does not pass the DSN
on argv, to keep the password out of `ps` — see §10 in the script
header comment).

## 5. Exit codes

| Code | Meaning |
| --- | --- |
| 0 | All seven constraints are `convalidated=true` after the run. |
| 1 | One or more constraints stayed `convalidated=false`. The script prints the offending constraint name(s) and the `(tenant_id, project_id)` pair from the first failing FK probe. See §6 below. |
| 2 | Prerequisite missing: `psql` not in PATH, `MIGRATE_DATABASE_URL` unset, DB unreachable, role lacks DDL privilege, or one of the eight tables is absent. |

## 6. What to do on failure (`exit 1`)

A `convalidated=false` result after this script implies a **real**
cross-tenant integrity violation in existing data — the constraint
predicate is correctly identifying a row whose `(tenant_id, project_id)`
pair does not match a `projects` row of the same tenant.

The script prints:

- the constraint name(s) that failed `VALIDATE`
- the offending `(tenant_id, project_id)` pair from PostgreSQL's
  `DETAIL:` line (the first violation only — PG aborts the scan at the
  first failure)

**Do not auto-DELETE.** The right next step is to inspect the offending
rows manually using the queries embedded in Step 3 of migration 045
(`apps/api/migrations/045_composite_fk_extension.up.sql`, search for
`Inspect with:`). For example, to find orphans in `sboms`:

```sql
SELECT s.id, s.tenant_id AS child_tenant, s.project_id,
       p.tenant_id AS parent_tenant
FROM sboms s
LEFT JOIN projects p ON p.id = s.project_id
WHERE s.tenant_id IS NULL
   OR p.id IS NULL
   OR p.tenant_id IS NULL
   OR p.tenant_id <> s.tenant_id;
```

Decide on the appropriate remediation with the data owner (typically:
restore the missing parent project, or reassign the child row to the
correct tenant). Then re-run this script.

The transaction the script runs is **atomic**: if `VALIDATE` raises, the
RLS-lifted state is rolled back automatically. No table is left in a
permissive RLS posture.

## 7. Cross-references

- Migration source: [`apps/api/migrations/045_composite_fk_extension.up.sql`](../../apps/api/migrations/045_composite_fk_extension.up.sql)
- M8 F157 fix commit: [`9367702`](https://github.com/youichi-uda/sbomhub/commit/9367702)
- M10-1 issue: [#70](https://github.com/youichi-uda/sbomhub/issues/70)
- RLS posture reference: migration 023 (FORCE RLS install), migration 030 (public_links RLS removal)
- Operator script: [`docker/scripts/validate-deferred-constraints.sh`](../../docker/scripts/validate-deferred-constraints.sh)
