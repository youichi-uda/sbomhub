# SBOMHub - Playwright e2e suite

The Next.js frontend ships two layered Playwright suites:

| Suite | Files | CI workflow | Purpose |
|---|---|---|---|
| Smoke | `apps/web/e2e/smoke/*.spec.ts` (3 specs) | `.github/workflows/web-e2e.yml::web-e2e` (M8 #67) | Black-box smoke against the production-shaped docker compose stack with empty Clerk key. Pins `/` -> locale redirect, `/dashboard` reachability, `/api/v1/health` contract. |
| Full | `apps/web/e2e/*.spec.ts` | `.github/workflows/web-e2e.yml::web-e2e-full` (M10-3 #71) | Feature-level flows: projects / sbom / vex / cra / meti / audit / dashboard / search / vulnerabilities / analytics / reports / etc. Self-seeds via the API for per-spec rows; needs the populated DB seed for dashboard / list views to render. |
| Meta | `apps/web/e2e/skip-reachability.spec.ts` | `web-e2e-full` (binding) + `.github/workflows/frontend-ci.yml` (fast copy) | **Hermetic** — no browser, no server, no database. AST-parses every spec in this directory and fails if a collection-time `test.skip(cond)` could silently disarm a gate under CI. Runs anywhere: `PLAYWRIGHT_SKIP_WEB_SERVER=1 pnpm exec playwright test e2e/skip-reachability.spec.ts`. |

> **Why the Meta suite exists.** A `test.skip(condition)` written at
> `test.describe` scope is evaluated at COLLECTION time, and skipping the
> group takes its `beforeAll` with it. A "CI must not skip this" guard
> written as a throwing `beforeAll` is therefore unreachable in exactly
> the situation it exists for, and a CI runner missing the tool reports
> "N skipped" on a GREEN job. `report-unmeasured-pdf.spec.ts` shipped
> with that shape. When adding an environment-conditional skip, append
> `&& !process.env.CI` to the condition — the meta gate enforces it, and
> its file header documents the escape hatch and the limits.

> The `web-e2e-full` job's `name:` still reads "26 specs". That string is
> a **required status check** on `main` under branch protection, so it is
> frozen at its original value and is not a live count — the job runs
> whatever `e2e/*.spec.ts` matches. Renaming it makes `main` unmergeable
> until the protection rule is edited to match.

This README is the **local repro recipe** for the full suite. The smoke
suite is also runnable locally via the same recipe (it shares the
stack).

## TL;DR

```bash
# 1. From the repo root, bring up postgres + redis + api + web.
docker compose up -d --wait postgres redis
./install.sh --bootstrap-roles
docker compose up -d api
# Wait for the api to apply migrations:
until curl -fsS http://localhost:8080/api/v1/health >/dev/null; do sleep 1; done
# Load the populated seed BEFORE the web container or any /me request
# fires — otherwise the auto-create path mints a random-UUID tenant.
docker compose exec -T postgres psql -U sbomhub -d sbomhub \
    < docker/seed/web-e2e.sql
# Analytics fixture (M49 render gate) — must come AFTER web-e2e.sql,
# which owns the tenant / project / CVE UUIDs it references.
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 \
    -U sbomhub -d sbomhub < docker/seed/analytics-mttr.sql
docker compose up -d web

# 2. Run the full Playwright suite against the docker compose web.
cd apps/web
pnpm install
pnpm exec playwright install --with-deps chromium
# report-unmeasured-pdf.spec.ts reads the generated PDF's text layer.
# Without poppler-utils it skips locally (and hard-fails under CI).
sudo apt-get install -y poppler-utils
PLAYWRIGHT_BASE_URL=http://localhost:3000 \
PLAYWRIGHT_API_URL=http://localhost:8080 \
PLAYWRIGHT_SKIP_WEB_SERVER=1 \
pnpm exec playwright test --project=chromium e2e/*.spec.ts

# 3. Or, run a subset:
PLAYWRIGHT_SKIP_WEB_SERVER=1 \
pnpm exec playwright test e2e/projects.spec.ts e2e/sbom.spec.ts
```

## Alternative: `dev:test` launcher (no docker web container)

`apps/web/package.json` ships a `dev:test` script that boots Next.js
directly with `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=''` and
`CLERK_SECRET_KEY=''`. This is the same auth-bypass behaviour the
production web image gets when built with empty Clerk build args, so
the same 26 specs pass against either target.

```bash
# From the repo root, bring up postgres + redis + api (no web yet):
docker compose up -d --wait postgres redis
./install.sh --bootstrap-roles
docker compose up -d api
until curl -fsS http://localhost:8080/api/v1/health >/dev/null; do sleep 1; done
docker compose exec -T postgres psql -U sbomhub -d sbomhub \
    < docker/seed/web-e2e.sql
# Analytics fixture (M49 render gate) — must come AFTER web-e2e.sql,
# which owns the tenant / project / CVE UUIDs it references.
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 \
    -U sbomhub -d sbomhub < docker/seed/analytics-mttr.sql

# Then run the bundled webServer launcher:
cd apps/web
NEXT_PUBLIC_API_URL=http://localhost:8080 \
pnpm exec playwright test --project=chromium e2e/*.spec.ts
```

Playwright's `webServer` block in `playwright.config.ts` will run
`pnpm dev:test` and reuse the existing server across runs (unless
`CI=1`). Set `PLAYWRIGHT_SKIP_WEB_SERVER=1` to disable that block when
you already have a Next.js (or production web image) listening on
`localhost:3000`.

## How the seed works

`docker/seed/web-e2e.sql` populates the minimum row set the 26 specs
need to render before their per-spec `beforeAll` creates additional
rows:

| Table | Row | Purpose |
|---|---|---|
| `tenants` | `00000000-0000-0000-0000-000000000001` (`slug='default'`, `clerk_org_id='self-hosted'`) | The self-hosted bootstrap tenant the API's `GetOrCreateDefault` looks up by slug. Hardcoding the UUID lets every other row FK-reference it deterministically. |
| `users` | `00000000-0000-0000-0000-000000000002` (`clerk_user_id='self-hosted'`) | The self-hosted bootstrap user. |
| `tenant_users` | (tenant, user, role='owner') | Self-hosted admin membership. |
| `projects` | `00000000-0000-0000-0000-000000000010` ("M10-3 Seed Project") | Seed project so `/projects` is not empty. |
| `sboms` + `components` | **2 SBOMs**: log4j-core 2.14.0 (vulnerable) + log4j-core 2.17.0 + lodash 4.17.21 (MIT) + gpl-test-component 1.0.0 (GPL-3.0-only) | M11-2 #77 extension — the 2nd SBOM gives the search spec a non-empty CVE database and gives the (currently re-skipped, see footer note) licenses spec ready MIT-allow + GPL-3-deny components to work with. The `sbom-diff` spec (M10-6 / M11-1) still uploads its own two SBOMs to a per-test project in `beforeAll`, so it does NOT depend on the seed having multiple SBOMs. |
| `vulnerabilities` + `component_vulnerabilities` | **4 CVEs**: CVE-2021-44228 (Critical, in_kev=true), CVE-2021-45046 (Critical, in_kev=true) — both linked to log4j-core 2.14.0; CVE-2021-23337 (High) + CVE-2020-8203 (High) — linked to lodash 4.17.21 | M11-2 #77 extension. The extra CVEs let `search.spec.ts` un-skip 3 CVE-search tests and `vulnerabilities.spec.ts` un-skip 1 detail-rendering test. |
| `license_policies` | MIT allow + GPL-3.0-only deny | M11-2 #77 extension. Drives the licenses spec's policy CRUD + violations API once the UI flow gap (project-detail Licenses tab — see footer note) is resolved in M12. The rows are kept so the API list / get endpoints still return data for ad-hoc inspection and a future un-skip. |
| `api_keys` | 1 tenant-level row, name='M11-2 Seed Key', synthetic hash | M11-2 #77 extension. The hash is a SYNTHETIC placeholder — it does NOT correspond to any real key value. The api-keys spec describe is currently re-skipped pending the same M12 UI flow decision (per-project tab vs `/settings/apikeys` only); the row stays so the GET endpoints still return non-empty data. **DO NOT** load this seed against a production database — see header §2 / CLAUDE.md M0 Constraints. |
| `vex_drafts` | 1 pending `not_affected` row | Seed AI VEX draft so `/triage` renders the list (decision filter row count > 0). |
| `cra_reports` | 1 pending `early_warning ja` row | Seed AI CRA report so `/cra-reports` renders the list. |
| `meti_assessments` | 1 `needs_review` row (criterion_id=`meti.env_setup.01`, phase=`env_setup`, override_status=NULL) | M11-2 #77 extension — pinned to a catalog-correct criterion id so the card title resolves to a translated string rather than the raw id, and override_status stays NULL so the override-form spec can interact with it. |
| `audit_logs` | 1 `seed.bootstrap` action | Seed audit row so `/audit` renders the list. |

All UUIDs are hardcoded constants (see CLAUDE.md M10-3 brief
"Constraints"). The seed file is **idempotent** — every INSERT carries
`ON CONFLICT DO NOTHING` so re-running against a partial DB is safe.

### `docker/seed/analytics-mttr.sql` (M49 render gate)

A second, append-only fixture loaded **after** `web-e2e.sql`, for
`analytics-unmeasured.spec.ts` and `report-unmeasured-pdf.spec.ts`. It
changes no row `web-e2e.sql` inserts, so the pre-existing specs see the
same database they always did.

`web-e2e.sql` seeds zero `vulnerability_resolution_events` and zero
`compliance_snapshots`, which means `/analytics` answers null for every
MTTR / SLO / compliance ratio at every period. That is already M49's
"state A" — a tenant that has never remediated anything, the state that
used to be reported as `0.0 時間 / 100.0%`. This file supplies the
complementary MEASURED state without disturbing it:

| Table | Row | Purpose |
|---|---|---|
| `vulnerability_resolution_events` | CRITICAL, detected −62 d, resolved −60 d (48 h vs a 24 h target → late) | Inside a 90-day window, outside a 30-day one. Gives the 90d view a real MTTR and a **measured 0.0% SLO achievement**, which is what makes "unmeasured renders as a label" falsifiable: a page that replaced every number with the label would still pass a label-only assertion. |
| `vulnerability_resolution_events` | HIGH, detected −60 d 12 h, resolved −60 d (12 h vs a 168 h target → on target) | The on-target counterpart: 100.0% achievement, green bar. Together the two give the headline a count-weighted mean of 30 h and an overall achievement of 50.0%. |
| `compliance_snapshots` | tenant-level, −20 d, 8 / 10 | A real 80% row in the compliance trend. |
| `compliance_snapshots` | tenant-level, −5 d, 0 / 0 | No checklist configured. Drives both the per-row and the headline "not measured" branch (209b55e replaced a hard-coded em dash here that bypassed next-intl). Newest row, so it is also what `GetQuickStats` reads for the headline tile. |

Timestamps are relative to load time and only their *differences* are
asserted, so the expected values are stable whenever the seed runs.
Idempotent via `ON CONFLICT (id) DO NOTHING` — the PK, deliberately:
`compliance_snapshots`' `UNIQUE (tenant_id, project_id, snapshot_date)`
treats NULLs as distinct in PostgreSQL 15, so a `project_id IS NULL` row
would re-insert forever if that constraint were the conflict target.

Both specs' `beforeAll` **fails** (does not skip) when the fixture is
missing, because a gate that silently downgrades itself to nothing when
its fixture is absent is not a gate.

`report-unmeasured-pdf.spec.ts` additionally needs `pdftotext`
(poppler-utils) on PATH: it downloads the real generated executive /
technical / compliance PDF and reads its text layer, since the
pre-existing Go test can only assert that `generatePDF` returned
non-empty bytes. Missing locally → the describe skips with an actionable
message; missing under `CI` → hard failure.

That split is expressed as `test.skip(!HAS_PDFTOTEXT && !process.env.CI)`
plus a `beforeAll` that throws. **The `&& !process.env.CI` is
load-bearing.** A describe-level `test.skip(cond)` is evaluated at
collection time and skips the group *including its `beforeAll`*, so
writing the condition as a bare `!HAS_PDFTOTEXT` makes the CI hard-fail
unreachable — and a CI run without poppler-utils then reports "7 skipped"
on a green job, i.e. a gate that certifies the PDF's contents without
opening one. Verified both directions rather than assumed:

```
CI=1   + PATH without /usr/bin -> 1 failed, 6 did not run, exit 1
(unset)+ PATH without /usr/bin -> 7 skipped, exit 0
CI=1   + pdftotext present     -> all 7 collected and run
```

## Critical ordering

The API's `apps/api/internal/middleware/auth.go::handleSelfHostedAuth`
calls `TenantRepository.GetOrCreateDefault()` on every authenticated
request. That repo looks up by `slug='default'` and creates a new
tenant with a fresh random UUID if not found. **Loading the seed AFTER
the API has handled an authenticated request will pollute the DB with
two `slug='default'` tenants (different UUIDs)**, after which the FK
references in the seed clash with the auto-created tenant.

To avoid this:

1. Start postgres + redis.
2. Start the **api** container (which runs migrations on boot).
3. Wait for `/api/v1/health` — this is a public endpoint, no Auth
   middleware, so it does NOT trigger `GetOrCreateDefault`.
4. Load the seed (`web-e2e.sql`, then `analytics-mttr.sql`).
5. Start the **web** container — its first SSR call to `/api/v1/me`
   will now find the seeded tenant by slug and use its UUID.

The CI workflow (`.github/workflows/web-e2e.yml::web-e2e-full`)
enforces this ordering and asserts the seeded UUID via a `curl /me`
guard between steps 4 and 5.

## When a spec fails

1. Re-run with `PWDEBUG=1` for a UI trace:
   `PWDEBUG=1 PLAYWRIGHT_SKIP_WEB_SERVER=1 pnpm exec playwright test e2e/<spec>.spec.ts`
2. Open `apps/web/playwright-report/index.html` after the run for
   per-step screenshots / traces (CI uploads the same dir as
   `playwright-report-full` artifact on failure).
3. If the spec relies on a 3rd-party API (Clerk hosted UI, OpenAI /
   Anthropic / Gemini, GitHub OAuth, Jira), mark it `test.skip` with a
   `// M10-3: requires <X> external API, defer to M11 with mock layer`
   comment and add to the PR / commit body. Do NOT lower the per-spec
   timeout or strip assertions to make a flaky spec green.
