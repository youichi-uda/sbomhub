# SBOMHub - Playwright e2e suite

The Next.js frontend ships two layered Playwright suites:

| Suite | Files | CI workflow | Purpose |
|---|---|---|---|
| Smoke | `apps/web/e2e/smoke/*.spec.ts` (3 specs) | `.github/workflows/web-e2e.yml::web-e2e` (M8 #67) | Black-box smoke against the production-shaped docker compose stack with empty Clerk key. Pins `/` -> locale redirect, `/dashboard` reachability, `/api/v1/health` contract. |
| Full | `apps/web/e2e/*.spec.ts` (26 specs) | `.github/workflows/web-e2e.yml::web-e2e-full` (M10-3 #71) | Feature-level flows: projects / sbom / vex / cra / meti / audit / dashboard / search / vulnerabilities / etc. Self-seeds via the API for per-spec rows; needs the populated DB seed for dashboard / list views to render. |

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
docker compose up -d web

# 2. Run the full Playwright suite against the docker compose web.
cd apps/web
pnpm install
pnpm exec playwright install --with-deps chromium
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
4. Load the seed.
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
