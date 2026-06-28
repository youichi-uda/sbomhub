# CI inventory

## 1. Overview

Trust Rescue P1 #17 / 9.5.1 acceptance gate.

M1 (AI VEX triage MVP) に着手する前に、 `youichi-uda/sbomhub` と
`youichi-uda/sbomhub-cli` の CI 状況を棚卸しし、 不足している quality
gate を可視化する。 本ドキュメントはレポジトリの状態の真実 (source of
truth) として、 ブランチ保護設定と並んで参照される。

本 wave (#17) では、 棚卸しと doc 化を完遂し、 不足分のうち最も critical
な **Go unit test workflow (sbomhub)** のみを新規追加した。 その他の
gate (migration roundtrip / RLS integration / frontend lint) は §4
Action items に TODO として記録し、 後続 wave で順次追加する。

## 2. sbomhub (repo: youichi-uda/sbomhub)

### 2.1 Existing workflows (5)

| Workflow | Trigger | Job | Status |
|---|---|---|---|
| `docker-compose-smoke.yml` | push main / PR (compose paths) | ENCRYPTION_KEY refusal check (default key を再導入していないか) | Wave 2a / Trust Rescue P0 #5 |
| `docker-publish.yml` | push main / tag `v*` | Docker Hub に `y1uda/sbomhub-api` / `y1uda/sbomhub-web` を build & push | 既存 (release pipeline) |
| `docs-curl-smoke.yml` | push main / PR (docs/snippets, api, compose paths) | `docs/snippets/curl-upload.md` の curl block を live API に対して実行 | Wave 5b + R9-9a + R17 / Trust Rescue P1 #11 |
| `install-smoke.yml` | push main / PR (install.sh, compose, env paths) | `install.sh --start` を Ubuntu で full smoke、 macOS で .env 生成のみ smoke | Trust Rescue P1 #15 / 9.4.3 |
| `sbom-upload.yml` | `workflow_dispatch` (manual) | 自己 SBOM 生成 → SBOMHub にアップロード (dogfooding) | 既存 (運用用) |

新規追加 (本 wave):

| Workflow | Trigger | Job | Status |
|---|---|---|---|
| `go-test.yml` | push main / PR (`apps/api/**`) | `go build ./...` + `go test ./...` (integration 除外) | Trust Rescue P1 #17 / 9.5.1 |
| `golangci-lint.yml` | push main / PR (`apps/api/**`) | `golangci-lint run` against apps/api (warn-only initial landing) | Trust Rescue P1 #17-followup |
| `rls-integration.yml` | push main / PR (`apps/api/**`, compose, install.sh, env paths) | docker compose postgres + role bootstrap + migrate → `go test -tags=integration ./internal/repository/... ./internal/middleware/...` | Trust Rescue P1 #17-followup |
| `migration-roundtrip.yml` | push main / PR (`apps/api/migrations/**`, `apps/api/cmd/migrate/**`, compose, install.sh, env paths) | docker compose postgres + role bootstrap + `migrate up` → `migrate down 999` → `migrate up` (regression check)。 schema diff は warn-only で初回 landing | Trust Rescue P1 #17-followup |
| `frontend-ci.yml` | push main / PR (`apps/web/**`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json` paths) | pnpm install → `pnpm --filter web lint` / `typecheck` (`tsc --noEmit`) / `build` (`next build`)。 Node 22 LTS / pnpm 9、 warn-only initial landing | Trust Rescue P1 #17-followup |
| `web-e2e.yml` | push main / PR (`apps/web/**`, `apps/api/**`, compose / install.sh / env / pnpm paths) | docker compose (postgres + redis + locally built api + web) を起動 → Playwright (chromium) で `apps/web/e2e/smoke/` を実行。 home (`/` redirect + SBOMHub brand) / dashboard (auth surface に到達) / api-health (`/api/v1/health` `status=ok`) の 3 scenario | M8 #67 |

### 2.2 Required quality gates

| Gate | Current status | Action |
|---|---|---|
| `go build ./...` (apps/api) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `go test ./...` (apps/api、 unit のみ) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `golangci-lint` (apps/api) | `golangci-lint.yml` + `apps/api/.golangci.yml` で実装、 `continue-on-error: true` の warn-only で初回 landing | (P2) 既存 lint 違反 fix 後に strict 化 (continue-on-error 削除 + Required status checks 追加) |
| migration test (up/down/up roundtrip) | `migration-roundtrip.yml` (#17-followup) で docker compose postgres + role bootstrap + `cmd/migrate up && down 999 && up` を実行。 up/down/up が success することを block、 schema diff は warn-only で初回 landing | OK (本 wave、 strict 化は P2) |
| RLS integration test | `apps/api/internal/repository/*_rls_test.go` (rls / apikey / audit / public_link / subscription) + `internal/middleware/tx_test.go` に `//go:build integration` で実装済、 `rls-integration.yml` (#17-followup) で CI 実行 | OK (本 wave) |
| frontend build (`pnpm build`) | `frontend-ci.yml` (#17-followup) で Node 22 / pnpm 9 + dummy env で `pnpm --filter web build` を実行、 `continue-on-error: true` の warn-only で初回 landing | OK (本 wave、 strict 化は P2) |
| frontend typecheck (`pnpm tsc --noEmit`) | 同上 workflow に `pnpm --filter web typecheck` step として統合 (`tsc --noEmit` 経由)、 warn-only | OK (本 wave、 strict 化は P2) |
| frontend lint (`pnpm lint`) | 同上 workflow に `pnpm --filter web lint` step として統合 (`next lint` 経由)、 warn-only | OK (本 wave、 strict 化は P2) |
| compose smoke (`/api/v1/health` まで通る) | `docs-curl-smoke.yml` と `install-smoke.yml` で間接カバー (compose up → health 待ち) | OK (専用 workflow 不要) |
| docs curl smoke | `docs-curl-smoke.yml` | OK |
| install.sh smoke | `install-smoke.yml` (Ubuntu + macOS) | OK |
| CLI release / install smoke | sbomhub-cli `ci.yml` (release) + sbomhub `install-smoke.yml` (install.sh) | OK |
| Golden Path E2E (Playwright) | `apps/web/e2e/smoke/` の 3 scenario (home / dashboard / api-health) を `web-e2e.yml` (M8 #67) で実行。 docker compose 一式を立てて 本番 web image (Clerk key 空) に対し chromium で叩く、 M7-5 docker-publish.yml の build-time HTML marker smoke と役割分担 (smoke=image build time / E2E=full stack runtime flow)。 旧 `apps/web/e2e/*.spec.ts` (26 spec) は `dev:test` 前提のため引き続き local-only | OK (本 wave、 認証込み深堀りは M1 で本格化) |
| security scanning (Snyk / GitGuardian / gosec / trivy) | **未設定** | (P2) 別 wave |

### 2.3 Branch protection settings

GitHub UI から `main` ブランチに対して以下を user 操作で設定する
(GitHub UI 経由のため、 本 wave では doc 案内のみ)。

Settings → Branches → Branch protection rules → `main`:

- **Require a pull request before merging**: ON
  - Require approvals: 1 (solo maintainer の場合は任意、 codex review を必須化するなら別途 GitHub App 経由)
- **Require status checks to pass before merging**: ON
  - Require branches to be up to date before merging: ON
  - Required status checks (現状):
    - `docker-compose smoke / docker compose must abort without ENCRYPTION_KEY`
    - `docs curl smoke / docs curl upload must succeed against live api`
    - `install.sh smoke / install.sh must succeed on ubuntu-latest`
    - `install.sh smoke / install.sh must succeed on macos-latest`
    - `Go test / build-and-test` (本 wave で追加)
- **Require linear history**: ON (rebase only、 merge commit 禁止)
- **Require conversation resolution before merging**: ON
- **Do not allow bypassing the above settings**: ON (管理者も bypass 不可、 ただし solo maintainer なら判断)
- **Restrict who can push to matching branches**: org owner / maintainer のみ

後続 wave で追加した workflow も上の Required status checks に都度追加する。

## 3. sbomhub-cli (repo: youichi-uda/sbomhub-cli)

### 3.1 Existing workflows (1)

| Workflow | Trigger | Job | Status |
|---|---|---|---|
| `ci.yml` | push main / PR main / tag `v*` | Test (`go test ./... -v -race -coverprofile`), Build (ubuntu/macos/windows matrix), Lint (`golangci-lint`、 `continue-on-error: true`)、 Release (goreleaser on tag) | 既存 (#15 で確認) |

### 3.2 Required quality gates

| Gate | Current status | Action |
|---|---|---|
| `go test ./...` | `ci.yml` test job (race + coverage + codecov upload) | OK |
| `go build ./cmd/sbomhub` (cross-platform) | `ci.yml` build job (ubuntu/macos/windows matrix) | OK |
| `golangci-lint` | `ci.yml` lint job、 **ただし `continue-on-error: true`** (Go 1.25 を golangci-lint がまだサポートしていないため、 一時的に nonblocking) | (P2) golangci-lint が Go 1.25 に追従次第 `continue-on-error` を外す |
| goreleaser snapshot (release dry-run) | tag 時のみ `release` job で実行、 PR 時の dry-run は **未設定** | (P2) `goreleaser release --snapshot --clean` の PR-time smoke を追加 (release 失敗を tag 前に検知) |
| install smoke (one-liner / homebrew tap) | sbomhub repo 側 `install-smoke.yml` で一部カバー (install.sh)、 homebrew tap の install smoke は未設定 | (P3) 別 wave |

### 3.3 Branch protection settings

sbomhub と同様の方針 (Settings → Branches → `main`):

- Require a pull request before merging: ON
- Required status checks:
  - `CI / Test`
  - `CI / Build (ubuntu-latest)`
  - `CI / Build (macos-latest)`
  - `CI / Build (windows-latest)`
  - (`CI / Lint` は `continue-on-error: true` で運用中のため一旦 optional、 Go 1.25 追従後に required 化)
- Require linear history: ON

## 4. Action items

本 doc 投入後の TODO list (P1 = M1 着手前に消化、 P2 = M1 と並行、
P3 = それ以降):

- [x] (P1) sbomhub: Go test workflow 追加 — 本 wave (#17) で `go-test.yml` 追加済
- [x] (P1) sbomhub: `.golangci.yml` 設定 + golangci-lint workflow 追加 — `apps/api/.golangci.yml` + `golangci-lint.yml` で warn-only landing (#17-followup)。 既存 lint 違反 fix と strict 化 (continue-on-error 削除) は P2 で別 wave
- [x] (P1) sbomhub: migration roundtrip workflow 追加 — `migration-roundtrip.yml` (#17-followup) で docker compose postgres + role bootstrap + `cmd/migrate up && down 999 && up` を実行。 up/down/up が完走することを block、 schema diff (pg_dump --schema-only) は 027 backfill 等 known non-roundtrippable migration を抱えるため warn-only で初回 landing。 strict 化 (diff → exit 1) は P2 で別 wave
- [x] (P1) sbomhub: RLS integration test workflow 追加 — `rls-integration.yml` で docker compose postgres + role bootstrap + migrate → `go test -tags=integration ./internal/repository/... ./internal/middleware/...` を実行 (#17-followup)
- [x] (P1) sbomhub: frontend lint/typecheck/build workflow 追加 — `frontend-ci.yml` (#17-followup) で Node 22 LTS + pnpm 9 で `pnpm --filter web lint` / `typecheck` (`tsc --noEmit`) / `build` (`next build`) を実行。 各 step `continue-on-error: true` の warn-only で初回 landing (apps/web に既存 lint / type 違反が残存している可能性があり、 無関係 PR を block しないため)。 strict 化 (continue-on-error 削除 + Required status checks 追加) は既存違反 fix 後 P2 で別 wave。 `apps/web/package.json` に `typecheck` script (`tsc --noEmit`) を追加
- [ ] (USER) GitHub UI で `main` ブランチに上記 Required status checks 設定 (§2.3 / §3.3)
- [x] (P2) sbomhub: Golden Path E2E skeleton (Playwright を CI で実行) — `web-e2e.yml` (M8 #67) で docker compose 一式 (postgres + redis + locally built api + web) を立て、 chromium で `apps/web/e2e/smoke/` (home / dashboard / api-health) を実行。 docker-publish.yml (M7-5) の build-time HTML marker smoke と役割分担 (smoke=image build time / E2E=full stack runtime flow)。 認証込みの深堀り spec (`apps/web/e2e/*.spec.ts` 26 件、 `dev:test` 前提) の CI 化は M1 で別 wave
- [ ] (P2) sbomhub-cli: golangci-lint の `continue-on-error: true` 解除 (Go 1.25 対応待ち)
- [ ] (P2) sbomhub-cli: PR 時の goreleaser snapshot dry-run 追加
- [ ] (P2) sbomhub / sbomhub-cli: security scanning (Snyk / GitGuardian / gosec / trivy fs scan) workflow 追加
- [ ] (P3) sbomhub-cli: homebrew tap / scoop bucket の install smoke 追加

## 5. Out of scope (M0 では決めない)

- 詳細な E2E test (Playwright / Cypress) の本格運用 → M1
- performance / load test → M2 以降
- security scanning (Snyk / GitGuardian) の本格運用 → 別 wave
- multi-arch container build (arm64 / linux-arm) → 別 wave
- supply chain attestation (SLSA / cosign) → 別 wave

## 6. Related issues

- #5 / #7 (compose smoke、 Wave 2a で完了)
- #11 (docs curl CI、 Wave 5b + R9-9a で完了)
- #15 (install.sh smoke、 R12-12a で完了)
- #17 (CI inventory、 本 wave)
- M1 で Golden Path E2E
