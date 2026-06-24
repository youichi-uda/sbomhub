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

### 2.2 Required quality gates

| Gate | Current status | Action |
|---|---|---|
| `go build ./...` (apps/api) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `go test ./...` (apps/api、 unit のみ) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `golangci-lint` (apps/api) | **未設定** (リポジトリに `.golangci.yml` も存在せず) | (P1) `golangci-lint` workflow + 設定ファイル追加 |
| migration test (up/down/up roundtrip) | **未設定** | (P1) docker compose postgres + golang-migrate で round-trip 確認する workflow 追加 |
| RLS integration test | `apps/api/internal/repository/rls_test.go` に `//go:build integration` で実装済、 CI 実行は **未設定** | (P1) docker compose 起動 → `go test -tags=integration ./internal/repository/...` を実行する workflow 追加 |
| frontend build (`pnpm build`) | **未設定** | (P1) `apps/web` の `pnpm install && pnpm build` workflow 追加 |
| frontend typecheck (`pnpm tsc --noEmit`) | **未設定** | (P1) 同上の workflow に統合 |
| frontend lint (`pnpm lint`) | **未設定** | (P1) 同上 |
| compose smoke (`/api/v1/health` まで通る) | `docs-curl-smoke.yml` と `install-smoke.yml` で間接カバー (compose up → health 待ち) | OK (専用 workflow 不要) |
| docs curl smoke | `docs-curl-smoke.yml` | OK |
| install.sh smoke | `install-smoke.yml` (Ubuntu + macOS) | OK |
| CLI release / install smoke | sbomhub-cli `ci.yml` (release) + sbomhub `install-smoke.yml` (install.sh) | OK |
| Golden Path E2E (Playwright) | `apps/web/e2e/` に skeleton あり、 CI 実行は **未設定** | (P2) M1 で本格化、 M0 では doc に予告のみ |
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
- [ ] (P1) sbomhub: `.golangci.yml` 設定 + golangci-lint workflow 追加
- [ ] (P1) sbomhub: migration roundtrip workflow 追加 (docker compose postgres + `cmd/migrate up && down && up`)
- [ ] (P1) sbomhub: RLS integration test workflow 追加 (docker compose 経由で `go test -tags=integration ./internal/repository/...`)
- [ ] (P1) sbomhub: frontend lint/typecheck/build workflow 追加 (`apps/web` の pnpm)
- [ ] (USER) GitHub UI で `main` ブランチに上記 Required status checks 設定 (§2.3 / §3.3)
- [ ] (P2) sbomhub: Golden Path E2E skeleton (M1 で本格化、 Playwright を CI で実行)
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
