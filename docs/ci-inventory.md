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

> **完全な一覧は §2.4 (machine-checked)**。 §2.1 / §2.2 の表は各 wave の
> 経緯を残した prose であり、 網羅性は保証しない (実際 2026-08 時点で 21
> workflow 中 10 件がこの表から漏れていた)。 workflow / job の集合として
> 正しいのは §2.4 のブロックだけで、 そこだけが
> `tools/lint-ci-inventory` により CI で実ファイルと突き合わされる。

### 2.1 Existing workflows (5) — #17 wave 時点

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
| `frontend-ci.yml` | push main / PR (`apps/web/**`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `package.json` paths) | pnpm install → `pnpm --filter web lint` (**hard gate, ESLint v9 flat config**, M11-5 #80) / `typecheck` (`tsc --noEmit`, **hard gate**, M12-5 #86) / `build` (`next build`, **hard gate**, M12-5 #86)。 Node 22 LTS / pnpm 10.34.3 | Trust Rescue P1 #17-followup / M10-4 / M11-5 / M12-5 |
| `web-e2e.yml` (job: `web-e2e`) | push main / PR (`apps/web/**`, `apps/api/**`, compose / `docker/seed/**` / install.sh / env / pnpm paths) | docker compose (postgres + redis + locally built api + web) を起動 → Playwright (chromium) で `apps/web/e2e/smoke/` を実行。 home (`/` redirect + SBOMHub brand) / dashboard (auth surface に到達) / api-health (`/api/v1/health` `status=ok`) の 3 scenario | M8 #67 |
| `web-e2e.yml` (job: `web-e2e-full`) | 同上 trigger | docker compose 一式 + `docker/seed/web-e2e.sql` (deterministic tenant + project + **2 SBOMs** (log4j-core 2.14.0 / 2.17.0) + 4 components + **4 CVEs (44228 / 45046 / 23337 / 8203)** + vex_draft + cra_report + **meti.env_setup.01** + audit_log + **license_policies (MIT allow + GPL-3 deny)** + **api_keys 1 件 (synthetic hash)**) を pre-load → Playwright (chromium, `retries: 2`, `timeout: 60_000`) で `apps/web/e2e/*.spec.ts` を実行 (job 名の "26" は branch protection に焼き付いた**凍結値**であり spec 数ではない。 §2.5 参照)。 seed は web 起動より前に load することで API の `GetOrCreateDefault` が deterministic UUID (`00000000-0000-0000-0000-000000000001`) を採用する経路を強制 | M10-3 #71 / M11-2 #77 |

後続 wave で追加され、 §2.1 の表からは**長らく漏れていた** 10 workflow
(2026-08-04 に `tools/lint-ci-inventory` 導入と同時に収録):

| Workflow | Trigger | Job (= check 名) | 何を守るか |
|---|---|---|---|
| `migration-lint.yml` | push main / PR (`apps/api/migrations/**`, `tools/lint-migration-rls/**`, 自 workflow) | `lint-migration-rls` | 新規 tenant-scoped table を作る migration が RLS enable / policy を忘れていないか。 tenant 分離の一次統制が RLS なので hard gate (M13-5 #91) |
| `migration-lock-lint.yml` | push main / PR (`apps/api/migrations/**`, `tools/lint-migration-locks/**`, `cmd/migrate/main.go`, `internal/database/migrate.go`, 自 workflow) | `lint-migration-locks` | 既存 relation に SHARE 以上のロックを取る migration が `lock_timeout` budget を先に張っているか。 CONCURRENTLY は runner の tx 内で走らないので拒否 |
| `toolchain-lint.yml` | push main / PR (`apps/api/go.mod`, `apps/**/Dockerfile*`, `packages/**/Dockerfile*`, `docker/**`, `.github/workflows/**`, `tools/**`) | `lint-toolchain-alignment` | go.mod / Dockerfile / workflow / `tools/*/go.mod` の Go pin 4 層が乖離していないか (F243 / M16-2 #104。 M15-3 で go.mod だけ上げて Dockerfile が取り残され main が 4 workflow RED になった事故の再発防止) |
| `nullscan.yml` | push main / PR (`apps/api/**`, compose, install.sh, env, 自 workflow) | `static gate (hermetic)` / `schema snapshot drift + measured tolerance table` | nullable 列を NULL 非許容の Go 型に scan する B1/B2 バグクラス。 前者は committed schema snapshot による静的解析 + baseline 差分、 後者は実 PostgreSQL で snapshot drift と NULL 耐性 decision table を実測 (M46 W0) |
| `golden-path-e2e.yml` | push main / PR (`apps/api/**`, `scripts/golden-path-e2e.sh`, fixture, compose, env, install.sh, 自 workflow) / 毎日 17:00 UTC / dispatch | `Golden Path 12-step against live api (curl + jq)` | 起動直後の compose stack に対し M0+M1+M2+M3 の happy path 12 step を curl で通し、 Evidence Pack に承認済 VEX + CRA + METI が入ることまで確認 (#43) |
| `project-scope-e2e.yml` | push main / PR (`apps/api/**`, `scripts/project-scope-e2e.sh`, fixture, compose, env, install.sh, `docker/scripts/_env_helpers.sh`, override, 自 workflow) | `project-scoped API key matrix over HTTP (every apiKeyRouteScope route)` | project-scoped API key が実 `sbh_...` 文字列として router + middleware chain を通ったときに `apiKeyRouteScope` の全 route で正しく DENY されるか (M50 W2/W3)。 unit / integration test では wire 越しの経路を張れない |
| `scheduler-integration.yml` | push main / PR (`apps/api/internal/scheduler/**`, `apps/api/migrations/**`, compose, install.sh, env, 自 workflow) | `F234 chunk-abort blast-radius smoke` | chunk 単位 tx 分割の blast-radius 封じ込め。 sqlmock では "current transaction is aborted" の ACID 挙動を再現できないため実 PostgreSQL 必須 (F234 / M15-2 #99) |
| `mcp-server-ci.yml` | push main / PR (`packages/mcp-server/**`, pnpm 系, `package.json`, 自 workflow, `apps/api/internal/middleware/project_scope.go`, `apps/api/internal/service/scan_tracker.go`) | `typecheck / build` | `packages/mcp-server` の `tsc --noEmit` 0 error と `dist/index.js` 生成 (どちらも hard gate)。 CI 皆無の間に SDK の型強化で 17 error まで腐って「宣伝しているのに build できない」状態になっていた (M46 Track D) |
| `release.yml` | tag push `v*` / dispatch | `goreleaser` | `llm-bench` バイナリ archive + curl-only 運用 artifact (`install.sh` / `docker-compose.yml` / `.env.example` / `docker/scripts/*.sh`) + release 単位 `SHA256SUMS` を GitHub Release に publish (M5-2 #54 / M7 #57) |
| `dr-rehearsal.yml` | 毎週日曜 04:00 UTC / dispatch | `dr-rehearsal` | HEAD の API image を build して DR (バックアップ/リストア) リハーサルを通す。 定期実行のみで PR は gate しない |

### 2.2 Required quality gates

| Gate | Current status | Action |
|---|---|---|
| `go build ./...` (apps/api) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `go test ./...` (apps/api、 unit のみ) | 新規 `go-test.yml` で実装 | OK (本 wave) |
| `golangci-lint` (apps/api) | `golangci-lint.yml` + `apps/api/.golangci.yml` (v2 schema) で実装、 M46 Track C-3c で **hard gate** 化 (continue-on-error 削除)。 注: 初回 landing の warn-only 期間は実際には一度も lint していなかった — 当時 pin していた v1.62 (および v1 最終の v1.64.8) は go1.23/1.24 build のため go.mod `go 1.26` directive に対し exit 3 で config error になり、 continue-on-error がそれを飲み込んで green に見えていた (2026-07-25 実測)。 M46 の各 wave で 277 → 0 件まで消化した上で golangci-lint **v2.12.2** (action@v9) に pin して strict 化 | OK (M46 Track C-3c で strict 化完了。 Required status checks 追加は §2.3 / USER action item で promote) |
| migration test (up/down/up roundtrip) | `migration-roundtrip.yml` (#17-followup) で docker compose postgres + role bootstrap + `cmd/migrate up && down 999 && up` を実行。 up/down/up が success することを block、 schema diff は warn-only で初回 landing | OK (本 wave、 strict 化は P2) |
| RLS integration test | `apps/api/internal/repository/*_rls_test.go` (rls / apikey / audit / public_link / subscription) + `internal/middleware/tx_test.go` に `//go:build integration` で実装済、 `rls-integration.yml` (#17-followup) で CI 実行 | OK (本 wave) |
| frontend build (`pnpm build`) | `frontend-ci.yml` (#17-followup) で Node 22 / pnpm 10.34.3 + dummy env で `pnpm --filter web build` を実行、 M12-5 #86 で `continue-on-error` を解除し **hard gate** 化 (M11-1 F164 production-build hydration-crash isolation の教訓: `next dev` は RSC full-SSR-hydration regression を捕まえられない) | OK (M12-5 #86 で strict 化完了。 Required status checks 追加は §2.3 / USER action item で promote) |
| frontend typecheck (`pnpm tsc --noEmit`) | 同上 workflow に `pnpm --filter web typecheck` step として統合 (`tsc --noEmit` 経由)、 M12-5 #86 で `continue-on-error` を解除し **hard gate** 化 (M11-5 lint cleanup 後 `tsc --noEmit` が zero error に達したため) | OK (M12-5 #86 で strict 化完了。 Required status checks 追加は §2.3 / USER action item で promote) |
| frontend lint (`pnpm lint`) | 同上 workflow に `pnpm --filter web lint` step として統合。 M11-5 #80 で ESLint v9 flat config (`apps/web/eslint.config.mjs`) に移行 + `next lint` → `eslint .` に switch (Next 16 が `next lint` を削除したため) + `continue-on-error` 解除で **hard gate** 化 | OK (M11-5 で strict 化完了。 残 warning は pre-existing、 必要に応じ別 wave で fix) |
| compose smoke (`/api/v1/health` まで通る) | `docs-curl-smoke.yml` と `install-smoke.yml` で間接カバー (compose up → health 待ち) | OK (専用 workflow 不要) |
| docs curl smoke | `docs-curl-smoke.yml` | OK |
| install.sh smoke | `install-smoke.yml` (Ubuntu + macOS) | OK |
| CLI release / install smoke | sbomhub-cli `ci.yml` (release) + sbomhub `install-smoke.yml` (install.sh) | OK |
| Golden Path E2E (Playwright) | `apps/web/e2e/smoke/` の 3 scenario (home / dashboard / api-health) を `web-e2e.yml::web-e2e` (M8 #67) で実行 + `apps/web/e2e/*.spec.ts` の 26 spec を `web-e2e.yml::web-e2e-full` (M10-3 #71) で `docker/seed/web-e2e.sql` populated stack に対し実行。 docker compose 一式を立てて 本番 web image (Clerk key 空 → mock auth shim) に対し chromium で叩く、 M7-5 docker-publish.yml の build-time HTML marker smoke と役割分担 (smoke=image build time / E2E=full stack runtime flow) | OK (M10-3 #71、 認証込み深堀りは M11 で外部 API mock 化) |
| security scanning (Snyk / GitGuardian / gosec / trivy) | **未設定** | (P2) 別 wave |

### 2.3 Branch protection settings

GitHub UI から `main` ブランチに対して以下を user 操作で設定する
(GitHub UI 経由のため、 本 wave では doc 案内のみ)。

Settings → Branches → Branch protection rules → `main`:

- **Require a pull request before merging**: ON
  - Require approvals: 1 (solo maintainer の場合は任意、 codex review を必須化するなら別途 GitHub App 経由)
- **Require status checks to pass before merging**: ON
  - Require branches to be up to date before merging: ON
  - Required status checks: **§2.5 の snapshot が実測値**。 かつてここに
    書かれていた 6 件のリスト (#17 wave 時点の「こう設定してほしい」案) は
    実際の設定と一致していなかった (`install.sh must succeed on ...` /
    `docker compose must abort without ENCRYPTION_KEY` は required では
    ない) ため削除した。 追加・削除するときは §2.5 を `gh api` の出力で
    更新すること。
- **Require linear history**: ON (rebase only、 merge commit 禁止)
- **Require conversation resolution before merging**: ON
- **Do not allow bypassing the above settings**: ON (管理者も bypass 不可、 ただし solo maintainer なら判断)
- **Restrict who can push to matching branches**: org owner / maintainer のみ

後続 wave で追加した workflow も上の Required status checks に都度追加する。

### 2.4 Workflow / job インベントリ (machine-checked)

**この節だけが workflow / job の集合として権威を持つ。** 下のブロックは
`tools/lint-ci-inventory` が `.github/workflows/*.yml` から生成し、
`.github/workflows/repo-hygiene.yml` の `lint-ci-inventory` job が実
ファイルと**集合として一致すること**を CI で検証する。 workflow を足す /
消す / job を rename すると red になる。

再生成:

```bash
(cd tools/lint-ci-inventory && go run . --repo-root ../.. --fix)
```

形式は `<workflow file> :: <job id> :: <check 名>`。 check 名は GitHub が
status check として表示し、 branch protection が**名前で**照合する文字列
(`name:` 未指定なら job id がそのまま使われる)。

なぜ prose の表と別に持つのか: §2.1 / §2.2 は wave ごとの経緯を書いた散文
で、 網羅性を機械的に保証できない。 実際 #17 wave で 5 workflow を収録した
まま 21 まで増え、 required status check 17 件のうち 12 件が「どこにも書か
れていない workflow」から出ていた。 読まれて信じられる source of truth が
2/3 欠けている状態は、 doc が無い状態より悪い。

<!-- BEGIN GENERATED: workflow-job-inventory -->

```text
docker-compose-smoke.yml :: refuse-without-encryption-key :: docker compose must abort without ENCRYPTION_KEY
docker-publish.yml :: build-and-push :: build-and-push
docs-curl-smoke.yml :: curl-smoke :: docs curl upload must succeed against live api
dr-rehearsal.yml :: dr-rehearsal :: dr-rehearsal
frontend-ci.yml :: frontend :: lint / typecheck / build
go-test.yml :: build-and-test :: build-and-test
golangci-lint.yml :: golangci :: lint
golden-path-e2e.yml :: api-e2e :: Golden Path 12-step against live api (curl + jq)
install-smoke.yml :: install-smoke :: install.sh must succeed on ${{ matrix.os }}
mcp-server-ci.yml :: mcp-server :: typecheck / build
migration-lint.yml :: lint :: lint-migration-rls
migration-lock-lint.yml :: lint :: lint-migration-locks
migration-roundtrip.yml :: migration-roundtrip :: roundtrip
nullscan.yml :: analyze :: static gate (hermetic)
nullscan.yml :: schema-drift :: schema snapshot drift + measured tolerance table
project-scope-e2e.yml :: api-key-project-scope :: project-scoped API key matrix over HTTP (every apiKeyRouteScope route)
release.yml :: goreleaser :: goreleaser
repo-hygiene.yml :: ci-inventory :: lint-ci-inventory
repo-hygiene.yml :: tools-build-hygiene :: tools build leaves no untracked artifacts
rls-integration.yml :: rls-integration :: integration
sbom-upload.yml :: sbom :: sbom
scheduler-integration.yml :: scheduler-integration :: F234 chunk-abort blast-radius smoke
toolchain-lint.yml :: lint :: lint-toolchain-alignment
web-e2e.yml :: web-e2e :: Playwright smoke (home / dashboard / api-health)
web-e2e.yml :: web-e2e-full :: Playwright full suite (26 specs against seeded stack)
```

<!-- END GENERATED: workflow-job-inventory -->

### 2.5 `main` の Required status checks (snapshot)

取得元 (読み取りのみ):

```bash
t=$(gh auth token --user youichi-uda)
GH_TOKEN="$t" gh api repos/youichi-uda/sbomhub/branches/main/protection \
  -q '.required_status_checks.contexts[]'
```

最終取得: **2026-08-04**、 17 件。 `tools/lint-ci-inventory` は下の各行が
§2.4 のいずれかの job の check 名と一致することを検証する — **GitHub は
required check を名前で照合するので、 job の `name:` を変えた瞬間に
required check が宙に浮き、 protection rule を人手で直すまで `main` が
永久に merge 不能になる**。 その罠を「stuck branch」ではなく「red lint」に
変換するのがこの照合の目的。

したがって:

- **既存 job の `name:` は変更しない。** 変更が必要なら branch protection
  を先に更新し、 同じ PR でこの snapshot も更新する。
- 特に `Playwright full suite (26 specs against seeded stack)` の
  **「26」は凍結値**。 `apps/web/e2e/*.spec.ts` の実数ではなく、 job 名の
  一部としてすでに protection に焼き付いている。 spec を増減しても更新
  しないこと (`.github/workflows/web-e2e.yml` の job header にも同旨の
  コメントがある)。
- この lint は GitHub 側と照合しない (hermetic / offline / fork でも動く)。
  照合するのは「snapshot に載っている名前を出す job が今も存在するか」
  だけで、 「GitHub 側の設定が snapshot と同じか」は人手 + 上の `gh api`
  で確認する。

<!-- BEGIN SNAPSHOT: required-status-checks -->

```text
build-and-test
lint
integration
F234 chunk-abort blast-radius smoke
roundtrip
lint-migration-rls
lint-migration-locks
lint-toolchain-alignment
static gate (hermetic)
schema snapshot drift + measured tolerance table
Golden Path 12-step against live api (curl + jq)
docs curl upload must succeed against live api
Playwright smoke (home / dashboard / api-health)
Playwright full suite (26 specs against seeded stack)
build-and-push
project-scoped API key matrix over HTTP (every apiKeyRouteScope route)
typecheck / build
```

<!-- END SNAPSHOT: required-status-checks -->

紛らわしい点を 2 つ明記しておく:

- `typecheck / build` は **`mcp-server-ci.yml`** の job 名であり、
  `frontend-ci.yml` の `lint / typecheck / build` とは別物。 後者は
  required ではない。
- `lint` は **`golangci-lint.yml`** の job 名。 `migration-lint.yml` /
  `migration-lock-lint.yml` / `toolchain-lint.yml` の job **id** も `lint`
  だが、 それぞれ `name:` を持つので check 名は衝突しない。

### 2.6 repo-hygiene.yml

§2.4 / §2.5 を守る lint 本体と、 `tools/` の build 生成物が untracked の
まま commit に紛れないことの確認を置いた workflow。 2 job とも hermetic
(DB もサーバも不要、 数十秒)。

| Job (= check 名) | 何を守るか |
|---|---|
| `lint-ci-inventory` | §2.4 のブロックが `.github/workflows/*.yml` の実集合と一致すること + §2.5 の各 required check 名を出す job が実在すること。 lint 自身の unit test も同 job で先に走らせる (「lint を緩めて diff を通す」防止) |
| `tools build leaves no untracked artifacts` | `tools/*/` の各モジュールで `go build ./...` を実行しても `git status --porcelain` が clean であること。 `go build` はモジュール名と同名のバイナリを `main.go` の隣に落とすので、 `.gitignore` に載っていないと `git add -A` で数 MB の実行ファイルが commit に入る (node_modules を commit して 421K insertions になった事故と同クラス)。 新しい tool を足したときの `.gitignore` 追記漏れを PR 時に検出する |

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
- [x] (P1) sbomhub: frontend lint/typecheck/build workflow 追加 — `frontend-ci.yml` (#17-followup) で Node 22 LTS + pnpm 9 で `pnpm --filter web lint` / `typecheck` (`tsc --noEmit`) / `build` (`next build`) を実行。 各 step `continue-on-error: true` の warn-only で初回 landing (apps/web に既存 lint / type 違反が残存している可能性があり、 無関係 PR を block しないため)。 `apps/web/package.json` に `typecheck` script (`tsc --noEmit`) を追加。 strict 化 (continue-on-error 削除) は lint=M11-5 #80、 typecheck/build=M12-5 #86 で完了 (下の M11-5 / M12-5 entry 参照、 Required status checks 追加は §2.3 USER action item で promote)
- [x] (M10-4 #72) sbomhub: `frontend-ci.yml` に proxy.ts matcher 不変条件 fixture (`apps/web/src/proxy.matcher.test.mjs`) + pnpm-workspace.yaml placeholder 検知 + pnpm 10 lifecycle-script skipped 5 package の native binding probe を追加。 §4.3 参照
- [x] (M11-5 #80) sbomhub: `apps/web` の lint gate を strict 化。 ESLint v9 flat config (`apps/web/eslint.config.mjs`) に移行 (Next 16 が `next lint` を削除したため `next lint` → `eslint .`)、 既存 25 error を全部解消 (`@typescript-eslint/no-empty-object-type` 3 件 / `@typescript-eslint/no-explicit-any` 4 件 / `react/no-unescaped-entities` 6 件 / `@next/next/no-html-link-for-pages` 1 file / その他)、 `react-hooks` plugin v7 の新 strict rule (`set-state-in-effect` / `immutability`) は pre-existing 違反の refactor 規模を考慮し `warn` に downgrade (config に rationale 明記)、 `lib/auth.ts` の build-time-conditional Clerk hook 3 件は inline disable + 経緯コメント。 `frontend-ci.yml::Lint` step の `continue-on-error: true` を解除して hard gate 化。 typecheck / build は warn-only 据え置き (別 wave)
- [x] (M12-5 #86) sbomhub: `apps/web` の typecheck / build gate を strict 化。 `frontend-ci.yml::Typecheck` (`tsc --noEmit`) と `frontend-ci.yml::Build` (`next build` with dummy `NEXT_PUBLIC_API_URL` / Clerk placeholder env) の `continue-on-error: true` を解除し **hard gate** 化。 M11-5 #80 lint cleanup の延長で `tsc --noEmit` が zero error に到達したことを確認後 promote、 build hard gate は M11-1 F164 production-build hydration-crash isolation (`next dev` では露見しない RSC full-SSR-hydration regression を捕まえる必須 guard) を根拠に typecheck と同時 promote。 併せて `react-hooks/set-state-in-effect` / `react-hooks/immutability` を M11-5 で `warn` に downgrade していた pre-existing 違反を全件解消し、 `apps/web/eslint.config.mjs` で `error` に昇格 (config rationale 更新)。 Required status checks への追加 (§2.3) は引き続き USER action
- [x] (2026-08-04) sbomhub: **本 doc 自身の drift 検知**を CI gate 化。 収録漏れが 21 workflow 中 10 件 (`dr-rehearsal` / `golden-path-e2e` / `mcp-server-ci` / `migration-lint` / `migration-lock-lint` / `nullscan` / `project-scope-e2e` / `release` / `scheduler-integration` / `toolchain-lint`) まで膨らみ、 required status check 17 件のうち 12 件が「本 doc に一行も無い workflow」から出ている状態だった。 §2.1 末尾に 10 件の prose を追記、 §2.4 に machine-checked な workflow/job インベントリブロック、 §2.5 に required status checks の snapshot を追加。 `tools/lint-ci-inventory` + `.github/workflows/repo-hygiene.yml::lint-ci-inventory` が (a) §2.4 ブロックと `.github/workflows/*.yml` の集合一致 (b) §2.5 の各 check 名を出す job の実在 を PR 時に検証する。 (b) は job `name:` の rename が required check を宙に浮かせて `main` を永久 merge 不能にする罠を、 stuck branch ではなく red lint に変換するためのもの。 §2.3 の stale な required check リスト (実設定と不一致) は削除して §2.5 へ集約
- [ ] (USER) §2.6 の 2 job (`lint-ci-inventory` / `tools build leaves no untracked artifacts`) を required status check に promote するか判断 (どちらも hermetic で 1 分未満)
- [ ] (USER) GitHub UI で `main` ブランチに上記 Required status checks 設定 (§2.3 / §3.3)
- [x] (P2) sbomhub: Golden Path E2E skeleton (Playwright を CI で実行) — `web-e2e.yml::web-e2e` (M8 #67) で docker compose 一式 (postgres + redis + locally built api + web) を立て、 chromium で `apps/web/e2e/smoke/` (home / dashboard / api-health) を実行。 docker-publish.yml (M7-5) の build-time HTML marker smoke と役割分担 (smoke=image build time / E2E=full stack runtime flow)
- [x] (M10-3 #71) sbomhub: 認証込みの深堀り spec (`apps/web/e2e/*.spec.ts` 26 件) を `web-e2e.yml::web-e2e-full` に promote。 `docker/seed/web-e2e.sql` で deterministic UUID の test tenant + project + sbom + component + CVE-2021-44228 + vex_draft + cra_report + meti_assessment + audit_log を pre-load し、 web 起動より前に seed を load することで API の `GetOrCreateDefault` が seeded tenant を採用する経路を強制。 spec ごとの timeout は `playwright.config.ts` で `60_000`、 retries は CI で `2`、 失敗時は `playwright-report-full` artifact を upload。 local repro recipe は `apps/web/e2e/README.md`。 §4.4 参照
- [ ] (P2) sbomhub-cli: golangci-lint の `continue-on-error: true` 解除 (Go 1.25 対応待ち)
- [ ] (P2) sbomhub-cli: PR 時の goreleaser snapshot dry-run 追加
- [ ] (P2) sbomhub / sbomhub-cli: security scanning (Snyk / GitGuardian / gosec / trivy fs scan) workflow 追加
- [ ] (P3) sbomhub-cli: homebrew tap / scoop bucket の install smoke 追加

## 4.3 frontend-ci.yml: M10-4 guard rails

`frontend-ci.yml` (M10-4 #72) に以下の hard gate を追加した。 いずれも
`continue-on-error: true` ではなく即時 fail。

| Guard | 何を守るか |
|---|---|
| `Guard pnpm-workspace.yaml against placeholder` | `pnpm-workspace.yaml` に `'@clerk/shared': set this to true or false` 等の `pnpm approve-builds` scaffold が紛れ込んだ際に PR を block。 M5-M9 で 数回 stale commit が発生し `git checkout --` revert が必要だった (詳細: pnpm-workspace.yaml header comment) |
| `Proxy matcher invariant (M10-4)` | `apps/web/src/proxy.matcher.test.mjs` を `node` で実行し、 proxy.ts の middleware matcher が `/secret.json` / `/leak.txt` 等 static-extension path を auth から bypass させない不変条件を pin |
| `pnpm 10 lifecycle script skip probe (M10-4)` | pnpm 10.34.3 が自動 skip する `@clerk/shared` / `@parcel/watcher` / `@swc/core` / `sharp` / `unrs-resolver` の native binding が **install 後に require できる**ことを確認。 binding が壊れていれば runtime まで露見せず CI で先に fail (詳細: package.json `// pnpm-skip-monitor` 参照) |

これら 3 つは全て M10-4 #72 で追加。 過去 M5-M9 で manual revert / stale catch を要した polish item を CI gate 化した。

## 4.4 web-e2e.yml::web-e2e-full: M10-3 promote

`web-e2e.yml` (M10-3 #71) に full Playwright suite job を追加した。 既存
の smoke job (`web-e2e`, 3 spec) と並行 (matrix ではなく独立 job) で実行する。

| 観点 | 値 / 説明 |
|---|---|
| trigger | `web-e2e` と同じ paths (apps/web, apps/api, compose, install.sh, env, pnpm 系) に `docker/seed/**` を追加 |
| seed | `docker/seed/web-e2e.sql` — deterministic UUID (`00000000-0000-0000-0000-000000000001` 以下) で tenant + user + project + sbom + component + CVE-2021-44228 + vex_draft + cra_report + meti_assessment + audit_log を 1 件ずつ insert。 `ON CONFLICT DO NOTHING` で idempotent |
| seed load 経路 | `docker compose exec -T postgres psql -U sbomhub -d sbomhub < docker/seed/web-e2e.sql`。 sbomhub superuser は `rolbypassrls=t` なので FORCE RLS table も `SET LOCAL app.current_tenant_id` 不要 |
| ordering | postgres + redis → install.sh --bootstrap-roles → **api 単体起動 (web まだ)** → /health 待ち → seed load → /me で deterministic tenant_id を verify → web 起動 → playwright |
| spec selector | `pnpm exec playwright test --project=chromium e2e/*.spec.ts` (top-level glob で `e2e/smoke/` subdir を除外、 26 件) |
| timeout | `playwright.config.ts::timeout: 60_000`、 job-level `timeout-minutes: 35` |
| retries | CI 時 `retries: 2` (既存設定を踏襲) |
| artifact | 失敗時 `playwright-report-full` (apps/web/playwright-report + test-results) を upload、 retention 7 日 |
| auth mode | 本番 web image を `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=` build arg で焼き込み → `isAuthEnabled()` が false → mock auth shim (`apps/web/src/lib/auth.ts`) が active。 dev:test launcher と同等の経路だが production image を使うため build path も同時に validate される |

honest limitations (M12 で対処):
- Clerk hosted UI (sign-in / sign-up / org switcher) の経路は本 job でも未カバー。 anonymous-request shim (`error-handling.spec.ts::should display error for unauthorized access`) も同じ理由で M12 に積み残し。
- LLM provider (OpenAI / Anthropic / Gemini) を要する flow (triage runner / cra runner の actual draft generation) は seed 済み draft で UI shell のみ exercise、 LLM 呼び出しの mock layer は M12。
- 3rd-party integration spec (`integrations.spec.ts` の GitHub / Jira 連携、 `sso-settings.spec.ts` の SAML / OIDC) は無認証で API が 404 / 401 を返す経路を許容する設計のため、 spec 自体は green になるが「integration 動作確認」までは到達しない。
- Duplicate-project-name prevention (`error-handling.spec.ts::should prevent duplicate project creation`) は product decision (UNIQUE (tenant_id, name) を加えるか UI dedup hint で済ますか) が未確定のため M12 に積み残し。

### M11-2 #77 で un-skip 済み (was-skipped → enabled)

M10-3 で 22 spec、 M11-1 (`sbom-diff.spec.ts`) で 21 spec まで減らした skipped を、 M11-2 で **13 件 un-skip** した。 licenses + api-keys describe は最初 un-skip したが、 UI flow gap (project-detail に Licenses / API Keys タブが無い、 spec が想定する dialog shape も乖離) で **35-min CI cap を burnt したため re-skip して M12 product decision 待ち** (run 28378387603 cancellation 参照):

| spec | tests | M11-2 で扱った内容 |
|---|---|---|
| `meti-assessment.spec.ts` | 3 | seed criterion_id を catalog-correct `meti.env_setup.01` に揃え、 spec body の soft-gate を信頼して un-skip |
| `search.spec.ts` | 3 | seed enrichment (4 CVE rows: 44228 / 45046 / 23337 / 8203) |
| `vulnerabilities.spec.ts` | 1 | seed component_vulnerabilities row |
| `integrations.spec.ts` / `ipa-settings.spec.ts` / `sso-settings.spec.ts` | 3 | sidebar h1 ("SBOMHub") との strict-mode 衝突を `getByRole('heading', { name: regex, level: 1 })` で disambiguate |
| `auth.spec.ts::EN→JA` | 1 | empty-Clerk-key mock auth で router.push 経路が確定したため re-enable |
| `security.spec.ts::HTML/SQL in search` | 2 | EN page で button label 'Search' に揃える (旧: Japanese '검索') |
| `security.spec.ts::null bytes` | 1 | parameterised INSERT で安全な outcome envelope (200/201/400/422/500) に揃える |
| `security.spec.ts::SQL in project` | 1 | dialog button locator + main 内 heading で disambiguate |

残 skipped (M12 対象、 計 14 spec):

| spec | tests | reason |
|---|---|---|
| `licenses.spec.ts::License Policy Management` | 6 | **UI flow gap (not seed gap)**. project-detail page に Licenses tab が無く、 Add Policy dialog の shape も乖離。 M11-2 初回 attempt で 35-min CI cap を burnt (run 28378387603 cancellation) ため re-skip。 product decision: project-detail に Licenses tab を生やすか、 spec を /settings/* へ移すか |
| `api-keys.spec.ts::API Keys Management` | 6 | **UI flow gap (not seed gap)**. project-detail page に API Keys tab が無く (現状は tenant-level `/settings/apikeys` のみ)、 spec が想定する dialog shape も乖離。 M11-2 初回 attempt で ~18 min CI を burnt。 product decision: project-detail に API Keys tab を追加するか、 spec を /settings/apikeys に揃えるか |
| `error-handling.spec.ts::should display error for unauthorized access` | 1 | dev:test に anonymous-request shim が無い (multi-file refactor 必須) |
| `error-handling.spec.ts::should prevent duplicate project creation` | 1 | product decision (UNIQUE constraint or UI dedup hint) 未確定 |

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
