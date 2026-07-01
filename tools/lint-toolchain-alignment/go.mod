// Standalone Go module for the toolchain alignment lint (F243, M16-2 #104).
//
// We keep this separate from `apps/api/go.mod` for the same reason as
// `tools/lint-migration-rls`: adding a CI lint tool must NOT pull tooling
// dependencies into the production backend's dependency graph (the tool
// happens to use only stdlib today, but the boundary is enforced at the
// module level so a future addition stays contained).
//
// Invoke from the repo root via:
//
//	(cd tools/lint-toolchain-alignment && go run . --repo-root ../..)
//
// or, if you prefer not to chdir:
//
//	go run ./tools/lint-toolchain-alignment/main.go --repo-root .
//
// The former shape is what the CI workflow uses (see
// .github/workflows/toolchain-lint.yml) — the tool lives in its own
// module without a covering workspace, so `cd` into the module dir is
// the most robust invocation.
//
// The `toolchain go1.26.4` line below is the lint's own dogfood: the
// tool checks itself, so if this line drifts from `apps/api/go.mod` the
// tool will flag itself as a drift in the very first run. That is
// intentional — the lint should be the strictest reader of its own
// contract.
module github.com/sbomhub/sbomhub/tools/lint-toolchain-alignment

go 1.26

toolchain go1.26.4
