// Standalone Go module for the CI inventory drift lint.
//
// Same module-boundary posture as `tools/lint-migration-rls`,
// `tools/lint-migration-locks` and `tools/lint-toolchain-alignment`:
// adding a CI lint tool must NOT pull tooling dependencies into the
// production backend's dependency graph. Stdlib only, no go.sum.
//
// Invoke from the repo root via:
//
//	(cd tools/lint-ci-inventory && go run . --repo-root ../..)
//
// and regenerate the doc's generated block with:
//
//	(cd tools/lint-ci-inventory && go run . --repo-root ../.. --fix)
//
// That `cd` shape is what the CI workflow uses (see
// .github/workflows/repo-hygiene.yml) — the tool lives in its own module
// without a covering workspace, so entering the module directory is the
// most robust invocation.
//
// The `toolchain go1.26.4` line below is checked by
// `tools/lint-toolchain-alignment` layer 1 (it globs `tools/*/go.mod`),
// so it must track `apps/api/go.mod`'s toolchain directive exactly.
module github.com/sbomhub/sbomhub/tools/lint-ci-inventory

go 1.26

toolchain go1.26.4
