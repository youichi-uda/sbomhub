// Standalone Go module for the CI inventory drift lint.
//
// Same module-boundary posture as `tools/lint-migration-rls`,
// `tools/lint-migration-locks` and `tools/lint-toolchain-alignment`:
// adding a CI lint tool must NOT pull tooling dependencies into the
// production backend's dependency graph.
//
// Unlike its three siblings this module is NOT stdlib-only. It depends on
// github.com/goccy/go-yaml, because hand-rolling the YAML scan produced a
// steady stream of review findings that were all the same defect — an
// incomplete YAML implementation — and several of them were false
// positives that would have turned `main` red on a correct workflow. See
// the "YAML parsing" section of main.go's package comment.
//
// That is exactly the case the boundary was drawn for: `apps/api` cannot
// see this dependency, because the boundary is the MODULE, not the
// absence of dependencies. gopkg.in/yaml.v3 was not an option — it is
// archived and unmaintained as of 2026, and this repo treats "libraries
// stay current" as a security-product rule.
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

require github.com/goccy/go-yaml v1.19.2
