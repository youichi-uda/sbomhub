// Standalone Go module for the migration lock-discipline lint.
//
// We keep this separate from `apps/api/go.mod` for the same reason as
// `tools/lint-migration-rls` and `tools/lint-toolchain-alignment`:
// adding a CI lint tool must NOT pull tooling dependencies into the
// production backend's dependency graph (the tool happens to use only
// stdlib today, but the boundary is enforced at the module level so a
// future addition stays contained).
//
// Invoke from the repo root via:
//
//	(cd tools/lint-migration-locks && go run . --dir ../../apps/api/migrations)
//
// That `cd` shape is what the CI workflow uses (see
// .github/workflows/migration-lock-lint.yml) — the tool lives in its own
// module without a covering workspace, so entering the module directory
// is the most robust invocation. Same posture as the other two lints.
//
// The `toolchain go1.26.4` line below is checked by
// `tools/lint-toolchain-alignment` layer 1 (it globs `tools/*/go.mod`),
// so it must track `apps/api/go.mod`'s toolchain directive exactly.
module github.com/sbomhub/sbomhub/tools/lint-migration-locks

go 1.26

toolchain go1.26.4
