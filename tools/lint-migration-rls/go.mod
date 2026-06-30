// Standalone Go module for the migration RLS lint.
//
// We keep this separate from `apps/api/go.mod` so that adding a CI lint
// tool does NOT pull tooling dependencies into the production backend's
// dependency graph (the tool happens to use only stdlib today, but the
// boundary is enforced at the module level so a future addition stays
// contained).
//
// Invoke from the repo root via:
//
//	(cd tools/lint-migration-rls && go run . --dir ../../apps/api/migrations)
//
// or, if you prefer not to chdir:
//
//	go run ./tools/lint-migration-rls/main.go --dir apps/api/migrations
//
// The latter form is what the CI workflow uses (see
// .github/workflows/migration-lint.yml) — it's robust against the working
// directory the runner happens to start in.
module github.com/sbomhub/sbomhub/tools/lint-migration-rls

go 1.25
