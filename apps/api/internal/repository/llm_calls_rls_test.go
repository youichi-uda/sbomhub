//go:build integration

// Package repository - llm_calls tenant-isolation integration test
// (M1 Wave M1-1 / issue #20, migration 032).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestLLMCalls ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 032_llm_calls (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The llm_calls INSERT goes through the FORCE RLS WITH CHECK policy
//     installed in migration 032. A session that has not set
//     app.current_tenant_id, or that has set it to a different tenant,
//     must NOT be able to insert a row with a third tenant's id.
//
//  2. A read from tenant B's session must NOT surface rows that tenant A
//     inserted. This is the audit-log isolation guarantee --
//     cross-tenant prompt/response leakage would defeat the audit's
//     purpose.
//
//  3. The unit-level rls_test.go already covers projects/sboms. We
//     duplicate the seed-tenant helper here rather than refactoring to
//     keep this test self-contained and the file readable in isolation
//     (same convention as audit_rls_test.go / apikey_rls_test.go).
package repository

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func llmCallsTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("llm_calls integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadyLLMCalls checks that llm_calls exists AND that RLS is
// still ENABLE + FORCE on it (migration 032 state). If RLS has been
// removed by a future migration without updating this test, we skip
// loudly rather than silently mis-test the policy.
func schemaReadyLLMCalls(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'llm_calls'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("llm_calls existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("llm_calls table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.llm_calls'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("llm_calls RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("llm_calls RLS not in expected state (enabled=%v, force=%v); "+
			"migration 032 may have been reverted -- skipping", rlsEnabled, rlsForce)
		return false
	}
	return true
}

func seedTenantForLLMCalls(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "llm-calls-test-"+label+"-"+id.String(),
		"LLMCalls Test "+label,
		"llm-calls-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// openOrSkipLLMCalls is a local wrapper around sql.Open that skips the
// test (rather than failing) when the database is unreachable -- so CI
// without Postgres just skips this file.
func openOrSkipLLMCalls(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open: %v -- skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("db unreachable: %v -- skipping", err)
	}
	return db
}

// TestLLMCalls_TenantIsolation_RLS verifies the load-bearing security
// property of migration 032: under the sbomhub_app (NOBYPASSRLS) role, a
// row written by tenant A is invisible to tenant B, and tenant B cannot
// forge a row claiming to belong to tenant A (the WITH CHECK clause
// rejects the INSERT).
func TestLLMCalls_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openOrSkipLLMCalls(t, migURL)
	defer migDB.Close()
	if !schemaReadyLLMCalls(t, migDB) {
		return
	}
	appDB := openOrSkipLLMCalls(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForLLMCalls(t, migDB, "A")
	tenantB := seedTenantForLLMCalls(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the llm_calls rows we are about to
		// insert.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert one llm_calls row.
	rowA := uuid.New()
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO llm_calls (
			id, tenant_id, purpose, provider, model,
			prompt_hash, response_hash,
			input_tokens, output_tokens, cost_usd, duration_ms
		) VALUES ($1, $2, 'vex_triage', 'openai', 'gpt-4o',
			$3, $4, 10, 5, 0.001, 100)
	`, rowA, tenantA, hex64("p"), hex64("r")); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, count tenant A's row by id.
	// RLS should make it invisible -> count must be 0.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(`SELECT COUNT(*) FROM llm_calls WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak: tenantB saw %d row(s) for tenantA's llm_calls.id=%s; expected 0", seen, rowA)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it. We expect an error here.
	rowForged := uuid.New()
	_, forgeErr := txB.Exec(`
		INSERT INTO llm_calls (
			id, tenant_id, purpose, provider, model,
			prompt_hash, response_hash,
			input_tokens, output_tokens, cost_usd, duration_ms
		) VALUES ($1, $2, 'vex_triage', 'openai', 'gpt-4o',
			$3, $4, 10, 5, 0.001, 100)
	`, rowForged, tenantA, hex64("pf"), hex64("rf"))
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken: tenantB session was able to insert a row "+
			"with tenant_id=%s (tenantA). This is the cross-tenant write primitive "+
			"the policy is supposed to prevent.", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible to its owner (the policy must not over-reject).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(`SELECT COUNT(*) FROM llm_calls WHERE id = $1`, rowA).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own llm_calls rows for id=%s; expected 1 -- RLS policy may be over-restrictive", seen, rowA)
	}
}

// hex64 produces a 64-character lowercase hex string from any short
// label. Sufficient to satisfy the CHAR(64) prompt_hash / response_hash
// columns; the actual hash value does not matter for the RLS test.
func hex64(label string) string {
	const hexChars = "0123456789abcdef"
	out := make([]byte, 64)
	for i := 0; i < 64; i++ {
		// Cheap deterministic fill -- not a real hash, just placeholder
		// bytes that fit CHAR(64).
		out[i] = hexChars[(int(label[i%len(label)])+i)%16]
	}
	return string(out)
}
