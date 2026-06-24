//go:build integration

// Package repository - tenant_llm_config tenant-isolation integration test
// (M1 Codex review round 1 / F1, migration 037).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestTenantLLMConfig ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 037_tenant_llm_config_rls (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The tenant_llm_config INSERT goes through the FORCE RLS WITH CHECK
//     policy installed in migration 037. A session that has set
//     app.current_tenant_id to tenant B must NOT be able to insert a row
//     with tenant A's id (cross-tenant write primitive).
//
//  2. A read from tenant B's session must NOT surface a row that tenant A
//     inserted. This is the load-bearing security guarantee of F1: the
//     tenant_llm_config row carries `encrypted_api_key` (BYOK ciphertext),
//     so a cross-tenant read leaks operator-supplied LLM credentials.
//
//  3. tenant A still sees its own row (policy must not over-reject).
//
// This file mirrors llm_calls_rls_test.go (migration 032). See its header
// for the rationale behind the duplicated helpers (we keep each RLS test
// file self-contained for readability).
package repository

import (
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func tenantLLMConfigTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("tenant_llm_config integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadyTenantLLMConfig checks that tenant_llm_config exists AND that
// RLS is ENABLE + FORCE on it (migration 037 state). If a future migration
// reverts RLS without updating this test, we skip loudly rather than
// silently mis-test the policy.
func schemaReadyTenantLLMConfig(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'tenant_llm_config'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("tenant_llm_config existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("tenant_llm_config table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.tenant_llm_config'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("tenant_llm_config RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		// This is the regression-test failure mode: the table exists but
		// RLS is not in the post-037 state. Codex F1 says this is a high-
		// severity gap, so fail (not skip) when the schema is ready
		// enough to have the table but missing the policy.
		t.Fatalf("tenant_llm_config RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 037 either not applied or "+
			"reverted -- this is the F1 regression. Run `go run ./cmd/migrate up`.",
			rlsEnabled, rlsForce)
		return false
	}
	// Also assert the named policy is present, so a future schema change
	// that disables and re-enables RLS without re-creating the policy
	// regresses loudly.
	var policyCount int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM pg_policies
		WHERE schemaname = 'public'
		  AND tablename  = 'tenant_llm_config'
		  AND policyname = 'tenant_isolation_tenant_llm_config'
	`).Scan(&policyCount); err != nil {
		t.Skipf("pg_policies lookup failed: %v -- skipping", err)
		return false
	}
	if policyCount != 1 {
		t.Fatalf("tenant_llm_config policy tenant_isolation_tenant_llm_config not "+
			"found (count=%d). Migration 037 either not applied or reverted -- "+
			"this is the F1 regression.", policyCount)
		return false
	}
	return true
}

func seedTenantForTenantLLMConfig(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "tenant-llm-config-test-"+label+"-"+id.String(),
		"TenantLLMConfig Test "+label,
		"tlc-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// openOrSkipTenantLLMConfig is a local wrapper around sql.Open that skips
// the test (rather than failing) when the database is unreachable -- so CI
// without Postgres just skips this file.
func openOrSkipTenantLLMConfig(t *testing.T, url string) *sql.DB {
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

// TestTenantLLMConfig_TenantIsolation_RLS verifies the load-bearing
// security property of migration 037 (Codex round 1 / F1): under the
// sbomhub_app (NOBYPASSRLS) role, a tenant_llm_config row written by
// tenant A is invisible to tenant B, and tenant B cannot forge a row
// claiming to belong to tenant A (the WITH CHECK clause rejects the
// INSERT). The encrypted_api_key column carries BYOK ciphertext, so a
// cross-tenant leak here is a credential-disclosure bug.
func TestTenantLLMConfig_TenantIsolation_RLS(t *testing.T) {
	appURL, migURL := tenantLLMConfigTestEnv(t)

	migDB := openOrSkipTenantLLMConfig(t, migURL)
	defer migDB.Close()
	if !schemaReadyTenantLLMConfig(t, migDB) {
		return
	}
	appDB := openOrSkipTenantLLMConfig(t, appURL)
	defer appDB.Close()

	tenantA := seedTenantForTenantLLMConfig(t, migDB, "A")
	tenantB := seedTenantForTenantLLMConfig(t, migDB, "B")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the tenant_llm_config rows.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	// --- Step 1: as app role under tenant A, insert one tenant_llm_config row.
	// The encrypted_api_key payload is a fixed test marker; it is BYTEA in
	// the schema so we just stuff arbitrary bytes -- the RLS test does not
	// exercise the crypto path.
	apiKeyCipherA := []byte("test-ciphertext-tenantA-nonce||sealed-bytes")
	txA, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA: %v", err)
	}
	if _, err := txA.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		_ = txA.Rollback()
		t.Fatalf("SET LOCAL tenantA: %v", err)
	}
	if _, err := txA.Exec(`
		INSERT INTO tenant_llm_config (
			tenant_id, mode, provider, encrypted_api_key, model
		) VALUES ($1, 'byok', 'openai', $2, 'gpt-4o')
	`, tenantA, apiKeyCipherA); err != nil {
		_ = txA.Rollback()
		t.Fatalf("tenantA insert: %v", err)
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit tenantA: %v", err)
	}

	// --- Step 2: as app role under tenant B, attempt to read tenant A's
	// row by primary key. RLS must make it invisible -> COUNT == 0.
	txB, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantB: %v", err)
	}
	defer txB.Rollback()
	if _, err := txB.Exec(`SET LOCAL app.current_tenant_id = '` + tenantB.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantB: %v", err)
	}
	var seen int
	if err := txB.QueryRow(
		`SELECT COUNT(*) FROM tenant_llm_config WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantB count: %v", err)
	}
	if seen != 0 {
		t.Fatalf("RLS leak (F1 regression): tenantB saw %d row(s) for tenantA's "+
			"tenant_llm_config; expected 0. This means encrypted_api_key is "+
			"readable across tenants -- the exact gap Codex round 1 F1 flagged.",
			seen)
	}

	// --- Step 2b: also verify direct encrypted_api_key SELECT returns no
	// rows from tenant B's session. We want to be very explicit that the
	// ciphertext column itself is unreadable cross-tenant.
	var leakedCipher []byte
	err = txB.QueryRow(
		`SELECT encrypted_api_key FROM tenant_llm_config WHERE tenant_id = $1`, tenantA,
	).Scan(&leakedCipher)
	if err == nil {
		t.Fatalf("RLS leak (F1 regression): tenantB read tenantA's encrypted_api_key "+
			"(%d bytes). Cross-tenant BYOK credential disclosure.", len(leakedCipher))
	}
	if err != sql.ErrNoRows {
		// Any other error (e.g. permission denied) is acceptable as long
		// as the ciphertext did not leak; log it for debuggability.
		t.Logf("tenantB encrypted_api_key SELECT returned %v (no leak, ok)", err)
	}

	// --- Step 3: tenantB tries to INSERT a row claiming tenant_id =
	// tenantA. WITH CHECK should reject it. We expect an error here.
	// Use an explicit clerk_org collision-safe payload so the test does
	// not falsely succeed because of a unique-key conflict.
	apiKeyCipherForged := []byte("test-ciphertext-forged-by-tenantB")
	// Pick a fresh tenant_id-shaped UUID that does NOT exist as a tenant,
	// so that any failure we observe is from the RLS WITH CHECK clause
	// (and not from a tenants FK violation that would also reject the
	// row). We attempt to insert a row claiming tenant A's id, which
	// DOES exist as a tenant -- so the only thing that can reject this
	// INSERT is the WITH CHECK predicate on tenant_id =
	// current_setting('app.current_tenant_id')::UUID, which under
	// tenant B's session evaluates to tenantB != tenantA -> false.
	_, forgeErr := txB.Exec(`
		INSERT INTO tenant_llm_config (
			tenant_id, mode, provider, encrypted_api_key, model
		) VALUES ($1, 'byok', 'anthropic', $2, 'claude-opus-4-7')
		ON CONFLICT (tenant_id) DO UPDATE
		SET encrypted_api_key = EXCLUDED.encrypted_api_key
	`, tenantA, apiKeyCipherForged)
	if forgeErr == nil {
		t.Fatalf("RLS WITH CHECK broken (F1 regression): tenantB session was able "+
			"to write a row with tenant_id=%s (tenantA). This is the cross-tenant "+
			"BYOK overwrite primitive the policy is supposed to prevent.", tenantA)
	}

	// --- Step 4: as tenant A again, confirm the original row is still
	// visible to its owner (policy must not over-reject).
	txA2, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin tenantA2: %v", err)
	}
	defer txA2.Rollback()
	if _, err := txA2.Exec(`SET LOCAL app.current_tenant_id = '` + tenantA.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL tenantA2: %v", err)
	}
	if err := txA2.QueryRow(
		`SELECT COUNT(*) FROM tenant_llm_config WHERE tenant_id = $1`, tenantA,
	).Scan(&seen); err != nil {
		t.Fatalf("tenantA2 count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("tenantA session sees %d of its own tenant_llm_config rows; "+
			"expected 1 -- RLS policy may be over-restrictive", seen)
	}

	// And the ciphertext must round-trip unchanged.
	var roundTripCipher []byte
	if err := txA2.QueryRow(
		`SELECT encrypted_api_key FROM tenant_llm_config WHERE tenant_id = $1`, tenantA,
	).Scan(&roundTripCipher); err != nil {
		t.Fatalf("tenantA2 ciphertext SELECT: %v", err)
	}
	if string(roundTripCipher) != string(apiKeyCipherA) {
		t.Fatalf("encrypted_api_key round-trip mismatch: got %q, want %q",
			string(roundTripCipher), string(apiKeyCipherA))
	}
}
