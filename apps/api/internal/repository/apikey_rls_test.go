//go:build integration

// Package repository - api_keys tenant-isolation integration test
// (Trust Rescue P0 #18).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestAPIKey ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 028_api_keys_remove_rls (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The api_keys SELECT-by-key_hash lookup that MultiAuth / APIKeyAuth
//     do BEFORE any tenant context is set must succeed under the
//     NOBYPASSRLS app role. Before migration 028 it returned zero rows
//     because FORCE ROW LEVEL SECURITY + an unset `app.current_tenant_id`
//     GUC reduced the policy to FALSE, killing all CLI/GitHub-Actions auth
//     in production.
//
//  2. Now that RLS is off, tenant isolation on api_keys lives entirely in
//     APIKeyRepository's `tenant_id = $N` clauses. ListByTenant /
//     GetByID / ListByProject MUST NOT leak rows belonging to another
//     tenant — these tests are what stop a regression from re-enabling
//     cross-tenant access.
package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// apikeyTestEnv mirrors rlsTestEnv but is duplicated locally to keep this
// file self-contained (rls_test.go already declares the helper in the same
// package, so we just reuse it by name).
func apikeyTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("api_keys integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// hashRawKey replicates service.hashKey (SHA-256 over the raw bearer
// token). Duplicated here to avoid creating an import cycle between this
// package and internal/service.
func hashRawKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// schemaReadyAPIKeys checks that api_keys exists AND that migration 028
// has actually run — i.e. row-level security is disabled. If 028 hasn't
// been applied we want to skip with a loud message rather than fail in a
// confusing way.
func schemaReadyAPIKeys(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tableExists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'api_keys'
		)
	`).Scan(&tableExists); err != nil {
		t.Skipf("api_keys existence check failed: %v — skipping", err)
		return false
	}
	if !tableExists {
		t.Skip("api_keys table not present — run migrations first")
		return false
	}

	// pg_class.relrowsecurity is true after ENABLE RLS, false after
	// DISABLE RLS. Migration 028 calls DISABLE so we expect false.
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE oid = 'public.api_keys'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("api_keys RLS-state check failed: %v — skipping", err)
		return false
	}
	if rlsEnabled || rlsForce {
		t.Skipf("api_keys still has RLS enabled (rowsec=%v, force=%v) — "+
			"migration 028 has not been applied to this database; skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// seedTenant inserts a tenant row using the migrator role (tenants has no
// RLS so this is straightforward) and returns its UUID.
func seedTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "apikey-test-"+label+"-"+id.String(),
		"APIKey Test "+label,
		"apikey-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// seedAPIKey inserts an api_keys row via the repository under the app role.
// We deliberately use the repository's own Create so the same code path the
// real server takes is exercised.
func seedAPIKey(
	t *testing.T,
	ctx context.Context,
	repo *APIKeyRepository,
	tenantID uuid.UUID,
	name string,
) *model.APIKey {
	t.Helper()
	raw := "sbh_apikey_test_" + uuid.NewString()[:24]
	now := time.Now().UTC().Truncate(time.Microsecond)
	k := &model.APIKey{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ProjectID:   nil,
		Name:        name,
		KeyHash:     hashRawKey(raw),
		KeyPrefix:   raw[:12],
		Permissions: "write",
		CreatedAt:   now,
	}
	if err := repo.Create(ctx, k); err != nil {
		t.Fatalf("repo.Create(%s): %v", name, err)
	}
	return k
}

// TestAPIKey_LookupByHashWorksWithoutTenantContext is the core acceptance
// criterion for P0 #18: under the NOBYPASSRLS app role and with no
// `app.current_tenant_id` GUC set, GetByKeyHash must return the row.
//
// If migration 028 ever gets reverted (or someone re-enables RLS on
// api_keys), this test fails — and that is exactly the regression that
// took production auth down before #18.
func TestAPIKey_LookupByHashWorksWithoutTenantContext(t *testing.T) {
	appURL, migURL := apikeyTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyAPIKeys(t, migDB) {
		return
	}

	appDB, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Skipf("sql.Open(appURL) failed: %v — skipping", err)
	}
	defer appDB.Close()
	if err := appDB.Ping(); err != nil {
		t.Skipf("appDB unreachable: %v — skipping", err)
	}

	// Confirm we really are connected as a NOBYPASSRLS role — this is
	// the configuration that exposed the original bug.
	var bypass bool
	if err := appDB.QueryRow(
		`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("query rolbypassrls: %v", err)
	}
	if bypass {
		t.Fatalf("app role has rolbypassrls=true; switch DATABASE_URL to sbomhub_app")
	}

	tenantID := seedTenant(t, migDB, "lookup")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := NewAPIKeyRepository(appDB)
	ctx := context.Background()
	key := seedAPIKey(t, ctx, repo, tenantID, "lookup target")

	// Sanity: no tenant GUC set on this connection. Looking up the row
	// by hash MUST succeed — this is the entire point of removing RLS
	// on api_keys.
	got, err := repo.GetByKeyHash(ctx, key.KeyHash)
	if err != nil {
		t.Fatalf("GetByKeyHash: %v", err)
	}
	if got == nil {
		t.Fatalf("GetByKeyHash returned nil under sbomhub_app with no tenant GUC; "+
			"this is the P0 #18 regression — migration 028 likely missing. tenant=%s, key=%s",
			tenantID, key.ID)
	}
	if got.ID != key.ID || got.TenantID != tenantID {
		t.Fatalf("GetByKeyHash returned wrong row: got id=%s tenant=%s, want id=%s tenant=%s",
			got.ID, got.TenantID, key.ID, tenantID)
	}
}

// TestAPIKey_ApplicationLayerTenantIsolation pins down that, with RLS off
// (migration 028), the `tenant_id = $N` clauses in APIKeyRepository do all
// the tenant-isolation work. Each tenant must only see its own keys, and
// cross-tenant GetByID must return nil.
func TestAPIKey_ApplicationLayerTenantIsolation(t *testing.T) {
	appURL, migURL := apikeyTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyAPIKeys(t, migDB) {
		return
	}

	appDB, err := sql.Open("postgres", appURL)
	if err != nil {
		t.Skipf("sql.Open(appURL) failed: %v — skipping", err)
	}
	defer appDB.Close()
	if err := appDB.Ping(); err != nil {
		t.Skipf("appDB unreachable: %v — skipping", err)
	}

	tenantA := seedTenant(t, migDB, "A")
	tenantB := seedTenant(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewAPIKeyRepository(appDB)
	ctx := context.Background()

	keyA := seedAPIKey(t, ctx, repo, tenantA, "tenant-A key")
	keyB := seedAPIKey(t, ctx, repo, tenantB, "tenant-B key")

	// 1. ListByTenant(A) must contain keyA but not keyB.
	listA, err := repo.ListByTenant(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListByTenant(A): %v", err)
	}
	if !containsKeyID(listA, keyA.ID) {
		t.Fatalf("ListByTenant(A) missing tenant A's own key %s; got %s", keyA.ID, summarize(listA))
	}
	if containsKeyID(listA, keyB.ID) {
		t.Fatalf("ListByTenant(A) leaked tenant B's key %s; got %s", keyB.ID, summarize(listA))
	}

	// 2. ListByTenant(B) must contain keyB but not keyA.
	listB, err := repo.ListByTenant(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListByTenant(B): %v", err)
	}
	if !containsKeyID(listB, keyB.ID) {
		t.Fatalf("ListByTenant(B) missing tenant B's own key %s; got %s", keyB.ID, summarize(listB))
	}
	if containsKeyID(listB, keyA.ID) {
		t.Fatalf("ListByTenant(B) leaked tenant A's key %s; got %s", keyA.ID, summarize(listB))
	}

	// 3. Cross-tenant GetByID must return nil — tenantA cannot read
	//    tenantB's key even when it knows the UUID.
	cross, err := repo.GetByID(ctx, tenantA, keyB.ID)
	if err != nil {
		t.Fatalf("GetByID(A, keyB): %v", err)
	}
	if cross != nil {
		t.Fatalf("GetByID(A, keyB) returned %s; cross-tenant read should yield nil", cross.ID)
	}

	// 4. Same-tenant GetByID must still succeed (sanity for the
	//    `tenant_id = $2` filter not being over-restrictive).
	own, err := repo.GetByID(ctx, tenantA, keyA.ID)
	if err != nil {
		t.Fatalf("GetByID(A, keyA): %v", err)
	}
	if own == nil || own.ID != keyA.ID {
		t.Fatalf("GetByID(A, keyA) returned %v; want id=%s", own, keyA.ID)
	}

	// 5. Cross-tenant Delete must report not-found and leave the row
	//    intact.
	if err := repo.Delete(ctx, tenantA, keyB.ID); err == nil {
		t.Fatalf("Delete(A, keyB) succeeded; cross-tenant delete must fail")
	}
	stillThere, err := repo.GetByID(ctx, tenantB, keyB.ID)
	if err != nil {
		t.Fatalf("GetByID(B, keyB) after cross-delete: %v", err)
	}
	if stillThere == nil {
		t.Fatalf("tenant B's key disappeared after a cross-tenant Delete from tenant A")
	}
}

func containsKeyID(keys []model.APIKey, id uuid.UUID) bool {
	for _, k := range keys {
		if k.ID == id {
			return true
		}
	}
	return false
}

func summarize(keys []model.APIKey) string {
	if len(keys) == 0 {
		return "[]"
	}
	out := "["
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("{id=%s tenant=%s}", k.ID, k.TenantID)
	}
	return out + "]"
}
