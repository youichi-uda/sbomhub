//go:build integration

// Package repository — TenantRepository.Create integration test under
// migration 048 (F185) FORCE RLS, pinning the F187 fix (M13 Phase D
// round 3).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestTenantCreate ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 048_legacy_scan_settings_logs_rls (the api
//     server's auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. F187 root cause: TenantRepository.Create wraps the `tenants` +
//     `scan_settings` inserts in a single tx. Migration 048 brought
//     scan_settings under FORCE RLS with WITH CHECK bound to
//     `current_setting('app.current_tenant_id', true)::UUID`. Pre-F187
//     the Create tx never bound that GUC, so the WITH CHECK predicate
//     evaluated against NULL, the scan_settings INSERT was rejected,
//     the tx rolled back, and the `tenants` INSERT was lost along
//     with it. Every tenant-bootstrap entry path
//     (TenantRepository.GetOrCreateDefault, GetOrCreateByClerkOrgID,
//     webhook_clerk.go::Handle, middleware/auth.go bootstrap) was
//     therefore broken under the sbomhub_app role from the moment
//     migration 048 shipped.
//
//  2. The F187 fix is `set_config('app.current_tenant_id', t.ID, true)`
//     issued between the tenants INSERT and the scan_settings INSERT.
//     The `true` second argument is SET LOCAL semantics — the GUC
//     does NOT leak across pooled connection re-use after Commit.
//
//  3. After Create lands, the runtime app role sees:
//        - exactly one `tenants` row for the new tenant id;
//        - exactly one `scan_settings` row for the new tenant id;
//     under a fresh tx bound to that tenant's GUC. A cross-tenant tx
//     bound to a different tenant's GUC sees neither row — F185
//     isolation holds because Create did not piggyback any global
//     visibility for the GUC value it briefly bound.
//
// The pre-fix failure mode the test guards against is
// `pq: new row violates row-level security policy for table
// "scan_settings"` returned from TenantRepository.Create, which used to
// surface in production as a refused tenant bootstrap on every Clerk
// org admission and every self-host first-boot. See tenant.go's Create
// godoc for the trail.

package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

func tenantCreateTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("tenant Create integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

func openOrSkipTenantCreate(t *testing.T, url string) *sql.DB {
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

// schemaReadyTenantCreate verifies that scan_settings is under FORCE RLS
// (the migration 048 state F187 fixes against). If it is NOT, the test
// is meaningless — the WITH CHECK predicate the Create fix exists to
// satisfy would not be enforced. We fail loudly (rather than silently
// passing) when the schema is "ready enough" to have the table but
// missing the policy, mirroring the same guard in
// scan_settings_rls_test.go.
func schemaReadyTenantCreate(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'scan_settings'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("scan_settings existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("scan_settings table not present -- run migrations first")
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = 'public.scan_settings'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("scan_settings RLS state check failed: %v -- skipping", err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Fatalf("scan_settings RLS not in expected state "+
			"(enabled=%v, force=%v). Migration 048 either not applied or "+
			"reverted -- the F187 Create fix only matters under FORCE RLS.",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// TestTenantCreate_LandsBothTenantAndScanSettings_RLS is the F187
// regression pin. It runs TenantRepository.Create through the runtime
// sbomhub_app (NOBYPASSRLS) role and asserts that:
//
//   - Create returns no error (pre-fix it returned the WITH CHECK
//     rejection from the scan_settings INSERT).
//   - The new tenants row is present.
//   - The new scan_settings row is present and visible to the owning
//     tenant under a fresh GUC-bound tx.
//
// A second tx bound to a different tenant's GUC verifies that the
// scan_settings row F187 just persisted is invisible to other tenants —
// i.e. the F185 isolation contract still holds after the F187 fix
// (the SET LOCAL GUC inside Create did not leak across connections
// because of its `is_local = true` second argument).
func TestTenantCreate_LandsBothTenantAndScanSettings_RLS(t *testing.T) {
	appURL, migURL := tenantCreateTestEnv(t)

	migDB := openOrSkipTenantCreate(t, migURL)
	defer migDB.Close()
	if !schemaReadyTenantCreate(t, migDB) {
		return
	}
	appDB := openOrSkipTenantCreate(t, appURL)
	defer appDB.Close()

	repo := NewTenantRepository(appDB)

	now := time.Now().UTC()
	tenantID := uuid.New()
	// Disambiguate parallel test runs and CI re-runs without UNIQUE
	// collisions on clerk_org_id / slug. Both have UNIQUE indexes
	// (migration 001 / 002) so we suffix with the uuid head.
	suffix := tenantID.String()[:12]
	t.Cleanup(func() {
		// scan_settings CASCADE-deletes via tenant_id FK (migration 010).
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	tenant := &model.Tenant{
		ID:         tenantID,
		ClerkOrgID: "f187-test-" + suffix,
		Name:       "F187 Test Tenant " + suffix,
		Slug:       "f187-" + suffix,
		Plan:       model.PlanEnterprise,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	// --- Step 1: Create through the runtime app role. Pre-fix this
	// returns `pq: new row violates row-level security policy for
	// table "scan_settings"` because the WITH CHECK predicate sees
	// NULL for current_setting('app.current_tenant_id', true).
	ctx := context.Background()
	if err := repo.Create(ctx, tenant); err != nil {
		t.Fatalf("F187 regression: TenantRepository.Create failed under "+
			"sbomhub_app role with migration 048 FORCE RLS active: %v. "+
			"This is the exact failure mode the tx-scoped GUC set_config "+
			"in Create() exists to prevent.", err)
	}

	// --- Step 2: confirm both rows landed. The tenants row is on a
	// non-RLS table so it's globally visible. The scan_settings row
	// must be visible from a tx bound to this tenant's GUC.
	var tenantSeen int
	if err := appDB.QueryRow(
		`SELECT COUNT(*) FROM tenants WHERE id = $1`, tenantID,
	).Scan(&tenantSeen); err != nil {
		t.Fatalf("tenants count: %v", err)
	}
	if tenantSeen != 1 {
		t.Fatalf("expected exactly 1 tenants row for %s, saw %d", tenantID, tenantSeen)
	}

	withTx := func(tenantForGUC uuid.UUID, fn func(*sql.Tx) error) {
		tx, err := appDB.Begin()
		if err != nil {
			t.Fatalf("appDB.Begin: %v", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantForGUC.String(),
		); err != nil {
			t.Fatalf("SET LOCAL app.current_tenant_id = %s: %v", tenantForGUC, err)
		}
		if err := fn(tx); err != nil {
			t.Fatal(err)
		}
	}

	withTx(tenantID, func(tx *sql.Tx) error {
		var scanSettingsSeen int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM scan_settings WHERE tenant_id = $1`, tenantID,
		).Scan(&scanSettingsSeen); err != nil {
			return err
		}
		if scanSettingsSeen != 1 {
			t.Fatalf("F187 regression: scan_settings row missing for tenant %s "+
				"(saw %d). The TenantRepository.Create tx should have inserted "+
				"the default schedule when it bound the tenant GUC.",
				tenantID, scanSettingsSeen)
		}
		return nil
	})

	// --- Step 3: isolation check. A different tenant's tx must NOT see
	// the scan_settings row F187 just persisted — the SET LOCAL inside
	// Create() is `is_local=true`, so it must not have leaked past the
	// Commit on the pooled connection.
	otherTenantID := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		otherTenantID,
		"f187-other-"+otherTenantID.String()[:12],
		"F187 Other "+otherTenantID.String()[:8],
		"f187-other-"+otherTenantID.String()[:8],
	); err != nil {
		t.Fatalf("seed otherTenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, otherTenantID)
	})

	withTx(otherTenantID, func(tx *sql.Tx) error {
		var leak int
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM scan_settings WHERE tenant_id = $1`, tenantID,
		).Scan(&leak); err != nil {
			return err
		}
		if leak != 0 {
			t.Fatalf("F185 regression: a tx bound to otherTenant's GUC saw %d "+
				"row(s) for tenant %s's scan_settings; expected 0. The F187 "+
				"tx-scoped GUC inside Create() must not weaken the FORCE RLS "+
				"isolation that migration 048 established.",
				leak, tenantID)
		}
		return nil
	})
}

// TestTenantCreate_GetOrCreateDefault_RoundTrips guards the
// GetOrCreateDefault path specifically — this is what self-host
// first-boot and middleware/auth.go:78 hit. Pre-F187, the first call
// returned an RLS rejection and never populated the row, so every
// subsequent boot kept failing on the same path. The test runs the
// helper twice and asserts both calls return the same tenant id (the
// second call is a GetBySlug hit on the row the first call persisted).
func TestTenantCreate_GetOrCreateDefault_RoundTrips(t *testing.T) {
	appURL, migURL := tenantCreateTestEnv(t)

	migDB := openOrSkipTenantCreate(t, migURL)
	defer migDB.Close()
	if !schemaReadyTenantCreate(t, migDB) {
		return
	}
	appDB := openOrSkipTenantCreate(t, appURL)
	defer appDB.Close()

	// GetOrCreateDefault uses a fixed slug "default" which collides
	// with whatever previous test run / actual app has done. Reset
	// before/after under the migrator role (which sees everything).
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE slug = 'default'`)
	})
	if _, err := migDB.Exec(`DELETE FROM tenants WHERE slug = 'default'`); err != nil {
		t.Fatalf("pre-clean default tenant: %v", err)
	}

	repo := NewTenantRepository(appDB)
	ctx := context.Background()

	first, err := repo.GetOrCreateDefault(ctx)
	if err != nil {
		t.Fatalf("F187 regression: GetOrCreateDefault failed on first call "+
			"(self-host first-boot path is broken without the tx-scoped GUC "+
			"in Create): %v", err)
	}
	if first == nil || first.ID == uuid.Nil {
		t.Fatal("GetOrCreateDefault returned nil/empty tenant on first call")
	}

	second, err := repo.GetOrCreateDefault(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateDefault failed on second call: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("GetOrCreateDefault second call returned a different tenant "+
			"id %s than the first %s — the first call's Create() must have "+
			"persisted the row so the second call falls through GetBySlug",
			second.ID, first.ID)
	}

	// The scan_settings auto-creation must have fired too.
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`SELECT set_config('app.current_tenant_id', $1, true)`,
		first.ID.String(),
	); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	var seen int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM scan_settings WHERE tenant_id = $1`, first.ID,
	).Scan(&seen); err != nil {
		// Distinguish RLS error from real failure for clearer diagnosis.
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("F187 regression: scan_settings row never landed for " +
				"the default tenant — Create's tx must roll back when the " +
				"GUC is unset.")
		}
		t.Fatalf("scan_settings count: %v", err)
	}
	if seen != 1 {
		t.Fatalf("F187 regression: default tenant has %d scan_settings rows; "+
			"expected exactly 1 from Create's auto-provision.", seen)
	}
}
