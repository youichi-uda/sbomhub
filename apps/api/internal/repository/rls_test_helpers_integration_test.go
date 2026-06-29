//go:build integration

// Package repository - shared helpers for integration tests under the
// FORCE ROW LEVEL SECURITY regime (M0 Trust Rescue / migration 023+).
//
// Migrations 023, 040, 045 etc. give tenant-scoped tables FORCE RLS with
// WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID).
// The migrator role is NOBYPASSRLS, so even seed INSERTs from the migrator
// session must run inside a tx that has SET LOCAL app.current_tenant_id;
// otherwise the GUC returns NULL, the predicate evaluates to NULL, and
// the INSERT is rejected with
//
//	pq: new row violates row-level security policy for table "<name>"
//
// withTenantGUC encapsulates that pattern so individual *_rls_test.go
// files do not each reimplement the tx + SET LOCAL + COMMIT sequence.

package repository

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

// withTenantGUC opens a transaction on db, sets the tenant GUC to
// tenantID, runs fn against the tx, then COMMITs. On any failure (incl.
// fn calling t.Fatalf via runtime.Goexit or panicking) the deferred
// rollback closes the tx so the underlying connection is released
// promptly instead of waiting for the test process to exit.
//
// Use this from seed helpers and from CHECK-constraint tests that need
// to INSERT into a tenant-scoped table via the migrator role.
func withTenantGUC(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(*sql.Tx)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("withTenantGUC begin tx (tenant=%s): %v", tenantID, err)
	}
	// M9 F158: defer rollback guard; t.Fatalf inside fn() unwinds via
	// runtime.Goexit and would otherwise skip the Commit + leak the tx.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("withTenantGUC SET LOCAL app.current_tenant_id=%s: %v", tenantID, err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("withTenantGUC commit (tenant=%s): %v", tenantID, err)
	}
	committed = true
}

// execAsTenant runs a single INSERT/UPDATE/DELETE inside a
// tenant-scoped tx. Returns the resulting error (or nil) so the caller
// can assert against CHECK / NOT NULL / FK violations.
//
// Unlike withTenantGUC, execAsTenant does NOT t.Fatalf on the exec
// itself — many CHECK-constraint tests deliberately exercise inserts
// that are expected to fail, and need the error value to assert against.
// It still t.Fatalf's on Begin / SET LOCAL / Commit failure, and uses a
// deferred rollback so a t.Fatalf along those paths still closes the tx.
func execAsTenant(t *testing.T, db *sql.DB, tenantID uuid.UUID, query string, args ...any) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("execAsTenant begin tx (tenant=%s): %v", tenantID, err)
	}
	// M9 F158: defer rollback guard; same rationale as withTenantGUC.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("execAsTenant SET LOCAL app.current_tenant_id=%s: %v", tenantID, err)
	}
	_, execErr := tx.Exec(query, args...)
	if execErr != nil {
		// CHECK / FK violation aborts the tx; deferred rollback closes it.
		return execErr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("execAsTenant commit (tenant=%s): %v", tenantID, err)
	}
	committed = true
	return nil
}
