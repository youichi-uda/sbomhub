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
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// ---------------------------------------------------------------------------
// C27: cleanup-trap eradication + tenant-leak gate (M46).
//
// Root cause of the historical leak (2,869 orphan tenants rows on the shared
// dev DB): tests opened the migrator handle with `defer migDB.Close()` and
// registered the tenant DELETE with t.Cleanup. t.Cleanup functions run AFTER
// the test function returns — i.e. after all defers — so the DELETE always
// hit a closed *sql.DB (`sql: database is closed`) and was silenced by
// `_, _ =`. Every test run leaked its tenants.
//
// The regime enforced here:
//
//  1. openIntegrationDB registers Close via t.Cleanup at open time. Because
//     t.Cleanup is LIFO, the Close registered FIRST runs LAST — any delete
//     cleanup registered later still sees an open handle. Never use
//     `defer db.Close()` for handles that cleanups depend on.
//  2. seedIntegrationTenant registers its own DELETE cleanup immediately
//     after a successful INSERT, so a later t.Fatal cannot strand the row,
//     and reports delete failures via t.Errorf (see policy note below).
//  3. Every test tenant carries the canonical marker prefix
//     c27TenantOrgPrefix in clerk_org_id (and slug), and TestMain fails the
//     package run if the number of marker rows grew during the run.
//
// Cleanup-failure policy (deliberate): a failed tenant delete calls
// t.Errorf on the OWNING test, failing that test only. Rationale: the
// package-level gate below would fail anyway; failing the owning test
// pinpoints WHICH test leaked instead of leaving a package-level puzzle.
// A DELETE that matches 0 rows is not an error (tests may legitimately
// remove their own tenants mid-test).
//
// Gate limitations (documented, not hidden):
//   - Rows created without the marker prefix are invisible to the gate.
//     The only such row today is the slug='default' tenant created through
//     the production GetOrCreateDefault path in tenant_rls_test.go; that
//     test deletes it in its own (now un-trapped) cleanup.
//   - Non-tenant global rows (vulnerabilities CVE-M5-1-*, audit_logs with
//     tenant_id NULL) are reaped by their own error-visible cleanups but
//     not counted by this gate.
//   - Two concurrent `go test` invocations of the SAME package against the
//     same DB can trip the gate spuriously (each package has its own prefix,
//     so cross-package parallelism inside one `go test ./...` run is safe).
// ---------------------------------------------------------------------------

// c27TenantOrgPrefix marks every tenant row created by this package's
// integration tests (clerk_org_id and slug prefix). Per-package prefixes:
// repository=itest-repo-, scheduler=itest-sched-, service=itest-svc-,
// middleware=itest-mw-.
const c27TenantOrgPrefix = "itest-repo-"

// openIntegrationDB opens url, skips the test when the DB is unreachable,
// and registers Close via t.Cleanup so it runs AFTER (LIFO) any cleanup
// registered later by the test body.
func openIntegrationDB(t *testing.T, url string) *sql.DB {
	t.Helper()
	if url == "" {
		t.Skip("DATABASE_URL / MIGRATE_DATABASE_URL not set — skipping")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open: %v — skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("db unreachable: %v — skipping", err)
	}
	// C27 cleanup-trap: register Close FIRST so it runs LAST.
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// seedIntegrationTenant inserts a canonical marker-prefixed tenant as the
// migrator role and registers an error-visible DELETE cleanup immediately.
// ON DELETE CASCADE on the tenants FKs reaps all tenant-scoped child rows.
func seedIntegrationTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	org := c27TenantOrgPrefix + label + "-" + id.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, org, "itest "+label, c27TenantOrgPrefix+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s (%s): %v", id, org, err)
		}
	})
	return id
}

// registerCleanupExec registers an error-visible cleanup for rows that the
// tenant CASCADE does not reap (global tables: vulnerabilities, audit_logs
// with tenant_id NULL, ...).
func registerCleanupExec(t *testing.T, db *sql.DB, what, query string, args ...any) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := db.Exec(query, args...); err != nil {
			t.Errorf("C27 cleanup %s: %v", what, err)
		}
	})
}

// countC27Tenants returns the number of marker rows, or -1 on error.
func countC27Tenants(db *sql.DB) int64 {
	var n int64
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM tenants WHERE clerk_org_id LIKE $1`,
		c27TenantOrgPrefix+"%",
	).Scan(&n); err != nil {
		return -1
	}
	return n
}

// TestMain is the leak gate: it counts marker tenants before and after the
// package's tests and fails the run when the count grew. Only active under
// -tags=integration (this file's build tag); the unit-test build keeps the
// default TestMain.
func TestMain(m *testing.M) {
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	var gateDB *sql.DB
	before := int64(-1)
	if url != "" {
		if db, err := sql.Open("postgres", url); err == nil {
			if db.Ping() == nil {
				gateDB = db
				before = countC27Tenants(db)
			} else {
				_ = db.Close()
			}
		}
	}
	code := m.Run()
	if gateDB != nil {
		after := countC27Tenants(gateDB)
		switch {
		case before < 0 || after < 0:
			fmt.Fprintf(os.Stderr,
				"C27 leak gate: tenant count query failed (before=%d after=%d) — gate inconclusive\n",
				before, after)
		case after > before:
			fmt.Fprintf(os.Stderr,
				"C27 LEAK GATE FAILED: %q tenants grew %d -> %d during this run — a test leaked rows\n",
				c27TenantOrgPrefix, before, after)
			if code == 0 {
				code = 1
			}
		case after > 0:
			fmt.Fprintf(os.Stderr,
				"C27 leak gate: no growth this run, but %d pre-existing %q rows remain (residue from older runs)\n",
				after, c27TenantOrgPrefix)
		}
		_ = gateDB.Close()
	}
	os.Exit(code)
}

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
