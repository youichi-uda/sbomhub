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
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// uuidHex returns the 32-hex (dash-free) form of id, for suffixing UNIQUE
// columns too narrow for the 36-char canonical form (e.g.
// vulnerabilities.cve_id VARCHAR(50)). Full 128-bit entropy — 8-hex
// truncations are only 32 bits and collide probabilistically (M46 Codex
// round A, Low).
func uuidHex(id uuid.UUID) string {
	return hex.EncodeToString(id[:])
}

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
//     test skips when a foreign default tenant pre-exists and otherwise
//     deletes only the row it created (by id) in its own cleanup.
//   - Non-tenant global rows (vulnerabilities CVE-M5-1-*, audit_logs with
//     tenant_id NULL) are reaped by their own error-visible cleanups but
//     not counted by this gate.
//   - Two concurrent `go test` invocations of the SAME package against the
//     same DB can still trip the GROWTH check spuriously; the run-id
//     residue check (primary signal, M46 round A) is exact per run.
// ---------------------------------------------------------------------------

// c27TenantOrgPrefix marks every tenant row created by this package's
// integration tests (clerk_org_id and slug prefix). Per-package prefixes:
// repository=itest-repo-, scheduler=itest-sched-, service=itest-svc-,
// middleware=itest-mw-.
const c27TenantOrgPrefix = "itest-repo-"

// c27RunID identifies THIS test-process run and is embedded in every marker
// clerk_org_id (see c27Org). The leak gate checks that rows carrying this
// run's id are gone after m.Run — a direct residue check that two
// concurrent runs of the same package cannot cancel out, unlike a bare
// before/after count diff (run A's "before" may include run B's live temp
// rows; if B cleans up while A leaks one row, the totals balance and a
// diff-only gate stays silent — Codex M46 round A).
var c27RunID = uuid.NewString()

// c27Org builds the canonical marker clerk_org_id for a tenant seeded by
// this run: <package prefix><run id>-<label>. Every test-created tenant
// MUST route its clerk_org_id through this helper so the run-scoped gate
// can see it.
func c27Org(label string) string {
	return c27TenantOrgPrefix + c27RunID + "-" + label
}

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
// The slug carries the FULL uuid: slug is UNIQUE and an 8-hex suffix is
// only 32 bits, which collides probabilistically across runs / residue
// (M46 Codex round A, Low).
func seedIntegrationTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	org := c27Org(label + "-" + id.String())
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, org, "itest "+label, c27TenantOrgPrefix+label+"-"+id.String(),
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

// countC27Tenants returns the number of marker rows (any run).
func countC27Tenants(db *sql.DB) (int64, error) {
	var n int64
	err := db.QueryRow(
		`SELECT COUNT(*) FROM tenants WHERE clerk_org_id LIKE $1`,
		c27TenantOrgPrefix+"%",
	).Scan(&n)
	return n, err
}

// listC27RunResidue returns the clerk_org_id of every tenants row created
// by THIS run (marker prefix + run id) that still exists.
func listC27RunResidue(db *sql.DB) ([]string, error) {
	rows, err := db.Query(
		`SELECT clerk_org_id FROM tenants WHERE clerk_org_id LIKE $1 ORDER BY clerk_org_id`,
		c27TenantOrgPrefix+c27RunID+"-%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []string
	for rows.Next() {
		var org string
		if err := rows.Scan(&org); err != nil {
			return nil, err
		}
		orgs = append(orgs, org)
	}
	return orgs, rows.Err()
}

// TestMain is the leak gate. Only active under -tags=integration (this
// file's build tag); the unit-test build keeps the default TestMain.
//
// Fail-closed contract (M46 Codex round A): when an integration URL IS
// configured, any failure to stand the gate up — open, ping, or a count
// query — fails the package run instead of silently disabling leak
// detection. The ONLY silent path is "no URL configured" (plain local
// dev), where every test skips itself and there is nothing to leak.
//
// Leak detection is two signals:
//  1. run-id residue (primary, exact): rows whose clerk_org_id carries
//     THIS run's c27RunID must all be gone after m.Run.
//  2. marker growth (secondary, kept from the original gate): total
//     marker rows must not grow. Concurrent runs of the same package can
//     still trip this one spuriously (documented limitation), but it
//     catches rows seeded with the prefix while bypassing c27Org.
func TestMain(m *testing.M) {
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		os.Exit(m.Run())
	}
	gateDB, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"C27 leak gate: sql.Open failed: %v — integration URL is set, failing closed\n", err)
		os.Exit(1)
	}
	if err := gateDB.Ping(); err != nil {
		fmt.Fprintf(os.Stderr,
			"C27 leak gate: integration DB unreachable: %v — failing closed "+
				"(unset DATABASE_URL/MIGRATE_DATABASE_URL to run without the integration DB)\n", err)
		os.Exit(1)
	}
	before, err := countC27Tenants(gateDB)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"C27 leak gate: pre-run marker count failed: %v — failing closed\n", err)
		os.Exit(1)
	}
	code := m.Run()
	residue, err := listC27RunResidue(gateDB)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"C27 leak gate: post-run residue query failed: %v — failing closed\n", err)
		os.Exit(1)
	}
	after, err := countC27Tenants(gateDB)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"C27 leak gate: post-run marker count failed: %v — failing closed\n", err)
		os.Exit(1)
	}
	if len(residue) > 0 {
		fmt.Fprintf(os.Stderr,
			"C27 LEAK GATE FAILED: %d tenant row(s) created by this run (run id %s) survived m.Run: %v\n",
			len(residue), c27RunID, residue)
		if code == 0 {
			code = 1
		}
	}
	switch {
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
