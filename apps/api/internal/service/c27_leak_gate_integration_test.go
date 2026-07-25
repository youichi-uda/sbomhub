//go:build integration

// Package service — C27 tenant-leak gate for integration tests (M46).
//
// See internal/repository/rls_test_helpers_integration_test.go for the full
// cleanup-trap rationale (defer Close vs t.Cleanup LIFO ordering) and the
// gate's documented limitations. Summary of the regime in this package:
//
//   - openOrSkipVS registers Close via t.Cleanup at open time, so
//     row-DELETE cleanups registered later always run against an open
//     handle. Never `defer db.Close()` a handle that cleanups depend on.
//   - Every tenant seeded by this package's fixtures carries the
//     c27TenantOrgPrefix marker in clerk_org_id (and slug); TestMain fails
//     the run when the number of marker rows grew.
//   - Cleanup failures call t.Errorf on the owning test (loud, pinpointed)
//     instead of `_, _ =` (silent leak).
package service

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// c27TenantOrgPrefix marks every tenant row created by this package's
// integration tests. Per-package prefixes keep concurrent `go test ./...`
// package binaries from tripping each other's gates.
const c27TenantOrgPrefix = "itest-svc-"

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

// TestMain is the C27 leak gate: fails the package run when the number of
// marker tenants grew during the run. Integration builds only.
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
