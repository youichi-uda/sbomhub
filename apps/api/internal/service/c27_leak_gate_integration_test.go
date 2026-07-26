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
//     c27Org(...) marker in clerk_org_id (package prefix + run id);
//     TestMain fails the run when rows carrying THIS run's id survive.
//   - Cleanup failures call t.Errorf on the owning test (loud, pinpointed)
//     instead of `_, _ =` (silent leak).
package service

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

// c27TenantOrgPrefix marks every tenant row created by this package's
// integration tests. Per-package prefixes keep concurrent `go test ./...`
// package binaries from tripping each other's gates.
const c27TenantOrgPrefix = "itest-svc-"

// c27RunID identifies THIS test-process run and is embedded in every marker
// clerk_org_id (see c27Org). The leak gate checks that rows carrying this
// run's id are gone after m.Run — a direct residue check that two
// concurrent runs of the same package cannot cancel out, unlike a bare
// before/after count diff (Codex M46 round A).
var c27RunID = uuid.NewString()

// c27Org builds the canonical marker clerk_org_id for a tenant seeded by
// this run: <package prefix><run id>-<label>. Every test-created tenant
// MUST route its clerk_org_id through this helper so the run-scoped gate
// can see it.
func c27Org(label string) string {
	return c27TenantOrgPrefix + c27RunID + "-" + label
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

// TestMain is the C27 leak gate. Integration builds only.
//
// Fail-closed contract (M46 Codex round A): when an integration URL IS
// configured, any failure to stand the gate up — open, ping, or a count
// query — fails the package run instead of silently disabling leak
// detection. The ONLY silent path is "no URL configured" (plain local
// dev), where every test skips itself and there is nothing to leak.
//
// Leak detection is two signals: (1) run-id residue — exact, primary;
// (2) marker growth — kept from the original gate, still spurious-trippable
// by concurrent runs of the same package (documented limitation) but it
// catches rows seeded with the prefix while bypassing c27Org.
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
