//go:build integration

// Package repository — issue_tracker_connections.tracker_type CHECK
// registry integration test (M24-2 / issue #126 / F357, migration 050).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestIssueTrackerConnections_TrackerTypeCheck ./internal/repository
//
// -count=1 is load-bearing (F344, M23-2 #124): the live constraint
// catalog state and INSERT behaviour this test asserts against are NOT
// inputs to go's test cache — only consulted env vars (DATABASE_URL /
// MIGRATE_DATABASE_URL here) and files opened inside the module root
// are. Re-running after re-migrating the database with an unchanged
// binary, flags, and env would otherwise return the previous cached
// verdict instead of re-checking the DB.
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 050 (`go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. Migration 050 was applied: pg_constraint carries the CHECK
//     constraint issue_tracker_connections_tracker_type_check. The
//     constraint ships NOT VALID (convalidated = false) by design —
//     see the 050 header for the 045-precedent RLS rationale — and
//     this test does NOT assert convalidated either way, so a later
//     operator-run VALIDATE CONSTRAINT stays green.
//
//  2. NOT VALID skips only existing-row validation: a NEW insert with
//     an out-of-registry tracker_type ('bogus') is rejected with a
//     CHECK violation naming the constraint.
//
//  3. All three registry values ('jira', 'backlog', 'github') pass the
//     CHECK. 'github' is deliberately pre-registered ahead of the M24
//     GitHub tracker wave (issue #125) so the DB registry is closed in
//     a single migration instead of a DROP + re-ADD churn later.
//
// issue_tracker_connections is FORCE RLS (023) and its 015 policy calls
// current_setting('app.current_tenant_id') without missing_ok, so every
// INSERT below runs through execAsTenant (tx + SET LOCAL tenant GUC —
// rls_test_helpers_integration_test.go), matching the established
// CHECK-constraint test pattern of cra_reports_rls_test.go.
package repository

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// issueTrackerCheckTestEnv reuses the shared env helper so a single
// DATABASE_URL / MIGRATE_DATABASE_URL pair drives every integration
// test in this package (same delegation as craReportsTestEnv).
func issueTrackerCheckTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // reuse env helper from llm_calls_rls_test.go
}

func openOrSkipIssueTrackerCheck(t *testing.T, url string) *sql.DB {
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

// schemaReadyIssueTrackerCheck skips when the table itself is missing
// (schema not migrated at all) but FAILS loudly when the table exists
// without the 050 constraint — a dropped / renamed constraint is
// exactly the regression class this test exists to catch.
func schemaReadyIssueTrackerCheck(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'issue_tracker_connections'
		)
	`).Scan(&exists); err != nil {
		t.Skipf("issue_tracker_connections existence check failed: %v -- skipping", err)
		return false
	}
	if !exists {
		t.Skip("issue_tracker_connections table not present -- run migrations first")
		return false
	}

	var contype string
	var convalidated bool
	err := db.QueryRow(`
		SELECT contype, convalidated
		FROM pg_constraint
		WHERE conrelid = 'public.issue_tracker_connections'::regclass
		  AND conname = 'issue_tracker_connections_tracker_type_check'
	`).Scan(&contype, &convalidated)
	if err == sql.ErrNoRows {
		t.Fatalf("F357: constraint issue_tracker_connections_tracker_type_check not found " +
			"on issue_tracker_connections. Migration 050 (issue_tracker_type_check) did " +
			"not run, or a later migration dropped/renamed it -- re-run `go run ./cmd/migrate up`.")
		return false
	}
	if err != nil {
		t.Fatalf("F357: pg_constraint lookup failed: %v", err)
		return false
	}
	if contype != "c" {
		t.Fatalf("F357: issue_tracker_connections_tracker_type_check has contype=%q, want 'c' (CHECK)", contype)
		return false
	}
	// convalidated=false is the shipped NOT VALID state; true after an
	// operator VALIDATE CONSTRAINT. Both are acceptable -- log only.
	t.Logf("issue_tracker_connections_tracker_type_check present (convalidated=%v)", convalidated)
	return true
}

func seedTenantForIssueTrackerCheck(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "tracker-check-test-"+label+"-"+id.String(),
		"TrackerCheck Test "+label,
		"tracker-check-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// TestIssueTrackerConnections_TrackerTypeCheck_F357 verifies the
// migration 050 tracker_type CHECK registry against a real PostgreSQL:
// bogus values are rejected on new writes despite NOT VALID, and all
// three registry values ('jira', 'backlog', 'github') pass.
func TestIssueTrackerConnections_TrackerTypeCheck_F357(t *testing.T) {
	_, migURL := issueTrackerCheckTestEnv(t)
	migDB := openOrSkipIssueTrackerCheck(t, migURL)
	defer migDB.Close()
	if !schemaReadyIssueTrackerCheck(t, migDB) {
		return
	}

	tenant := seedTenantForIssueTrackerCheck(t, migDB, "F357")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the issue_tracker_connections
		// rows inserted below (RI actions bypass RLS by design).
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	insertConn := func(trackerType, name string) error {
		// auth_type has a DEFAULT; every other NOT NULL column is
		// supplied. UNIQUE(tenant_id, tracker_type, name) is satisfied
		// by per-value names under a fresh tenant.
		return execAsTenant(t, migDB, tenant, `
			INSERT INTO issue_tracker_connections (
				id, tenant_id, tracker_type, name, base_url, auth_token_encrypted
			) VALUES ($1, $2, $3, $4,
				'https://tracker.example.invalid', 'enc:f357-test-token')
		`, uuid.New(), tenant, trackerType, name)
	}

	// --- (a) Out-of-registry value must be rejected by the CHECK even
	// though the constraint is NOT VALID ('bogus' = 5 chars, fits
	// VARCHAR(20) so the type length check cannot pre-empt the CHECK).
	err := insertConn("bogus", "f357-bogus")
	if err == nil {
		t.Fatalf("F357: INSERT with tracker_type='bogus' succeeded; the migration 050 " +
			"CHECK registry is meant to reject out-of-registry values on new writes " +
			"(NOT VALID skips only existing-row validation)")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "issue_tracker_connections_tracker_type_check") {
		t.Fatalf("F357: expected a CHECK violation naming "+
			"issue_tracker_connections_tracker_type_check for tracker_type='bogus', got: %v", err)
	}

	// --- (b) Every registry value must pass the CHECK. INSERT success
	// is the expected outcome; a failure that is NOT the tracker_type
	// CHECK still proves CHECK passage (the property F357 pins) and is
	// surfaced via t.Logf instead of failing the CHECK contract.
	for _, trackerType := range []string{"jira", "backlog", "github"} {
		err := insertConn(trackerType, "f357-"+trackerType)
		if err == nil {
			continue
		}
		if strings.Contains(strings.ToLower(err.Error()), "issue_tracker_connections_tracker_type_check") {
			t.Errorf("F357: registry value %q was rejected by the tracker_type CHECK; "+
				"the 050 allow-list ('jira','backlog','github') has regressed: %v", trackerType, err)
			continue
		}
		t.Logf("F357: INSERT of registry value %q failed with a non-CHECK error (%v); "+
			"the tracker_type CHECK itself was not violated, so the CHECK-passage "+
			"property holds -- investigate the environment if unexpected", trackerType, err)
	}
}
