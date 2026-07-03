//go:build integration

// Package repository — vulnerability_tickets.external_project_key column
// integration test (M25-A / issue #128 / F366, migration 051).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestVulnerabilityTickets_ExternalProjectKey ./internal/repository
//
// -count=1 is load-bearing (F344, M23-2 #124): the live schema state this
// test asserts against is NOT an input to go's test cache — only consulted
// env vars (DATABASE_URL / MIGRATE_DATABASE_URL) and files opened inside the
// module root are. Re-running after re-migrating the database with an
// unchanged binary, flags, and env would otherwise return the previous
// cached verdict instead of re-checking the DB.
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 051 (`go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. Migration 051 was applied: vulnerability_tickets carries
//     external_project_key as a nullable VARCHAR(200) with no default and,
//     critically, existing rows were NOT backfilled (the 051 header records
//     why a migrator whole-table UPDATE under FORCE RLS + the missing_ok-less
//     015 policy is a hazard).
//
//  2. The full F366 INSERT shape lands: a ticket row INSERTed with the
//     column list repository.CreateTicket uses (external_project_key
//     included) succeeds against the real schema — the sqlmock unit tests
//     cannot catch a column-list/schema drift (anti-pattern 21).
//
//  3. The legacy shape still lands: an INSERT omitting external_project_key
//     succeeds and stores SQL NULL, and the COALESCE(external_project_key,
//     ”) read that repository.GetTicket uses maps that NULL to ” — the
//     service-side "legacy row, fall back to the URL-derived repository"
//     sentinel.
//
// vulnerability_tickets is FORCE RLS (023) and its 015 policy calls
// current_setting('app.current_tenant_id') without missing_ok, so every
// INSERT below runs through execAsTenant / withTenantGUC (tx + SET LOCAL
// tenant GUC — rls_test_helpers_integration_test.go), the established
// pattern of issue_tracker_check_integration_test.go.
package repository

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func ticketProjectKeyTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	return llmCallsTestEnv(t) // shared env helper (llm_calls_rls_test.go)
}

func openOrSkipTicketProjectKey(t *testing.T, url string) *sql.DB {
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

// schemaReadyTicketProjectKey skips when the table itself is missing (schema
// not migrated at all) but FAILS loudly when the table exists without the
// 051 column, or with a column whose shape drifted from the 051 contract —
// a dropped / retyped / defaulted column is exactly the regression class
// this test exists to catch.
func schemaReadyTicketProjectKey(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tableExists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'vulnerability_tickets'
		)
	`).Scan(&tableExists); err != nil {
		t.Skipf("vulnerability_tickets existence check failed: %v -- skipping", err)
		return false
	}
	if !tableExists {
		t.Skip("vulnerability_tickets table not present -- run migrations first")
		return false
	}

	var dataType, isNullable string
	var maxLen sql.NullInt64
	var colDefault sql.NullString
	err := db.QueryRow(`
		SELECT data_type, is_nullable, character_maximum_length, column_default
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'vulnerability_tickets'
		  AND column_name = 'external_project_key'
	`).Scan(&dataType, &isNullable, &maxLen, &colDefault)
	if err == sql.ErrNoRows {
		t.Fatalf("F366: column vulnerability_tickets.external_project_key not found. " +
			"Migration 051 (ticket_external_project_key) did not run, or a later " +
			"migration dropped/renamed it -- re-run `go run ./cmd/migrate up`.")
		return false
	}
	if err != nil {
		t.Fatalf("F366: information_schema.columns lookup failed: %v", err)
		return false
	}
	if dataType != "character varying" || !maxLen.Valid || maxLen.Int64 != 200 {
		t.Fatalf("F366: external_project_key is %s(%v), want character varying(200) per migration 051", dataType, maxLen)
	}
	if isNullable != "YES" {
		t.Fatalf("F366: external_project_key is_nullable=%q, want YES — legacy pre-051 rows are deliberately NULL (no backfill)", isNullable)
	}
	if colDefault.Valid {
		t.Fatalf("F366: external_project_key has default %q, want none per migration 051", colDefault.String)
	}
	return true
}

// TestVulnerabilityTickets_ExternalProjectKey_F366 verifies the migration
// 051 column against a real PostgreSQL: the CreateTicket INSERT shape
// (external_project_key included) succeeds, the legacy shape (column
// omitted) stores NULL, and the GetTicket COALESCE maps that NULL to ”.
func TestVulnerabilityTickets_ExternalProjectKey_F366(t *testing.T) {
	_, migURL := ticketProjectKeyTestEnv(t)
	migDB := openOrSkipTicketProjectKey(t, migURL)
	defer migDB.Close()
	if !schemaReadyTicketProjectKey(t, migDB) {
		return
	}

	tenant := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		tenant, "ticket-repo-test-"+tenant.String(),
		"TicketRepo Test F366",
		"ticket-repo-test-"+tenant.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	vulnID := uuid.New()
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the project / connection / ticket
		// rows (RI actions bypass RLS by design); the global
		// vulnerabilities row has no tenant CASCADE and is reaped
		// explicitly.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID)
	})

	projectID := uuid.New()
	connID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'ticket-repo-test-f366')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// vulnerabilities is a global (RLS-exempt) table — plain insert.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'HIGH')
	`, vulnID, "CVE-2026-F366-"+tenant.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO issue_tracker_connections (
			id, tenant_id, tracker_type, name, base_url, auth_token_encrypted,
			default_project_key
		) VALUES ($1, $2, 'github', 'f366-conn',
			'https://api.github.com', 'enc:f366-test-token', 'octocat/hello-world')
	`, connID, tenant); err != nil {
		t.Fatalf("seed issue_tracker_connections: %v", err)
	}

	// --- (a) F366 INSERT shape: the exact column list CreateTicket uses,
	// with a per-ticket override repository persisted.
	overrideTicket := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vulnerability_tickets (
			id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			external_project_key,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, '42', '42',
			'https://github.com/octocat/other-repo/issues/42',
			'octocat/other-repo',
			'open', 'open', '', '', 'f366 override ticket', NOW(), NOW(), NOW())
	`, overrideTicket, tenant, vulnID, projectID, connID); err != nil {
		t.Fatalf("F366: INSERT with external_project_key failed against the real 051 schema: %v", err)
	}

	// --- (b) Legacy INSERT shape: column omitted -> SQL NULL (the pre-051
	// application column list). A second connection avoids the
	// UNIQUE(vulnerability_id, connection_id) collision.
	legacyConn := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO issue_tracker_connections (
			id, tenant_id, tracker_type, name, base_url, auth_token_encrypted,
			default_project_key
		) VALUES ($1, $2, 'github', 'f366-conn-legacy',
			'https://api.github.com', 'enc:f366-test-token', 'octocat/hello-world')
	`, legacyConn, tenant); err != nil {
		t.Fatalf("seed legacy issue_tracker_connections: %v", err)
	}
	legacyTicket := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vulnerability_tickets (
			id, tenant_id, vulnerability_id, project_id, connection_id,
			external_ticket_id, external_ticket_key, external_ticket_url,
			local_status, external_status, priority, assignee, summary,
			last_synced_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, '7', '7',
			'https://github.com/octocat/hello-world/issues/7',
			'open', 'open', '', '', 'f366 legacy ticket', NOW(), NOW(), NOW())
	`, legacyTicket, tenant, vulnID, projectID, legacyConn); err != nil {
		t.Fatalf("F366: legacy-shape INSERT (external_project_key omitted) failed: %v", err)
	}

	// --- (c) Read-back within the tenant GUC: raw NULL vs stored value, and
	// the GetTicket COALESCE contract.
	withTenantGUC(t, migDB, tenant, func(tx *sql.Tx) {
		var rawOverride sql.NullString
		var coalescedOverride string
		if err := tx.QueryRow(`
			SELECT external_project_key, COALESCE(external_project_key, '')
			FROM vulnerability_tickets WHERE id = $1
		`, overrideTicket).Scan(&rawOverride, &coalescedOverride); err != nil {
			t.Fatalf("read back override ticket: %v", err)
		}
		if !rawOverride.Valid || rawOverride.String != "octocat/other-repo" {
			t.Errorf("override ticket external_project_key = %+v, want 'octocat/other-repo'", rawOverride)
		}
		if coalescedOverride != "octocat/other-repo" {
			t.Errorf("override ticket COALESCE read = %q, want 'octocat/other-repo'", coalescedOverride)
		}

		var rawLegacy sql.NullString
		var coalescedLegacy string
		if err := tx.QueryRow(`
			SELECT external_project_key, COALESCE(external_project_key, '')
			FROM vulnerability_tickets WHERE id = $1
		`, legacyTicket).Scan(&rawLegacy, &coalescedLegacy); err != nil {
			t.Fatalf("read back legacy ticket: %v", err)
		}
		if rawLegacy.Valid {
			t.Errorf("legacy ticket external_project_key = %q, want SQL NULL (051 does not backfill and the column has no default)", rawLegacy.String)
		}
		if coalescedLegacy != "" {
			t.Errorf("legacy ticket COALESCE read = %q, want '' (the URL-fallback sentinel GetTicket hands the service)", coalescedLegacy)
		}
	})
}
