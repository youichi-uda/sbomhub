//go:build integration

// Package repository — issue_tracker_connections + vulnerability_tickets
// nullable-column scan regression tests.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'IssueTracker|VulnerabilityTickets_NullableColumnScan' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to
// go's test cache.
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 015+ (`go run ./cmd/migrate up`).
//
// What these tests pin down:
//
// The 015 schema leaves several columns of both integration tables
// nullable while the model scans them into plain string fields:
//
//   - issue_tracker_connections: auth_email, default_project_key,
//     default_issue_type (a GitHub PAT connection has no auth_email at
//     all).
//   - vulnerability_tickets: external_ticket_key, external_status,
//     priority, assignee, summary (plus external_project_key, already
//     COALESCEd since F366/051).
//
// A NULL in any of them used to abort the scan with
//
//	sql: Scan error on column index N, name "<col>":
//	converting NULL to string is unsupported
//
// which killed the offending read for the whole tenant: GetConnection ->
// SyncTicket (scheduler/ticket_sync.go), ListConnections /
// ListConnectionsByType, and — for vulnerability_tickets — GetTicketsToSync
// (the per-tenant sync loop) and ListTickets (the tickets API, a 500).
// NULL rows are reachable in practice: the application always writes ”
// (Create*/Update* bind the plain string fields directly), but rows seeded
// by operators / import SQL / support tooling omit the optional columns.
//
// The fix COALESCEs the nullable string columns to ” in every SELECT
// (same pattern as GetTicket's external_project_key, F366), keeping the
// model's plain-string "empty means absent" contract. The *time.Time
// columns (last_sync_at / last_synced_at) stay bare: NULL is
// representable and meaningful there.
//
// Both tables are FORCE RLS (023) with an 015 policy that calls
// current_setting('app.current_tenant_id') without missing_ok, so seeds
// run through withTenantGUC (migrator role) and repository reads run
// inside an app-role tx with the tenant GUC pinned via database.WithTx —
// the exact production shape (request middleware / runWithTenantTx). The
// schema-readiness guards assert that shape is real: RLS is still
// ENABLE + FORCE on the table and the app connection role is
// rolbypassrls=false, so a reverted RLS migration or a mis-provisioned
// (superuser) app role skips/fails loudly instead of silently
// mis-testing.
package repository

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// readAsTenantTx opens a tx on db, pins the tenant GUC, attaches the tx
// to ctx via database.WithTx (so repository q(ctx) routes through it),
// runs fn, then rolls back (reads only — nothing to commit).
func readAsTenantTx(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("readAsTenantTx begin tx (tenant=%s): %v", tenantID, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("readAsTenantTx SET LOCAL app.current_tenant_id=%s: %v", tenantID, err)
	}
	fn(database.WithTx(context.Background(), tx))
}

// schemaReadyNullScan skips when the table is missing (schema not
// migrated) but SKIPS loudly when the table exists without RLS in the
// 015/023 ENABLE + FORCE state — a NULL-scan test read through a
// non-RLS table (or a bypassing role, see assertAppRoleEnforcesRLS)
// would not be exercising the production path the fix protects.
func schemaReadyNullScan(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)
	`, table).Scan(&exists); err != nil {
		t.Skipf("%s existence check failed: %v -- skipping", table, err)
		return false
	}
	if !exists {
		t.Skipf("%s table not present -- run migrations first", table)
		return false
	}
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class WHERE oid = ('public.' || $1)::regclass
	`, table).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("%s RLS state check failed: %v -- skipping", table, err)
		return false
	}
	if !rlsEnabled || !rlsForce {
		t.Skipf("%s RLS not in expected ENABLE+FORCE state (enabled=%v, force=%v); "+
			"migration 023 may have been reverted -- skipping", table, rlsEnabled, rlsForce)
		return false
	}
	return true
}

// assertAppRoleEnforcesRLS fails when the reader connection's role can
// bypass RLS. The NULL-scan reads below only exercise the production
// path (app role, RLS-pinned by the tenant GUC) if the role actually
// obeys RLS; a superuser / rolbypassrls app connection would silently
// read across tenants and defeat the point of the tenant-scoped seeds.
func assertAppRoleEnforcesRLS(t *testing.T, appDB *sql.DB) {
	t.Helper()
	var role string
	var bypass bool
	if err := appDB.QueryRow(
		`SELECT current_user, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &bypass); err != nil {
		t.Fatalf("app-role rolbypassrls lookup failed: %v", err)
	}
	if bypass {
		t.Fatalf("app connection role %q has rolbypassrls=true; DATABASE_URL must point at a "+
			"NOBYPASSRLS runtime role (sbomhub_app) for the RLS-scoped reads to be meaningful", role)
	}
}

// TestIssueTrackerConnections_NullableColumnScan verifies against a real
// PostgreSQL that connection reads survive rows where every nullable
// column is NULL, and that fully-populated rows round-trip unchanged
// through every read path (pinning the List-side column order too).
func TestIssueTrackerConnections_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openOrSkipIssueTrackerCheck(t, migURL)
	// C27 cleanup-trap: register closes via t.Cleanup (not defer) so the
	// fixture-delete cleanup registered LATER runs FIRST (LIFO) — a
	// deferred Close would fire before t.Cleanup and leave the seed rows
	// resident against a closed *sql.DB.
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyNullScan(t, migDB, "issue_tracker_connections") {
		return
	}
	appDB := openOrSkipIssueTrackerCheck(t, appURL)
	t.Cleanup(func() { _ = appDB.Close() })
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedTenantForIssueTrackerCheck(t, migDB, "nullscan")
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps the connection rows.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
	})

	// --- Seed 1: GitHub-PAT-shaped row. auth_email, default_project_key,
	// default_issue_type, last_sync_at all omitted => NULL in the DB.
	nullConnID := uuid.New()
	withTenantGUC(t, migDB, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`
			INSERT INTO issue_tracker_connections (
				id, tenant_id, tracker_type, name, base_url, auth_token_encrypted
			) VALUES ($1, $2, 'github', 'nullscan-github', 'https://api.github.com', 'enc:nullscan-pat')
		`, nullConnID, tenant); err != nil {
			t.Fatalf("seed NULL-column connection: %v", err)
		}
	})

	// --- Seed 2: Jira-shaped row with every nullable column populated,
	// pinning that the fix does not disturb non-NULL values.
	jiraConnID := uuid.New()
	jiraSyncAt := time.Now().UTC().Truncate(time.Second)
	withTenantGUC(t, migDB, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`
			INSERT INTO issue_tracker_connections (
				id, tenant_id, tracker_type, name, base_url, auth_email,
				auth_token_encrypted, default_project_key, default_issue_type, last_sync_at
			) VALUES ($1, $2, 'jira', 'nullscan-jira', 'https://example.atlassian.net',
				'ops@example.com', 'enc:nullscan-jira-token', 'PROJ', 'Bug', $3)
		`, jiraConnID, tenant, jiraSyncAt); err != nil {
			t.Fatalf("seed populated connection: %v", err)
		}
	})

	repo := NewIssueTrackerRepository(appDB)

	assertNullRow := func(t *testing.T, conn *model.IssueTrackerConnection, via string) {
		t.Helper()
		if conn.AuthEmail != "" {
			t.Errorf("%s: AuthEmail = %q, want \"\" for NULL auth_email", via, conn.AuthEmail)
		}
		if conn.DefaultProjectKey != "" {
			t.Errorf("%s: DefaultProjectKey = %q, want \"\" for NULL default_project_key", via, conn.DefaultProjectKey)
		}
		if conn.DefaultIssueType != "" {
			t.Errorf("%s: DefaultIssueType = %q, want \"\" for NULL default_issue_type", via, conn.DefaultIssueType)
		}
		if conn.LastSyncAt != nil {
			t.Errorf("%s: LastSyncAt = %v, want nil for NULL last_sync_at", via, conn.LastSyncAt)
		}
	}
	// assertJiraRow pins the non-NULL round-trip AND, on the List paths,
	// the SELECT/Scan column order: a silent column-order regression
	// would surface here as a value landing in the wrong field.
	assertJiraRow := func(t *testing.T, conn *model.IssueTrackerConnection, via string) {
		t.Helper()
		if conn.AuthEmail != "ops@example.com" {
			t.Errorf("%s: AuthEmail = %q, want %q", via, conn.AuthEmail, "ops@example.com")
		}
		if conn.DefaultProjectKey != "PROJ" {
			t.Errorf("%s: DefaultProjectKey = %q, want %q", via, conn.DefaultProjectKey, "PROJ")
		}
		if conn.DefaultIssueType != "Bug" {
			t.Errorf("%s: DefaultIssueType = %q, want %q", via, conn.DefaultIssueType, "Bug")
		}
		if conn.LastSyncAt == nil || !conn.LastSyncAt.UTC().Equal(jiraSyncAt) {
			t.Errorf("%s: LastSyncAt = %v, want %v", via, conn.LastSyncAt, jiraSyncAt)
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- (a) GetConnection on the all-NULL row: this is the exact
		// statement scheduler/ticket_sync.go -> SyncTicket dies on.
		conn, err := repo.GetConnection(ctx, nullConnID)
		if err != nil {
			t.Fatalf("GetConnection on a row with NULL auth_email/default_project_key/"+
				"default_issue_type must not fail, got: %v", err)
		}
		if conn == nil {
			t.Fatalf("GetConnection returned nil for seeded connection %s", nullConnID)
		}
		assertNullRow(t, conn, "GetConnection(null)")

		// --- (b) GetConnection on the populated row: values unchanged.
		jconn, err := repo.GetConnection(ctx, jiraConnID)
		if err != nil {
			t.Fatalf("GetConnection (populated row): %v", err)
		}
		if jconn == nil {
			t.Fatalf("GetConnection returned nil for seeded connection %s", jiraConnID)
		}
		assertJiraRow(t, jconn, "GetConnection(jira)")

		// --- (c) ListConnections must return BOTH rows without a scan
		// error (one poisoned row used to abort the whole list), and
		// carry the Jira row's non-NULL values in the right fields.
		conns, err := repo.ListConnections(ctx, tenant)
		if err != nil {
			t.Fatalf("ListConnections with a NULL-column row in the tenant must not fail, got: %v", err)
		}
		if len(conns) != 2 {
			t.Fatalf("ListConnections returned %d rows, want 2", len(conns))
		}
		var sawNull, sawJira bool
		for i := range conns {
			switch conns[i].ID {
			case nullConnID:
				sawNull = true
				assertNullRow(t, &conns[i], "ListConnections(null)")
			case jiraConnID:
				sawJira = true
				assertJiraRow(t, &conns[i], "ListConnections(jira)")
			}
		}
		if !sawNull {
			t.Errorf("ListConnections did not return the NULL-column row %s", nullConnID)
		}
		if !sawJira {
			t.Errorf("ListConnections did not return the populated row %s", jiraConnID)
		}

		// --- (d) ListConnectionsByType(github): exactly the NULL row.
		byGitHub, err := repo.ListConnectionsByType(ctx, tenant, model.TrackerTypeGitHub)
		if err != nil {
			t.Fatalf("ListConnectionsByType(github) with a NULL-column row must not fail, got: %v", err)
		}
		if len(byGitHub) != 1 || byGitHub[0].ID != nullConnID {
			t.Fatalf("ListConnectionsByType(github) = %d rows (want exactly the seeded row %s)",
				len(byGitHub), nullConnID)
		}
		assertNullRow(t, &byGitHub[0], "ListConnectionsByType(github)")

		// --- (e) ListConnectionsByType(jira): exactly the populated row,
		// pinning the List-side column order for non-NULL values.
		byJira, err := repo.ListConnectionsByType(ctx, tenant, model.TrackerTypeJira)
		if err != nil {
			t.Fatalf("ListConnectionsByType(jira): %v", err)
		}
		if len(byJira) != 1 || byJira[0].ID != jiraConnID {
			t.Fatalf("ListConnectionsByType(jira) = %d rows (want exactly the seeded row %s)",
				len(byJira), jiraConnID)
		}
		assertJiraRow(t, &byJira[0], "ListConnectionsByType(jira)")
	})
}

// TestVulnerabilityTickets_NullableColumnScan verifies against a real
// PostgreSQL that ticket reads survive a row whose five nullable string
// columns (external_ticket_key, external_status, priority, assignee,
// summary) are all NULL, and that a fully-populated row round-trips
// unchanged. This is the regression guard for the COALESCE fix on
// GetTicket / GetTicketByVulnerability / ListTicketsByVulnerability /
// ListTickets / GetTicketsToSync.
func TestVulnerabilityTickets_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openOrSkipIssueTrackerCheck(t, migURL)
	t.Cleanup(func() { _ = migDB.Close() })
	if !schemaReadyNullScan(t, migDB, "vulnerability_tickets") {
		return
	}
	appDB := openOrSkipIssueTrackerCheck(t, appURL)
	t.Cleanup(func() { _ = appDB.Close() })
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedTenantForIssueTrackerCheck(t, migDB, "tkt-nullscan")
	vulnID := uuid.New()
	t.Cleanup(func() {
		// CASCADE FK on tenants reaps project / connection / ticket rows;
		// the global vulnerabilities row has no tenant CASCADE.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenant)
		_, _ = migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID)
	})

	// FK deps: a tenant-scoped project + connection(s), and a global
	// (RLS-exempt) vulnerability row.
	projectID := uuid.New()
	nullConnID := uuid.New()
	popConnID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'tkt-nullscan-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'HIGH')
	`, vulnID, "CVE-2026-NULLSCAN-"+tenant.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	// Two connections so both tickets satisfy UNIQUE(vulnerability_id,
	// connection_id) under the single seeded vulnerability.
	for _, c := range []struct {
		id   uuid.UUID
		name string
	}{{nullConnID, "tkt-nullscan-conn-null"}, {popConnID, "tkt-nullscan-conn-pop"}} {
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO issue_tracker_connections (
				id, tenant_id, tracker_type, name, base_url, auth_token_encrypted
			) VALUES ($1, $2, 'github', $3, 'https://api.github.com', 'enc:tkt-nullscan-token')
		`, c.id, tenant, c.name); err != nil {
			t.Fatalf("seed connection %s: %v", c.name, err)
		}
	}

	// --- Seed ticket 1: minimal insert. external_ticket_key,
	// external_status, priority, assignee, summary all omitted => NULL.
	// last_synced_at omitted too (=> NULL), keeping it eligible for
	// GetTicketsToSync. local_status defaults to 'open'.
	nullTicketID := uuid.New()
	withTenantGUC(t, migDB, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`
			INSERT INTO vulnerability_tickets (
				id, tenant_id, vulnerability_id, project_id, connection_id,
				external_ticket_id, external_ticket_url
			) VALUES ($1, $2, $3, $4, $5, '99',
				'https://github.com/octocat/hello-world/issues/99')
		`, nullTicketID, tenant, vulnID, projectID, nullConnID); err != nil {
			t.Fatalf("seed NULL-column ticket: %v", err)
		}
	})

	// --- Seed ticket 2: every nullable string column populated, and
	// last_synced_at set to now so it is NOT eligible for
	// GetTicketsToSync (isolating that assertion to the NULL ticket).
	popTicketID := uuid.New()
	popSyncedAt := time.Now().UTC().Truncate(time.Second)
	withTenantGUC(t, migDB, tenant, func(tx *sql.Tx) {
		if _, err := tx.Exec(`
			INSERT INTO vulnerability_tickets (
				id, tenant_id, vulnerability_id, project_id, connection_id,
				external_ticket_id, external_ticket_key, external_ticket_url,
				local_status, external_status, priority, assignee, summary,
				last_synced_at
			) VALUES ($1, $2, $3, $4, $5, '55', 'KEY-55',
				'https://github.com/octocat/hello-world/issues/55',
				'open', 'in_review', 'high', 'alice', 'populated summary', $6)
		`, popTicketID, tenant, vulnID, projectID, popConnID, popSyncedAt); err != nil {
			t.Fatalf("seed populated ticket: %v", err)
		}
	})

	repo := NewIssueTrackerRepository(appDB)

	assertNullTicket := func(t *testing.T, tk *model.VulnerabilityTicket, via string) {
		t.Helper()
		if tk.ExternalTicketKey != "" {
			t.Errorf("%s: ExternalTicketKey = %q, want \"\" for NULL", via, tk.ExternalTicketKey)
		}
		if tk.ExternalStatus != "" {
			t.Errorf("%s: ExternalStatus = %q, want \"\" for NULL", via, tk.ExternalStatus)
		}
		if tk.Priority != "" {
			t.Errorf("%s: Priority = %q, want \"\" for NULL", via, tk.Priority)
		}
		if tk.Assignee != "" {
			t.Errorf("%s: Assignee = %q, want \"\" for NULL", via, tk.Assignee)
		}
		if tk.Summary != "" {
			t.Errorf("%s: Summary = %q, want \"\" for NULL", via, tk.Summary)
		}
	}
	assertPopTicket := func(t *testing.T, tk *model.VulnerabilityTicket, via string) {
		t.Helper()
		if tk.ExternalTicketKey != "KEY-55" {
			t.Errorf("%s: ExternalTicketKey = %q, want %q", via, tk.ExternalTicketKey, "KEY-55")
		}
		if tk.ExternalStatus != "in_review" {
			t.Errorf("%s: ExternalStatus = %q, want %q", via, tk.ExternalStatus, "in_review")
		}
		if tk.Priority != "high" {
			t.Errorf("%s: Priority = %q, want %q", via, tk.Priority, "high")
		}
		if tk.Assignee != "alice" {
			t.Errorf("%s: Assignee = %q, want %q", via, tk.Assignee, "alice")
		}
		if tk.Summary != "populated summary" {
			t.Errorf("%s: Summary = %q, want %q", via, tk.Summary, "populated summary")
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- (a) GetTicket on the all-NULL row must not fail.
		tk, err := repo.GetTicket(ctx, nullTicketID)
		if err != nil {
			t.Fatalf("GetTicket on a row with NULL external_ticket_key/external_status/"+
				"priority/assignee/summary must not fail, got: %v", err)
		}
		if tk == nil {
			t.Fatalf("GetTicket returned nil for seeded ticket %s", nullTicketID)
		}
		assertNullTicket(t, tk, "GetTicket(null)")

		// --- (b) GetTicket on the populated row: values unchanged.
		ptk, err := repo.GetTicket(ctx, popTicketID)
		if err != nil {
			t.Fatalf("GetTicket (populated row): %v", err)
		}
		if ptk == nil {
			t.Fatalf("GetTicket returned nil for seeded ticket %s", popTicketID)
		}
		assertPopTicket(t, ptk, "GetTicket(pop)")

		// --- (c) GetTicketByVulnerability on the NULL row's connection.
		gtv, err := repo.GetTicketByVulnerability(ctx, vulnID, nullConnID)
		if err != nil {
			t.Fatalf("GetTicketByVulnerability with a NULL-column row must not fail, got: %v", err)
		}
		if gtv == nil || gtv.ID != nullTicketID {
			t.Fatalf("GetTicketByVulnerability returned %+v, want ticket %s", gtv, nullTicketID)
		}
		assertNullTicket(t, gtv, "GetTicketByVulnerability(null)")

		// --- (d) GetTicketsToSync: the NULL ticket (last_synced_at NULL,
		// local_status 'open', active connection) is eligible and must
		// scan clean. RLS scopes the query to this fresh tenant.
		toSync, err := repo.GetTicketsToSync(ctx, 15*time.Minute)
		if err != nil {
			t.Fatalf("GetTicketsToSync with a NULL-column row must not fail, got: %v", err)
		}
		var foundNull bool
		for i := range toSync {
			if toSync[i].ID == nullTicketID {
				foundNull = true
				assertNullTicket(t, &toSync[i], "GetTicketsToSync(null)")
			}
			if toSync[i].ID == popTicketID {
				t.Errorf("GetTicketsToSync returned the populated ticket %s whose "+
					"last_synced_at is recent; the olderThan filter should exclude it", popTicketID)
			}
		}
		if !foundNull {
			t.Errorf("GetTicketsToSync did not return the eligible NULL-column ticket %s", nullTicketID)
		}

		// --- (e) ListTickets: both rows, no scan error, correct column
		// order (the tickets API path — a NULL row used to 500 it).
		list, total, err := repo.ListTickets(ctx, tenant, "", 100, 0)
		if err != nil {
			t.Fatalf("ListTickets with a NULL-column row must not fail, got: %v", err)
		}
		if total != 2 {
			t.Errorf("ListTickets total = %d, want 2", total)
		}
		var listNull, listPop bool
		for i := range list {
			switch list[i].ID {
			case nullTicketID:
				listNull = true
				assertNullTicket(t, &list[i].VulnerabilityTicket, "ListTickets(null)")
			case popTicketID:
				listPop = true
				assertPopTicket(t, &list[i].VulnerabilityTicket, "ListTickets(pop)")
			}
		}
		if !listNull || !listPop {
			t.Errorf("ListTickets missing rows (null=%v pop=%v)", listNull, listPop)
		}

		// --- (f) ListTicketsByVulnerability: same property.
		byVuln, err := repo.ListTicketsByVulnerability(ctx, vulnID)
		if err != nil {
			t.Fatalf("ListTicketsByVulnerability with a NULL-column row must not fail, got: %v", err)
		}
		var bvNull bool
		for i := range byVuln {
			if byVuln[i].ID == nullTicketID {
				bvNull = true
				assertNullTicket(t, &byVuln[i].VulnerabilityTicket, "ListTicketsByVulnerability(null)")
			}
		}
		if !bvNull {
			t.Errorf("ListTicketsByVulnerability did not return the NULL-column ticket %s", nullTicketID)
		}
	})
}
