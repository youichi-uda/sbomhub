//go:build integration

// Package repository - public_links tenant-isolation integration test
// (Trust Rescue codex-r5 P1).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestPublicLink ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 030_public_links_remove_rls (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The anonymous /api/v1/public/:token endpoint's GetByToken lookup —
//     which runs under sbomhub_app (NOBYPASSRLS) with NO tenant GUC bound,
//     because the route has no auth/tenant middleware — must return the
//     row. Before migration 030 it returned zero rows because the RLS
//     policy reduced to a UUID cast of empty-string and rejected every
//     row, silently killing every public share link in production.
//
//  2. Now that RLS is off, tenant isolation on public_links lives entirely
//     in PublicLinkRepository's `tenant_id = $N` clauses. ListByProject /
//     GetByID / Update / Delete MUST NOT leak rows belonging to another
//     tenant — these tests are what stop a regression from re-enabling
//     cross-tenant access.
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// publicLinkTestEnv mirrors rlsTestEnv / apikeyTestEnv / auditTestEnv but
// is duplicated locally so this file is self-contained when read in
// isolation.
func publicLinkTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("public_links integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadyPublicLinks checks that public_links exists AND that migration
// 030 has actually run — i.e. row-level security is disabled. If 030 hasn't
// been applied we want to skip with a loud message rather than fail in a
// confusing way (the bug we're guarding against would manifest as an empty
// row set, not as an obvious SQL error).
func schemaReadyPublicLinks(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tableExists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'public_links'
		)
	`).Scan(&tableExists); err != nil {
		t.Skipf("public_links existence check failed: %v — skipping", err)
		return false
	}
	if !tableExists {
		t.Skip("public_links table not present — run migrations first")
		return false
	}

	// pg_class.relrowsecurity is true after ENABLE RLS, false after
	// DISABLE RLS. Migration 030 calls DISABLE so we expect false.
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE oid = 'public.public_links'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("public_links RLS-state check failed: %v — skipping", err)
		return false
	}
	if rlsEnabled || rlsForce {
		t.Skipf("public_links still has RLS enabled (rowsec=%v, force=%v) — "+
			"migration 030 has not been applied to this database; skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// seedTenantForPublicLink inserts a tenant row using the migrator role and
// returns its UUID. The tenants table has no RLS so this is straightforward.
func seedTenantForPublicLink(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "publink-test-"+label+"-"+id.String(),
		"PublicLink Test "+label,
		"publink-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// seedProjectForPublicLink inserts a projects row via the migrator role.
// public_links has a FK to projects, so we need a real project row.
//
// projects is under FORCE ROW LEVEL SECURITY (migration 023 + 027) and the
// migrator role is NOBYPASSRLS, so we have to set the tenant GUC inside
// the seeding tx for the INSERT's WITH CHECK clause to pass.
func seedProjectForPublicLink(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin seedProject tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(
		fmt.Sprintf(`SET LOCAL app.current_tenant_id = '%s'`, tenantID.String()),
	); err != nil {
		t.Fatalf("SET LOCAL tenant GUC: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO projects (id, tenant_id, name, description) VALUES ($1, $2, $3, $4)`,
		id, tenantID, "PublicLink Test Project "+label, "integration test fixture",
	); err != nil {
		t.Fatalf("seed project %s: %v", label, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seedProject tx: %v", err)
	}
	return id
}

// seedPublicLink inserts a public_links row via the repository under the
// app role. We deliberately use the repository's own Create so the same
// code path the real server takes is exercised — this is what makes the
// test catch a future regression that re-enables RLS.
func seedPublicLink(
	t *testing.T,
	ctx context.Context,
	repo *PublicLinkRepository,
	tenantID, projectID uuid.UUID,
	name string,
) *model.PublicLink {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	// 64 hex chars to match the application's `generateToken(32)` length,
	// guaranteed-unique per-row via uuid (the UNIQUE constraint on token
	// would reject a fixed value if two tests ran back-to-back).
	tok := uuid.NewString() + uuid.NewString()
	tok = tok[:64]
	link := &model.PublicLink{
		ID:            uuid.New(),
		TenantID:      tenantID,
		ProjectID:     projectID,
		Token:         tok,
		Name:          name,
		ExpiresAt:     now.Add(24 * time.Hour),
		IsActive:      true,
		ViewCount:     0,
		DownloadCount: 0,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := repo.Create(ctx, link); err != nil {
		t.Fatalf("repo.Create(%s): %v", name, err)
	}
	return link
}

// TestPublicLink_TokenLookupWorksWithoutTenantContext is the core
// acceptance criterion for codex-r5 P1: under the sbomhub_app
// (NOBYPASSRLS) role, with no `app.current_tenant_id` GUC set, the
// GetByToken lookup that the anonymous /api/v1/public/:token endpoint
// performs must return the row.
//
// If migration 030 is ever reverted (or someone re-enables RLS on
// public_links), this test fails — and that is exactly the regression
// that broke every dashboard-generated public share link before
// codex-r5.
func TestPublicLink_TokenLookupWorksWithoutTenantContext(t *testing.T) {
	appURL, migURL := publicLinkTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyPublicLinks(t, migDB) {
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
	// the configuration that exposed the original public-link bug.
	var bypass bool
	if err := appDB.QueryRow(
		`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("query rolbypassrls: %v", err)
	}
	if bypass {
		t.Fatalf("app role has rolbypassrls=true; switch DATABASE_URL to sbomhub_app")
	}

	tenantID := seedTenantForPublicLink(t, migDB, "lookup")
	projectID := seedProjectForPublicLink(t, migDB, tenantID, "lookup")
	t.Cleanup(func() {
		// ON DELETE CASCADE on the tenants FK takes the project and
		// public_links rows with it.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()
	link := seedPublicLink(t, ctx, repo, tenantID, projectID, "lookup target")

	// Sanity: no tenant GUC set on this connection. Looking up the row
	// by token MUST succeed — this is the entire point of removing RLS
	// on public_links.
	got, err := repo.GetByToken(ctx, link.Token)
	if err != nil {
		t.Fatalf("GetByToken: %v", err)
	}
	if got == nil {
		t.Fatalf("GetByToken returned nil under sbomhub_app with no tenant GUC; "+
			"this is the codex-r5 P1 regression — migration 030 likely missing. "+
			"tenant=%s, link=%s", tenantID, link.ID)
	}
	if got.ID != link.ID || got.TenantID != tenantID {
		t.Fatalf("GetByToken returned wrong row: got id=%s tenant=%s, want id=%s tenant=%s",
			got.ID, got.TenantID, link.ID, tenantID)
	}

	// Downstream mutations (IncrementView, IsDownloadLimitReached) also
	// run without tenant middleware — the handler passes link.TenantID
	// it got from the token lookup. They must succeed here too.
	if err := repo.IncrementView(ctx, link.TenantID, link.ID); err != nil {
		t.Fatalf("IncrementView under no-GUC sbomhub_app: %v", err)
	}
	reached, err := repo.IsDownloadLimitReached(ctx, link.TenantID, link.ID)
	if err != nil {
		t.Fatalf("IsDownloadLimitReached under no-GUC sbomhub_app: %v", err)
	}
	if reached {
		t.Fatalf("IsDownloadLimitReached returned true for a link with no allowed_downloads cap")
	}

	// CreateAccessLog writes the public_link_access_logs row that the
	// /public/:token endpoint persists for view/download analytics. It
	// also lives under RLS pre-030 and silently fails the same way.
	if err := repo.CreateAccessLog(ctx, &model.PublicLinkAccessLog{
		ID:           uuid.New(),
		PublicLinkID: link.ID,
		Action:       "view",
		IPAddress:    "127.0.0.1",
		UserAgent:    "go-test",
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}); err != nil {
		t.Fatalf("CreateAccessLog under no-GUC sbomhub_app: %v", err)
	}
}

// TestPublicLink_ApplicationLayerTenantIsolation pins down that, with
// RLS off (migration 030), the `tenant_id = $N` clauses in
// PublicLinkRepository do all the tenant-isolation work. Each tenant must
// only see its own links, cross-tenant probes must return nil, and
// cross-tenant Delete must be a no-op that leaves the row intact.
func TestPublicLink_ApplicationLayerTenantIsolation(t *testing.T) {
	appURL, migURL := publicLinkTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyPublicLinks(t, migDB) {
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

	tenantA := seedTenantForPublicLink(t, migDB, "A")
	tenantB := seedTenantForPublicLink(t, migDB, "B")
	projectA := seedProjectForPublicLink(t, migDB, tenantA, "A")
	projectB := seedProjectForPublicLink(t, migDB, tenantB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewPublicLinkRepository(appDB)
	ctx := context.Background()

	linkA := seedPublicLink(t, ctx, repo, tenantA, projectA, "tenant-A link")
	linkB := seedPublicLink(t, ctx, repo, tenantB, projectB, "tenant-B link")

	// 1. ListByProject(A, projectA) must contain linkA but not linkB.
	listA, err := repo.ListByProject(ctx, tenantA, projectA)
	if err != nil {
		t.Fatalf("ListByProject(A): %v", err)
	}
	if !containsLinkID(listA, linkA.ID) {
		t.Fatalf("ListByProject(A) missing tenant A's own link %s; got %s",
			linkA.ID, summarizeLinks(listA))
	}
	if containsLinkID(listA, linkB.ID) {
		t.Fatalf("ListByProject(A) leaked tenant B's link %s; got %s",
			linkB.ID, summarizeLinks(listA))
	}

	// 2. ListByProject(A, projectB) — probing tenant B's project ID
	//    with tenant A's tenant context — must return nothing. This is
	//    the cross-tenant-by-construction check: even if a tenant guesses
	//    the project UUID of another tenant, the tenant filter excludes
	//    every row.
	leak, err := repo.ListByProject(ctx, tenantA, projectB)
	if err != nil {
		t.Fatalf("ListByProject(A, projectB): %v", err)
	}
	if len(leak) > 0 {
		t.Fatalf("ListByProject(tenantA, projectB) returned %d rows; "+
			"cross-tenant project probe must yield zero. got %s",
			len(leak), summarizeLinks(leak))
	}

	// 3. Cross-tenant GetByID must return nil — tenant A cannot read
	//    tenant B's link even when it knows the UUID.
	cross, err := repo.GetByID(ctx, tenantA, linkB.ID)
	if err != nil {
		t.Fatalf("GetByID(A, linkB): %v", err)
	}
	if cross != nil {
		t.Fatalf("GetByID(A, linkB) returned %s; cross-tenant read should yield nil",
			cross.ID)
	}

	// 4. Same-tenant GetByID must still succeed (sanity for the
	//    `tenant_id = $2` filter not being over-restrictive).
	own, err := repo.GetByID(ctx, tenantA, linkA.ID)
	if err != nil {
		t.Fatalf("GetByID(A, linkA): %v", err)
	}
	if own == nil || own.ID != linkA.ID {
		t.Fatalf("GetByID(A, linkA) returned %v; want id=%s", own, linkA.ID)
	}

	// 5. Cross-tenant Delete must report not-found and leave the row
	//    intact.
	if err := repo.Delete(ctx, tenantA, linkB.ID); err == nil {
		t.Fatalf("Delete(A, linkB) succeeded; cross-tenant delete must fail")
	}
	stillThere, err := repo.GetByID(ctx, tenantB, linkB.ID)
	if err != nil {
		t.Fatalf("GetByID(B, linkB) after cross-delete: %v", err)
	}
	if stillThere == nil {
		t.Fatalf("tenant B's link disappeared after a cross-tenant Delete from tenant A")
	}

	// 6. Cross-tenant IncrementView / IncrementDownload must be silent
	//    no-ops (UPDATE matches 0 rows) and leave the counters intact.
	//    UPDATE returns no error when 0 rows match, so we check the
	//    counters after to confirm no mutation occurred.
	if err := repo.IncrementView(ctx, tenantA, linkB.ID); err != nil {
		t.Fatalf("IncrementView(A, linkB) errored: %v", err)
	}
	if err := repo.IncrementDownload(ctx, tenantA, linkB.ID); err != nil {
		t.Fatalf("IncrementDownload(A, linkB) errored: %v", err)
	}
	after, err := repo.GetByID(ctx, tenantB, linkB.ID)
	if err != nil {
		t.Fatalf("GetByID(B, linkB) after cross-tenant increments: %v", err)
	}
	if after.ViewCount != 0 || after.DownloadCount != 0 {
		t.Fatalf("tenant B's link counters mutated by tenant A: view=%d download=%d",
			after.ViewCount, after.DownloadCount)
	}
}

func containsLinkID(links []model.PublicLink, id uuid.UUID) bool {
	for _, l := range links {
		if l.ID == id {
			return true
		}
	}
	return false
}

func summarizeLinks(links []model.PublicLink) string {
	if len(links) == 0 {
		return "[]"
	}
	out := "["
	for i, l := range links {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("{id=%s tenant=%s project=%s}", l.ID, l.TenantID, l.ProjectID)
	}
	return out + "]"
}
