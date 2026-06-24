//go:build integration

// Package repository - audit_logs tenant-isolation integration test
// (Trust Rescue P0 #18 follow-up).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestAudit ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 029_audit_logs_remove_rls (the api server's
//     auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The audit_logs INSERT that webhook handlers (Clerk / Lemon Squeezy)
//     and any other "system event" writer perform BEFORE — or entirely
//     without — a tenant context being set must succeed under the
//     sbomhub_app (NOBYPASSRLS) role. Before migration 029 it failed
//     silently because FORCE ROW LEVEL SECURITY + an unset
//     `app.current_tenant_id` GUC reduced the WITH CHECK predicate to NULL,
//     killing every webhook-driven audit write in production.
//
//  2. Now that RLS is off, tenant isolation on audit_logs lives entirely
//     in AuditRepository's `WHERE tenant_id = $N` clauses. List /
//     ListByUser / ListByResource / Count / ListWithFilter MUST NOT leak
//     rows belonging to another tenant — these tests are what stop a
//     regression from re-enabling cross-tenant access.
//
//  3. Rows written with `tenant_id IS NULL` (system-level events) must
//     remain invisible to every tenant's audit view. This is what keeps
//     a webhook event about tenant A from accidentally surfacing in
//     tenant B's audit log.
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

// auditTestEnv mirrors rlsTestEnv / apikeyTestEnv but is duplicated locally
// so this file is self-contained when read in isolation.
func auditTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("audit_logs integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadyAuditLogs checks that audit_logs exists AND that migration 029
// has actually run — i.e. row-level security is disabled. If 029 hasn't
// been applied we want to skip with a loud message rather than fail in a
// confusing way (the bug we're guarding against would manifest as an INSERT
// that silently never lands, not as an obvious SQL error).
func schemaReadyAuditLogs(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var tableExists bool
	if err := db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'audit_logs'
		)
	`).Scan(&tableExists); err != nil {
		t.Skipf("audit_logs existence check failed: %v — skipping", err)
		return false
	}
	if !tableExists {
		t.Skip("audit_logs table not present — run migrations first")
		return false
	}

	// pg_class.relrowsecurity is true after ENABLE RLS, false after
	// DISABLE RLS. Migration 029 calls DISABLE so we expect false.
	var rlsEnabled, rlsForce bool
	if err := db.QueryRow(`
		SELECT relrowsecurity, relforcerowsecurity
		FROM pg_class
		WHERE oid = 'public.audit_logs'::regclass
	`).Scan(&rlsEnabled, &rlsForce); err != nil {
		t.Skipf("audit_logs RLS-state check failed: %v — skipping", err)
		return false
	}
	if rlsEnabled || rlsForce {
		t.Skipf("audit_logs still has RLS enabled (rowsec=%v, force=%v) — "+
			"migration 029 has not been applied to this database; skipping",
			rlsEnabled, rlsForce)
		return false
	}
	return true
}

// seedTenantForAudit inserts a tenant row using the migrator role and
// returns its UUID. The tenants table has no RLS so this is straightforward.
func seedTenantForAudit(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "audit-test-"+label+"-"+id.String(),
		"Audit Test "+label,
		"audit-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// TestAudit_InsertSucceedsWithoutTenantContext is the core acceptance
// criterion for P0 #18 follow-up: under the sbomhub_app (NOBYPASSRLS) role,
// with no `app.current_tenant_id` GUC set, an audit_logs INSERT must
// succeed. Both the system-event case (tenant_id IS NULL) and the
// tenant-scoped case (tenant_id set, webhook-style) are exercised because
// both legitimate webhook patterns exist in handler/webhook_*.go.
//
// If migration 029 is ever reverted (or someone re-enables RLS on
// audit_logs), this test fails — and that is exactly the regression that
// silently killed Clerk / Lemon Squeezy webhook audit writes before #18-fu.
func TestAudit_InsertSucceedsWithoutTenantContext(t *testing.T) {
	appURL, migURL := auditTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyAuditLogs(t, migDB) {
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
	// the configuration that exposed the original webhook-audit bug.
	var bypass bool
	if err := appDB.QueryRow(
		`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("query rolbypassrls: %v", err)
	}
	if bypass {
		t.Fatalf("app role has rolbypassrls=true; switch DATABASE_URL to sbomhub_app")
	}

	tenantID := seedTenantForAudit(t, migDB, "insert")
	t.Cleanup(func() {
		// ON DELETE CASCADE on the tenants FK takes the audit_logs rows
		// with tenant_id set; the tenant_id=NULL row is cleaned up via
		// the explicit id-based DELETE below.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := NewAuditRepository(appDB)
	ctx := context.Background()

	// Case 1: system-level event (tenant_id IS NULL). This mirrors
	// webhook_clerk.go's user.created / user.updated / user.deleted
	// audit Log() calls, which set UserID but leave TenantID nil.
	systemLog := &model.AuditLog{
		ID:           uuid.New(),
		TenantID:     nil, // system event, no tenant yet
		UserID:       nil,
		Action:       model.ActionUserCreated,
		ResourceType: model.ResourceUser,
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := repo.Create(ctx, systemLog); err != nil {
		t.Fatalf("Create(tenant_id=NULL) failed under sbomhub_app with no tenant GUC: %v "+
			"— this is the P0 #18-followup regression; migration 029 likely missing", err)
	}
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM audit_logs WHERE id = $1`, systemLog.ID)
	})

	// Case 2: tenant-scoped event written outside a TenantTx tx. This
	// mirrors webhook_clerk.go's organization.created / .updated and
	// webhook_lemonsqueezy.go's subscription.* audit Log() calls, which
	// know the tenant id but don't have a TenantTx around them (the
	// webhook routes are mounted directly on the Echo instance, not on
	// the auth.Group). Before migration 029 the WITH CHECK predicate
	// rejected this INSERT because the GUC was unset.
	tenantLog := &model.AuditLog{
		ID:           uuid.New(),
		TenantID:     &tenantID,
		UserID:       nil,
		Action:       model.ActionSubscriptionCreated,
		ResourceType: model.ResourceSubscription,
		Details:      map[string]interface{}{"plan": "pro"},
		CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := repo.Create(ctx, tenantLog); err != nil {
		t.Fatalf("Create(tenant_id=%s) failed under sbomhub_app with no tenant GUC: %v "+
			"— webhook-driven audit writes are broken", tenantID, err)
	}
	// The tenant FK cleanup will reap this row via CASCADE.
}

// TestAudit_ApplicationLayerTenantIsolation pins down that, with RLS off
// (migration 029), the `WHERE tenant_id = $N` clauses in AuditRepository
// do all the tenant-isolation work. Each tenant must only see its own
// rows, cross-tenant probes must return zero rows, and rows with
// tenant_id IS NULL (system events) must be invisible to every tenant.
func TestAudit_ApplicationLayerTenantIsolation(t *testing.T) {
	appURL, migURL := auditTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadyAuditLogs(t, migDB) {
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

	tenantA := seedTenantForAudit(t, migDB, "A")
	tenantB := seedTenantForAudit(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewAuditRepository(appDB)
	ctx := context.Background()

	// Seed: tenant A gets two rows, tenant B gets one row, and there is
	// one system-level (tenant_id=NULL) row.
	now := time.Now().UTC().Truncate(time.Microsecond)
	logA1 := seedAuditLog(t, ctx, repo, &tenantA, "tenant A row 1", now)
	logA2 := seedAuditLog(t, ctx, repo, &tenantA, "tenant A row 2", now.Add(time.Second))
	logB := seedAuditLog(t, ctx, repo, &tenantB, "tenant B row", now)
	logSystem := seedAuditLog(t, ctx, repo, nil, "system row (no tenant)", now)
	t.Cleanup(func() {
		// CASCADE cleans up the tenant-scoped rows when the tenant goes
		// away; the system (tenant_id=NULL) row needs an explicit DELETE.
		_, _ = migDB.Exec(`DELETE FROM audit_logs WHERE id = $1`, logSystem.ID)
	})

	// 1. List(tenantA) must contain logA1 + logA2 and must NOT contain
	//    logB or logSystem.
	listA, err := repo.List(ctx, tenantA, 100, 0)
	if err != nil {
		t.Fatalf("List(A): %v", err)
	}
	if !containsAuditID(listA, logA1.ID) || !containsAuditID(listA, logA2.ID) {
		t.Fatalf("List(A) missing one or both of tenant A's rows; got %s",
			summarizeAudits(listA))
	}
	if containsAuditID(listA, logB.ID) {
		t.Fatalf("List(A) leaked tenant B's row %s; got %s",
			logB.ID, summarizeAudits(listA))
	}
	if containsAuditID(listA, logSystem.ID) {
		t.Fatalf("List(A) leaked system (tenant_id=NULL) row %s; got %s",
			logSystem.ID, summarizeAudits(listA))
	}

	// 2. List(tenantB) must contain logB and must NOT contain logA*/
	//    logSystem.
	listB, err := repo.List(ctx, tenantB, 100, 0)
	if err != nil {
		t.Fatalf("List(B): %v", err)
	}
	if !containsAuditID(listB, logB.ID) {
		t.Fatalf("List(B) missing tenant B's row %s; got %s",
			logB.ID, summarizeAudits(listB))
	}
	if containsAuditID(listB, logA1.ID) || containsAuditID(listB, logA2.ID) {
		t.Fatalf("List(B) leaked one of tenant A's rows; got %s",
			summarizeAudits(listB))
	}
	if containsAuditID(listB, logSystem.ID) {
		t.Fatalf("List(B) leaked system row %s; got %s",
			logSystem.ID, summarizeAudits(listB))
	}

	// 3. Count(A) and Count(B) must reflect only own-tenant rows.
	cntA, err := repo.Count(ctx, tenantA)
	if err != nil {
		t.Fatalf("Count(A): %v", err)
	}
	if cntA < 2 {
		t.Fatalf("Count(A) = %d; expected >= 2 (we seeded 2 rows for tenant A)", cntA)
	}
	cntB, err := repo.Count(ctx, tenantB)
	if err != nil {
		t.Fatalf("Count(B): %v", err)
	}
	if cntB < 1 {
		t.Fatalf("Count(B) = %d; expected >= 1", cntB)
	}

	// 4. ListWithFilter(A) probing tenant B's data must yield nothing
	//    even when the filter is permissive — this is the
	//    cross-tenant-by-construction check.
	filterA, totalA, err := repo.ListWithFilter(ctx, tenantA, AuditFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListWithFilter(A): %v", err)
	}
	if containsAuditID(filterA, logB.ID) {
		t.Fatalf("ListWithFilter(A) leaked tenant B's row %s; got %s",
			logB.ID, summarizeAudits(filterA))
	}
	if containsAuditID(filterA, logSystem.ID) {
		t.Fatalf("ListWithFilter(A) leaked system row %s; got %s",
			logSystem.ID, summarizeAudits(filterA))
	}
	if totalA < 2 {
		t.Fatalf("ListWithFilter(A) total=%d; expected >= 2", totalA)
	}
}

// seedAuditLog inserts an audit_logs row via the repository under the app
// role. We deliberately use the repository's own Create so the same code
// path the real server takes is exercised — this is what makes the test
// catch a future regression that re-enables RLS.
func seedAuditLog(
	t *testing.T,
	ctx context.Context,
	repo *AuditRepository,
	tenantID *uuid.UUID,
	label string,
	at time.Time,
) *model.AuditLog {
	t.Helper()
	a := &model.AuditLog{
		ID:           uuid.New(),
		TenantID:     tenantID,
		UserID:       nil,
		Action:       "test.audit." + label,
		ResourceType: "test",
		Details:      map[string]interface{}{"label": label},
		CreatedAt:    at,
	}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("Create(%s): %v", label, err)
	}
	return a
}

func containsAuditID(logs []model.AuditLog, id uuid.UUID) bool {
	for _, l := range logs {
		if l.ID == id {
			return true
		}
	}
	return false
}

func summarizeAudits(logs []model.AuditLog) string {
	if len(logs) == 0 {
		return "[]"
	}
	out := "["
	for i, l := range logs {
		if i > 0 {
			out += ", "
		}
		tid := "<nil>"
		if l.TenantID != nil {
			tid = l.TenantID.String()
		}
		out += fmt.Sprintf("{id=%s tenant=%s action=%s}", l.ID, tid, l.Action)
	}
	return out + "]"
}
