//go:build integration

// Package repository - subscriptions / subscription_events / usage_records
// tenant-isolation integration test (Trust Rescue P0 #18 follow-up /
// codex-r15).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -run TestSubscription ./internal/repository
//
// Prerequisites (skipped otherwise):
//   - docker compose up -d postgres   (or any postgres reachable via env)
//   - DATABASE_URL set to a sbomhub_app (NOBYPASSRLS) connection string
//   - MIGRATE_DATABASE_URL set to a sbomhub_migrator connection string
//   - Schema migrated through 031_subscriptions_remove_rls (the api
//     server's auto-migrate covers this; or run `go run ./cmd/migrate up`).
//
// What this test pins down:
//
//  1. The webhook lookup `SubscriptionRepository.GetByLSSubscriptionID`
//     that handler/webhook_lemonsqueezy.go runs OUTSIDE any TenantTx
//     (the route is mounted directly on the Echo instance) must succeed
//     under the sbomhub_app (NOBYPASSRLS) role with no
//     `app.current_tenant_id` GUC set. Before migration 031 the USING
//     policy from migration 008 reduced to NULL and Postgres returned
//     zero rows, so every subscription_updated / cancelled / resumed /
//     expired / paused / unpaused event reported "subscription not
//     found" and SaaS billing lifecycle was silently broken.
//
//  2. Likewise the `Create` / `CreateEvent` / `RecordUsage` INSERTs that
//     run on the webhook path (no tenant GUC) must succeed under the
//     same role. Before migration 031 the USING-only policy implicitly
//     gated WITH CHECK on the same predicate and silently rejected
//     every webhook-driven row.
//
//  3. With RLS off, tenant isolation lives entirely in the application
//     layer. The tenant-scoped reads (`GetByTenantID`, `GetEvents`,
//     `GetUsage`) and tenant-scoped mutations (`Update`, `UpdateStatus`,
//     `Delete`) MUST NOT touch another tenant's rows — these tests are
//     what stop a regression from re-enabling cross-tenant access via a
//     buggy caller that swaps TenantID on the model struct.
package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// subscriptionTestEnv mirrors auditTestEnv / apikeyTestEnv but is
// duplicated locally so this file is self-contained when read in
// isolation.
func subscriptionTestEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("subscriptions integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Run `docker compose up -d postgres` " +
			"and source .env.example values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// schemaReadySubscriptions checks that the three Lemon Squeezy tables
// exist AND that migration 031 has actually run — i.e. row-level
// security is disabled on all of them. If 031 hasn't been applied we
// want to skip with a loud message rather than fail in a confusing way
// (the bug we're guarding against would manifest as a SELECT that
// silently returns zero rows / an INSERT that silently fails, not as
// an obvious SQL error).
func schemaReadySubscriptions(t *testing.T, db *sql.DB) bool {
	t.Helper()
	tables := []string{"subscriptions", "subscription_events", "usage_records"}
	for _, name := range tables {
		var tableExists bool
		if err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)
		`, name).Scan(&tableExists); err != nil {
			t.Skipf("%s existence check failed: %v — skipping", name, err)
			return false
		}
		if !tableExists {
			t.Skipf("%s table not present — run migrations first", name)
			return false
		}

		var rlsEnabled, rlsForce bool
		if err := db.QueryRow(`
			SELECT relrowsecurity, relforcerowsecurity
			FROM pg_class
			WHERE oid = ('public.' || $1)::regclass
		`, name).Scan(&rlsEnabled, &rlsForce); err != nil {
			t.Skipf("%s RLS-state check failed: %v — skipping", name, err)
			return false
		}
		if rlsEnabled || rlsForce {
			t.Skipf("%s still has RLS enabled (rowsec=%v, force=%v) — "+
				"migration 031 has not been applied to this database; skipping",
				name, rlsEnabled, rlsForce)
			return false
		}
	}
	return true
}

// seedTenantForSubscription inserts a tenant row using the migrator role
// and returns its UUID. The tenants table has no RLS so this is
// straightforward.
func seedTenantForSubscription(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		id, "sub-test-"+label+"-"+id.String(),
		"Subscription Test "+label,
		"sub-test-"+label+"-"+id.String()[:8],
	); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

// TestSubscription_WebhookLookupSucceedsWithoutTenantContext is the core
// acceptance criterion for codex-r15: under the sbomhub_app (NOBYPASSRLS)
// role, with no `app.current_tenant_id` GUC set, the Lemon Squeezy
// webhook lookup (and the INSERT it precedes) MUST succeed. This is the
// scenario every handler in `handler/webhook_lemonsqueezy.go` runs.
//
// If migration 031 is ever reverted (or someone re-enables RLS on the
// three tables), this test fails — and that is exactly the regression
// that silently killed every subscription lifecycle event before this
// fix.
func TestSubscription_WebhookLookupSucceedsWithoutTenantContext(t *testing.T) {
	appURL, migURL := subscriptionTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadySubscriptions(t, migDB) {
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
	// the configuration that exposed the original webhook-lookup bug.
	var bypass bool
	if err := appDB.QueryRow(
		`SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&bypass); err != nil {
		t.Fatalf("query rolbypassrls: %v", err)
	}
	if bypass {
		t.Fatalf("app role has rolbypassrls=true; switch DATABASE_URL to sbomhub_app")
	}

	tenantID := seedTenantForSubscription(t, migDB, "webhook")
	t.Cleanup(func() {
		// ON DELETE CASCADE on the tenants FK reaps subscriptions,
		// subscription_events, and usage_records rows.
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	repo := NewSubscriptionRepository(appDB)
	ctx := context.Background()

	// Step 1: Webhook receives `subscription_created` → Create. Must
	// succeed even though the connection has no tenant GUC. Before
	// migration 031 the USING-only policy reused the predicate for
	// WITH CHECK and silently rejected this row.
	now := time.Now().UTC().Truncate(time.Microsecond)
	lsSubID := "ls-sub-" + uuid.NewString()
	sub := &model.Subscription{
		ID:               uuid.New(),
		TenantID:         tenantID,
		LSSubscriptionID: lsSubID,
		LSCustomerID:     "ls-cust-1",
		LSVariantID:      "ls-var-1",
		LSProductID:      "ls-prod-1",
		Status:           model.StatusActive,
		Plan:             model.PlanPro,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := repo.Create(ctx, sub); err != nil {
		t.Fatalf("Create under sbomhub_app with no tenant GUC failed: %v "+
			"— this is the codex-r15 regression; migration 031 likely missing", err)
	}

	// Step 2: A subsequent webhook (`subscription_updated`,
	// `subscription_cancelled`, …) calls GetByLSSubscriptionID FIRST,
	// also outside any tenant context. Before migration 031 this
	// returned sql.ErrNoRows even for the tenant's own subscription,
	// so every downstream branch reported "subscription not found".
	got, err := repo.GetByLSSubscriptionID(ctx, lsSubID)
	if err != nil {
		t.Fatalf("GetByLSSubscriptionID under sbomhub_app with no tenant GUC failed: %v "+
			"— this is the codex-r15 regression; webhook lifecycle is broken", err)
	}
	if got.ID != sub.ID {
		t.Fatalf("GetByLSSubscriptionID returned wrong row: got %s, want %s", got.ID, sub.ID)
	}
	if got.TenantID != tenantID {
		t.Fatalf("GetByLSSubscriptionID returned wrong tenant: got %s, want %s",
			got.TenantID, tenantID)
	}

	// Step 3: Webhook then calls Update / CreateEvent on the resolved
	// subscription. Both run without a tenant GUC.
	got.Status = model.StatusCancelled
	got.UpdatedAt = time.Now()
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update under sbomhub_app with no tenant GUC failed: %v", err)
	}

	if err := repo.CreateEvent(ctx, &model.SubscriptionEvent{
		ID:             uuid.New(),
		SubscriptionID: got.ID,
		TenantID:       tenantID,
		EventType:      "subscription_cancelled",
		PreviousStatus: model.StatusActive,
		NewStatus:      model.StatusCancelled,
		CreatedAt:      time.Now(),
	}); err != nil {
		t.Fatalf("CreateEvent under sbomhub_app with no tenant GUC failed: %v", err)
	}

	// Step 4: Usage records (metered billing) write path.
	if err := repo.RecordUsage(ctx, &model.UsageRecord{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Metric:      model.MetricProjects,
		Quantity:    1,
		PeriodStart: now,
		PeriodEnd:   now.Add(24 * time.Hour),
		CreatedAt:   now,
	}); err != nil {
		t.Fatalf("RecordUsage under sbomhub_app with no tenant GUC failed: %v", err)
	}
}

// TestSubscription_ApplicationLayerTenantIsolation pins down that, with
// RLS off (migration 031), the `WHERE tenant_id = $N` clauses in
// SubscriptionRepository do all the tenant-isolation work. Each tenant
// must only see its own rows; cross-tenant Update / UpdateStatus /
// Delete probes must not touch other tenants' rows even when the caller
// supplies a model struct whose TenantID has been swapped.
func TestSubscription_ApplicationLayerTenantIsolation(t *testing.T) {
	appURL, migURL := subscriptionTestEnv(t)

	migDB, err := sql.Open("postgres", migURL)
	if err != nil {
		t.Skipf("sql.Open(migURL) failed: %v — skipping", err)
	}
	defer migDB.Close()
	if err := migDB.Ping(); err != nil {
		t.Skipf("migDB unreachable: %v — skipping", err)
	}
	if !schemaReadySubscriptions(t, migDB) {
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

	tenantA := seedTenantForSubscription(t, migDB, "A")
	tenantB := seedTenantForSubscription(t, migDB, "B")
	t.Cleanup(func() {
		_, _ = migDB.Exec(`DELETE FROM tenants WHERE id IN ($1, $2)`, tenantA, tenantB)
	})

	repo := NewSubscriptionRepository(appDB)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	subA := &model.Subscription{
		ID:               uuid.New(),
		TenantID:         tenantA,
		LSSubscriptionID: "ls-A-" + uuid.NewString(),
		LSCustomerID:     "cust-A",
		LSVariantID:      "var-A",
		Status:           model.StatusActive,
		Plan:             model.PlanPro,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := repo.Create(ctx, subA); err != nil {
		t.Fatalf("Create subA: %v", err)
	}
	subB := &model.Subscription{
		ID:               uuid.New(),
		TenantID:         tenantB,
		LSSubscriptionID: "ls-B-" + uuid.NewString(),
		LSCustomerID:     "cust-B",
		LSVariantID:      "var-B",
		Status:           model.StatusActive,
		Plan:             model.PlanStarter,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := repo.Create(ctx, subB); err != nil {
		t.Fatalf("Create subB: %v", err)
	}

	// 1. GetByTenantID(A) must return subA, GetByTenantID(B) must return
	//    subB — neither must leak the other.
	gotA, err := repo.GetByTenantID(ctx, tenantA)
	if err != nil {
		t.Fatalf("GetByTenantID(A): %v", err)
	}
	if gotA.ID != subA.ID {
		t.Fatalf("GetByTenantID(A) returned wrong sub: got %s, want %s", gotA.ID, subA.ID)
	}
	gotB, err := repo.GetByTenantID(ctx, tenantB)
	if err != nil {
		t.Fatalf("GetByTenantID(B): %v", err)
	}
	if gotB.ID != subB.ID {
		t.Fatalf("GetByTenantID(B) returned wrong sub: got %s, want %s", gotB.ID, subB.ID)
	}

	// 2. A buggy caller that loads subA by LS-ID but then mutates the
	//    TenantID on the struct to tenantB MUST NOT be able to rewrite
	//    subA's billing state. This is what the `AND tenant_id = $N`
	//    guard on Update buys us once RLS is gone.
	probe := *subA
	probe.TenantID = tenantB // hostile or buggy reassignment
	probe.Status = model.StatusCancelled
	probe.Plan = model.PlanFree
	if err := repo.Update(ctx, &probe); err != nil {
		t.Fatalf("Update probe: %v (should be a no-op, not an error)", err)
	}

	stillA, err := repo.GetByTenantID(ctx, tenantA)
	if err != nil {
		t.Fatalf("GetByTenantID(A) after cross-tenant Update probe: %v", err)
	}
	if stillA.Status != model.StatusActive || stillA.Plan != model.PlanPro {
		t.Fatalf("cross-tenant Update probe leaked into tenantA: status=%s plan=%s "+
			"(expected active/pro) — the `AND tenant_id = $N` guard on Update is missing",
			stillA.Status, stillA.Plan)
	}

	// 3. UpdateStatus(tenantB, subA.ID, "cancelled") MUST NOT cancel
	//    tenantA's subscription. (Cross-tenant by-ID probe.)
	if err := repo.UpdateStatus(ctx, tenantB, subA.ID, model.StatusCancelled); err != nil {
		t.Fatalf("UpdateStatus cross-tenant probe: %v (should be a no-op, not an error)", err)
	}
	stillA2, err := repo.GetByTenantID(ctx, tenantA)
	if err != nil {
		t.Fatalf("GetByTenantID(A) after cross-tenant UpdateStatus probe: %v", err)
	}
	if stillA2.Status != model.StatusActive {
		t.Fatalf("cross-tenant UpdateStatus probe leaked into tenantA: status=%s "+
			"(expected active) — the `AND tenant_id = $N` guard on UpdateStatus is missing",
			stillA2.Status)
	}

	// 4. Delete(tenantB, subA.ID) MUST NOT delete tenantA's subscription.
	if err := repo.Delete(ctx, tenantB, subA.ID); err != nil {
		t.Fatalf("Delete cross-tenant probe: %v (should be a no-op, not an error)", err)
	}
	if _, err := repo.GetByTenantID(ctx, tenantA); err != nil {
		t.Fatalf("tenantA subscription disappeared after cross-tenant Delete probe: %v "+
			"— the `AND tenant_id = $N` guard on Delete is missing", err)
	}
}
