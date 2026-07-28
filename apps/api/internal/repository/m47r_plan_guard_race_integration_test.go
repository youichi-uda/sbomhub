//go:build integration

// Package repository — M47R (Codex round 1, High): the `/plan/select-free`
// guard could still be beaten by a concurrent billing write.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47RPlanGuard' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # The anomaly
//
// `UpdatePlanUnlessSubscriptionLive` is one conditional UPDATE:
//
//	UPDATE tenants SET plan = $1 WHERE id = $2
//	  AND NOT EXISTS (SELECT 1 FROM subscriptions s
//	                  WHERE s.tenant_id = $2 AND s.status <> $3)
//
// W3 measured, and documented, that this is beaten by a concurrent
// subscription INSERT that has not committed yet: READ COMMITTED cannot see
// another transaction's uncommitted row, so the subquery finds nothing, the
// statement then BLOCKS on the tenants row the other transaction is holding,
// and when it is released Postgres re-checks the target row but NOT the
// subquery — which was evaluated against the older snapshot. Result:
// `tenants.plan = "free"` beside `subscriptions.status = "active"`. A paying
// tenant loses the entitlement it just bought.
//
// M47R made this MORE reachable rather than less: the Lemon Squeezy webhook
// used to write in autocommit, so the exposed window was one INSERT
// statement; it now runs the whole delivery in a transaction, so the window is
// the whole delivery.
//
// # The fix
//
// Take the tenant row lock FIRST, in its own statement. Blocking there means
// the guarded UPDATE that follows is a NEW statement with a NEW snapshot,
// which does see the now-committed subscription — so the guard fires. Lock
// ordering is safe: this path locks only `tenants`, while the webhook and
// /subscription/sync both take `subscriptions` first and `tenants` second, so
// there is no cycle to deadlock on.
//
// C27: `tenants` CASCADE reaps the seeded subscriptions rows.
package repository

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// m47rSeedTenant goes through seedIntegrationTenant so the row carries the
// package's C27 marker prefix and is visible to the leak gate, then sets the
// starting plan (which seedIntegrationTenant leaves at its column default).
func m47rSeedTenant(t *testing.T, migDB *sql.DB, plan string) uuid.UUID {
	t.Helper()
	id := seedIntegrationTenant(t, migDB, "m47r-planguard")
	if _, err := migDB.Exec(`UPDATE tenants SET plan = $1 WHERE id = $2`, plan, id); err != nil {
		t.Fatalf("set starting plan: %v", err)
	}
	return id
}

func m47rTenantPlan(t *testing.T, migDB *sql.DB, id uuid.UUID) string {
	t.Helper()
	var plan string
	if err := migDB.QueryRow(`SELECT plan FROM tenants WHERE id = $1`, id).Scan(&plan); err != nil {
		t.Fatalf("read tenants.plan: %v", err)
	}
	return plan
}

// TestM47RPlanGuard_LosesToAConcurrentUncommittedSubscription drives the exact
// interleaving: the billing transaction has inserted the subscription and
// written the paid plan but has NOT committed when select-free runs.
func TestM47RPlanGuard_LosesToAConcurrentUncommittedSubscription(t *testing.T) {
	migDB := m47MigratorDB(t)
	appDB := openIntegrationDB(t, os.Getenv("DATABASE_URL"))

	tenant := m47rSeedTenant(t, migDB, model.PlanFree)
	repo := NewTenantRepository(appDB)

	// --- T1: the billing writer (what the Lemon Squeezy webhook now does).
	t1, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin T1: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = t1.Rollback()
		}
	}()
	if _, err := t1.Exec(`
		INSERT INTO subscriptions (
			id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, created_at, updated_at)
		VALUES ($1, $2, $3, '1', '2', '3', $4, $5, NOW(), NOW())`,
		uuid.New(), tenant, "ls-"+uuid.NewString(), model.StatusActive, model.PlanTeam); err != nil {
		t.Fatalf("T1 insert subscription: %v", err)
	}
	if _, err := t1.Exec(`UPDATE tenants SET plan = $1 WHERE id = $2`, model.PlanTeam, tenant); err != nil {
		t.Fatalf("T1 update plan: %v", err)
	}

	// --- T2: select-free, on its own transaction, running while T1 is open.
	type result struct {
		applied bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		t2, err := appDB.Begin()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = t2.Rollback() }()
		ctx := database.WithTx(context.Background(), t2)
		applied, err := repo.UpdatePlanUnlessSubscriptionLive(
			ctx, tenant, model.PlanFree, model.StatusExpired)
		if err != nil {
			done <- result{err: err}
			return
		}
		if err := t2.Commit(); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{applied: applied}
	}()

	// Give T2 time to reach — and block on — the tenant row.
	select {
	case r := <-done:
		t.Fatalf("select-free finished before T1 committed (applied=%v err=%v); "+
			"it must have blocked on the tenant row T1 holds", r.applied, r.err)
	case <-time.After(500 * time.Millisecond):
	}

	if err := t1.Commit(); err != nil {
		t.Fatalf("commit T1: %v", err)
	}
	committed = true

	r := <-done
	if r.err != nil {
		t.Fatalf("select-free: %v", r.err)
	}
	if r.applied {
		t.Errorf("select-free applied the downgrade even though a live subscription had just " +
			"committed — the guard's NOT EXISTS was evaluated against the pre-block snapshot")
	}
	if plan := m47rTenantPlan(t, migDB, tenant); plan != model.PlanTeam {
		t.Errorf("tenants.plan = %q, want %q — a paying tenant lost the entitlement it just "+
			"bought, and nothing re-writes it (subscription_created already ran)", plan, model.PlanTeam)
	}
}

// TestM47RPlanGuard_LosesToAConcurrentReactivation is the Codex round-2
// Medium: the tenant row lock alone is not enough.
//
// It works for a subscription being CREATED because the INSERT takes FOR KEY
// SHARE on the parent tenant row (the FK check), which conflicts with the
// FOR UPDATE taken here. But a subscription being REACTIVATED — a
// `subscription_updated` that moves an expired row back to active WITHOUT
// changing the plan — touches only `subscriptions`, and the webhook skips the
// tenants write when the plan is unchanged. Nothing then makes select-free
// wait, so it reads the still-`expired` row, decides nothing is live, and
// writes `free` over a subscription that is about to be active again.
//
// The fix is to lock the tenant's subscription rows FIRST, in the same order
// every other billing writer takes them (subscriptions -> tenants).
func TestM47RPlanGuard_LosesToAConcurrentReactivation(t *testing.T) {
	migDB := m47MigratorDB(t)
	appDB := openIntegrationDB(t, os.Getenv("DATABASE_URL"))

	tenant := m47rSeedTenant(t, migDB, model.PlanTeam)
	subID := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO subscriptions (
			id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
			status, plan, created_at, updated_at)
		VALUES ($1, $2, $3, '1', '2', '3', $4, $5, NOW(), NOW())`,
		subID, tenant, "ls-"+uuid.NewString(), model.StatusExpired, model.PlanTeam); err != nil {
		t.Fatalf("seed expired subscription: %v", err)
	}
	repo := NewTenantRepository(appDB)

	// --- T1: the reactivating webhook delivery. Same plan, so it never
	// touches `tenants` — only the subscription row moves.
	t1, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin T1: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = t1.Rollback()
		}
	}()
	if _, err := t1.Exec(
		`UPDATE subscriptions SET status = $1, updated_at = NOW() WHERE id = $2`,
		model.StatusActive, subID); err != nil {
		t.Fatalf("T1 reactivate subscription: %v", err)
	}

	type result struct {
		applied bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		t2, err := appDB.Begin()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = t2.Rollback() }()
		applied, err := repo.UpdatePlanUnlessSubscriptionLive(
			database.WithTx(context.Background(), t2), tenant, model.PlanFree, model.StatusExpired)
		if err != nil {
			done <- result{err: err}
			return
		}
		if err := t2.Commit(); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{applied: applied}
	}()

	select {
	case r := <-done:
		t.Fatalf("select-free finished before the reactivation committed (applied=%v err=%v); "+
			"it must block on the subscription row T1 holds", r.applied, r.err)
	case <-time.After(500 * time.Millisecond):
	}

	if err := t1.Commit(); err != nil {
		t.Fatalf("commit T1: %v", err)
	}
	committed = true

	r := <-done
	if r.err != nil {
		t.Fatalf("select-free: %v", r.err)
	}
	if r.applied {
		t.Errorf("select-free applied the downgrade while a subscription was being reactivated " +
			"— it decided on the pre-block snapshot, in which the row was still expired")
	}
	if plan := m47rTenantPlan(t, migDB, tenant); plan != model.PlanTeam {
		t.Errorf("tenants.plan = %q, want %q — the tenant is on an active subscription again "+
			"and nothing re-writes the plan (the reactivating delivery left it alone because "+
			"the plan did not change)", plan, model.PlanTeam)
	}
}

// TestM47RPlanGuard_StillRefusesAndStillApplies is the pair of controls: the
// lock must not change the uncontended answers.
func TestM47RPlanGuard_StillRefusesAndStillApplies(t *testing.T) {
	migDB := m47MigratorDB(t)
	appDB := openIntegrationDB(t, os.Getenv("DATABASE_URL"))
	repo := NewTenantRepository(appDB)

	t.Run("live subscription refuses", func(t *testing.T) {
		tenant := m47rSeedTenant(t, migDB, model.PlanTeam)
		if _, err := migDB.Exec(`
			INSERT INTO subscriptions (
				id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id,
				status, plan, created_at, updated_at)
			VALUES ($1, $2, $3, '1', '2', '3', $4, $5, NOW(), NOW())`,
			uuid.New(), tenant, "ls-"+uuid.NewString(), model.StatusActive, model.PlanTeam); err != nil {
			t.Fatalf("seed subscription: %v", err)
		}
		applied, err := repo.UpdatePlanUnlessSubscriptionLive(
			context.Background(), tenant, model.PlanFree, model.StatusExpired)
		if err != nil {
			t.Fatalf("UpdatePlanUnlessSubscriptionLive: %v", err)
		}
		if applied {
			t.Error("applied = true, want false — a live subscription blocks the downgrade")
		}
		if plan := m47rTenantPlan(t, migDB, tenant); plan != model.PlanTeam {
			t.Errorf("tenants.plan = %q, want %q", plan, model.PlanTeam)
		}
	})

	t.Run("no subscription applies", func(t *testing.T) {
		tenant := m47rSeedTenant(t, migDB, model.PlanTeam)
		applied, err := repo.UpdatePlanUnlessSubscriptionLive(
			context.Background(), tenant, model.PlanFree, model.StatusExpired)
		if err != nil {
			t.Fatalf("UpdatePlanUnlessSubscriptionLive: %v", err)
		}
		if !applied {
			t.Error("applied = false, want true — nothing blocks this downgrade")
		}
		if plan := m47rTenantPlan(t, migDB, tenant); plan != model.PlanFree {
			t.Errorf("tenants.plan = %q, want %q", plan, model.PlanFree)
		}
	})

	t.Run("unknown tenant is a refusal, not an error", func(t *testing.T) {
		applied, err := repo.UpdatePlanUnlessSubscriptionLive(
			context.Background(), uuid.New(), model.PlanFree, model.StatusExpired)
		if err != nil {
			t.Fatalf("UpdatePlanUnlessSubscriptionLive: %v", err)
		}
		if applied {
			t.Error("applied = true for a tenant that does not exist")
		}
	})
}
