package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// UpdatePlanUnlessSubscriptionLive writes tenants.plan only while the tenant
// has no subscription row outside `endedStatus`, and reports whether the write
// happened (M47 W3 #3, TOCTOU half).
//
// It exists because the check and the write should be ONE statement. The
// handler's first cut read `subscriptions` and then called UpdatePlan, and the
// Lemon Squeezy webhook — which runs OUTSIDE the request's TenantTx — can
// create or reactivate a subscription in between, leaving a charged, live
// subscription next to a free entitlement.
//
// ONE STATEMENT WAS NOT ENOUGH (M47R, Codex round 1 High; measured against
// the dev Postgres, 2026-07-28, default READ COMMITTED).
//
// W3 shipped this as a single conditional UPDATE and documented the residue:
//
//	subscription INSERT already COMMITTED when it runs -> 0 rows, refused.
//	INSERT still UNCOMMITTED when it runs              -> 1 row, APPLIED;
//	  final state tenants.plan="free" beside status="active".
//
// The second line is a READ COMMITTED anomaly, not a missing predicate. The
// subquery is evaluated against the snapshot taken when the statement STARTS;
// the statement then blocks on the tenants row the other transaction holds,
// and when that transaction commits Postgres re-checks the TARGET row but not
// the subquery. So the guard decides on a world in which the subscription did
// not exist, and then writes into a world in which it does.
//
// M47R closes it by LOCKING FIRST, in two SEPARATE, EARLIER statements:
//
//	SELECT 1 FROM subscriptions WHERE tenant_id = $1 FOR UPDATE;  -- block here
//	SELECT 1 FROM tenants       WHERE id        = $1 FOR UPDATE;  -- and here
//	UPDATE tenants ... WHERE NOT EXISTS (...)                     -- fresh snapshot
//
// Blocking on the locks alone means the guarded UPDATE is a NEW statement with
// a NEW snapshot, which DOES see the committed subscription, so the guard
// fires and the caller answers 409.
//
// BOTH locks are needed, and each covers a case the other cannot (each was
// reproduced red → green against a real Postgres):
//
//   - `tenants` covers a subscription being CREATED. The INSERT takes FOR KEY
//     SHARE on the parent tenant row for its foreign-key check, which
//     conflicts with FOR UPDATE — so this waits even though the new
//     subscription row is invisible to it.
//     (TestM47RPlanGuard_LosesToAConcurrentUncommittedSubscription)
//   - `subscriptions` covers a subscription being REACTIVATED: a
//     `subscription_updated` that moves an expired row back to active without
//     changing the plan touches ONLY `subscriptions` — the webhook skips the
//     tenants write when the plan is unchanged — so the tenant lock alone
//     never fires. (TestM47RPlanGuard_LosesToAConcurrentReactivation, found
//     by the Codex round-2 review of the tenant-only version.)
//
// The locks are also what M47R needed rather than merely wanted: the Lemon
// Squeezy webhook used to write in autocommit, so the exposed window was one
// statement wide; since M47R it runs the whole delivery in a transaction, so
// without this the window would have been the whole delivery.
//
// LOCK ORDERING: `subscriptions` then `tenants` — the SAME order every other
// billing writer takes them. The webhook and /subscription/sync both claim the
// provider revision / update the subscription row first and call UpdatePlan
// second. There is therefore no cycle to deadlock on.
//
// WHAT THE LOCKS DO NOT DO (Codex round 3, Medium, which caught this comment
// claiming more than the code): they SERIALISE the two transactions; they do
// not decide which one goes first. If select-free wins the race — it acquires
// both locks while a same-plan reactivation is still waiting — it commits
// `free` legitimately, on a subscription that is expired at that moment. The
// reactivation then applies, sets the row active, and skips the tenants write
// because the plan did not change, leaving an active subscription beside a
// free entitlement.
//
// That direction is NOT closed here and cannot be: it is the webhook's
// "only write tenants.plan when the plan changed" rule, which M47 W3 chose
// deliberately (writing the product plan unconditionally from
// subscription_updated resurrects a paid plan when a same-revision update
// arrives alongside subscription_expired — see docs/SAAS_SETUP.md §2.5
// residual 8). Closing it means giving every ended→live transition an
// explicit entitlement write, which is an entitlement-policy change, not a
// locking one. Recorded as a residual in docs/SAAS_SETUP.md §2.5.
//
// What IS closed is the direction that actually loses money for the customer:
// select-free can no longer decide on a stale snapshot and overwrite a plan a
// concurrent billing transaction has already committed.
//
// The caller MUST run this inside its request transaction (TenantTx does), or
// the locks are released by the implicit commit of each SELECT and buy
// nothing.
//
// The policy (which statuses count as finished) stays with the caller rather
// than being hardcoded here, so `endedSubscriptionStatus` in the billing
// handler remains the single place that decides it. Today that is "everything
// except expired", matching handleSubscriptionExpired — the only webhook that
// downgrades.
//
// applied == false means the guard fired OR the tenant row does not exist.
// The caller CANNOT tell them apart (Codex round 2, Low: an earlier version of
// this sentence claimed it could). A vanished tenant is therefore reported to
// the caller the same way a live subscription is; the handler's diagnostic
// re-read then finds no subscription and logs `status=unknown`, which is the
// only place the difference shows. It is not worth a second return value: the
// caller reached here through TenantTx, which already resolved and pinned the
// tenant, so the row disappearing mid-request means the whole request is void.
//
// THE OTHER ORDER IS HARMLESS: a subscription CREATED a moment after this
// commits never lands next to a free plan at all, because since M47R
// handleSubscriptionCreated commits the subscription row and the paid
// entitlement in one transaction (Codex round 4, Low: the previous wording
// described the pre-M47R autocommit behaviour, in which the two were briefly
// observable apart). See docs/SAAS_SETUP.md §2.5.
func (r *TenantRepository) UpdatePlanUnlessSubscriptionLive(
	ctx context.Context, id uuid.UUID, plan, endedStatus string,
) (bool, error) {
	// Serialise against any in-flight billing transaction for this tenant, in
	// the subscriptions -> tenants order every billing writer uses. Either
	// statement matching no row is fine and is NOT special-cased: a tenant
	// with no subscription has nothing to wait for, and a tenant that does not
	// exist is refused by the guarded UPDATE below on its own.
	if _, err := r.q(ctx).ExecContext(ctx,
		`SELECT 1 FROM subscriptions WHERE tenant_id = $1 FOR UPDATE`, id,
	); err != nil {
		return false, fmt.Errorf("lock subscriptions of tenant %s for a guarded plan update: %w", id, err)
	}
	if _, err := r.q(ctx).ExecContext(ctx,
		`SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, id,
	); err != nil {
		return false, fmt.Errorf("lock tenant %s for a guarded plan update: %w", id, err)
	}

	query := `
		UPDATE tenants SET plan = $1, updated_at = NOW()
		WHERE id = $2
			AND NOT EXISTS (
				SELECT 1 FROM subscriptions s
				WHERE s.tenant_id = $2 AND s.status <> $3
			)
	`
	res, err := r.q(ctx).ExecContext(ctx, query, plan, id, endedStatus)
	if err != nil {
		return false, fmt.Errorf("update tenants.plan for %s (guarded): %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update tenants.plan (RowsAffected): %w", err)
	}
	return n > 0, nil
}
