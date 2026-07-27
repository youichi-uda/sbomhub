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
// WHAT THIS DOES AND DOES NOT BUY (measured against the dev Postgres,
// 2026-07-28, default READ COMMITTED):
//
//	subscription INSERT already COMMITTED when this runs -> 0 rows, refused.
//	INSERT still UNCOMMITTED when this runs              -> 1 row, applied;
//	  final state tenants.plan="free" beside status="active".
//
// The second case is not fixable by making the statement smarter: READ
// COMMITTED cannot see another transaction's uncommitted row, and neither can
// a subquery. It shrinks the exposure from "the whole read→write gap of the
// handler" to "the execution of one concurrent INSERT", and in production the
// webhook writes in autocommit (no wrapping transaction), so that is a
// single statement's width. Closing it entirely needs both sides to take the
// same lock — see docs/SAAS_SETUP.md §2.5 residuals.
//
// The policy (which statuses count as finished) stays with the caller rather
// than being hardcoded here, so `endedSubscriptionStatus` in the billing
// handler remains the single place that decides it. Today that is "everything
// except expired", matching handleSubscriptionExpired — the only webhook that
// downgrades.
//
// applied == false means the guard fired OR the tenant row does not exist.
// The caller distinguishes those only for diagnostics; both are refusals.
//
// NOTE this narrows the window on the tenants.plan write ALONE. A
// subscription created a moment later still lands next to a free plan until
// its own webhook writes the plan — which it does, unconditionally, in
// handleSubscriptionCreated, so that ordering self-heals. The ordering that
// does NOT self-heal is the one measured above: the webhook writes the plan
// first and this statement overwrites it afterwards. Full serialisation of
// billing state would need a per-tenant lock taken by the webhook path too;
// see docs/SAAS_SETUP.md §2.5.
func (r *TenantRepository) UpdatePlanUnlessSubscriptionLive(
	ctx context.Context, id uuid.UUID, plan, endedStatus string,
) (bool, error) {
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
