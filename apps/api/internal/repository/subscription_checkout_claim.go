package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sbomhub/sbomhub/internal/model"
)

// ErrCheckoutClaimNotFound is the single refusal of ConsumeCheckoutClaim.
//
// It covers every reason a claim token cannot be honoured — unknown token,
// expired claim, or a token already spent by a DIFFERENT subscription — on
// purpose. The caller is an unauthenticated webhook route; telling it which
// of those applied would let anyone probe for live tokens.
var ErrCheckoutClaimNotFound = errors.New("subscription_checkout_claims: no claimable row for this token")

// CreateCheckoutClaim records the tenant binding for a checkout that is about
// to be handed to a buyer (M47 W3 #2).
//
// Called from BillingHandler.CreateCheckout, which runs inside the request's
// TenantTx — so the row commits with the rest of the request, and a failed
// checkout creation leaves no dangling claim.
func (r *SubscriptionRepository) CreateCheckoutClaim(ctx context.Context, c *model.CheckoutClaim) error {
	query := `
		INSERT INTO subscription_checkout_claims (
			token_hash, tenant_id, plan, ls_variant_id, ls_checkout_id,
			created_at, expires_at
		) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7)
	`
	_, err := r.q(ctx).ExecContext(ctx, query,
		c.TokenHash, c.TenantID, c.Plan, c.LSVariantID, c.LSCheckoutID,
		c.CreatedAt, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert subscription_checkout_claims: %w", err)
	}
	return nil
}

// ConsumeCheckoutClaim resolves a claim token to the tenant that started the
// checkout, and marks it as belonging to lsSubscriptionID.
//
// It is a single conditional UPDATE ... RETURNING rather than a read followed
// by a write, so two concurrent deliveries of the same event cannot both
// believe they were first, and no window exists in which a token is
// resolvable by two different subscriptions.
//
// The predicate is the whole security contract:
//
//   - token_hash = $1                 the caller must present the token. Only
//     its SHA-256 is stored, so a dump of this
//     table yields nothing presentable.
//   - unconsumed AND unexpired        a FIRST use must fall inside the
//     binding window, OR
//   - ls_subscription_id = $2         a REDELIVERY of the subscription this
//     claim is already bound to, whenever it
//     arrives. Expiry deliberately does NOT
//     apply here (Codex round 1, Medium):
//     the binding is already established, only
//     that one subscription can present the
//     token, and Lemon Squeezy can replay a
//     delivery from the dashboard long after
//     the TTL — refusing then would strand a
//     paid subscription permanently.
//
// A different subscription presenting a spent token matches nothing and gets
// ErrCheckoutClaimNotFound — that is the replay this guard exists to refuse.
//
// COALESCE on both writes keeps the FIRST consumption's timestamp and id, so
// the audit trail records when the binding was actually established rather
// than when it was last re-confirmed.
//
// Runs on the webhook path, which has no transaction and no
// app.current_tenant_id; the table carries no RLS for exactly that reason
// (migration 060, same constraint as `subscriptions` in 031).
func (r *SubscriptionRepository) ConsumeCheckoutClaim(
	ctx context.Context, tokenHash, lsSubscriptionID string, now time.Time,
) (*model.CheckoutClaim, error) {
	if tokenHash == "" || lsSubscriptionID == "" {
		// Neither is a state the caller should be able to reach; refusing
		// here keeps an empty string from matching a NULL-ish row through
		// some future schema change.
		return nil, ErrCheckoutClaimNotFound
	}

	query := `
		UPDATE subscription_checkout_claims
		SET consumed_at = COALESCE(consumed_at, $3),
			ls_subscription_id = COALESCE(ls_subscription_id, $2)
		WHERE token_hash = $1
			AND (
				(ls_subscription_id IS NULL AND expires_at > $3)
				OR ls_subscription_id = $2
			)
		RETURNING token_hash, tenant_id, plan, ls_variant_id,
			COALESCE(ls_checkout_id, ''), created_at, expires_at,
			consumed_at, COALESCE(ls_subscription_id, '')
	`
	var c model.CheckoutClaim
	err := r.q(ctx).QueryRowContext(ctx, query, tokenHash, lsSubscriptionID, now).Scan(
		&c.TokenHash, &c.TenantID, &c.Plan, &c.LSVariantID,
		&c.LSCheckoutID, &c.CreatedAt, &c.ExpiresAt,
		&c.ConsumedAt, &c.LSSubscriptionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrCheckoutClaimNotFound
		}
		return nil, fmt.Errorf("consume subscription_checkout_claims: %w", err)
	}
	return &c, nil
}
