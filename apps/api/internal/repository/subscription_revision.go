package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ClaimProviderRevision is the compare-and-swap that gives subscription
// writes an ordering guarantee the transport does not provide (M47 W3 #4).
//
// `rev` is the provider's own `data.attributes.updated_at` for the delivery
// being processed. The statement advances the stored watermark and reports
// whether the caller may apply its delivery:
//
//	true  — rev is at least as new as everything already applied. Proceed.
//	false — rev is STRICTLY OLDER than the last applied revision. The
//	        delivery is obsolete; discard it (with a 2xx: retrying an
//	        obsolete event changes nothing).
//
// Why `<=` rather than `<` (i.e. why equal revisions are accepted): Lemon
// Squeezy emits several events for one state transition sharing a single
// updated_at — `subscription_updated` accompanies `subscription_expired`.
// Requiring a strictly newer revision would drop whichever arrived second,
// and dropping a terminal event fails in the direction that GRANTS
// entitlement. Accepting equals also makes the operation idempotent under
// redelivery: a retried delivery re-claims its own revision and re-applies,
// which matters because the caller claims BEFORE it writes, so a write that
// failed after a successful claim must still be recoverable.
//
// The consequence, stated plainly: this orders deliveries that carry
// DIFFERENT revisions. Two events sharing one revision are still applied in
// arrival order, whatever that is.
//
// THAT LIMIT IS CLOSED FOR THE WEBHOOK (M47R). It used to read: the claim and
// the state write are separate statements and the webhook path has no
// transaction, so two in-flight deliveries could interleave as
//
//	old claims R1 -> new claims R2 -> new writes state -> old writes state
//
// leaving the watermark at R2 beside R1's state. Since M47R the webhook runs
// each delivery inside one transaction (handler.applyDelivery) and the row
// lock this UPDATE takes is held until it commits, so the second delivery
// cannot even claim until the first has finished writing. The caller also
// re-reads the row after a successful claim, so it compares against committed
// state rather than its pre-claim snapshot.
//
// The guarantee for any FUTURE caller that runs this outside a transaction is
// still only "a delivery that LOSES the comparison never writes". There is no
// such caller today: handler.applyDelivery and BillingHandler.SyncSubscription
// (inside TenantTx) are both transactional.
//
// A NULL watermark (pre-061 rows, and rows just created) always accepts:
// there is no recorded revision to be older than.
//
// Note this is deliberately NOT tenant-scoped. Its only callers are the
// webhook handlers, which have no tenant context, and the sync handler, which
// has already proven ownership; the subscription id it takes comes from a row
// those callers just read, never from client input.
func (r *SubscriptionRepository) ClaimProviderRevision(
	ctx context.Context, subscriptionID uuid.UUID, rev time.Time,
) (bool, error) {
	query := `
		UPDATE subscriptions
		SET provider_updated_at = $2
		WHERE id = $1
			AND (provider_updated_at IS NULL OR provider_updated_at <= $2)
	`
	res, err := r.q(ctx).ExecContext(ctx, query, subscriptionID, rev)
	if err != nil {
		return false, fmt.Errorf("claim provider revision for subscription %s: %w", subscriptionID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim provider revision (RowsAffected): %w", err)
	}
	// n == 0 also covers "the row disappeared between the caller's read and
	// this statement". Reporting that as "do not apply" is correct either
	// way: there is nothing left to apply it to.
	return n > 0, nil
}
