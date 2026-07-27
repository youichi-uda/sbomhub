package model

import (
	"time"

	"github.com/google/uuid"
)

// CheckoutClaim is the server-held binding between a Lemon Squeezy checkout
// and the tenant that started it (M47 W3 #2).
//
// It exists because the tenant id used to travel to the provider and back
// through the BUYER's browser, inside the checkout URL's
// `checkout[custom][tenant_id]` parameter, where it was editable. The webhook
// HMAC proves only that Lemon Squeezy sent the delivery — never that the
// custom data in it was ours. A claim replaces that with an opaque token: the
// checkout carries the token, this row carries the tenant, and only the
// server can associate the two.
//
// TokenHash is the SHA-256 (hex) of the raw token. The raw token is never
// stored in SBOMHub's database and is kept out of its logs, exactly as with
// api_keys — it does of course reach Lemon Squeezy, which holds it as the
// checkout's custom data and hands it back on the webhook.
type CheckoutClaim struct {
	TokenHash string    `json:"-" db:"token_hash"`
	TenantID  uuid.UUID `json:"tenant_id" db:"tenant_id"`
	// Plan and LSVariantID record what the checkout was created FOR. They are
	// audit/support data: the plan actually granted is derived from the
	// provider's product_name on the resulting webhook, so a claim row can
	// never grant a plan Lemon Squeezy did not sell.
	Plan         string `json:"plan" db:"plan"`
	LSVariantID  string `json:"ls_variant_id" db:"ls_variant_id"`
	LSCheckoutID string `json:"ls_checkout_id,omitempty" db:"ls_checkout_id"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`

	// ConsumedAt / LSSubscriptionID are set together when a
	// subscription_created delivery first resolves this claim. They do not
	// make the claim single-use: a redelivery of the SAME subscription still
	// resolves — at any later time, expiry included, since the binding is
	// already established — while a different subscription presenting a spent
	// token is refused.
	ConsumedAt       *time.Time `json:"consumed_at,omitempty" db:"consumed_at"`
	LSSubscriptionID string     `json:"ls_subscription_id,omitempty" db:"ls_subscription_id"`
}

// CheckoutClaimTTL is how long a buyer has to complete a checkout.
//
// It is applied in TWO places so the two sides cannot drift apart:
//
//   - as `expires_at` on the checkout created at Lemon Squeezy, so the
//     buyer-facing URL stops being payable at the same moment;
//   - as the deadline for the FIRST binding of the claim row.
//
// Sending it to the provider is what stops the failure Codex round 3 named:
// with a perpetual checkout and an expiring claim, a customer could pay
// through a months-old URL and have the (correctly signed)
// subscription_created refused — money taken, no entitlement. It is better
// for the provider to refuse the payment than for us to refuse the purchase.
const CheckoutClaimTTL = 7 * 24 * time.Hour

// CheckoutClaimGrace is extra life given to the claim ROW beyond the
// provider-side checkout expiry.
//
// The claim's expiry is evaluated when the webhook is PROCESSED, not when the
// payment happened, so a delivery that is delayed or replayed near the
// deadline would otherwise be refused for a payment the provider had already
// accepted. The grace makes the row outlive the window in which a payment can
// still be made, and it is safe precisely because a claim can only be bound by
// a checkout Lemon Squeezy still considered valid.
//
// Redelivery of an ALREADY-bound claim ignores expiry entirely (see
// ConsumeCheckoutClaim), so this only widens the first-binding window.
const CheckoutClaimGrace = 7 * 24 * time.Hour
