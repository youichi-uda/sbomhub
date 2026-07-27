-- ============================================
-- Reverse of 060_subscription_checkout_claims.up.sql (M47 W3 #2).
--
-- ROLLBACK SEQUENCING -- read before running this down:
--   Roll the API binary back to a pre-060 build FIRST. From 060 onward,
--   handler/billing.go CreateCheckout INSERTs into this table and
--   handler/webhook_lemonsqueezy.go handleSubscriptionCreated resolves the
--   claim from it; with the table gone both fail with
--   `relation "subscription_checkout_claims" does not exist`, i.e. no tenant
--   can start a checkout and every subscription_created delivery 500s (and
--   is retried at most three more times before Lemon Squeezy drops it).
--
-- SECURITY ROLLBACK -- this down is not merely structural:
--   the pre-060 binary reads the tenant to bill out of
--   `meta.custom_data.tenant_id`, a value that travelled through the buyer's
--   browser. Rolling back therefore REOPENS the finding this table closed:
--   a buyer can point their purchase at another tenant. Treat it as an
--   accepted, temporary cost, not an oversight.
--
-- Data loss: in-flight checkouts. Any buyer holding a checkout URL created
-- before the rollback has a token that no longer resolves; under the
-- pre-060 binary their subscription_created carries no tenant_id either
-- (the new checkout stopped sending one), so the purchase arrives unlinked
-- and needs the manual operator linking documented in docs/SAAS_SETUP.md
-- §2.5. Prefer rolling back during a window with no open checkouts.
-- ============================================

DROP INDEX IF EXISTS idx_subscription_checkout_claims_expires;
DROP INDEX IF EXISTS idx_subscription_checkout_claims_tenant;
DROP TABLE IF EXISTS subscription_checkout_claims;
