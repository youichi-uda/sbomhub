-- ============================================
-- Server-held tenant binding for Lemon Squeezy checkouts (M47 W3 #2).
--
-- The hole this closes:
--   POST /api/v1/subscription/checkout used to answer with
--
--     https://sbomhub.lemonsqueezy.com/checkout/buy/<variant>
--       ?checkout[custom][tenant_id]=<caller's tenant>
--
--   and handleSubscriptionCreated took `meta.custom_data.tenant_id` from the
--   delivered webhook as the tenant to bill. The HMAC on that webhook proves
--   only that Lemon Squeezy sent it -- the custom value itself made a round
--   trip through the BUYER's browser, where the query string is editable
--   (docs.lemonsqueezy.com/help/checkout/passing-custom-data documents
--   `checkout[custom][...]` as a supported URL parameter, and returns
--   whatever arrives in the webhook's `meta`). Anyone willing to pay could
--   therefore attach a subscription to ANOTHER tenant: taking over its plan
--   lifecycle (a later cancel/expire downgrades the victim), and occupying
--   its single subscription slot -- `subscriptions` carries UNIQUE(tenant_id)
--   (008) -- so the victim cannot buy its own.
--
-- The fix, in one sentence: nothing that names a tenant is ever handed to
-- the client. The checkout carries an opaque 256-bit claim token; the
-- tenant it belongs to is stored HERE, server-side, and the webhook resolves
-- the token instead of trusting a tenant id.
--
-- Column notes:
--   token_hash          SHA-256 hex of the raw token, never the token itself
--                       -- same discipline as api_keys.key_hash (007) and for
--                       the same reason: this table is a read target for an
--                       unauthenticated route, and a leak of it must not
--                       yield usable tokens. PRIMARY KEY, so the webhook
--                       lookup is a single index hit. (The raw token is held
--                       by Lemon Squeezy as the checkout's custom data and is
--                       kept out of our logs; "never stored" is about THIS
--                       database.)
--   plan / ls_variant_id  what the checkout was created FOR. Recorded for
--                       audit and support only. The plan actually granted
--                       keeps coming from the provider's product_name in the
--                       webhook (productNameToPlan), because that is what the
--                       buyer actually paid for -- a claim row must not be
--                       able to grant a plan Lemon Squeezy did not sell.
--   expires_at          the binding window. A checkout link that is never
--                       completed stops being usable. NOT NULL: an unbounded
--                       claim is not a state this table should be able to
--                       hold.
--   consumed_at /
--   ls_subscription_id  set together the first time a subscription_created
--                       delivery resolves this token. They are NOT a
--                       one-shot lock: a REDELIVERY of the same subscription
--                       must still resolve (Lemon Squeezy retries a non-2xx
--                       delivery up to three more times, and the dashboard
--                       can replay one much later), so the consuming
--                       statement matches an already-bound row on
--                       `ls_subscription_id = $incoming` ALONE -- expires_at
--                       constrains the FIRST use only.
--                       A DIFFERENT subscription presenting a spent token is
--                       refused -- that is the replay this pair prevents.
--
-- RLS:
--   Deliberately none. The resolving read happens inside
--   handler/webhook_lemonsqueezy.go, whose route is mounted directly on the
--   Echo instance, outside TenantTx: no `app.current_tenant_id` GUC is set,
--   so under the NOBYPASSRLS `sbomhub_app` role a tenant policy would reduce
--   to NULL and return zero rows. That is exactly the chicken-and-egg
--   migration 031 resolved for `subscriptions` / `subscription_events` /
--   `usage_records`, and this table is on the same path -- it is the lookup
--   that REVEALS the tenant, so it cannot be gated on already knowing it.
--   Tenant scope is enforced application-side: the INSERT runs inside the
--   caller's TenantTx with its own tenant id, and the only read is by
--   token_hash.
-- lint:no-rls-required(subscription_checkout_claims): resolved by the Lemon Squeezy webhook, which runs outside TenantTx with no app.current_tenant_id (same constraint as subscriptions, migration 031)
-- ============================================

CREATE TABLE IF NOT EXISTS subscription_checkout_claims (
    token_hash         VARCHAR(64) PRIMARY KEY,
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    plan               VARCHAR(50) NOT NULL,
    ls_variant_id      VARCHAR(255) NOT NULL,
    ls_checkout_id     VARCHAR(255),
    created_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at        TIMESTAMP WITH TIME ZONE,
    ls_subscription_id VARCHAR(255)
);

-- Supports the operator question "which checkouts did this tenant start?"
-- and makes the CASCADE delete cheap.
CREATE INDEX IF NOT EXISTS idx_subscription_checkout_claims_tenant
    ON subscription_checkout_claims(tenant_id);

-- Supports periodic pruning of expired, unconsumed rows.
CREATE INDEX IF NOT EXISTS idx_subscription_checkout_claims_expires
    ON subscription_checkout_claims(expires_at);

COMMENT ON TABLE subscription_checkout_claims IS
    'M47 W3 #2: server-held tenant binding for Lemon Squeezy checkouts. One row per checkout created by POST /api/v1/subscription/checkout. The checkout carries only the opaque token whose SHA-256 is token_hash; handleSubscriptionCreated resolves that token to tenant_id instead of trusting meta.custom_data.tenant_id, which travelled through the buyer''s browser and was editable. No RLS by construction -- the webhook route runs outside TenantTx and this is the lookup that reveals the tenant (same constraint as subscriptions, migration 031); tenant scope is enforced application-side.';

COMMENT ON COLUMN subscription_checkout_claims.token_hash IS
    'SHA-256 (hex) of the raw claim token, mirroring api_keys.key_hash. The raw token is never stored in this database and is kept out of the application logs; Lemon Squeezy holds it as the checkout custom data and returns it on the subscription_created webhook.';

COMMENT ON COLUMN subscription_checkout_claims.plan IS
    'Plan the checkout was created for. Audit/support only -- the granted plan is derived from the provider''s product_name in the webhook, so a claim row cannot grant a plan Lemon Squeezy did not sell.';

COMMENT ON COLUMN subscription_checkout_claims.consumed_at IS
    'First time a subscription_created delivery resolved this token. Together with ls_subscription_id it permits redelivery of the SAME subscription at any later time -- expires_at gates the FIRST use only, because Lemon Squeezy can replay a delivery from the dashboard long after the TTL and refusing then would strand a paid subscription -- while refusing a different subscription presenting a spent token.';
