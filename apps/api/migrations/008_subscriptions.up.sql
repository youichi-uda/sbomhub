-- ============================================
-- SBOMHub Subscription/Billing Migration
-- (Lemon Squeezy integration)
-- ============================================

-- Subscriptions table
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ls_subscription_id VARCHAR(255) UNIQUE NOT NULL,
    ls_customer_id VARCHAR(255) NOT NULL,
    ls_variant_id VARCHAR(255) NOT NULL,
    ls_product_id VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    plan VARCHAR(50) NOT NULL,
    billing_anchor INTEGER,
    current_period_start TIMESTAMP WITH TIME ZONE,
    current_period_end TIMESTAMP WITH TIME ZONE,
    trial_ends_at TIMESTAMP WITH TIME ZONE,
    renews_at TIMESTAMP WITH TIME ZONE,
    ends_at TIMESTAMP WITH TIME ZONE,
    cancelled_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id)
);

-- Subscription status: on_trial, active, paused, past_due, unpaid, cancelled, expired
-- Plan: free, starter, pro, team, enterprise

-- Subscription history for billing events
CREATE TABLE subscription_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subscription_id UUID NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    ls_event_id VARCHAR(255),
    previous_status VARCHAR(50),
    new_status VARCHAR(50),
    previous_plan VARCHAR(50),
    new_plan VARCHAR(50),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Usage tracking for metered billing (optional future use)
CREATE TABLE usage_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    metric VARCHAR(100) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 0,
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, metric, period_start)
);

-- Indexes
CREATE INDEX idx_subscriptions_tenant_id ON subscriptions(tenant_id);
CREATE INDEX idx_subscriptions_ls_subscription_id ON subscriptions(ls_subscription_id);
CREATE INDEX idx_subscriptions_ls_customer_id ON subscriptions(ls_customer_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_plan ON subscriptions(plan);
CREATE INDEX idx_subscriptions_current_period_end ON subscriptions(current_period_end);

CREATE INDEX idx_subscription_events_subscription_id ON subscription_events(subscription_id);
CREATE INDEX idx_subscription_events_tenant_id ON subscription_events(tenant_id);
CREATE INDEX idx_subscription_events_event_type ON subscription_events(event_type);
CREATE INDEX idx_subscription_events_created_at ON subscription_events(created_at);

CREATE INDEX idx_usage_records_tenant_id ON usage_records(tenant_id);
CREATE INDEX idx_usage_records_metric ON usage_records(metric);
CREATE INDEX idx_usage_records_period ON usage_records(period_start, period_end);

-- Enable RLS
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_records ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY tenant_isolation_subscriptions ON subscriptions
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_subscription_events ON subscription_events
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

CREATE POLICY tenant_isolation_usage_records ON usage_records
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);

-- ============================================
-- Plan Limits Configuration
-- ============================================

CREATE TABLE plan_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    plan VARCHAR(50) UNIQUE NOT NULL,
    max_users INTEGER NOT NULL DEFAULT 1,
    max_projects INTEGER NOT NULL DEFAULT 2,
    max_sboms_per_project INTEGER NOT NULL DEFAULT 10,
    max_api_keys INTEGER NOT NULL DEFAULT 5,
    api_rate_limit INTEGER NOT NULL DEFAULT 100,
    features JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default plan limits
INSERT INTO plan_limits (plan, max_users, max_projects, max_sboms_per_project, max_api_keys, api_rate_limit, features) VALUES
    ('free', 1, 2, 5, 2, 60, '{"vulnerability_alerts": true, "vex_support": false, "license_policies": false, "slack_integration": false, "discord_integration": false, "api_access": false}'),
    ('starter', 3, 10, 50, 10, 300, '{"vulnerability_alerts": true, "vex_support": true, "license_policies": true, "slack_integration": true, "discord_integration": true, "api_access": true}'),
    ('pro', 10, -1, 200, 50, 1000, '{"vulnerability_alerts": true, "vex_support": true, "license_policies": true, "slack_integration": true, "discord_integration": true, "api_access": true, "priority_support": true}'),
    ('team', 30, -1, -1, -1, 3000, '{"vulnerability_alerts": true, "vex_support": true, "license_policies": true, "slack_integration": true, "discord_integration": true, "api_access": true, "priority_support": true, "sso": false}'),
    ('enterprise', -1, -1, -1, -1, -1, '{"vulnerability_alerts": true, "vex_support": true, "license_policies": true, "slack_integration": true, "discord_integration": true, "api_access": true, "priority_support": true, "sso": true, "custom_integrations": true}');

-- Note: -1 means unlimited
