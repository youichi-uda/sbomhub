-- Drop RLS policies
DROP POLICY IF EXISTS tenant_isolation_usage_records ON usage_records;
DROP POLICY IF EXISTS tenant_isolation_subscription_events ON subscription_events;
DROP POLICY IF EXISTS tenant_isolation_subscriptions ON subscriptions;

-- Disable RLS
ALTER TABLE usage_records DISABLE ROW LEVEL SECURITY;
ALTER TABLE subscription_events DISABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions DISABLE ROW LEVEL SECURITY;

-- Drop tables
DROP TABLE IF EXISTS plan_limits;
DROP TABLE IF EXISTS usage_records;
DROP TABLE IF EXISTS subscription_events;
DROP TABLE IF EXISTS subscriptions;
