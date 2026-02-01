-- ============================================
-- Fix plan_limits to include audit_logs feature
-- BUG-06: Cloud Team plan should have audit_logs enabled
-- ============================================

-- Update pro plan to include audit_logs
UPDATE plan_limits
SET features = features || '{"audit_logs": true}'::jsonb,
    updated_at = NOW()
WHERE plan = 'pro';

-- Update team plan to include audit_logs
UPDATE plan_limits
SET features = features || '{"audit_logs": true}'::jsonb,
    updated_at = NOW()
WHERE plan = 'team';

-- Update enterprise plan to include audit_logs (should already have it, but ensure consistency)
UPDATE plan_limits
SET features = features || '{"audit_logs": true}'::jsonb,
    updated_at = NOW()
WHERE plan = 'enterprise';
