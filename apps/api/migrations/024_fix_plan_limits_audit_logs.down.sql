-- Rollback: Remove audit_logs from plan_limits features
-- Note: This removes the key, restoring original state

UPDATE plan_limits
SET features = features - 'audit_logs',
    updated_at = NOW()
WHERE plan IN ('pro', 'team', 'enterprise');
