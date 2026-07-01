-- ============================================
-- Revert F299 (M20-2 #116) plan_limits feature-set parity backfill.
-- See 049_plan_features_parity_backfill.up.sql header for rationale.
--
-- The up migration only touches free / starter (adds
-- audit_logs=false + priority_support=false); pro / team / enterprise
-- were already handled by migration 024 (audit_logs) / 008 seed
-- (priority_support). So the down restricts its DELETE-key operation
-- to free / starter rows and only to the keys we added. JSONB "-"
-- strips the key if present, otherwise no-op.
-- ============================================

UPDATE plan_limits
   SET features = (features - 'audit_logs') - 'priority_support'
 WHERE plan IN ('free', 'starter');
