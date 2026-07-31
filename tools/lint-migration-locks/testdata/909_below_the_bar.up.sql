-- SHARE UPDATE EXCLUSIVE and ROW EXCLUSIVE are both below the bar:
-- measured, neither conflicts with a live reader or a live writer.
ALTER TABLE components VALIDATE CONSTRAINT components_eol_status_check;

COMMENT ON TABLE components IS 'note';

UPDATE plan_limits SET features = features WHERE plan = 'pro';

INSERT INTO plan_limits (plan) VALUES ('free') ON CONFLICT DO NOTHING;
