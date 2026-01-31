-- Rollback SSVC integration

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS ssvc_decision;

DROP TABLE IF EXISTS ssvc_assessment_history;
DROP TABLE IF EXISTS ssvc_assessments;
DROP TABLE IF EXISTS ssvc_project_defaults;

DROP TYPE IF EXISTS ssvc_decision;
DROP TYPE IF EXISTS ssvc_safety_impact;
DROP TYPE IF EXISTS ssvc_mission_prevalence;
DROP TYPE IF EXISTS ssvc_technical_impact;
DROP TYPE IF EXISTS ssvc_automatable;
DROP TYPE IF EXISTS ssvc_exploitation;
