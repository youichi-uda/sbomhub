-- A relation whose name ends in `_cascade` must not have that suffix
-- eaten by the CASCADE/RESTRICT trailing-keyword strip.
DROP TABLE IF EXISTS audit_cascade;
