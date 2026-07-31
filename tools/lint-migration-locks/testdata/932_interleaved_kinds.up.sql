-- An unrecognised statement on line 3 and a non-transactional one on
-- line 4. Findings must come out in source order, not grouped by kind.
NOTIFY sample_channel, 'payload';
CREATE INDEX CONCURRENTLY idx_probe ON components(name);
