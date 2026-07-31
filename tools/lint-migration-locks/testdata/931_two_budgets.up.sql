-- Two uncovered statements with DIFFERENT causes: the first has no
-- budget in force at all, the third has one that was reset to zero.
-- Each finding must name its own cause.
ALTER TABLE a_tbl ADD COLUMN x INTEGER;

SET LOCAL lock_timeout = '5s';

ALTER TABLE b_tbl ADD COLUMN x INTEGER;

SET LOCAL lock_timeout = '0';

ALTER TABLE c_tbl ADD COLUMN x INTEGER;
