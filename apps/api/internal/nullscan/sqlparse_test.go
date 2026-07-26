package nullscan

import (
	"strings"
	"testing"
)

// TestAnalyzeSQLNullability drives the SQL layer directly (no go/packages):
// each case asserts per-projection nullability or an unanalyzable error.
func TestAnalyzeSQLNullability(t *testing.T) {
	schema := testSchema()

	type want struct {
		nullable bool
		known    bool
	}
	cases := []struct {
		name string
		sql  string
		want []want
		err  string // substring of expected error ("" = no error)
	}{
		{
			name: "plain columns",
			sql:  `SELECT id, name, description FROM things`,
			want: []want{{false, true}, {false, true}, {true, true}},
		},
		{
			name: "coalesce guards",
			sql:  `SELECT COALESCE(description, ''), COALESCE(score, 0) FROM things`,
			want: []want{{false, true}, {false, true}},
		},
		{
			name: "coalesce all nullable stays nullable",
			sql:  `SELECT COALESCE(description, NULL) FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "left join makes NOT NULL columns nullable",
			sql: `SELECT t.name, r.id, r.thing_id FROM things t
			      LEFT JOIN refs r ON r.thing_id = t.id`,
			want: []want{{false, true}, {true, true}, {true, true}},
		},
		{
			name: "right join flips the other side",
			sql: `SELECT t.name, r.id FROM things t
			      RIGHT JOIN refs r ON r.thing_id = t.id`,
			want: []want{{true, true}, {false, true}},
		},
		{
			name: "aggregates without GROUP BY",
			sql:  `SELECT COUNT(*), MAX(created_at), SUM(score) FROM things`,
			want: []want{{false, true}, {true, true}, {true, true}},
		},
		{
			name: "aggregates with GROUP BY",
			sql:  `SELECT owner_id, MAX(created_at), MAX(score) FROM things GROUP BY owner_id`,
			want: []want{{true, true}, {false, true}, {true, true}},
		},
		{
			name: "count filter stays non-null",
			sql:  `SELECT COUNT(*) FILTER (WHERE score > 1) FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "sum filter nullable even with GROUP BY",
			sql:  `SELECT SUM(id) FILTER (WHERE label = 'x') FROM refs GROUP BY thing_id`,
			want: []want{{true, true}},
		},
		{
			name: "cast strips",
			sql:  `SELECT created_at::date, description::text FROM things`,
			want: []want{{false, true}, {true, true}},
		},
		{
			name: "case with else and non-null branches",
			sql:  `SELECT CASE WHEN score > 1 THEN 'a' ELSE 'b' END FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "case without else",
			sql:  `SELECT CASE WHEN score > 1 THEN 'a' END FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "is null predicate is boolean",
			sql:  `SELECT description IS NOT NULL FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "nullif is nullable",
			sql:  `SELECT NULLIF(name, '') FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "json extraction nullable",
			sql:  `SELECT name::jsonb ->> 'k' FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "scalar count subquery non-null",
			sql:  `SELECT (SELECT COUNT(*) FROM refs) FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "scalar non-count subquery nullable",
			sql:  `SELECT (SELECT label FROM refs LIMIT 1) FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "cte propagation",
			sql: `WITH w AS (SELECT description AS d, name FROM things)
			      SELECT d, name FROM w`,
			want: []want{{true, true}, {false, true}},
		},
		{
			name: "returning list",
			sql:  `INSERT INTO things (id, name) VALUES ($1, $2) RETURNING id, deleted_at`,
			want: []want{{false, true}, {true, true}},
		},
		{
			name: "update returning with FROM clause",
			sql: `WITH prev AS (SELECT id, deleted_at FROM things)
			      UPDATE things t SET name = $1 FROM prev
			      WHERE prev.id = t.id RETURNING prev.deleted_at`,
			want: []want{{true, true}},
		},
		{
			name: "distinct on",
			sql:  `SELECT DISTINCT ON (name) name, score FROM things ORDER BY name, score DESC`,
			want: []want{{false, true}, {true, true}},
		},
		{
			name: "string concat strict",
			sql:  `SELECT name || 'x', description || 'x' FROM things`,
			want: []want{{false, true}, {true, true}},
		},
		{
			name: "exists non-null",
			sql:  `SELECT EXISTS(SELECT 1 FROM refs) FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "select star over subquery",
			sql:  `SELECT * FROM (SELECT name, description FROM things) sub`,
			want: []want{{false, true}, {true, true}},
		},
		{
			name: "bare column ambiguity across joins agrees",
			sql:  `SELECT label FROM things t LEFT JOIN refs r ON r.thing_id = t.id`,
			want: []want{{true, true}},
		},
		{
			name: "union rejected",
			sql:  `SELECT id FROM things UNION SELECT id FROM refs`,
			err:  "set operation",
		},
		{
			name: "select star over real table rejected",
			sql:  `SELECT * FROM things`,
			err:  "cannot be expanded",
		},
		{
			name: "unknown table",
			sql:  `SELECT foo FROM not_a_table`,
			want: []want{{false, false}},
		},
		{
			name: "dynamic fragment in projection rejected",
			sql:  `SELECT ` + DynMarker + ` FROM things`,
			err:  "dynamic fragment",
		},
		{
			name: "dynamic fragment in tail tolerated",
			sql:  `SELECT description FROM things WHERE x = ` + DynMarker + ` ORDER BY ` + DynMarker,
			want: []want{{true, true}},
		},
		{
			name: "arithmetic tail is not an alias",
			sql:  `SELECT score - 1 FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "AT TIME ZONE is honestly unanalyzable",
			sql:  `SELECT created_at AT TIME ZONE 'utc' FROM things`,
			want: []want{{false, false}},
		},
		{
			name: "bare column with opaque source in scope is unanalyzable",
			sql:  `SELECT name FROM things, generate_series(1, 2) g`,
			want: []want{{false, false}},
		},
		{
			name: "quoted string escape and numeric literals",
			sql:  `SELECT 'it''s', 1.5e-3, name FROM things`,
			want: []want{{false, true}, {false, true}, {false, true}},
		},
		{
			name: "extract epoch does not misread the field name",
			sql:  `SELECT EXTRACT(EPOCH FROM created_at) / 3600 FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "extract over nullable stays nullable",
			sql:  `SELECT EXTRACT(EPOCH FROM deleted_at) FROM things`,
			want: []want{{true, true}},
		},
		{
			// gemini-r1 #1: IN-list elements must be evaluated
			name: "IN with nullable list element is nullable",
			sql:  `SELECT name IN (description, 'x') FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "IN with literal list over non-null lhs is non-null",
			sql:  `SELECT name IN ('a', 'b') FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "BETWEEN with nullable bound is nullable",
			sql:  `SELECT id BETWEEN score AND 10 FROM things`,
			want: []want{{true, true}},
		},
		{
			// gemini-r1 #4: schema-qualified cast must not become a column ref
			name: "schema-qualified cast strips cleanly",
			sql:  `SELECT name::public.citext FROM things`,
			want: []want{{false, true}},
		},
		{
			// gemini-r2 #1: HAVING can empty a COUNT subquery => NULL
			name: "count subquery with HAVING is nullable",
			sql:  `SELECT (SELECT COUNT(*) FROM refs HAVING COUNT(*) > 10) FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "count subquery with LIMIT is nullable",
			sql:  `SELECT (SELECT COUNT(*) FROM refs LIMIT 1) FROM things`,
			want: []want{{true, true}},
		},
		{
			// gemini-r2 #3: schema-qualified RETURNING target
			name: "schema-qualified insert returning",
			sql:  `INSERT INTO public.things (id, name) VALUES ($1, $2) RETURNING name, deleted_at`,
			want: []want{{false, true}, {true, true}},
		},
		{
			// gemini-r4 #1: operators after END must not be dropped
			name: "CASE plus nullable trailing operand is nullable",
			sql:  `SELECT CASE WHEN id > '' THEN 1 ELSE 2 END + score FROM things`,
			want: []want{{true, true}},
		},
		{
			name: "CASE plus non-null trailing operand stays non-null",
			sql:  `SELECT CASE WHEN id > '' THEN 1 ELSE 2 END + 5 FROM things`,
			want: []want{{false, true}},
		},
		{
			name: "ARRAY concat with nullable operand is nullable",
			sql:  `SELECT ARRAY[1, 2] || score FROM things`,
			want: []want{{true, true}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cols, err := analyzeSQL(tc.sql, schema)
			if tc.err != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got cols %+v", tc.err, cols)
				}
				if !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("expected error containing %q, got %q", tc.err, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cols) != len(tc.want) {
				t.Fatalf("got %d projection columns, want %d: %+v", len(cols), len(tc.want), cols)
			}
			for i, w := range tc.want {
				if cols[i].known != w.known {
					t.Errorf("col %d (%s): known=%v want %v (reason: %s)", i, cols[i].expr, cols[i].known, w.known, cols[i].reason)
					continue
				}
				if w.known && cols[i].nullable != w.nullable {
					t.Errorf("col %d (%s): nullable=%v want %v (reason: %s)", i, cols[i].expr, cols[i].nullable, w.nullable, cols[i].reason)
				}
			}
		})
	}
}

func TestSchemaDeterministicMarshal(t *testing.T) {
	s := testSchema()
	s.GeneratedBy = "x"
	a, err := s.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.MarshalDeterministic()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("MarshalDeterministic is not deterministic")
	}
	if !strings.HasSuffix(string(a), "\n") {
		t.Fatal("missing trailing newline")
	}
}
