// Package q is the nullscan unit-test corpus. Each function exercises one
// analyzer behavior; nullscan_test.go asserts the exact findings.
//
// Schema used by the test (defined in nullscan_test.go, not schema.json):
//
//	things:  id uuid NOT NULL, owner_id uuid NULL, name text NOT NULL,
//	         description text NULL, score float8 NULL,
//	         created_at timestamptz NOT NULL, deleted_at timestamptz NULL
//	refs:    id bigint NOT NULL, thing_id uuid NOT NULL, label text NULL
package q

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// simpleViolation: DDL-nullable description into plain string.
func simpleViolation(ctx context.Context, db *sql.DB) (string, string, error) {
	var name, desc string
	err := db.QueryRowContext(ctx,
		`SELECT name, description FROM things WHERE id = $1`, 1,
	).Scan(&name, &desc)
	return name, desc, err
}

// coalesceOK: the B1 fix pattern must be clean.
func coalesceOK(ctx context.Context, db *sql.DB) (string, error) {
	var desc string
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(description, '') FROM things WHERE id = $1`, 1,
	).Scan(&desc)
	return desc, err
}

// pointerAndNullTypesOK: NULL-tolerant destinations must be clean.
func pointerAndNullTypesOK(ctx context.Context, db *sql.DB) error {
	var desc *string
	var score sql.NullFloat64
	var deletedAt *time.Time
	var raw []byte
	return db.QueryRowContext(ctx,
		`SELECT description, score, deleted_at, description FROM things`,
	).Scan(&desc, &score, &deletedAt, &raw)
}

// leftJoinNullSide: refs.id is NOT NULL in DDL but nullable through the
// LEFT JOIN.
func leftJoinNullSide(ctx context.Context, db *sql.DB) error {
	var name string
	var refID int64
	return db.QueryRowContext(ctx, `
		SELECT t.name, r.id
		FROM things t
		LEFT JOIN refs r ON r.thing_id = t.id
		WHERE t.id = $1`, 1,
	).Scan(&name, &refID)
}

// innerJoinSafe: same shape with INNER JOIN must be clean.
func innerJoinSafe(ctx context.Context, db *sql.DB) error {
	var name string
	var refID int64
	return db.QueryRowContext(ctx, `
		SELECT t.name, r.id
		FROM things t
		JOIN refs r ON r.thing_id = t.id
		WHERE t.id = $1`, 1,
	).Scan(&name, &refID)
}

// aggregateNull: MAX over zero rows is NULL; COUNT never is.
func aggregateNull(ctx context.Context, db *sql.DB) error {
	var maxScore float64
	var n int
	return db.QueryRowContext(ctx,
		`SELECT MAX(score), COUNT(*) FROM things`,
	).Scan(&maxScore, &n)
}

// groupedAggregate: with GROUP BY the group is never empty, so
// MAX(created_at) (NOT NULL arg) is safe but MAX(score) (nullable arg)
// still is not.
func groupedAggregate(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `
		SELECT owner_id, MAX(created_at), MAX(score)
		FROM things
		GROUP BY owner_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var owner *string
		var latest time.Time
		var best float64
		if err := rows.Scan(&owner, &latest, &best); err != nil {
			return err
		}
	}
	return rows.Err()
}

// caseWithoutElse yields NULL when no branch matches.
func caseWithoutElse(ctx context.Context, db *sql.DB) error {
	var label string
	return db.QueryRowContext(ctx,
		`SELECT CASE WHEN score > 5 THEN 'hot' END FROM things`,
	).Scan(&label)
}

// countMismatch: projection width 2, one Scan arg => unanalyzable.
func countMismatch(ctx context.Context, db *sql.DB) error {
	var id string
	return db.QueryRowContext(ctx,
		`SELECT id, name FROM things`,
	).Scan(&id)
}

// dynamicSQL: the SQL comes in as a parameter => unanalyzable.
func dynamicSQL(ctx context.Context, db *sql.DB, query string) error {
	var id string
	return db.QueryRowContext(ctx, query).Scan(&id)
}

// sprintfTail: dynamic fragment only in the WHERE tail stays analyzable.
func sprintfTail(ctx context.Context, db *sql.DB, argIndex int) error {
	query := fmt.Sprintf(`SELECT description FROM things WHERE name = $%d`, argIndex)
	var desc string
	return db.QueryRowContext(ctx, query).Scan(&desc)
}

// conditionalWhere: the += append fork must not lose the projection.
func conditionalWhere(ctx context.Context, db *sql.DB, filter string) error {
	query := `SELECT name, description FROM things WHERE 1=1`
	if filter != "" {
		query += ` AND name = $1`
	}
	rows, err := db.QueryContext(ctx, query, filter)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, desc string
		if err := rows.Scan(&name, &desc); err != nil {
			return err
		}
	}
	return rows.Err()
}

// uuidSilentZero: nullable owner_id into uuid.UUID => warning, not violation.
func uuidSilentZero(ctx context.Context, db *sql.DB) error {
	var owner uuid.UUID
	return db.QueryRowContext(ctx,
		`SELECT owner_id FROM things WHERE id = $1`, 1,
	).Scan(&owner)
}

// uuidPointerOK: *uuid.UUID is fully tolerant.
func uuidPointerOK(ctx context.Context, db *sql.DB) error {
	var owner *uuid.UUID
	return db.QueryRowContext(ctx,
		`SELECT owner_id FROM things WHERE id = $1`, 1,
	).Scan(&owner)
}

// namedByteSlice: json.RawMessage rejects NULL (measured) => violation.
func namedByteSlice(ctx context.Context, db *sql.DB) error {
	var payload json.RawMessage
	return db.QueryRowContext(ctx,
		`SELECT description FROM things`,
	).Scan(&payload)
}

// customScanner implements sql.Scanner and is assumed tolerant.
type customScanner struct{ v string }

func (c *customScanner) Scan(src any) error { return nil }

func scannerOK(ctx context.Context, db *sql.DB) error {
	var c customScanner
	return db.QueryRowContext(ctx,
		`SELECT description FROM things`,
	).Scan(&c)
}

// returningViolation: INSERT ... RETURNING a nullable column into time.Time.
func returningViolation(ctx context.Context, db *sql.DB) error {
	var deletedAt time.Time
	return db.QueryRowContext(ctx, `
		INSERT INTO things (id, name) VALUES ($1, $2)
		RETURNING deleted_at`, 1, "x",
	).Scan(&deletedAt)
}

// cteFlow: CTE column nullability propagates.
func cteFlow(ctx context.Context, db *sql.DB) error {
	var d string
	return db.QueryRowContext(ctx, `
		WITH w AS (
			SELECT description AS d FROM things
		)
		SELECT d FROM w`,
	).Scan(&d)
}

// subqueryStar: SELECT * over a subquery expands to its columns.
func subqueryStar(ctx context.Context, db *sql.DB) error {
	var name, desc string
	return db.QueryRowContext(ctx, `
		SELECT * FROM (
			SELECT name, description FROM things
		) sub LIMIT 1`,
	).Scan(&name, &desc)
}

// scalarCountSubquery is always one non-NULL row => clean.
func scalarCountSubquery(ctx context.Context, db *sql.DB) error {
	var n int
	return db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM refs WHERE thing_id = things.id) AS n FROM things`,
	).Scan(&n)
}

// jsonExtraction can always be NULL.
func jsonExtraction(ctx context.Context, db *sql.DB) error {
	var v string
	return db.QueryRowContext(ctx,
		`SELECT name::jsonb ->> 'k' FROM things`,
	).Scan(&v)
}

// rowsVarReuse: the same rows variable feeds two sequential queries of equal
// width; each Scan must pair only with ITS query (gemini-r1 #3): the first
// reads a nullable column, the second a NOT NULL one.
func rowsVarReuse(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT description FROM things`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var desc string
		if err := rows.Scan(&desc); err != nil { // violation: things.description
			return err
		}
	}
	rows.Close()

	rows, err = db.QueryContext(ctx, `SELECT name FROM things`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil { // clean: things.name NOT NULL
			return err
		}
	}
	return rows.Err()
}

// positionalVerb: %[n] positional Sprintf verbs would silently mis-map
// arguments, so the resolver must refuse (unanalyzable), never emit wrong
// SQL (gemini-r2 #2).
func positionalVerb(ctx context.Context, db *sql.DB) error {
	col := "description"
	query := fmt.Sprintf(`SELECT %[1]s FROM things`, col)
	var v string
	return db.QueryRowContext(ctx, query).Scan(&v)
}

// conditionalDynamicBranch: one branch is statically readable, the other is
// not — the unreadable branch must surface as unanalyzable even though the
// readable one matches (gemini-r1 #2).
func conditionalDynamicBranch(ctx context.Context, db *sql.DB, dyn string, useDyn bool) error {
	query := `SELECT name FROM things`
	if useDyn {
		query = dyn
	}
	var name string
	return db.QueryRowContext(ctx, query).Scan(&name)
}
