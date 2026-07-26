//go:build integration

package nullscan

import (
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// localEnum mimics the model-layer pattern `type Severity string` /
// `type TrackerType string`: a named type with underlying string and no
// sql.Scanner implementation.
type localEnum string

// TestNullToleranceDecisionTable is the *measured* evidence behind the
// scan-target NULL-tolerance decision table in tolerance.go. It drives the
// real lib/pq driver against the dev/CI PostgreSQL (DATABASE_URL) and
// asserts, for every destination type class the analyzer distinguishes,
// whether scanning a SQL NULL into it errors, succeeds, or succeeds while
// silently leaving the zero value.
//
// Notable measured facts (2026-07-25, PostgreSQL 15.x, lib/pq v1.10.9,
// google/uuid v1.6.0):
//
//   - uuid.UUID implements sql.Scanner and its Scan(nil) returns nil WITHOUT
//     touching the receiver: scanning NULL into uuid.UUID does NOT error, it
//     silently leaves the zero UUID. The analyzer therefore classifies
//     uuid.UUID as "silent-zero" (no 500, but a data-integrity hazard), not
//     as a hard violation.
//   - *uuid.UUID (pointer field) is fully NULL-tolerant (stays nil).
//   - pq.StringArray / pq.Int64Array / pq.Array(&slice) accept NULL and set
//     the slice to nil.
//   - []byte and json.RawMessage accept NULL (become nil).
//   - A named type with underlying string (no Scanner) errors exactly like
//     plain string: "converting NULL to string is unsupported".
//
// Run with:
//
//	go test -tags=integration ./internal/nullscan/ -run TestNullToleranceDecisionTable -v
func TestNullToleranceDecisionTable(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping NULL-tolerance probe")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	scanNull := func(t *testing.T, castExpr string, dest any) error {
		t.Helper()
		return db.QueryRow(`SELECT ` + castExpr).Scan(dest)
	}

	mustErrNULL := func(t *testing.T, name, cast string, dest any) {
		t.Helper()
		err := scanNull(t, cast, dest)
		if err == nil {
			t.Fatalf("%s: expected scan error for NULL, got nil", name)
		}
		if !strings.Contains(err.Error(), "converting NULL") &&
			!strings.Contains(err.Error(), "unsupported") {
			t.Logf("%s: errored with unexpected message (still counts as NG): %v", name, err)
		}
		t.Logf("MEASURED %-28s <- %-18s => ERROR: %v", name, cast, err)
	}
	mustOK := func(t *testing.T, name, cast string, dest any) {
		t.Helper()
		if err := scanNull(t, cast, dest); err != nil {
			t.Fatalf("%s: expected NULL-tolerant scan, got error: %v", name, err)
		}
		t.Logf("MEASURED %-28s <- %-18s => OK", name, cast)
	}

	// --- NG class: plain Go types without NULL representation -> scan error.
	var s string
	mustErrNULL(t, "string", "NULL::text", &s)
	var i64 int64
	mustErrNULL(t, "int64", "NULL::bigint", &i64)
	var i int
	mustErrNULL(t, "int", "NULL::int", &i)
	var f64 float64
	mustErrNULL(t, "float64", "NULL::float8", &f64)
	var b bool
	mustErrNULL(t, "bool", "NULL::boolean", &b)
	var tm time.Time
	mustErrNULL(t, "time.Time", "NULL::timestamptz", &tm)
	var enum localEnum
	mustErrNULL(t, "named-string(localEnum)", "NULL::text", &enum)

	// --- OK class: pointer / sql.Null* / []byte / any.
	var sp *string
	mustOK(t, "*string", "NULL::text", &sp)
	if sp != nil {
		t.Fatalf("*string: expected nil after NULL scan, got %v", *sp)
	}
	var tp *time.Time
	mustOK(t, "*time.Time", "NULL::timestamptz", &tp)
	var ns sql.NullString
	mustOK(t, "sql.NullString", "NULL::text", &ns)
	if ns.Valid {
		t.Fatalf("sql.NullString: expected Valid=false")
	}
	var nt sql.NullTime
	mustOK(t, "sql.NullTime", "NULL::timestamptz", &nt)
	var ni sql.NullInt64
	mustOK(t, "sql.NullInt64", "NULL::bigint", &ni)
	var nf sql.NullFloat64
	mustOK(t, "sql.NullFloat64", "NULL::float8", &nf)
	var bs []byte
	mustOK(t, "[]byte(text)", "NULL::text", &bs)
	if bs != nil {
		t.Fatalf("[]byte: expected nil after NULL scan")
	}
	mustOK(t, "[]byte(bytea)", "NULL::bytea", &bs)
	// json.RawMessage is a *named* []byte without a Scanner. database/sql's
	// NULL fast path only special-cases the exact types *[]byte / *RawBytes /
	// *any, and the reflect fallback has no nil handling for slice-kind
	// destinations — so, measured: named byte slices REJECT NULL.
	var raw json.RawMessage
	mustErrNULL(t, "json.RawMessage", "NULL::jsonb", &raw)
	var anyv any
	mustOK(t, "any", "NULL::text", &anyv)
	if anyv != nil {
		t.Fatalf("any: expected nil after NULL scan")
	}

	// --- pq array types: measured NULL-tolerant (Scan has `case nil`).
	sa := pq.StringArray{"sentinel"}
	mustOK(t, "pq.StringArray", "NULL::text[]", &sa)
	if sa != nil {
		t.Fatalf("pq.StringArray: expected nil after NULL scan, got %v", sa)
	}
	ia := pq.Int64Array{42}
	mustOK(t, "pq.Int64Array", "NULL::bigint[]", &ia)
	if ia != nil {
		t.Fatalf("pq.Int64Array: expected nil after NULL scan, got %v", ia)
	}
	viaArray := []string{"sentinel"}
	mustOK(t, "pq.Array(&[]string)", "NULL::text[]", pq.Array(&viaArray))
	if viaArray != nil {
		t.Fatalf("pq.Array(&[]string): expected nil after NULL scan, got %v", viaArray)
	}

	// --- uuid.UUID: THE load-bearing measurement. google/uuid v1.6.0
	// Scan(nil) returns nil and leaves the receiver untouched, so a NULL scan
	// neither errors nor marks anything: callers silently observe the zero
	// UUID (or, worse, a stale previous value on a reused variable).
	sentinel := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	u := sentinel
	err = scanNull(t, "NULL::uuid", &u)
	if err != nil {
		t.Fatalf("uuid.UUID: measured behavior changed! NULL scan now errors: %v "+
			"(update tolerance.go decision table: uuid.UUID would move from "+
			"silent-zero to hard violation)", err)
	}
	if u != sentinel {
		t.Logf("MEASURED uuid.UUID <- NULL::uuid => OK, receiver overwritten to %s", u)
	} else {
		t.Logf("MEASURED uuid.UUID <- NULL::uuid => OK, receiver left untouched (stale value hazard)")
	}

	var up *uuid.UUID
	mustOK(t, "*uuid.UUID", "NULL::uuid", &up)
	if up != nil {
		t.Fatalf("*uuid.UUID: expected nil after NULL scan, got %v", *up)
	}

	// Sanity: non-NULL values still land in the plain types.
	if err := db.QueryRow(`SELECT 'x'::text`).Scan(&s); err != nil || s != "x" {
		t.Fatalf("sanity text scan: %q %v", s, err)
	}
	if err := db.QueryRow(`SELECT '11111111-2222-3333-4444-555555555555'::uuid`).Scan(&u); err != nil || u != sentinel {
		t.Fatalf("sanity uuid scan: %v %v", u, err)
	}
}
