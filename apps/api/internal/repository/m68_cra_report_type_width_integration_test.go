//go:build integration

// Package repository — migration 068: cra_reports.report_type must hold
// every report type the CHECK constraint allows.
//
// Migration 038 declared report_type VARCHAR(20) with
// CHECK (report_type IN ('early_warning', 'detailed_notification',
// 'final_report')). 'detailed_notification' is 21 characters, so every 72h
// report insert failed with pq 22001 (value too long) and the
// POST /cra/reports route answered 500.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M68' ./internal/repository
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/database"
)

// Every report type the runner emits (service/cra.ReportType*) round-trips
// through the repository. The literals are spelled out because importing
// service/cra from this package would be an import cycle; the companion
// catalogue test below covers any value added to the CHECK later.
func TestM68CRAReports_EveryReportTypeInserts(t *testing.T) {
	appURL, migURL := craReportsTestEnv(t)
	migDB := openOrSkipCRAReports(t, migURL)
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	appDB := openOrSkipCRAReports(t, appURL)
	tenantID := seedTenantForCRAReports(t, migDB, "M68")
	repo := NewCRAReportsRepository(appDB)

	for _, rt := range []string{"early_warning", "detailed_notification", "final_report"} {
		t.Run(rt, func(t *testing.T) {
			tx, err := appDB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
				t.Fatal(err)
			}
			ctx := database.WithTx(context.Background(), tx)
			id := uuid.New()
			if err := repo.Insert(ctx, &CRAReport{
				ID:              id,
				TenantID:        tenantID,
				ProjectID:       uuid.New(),
				VulnerabilityID: uuid.New(),
				CVEID:           "CVE-2026-0068",
				ReportType:      rt,
				Lang:            "en",
				DraftText:       "m68 body",
				Evidence:        validCRAEvidence(),
			}); err != nil {
				t.Fatalf("Insert report_type=%q: %v", rt, err)
			}
			got, err := repo.Get(ctx, tenantID, id)
			if err != nil || got == nil {
				t.Fatalf("Get: %v (row=%v)", err, got)
			}
			if got.ReportType != rt {
				t.Fatalf("report_type round-trip: got %q want %q", got.ReportType, rt)
			}
		})
	}
}

// Schema-wide guard for the whole defect class: no CHECK constraint on a
// length-limited character column may allow a literal longer than the
// column. Such a value passes the CHECK in review and fails only at runtime
// with 22001.
func TestM68Schema_NoCheckLiteralExceedsColumnWidth(t *testing.T) {
	_, migURL := craReportsTestEnv(t)
	migDB := openOrSkipCRAReports(t, migURL)
	if !schemaReadyCRAReports(t, migDB) {
		return
	}
	for _, v := range overlongCheckLiterals(t, migDB) {
		t.Error(v)
	}
}

// The guard must see a literal that contains a quote (deparsed as '...”...'):
// Codex R3 showed a regex that stopped at the doubled quote split
// '12345678901234567890”x' (22 characters) into a 20- and a 1-character
// fragment and passed a VARCHAR(20) column that cannot hold it.
func TestM68Schema_GuardSeesQuotedLiterals(t *testing.T) {
	_, migURL := craReportsTestEnv(t)
	migDB := openOrSkipCRAReports(t, migURL)
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`CREATE TABLE m68_guard_probe (
		c VARCHAR(20) CHECK (c IN ('short', '12345678901234567890''x')),
		d VARCHAR(20) CHECK ('123456789012345678901' = d OR d = 'ok'))`); err != nil {
		t.Fatal(err)
	}
	// Codex R5: no false positives. A multi-column CHECK compares each literal
	// with ONE of its columns, and a pattern literal (regex / LIKE) is not a
	// value the column must hold.
	if _, err := tx.Exec(`CREATE TABLE m68_guard_probe_ok (
		short VARCHAR(3), state VARCHAR(32),
		CHECK (short = 'ok' AND state = 'detailed_notification'),
		CHECK (short ~ '^[a-z]{1,3}$' AND short NOT LIKE 'xxxxxxxxxxxxxxxx%'),
		CHECK (state IN ('early_warning', 'detailed_notification')))`); err != nil {
		t.Fatal(err)
	}
	got := overlongCheckLiterals(t, tx)
	want := []string{
		`m68_guard_probe.c is limited to 20 characters but its CHECK allows "12345678901234567890'x" (22)`,
		// Codex R6: the literal on the LEFT of the comparison.
		`m68_guard_probe.d is limited to 20 characters but its CHECK allows "123456789012345678901" (21)`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("guard found %q, want exactly %q", got, want)
	}
}

type catalogueQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// overlongCheckLiterals lists every CHECK value literal longer than its
// length-limited character column. Only single-column CHECKs are judged (in a
// multi-column one the catalogue does not say which literal belongs to which
// column); every enum-like CHECK in this schema is single-column. Literals are parsed in Go from
// pg_get_constraintdef: a '...' run with ” as an escaped quote (the
// deparser always emits standard-conforming strings).
func overlongCheckLiterals(t *testing.T, db catalogueQueryer) []string {
	t.Helper()
	rows, err := db.Query(`
		WITH cols AS (
			SELECT c.oid AS relid, c.relname, a.attname, a.attnum,
			       a.atttypmod - 4 AS maxlen
			FROM pg_attribute a
			JOIN pg_class c ON c.oid = a.attrelid
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
			  AND a.attnum > 0 AND NOT a.attisdropped
			  AND a.atttypid IN ('varchar'::regtype, 'bpchar'::regtype)
			  AND a.atttypmod > 0
		)
		SELECT cols.relname, cols.attname, cols.maxlen, pg_get_constraintdef(con.oid)
		FROM cols
		JOIN pg_constraint con ON con.conrelid = cols.relid AND con.contype = 'c'
		                      AND con.conkey = ARRAY[cols.attnum]::int2[]
		ORDER BY 1, 2`)
	if err != nil {
		t.Fatalf("catalogue query: %v", err)
	}
	defer rows.Close()
	var out []string
	checked := 0
	for rows.Next() {
		var rel, col, def string
		var maxlen int
		if err := rows.Scan(&rel, &col, &maxlen, &def); err != nil {
			t.Fatal(err)
		}
		for _, lit := range sqlValueLiterals(def) {
			checked++
			if n := utf8.RuneCountInString(lit); n > maxlen {
				out = append(out, fmt.Sprintf("%s.%s is limited to %d characters but its CHECK allows %q (%d)", rel, col, maxlen, lit, n))
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("guard checked no CHECK literal at all; the catalogue query is blind")
	}
	return out
}

// sqlValueLiterals returns the literals of def that are VALUES the column is
// compared with: an operand of = / <> or an element of an IN / ARRAY list
// (deparsed as `= ANY ((ARRAY['a'::…, 'b'::…])::text[])`), on either side of
// the operator. Pattern operands
// (~, LIKE / ~~) are skipped — a regex is not a value the column holds.
func sqlValueLiterals(def string) []string {
	var out []string
	for _, l := range sqlStringLiterals(def) {
		before := strings.TrimRight(def[:l.start], " (")
		after := strings.TrimLeft(skipCast(def[l.end:]), " )")
		if strings.HasSuffix(before, "=") || strings.HasSuffix(before, "<>") ||
			strings.HasSuffix(before, "ARRAY[") || strings.HasSuffix(before, ",") ||
			strings.HasPrefix(after, "=") || strings.HasPrefix(after, "<>") {
			out = append(out, l.text)
		}
	}
	return out
}

// skipCast drops a leading `::type` cast (possibly `::character varying`,
// possibly followed by `)` and further casts) from s.
func skipCast(s string) string {
	for {
		t := strings.TrimLeft(s, ")")
		if !strings.HasPrefix(t, "::") {
			return s
		}
		t = t[2:]
		i := 0
		for i < len(t) && (t[i] == '_' || t[i] == ' ' || t[i] == '[' || t[i] == ']' ||
			(t[i] >= 'a' && t[i] <= 'z') || (t[i] >= '0' && t[i] <= '9')) {
			i++
		}
		s = t[i:]
	}
}

type sqlLiteral struct {
	start int // offset of the opening quote
	end   int // offset just past the closing quote
	text  string
}

func sqlStringLiterals(def string) []sqlLiteral {
	var out []sqlLiteral
	for i := 0; i < len(def); i++ {
		if def[i] != '\'' {
			continue
		}
		var b strings.Builder
		j := i + 1
		for ; j < len(def); j++ {
			if def[j] == '\'' {
				if j+1 < len(def) && def[j+1] == '\'' {
					b.WriteByte('\'')
					j++
					continue
				}
				break
			}
			b.WriteByte(def[j])
		}
		out = append(out, sqlLiteral{start: i, end: j + 1, text: b.String()})
		i = j
	}
	return out
}
