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
		c VARCHAR(20) CHECK (c IN ('short', '12345678901234567890''x')))`); err != nil {
		t.Fatal(err)
	}
	got := overlongCheckLiterals(t, tx)
	want := `m68_guard_probe.c is limited to 20 characters but its CHECK allows "12345678901234567890'x" (22)`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("guard found %q, want exactly [%q]", got, want)
	}
}

type catalogueQueryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// overlongCheckLiterals lists every CHECK literal longer than its
// length-limited character column. Literals are parsed in Go from
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
		                      AND cols.attnum = ANY (con.conkey)
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
		for _, lit := range sqlStringLiterals(def) {
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

func sqlStringLiterals(def string) []string {
	var out []string
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
		out = append(out, b.String())
		i = j
	}
	return out
}
