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
	"testing"

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
	rows, err := migDB.Query(`
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
		), chk AS (
			SELECT con.conrelid, unnest(con.conkey) AS attnum,
			       pg_get_constraintdef(con.oid) AS def
			FROM pg_constraint con WHERE con.contype = 'c'
		)
		SELECT cols.relname, cols.attname, cols.maxlen, l.lit
		FROM cols
		JOIN chk ON chk.conrelid = cols.relid AND chk.attnum = cols.attnum
		CROSS JOIN LATERAL (
			SELECT (regexp_matches(chk.def, '''([^'']*)''', 'g'))[1] AS lit
		) l
		WHERE length(l.lit) > cols.maxlen
		ORDER BY 1, 2, 4`)
	if err != nil {
		t.Fatalf("catalogue query: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var rel, col, lit string
		var maxlen int
		if err := rows.Scan(&rel, &col, &maxlen, &lit); err != nil {
			t.Fatal(err)
		}
		n++
		t.Errorf("%s.%s is limited to %d characters but its CHECK allows %q (%d)", rel, col, maxlen, lit, len(lit))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("checked: %d over-long CHECK literal(s)", n)
}
