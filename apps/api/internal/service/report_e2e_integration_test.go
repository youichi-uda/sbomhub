//go:build integration

// Package service — report generation end-to-end integration test
// (M46 Track C-3a).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run TestReportGeneration_E2E ./internal/service
//
// Prerequisites: same env contract as the VEX suggestions integration test
// (DATABASE_URL = sbomhub_app / MIGRATE_DATABASE_URL = sbomhub_migrator,
// schema migrated). Skips otherwise.
//
// What this pins down: the FULL production report pipeline against a real
// RLS-enforcing PostgreSQL — GenerateReport persists the "generating" row
// inside a tenant tx, the post-commit launcher spawns generateReportAsync,
// the goroutine opens its own tenant tx (codex-r5 P2), renders a real
// XLSX / PDF, and the terminal UpdateReport flips the row to "completed"
// with the file bytes stored in the DB. The downloaded XLSX must open in
// excelize and the PDF must be a parsable PDF header — i.e. the M46 error
// collection refactor did not break real-world generation.
//
// C27 leak-gate compliance: the tenant is seeded via seedTenantVS (marker
// clerk_org_id + CASCADE cleanup); the user row seeded for the generated_by
// FK registers its own DELETE cleanup, which runs BEFORE the tenant delete
// (LIFO) and detaches from generated_reports via ON DELETE SET NULL.
package service

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// seedUserRPT inserts a users row for the generated_by FK on
// generated_reports. users is not tenant-scoped (no CASCADE from tenants),
// so it registers its own cleanup.
func seedUserRPT(t *testing.T, migDB *sql.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO users (id, clerk_user_id, email, name) VALUES ($1,$2,$3,$4)`,
		id, "itest-svc-rpt-"+id.String(), "rpt-"+id.String()+"@example.test", "Report E2E User",
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Errorf("C27 cleanup: delete user %s: %v", id, err)
		}
	})
	return id
}

// waitForReportTerminal polls the report row (inside tenant-scoped txes, as a
// live request would) until it leaves the "generating" state.
func waitForReportTerminal(t *testing.T, svc *ReportService, tenantID, reportID uuid.UUID) *model.GeneratedReport {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var got *model.GeneratedReport
		if err := svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
			r, err := svc.GetReport(txCtx, tenantID, reportID)
			got = r
			return err
		}); err != nil {
			t.Fatalf("poll report %s: %v", reportID, err)
		}
		if got != nil && got.Status != model.ReportStatusGenerating && got.Status != model.ReportStatusPending {
			return got
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("report %s did not reach a terminal status within 60s", reportID)
	return nil
}

func TestReportGeneration_E2E_RealPG_XLSXAndPDF(t *testing.T) {
	appURL, migURL := vexSuggestionsTestEnv(t)
	migDB := openOrSkipVS(t, migURL)
	if !schemaReadyVS(t, migDB) {
		return
	}
	// schemaReadyVS predates the report tables — check generated_reports too.
	var exists bool
	if err := migDB.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.tables
			WHERE table_schema='public' AND table_name='generated_reports')`).Scan(&exists); err != nil || !exists {
		t.Skipf("generated_reports not present (err=%v) -- run migrations first", err)
	}
	appDB := openOrSkipVS(t, appURL)

	tenantID := seedTenantVS(t, migDB, "RPT")
	userID := seedUserRPT(t, migDB)

	svc := NewReportService(
		repository.NewReportRepository(appDB),
		repository.NewDashboardRepository(appDB),
		repository.NewAnalyticsRepository(appDB),
		repository.NewTenantRepository(appDB),
		repository.NewChecklistRepository(appDB),
		repository.NewVisualizationRepository(appDB),
		t.TempDir(),
	)
	svc.SetDB(appDB)

	cases := []struct {
		format string
		verify func(t *testing.T, content []byte)
	}{
		{model.ReportFormatXLSX, func(t *testing.T, content []byte) {
			f, err := excelize.OpenReader(bytes.NewReader(content))
			if err != nil {
				t.Fatalf("stored XLSX bytes are not a readable workbook: %v", err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					t.Errorf("close workbook: %v", err)
				}
			}()
			tr := GetTranslations("ja")
			if v, err := f.GetCellValue(tr.SheetSummary, "A1"); err != nil || v != tr.TitleExecutive {
				t.Fatalf("summary title = %q err = %v, want %q", v, err, tr.TitleExecutive)
			}
		}},
		{model.ReportFormatPDF, func(t *testing.T, content []byte) {
			if !bytes.HasPrefix(content, []byte("%PDF-")) {
				t.Fatalf("stored PDF bytes do not start with %%PDF- (got %q...)", content[:minInt(8, len(content))])
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			// 1. Create the "generating" row inside a tenant tx, exactly as the
			// handler/scheduler paths do, and get the post-commit launcher.
			var report *model.GeneratedReport
			var launcher func()
			if err := svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
				r, l, err := svc.GenerateReport(txCtx, tenantID, userID, model.GenerateReportInput{
					ReportType: model.ReportTypeExecutive,
					Format:     tc.format,
					Locale:     "ja",
				})
				report, launcher = r, l
				return err
			}); err != nil {
				t.Fatalf("GenerateReport: %v", err)
			}

			// 2. Parent tx has committed — fire the launcher (scheduler path).
			launcher()

			// 3. The async goroutine must flip the row to "completed".
			got := waitForReportTerminal(t, svc, tenantID, report.ID)
			if got.Status != model.ReportStatusCompleted {
				t.Fatalf("report status = %q (error_message=%q), want %q",
					got.Status, got.ErrorMessage, model.ReportStatusCompleted)
			}

			// 4. Download through the service API and verify the payload is a
			// real, openable document.
			var content []byte
			var filename string
			if err := svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
				c, fn, err := svc.GetReportFile(txCtx, tenantID, report.ID)
				content, filename = c, fn
				return err
			}); err != nil {
				t.Fatalf("GetReportFile: %v", err)
			}
			if !strings.HasSuffix(filename, "."+tc.format) {
				t.Fatalf("filename = %q, want *.%s", filename, tc.format)
			}
			if len(content) == 0 {
				t.Fatal("report content is empty")
			}
			tc.verify(t, content)
		})
	}
}
