package service

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/xuri/excelize/v2"
)

// codex-r5 P2 regression guard.
//
// generateReportAsync runs on a goroutine spawned by GenerateReport. By the
// time the goroutine wakes up, the caller's tenant tx has committed and the
// pool connection it borrowed is back in the pool with no app.current_tenant_id
// GUC set. Without an explicit tenant-scoped tx in the async path,
// repository.q(ctx) degrades to a raw *sql.DB, the RLS WITH CHECK on
// generated_reports rejects the UPDATE, and the report sticks at
// "generating" forever.
//
// These tests pin down the contract for the helpers that hold that fix in
// place: runWithTenantTx and markReportFailed. We do not test generateReportAsync
// end-to-end because its data-gathering side-effects span many repos that
// would require a sprawling mock; the helpers are the load-bearing piece.
func newTestReportService(t *testing.T, db *sql.DB) *ReportService {
	t.Helper()
	// Repositories that are exercised by the helper paths under test.
	// Other repos can stay nil — they are not touched by runWithTenantTx
	// or markReportFailed.
	reportRepo := repository.NewReportRepository(db)
	svc := NewReportService(reportRepo, nil, nil, nil, nil, nil, t.TempDir())
	svc.SetDB(db)
	return svc
}

func TestRunWithTenantTx_PinsTenantAndCommitsOnSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()

	mock.ExpectBegin()
	// The set_config call is the load-bearing line — it must execute before
	// fn runs so any repo call inside fn sees the right RLS context.
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT 1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	svc := newTestReportService(t, db)

	called := false
	err = svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
		called = true
		_, ferr := svc.db.ExecContext(txCtx, "SELECT 1")
		return ferr
	})
	if err != nil {
		t.Fatalf("runWithTenantTx: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRunWithTenantTx_RollsBackOnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	svc := newTestReportService(t, db)

	sentinel := errors.New("downstream failure")
	gotErr := svc.runWithTenantTx(context.Background(), tenantID, func(_ context.Context) error {
		return sentinel
	})
	if !errors.Is(gotErr, sentinel) {
		t.Fatalf("runWithTenantTx err = %v, want %v", gotErr, sentinel)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRunWithTenantTx_NilDBReturnsErrorInsteadOfPanic(t *testing.T) {
	// Belt-and-braces for the "SetDB was never called" branch. We do not
	// want a silent panic from a nil *sql.DB inside WithTxFunc — better to
	// return a clear error so the goroutine's outer logging captures it.
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	err := svc.runWithTenantTx(context.Background(), uuid.New(), func(_ context.Context) error {
		t.Fatal("fn must not be invoked when db is nil")
		return nil
	})
	if err == nil {
		t.Fatal("expected error when db is nil")
	}
}

func TestMarkReportFailed_OpensFreshTenantTxForFailureUpdate(t *testing.T) {
	// This is the codex-r5 P2 core regression guard: after a generation
	// error, the "failed" UPDATE must run inside its own tenant-scoped tx
	// (the generation tx has already rolled back, so re-using it is
	// impossible — and the request-driven path that originally created
	// the row is long gone).
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	reportID := uuid.New()
	report := &model.GeneratedReport{
		ID:       reportID,
		TenantID: tenantID,
		Status:   model.ReportStatusGenerating,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// UpdateReport SQL — match the UPDATE prefix; arg order is fixed by
	// repository.ReportRepository.UpdateReport (id, file_path, file_size,
	// file_content, status, error_message, email_sent_at, email_recipients,
	// completed_at, tenant_id). We assert the status field flipped to
	// "failed" and the error message landed in error_message. tenant_id is
	// the M47 W2 belt (`WHERE id = $1 AND tenant_id = $10`).
	mock.ExpectExec("UPDATE generated_reports").
		WithArgs(
			reportID,
			"",          // file_path
			0,           // file_size
			[]byte(nil), // file_content
			model.ReportStatusFailed,
			"boom",
			(*sql.NullTime)(nil), // email_sent_at = nil
			sqlmock.AnyArg(),     // pq.Array(email_recipients)
			(*sql.NullTime)(nil), // completed_at = nil
			tenantID,             // M47 W2 tenant belt
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	svc := newTestReportService(t, db)
	svc.markReportFailed(context.Background(), tenantID, report, "boom")

	if report.Status != model.ReportStatusFailed {
		t.Fatalf("report.Status = %q, want %q", report.Status, model.ReportStatusFailed)
	}
	if report.ErrorMessage != "boom" {
		t.Fatalf("report.ErrorMessage = %q, want %q", report.ErrorMessage, "boom")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// codex-r6 P1 regression guard.
//
// Previously GenerateReport spawned generateReportAsync inline with `go ...`
// before returning. On fast generators the goroutine's UpdateReport landed
// before the parent CreateReport INSERT became visible, silently matched 0
// rows, and the report stuck at "generating" forever. The fix returns a
// launcher closure that the caller invokes AFTER the parent tx commits
// (handler via middleware.RegisterPostCommit, scheduler directly after
// runWithTenantTx returns).
//
// These tests pin down: (a) GenerateReport runs CreateReport synchronously
// inside the caller's context and returns a non-nil launcher on success,
// (b) the goroutine is NOT spawned until the launcher is called, and (c) an
// error path returns nil report + nil launcher so callers can wire
// RegisterPostCommit unconditionally.
func TestGenerateReport_ReturnsLauncherAndDoesNotLaunchInline(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	userID := uuid.New()

	// Only the synchronous CreateReport INSERT must hit the DB during
	// GenerateReport. If the launcher had fired inline, sqlmock would also
	// see the goroutine's BEGIN / set_config / UPDATE / COMMIT (or fail with
	// unmet expectations on its own schedule). The absence of any "extra"
	// matcher here is the load-bearing assertion.
	mock.ExpectExec("INSERT INTO generated_reports").
		WillReturnResult(sqlmock.NewResult(0, 1))

	svc := newTestReportService(t, db)

	now := time.Now()
	input := model.GenerateReportInput{
		ReportType:  model.ReportTypeExecutive,
		Format:      model.ReportFormatPDF,
		PeriodStart: now.AddDate(0, -1, 0),
		PeriodEnd:   now,
		Locale:      "ja",
	}

	report, launcher, err := svc.GenerateReport(context.Background(), tenantID, userID, input)
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	if report == nil {
		t.Fatal("report is nil on success")
	}
	if launcher == nil {
		t.Fatal("launcher is nil on success — would race the tx commit")
	}
	if report.TenantID != tenantID {
		t.Fatalf("report.TenantID = %v, want %v", report.TenantID, tenantID)
	}
	if report.Status != model.ReportStatusGenerating {
		t.Fatalf("report.Status = %q, want %q", report.Status, model.ReportStatusGenerating)
	}

	// At this point only the INSERT must have happened. Anything beyond
	// that — BEGIN/COMMIT for the async UPDATE — means the launcher fired
	// inline and the codex-r6 race is back.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected DB activity before launcher invoked: %v", err)
	}
}

func TestGenerateReport_ErrorPathReturnsNilLauncher(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	userID := uuid.New()

	mock.ExpectExec("INSERT INTO generated_reports").
		WillReturnError(errors.New("insert blew up"))

	svc := newTestReportService(t, db)

	input := model.GenerateReportInput{
		ReportType: model.ReportTypeExecutive,
		Format:     model.ReportFormatPDF,
	}

	report, launcher, gerr := svc.GenerateReport(context.Background(), tenantID, userID, input)
	if gerr == nil {
		t.Fatal("expected error on CreateReport failure")
	}
	if report != nil {
		t.Fatalf("report should be nil on error, got %+v", report)
	}
	// Nil launcher lets the scheduler path call launcher() unconditionally
	// only when err is nil, and lets the handler hand the launcher to
	// RegisterPostCommit (which is nil-safe by design — see middleware/tx.go)
	// without an extra nil branch.
	if launcher != nil {
		t.Fatal("launcher should be nil when GenerateReport returns an error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// M41 (F460) regression guard for gatherReportData.
//
// gatherReportData shipped with ZERO coverage. It called SIX deprecated
// dashboard-repo methods (GetTotalProjects / GetTotalComponents /
// GetVulnerabilityCounts / GetProjectScores / GetTopRisks / GetTrend) that
// ALWAYS returned an error, each guarded by `if ...; err == nil { assign }`, so
// the assignments never ran and every executive/technical report shipped with
// Summary counts = 0, an empty severity breakdown and no Top Risks / Project
// Scores / Trend. The fix swaps all six to the tenant-scoped *ByTenant variants.
//
// This test drives gatherReportData over a go-sqlmock DashboardRepository whose
// *ByTenant queries return canned rows, and asserts the dashboard data actually
// flows into the report struct. It is NON-VACUOUS: on the broken code the
// deprecated stubs return an error without ever issuing a query, so TopRisks
// stays empty and TotalProjects stays 0 — both asserted here — and the mock's
// per-*ByTenant expectations go unmet. Verified 2026-07-06 (Opus fallback): with
// GetTopRisksByTenant reverted to the deprecated GetTopRisks(ctx, 10), this test
// FAILS ("len(data.TopRisks) = 0, want 1"); restoring the fix makes it pass.
//
// Only dashboardRepo is wired non-nil — gatherReportData guards the analytics /
// checklist / visualization sections behind their own nil repo checks, so those
// branches are skipped and no other mock is needed.
func TestGatherReportData_PopulatesSummaryAndTopRisksFromTenantScopedDashboard(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	projID := uuid.New()

	// Queries fire in gatherReportData's order (projects, components,
	// vuln-counts, project-scores, top-risks, trend). sqlmock defaults to
	// ordered matching, so this also pins the call order and the exact
	// tenant-scoped arg shape of each *ByTenant query.

	// 1. GetTotalProjectsByTenant(ctx, tenantID)
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM projects WHERE tenant_id = \$1`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	// 2. GetTotalComponentsByTenant(ctx, tenantID)
	mock.ExpectQuery(`FROM components c\s+INNER JOIN sboms`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	// 3. GetVulnerabilityCountsByTenant(ctx, tenantID)
	mock.ExpectQuery(`SELECT\s+COALESCE\(SUM\(CASE WHEN v\.severity = 'CRITICAL' THEN 1 ELSE 0 END\), 0\) as critical,`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"critical", "high", "medium", "low"}).
			AddRow(3, 5, 2, 1))

	// 4. GetProjectScoresByTenant(ctx, tenantID)
	mock.ExpectQuery(`FROM projects p\s+LEFT JOIN sboms`).
		WithArgs(tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "critical", "high", "medium", "low"}).
			AddRow(projID, "app-a", 3, 5, 2, 1))

	// 5. GetTopRisksByTenant(ctx, tenantID, 10, "epss") — pin the EPSS outer
	// ordering so a revert to sortBy="cvss" (wrong for a compliance report) is
	// caught, not just the presence of the query.
	mock.ExpectQuery(`(?is)DISTINCT ON \(v\.cve_id\).*ORDER BY epss_score DESC NULLS LAST`).
		WithArgs(tenantID, 10).
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "epss_score", "cvss_score", "severity",
			"project_id", "project_name", "component_name", "component_version",
		}).AddRow("CVE-2026-9999", 0.75, 9.1, "CRITICAL", projID, "app-a", "libz", "1.2"))

	// 6. GetTrendByTenant(ctx, tenantID, 30) — arg order is (days, tenantID).
	mock.ExpectQuery(`WITH date_series AS`).
		WithArgs(30, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"date", "critical", "high", "medium", "low"}).
			AddRow(time.Now(), 1, 2, 3, 4))

	dashboardRepo := repository.NewDashboardRepository(db)
	svc := NewReportService(nil, dashboardRepo, nil, nil, nil, nil, t.TempDir())

	now := time.Now()
	data := svc.gatherReportData(context.Background(), tenantID, now.AddDate(0, -1, 0), now)

	// Summary fields must reflect the mocked dashboard reads (0 on broken code).
	if data.Summary.TotalProjects != 7 {
		t.Errorf("Summary.TotalProjects = %d, want 7", data.Summary.TotalProjects)
	}
	if data.Summary.TotalComponents != 42 {
		t.Errorf("Summary.TotalComponents = %d, want 42", data.Summary.TotalComponents)
	}
	if data.Summary.TotalVulnerabilities != 11 { // 3+5+2+1
		t.Errorf("Summary.TotalVulnerabilities = %d, want 11", data.Summary.TotalVulnerabilities)
	}

	// Severity breakdown must be populated (empty map on broken code).
	if got := data.VulnerabilityData.BySeverity["CRITICAL"]; got != 3 {
		t.Errorf("BySeverity[CRITICAL] = %d, want 3", got)
	}
	if got := data.VulnerabilityData.BySeverity["HIGH"]; got != 5 {
		t.Errorf("BySeverity[HIGH] = %d, want 5", got)
	}

	// Top Risks: the key assertion — non-empty and correctly populated.
	if len(data.TopRisks) != 1 {
		t.Fatalf("len(data.TopRisks) = %d, want 1", len(data.TopRisks))
	}
	if data.TopRisks[0].CVEID != "CVE-2026-9999" {
		t.Errorf("TopRisks[0].CVEID = %q, want CVE-2026-9999", data.TopRisks[0].CVEID)
	}
	if data.TopRisks[0].EPSSScore == nil || *data.TopRisks[0].EPSSScore != 0.75 {
		t.Errorf("TopRisks[0].EPSSScore = %v, want 0.75", data.TopRisks[0].EPSSScore)
	}
	if data.TopRisks[0].CVSSScore == nil || *data.TopRisks[0].CVSSScore != 9.1 {
		t.Errorf("TopRisks[0].CVSSScore = %v, want 9.1", data.TopRisks[0].CVSSScore)
	}

	// Project scores and trend must also flow through.
	if len(data.ProjectScores) != 1 {
		t.Errorf("len(data.ProjectScores) = %d, want 1", len(data.ProjectScores))
	}
	if len(data.VulnerabilityData.TrendData) != 1 {
		t.Errorf("len(TrendData) = %d, want 1", len(data.VulnerabilityData.TrendData))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (a deprecated stub would skip the query entirely): %v", err)
	}
}

func TestSetDB_IsNilSafeAndIdempotent(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	if svc.db != nil {
		t.Fatal("freshly-constructed svc.db should be nil")
	}

	// Nil-safe: calling with nil must not clear an existing handle.
	svc.SetDB(nil)
	if svc.db != nil {
		t.Fatal("SetDB(nil) should be a no-op")
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc.SetDB(db)
	if svc.db != db {
		t.Fatal("SetDB(db) did not attach db")
	}

	// Subsequent nil call must not clobber.
	svc.SetDB(nil)
	if svc.db != db {
		t.Fatal("SetDB(nil) cleared a previously-attached db")
	}
}

// ----------------------------------------------------------------------------
// M46 Track C-3a regression — generateExcel used to discard the error return
// of ~97 excelize calls (errcheck), so a failed cell/sheet/style write would
// have produced a "successful" but silently-incomplete workbook. Same defect
// class GenerateComplianceExcel had before Track C-1 (commit 89319ca); same
// fix: every write is routed through the shared first-error collector
// (reportErrs) and checked once before serialization.
//
// Honest scope note: on the pinned excelize v2.10.0, generateExcel cannot be
// driven into an excelize failure from its public inputs — sheet names are
// fixed translations, cell references are generated in-range, and oversized
// strings are silently TRUNCATED by SetCellValue (setCellString truncates at
// TotalCellChars instead of returning an error; verified in the module
// source), so an end-to-end "corrupt workbook returned as success" red test
// is not constructible today. The contract is therefore pinned in layers:
//  1. this test drives the collector with REAL excelize errors of the exact
//     call shapes generateExcel routes through it,
//  2. the happy-path tests below open the produced workbook and pin the
//     layout, so the ec.collect refactor cannot silently drop content, and
//  3. TestRunReportGeneration_* pin that a generator error (any source)
//     propagates to the caller instead of flipping the row to "completed".
//
// ----------------------------------------------------------------------------
func TestReportExcelWriteFailure_IsCollectedForPropagation(t *testing.T) {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close workbook: %v", err)
		}
	}()

	ec := &reportErrs{}

	// Call shapes used by generateExcel, healthy: must not record anything.
	ec.collect(f.SetColWidth("Sheet1", "A", "A", 25))
	ec.collect(f.SetCellValue("Sheet1", "A1", "ok"))
	if ec.err != nil {
		t.Fatalf("healthy writes must not record an error, got %v", ec.err)
	}

	// Real excelize failure #1: column width beyond the format limit (the
	// same SetColWidth shape generateExcel uses for every sheet).
	ec.collect(f.SetColWidth("Sheet1", "A", "A", excelize.MaxColumnWidth+1))
	if !errors.Is(ec.err, excelize.ErrColumnWidth) {
		t.Fatalf("expected ErrColumnWidth to be collected, got %v", ec.err)
	}
	first := ec.err

	// Real excelize failure #2 (SetCellValue on a missing sheet) must NOT
	// overwrite the first recorded failure — later errors after a failure
	// are knock-on noise.
	ec.collect(f.SetCellValue("no-such-sheet", "A1", "x"))
	if !errors.Is(ec.err, first) {
		t.Fatalf("first error was overwritten: got %v, want %v", ec.err, first)
	}
}

// buildFullReportData returns an ExecutiveReportData that exercises every
// sheet builder in generateExcel (summary, top risks, trend, checklist,
// visualization) and every PDF content section, so the happy-path tests pin
// the report layout across the M46 errcheck refactor.
func buildFullReportData() *model.ExecutiveReportData {
	gen := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	return &model.ExecutiveReportData{
		PeriodStart: gen.AddDate(0, -1, 0),
		PeriodEnd:   gen,
		GeneratedAt: gen,
		Summary: model.ReportSummary{
			TotalProjects:        7,
			TotalComponents:      42,
			TotalVulnerabilities: 11,
			ResolvedInPeriod:     3,
			AverageMTTRHours:     f64p(12.5),
			SLOAchievementPct:    f64p(99.5),
			ComplianceScore:      8,
			ComplianceMaxScore:   16,
		},
		VulnerabilityData: model.VulnReportData{
			BySeverity: map[string]int{"CRITICAL": 3, "HIGH": 5, "MEDIUM": 2, "LOW": 1},
			TrendData: []model.TrendPoint{
				{Date: gen.AddDate(0, 0, -1), Critical: 1, High: 2, Medium: 3, Low: 4},
			},
		},
		ProjectScores: []model.ProjectScore{},
		TopRisks: []model.TopRisk{{
			CVEID:         "CVE-2026-0001",
			EPSSScore:     f64p(0.75),
			CVSSScore:     f64p(9.1),
			Severity:      "CRITICAL",
			ProjectName:   "app-a",
			ComponentName: "libz",
		}},
		ChecklistData: &model.ChecklistReportData{
			Score:    1,
			MaxScore: 2,
			Phases: []model.ChecklistPhaseReportData{{
				Phase:    "setup",
				LabelJa:  "フェーズ1",
				Score:    1,
				MaxScore: 2,
				Items: []model.ChecklistItemReportData{
					{ID: "a", LabelJa: "項目A", AutoVerify: true, Passed: true, Note: "自動確認"},
					{ID: "b", LabelJa: "項目B", Passed: false, Note: "未対応"},
				},
			}},
		},
		VisualizationData: &model.VisualizationReportData{
			SBOMAuthorScope:  "supplier",
			DependencyScope:  "direct",
			GenerationMethod: "auto",
			DataFormat:       "cyclonedx",
			UtilizationScope: []string{"vulnerability", "license"},
			UtilizationActor: "development",
		},
	}
}

func hasSheet(sheets []string, name string) bool {
	for _, s := range sheets {
		if s == name {
			return true
		}
	}
	return false
}

func TestGenerateExcel_ExecutiveHappyPathProducesReadableWorkbook(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	tr := GetTranslations("ja")

	b, err := svc.generateExcel(buildFullReportData(), model.ReportTypeExecutive, "ja")
	if err != nil {
		t.Fatalf("generateExcel: %v", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("generated bytes are not a readable workbook: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close workbook: %v", err)
		}
	}()

	sheets := f.GetSheetList()
	if !hasSheet(sheets, tr.SheetSummary) || !hasSheet(sheets, tr.SheetTopRisks) {
		t.Fatalf("executive workbook must have summary + top risks sheets, got %v", sheets)
	}
	// Trend is technical-only; checklist/visualization are compliance-only.
	for _, absent := range []string{tr.SheetTrend, tr.SheetChecklist, tr.SheetVisualization} {
		if hasSheet(sheets, absent) {
			t.Fatalf("executive workbook must not contain sheet %q, got %v", absent, sheets)
		}
	}

	// Summary layout: title, then summary rows 5-11, severity block 14-18.
	if v, _ := f.GetCellValue(tr.SheetSummary, "A1"); v != tr.TitleExecutive {
		t.Fatalf("summary A1 = %q, want %q", v, tr.TitleExecutive)
	}
	if v, _ := f.GetCellValue(tr.SheetSummary, "B5"); v != "7" {
		t.Fatalf("total projects B5 = %q, want 7", v)
	}
	if v, _ := f.GetCellValue(tr.SheetSummary, "B7"); v != "11" {
		t.Fatalf("total vulnerabilities B7 = %q, want 11", v)
	}
	if v, _ := f.GetCellValue(tr.SheetSummary, "B11"); v != "8 / 16" {
		t.Fatalf("compliance score B11 = %q, want 8 / 16", v)
	}
	if v, _ := f.GetCellValue(tr.SheetSummary, "A14"); v != tr.VulnerabilityBreakdown {
		t.Fatalf("severity header A14 = %q, want %q", v, tr.VulnerabilityBreakdown)
	}
	if v, _ := f.GetCellValue(tr.SheetSummary, "B15"); v != "3" {
		t.Fatalf("critical count B15 = %q, want 3", v)
	}

	// Top risks data row.
	if v, _ := f.GetCellValue(tr.SheetTopRisks, "A2"); v != "CVE-2026-0001" {
		t.Fatalf("top risk A2 = %q, want CVE-2026-0001", v)
	}
	if v, _ := f.GetCellValue(tr.SheetTopRisks, "E2"); v != "75.00%" {
		t.Fatalf("top risk EPSS E2 = %q, want 75.00%%", v)
	}
}

func TestGenerateExcel_ComplianceHappyPathIncludesChecklistAndVisualization(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	tr := GetTranslations("ja")

	b, err := svc.generateExcel(buildFullReportData(), model.ReportTypeCompliance, "ja")
	if err != nil {
		t.Fatalf("generateExcel: %v", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("generated bytes are not a readable workbook: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close workbook: %v", err)
		}
	}()

	sheets := f.GetSheetList()
	for _, want := range []string{tr.SheetSummary, tr.SheetChecklist, tr.SheetVisualization} {
		if !hasSheet(sheets, want) {
			t.Fatalf("compliance workbook missing sheet %q, got %v", want, sheets)
		}
	}
	if hasSheet(sheets, tr.SheetTopRisks) || hasSheet(sheets, tr.SheetTrend) {
		t.Fatalf("compliance workbook must not contain top-risks/trend sheets, got %v", sheets)
	}

	// Checklist sheet: title, progress, then item rows from row 5.
	if v, _ := f.GetCellValue(tr.SheetChecklist, "A1"); v != tr.METIChecklist {
		t.Fatalf("checklist A1 = %q, want %q", v, tr.METIChecklist)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "B2"); v != "1 / 2 (50%)" {
		t.Fatalf("checklist progress B2 = %q, want 1 / 2 (50%%)", v)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "A5"); v != "フェーズ1" {
		t.Fatalf("checklist phase label A5 = %q, want フェーズ1", v)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "C5"); v != "○" {
		t.Fatalf("checklist auto-verify C5 = %q, want ○", v)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "D5"); v != tr.Completed {
		t.Fatalf("checklist status D5 = %q, want %q", v, tr.Completed)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "E5"); v != "自動確認" {
		t.Fatalf("checklist note E5 = %q, want 自動確認", v)
	}
	if v, _ := f.GetCellValue(tr.SheetChecklist, "D6"); v != tr.NotCompleted {
		t.Fatalf("checklist status D6 = %q, want %q", v, tr.NotCompleted)
	}

	// Visualization sheet: title + the six framework rows (4-9).
	if v, _ := f.GetCellValue(tr.SheetVisualization, "A1"); v != tr.VisualizationFramework {
		t.Fatalf("visualization A1 = %q, want %q", v, tr.VisualizationFramework)
	}
	if v, _ := f.GetCellValue(tr.SheetVisualization, "A4"); v != tr.VizSBOMAuthor {
		t.Fatalf("visualization A4 = %q, want %q", v, tr.VizSBOMAuthor)
	}
	if v, _ := f.GetCellValue(tr.SheetVisualization, "B4"); v == "" {
		t.Fatal("visualization B4 (SBOM author label) must not be empty")
	}
	if v, _ := f.GetCellValue(tr.SheetVisualization, "B8"); !strings.Contains(v, ", ") {
		t.Fatalf("visualization B8 (utilization scopes) = %q, want comma-joined labels", v)
	}
}

// Codex C-3a round 1 (Medium): the Trend sheet builder is technical-only and
// was not exercised by the executive/compliance happy-path tests, leaving the
// ec.collect conversion of that branch unpinned.
func TestGenerateExcel_TechnicalHappyPathIncludesTrendSheet(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	tr := GetTranslations("ja")

	b, err := svc.generateExcel(buildFullReportData(), model.ReportTypeTechnical, "ja")
	if err != nil {
		t.Fatalf("generateExcel: %v", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("generated bytes are not a readable workbook: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close workbook: %v", err)
		}
	}()

	sheets := f.GetSheetList()
	for _, want := range []string{tr.SheetSummary, tr.SheetTopRisks, tr.SheetTrend} {
		if !hasSheet(sheets, want) {
			t.Fatalf("technical workbook missing sheet %q, got %v", want, sheets)
		}
	}
	for _, absent := range []string{tr.SheetChecklist, tr.SheetVisualization} {
		if hasSheet(sheets, absent) {
			t.Fatalf("technical workbook must not contain sheet %q, got %v", absent, sheets)
		}
	}

	// Trend data row: header row 1, first point at row 2. The date cell is
	// style-formatted by excelize, so pin non-emptiness for A2 and the exact
	// severity counts for B2-E2 (1/2/3/4 from buildFullReportData).
	if v, _ := f.GetCellValue(tr.SheetTrend, "A1"); v != tr.Date {
		t.Fatalf("trend header A1 = %q, want %q", v, tr.Date)
	}
	if v, _ := f.GetCellValue(tr.SheetTrend, "A2"); v == "" {
		t.Fatal("trend date A2 must not be empty")
	}
	for cell, want := range map[string]string{"B2": "1", "C2": "2", "D2": "3", "E2": "4"} {
		if v, _ := f.GetCellValue(tr.SheetTrend, cell); v != want {
			t.Fatalf("trend %s = %q, want %q", cell, v, want)
		}
	}
}

func TestGeneratePDF_AllReportTypesProduceParsablePDF(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	data := buildFullReportData()

	for _, reportType := range []string{
		model.ReportTypeExecutive,
		model.ReportTypeTechnical,
		model.ReportTypeCompliance,
	} {
		b, err := svc.generatePDF(data, reportType, "ja")
		if err != nil {
			t.Fatalf("generatePDF(%s): %v", reportType, err)
		}
		if !bytes.HasPrefix(b, []byte("%PDF-")) {
			t.Fatalf("generatePDF(%s) output does not start with %%PDF- (got %q...)", reportType, b[:minInt(8, len(b))])
		}
		// The embedded IPAGothic font alone is several hundred KB; a tiny
		// output means the document was not actually assembled.
		if len(b) < 10_000 {
			t.Fatalf("generatePDF(%s) output suspiciously small: %d bytes", reportType, len(b))
		}
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// xlsxContentArg matches the file_content UPDATE argument only if it carries
// a plausible XLSX payload (ZIP container magic "PK"). This keeps the
// success-path pipeline test honest: the terminal UPDATE must persist real
// workbook bytes, not an empty slice.
type xlsxContentArg struct{}

func (xlsxContentArg) Match(v driver.Value) bool {
	b, ok := v.([]byte)
	return ok && bytes.HasPrefix(b, []byte("PK"))
}

// M46 Track C-3a: pins the success half of the error-propagation contract —
// runReportGeneration drives gather → generateExcel → UpdateReport inside one
// tenant tx and the row flips to "completed" with real workbook bytes.
func TestRunReportGeneration_SuccessFlipsRowToCompletedWithRealWorkbook(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	now := time.Now()
	report := &model.GeneratedReport{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ReportType:  model.ReportTypeExecutive,
		Format:      model.ReportFormatXLSX,
		Status:      model.ReportStatusGenerating,
		PeriodStart: now.AddDate(0, -1, 0),
		PeriodEnd:   now,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs(tenantID.String()).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE generated_reports").
		WithArgs(
			report.ID,
			sqlmock.AnyArg(), // file_path (timestamped filename)
			sqlmock.AnyArg(), // file_size
			xlsxContentArg{}, // file_content must be a real ZIP/XLSX payload
			model.ReportStatusCompleted,
			"",               // error_message stays empty on success
			sqlmock.AnyArg(), // email_sent_at
			sqlmock.AnyArg(), // email_recipients
			sqlmock.AnyArg(), // completed_at (stamped inside)
			tenantID,         // M47 W2 tenant belt
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	svc := newTestReportService(t, db)

	if err := svc.runWithTenantTx(context.Background(), tenantID, func(txCtx context.Context) error {
		return svc.runReportGeneration(txCtx, tenantID, report, "ja")
	}); err != nil {
		t.Fatalf("runReportGeneration: %v", err)
	}

	if report.Status != model.ReportStatusCompleted {
		t.Fatalf("report.Status = %q, want %q", report.Status, model.ReportStatusCompleted)
	}
	if report.FileSize == 0 || len(report.FileContent) != report.FileSize {
		t.Fatalf("FileSize = %d, len(FileContent) = %d — must be a consistent non-empty payload",
			report.FileSize, len(report.FileContent))
	}
	if report.CompletedAt == nil {
		t.Fatal("CompletedAt must be stamped on success")
	}
	if !strings.HasSuffix(report.FilePath, ".xlsx") {
		t.Fatalf("FilePath = %q, want *.xlsx", report.FilePath)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// M46 Track C-3a: pins the failure half of the propagation contract — a
// generator error must surface to the caller (which rolls the tx back and
// records "failed" via markReportFailed) and must NOT reach the terminal
// UpdateReport. reportRepo is intentionally nil: if runReportGeneration
// wrongly proceeded past the failed generation, the test would panic instead
// of returning the error.
func TestRunReportGeneration_GeneratorFailureReturnsErrorBeforeTerminalUpdate(t *testing.T) {
	svc := NewReportService(nil, nil, nil, nil, nil, nil, t.TempDir())
	report := &model.GeneratedReport{
		ID:         uuid.New(),
		ReportType: model.ReportTypeExecutive,
		Format:     "docx", // unsupported → generation error
		Status:     model.ReportStatusGenerating,
	}

	err := svc.runReportGeneration(context.Background(), uuid.New(), report, "ja")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Fatalf("error must name the unsupported format, got: %v", err)
	}
	if report.Status != model.ReportStatusGenerating {
		t.Fatalf("report.Status = %q — runReportGeneration must not flip the status itself on failure", report.Status)
	}
}

// M46 Track C-3a (unparam) — gatherReportData's error return was ALWAYS nil,
// because the M41 (F461) design folds every failing section read into
// WARN-log + empty section instead of failing the report. This test pins that
// degradation contract across the signature cleanup: with every dashboard
// query failing, gatherReportData still returns a usable (zero-valued) data
// struct and does not panic. If a future change makes section failures fatal,
// this test must be revisited TOGETHER with reintroducing the error return —
// see the doc comment on gatherReportData.
func TestGatherReportData_DashboardFailuresDegradeToEmptySectionsNotError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	dbDown := errors.New("connection refused")

	// All six dashboard reads fail, in gatherReportData's call order.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM projects WHERE tenant_id = \$1`).WillReturnError(dbDown)
	mock.ExpectQuery(`FROM components c\s+INNER JOIN sboms`).WillReturnError(dbDown)
	mock.ExpectQuery(`SELECT\s+COALESCE\(SUM\(CASE WHEN v\.severity = 'CRITICAL' THEN 1 ELSE 0 END\), 0\) as critical,`).WillReturnError(dbDown)
	mock.ExpectQuery(`FROM projects p\s+LEFT JOIN sboms`).WillReturnError(dbDown)
	mock.ExpectQuery(`(?is)DISTINCT ON \(v\.cve_id\)`).WillReturnError(dbDown)
	mock.ExpectQuery(`WITH date_series AS`).WillReturnError(dbDown)

	svc := NewReportService(nil, repository.NewDashboardRepository(db), nil, nil, nil, nil, t.TempDir())

	now := time.Now()
	data := svc.gatherReportData(context.Background(), tenantID, now.AddDate(0, -1, 0), now)
	if data == nil {
		t.Fatal("gatherReportData must always return a data struct")
		return // unreachable; keeps staticcheck SA5011 quiet (Codex C-3a round 1, Low)
	}
	if data.Summary.TotalProjects != 0 || data.Summary.TotalComponents != 0 ||
		data.Summary.TotalVulnerabilities != 0 {
		t.Fatalf("failed reads must leave summary zero-valued, got %+v", data.Summary)
	}
	if len(data.TopRisks) != 0 || len(data.ProjectScores) != 0 || len(data.VulnerabilityData.TrendData) != 0 {
		t.Fatalf("failed reads must leave sections empty, got risks=%d scores=%d trend=%d",
			len(data.TopRisks), len(data.ProjectScores), len(data.VulnerabilityData.TrendData))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations (all six dashboard reads must still be attempted): %v", err)
	}
}
