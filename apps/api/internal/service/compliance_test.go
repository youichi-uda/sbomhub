package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/xuri/excelize/v2"
)

// ----------------------------------------------------------------------------
// M46 Track C regression — GenerateComplianceExcel used to discard the error
// return of ~50 excelize calls (errcheck findings), so a failed cell write
// still produced a "successful" but corrupt/incomplete workbook. These tests
// pin (a) the error-collection mechanism the generator now routes every
// write through, exercised with REAL excelize errors, and (b) the happy-path
// workbook/CSV content so the errcheck refactor cannot silently change the
// report layout.
// ----------------------------------------------------------------------------

func testComplianceResult() *model.ComplianceResult {
	failDetail := "SBOMがアップロードされていません"
	return &model.ComplianceResult{
		ProjectID: uuid.New(),
		Score:     1,
		MaxScore:  2,
		Categories: []model.ComplianceCategory{
			{
				Name:     string(model.ComplianceCategorySBOM),
				Label:    "SBOM生成",
				Score:    1,
				MaxScore: 2,
				Checks: []model.ComplianceCheck{
					{ID: "required_fields", Label: "必須フィールドが含まれている", Passed: true},
					{ID: "sbom_exists", Label: "SBOMが登録されている", Passed: false, Details: &failDetail},
				},
			},
		},
	}
}

// ----------------------------------------------------------------------------
// M46 Codex round A regression — the Track C-1 unparam cleanup removed the
// error returns from the CheckCompliance check helpers, which turned
// repository FAILURES into compliance PASSES: a failed vulnerability-count
// query zero-valued the counts and scored `no_unresolved_critical`, and a
// failed component-list query scored `no_violations`. For a compliance
// product that is the worst possible failure mode (the audit surface says
// 合格 while the underlying query never ran). The contract pinned here:
// an infrastructure error propagates to the caller (HTTP 500 via the
// handler's existing error path) and NEVER yields a scored result.
// ----------------------------------------------------------------------------

func newSqlmockComplianceService(t *testing.T) (*ComplianceService, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewComplianceService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
		repository.NewVulnerabilityRepository(db),
		repository.NewVEXRepository(db),
		repository.NewLicensePolicyRepository(db),
		repository.NewDashboardRepository(db),
	), mock
}

func timeNowForTest() time.Time { return time.Now() }

func sbomRow(sbomID, projectID uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows(
		[]string{"id", "project_id", "format", "version", "raw_data", "created_at"},
	).AddRow(sbomID, projectID, string(model.FormatCycloneDX), "1.4", []byte(`{}`), timeNowForTest())
}

func TestCheckCompliance_VulnCountQueryFailure_IsAnErrorNotAPass(t *testing.T) {
	s, mock := newSqlmockComplianceService(t)
	projectID := uuid.New()

	// SBOM generation: no SBOM at all. sql.ErrNoRows is ABSENCE, not an
	// infrastructure error — the category must still be computed (fails
	// its checks honestly) and CheckCompliance must keep going.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM sboms WHERE project_id = $1`)).
		WillReturnError(sql.ErrNoRows)
	// Vulnerability management: the counts query fails (infrastructure).
	mock.ExpectQuery(regexp.QuoteMeta(`FROM vulnerabilities v`)).
		WillReturnError(errors.New("connection reset by peer"))

	res, err := s.CheckCompliance(context.Background(), projectID)
	if err == nil {
		t.Fatalf("CheckCompliance must FAIL when the vulnerability count query "+
			"fails; got nil error with result %+v — pre-M46-fix this zero-valued "+
			"the counts and scored no_unresolved_critical as 合格", res)
	}
	if res != nil {
		t.Fatalf("CheckCompliance must not return a partial result alongside an error, got %+v", res)
	}
	if !strings.Contains(err.Error(), "vulnerability management") {
		t.Fatalf("error must name the failing check group, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestCheckCompliance_ComponentListFailure_IsAnErrorNotNoViolations(t *testing.T) {
	s, mock := newSqlmockComplianceService(t)
	projectID := uuid.New()
	sbomID := uuid.New()

	// checkSBOMGeneration: SBOM + one well-formed component (all green).
	mock.ExpectQuery(regexp.QuoteMeta(`FROM sboms WHERE project_id = $1`)).
		WillReturnRows(sbomRow(sbomID, projectID))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM components WHERE sbom_id = $1`)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "sbom_id", "name", "version", "type", "purl", "license", "created_at"},
		).AddRow(uuid.New(), sbomID, "left-pad", "1.0.0", "library", "pkg:npm/left-pad@1.0.0", "MIT", timeNowForTest()))
	// checkVulnerabilityManagement: counts fine, no VEX statements.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM vulnerabilities v`)).
		WillReturnRows(sqlmock.NewRows([]string{"critical", "high", "medium", "low"}).AddRow(0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM vex_statements vs`)).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "project_id", "vulnerability_id", "component_id",
			"status", "justification", "action_statement", "impact_statement",
			"created_by", "created_at", "updated_at", "cve_id", "severity", "name", "version",
		}))
	// checkLicenseManagement: a policy exists, the SBOM re-read succeeds,
	// but the component list needed to evaluate violations FAILS.
	mock.ExpectQuery(regexp.QuoteMeta(`FROM license_policies`)).
		WillReturnRows(sqlmock.NewRows(
			[]string{"id", "project_id", "license_id", "license_name", "policy_type", "reason", "created_at", "updated_at"},
		).AddRow(uuid.New(), projectID, "GPL-3.0", "GPL 3.0", string(model.LicensePolicyDenied), "", timeNowForTest(), timeNowForTest()))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM sboms WHERE project_id = $1`)).
		WillReturnRows(sbomRow(sbomID, projectID))
	mock.ExpectQuery(regexp.QuoteMeta(`FROM components WHERE sbom_id = $1`)).
		WillReturnError(errors.New("storage failure"))

	res, err := s.CheckCompliance(context.Background(), projectID)
	if err == nil {
		t.Fatalf("CheckCompliance must FAIL when the component list query fails "+
			"during license violation evaluation; got nil error with result %+v — "+
			"pre-M46-fix this counted zero violations and scored no_violations as 合格", res)
	}
	if res != nil {
		t.Fatalf("CheckCompliance must not return a partial result alongside an error, got %+v", res)
	}
	if !strings.Contains(err.Error(), "license management") {
		t.Fatalf("error must name the failing check group, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func TestReportErrs_KeepsFirstRealExcelizeError(t *testing.T) {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close workbook: %v", err)
		}
	}()

	ec := &reportErrs{}
	ec.collect(nil)
	if ec.err != nil {
		t.Fatalf("collect(nil) must not record an error, got %v", ec.err)
	}

	// Real excelize failure of the exact call shape GenerateComplianceExcel
	// uses: writing to a sheet that does not exist.
	ec.collect(f.SetCellValue("no-such-sheet", "A1", "x"))
	if ec.err == nil {
		t.Fatal("expected SetCellValue on missing sheet to be collected")
	}
	first := ec.err

	// A later, different failure must not overwrite the first one.
	ec.collect(errors.New("second error"))
	if !errors.Is(ec.err, first) {
		t.Fatalf("first error was overwritten: got %v, want %v", ec.err, first)
	}
	ec.collect(nil)
	if !errors.Is(ec.err, first) {
		t.Fatalf("collect(nil) cleared the recorded error: got %v", ec.err)
	}
}

func TestGenerateComplianceExcel_SuccessProducesReadableWorkbook(t *testing.T) {
	s := &ComplianceService{}
	result := testComplianceResult()

	b, err := s.GenerateComplianceExcel(context.Background(), result.ProjectID, result)
	if err != nil {
		t.Fatalf("GenerateComplianceExcel: %v", err)
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

	wantSheets := []string{"サマリー", "チェック項目詳細", "推奨事項"}
	got := f.GetSheetList()
	for _, want := range wantSheets {
		found := false
		for _, name := range got {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("sheet %q missing; sheets = %v", want, got)
		}
	}

	title, err := f.GetCellValue("サマリー", "A1")
	if err != nil || title != "経産省SBOMガイドライン コンプライアンスレポート" {
		t.Fatalf("summary title = %q err = %v", title, err)
	}
	score, err := f.GetCellValue("サマリー", "B6")
	if err != nil || score != "1 / 2 (50%)" {
		t.Fatalf("total score cell = %q err = %v, want \"1 / 2 (50%%)\"", score, err)
	}

	// Detail rows: row 2 = passed check, row 3 = failed check with details
	// and a recommendation.
	if v, _ := f.GetCellValue("チェック項目詳細", "C2"); v != "達成" {
		t.Fatalf("detail C2 = %q, want 達成", v)
	}
	if v, _ := f.GetCellValue("チェック項目詳細", "C3"); v != "未達成" {
		t.Fatalf("detail C3 = %q, want 未達成", v)
	}
	if v, _ := f.GetCellValue("チェック項目詳細", "D3"); v != "SBOMがアップロードされていません" {
		t.Fatalf("detail D3 = %q", v)
	}
	if v, _ := f.GetCellValue("推奨事項", "A2"); v != "SBOMが登録されている" {
		t.Fatalf("recommendation A2 = %q", v)
	}
}

func TestGenerateComplianceCSV_SuccessAndContent(t *testing.T) {
	s := &ComplianceService{}
	result := testComplianceResult()

	b, err := s.GenerateComplianceCSV(context.Background(), result.ProjectID, result)
	if err != nil {
		t.Fatalf("GenerateComplianceCSV: %v", err)
	}
	if !bytes.HasPrefix(b, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV must start with a UTF-8 BOM for Excel compatibility")
	}

	r := csv.NewReader(strings.NewReader(string(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}))))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("generated CSV is not parseable: %v", err)
	}
	// 4 metadata rows + column header + 2 data rows (the separator row is
	// an empty line, which csv.Reader skips)
	if len(records) != 7 {
		t.Fatalf("record count = %d, want 7; records = %v", len(records), records)
	}
	if records[0][0] != "経済産業省コンプライアンスレポート" {
		t.Fatalf("header = %v", records[0])
	}
	failedRow := records[6]
	if failedRow[1] != "SBOMが登録されている" || failedRow[2] != "未達成" ||
		failedRow[3] != "SBOMがアップロードされていません" || failedRow[4] == "" {
		t.Fatalf("failed-check row = %v", failedRow)
	}
}
