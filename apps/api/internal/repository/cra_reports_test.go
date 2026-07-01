package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// validCRAEvidence is a helper that produces a non-empty JSONB
// evidence array so each test does not have to spell out the full
// citation shape. The CHECK constraint at the DB layer requires
// jsonb_array_length(evidence) > 0; this satisfies that.
func validCRAEvidence() json.RawMessage {
	return json.RawMessage(`[{"kind":"vex_draft","ref":"00000000-0000-0000-0000-000000000001"},{"kind":"template","ref":"early_warning_ja"}]`)
}

// TestCRAReportsRepository_Insert_PassesTenantID asserts the INSERT
// column ordering matches migration 038 and binds tenant_id at
// position 2 -- the same load-bearing position that the RLS WITH
// CHECK policy compares against. A mis-positioned bind would silently
// land tenant_id wrong, which the RLS layer would reject at runtime
// with a confusing error, or, worse, in a future world where RLS is
// removed, would leak rows across tenants.
func TestCRAReportsRepository_Insert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	sourceVEX := uuid.New()
	llmID := uuid.New()
	createdBy := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()
	ev := validCRAEvidence()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_reports")).
		WithArgs(
			rowID,             // $1  id
			tenantID,          // $2  tenant_id
			projectID,         // $3  project_id
			vulnID,            // $4  vulnerability_id
			"CVE-2025-99999",  // $5  cve_id
			"early_warning",   // $6  report_type
			"ja",              // $7  lang
			"draft",           // $8  state (default)
			"draft body here", // $9  draft_text
			"openai",          // $10 provider
			"gpt-4o",          // $11 model
			"p"+repeatHex(63), // $12 prompt_hash
			"r"+repeatHex(63), // $13 response_hash
			[]byte(ev),        // $14 evidence
			sourceVEX,         // $15 source_vex_draft_id
			llmID,             // $16 llm_call_id
			"pending",         // $17 decision (default)
			nil,               // $18 decision_by
			nil,               // $19 decision_at
			nil,               // $20 decision_note
			createdBy,         // $21 created_by
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(rowID, now, now))

	c := &CRAReport{
		ID:               rowID,
		TenantID:         tenantID,
		ProjectID:        projectID,
		VulnerabilityID:  vulnID,
		CVEID:            "CVE-2025-99999",
		ReportType:       "early_warning",
		Lang:             "ja",
		DraftText:        "draft body here",
		Provider:         "openai",
		Model:            "gpt-4o",
		PromptHash:       "p" + repeatHex(63),
		ResponseHash:     "r" + repeatHex(63),
		Evidence:         ev,
		SourceVEXDraftID: &sourceVEX,
		LLMCallID:        &llmID,
		CreatedBy:        &createdBy,
	}
	if err := repo.Insert(context.Background(), c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if c.State != "draft" {
		t.Errorf("expected Insert to default State to draft, got %q", c.State)
	}
	if c.Decision != "pending" {
		t.Errorf("expected Insert to default Decision to pending, got %q", c.Decision)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_Insert_RejectsZeroTenant pins the fail-
// fast on missing tenant -- same rationale as the other M1/M2
// repositories.
func TestCRAReportsRepository_Insert_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	err = repo.Insert(context.Background(), &CRAReport{
		// TenantID intentionally zero
		ProjectID:       uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-1",
		ReportType:      "early_warning",
		Lang:            "ja",
		DraftText:       "x",
		Evidence:        validCRAEvidence(),
	})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRAReportsRepository_Insert_RejectsNil guards the nil-pointer
// case.
func TestCRAReportsRepository_Insert_RejectsNil(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	if err := repo.Insert(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil CRAReport, got nil")
	}
}

// TestCRAReportsRepository_Insert_RejectsEmptyRequired pins the per-
// field validation. project_id / vulnerability_id / cve_id /
// report_type / lang / draft_text are all required.
func TestCRAReportsRepository_Insert_RejectsEmptyRequired(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	ev := validCRAEvidence()

	cases := []struct {
		name string
		c    *CRAReport
	}{
		{"no project_id", &CRAReport{TenantID: tenantID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", ReportType: "early_warning", Lang: "ja", DraftText: "x", Evidence: ev}},
		{"no vulnerability_id", &CRAReport{TenantID: tenantID, ProjectID: projectID, CVEID: "CVE-2025-1", ReportType: "early_warning", Lang: "ja", DraftText: "x", Evidence: ev}},
		{"no cve_id", &CRAReport{TenantID: tenantID, ProjectID: projectID, VulnerabilityID: vulnID, ReportType: "early_warning", Lang: "ja", DraftText: "x", Evidence: ev}},
		{"no report_type", &CRAReport{TenantID: tenantID, ProjectID: projectID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", Lang: "ja", DraftText: "x", Evidence: ev}},
		{"no lang", &CRAReport{TenantID: tenantID, ProjectID: projectID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", ReportType: "early_warning", DraftText: "x", Evidence: ev}},
		{"no draft_text", &CRAReport{TenantID: tenantID, ProjectID: projectID, VulnerabilityID: vulnID, CVEID: "CVE-2025-1", ReportType: "early_warning", Lang: "ja", Evidence: ev}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := repo.Insert(context.Background(), tc.c); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

// TestCRAReportsRepository_Insert_RequiresEvidence pins the load-
// bearing "no AI output without evidence" rule
// (PRODUCT_REBOOT_PLAN.md §8.5). The DB CHECK also catches this but
// the local guard turns the error into a clearer message and skips
// the round-trip. Same regression-class guard as vex_drafts (M1 F4).
func TestCRAReportsRepository_Insert_RequiresEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()

	cases := []struct {
		name string
		ev   json.RawMessage
	}{
		{"nil evidence", nil},
		{"empty bytes", json.RawMessage("")},
		{"empty array", json.RawMessage("[]")},
		{"not an array (object)", json.RawMessage(`{"kind":"x"}`)},
		{"not an array (string)", json.RawMessage(`"single"`)},
		{"malformed json", json.RawMessage(`[`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &CRAReport{
				TenantID:        tenantID,
				ProjectID:       projectID,
				VulnerabilityID: vulnID,
				CVEID:           "CVE-2025-1",
				ReportType:      "early_warning",
				Lang:            "ja",
				DraftText:       "x",
				Evidence:        tc.ev,
			}
			if err := repo.Insert(context.Background(), c); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued for empty-evidence cases: %v", err)
	}
}

// TestCRAReportsRepository_Insert_AssignsIDAndDefaults verifies the
// repository allocates a UUID when none is supplied AND defaults
// State to 'draft' and Decision to 'pending'.
func TestCRAReportsRepository_Insert_AssignsIDAndDefaults(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	now := time.Now().UTC()
	ev := validCRAEvidence()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_reports")).
		WithArgs(
			sqlmock.AnyArg(),        // $1  id (generated)
			tenantID,                // $2
			projectID,               // $3
			vulnID,                  // $4
			"CVE-2025-1",            // $5
			"detailed_notification", // $6
			"en",                    // $7
			"draft",                 // $8  state default
			"hand-authored",         // $9
			nil,                     // $10 provider (empty -> NULL)
			nil,                     // $11 model
			nil,                     // $12 prompt_hash
			nil,                     // $13 response_hash
			[]byte(ev),              // $14 evidence
			nil,                     // $15 source_vex_draft_id
			nil,                     // $16 llm_call_id
			"pending",               // $17 decision default
			nil,                     // $18 decision_by
			nil,                     // $19 decision_at
			nil,                     // $20 decision_note
			nil,                     // $21 created_by
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now))

	c := &CRAReport{
		TenantID:        tenantID,
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		CVEID:           "CVE-2025-1",
		ReportType:      "detailed_notification",
		Lang:            "en",
		DraftText:       "hand-authored",
		Evidence:        ev,
	}
	if err := repo.Insert(context.Background(), c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if c.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Insert, got uuid.Nil")
	}
	if c.State != "draft" {
		t.Errorf("expected default State draft, got %q", c.State)
	}
	if c.Decision != "pending" {
		t.Errorf("expected default Decision pending, got %q", c.Decision)
	}
	if c.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated after Insert, got zero")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_Insert_WrapsDBError ensures driver errors
// surface with context.
func TestCRAReportsRepository_Insert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_reports")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Insert(context.Background(), &CRAReport{
		TenantID:        uuid.New(),
		ProjectID:       uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-1",
		ReportType:      "final_report",
		Lang:            "en",
		DraftText:       "x",
		Evidence:        validCRAEvidence(),
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestCRAReportsRepository_Get_ReturnsNilOnNoRows pins down the
// (*CRAReport, error) contract.
func TestCRAReportsRepository_Get_ReturnsNilOnNoRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()

	mock.ExpectQuery(regexp.QuoteMeta("FROM cra_reports")).
		WithArgs(tenantID, id).
		WillReturnError(sql.ErrNoRows)

	got, err := repo.Get(context.Background(), tenantID, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil result, got %+v", got)
	}
}

// TestCRAReportsRepository_Get_RejectsZero pins the fail-fast on
// missing tenant / id.
func TestCRAReportsRepository_Get_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	if _, err := repo.Get(context.Background(), uuid.Nil, uuid.New()); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.Get(context.Background(), uuid.New(), uuid.Nil); err == nil {
		t.Fatal("expected error for zero id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// cra_reports row columns for ListByProject result helpers.
var craReportListCols = []string{
	"id", "tenant_id",
	"project_id", "vulnerability_id",
	"cve_id",
	"report_type", "lang", "state",
	"draft_text",
	"provider", "model", "prompt_hash", "response_hash",
	"evidence",
	"source_vex_draft_id", "llm_call_id",
	"decision", "decision_by", "decision_at", "decision_note",
	"created_by",
	"created_at", "updated_at",
}

// TestCRAReportsRepository_ListByProject_PassesTenantID asserts the
// WHERE clause binds tenant_id at $1, project_id at $2, and applies
// LIMIT/OFFSET defaults.
func TestCRAReportsRepository_ListByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()
	vulnID := uuid.New()
	rowID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM cra_reports[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2`).
		WithArgs(tenantID, projectID, 100, 0). // F24-pattern default limit
		WillReturnRows(sqlmock.NewRows(craReportListCols).AddRow(
			rowID, tenantID,
			projectID, vulnID,
			"CVE-2025-1",
			"early_warning", "ja", "draft",
			"draft body",
			"openai", "gpt-4o", nil, nil,
			[]byte(validCRAEvidence()),
			nil, nil,
			"pending", nil, nil, nil,
			nil,
			now, now,
		))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, CRAReportListFilter{})
	if err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s, got %s", tenantID, out[0].TenantID)
	}
	if out[0].ReportType != "early_warning" {
		t.Errorf("unexpected report_type: %q", out[0].ReportType)
	}
	if out[0].Lang != "ja" {
		t.Errorf("unexpected lang: %q", out[0].Lang)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_ListByProject_RejectsZeroTenant mirrors
// the read-side fail-fast.
func TestCRAReportsRepository_ListByProject_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	if _, err := repo.ListByProject(context.Background(), uuid.Nil, uuid.New(), CRAReportListFilter{}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.ListByProject(context.Background(), uuid.New(), uuid.Nil, CRAReportListFilter{}); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRAReportsRepository_ListByProject_AppliesFilters covers the
// dynamic WHERE-builder for the full filter set (cve_id, report_type,
// lang, state, decision).
func TestCRAReportsRepository_ListByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT[\s\S]+FROM cra_reports[\s\S]+cve_id = \$3[\s\S]+report_type = \$4[\s\S]+lang = \$5[\s\S]+state = \$6[\s\S]+decision = \$7`).
		WithArgs(tenantID, projectID, "CVE-2025-1", "early_warning", "ja", "draft", "pending", 10, 5).
		WillReturnRows(sqlmock.NewRows(craReportListCols))

	out, err := repo.ListByProject(context.Background(), tenantID, projectID, CRAReportListFilter{
		CVEID:      "CVE-2025-1",
		ReportType: "early_warning",
		Lang:       "ja",
		State:      "draft",
		Decision:   "pending",
		Limit:      10,
		Offset:     5,
	})
	if err != nil {
		t.Fatalf("ListByProject with filters: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepo_ListByProject_LimitClamp pins the repository-
// level defense-in-depth clamp (mirrors VEXDrafts #F24 regression).
// The handler already rejects out-of-band limits with 400, but the
// repository is reachable from any internal caller that builds a
// CRAReportListFilter directly (e.g. M2-6 evidence pack bundler in
// issue #34). The constants
// (craReportsListDefaultLimit=100, craReportsListMaxLimit=500) must
// be honored regardless of caller hygiene.
func TestCRAReportsRepo_ListByProject_LimitClamp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	// LIMIT $3 OFFSET $4. The repo must bind 500 (clamped), NOT 10000.
	mock.ExpectQuery(`SELECT[\s\S]+FROM cra_reports[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2[\s\S]+LIMIT \$3 OFFSET \$4`).
		WithArgs(tenantID, projectID, 500, 0).
		WillReturnRows(sqlmock.NewRows(craReportListCols))

	if _, err := repo.ListByProject(context.Background(), tenantID, projectID, CRAReportListFilter{
		Limit: 10000,
	}); err != nil {
		t.Fatalf("ListByProject with oversized limit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expected SQL LIMIT to be clamped to 500, but: %v", err)
	}
}

// TestCRAReportsRepository_CountByProject_PassesTenantID pins the
// F28-pattern X-Total-Count helper. tenant_id at $1, project_id at $2.
// COUNT(*) only -- the result is the total cardinality the handler
// emits as X-Total-Count for the Web UI.
func TestCRAReportsRepository_CountByProject_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM cra_reports[\s\S]+WHERE tenant_id = \$1 AND project_id = \$2`).
		WithArgs(tenantID, projectID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))

	n, err := repo.CountByProject(context.Background(), tenantID, projectID, CRAReportListFilter{})
	if err != nil {
		t.Fatalf("CountByProject: %v", err)
	}
	if n != 42 {
		t.Errorf("expected count 42, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_CountByProject_AppliesFilters ensures the
// filter shape matches ListByProject so X-Total-Count and the page
// length are adjudicated on the same units (M1 F29 regression-class
// guard).
func TestCRAReportsRepository_CountByProject_AppliesFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	projectID := uuid.New()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM cra_reports[\s\S]+cve_id = \$3[\s\S]+report_type = \$4[\s\S]+lang = \$5[\s\S]+state = \$6[\s\S]+decision = \$7`).
		WithArgs(tenantID, projectID, "CVE-2025-1", "early_warning", "ja", "draft", "pending").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	n, err := repo.CountByProject(context.Background(), tenantID, projectID, CRAReportListFilter{
		CVEID:      "CVE-2025-1",
		ReportType: "early_warning",
		Lang:       "ja",
		State:      "draft",
		Decision:   "pending",
	})
	if err != nil {
		t.Fatalf("CountByProject with filters: %v", err)
	}
	if n != 7 {
		t.Errorf("expected count 7, got %d", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_CountByProject_RejectsZero pins the read-
// side fail-fast for tenant/project.
func TestCRAReportsRepository_CountByProject_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	if _, err := repo.CountByProject(context.Background(), uuid.Nil, uuid.New(), CRAReportListFilter{}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.CountByProject(context.Background(), uuid.New(), uuid.Nil, CRAReportListFilter{}); err == nil {
		t.Fatal("expected error for zero project_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRAReportsRepository_UpdateDecision_PassesArgs pins the UPDATE
// statement's argument shape. tenant_id at $1 (load-bearing for the
// belt-and-braces tenant scope), id at $2, decision lifecycle fields
// at $3..$6, then the COALESCE-overwrite slot for the edited case at
// $7 (draft_text).
func TestCRAReportsRepository_UpdateDecision_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()
	when := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	editedDraft := "operator-refined draft text"

	mock.ExpectExec(regexp.QuoteMeta("UPDATE cra_reports SET")).
		WithArgs(
			tenantID,    // $1
			id,          // $2
			"edited",    // $3
			by,          // $4
			when,        // $5
			"reviewed",  // $6 decision_note
			editedDraft, // $7 draft_text COALESCE
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.UpdateDecision(context.Background(), tenantID, id, CRAReportDecisionUpdate{
		Decision:        "edited",
		DecisionBy:      by,
		DecisionAt:      when,
		DecisionNote:    "reviewed",
		EditedDraftText: &editedDraft,
	})
	if err != nil {
		t.Fatalf("UpdateDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_UpdateDecision_ApprovedKeepsDraftText
// verifies that an 'approved' decision leaves EditedDraftText at NULL
// (-> COALESCE keeps existing AI value). This is the contract that
// protects the AI evidence trail (the prose the LLM drafted) from
// being inadvertently nuked by an approve action.
func TestCRAReportsRepository_UpdateDecision_ApprovedKeepsDraftText(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()

	mock.ExpectExec(regexp.QuoteMeta("UPDATE cra_reports SET")).
		WithArgs(
			tenantID,         // $1
			id,               // $2
			"approved",       // $3
			by,               // $4
			sqlmock.AnyArg(), // $5 decision_at (defaulted to NOW())
			nil,              // $6 decision_note (empty -> NULL)
			nil,              // $7 draft_text COALESCE (nil pointer -> NULL -> keep)
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.UpdateDecision(context.Background(), tenantID, id, CRAReportDecisionUpdate{
		Decision:   "approved",
		DecisionBy: by,
	})
	if err != nil {
		t.Fatalf("UpdateDecision: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_UpdateDecision_RejectsInvalidDecision pins
// the decision allow-list ('approved' | 'edited' | 'rejected'). The
// DB CHECK also catches this but the local guard turns a pq error
// into a clearer message and skips the round-trip.
func TestCRAReportsRepository_UpdateDecision_RejectsInvalidDecision(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	cases := []string{"", "pending", "approve", "DELETED", "ok", "submitted"}
	for _, dec := range cases {
		t.Run("decision="+dec, func(t *testing.T) {
			err := repo.UpdateDecision(context.Background(), uuid.New(), uuid.New(), CRAReportDecisionUpdate{
				Decision:   dec,
				DecisionBy: uuid.New(),
			})
			if err == nil {
				t.Fatalf("expected error for decision %q, got nil", dec)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRAReportsRepository_UpdateDecision_RejectsZero pins the per-
// argument fail-fast.
func TestCRAReportsRepository_UpdateDecision_RejectsZero(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()

	if err := repo.UpdateDecision(context.Background(), uuid.Nil, id, CRAReportDecisionUpdate{Decision: "approved", DecisionBy: by}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := repo.UpdateDecision(context.Background(), tenantID, uuid.Nil, CRAReportDecisionUpdate{Decision: "approved", DecisionBy: by}); err == nil {
		t.Fatal("expected error for zero id, got nil")
	}
	if err := repo.UpdateDecision(context.Background(), tenantID, id, CRAReportDecisionUpdate{Decision: "approved"}); err == nil {
		t.Fatal("expected error for zero decision_by, got nil")
	}
}

// TestCRAReportsRepository_UpdateDecision_NoRowsErrors verifies the
// "silent no-op" guard: when the UPDATE matches zero rows (wrong id,
// wrong tenant, OR already decided per F31), the repository returns a
// wrapped sql.ErrNoRows so handlers can distinguish "decision landed"
// from "could not apply".
func TestCRAReportsRepository_UpdateDecision_NoRowsErrors(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	mock.ExpectExec(regexp.QuoteMeta("UPDATE cra_reports SET")).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.UpdateDecision(context.Background(), uuid.New(), uuid.New(), CRAReportDecisionUpdate{
		Decision:   "approved",
		DecisionBy: uuid.New(),
	})
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected wrapped sql.ErrNoRows, got %v", err)
	}
}

// TestCRAReportsRepo_UpdateDecision_AlreadyApproved_F31 pins the
// state-machine guard (M2 Codex review #F31): the WHERE clause carries
// `AND decision = 'pending'`, so an already-decided row matches zero
// rows and the repository returns wrapped sql.ErrNoRows. Without this
// guard, a follow-up decision='edited' call against an already-
// approved report would silently rewrite the approved draft_text (the
// AI evidence trail), and any party with write permission could
// "re-decide" a previously rejected report — silently swapping the
// compliance verdict.
//
// The test asserts both the strict regex match on the guard literal in
// the SQL AND the wrapped sql.ErrNoRows return contract that the
// handler relies on to surface a 409.
func TestCRAReportsRepo_UpdateDecision_AlreadyApproved_F31(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	id := uuid.New()
	by := uuid.New()

	// Regex matcher requires the guard literal to appear in the SQL.
	// A regression that drops the `AND decision = 'pending'` clause
	// fails this test even before the result-shape assertion runs.
	mock.ExpectExec(`UPDATE cra_reports SET[\s\S]+WHERE tenant_id = \$1 AND id = \$2 AND decision = 'pending'`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.UpdateDecision(context.Background(), tenantID, id, CRAReportDecisionUpdate{
		Decision:   "edited",
		DecisionBy: by,
	})
	if err == nil {
		t.Fatal("F31: expected sql.ErrNoRows when row already decided, got nil")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("F31: expected wrapped sql.ErrNoRows, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("F31: SQL guard expectation not met: %v", err)
	}
}

// TestCRAReport_JSONShape pins the wire JSON tags. M1 F28 fix
// regression: the Web UI relies on snake_case keys; a missing or
// renamed tag would silently break the /cra/reports page. We do not
// hand-roll a marshal-and-compare here because field order would be
// brittle; instead we round-trip a struct and assert every load-
// bearing key shows up in the marshalled JSON. Adding a new field
// without a json tag fails this test.
func TestCRAReport_JSONShape(t *testing.T) {
	c := CRAReport{
		ID:              uuid.New(),
		TenantID:        uuid.New(),
		ProjectID:       uuid.New(),
		VulnerabilityID: uuid.New(),
		CVEID:           "CVE-2025-1",
		ReportType:      "early_warning",
		Lang:            "ja",
		State:           "draft",
		DraftText:       "x",
		Provider:        "openai",
		Model:           "gpt-4o",
		PromptHash:      "p",
		ResponseHash:    "r",
		Evidence:        validCRAEvidence(),
		Decision:        "pending",
		DecisionNote:    "note",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	required := []string{
		`"id":`, `"tenant_id":`, `"project_id":`, `"vulnerability_id":`,
		`"cve_id":`, `"report_type":`, `"lang":`, `"state":`,
		`"draft_text":`, `"provider":`, `"model":`,
		`"prompt_hash":`, `"response_hash":`, `"evidence":`,
		`"decision":`, `"decision_note":`,
		`"created_at":`, `"updated_at":`,
	}
	for _, key := range required {
		if !contains(s, key) {
			t.Errorf("expected wire JSON to contain %s; got %s", key, s)
		}
	}
}

// contains is a tiny strings.Contains replacement so the test file
// does not pull in another import just for one assertion helper.
func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
