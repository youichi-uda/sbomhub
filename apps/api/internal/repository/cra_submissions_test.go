package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// cra_submissions row columns for ListByReport result helpers. Order
// matches the SELECT + scanCRASubmissionRow contract in
// cra_submissions.go.
var craSubmissionListCols = []string{
	"id", "tenant_id",
	"cra_report_id",
	"authority",
	"submitted_at",
	"submitted_by",
	"reference_number",
	"notes",
	"created_at", "updated_at",
}

func strptr(s string) *string { return &s }

// TestCRASubmissionsRepository_Record_PassesArgs asserts the INSERT
// column ordering matches migration 053 and binds tenant_id at $1 --
// the same load-bearing position the RLS WITH CHECK policy compares
// against. A mis-positioned bind would silently land tenant_id wrong,
// which the RLS layer would reject at runtime or (RLS-off future) leak
// rows across tenants.
func TestCRASubmissionsRepository_Record_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	tenantID := uuid.New()
	reportID := uuid.New()
	submittedBy := uuid.New()
	rowID := uuid.New()
	when := time.Date(2026, 7, 5, 9, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_submissions")).
		WithArgs(
			tenantID,        // $1 tenant_id
			reportID,        // $2 cra_report_id
			"ENISA CSIRT",   // $3 authority
			when,            // $4 submitted_at
			submittedBy,     // $5 submitted_by
			"ACK-2026-0001", // $6 reference_number
			"72h detailed",  // $7 notes
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(rowID, now, now))

	got, err := repo.Record(context.Background(), CRASubmissionInput{
		TenantID:        tenantID,
		CRAReportID:     reportID,
		Authority:       "ENISA CSIRT",
		SubmittedAt:     when,
		SubmittedBy:     &submittedBy,
		ReferenceNumber: strptr("ACK-2026-0001"),
		Notes:           strptr("72h detailed"),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got.ID != rowID {
		t.Errorf("expected returned id %s, got %s", rowID, got.ID)
	}
	if got.TenantID != tenantID || got.CRAReportID != reportID {
		t.Errorf("input fields not echoed back: tenant=%s report=%s", got.TenantID, got.CRAReportID)
	}
	if !got.SubmittedAt.Equal(when) {
		t.Errorf("expected echoed submitted_at %s, got %s", when, got.SubmittedAt)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("expected created_at/updated_at populated from RETURNING")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRASubmissionsRepository_Record_NullableFields verifies the three
// optional fields (submitted_by / reference_number / notes) land as SQL
// NULL when their pointers are nil.
func TestCRASubmissionsRepository_Record_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	tenantID := uuid.New()
	reportID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_submissions")).
		WithArgs(
			tenantID,         // $1
			reportID,         // $2
			"BSI",            // $3
			sqlmock.AnyArg(), // $4 submitted_at (defaulted)
			nil,              // $5 submitted_by -> NULL
			nil,              // $6 reference_number -> NULL
			nil,              // $7 notes -> NULL
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New(), now, now))

	got, err := repo.Record(context.Background(), CRASubmissionInput{
		TenantID:    tenantID,
		CRAReportID: reportID,
		Authority:   "BSI",
		// SubmittedAt zero -> repo defaults to NOW().
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got.SubmittedAt.IsZero() {
		t.Error("expected zero SubmittedAt to be defaulted to a non-zero time")
	}
	if got.SubmittedBy != nil || got.ReferenceNumber != nil || got.Notes != nil {
		t.Error("expected nil optional fields to be echoed back as nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRASubmissionsRepository_Record_RejectsInvalid pins the fail-fast
// validation. tenant_id / cra_report_id / authority are all required
// and no SQL must be issued when any is missing.
func TestCRASubmissionsRepository_Record_RejectsInvalid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	cases := []struct {
		name string
		in   CRASubmissionInput
	}{
		{"no tenant", CRASubmissionInput{CRAReportID: uuid.New(), Authority: "X"}},
		{"no report", CRASubmissionInput{TenantID: uuid.New(), Authority: "X"}},
		{"empty authority", CRASubmissionInput{TenantID: uuid.New(), CRAReportID: uuid.New(), Authority: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := repo.Record(context.Background(), tc.in); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRASubmissionsRepository_Record_WrapsDBError ensures driver errors
// surface with context.
func TestCRASubmissionsRepository_Record_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO cra_submissions")).
		WillReturnError(sql.ErrConnDone)

	_, err = repo.Record(context.Background(), CRASubmissionInput{
		TenantID:    uuid.New(),
		CRAReportID: uuid.New(),
		Authority:   "X",
		SubmittedAt: time.Now().UTC(),
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestCRASubmissionsRepository_ListByReport_PassesArgs asserts the WHERE
// clause binds tenant_id at $1, cra_report_id at $2, and orders by
// submitted_at DESC (the timeline order).
func TestCRASubmissionsRepository_ListByReport_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	tenantID := uuid.New()
	reportID := uuid.New()
	rowID := uuid.New()
	submittedBy := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM cra_submissions[\s\S]+WHERE tenant_id = \$1 AND cra_report_id = \$2[\s\S]+ORDER BY submitted_at DESC`).
		WithArgs(tenantID, reportID).
		WillReturnRows(sqlmock.NewRows(craSubmissionListCols).AddRow(
			rowID, tenantID,
			reportID,
			"ENISA CSIRT",
			now,
			submittedBy.String(),
			"ACK-1",
			"note",
			now, now,
		))

	out, err := repo.ListByReport(context.Background(), tenantID, reportID)
	if err != nil {
		t.Fatalf("ListByReport: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID || out[0].CRAReportID != reportID {
		t.Errorf("unexpected scoping: tenant=%s report=%s", out[0].TenantID, out[0].CRAReportID)
	}
	if out[0].SubmittedBy == nil || *out[0].SubmittedBy != submittedBy {
		t.Errorf("expected submitted_by %s, got %v", submittedBy, out[0].SubmittedBy)
	}
	if out[0].ReferenceNumber == nil || *out[0].ReferenceNumber != "ACK-1" {
		t.Errorf("expected reference_number ACK-1, got %v", out[0].ReferenceNumber)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRASubmissionsRepository_ListByReport_NullOptionalCols verifies
// NULL optional columns decode to nil pointers.
func TestCRASubmissionsRepository_ListByReport_NullOptionalCols(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	tenantID := uuid.New()
	reportID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM cra_submissions`).
		WithArgs(tenantID, reportID).
		WillReturnRows(sqlmock.NewRows(craSubmissionListCols).AddRow(
			uuid.New(), tenantID,
			reportID,
			"BSI",
			now,
			nil, // submitted_by NULL
			nil, // reference_number NULL
			nil, // notes NULL
			now, now,
		))

	out, err := repo.ListByReport(context.Background(), tenantID, reportID)
	if err != nil {
		t.Fatalf("ListByReport: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].SubmittedBy != nil || out[0].ReferenceNumber != nil || out[0].Notes != nil {
		t.Errorf("expected NULL optional columns to decode to nil pointers, got %+v", out[0])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRASubmissionsRepository_ListByReport_RejectsZero mirrors the
// read-side fail-fast.
func TestCRASubmissionsRepository_ListByReport_RejectsZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	if _, err := repo.ListByReport(context.Background(), uuid.Nil, uuid.New()); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if _, err := repo.ListByReport(context.Background(), uuid.New(), uuid.Nil); err == nil {
		t.Fatal("expected error for zero cra_report_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRAReportsRepository_MarkSubmitted_Guard pins the load-bearing
// UPDATE: state -> 'submitted' with the belt-and-braces
// `decision = 'approved'` guard and the tenant/id scope. A regression
// that drops the guard or the state assignment fails the regex match.
func TestCRAReportsRepository_MarkSubmitted_Guard(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	tenantID := uuid.New()
	reportID := uuid.New()

	mock.ExpectExec(`UPDATE cra_reports SET[\s\S]+state\s*=\s*'submitted'[\s\S]+WHERE tenant_id = \$1 AND id = \$2 AND decision = 'approved'`).
		WithArgs(tenantID, reportID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := repo.MarkSubmitted(context.Background(), tenantID, reportID); err != nil {
		t.Fatalf("MarkSubmitted: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_MarkSubmitted_IdempotentZeroRows pins the
// idempotency contract: zero rows affected is NOT an error (belt-and-
// braces guard + handler already gated approved-only). Unlike
// UpdateDecision, MarkSubmitted must return nil on n == 0.
func TestCRAReportsRepository_MarkSubmitted_IdempotentZeroRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	mock.ExpectExec(regexp.QuoteMeta("UPDATE cra_reports SET")).
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := repo.MarkSubmitted(context.Background(), uuid.New(), uuid.New()); err != nil {
		t.Fatalf("expected nil error on zero-rows idempotent no-op, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRAReportsRepository_MarkSubmitted_WrapsDBError ensures driver
// errors surface with context.
func TestCRAReportsRepository_MarkSubmitted_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	mock.ExpectExec(regexp.QuoteMeta("UPDATE cra_reports SET")).
		WillReturnError(sql.ErrConnDone)

	err = repo.MarkSubmitted(context.Background(), uuid.New(), uuid.New())
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestCRAReportsRepository_MarkSubmitted_RejectsZero pins the per-
// argument fail-fast.
func TestCRAReportsRepository_MarkSubmitted_RejectsZero(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRAReportsRepository(db)
	if err := repo.MarkSubmitted(context.Background(), uuid.Nil, uuid.New()); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := repo.MarkSubmitted(context.Background(), uuid.New(), uuid.Nil); err == nil {
		t.Fatal("expected error for zero id, got nil")
	}
}

// TestCRASubmissionsRepository_EarliestSubmittedAtByReports_PassesArgs
// pins the batched MIN(submitted_at) query (M34-A / F423): tenant_id at
// $1, the report-id array cast to ::uuid[] at $2, GROUP BY cra_report_id,
// and the returned map keyed by report id with each report's earliest
// submission time. A report id with no submissions is absent from the map
// (only the two returned rows land; the third id passed in does not).
func TestCRASubmissionsRepository_EarliestSubmittedAtByReports_PassesArgs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	tenantID := uuid.New()
	reportA := uuid.New()
	reportB := uuid.New()
	reportC := uuid.New() // has no submissions -> absent from the result map
	earliestA := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	earliestB := time.Date(2026, 6, 25, 8, 30, 0, 0, time.UTC)

	mock.ExpectQuery(`SELECT cra_report_id, MIN\(submitted_at\)[\s\S]+FROM cra_submissions[\s\S]+WHERE tenant_id = \$1 AND cra_report_id = ANY\(\$2::uuid\[\]\)[\s\S]+GROUP BY cra_report_id`).
		WithArgs(tenantID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"cra_report_id", "min"}).
			AddRow(reportA, earliestA).
			AddRow(reportB, earliestB))

	out, err := repo.EarliestSubmittedAtByReports(context.Background(), tenantID, []uuid.UUID{reportA, reportB, reportC})
	if err != nil {
		t.Fatalf("EarliestSubmittedAtByReports: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 entries, got %d (%v)", len(out), out)
	}
	if got, ok := out[reportA]; !ok || !got.Equal(earliestA) {
		t.Errorf("reportA earliest = %v (ok=%v), want %v", got, ok, earliestA)
	}
	if got, ok := out[reportB]; !ok || !got.Equal(earliestB) {
		t.Errorf("reportB earliest = %v (ok=%v), want %v", got, ok, earliestB)
	}
	if _, ok := out[reportC]; ok {
		t.Errorf("reportC has no submissions and must be absent from the map, got present")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCRASubmissionsRepository_EarliestSubmittedAtByReports_EmptyReportIDs
// pins the short-circuit: an empty slice returns an empty (non-nil) map
// and issues NO query.
func TestCRASubmissionsRepository_EarliestSubmittedAtByReports_EmptyReportIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	out, err := repo.EarliestSubmittedAtByReports(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("EarliestSubmittedAtByReports(empty): %v", err)
	}
	if out == nil {
		t.Fatal("expected a non-nil empty map, got nil")
	}
	if len(out) != 0 {
		t.Errorf("expected empty map, got %d entries", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued for empty reportIDs: %v", err)
	}
}

// TestCRASubmissionsRepository_EarliestSubmittedAtByReports_RejectsZeroTenant
// mirrors the read-side fail-fast: a zero tenant is rejected before any
// SQL.
func TestCRASubmissionsRepository_EarliestSubmittedAtByReports_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	if _, err := repo.EarliestSubmittedAtByReports(context.Background(), uuid.Nil, []uuid.UUID{uuid.New()}); err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestCRASubmissionsRepository_EarliestSubmittedAtByReports_WrapsDBError
// ensures driver errors surface with context.
func TestCRASubmissionsRepository_EarliestSubmittedAtByReports_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewCRASubmissionsRepository(db)
	mock.ExpectQuery(`SELECT cra_report_id, MIN\(submitted_at\)`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(sql.ErrConnDone)

	_, err = repo.EarliestSubmittedAtByReports(context.Background(), uuid.New(), []uuid.UUID{uuid.New()})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}

// TestCRASubmission_JSONShape pins the wire JSON tags. The Wave B (F419)
// handler serialises this struct directly; the Web (Wave C) and CLI
// (Wave D) clients read snake_case keys. A missing / renamed tag would
// silently break the submission timeline. Adding a field without a json
// tag fails this test.
func TestCRASubmission_JSONShape(t *testing.T) {
	by := uuid.New()
	s := CRASubmission{
		ID:              uuid.New(),
		TenantID:        uuid.New(),
		CRAReportID:     uuid.New(),
		Authority:       "ENISA CSIRT",
		SubmittedAt:     time.Now().UTC(),
		SubmittedBy:     &by,
		ReferenceNumber: strptr("ACK-1"),
		Notes:           strptr("note"),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	str := string(b)
	required := []string{
		`"id":`, `"tenant_id":`, `"cra_report_id":`, `"authority":`,
		`"submitted_at":`, `"submitted_by":`, `"reference_number":`,
		`"notes":`, `"created_at":`, `"updated_at":`,
	}
	for _, key := range required {
		if !strings.Contains(str, key) {
			t.Errorf("expected wire JSON to contain %s; got %s", key, str)
		}
	}
}
