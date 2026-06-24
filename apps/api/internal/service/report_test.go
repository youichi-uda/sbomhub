package service

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
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
	// completed_at). We assert the status field flipped to "failed" and the
	// error message landed in error_message.
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
