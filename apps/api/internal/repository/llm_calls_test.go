package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestLLMCallsRepository_Insert_PassesTenantID asserts that the INSERT
// statement binds tenant_id at position 2 and that the column ordering
// matches the migration 032 schema. The tenant_id position is
// load-bearing: it pairs with the RLS WITH CHECK clause -- a
// mis-positioned bind would silently land tenant_id NULL (or some other
// value), which the RLS layer would reject at runtime with a confusing
// error, or, worse, in a future world where RLS is removed, would leak
// rows across tenants.
func TestLLMCallsRepository_Insert_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	tenantID := uuid.New()
	userID := uuid.New()
	callID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO llm_calls")).
		WithArgs(
			callID,             // $1  id
			tenantID,           // $2  tenant_id
			userID,             // $3  user_id
			"vex_triage",       // $4  purpose
			"openai",           // $5  provider
			"gpt-4o",           // $6  model
			"deadbeef",         // $7  prompt_hash
			"prompt preview",   // $8  prompt_preview
			"cafebabe",         // $9  response_hash
			"response preview", // $10 response_preview
			nil,                // $11 response_body (empty -> NULL)
			120,                // $12 input_tokens
			45,                 // $13 output_tokens
			0.0123,             // $14 cost_usd
			800,                // $15 duration_ms
			"stop",             // $16 finish_reason
			nil,                // $17 error_message (empty -> NULL)
			"CVE-2025-12345",   // $18 triage_target_cve
			nil,                // $19 triage_target_component_id
			nil,                // $20 cra_report_id
			now,                // $21 created_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Insert(context.Background(), &LLMCall{
		ID:              callID,
		TenantID:        tenantID,
		UserID:          &userID,
		Purpose:         "vex_triage",
		Provider:        "openai",
		Model:           "gpt-4o",
		PromptHash:      "deadbeef",
		PromptPreview:   "prompt preview",
		ResponseHash:    "cafebabe",
		ResponsePreview: "response preview",
		InputTokens:     120,
		OutputTokens:    45,
		CostUSD:         0.0123,
		DurationMs:      800,
		FinishReason:    "stop",
		TriageTargetCVE: "CVE-2025-12345",
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("Insert returned unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLLMCallsRepository_Insert_RejectsZeroTenant pins down the
// fail-fast contract: a zero TenantID is rejected before any SQL is
// issued. This stops a caller-side bug (forgotten tenant assignment)
// from being silently caught by the RLS layer with a generic
// "permission denied" error that is harder to debug.
func TestLLMCallsRepository_Insert_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// Deliberately no ExpectExec: a SQL call here would fail the test.

	repo := NewLLMCallsRepository(db)
	err = repo.Insert(context.Background(), &LLMCall{
		// TenantID intentionally zero
		Purpose:      "vex_triage",
		Provider:     "openai",
		Model:        "gpt-4o",
		PromptHash:   "x",
		ResponseHash: "y",
	})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestLLMCallsRepository_Insert_RejectsNil guards against the
// nil-pointer dereference that would otherwise happen on a
// repo.Insert(ctx, nil) call (e.g. from an over-zealous error path that
// reuses the same variable).
func TestLLMCallsRepository_Insert_RejectsNil(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	if err := repo.Insert(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil LLMCall, got nil")
	}
}

// TestLLMCallsRepository_Insert_AssignsIDIfZero verifies that the
// repository allocates a UUID when the caller does not supply one, and
// that the assigned id is written back to the struct so callers can log
// it. This is the same convention as uuid.New() default in
// AuditRepository.Log.
func TestLLMCallsRepository_Insert_AssignsIDIfZero(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	tenantID := uuid.New()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO llm_calls")).
		WithArgs(
			sqlmock.AnyArg(), // $1  id (generated; AnyArg lets us still assert it was set after)
			tenantID,         // $2  tenant_id
			nil,              // $3  user_id (nil pointer -> NULL)
			"embed", "ollama", "qwen2.5-coder:7b",
			"hashp", nil, "hashr", nil, nil,
			10, 0, 0.0, 12,
			nil, nil,
			nil, nil, nil,
			sqlmock.AnyArg(), // $21 created_at (defaulted)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	c := &LLMCall{
		TenantID:     tenantID,
		Purpose:      "embed",
		Provider:     "ollama",
		Model:        "qwen2.5-coder:7b",
		PromptHash:   "hashp",
		ResponseHash: "hashr",
		InputTokens:  10,
		DurationMs:   12,
	}
	if err := repo.Insert(context.Background(), c); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if c.ID == uuid.Nil {
		t.Fatal("expected ID to be populated after Insert, got uuid.Nil")
	}
	if c.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated after Insert, got zero")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLLMCallsRepository_List_PassesTenantID asserts that List binds
// tenant_id at position 1 and applies LIMIT/OFFSET defaults. The
// application-layer tenant filter is the safety net for the case where
// migration 032's RLS policy is ever lifted (compare audit_logs /
// api_keys / public_links, all of which removed RLS in 028/029/030 and
// rely solely on WHERE tenant_id = $N clauses now).
func TestLLMCallsRepository_List_PassesTenantID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	tenantID := uuid.New()

	rowCols := []string{
		"id", "tenant_id", "user_id",
		"purpose", "provider", "model",
		"prompt_hash", "prompt_preview",
		"response_hash", "response_preview", "response_body",
		"input_tokens", "output_tokens", "cost_usd", "duration_ms",
		"finish_reason", "error_message",
		"triage_target_cve", "triage_target_component_id", "cra_report_id",
		"created_at",
	}
	rowID := uuid.New()
	now := time.Now().UTC()

	mock.ExpectQuery(`SELECT[\s\S]+FROM llm_calls`).
		WithArgs(tenantID, 50, 0).
		WillReturnRows(sqlmock.NewRows(rowCols).AddRow(
			rowID, tenantID, nil,
			"vex_triage", "openai", "gpt-4o",
			"hashp", nil,
			"hashr", nil, nil,
			120, 45, 0.0123, 800,
			nil, nil,
			nil, nil, nil,
			now,
		))

	out, err := repo.List(context.Background(), tenantID, LLMCallListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 row, got %d", len(out))
	}
	if out[0].TenantID != tenantID {
		t.Errorf("expected tenant_id %s in scanned row, got %s", tenantID, out[0].TenantID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLLMCallsRepository_List_RejectsZeroTenant mirrors the Insert
// fail-fast: List is the read counterpart and must refuse to issue a
// tenant-unscoped query, which would otherwise return zero rows under
// RLS (silently confusing) or every row (catastrophic if RLS is off).
func TestLLMCallsRepository_List_RejectsZeroTenant(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No ExpectQuery: any SQL would fail the assertion.

	repo := NewLLMCallsRepository(db)
	_, err = repo.List(context.Background(), uuid.Nil, LLMCallListFilter{})
	if err == nil {
		t.Fatal("expected error for zero tenant_id, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no SQL should have been issued: %v", err)
	}
}

// TestLLMCallsRepository_List_AppliesPurposeFilter pins down the optional
// filter wiring. Without this test a typo in the dynamic WHERE-builder
// (wrong $-index, missing AND) would silently fall back to "list
// everything for this tenant" and the bug would only surface in
// downstream analytics.
func TestLLMCallsRepository_List_AppliesPurposeFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	tenantID := uuid.New()

	rowCols := []string{
		"id", "tenant_id", "user_id",
		"purpose", "provider", "model",
		"prompt_hash", "prompt_preview",
		"response_hash", "response_preview", "response_body",
		"input_tokens", "output_tokens", "cost_usd", "duration_ms",
		"finish_reason", "error_message",
		"triage_target_cve", "triage_target_component_id", "cra_report_id",
		"created_at",
	}

	mock.ExpectQuery(`SELECT[\s\S]+FROM llm_calls[\s\S]+purpose = \$2`).
		WithArgs(tenantID, "cra_draft", 10, 5).
		WillReturnRows(sqlmock.NewRows(rowCols))

	out, err := repo.List(context.Background(), tenantID, LLMCallListFilter{
		Purpose: "cra_draft",
		Limit:   10,
		Offset:  5,
	})
	if err != nil {
		t.Fatalf("List with purpose filter: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected 0 rows, got %d", len(out))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestLLMCallsRepository_Insert_WrapsDBError makes sure the repository
// surfaces the underlying driver error with context instead of swallowing
// it. Useful for the audit layer in service/llm/audit.go which decides
// whether to retry / drop the audit row based on the error type.
func TestLLMCallsRepository_Insert_WrapsDBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewLLMCallsRepository(db)
	tenantID := uuid.New()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO llm_calls")).
		WillReturnError(sql.ErrConnDone)

	err = repo.Insert(context.Background(), &LLMCall{
		TenantID:     tenantID,
		Purpose:      "vex_triage",
		Provider:     "openai",
		Model:        "gpt-4o",
		PromptHash:   "x",
		ResponseHash: "y",
	})
	if err == nil || !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("expected wrapped sql.ErrConnDone, got %v", err)
	}
}
