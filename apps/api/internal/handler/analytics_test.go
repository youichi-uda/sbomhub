package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ----------------------------------------------------------------------------
// F443 regression — UpdateSLOTarget must not blanket-400 (and leak) DB errors
// ----------------------------------------------------------------------------
//
// Before F443, PUT /api/v1/analytics/slo-targets returned
// `400 {"error": err.Error()}` for EVERY AnalyticsService.UpdateSLOTarget
// failure. The service returned validation errors ("invalid severity",
// "target hours must be positive") AND, on the fall-through, the RAW
// (unwrapped) repository error — so a DB failure was both misreported as 400
// and leaked the driver string.
//
// The service now marks the validation returns with service.ErrValidation
// and %w-wraps the repository error ("upsert slo target: %w"); the handler
// splits on errors.Is(err, service.ErrValidation). These two tests are
// non-vacuous: pre-fix BOTH returned 400 + raw string.

// driveUpdateSLOTarget wires the handler with a sqlmock-backed real service
// and PUTs the supplied body, with an admin tenant context installed (the
// handler gates on tenant + CanAdmin before reaching the service).
func driveUpdateSLOTarget(t *testing.T, h *AnalyticsHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/analytics/slo-targets",
		strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Satisfy the tenant + admin gate so execution reaches the service.
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	c.Set(middleware.ContextKeyRole, model.RoleAdmin)

	if err := h.UpdateSLOTarget(c); err != nil {
		t.Fatalf("UpdateSLOTarget returned unexpected error: %v", err)
	}
	return rec
}

// TestAnalyticsHandler_UpdateSLOTarget_ValidationError_400_F443 pins the
// client-fixable branch: an invalid severity makes the service return an
// ErrValidation error BEFORE the repository is touched, so the handler must
// answer 400 with the helpful message. No sqlmock expectations are
// registered — a regression that reached the DB would trip sqlmock's
// "unexpected query".
func TestAnalyticsHandler_UpdateSLOTarget_ValidationError_400_F443(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	analyticsService := service.NewAnalyticsService(
		repository.NewAnalyticsRepository(db), nil,
	)
	h := NewAnalyticsHandler(analyticsService)

	rec := driveUpdateSLOTarget(t, h, `{"severity":"BOGUS","target_hours":24}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F443: invalid severity must return 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "invalid severity") {
		t.Errorf("F443: expected 'invalid severity' feedback, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestAnalyticsHandler_UpdateSLOTarget_InternalError_500_NoLeak_F443 pins the
// internal branch: valid inputs clear validation, so the service reaches
// UpsertSLOTarget; sqlmock makes that Exec fail with a distinctive driver
// string. The handler must answer 500 with a generic body and MUST NOT echo
// the raw DB error.
func TestAnalyticsHandler_UpdateSLOTarget_InternalError_500_NoLeak_F443(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	const rawDBLeak = "pq: deadlock detected SECRET-INTERNAL-DETAIL"
	mock.ExpectExec(`INSERT INTO slo_targets`).
		WillReturnError(errors.New(rawDBLeak))

	analyticsService := service.NewAnalyticsService(
		repository.NewAnalyticsRepository(db), nil,
	)
	h := NewAnalyticsHandler(analyticsService)

	rec := driveUpdateSLOTarget(t, h, `{"severity":"CRITICAL","target_hours":24}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F443: internal DB error must return 500, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if contains(rec.Body.String(), "SECRET-INTERNAL-DETAIL") {
		t.Errorf("F443: raw DB error leaked to client: %s", rec.Body.String())
	}
	if !contains(rec.Body.String(), "failed to update SLO target") {
		t.Errorf("F443: expected generic body, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
