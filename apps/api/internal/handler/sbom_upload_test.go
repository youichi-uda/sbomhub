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
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ----------------------------------------------------------------------------
// F443 regression — Upload must not blanket-400 (and leak) internal errors
// ----------------------------------------------------------------------------
//
// Before F443, POST /api/v1/projects/:id/sbom returned
// `400 {"error": err.Error()}` for EVERY SbomService.Import failure. Import
// returns a MIX:
//
//   - caller-fixable validation (malformed SBOM → parse/detect failure):
//     the message is safe + helpful feedback → 400 is correct.
//   - %w-wrapped internal/DB errors (resolve tenant / save sbom / save
//     component): these must be 500 with a generic body — the pre-fix path
//     both misreported them as 400 AND echoed the raw driver string.
//
// The service now marks the validation branch with service.ErrValidation and
// leaves the DB branch %w-wrapped; the handler splits on
// errors.Is(err, service.ErrValidation). These two tests are non-vacuous:
// pre-fix BOTH returned 400 + raw string.

// driveUpload wires the handler with a sqlmock-backed real service and
// POSTs the supplied body. Callers register whatever sqlmock expectations
// the body's Import path will (or will not) reach.
func driveUpload(t *testing.T, h *SbomHandler, projectID uuid.UUID, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/sbom",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())

	if err := h.Upload(c); err != nil {
		t.Fatalf("Upload returned unexpected error: %v", err)
	}
	return rec
}

// TestSBOMHandler_Upload_ValidationError_400_F443 pins the client-fixable
// branch: a malformed SBOM body makes detectFormatAndVersion (inside Import)
// fail BEFORE any repository call, so the service returns an ErrValidation
// error and the handler must answer 400 with the helpful parse message.
//
// No sqlmock expectations are registered — detection happens before the DB
// is touched, so a regression that reached a repository would trip sqlmock's
// "unexpected query".
func TestSBOMHandler_Upload_ValidationError_400_F443(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	projectID := uuid.New()
	// Valid JSON but not a recognisable SBOM shape → "unknown SBOM format".
	rec := driveUpload(t, h, projectID, `{"not":"an-sbom"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F443: malformed SBOM must return 400, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "failed to parse SBOM") {
		t.Errorf("F443: expected helpful parse-failure message, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestSBOMHandler_Upload_InternalError_500_NoLeak_F443 pins the internal
// branch: a well-formed CycloneDX body clears format detection, so Import
// reaches LookupProjectTenantID; sqlmock makes that query fail with a
// distinctive driver string. The handler must answer 500 with a generic body
// and MUST NOT echo the raw DB error.
func TestSBOMHandler_Upload_InternalError_500_NoLeak_F443(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	projectID := uuid.New()

	const rawDBLeak = "pq: connection reset by peer SECRET-INTERNAL-DETAIL"
	// Import → LookupProjectTenantID → SELECT tenant_id FROM projects ...
	mock.ExpectQuery(`SELECT tenant_id FROM projects WHERE id = \$1`).
		WithArgs(projectID).
		WillReturnError(errors.New(rawDBLeak))

	sbomService := service.NewSbomService(
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewSbomHandler(db, sbomService, nil, nil, nil)

	rec := driveUpload(t, h, projectID, `{"bomFormat":"CycloneDX","specVersion":"1.5"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("F443: internal DB error must return 500, got %d (body=%s)",
			rec.Code, rec.Body.String())
	}
	if contains(rec.Body.String(), "SECRET-INTERNAL-DETAIL") {
		t.Errorf("F443: raw DB error leaked to client: %s", rec.Body.String())
	}
	if !contains(rec.Body.String(), "failed to import SBOM") {
		t.Errorf("F443: expected generic body, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
