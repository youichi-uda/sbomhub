package handler

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ----------------------------------------------------------------------------
// F443 regression — CLIHandler.Upload must not blanket-400 (and leak)
// internal errors (mirrors sbom_upload_test.go for POST /cli/upload).
// ----------------------------------------------------------------------------
//
// Before the split, POST /cli/upload returned `400 {"error": err.Error()}` for
// EVERY CLIService.UploadSBOM failure. UploadSBOM returns a MIX:
//
//   - caller-fixable validation (malformed SBOM → format/component parse
//     failure): the message is safe + helpful feedback → 400 is correct.
//   - %w-wrapped internal/DB errors (resolve tenant / save sbom / save
//     component): these must be 500 with a generic body — the pre-fix path
//     both misreported them as 400 AND echoed the raw driver string.
//
// The service now marks the parse branch with service.ErrValidation and leaves
// the DB branch %w-wrapped; the handler splits on
// errors.Is(err, service.ErrValidation). These two tests are non-vacuous:
// pre-fix BOTH returned 400 + raw string.

// newCLIUpload builds a multipart/form-data POST /cli/upload request carrying
// project_name + an sbom file with the supplied body.
func newCLIUpload(t *testing.T, projectName, sbomBody string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("project_name", projectName); err != nil {
		t.Fatalf("write project_name: %v", err)
	}
	fw, err := w.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write([]byte(sbomBody)); err != nil {
		t.Fatalf("write sbom body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/cli/upload", &buf)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	return req
}

// driveCLIUpload wires the CLI handler with a sqlmock-backed real service and
// drives Upload for the supplied SBOM body. The tenant ID is injected directly
// into the echo context (the MultiAuth middleware does this in production).
func driveCLIUpload(t *testing.T, h *CLIHandler, tenantID uuid.UUID, sbomBody string) *httptest.ResponseRecorder {
	t.Helper()
	req := newCLIUpload(t, "test-project", sbomBody)
	rec := httptest.NewRecorder()
	e := echo.New()
	c := e.NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, tenantID)
	if err := h.Upload(c); err != nil {
		t.Fatalf("Upload returned unexpected error: %v", err)
	}
	return rec
}

// TestCLIHandler_Upload_ValidationError_400 pins the client-fixable branch:
// GetOrCreateProject resolves an existing project, then a malformed SBOM body
// makes detectFormatAndVersion (inside UploadSBOM) fail BEFORE any further
// repository call, so the service returns an ErrValidation error and the
// handler must answer 400 with the helpful parse message.
func TestCLIHandler_Upload_ValidationError_400(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	projectID := uuid.New()

	// GetOrCreateProject → GetByName finds an existing project (no create).
	mock.ExpectQuery(`SELECT id, name, description, created_at, updated_at FROM projects WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantID, "test-project").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "created_at", "updated_at"}).
			AddRow(projectID, "test-project", "", time.Now(), time.Now()))

	cliService := service.NewCLIService(
		repository.NewProjectRepository(db),
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewCLIHandler(cliService)

	// Valid JSON but not a recognisable SBOM shape → "unknown SBOM format".
	rec := driveCLIUpload(t, h, tenantID, `{"not":"an-sbom"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed SBOM must return 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "failed to detect SBOM format") {
		t.Errorf("expected helpful parse-failure message, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// TestCLIHandler_Upload_InternalError_500_NoLeak pins the internal branch: a
// well-formed CycloneDX body clears format detection, so UploadSBOM reaches
// GetTenantID; sqlmock makes that query fail with a distinctive driver string.
// The handler must answer 500 with a generic body and MUST NOT echo the raw DB
// error.
func TestCLIHandler_Upload_InternalError_500_NoLeak(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	tenantID := uuid.New()
	projectID := uuid.New()

	// GetOrCreateProject → GetByName finds an existing project (no create).
	mock.ExpectQuery(`SELECT id, name, description, created_at, updated_at FROM projects WHERE tenant_id = \$1 AND name = \$2`).
		WithArgs(tenantID, "test-project").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "created_at", "updated_at"}).
			AddRow(projectID, "test-project", "", time.Now(), time.Now()))

	const rawDBLeak = "pq: connection reset by peer SECRET-INTERNAL-DETAIL"
	// UploadSBOM → GetTenantID → SELECT tenant_id FROM projects WHERE id = $1.
	mock.ExpectQuery(`SELECT tenant_id FROM projects WHERE id = \$1`).
		WithArgs(projectID).
		WillReturnError(errors.New(rawDBLeak))

	cliService := service.NewCLIService(
		repository.NewProjectRepository(db),
		repository.NewSbomRepository(db),
		repository.NewComponentRepository(db),
	)
	h := NewCLIHandler(cliService)

	rec := driveCLIUpload(t, h, tenantID, `{"bomFormat":"CycloneDX","specVersion":"1.5"}`)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("internal DB error must return 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if contains(rec.Body.String(), "SECRET-INTERNAL-DETAIL") {
		t.Errorf("raw DB error leaked to client: %s", rec.Body.String())
	}
	if !contains(rec.Body.String(), "failed to import SBOM") {
		t.Errorf("expected generic body, got %s", rec.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
