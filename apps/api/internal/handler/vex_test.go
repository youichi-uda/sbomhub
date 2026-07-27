package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// fakeVEXWriter substitutes *service.VEXService for the Create/Update
// statement endpoints so the F443 validation-vs-internal HTTP status split
// is testable without a live DB. CreateStatement/UpdateStatement in the real
// service return a MIX of self-authored validation errors (safe to echo at
// 400) and %w-wrapped DB errors (must be an opaque 500); the handler
// discriminates on errors.Is(err, service.ErrValidation).
type fakeVEXWriter struct {
	stmt      *model.VEXStatement
	createErr error
	updateErr error
}

func (f *fakeVEXWriter) CreateStatement(_ context.Context, _ service.CreateVEXStatementInput) (*model.VEXStatement, error) {
	return f.stmt, f.createErr
}

func (f *fakeVEXWriter) UpdateStatement(_ context.Context, _, _, _ uuid.UUID, _ service.UpdateVEXStatementInput) (*model.VEXStatement, error) {
	return f.stmt, f.updateErr
}

// doCreate drives VEXHandler.Create with a minimal valid JSON body (a
// parseable vulnerability_id + status) so control reaches the service call,
// where the fake writer injects the error under test.
func doCreate(h *VEXHandler, projectID, vulnID uuid.UUID, status string) (*httptest.ResponseRecorder, error) {
	e := echo.New()
	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": vulnID.String(),
		"status":           status,
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/vex",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	// M47 W1: Create now requires the session tenant (it is checked against
	// the project's owner), so without it the handler fails closed at 401
	// and these F443 status-split cases would be vacuous.
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	return rec, h.Create(c)
}

// doUpdate drives VEXHandler.Update with a parseable vex_id param + body.
func doUpdate(h *VEXHandler, vexID uuid.UUID, status string) (*httptest.ResponseRecorder, error) {
	e := echo.New()
	body, _ := json.Marshal(map[string]string{"status": status})
	projectID := uuid.New()
	req := httptest.NewRequest(http.MethodPut,
		"/api/v1/projects/"+projectID.String()+"/vex/"+vexID.String(),
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// M47 W1: Update is now scoped by (tenant, project) — both must be
	// present or the handler fails closed before the writer is consulted,
	// which would make these F443 status-split cases vacuous.
	c.SetParamNames("id", "vex_id")
	c.SetParamValues(projectID.String(), vexID.String())
	c.Set(middleware.ContextKeyTenantID, uuid.New())
	return rec, h.Update(c)
}

// A representative internal error: the service's own "failed to check
// existing statement: %w" wrapper around a raw driver string. Neither the
// wrapper nor the driver text may reach the client — that is the F443 leak.
const (
	internalWrapper = "failed to check existing statement"
	rawDriverLeak   = "pq: SSL connection has been closed unexpectedly"
)

// TestVEXHandler_Create_ValidationError_400 pins that a service validation
// error (ValidationErrorf) is echoed verbatim at 400 — the legitimate
// caller-facing feedback the F443 fix must PRESERVE.
func TestVEXHandler_Create_ValidationError_400(t *testing.T) {
	h := &VEXHandler{writer: &fakeVEXWriter{
		createErr: service.ValidationErrorf("invalid VEX status: %s", "bogus"),
	}}

	rec, err := doCreate(h, uuid.New(), uuid.New(), "bogus")
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid VEX status: bogus") {
		t.Errorf("body = %s, want it to echo the validation message", rec.Body.String())
	}
}

// TestVEXHandler_Create_InternalError_500_NoLeak pins the F443 fix: a
// %w-wrapped DB error is a 500 with a GENERIC body — neither the wrapper nor
// the raw driver string may leak. Pre-fix this returned 400 + the raw string.
func TestVEXHandler_Create_InternalError_500_NoLeak(t *testing.T) {
	h := &VEXHandler{writer: &fakeVEXWriter{
		createErr: fmt.Errorf("%s: %w", internalWrapper, errors.New(rawDriverLeak)),
	}}

	rec, err := doCreate(h, uuid.New(), uuid.New(), "affected")
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, rec.Body.String())
}

// TestVEXHandler_Update_ValidationError_400 mirrors the Create validation
// case for the Update site.
func TestVEXHandler_Update_ValidationError_400(t *testing.T) {
	h := &VEXHandler{writer: &fakeVEXWriter{
		updateErr: service.ValidationErrorf("VEX statement not found"),
	}}

	rec, err := doUpdate(h, uuid.New(), "affected")
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "VEX statement not found") {
		t.Errorf("body = %s, want it to echo the validation message", rec.Body.String())
	}
}

// TestVEXHandler_Update_InternalError_500_NoLeak mirrors the Create
// internal-leak case for the Update site.
func TestVEXHandler_Update_InternalError_500_NoLeak(t *testing.T) {
	h := &VEXHandler{writer: &fakeVEXWriter{
		updateErr: fmt.Errorf("failed to update VEX statement: %w", errors.New(rawDriverLeak)),
	}}

	rec, err := doUpdate(h, uuid.New(), "affected")
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	assertNoLeak(t, rec.Body.String())
}

// assertNoLeak asserts the 500 body carries the generic client message and
// leaks neither the service wrapper nor the raw driver string.
func assertNoLeak(t *testing.T, body string) {
	t.Helper()
	if !strings.Contains(body, "failed to save VEX statement") {
		t.Errorf("body = %s, want the generic client message", body)
	}
	if strings.Contains(body, rawDriverLeak) {
		t.Errorf("body leaked the raw driver string: %s", body)
	}
	if strings.Contains(body, internalWrapper) {
		t.Errorf("body leaked the internal wrapper: %s", body)
	}
	if strings.Contains(body, "failed to update VEX statement") {
		t.Errorf("body leaked the internal wrapper: %s", body)
	}
}
