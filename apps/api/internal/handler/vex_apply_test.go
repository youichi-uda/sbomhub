package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// fakeVEXApplier substitutes *service.VEXService.ApplySuggestion so the
// Apply handler's HTTP-status mapping + audit-or-nothing emit are testable
// without a live DB (M27-A / F381, issue #132).
type fakeVEXApplier struct {
	result    *service.VEXApplyResult
	err       error
	gotInput  service.ApplySuggestionInput
	callCount int
}

func (f *fakeVEXApplier) ApplySuggestion(_ context.Context, in service.ApplySuggestionInput) (*service.VEXApplyResult, error) {
	f.callCount++
	f.gotInput = in
	return f.result, f.err
}

type fakeVEXAudit struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	err     error
}

func (f *fakeVEXAudit) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *input)
	return f.err
}

// doApply drives VEXHandler.Apply with a JSON body and a bound tenant / user
// context, mirroring the TenantTx-wrapped `auth` group the route lives under.
func doApply(h *VEXHandler, tenantID, userID, projectID uuid.UUID, body string) (echo.Context, *httptest.ResponseRecorder, error) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/vex/suggestions/apply",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, userID)
	c.Set(middleware.ContextKeyRole, model.RoleMember)
	err := h.Apply(c)
	return c, rec, err
}

func applyBody(sourceStmt, vuln, comp uuid.UUID) string {
	b, _ := json.Marshal(map[string]string{
		"source_statement_id": sourceStmt.String(),
		"vulnerability_id":    vuln.String(),
		"component_id":        comp.String(),
	})
	return string(b)
}

// TestVEXHandler_Apply_HappyPath_EmitsReuseAudit pins the audit lockstep
// emit surface: a successful apply returns 201 with the statement +
// provenance body AND emits exactly one vex_statement_reused_cross_project
// audit row carrying the source attribution + match_type in Details, keyed
// on the NEW target statement id (resource_type=vex).
func TestVEXHandler_Apply_HappyPath_EmitsReuseAudit(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	projectID := uuid.New()
	sourceStmt := uuid.New()
	vuln := uuid.New()
	targetComp := uuid.New()
	sourceProject := uuid.New()
	newStmtID := uuid.New()

	applier := &fakeVEXApplier{
		result: &service.VEXApplyResult{
			Statement: &model.VEXStatement{
				ID:              newStmtID,
				TenantID:        tenantID,
				ProjectID:       projectID,
				VulnerabilityID: vuln,
				ComponentID:     &targetComp,
				Status:          model.VEXStatusNotAffected,
			},
			SourceProjectID: sourceProject,
			MatchType:       model.VEXMatchTypePurl,
		},
	}
	audit := &fakeVEXAudit{}
	h := &VEXHandler{applier: applier, audit: audit}

	c, rec, err := doApply(h, tenantID, userID, projectID, applyBody(sourceStmt, vuln, targetComp))
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	// The service received the parsed + context-resolved input.
	if applier.callCount != 1 {
		t.Fatalf("ApplySuggestion call count = %d, want 1", applier.callCount)
	}
	gi := applier.gotInput
	if gi.TenantID != tenantID || gi.ProjectID != projectID || gi.SourceStatementID != sourceStmt ||
		gi.VulnerabilityID != vuln || gi.TargetComponentID != targetComp {
		t.Errorf("ApplySuggestion input mismatch: %+v", gi)
	}
	if gi.AppliedBy == nil || *gi.AppliedBy != userID {
		t.Errorf("AppliedBy = %v, want %s", gi.AppliedBy, userID)
	}

	// Exactly one audit row, correct action / resource / resource_id.
	if got := len(audit.entries); got != 1 {
		t.Fatalf("expected 1 audit entry, got %d", got)
	}
	entry := audit.entries[0]
	if entry.Action != model.AuditActionVEXReusedCrossProject {
		t.Errorf("audit action = %q, want %q", entry.Action, model.AuditActionVEXReusedCrossProject)
	}
	if entry.ResourceType != model.ResourceVEX {
		t.Errorf("audit resource_type = %q, want %q", entry.ResourceType, model.ResourceVEX)
	}
	if entry.ResourceID == nil || *entry.ResourceID != newStmtID {
		t.Errorf("audit resource_id = %v, want new statement id %s", entry.ResourceID, newStmtID)
	}
	if entry.TenantID == nil || *entry.TenantID != tenantID {
		t.Errorf("audit tenant_id = %v, want %s", entry.TenantID, tenantID)
	}
	if entry.Details["source_statement_id"] != sourceStmt.String() {
		t.Errorf("audit details.source_statement_id = %v, want %s", entry.Details["source_statement_id"], sourceStmt)
	}
	if entry.Details["source_project_id"] != sourceProject.String() {
		t.Errorf("audit details.source_project_id = %v, want %s", entry.Details["source_project_id"], sourceProject)
	}
	if entry.Details["match_type"] != model.VEXMatchTypePurl {
		t.Errorf("audit details.match_type = %v, want %s", entry.Details["match_type"], model.VEXMatchTypePurl)
	}

	// F208 parity: the audit-resource-id override points at the new statement.
	if v := c.Get(middleware.ContextKeyAuditResourceID); v != newStmtID {
		t.Errorf("SetAuditResourceID = %v, want new statement id %s", v, newStmtID)
	}

	// Response body shape.
	var resp ApplyVEXResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Statement == nil || resp.Statement.ID != newStmtID {
		t.Errorf("response.statement.id mismatch: %+v", resp.Statement)
	}
	if resp.Provenance.SourceStatementID != sourceStmt || resp.Provenance.SourceProjectID != sourceProject {
		t.Errorf("response.provenance mismatch: %+v", resp.Provenance)
	}
	if resp.Provenance.AppliedAt == "" {
		t.Errorf("response.provenance.applied_at is empty")
	}
}

// TestVEXHandler_Apply_AlreadyTriaged_409 pins the idempotency contract:
// ErrVEXApplyAlreadyTriaged maps to 409 and emits NO audit row.
func TestVEXHandler_Apply_AlreadyTriaged_409(t *testing.T) {
	applier := &fakeVEXApplier{err: service.ErrVEXApplyAlreadyTriaged}
	audit := &fakeVEXAudit{}
	h := &VEXHandler{applier: applier, audit: audit}

	_, rec, err := doApply(h, uuid.New(), uuid.New(), uuid.New(), applyBody(uuid.New(), uuid.New(), uuid.New()))
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if len(audit.entries) != 0 {
		t.Errorf("409 must not emit audit row, got %d", len(audit.entries))
	}
}

// TestVEXHandler_Apply_MatchFailed_400 pins the injection-guard mapping:
// ErrVEXApplyMatchFailed maps to 400 and emits no audit row.
func TestVEXHandler_Apply_MatchFailed_400(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"match_failed", service.ErrVEXApplyMatchFailed},
		{"source_not_found", service.ErrVEXApplySourceNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			applier := &fakeVEXApplier{err: tc.err}
			audit := &fakeVEXAudit{}
			h := &VEXHandler{applier: applier, audit: audit}

			_, rec, err := doApply(h, uuid.New(), uuid.New(), uuid.New(), applyBody(uuid.New(), uuid.New(), uuid.New()))
			if err != nil {
				t.Fatalf("Apply returned error: %v", err)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if len(audit.entries) != 0 {
				t.Errorf("400 must not emit audit row, got %d", len(audit.entries))
			}
		})
	}
}

// TestVEXHandler_Apply_AuditFailure_500 pins audit-or-nothing: when the
// domain audit write fails, the handler returns 500 so the ambient TenantTx
// rolls the statement + provenance INSERTs back (F32 / M1 F5 precedent).
func TestVEXHandler_Apply_AuditFailure_500(t *testing.T) {
	applier := &fakeVEXApplier{
		result: &service.VEXApplyResult{
			Statement: &model.VEXStatement{ID: uuid.New()},
			MatchType: model.VEXMatchTypeVulnerabilityOnly,
		},
	}
	audit := &fakeVEXAudit{err: context.DeadlineExceeded}
	h := &VEXHandler{applier: applier, audit: audit}

	_, rec, err := doApply(h, uuid.New(), uuid.New(), uuid.New(), applyBody(uuid.New(), uuid.New(), uuid.New()))
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if applier.callCount != 1 {
		t.Errorf("service must have been called before the audit failure, got %d", applier.callCount)
	}
}

// TestVEXHandler_Apply_InvalidBody_400 pins that a malformed id in the body
// is rejected at the handler boundary before the service is touched.
func TestVEXHandler_Apply_InvalidBody_400(t *testing.T) {
	applier := &fakeVEXApplier{}
	h := &VEXHandler{applier: applier, audit: &fakeVEXAudit{}}

	_, rec, err := doApply(h, uuid.New(), uuid.New(), uuid.New(),
		`{"source_statement_id":"not-a-uuid","vulnerability_id":"`+uuid.NewString()+`","component_id":"`+uuid.NewString()+`"}`)
	if err != nil {
		t.Fatalf("Apply returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if applier.callCount != 0 {
		t.Errorf("service must not be called on invalid body, got %d", applier.callCount)
	}
}
