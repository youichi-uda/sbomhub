package handler

import (
	"context"
	"database/sql"
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
	"github.com/sbomhub/sbomhub/internal/repository"
)

// fakeReachabilityUpserter records every Upsert so a test can assert the
// server-filled tenant_id / project_id injection and the per-row payload
// without a live PostgreSQL connection.
type fakeReachabilityUpserter struct {
	mu   sync.Mutex
	rows []repository.ReachabilityResult
	err  error
}

func (f *fakeReachabilityUpserter) Upsert(_ context.Context, rr *repository.ReachabilityResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.rows = append(f.rows, *rr)
	return nil
}

func (f *fakeReachabilityUpserter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

// fakeReachabilityAudit records every audit emit so a test can assert the
// audit-or-nothing surface (exactly one reachability_uploaded row).
type fakeReachabilityAudit struct {
	mu      sync.Mutex
	entries []model.CreateAuditLogInput
	err     error
}

func (f *fakeReachabilityAudit) Log(_ context.Context, input *model.CreateAuditLogInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, *input)
	return f.err
}

// fakeReachabilityProjectReader stands in for the tenant-scoped project
// existence check. err=sql.ErrNoRows models "project not found / foreign
// tenant" (the 404 path); nil models "project exists in tenant".
type fakeReachabilityProjectReader struct {
	err      error
	gotCalls int
}

func (f *fakeReachabilityProjectReader) GetByTenant(_ context.Context, _, projectID uuid.UUID) (*model.Project, error) {
	f.gotCalls++
	if f.err != nil {
		return nil, f.err
	}
	return &model.Project{ID: projectID}, nil
}

// doReachabilityUpload drives ReachabilityHandler.Upload with a JSON body
// and a bound tenant / user context, mirroring the TenantTx-wrapped route
// the endpoint lives under in main.go.
func doReachabilityUpload(h *ReachabilityHandler, tenantID, userID, projectID uuid.UUID, body string) (echo.Context, *httptest.ResponseRecorder, error) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/projects/"+projectID.String()+"/reachability",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(projectID.String())
	c.Set(middleware.ContextKeyTenantID, tenantID)
	c.Set(middleware.ContextKeyUserID, userID)
	c.Set(middleware.ContextKeyRole, model.RoleMember)
	err := h.Upload(c)
	return c, rec, err
}

func newTestReachabilityHandler(up *fakeReachabilityUpserter, audit *fakeReachabilityAudit, proj *fakeReachabilityProjectReader) *ReachabilityHandler {
	return &ReachabilityHandler{upserter: up, audit: audit, projects: proj}
}

// TestReachabilityHandler_Upload_HappyPath pins the write + audit lockstep:
// a valid two-row batch returns 201 with upserted=2, the fake upserter
// received both rows with the server-filled tenant_id / project_id and the
// client-supplied payload, and exactly one reachability_uploaded audit row
// is emitted keyed on the project id (resource_type=reachability).
func TestReachabilityHandler_Upload_HappyPath(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	projectID := uuid.New()
	comp1 := uuid.New()
	comp2 := uuid.New()

	conf := 0.87
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id":     comp1.String(),
				"cve_id":           "CVE-2024-0001",
				"ecosystem":        "go",
				"status":           "reachable",
				"confidence":       conf,
				"analyzer_version": "v1.2.3",
				"analyzed_at":      "2026-07-05T10:00:00Z",
				"evidence":         map[string]interface{}{"callgraph_nodes": []string{"main.main"}},
			},
			{
				"component_id": comp2.String(),
				"cve_id":       "CVE-2024-0002",
				"ecosystem":    "go",
				"status":       "not_present",
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	proj := &fakeReachabilityProjectReader{}
	h := newTestReachabilityHandler(up, audit, proj)

	_, rec, err := doReachabilityUpload(h, tenantID, userID, projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}

	var resp reachabilityUploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Upserted != 2 {
		t.Fatalf("upserted = %d, want 2", resp.Upserted)
	}

	if up.count() != 2 {
		t.Fatalf("upserter received %d rows, want 2", up.count())
	}
	// Server MUST fill tenant_id (session) + project_id (path) on every row.
	for i, rr := range up.rows {
		if rr.TenantID != tenantID {
			t.Errorf("row %d TenantID = %s, want %s (server-filled from session)", i, rr.TenantID, tenantID)
		}
		if rr.ProjectID != projectID {
			t.Errorf("row %d ProjectID = %s, want %s (server-filled from path)", i, rr.ProjectID, projectID)
		}
	}
	// First row's client-supplied payload flows through unchanged.
	r0 := up.rows[0]
	if r0.ComponentID != comp1 {
		t.Errorf("row 0 ComponentID = %s, want %s", r0.ComponentID, comp1)
	}
	if r0.CVEID != "CVE-2024-0001" {
		t.Errorf("row 0 CVEID = %q, want CVE-2024-0001", r0.CVEID)
	}
	if r0.Status != "reachable" {
		t.Errorf("row 0 Status = %q, want reachable", r0.Status)
	}
	if r0.Confidence == nil || *r0.Confidence != conf {
		t.Errorf("row 0 Confidence = %v, want %v", r0.Confidence, conf)
	}
	if r0.AnalyzerVersion != "v1.2.3" {
		t.Errorf("row 0 AnalyzerVersion = %q, want v1.2.3", r0.AnalyzerVersion)
	}
	if r0.AnalyzedAt == nil {
		t.Errorf("row 0 AnalyzedAt = nil, want RFC3339 timestamp")
	}
	// Second row omits the optional fields → nil confidence, empty version.
	if up.rows[1].Confidence != nil {
		t.Errorf("row 1 Confidence = %v, want nil (omitted)", up.rows[1].Confidence)
	}

	// Exactly one reachability_uploaded audit row, keyed on the project id.
	if len(audit.entries) != 1 {
		t.Fatalf("audit emitted %d rows, want exactly 1", len(audit.entries))
	}
	a := audit.entries[0]
	if a.Action != model.AuditActionReachabilityUploaded {
		t.Errorf("audit action = %q, want %q", a.Action, model.AuditActionReachabilityUploaded)
	}
	if a.ResourceType != model.ResourceReachability {
		t.Errorf("audit resource_type = %q, want %q", a.ResourceType, model.ResourceReachability)
	}
	if a.ResourceID == nil || *a.ResourceID != projectID {
		t.Errorf("audit resource_id = %v, want project id %s", a.ResourceID, projectID)
	}
	if a.TenantID == nil || *a.TenantID != tenantID {
		t.Errorf("audit tenant_id = %v, want %s", a.TenantID, tenantID)
	}
	if a.UserID == nil || *a.UserID != userID {
		t.Errorf("audit user_id = %v, want %s", a.UserID, userID)
	}

	if proj.gotCalls != 1 {
		t.Errorf("project existence check called %d times, want 1", proj.gotCalls)
	}
}

// TestReachabilityHandler_Upload_StatusEnumViolation: a status outside the
// four-state enum is a 400 with nothing written and no audit row.
func TestReachabilityHandler_Upload_StatusEnumViolation(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id": uuid.New().String(),
				"cve_id":       "CVE-2024-9999",
				"status":       "definitely_reachable", // not in enum
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	h := newTestReachabilityHandler(up, audit, &fakeReachabilityProjectReader{})

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 {
		t.Errorf("upserter received %d rows, want 0 on enum violation", up.count())
	}
	if len(audit.entries) != 0 {
		t.Errorf("audit emitted %d rows, want 0 on enum violation", len(audit.entries))
	}
}

// TestReachabilityHandler_Upload_MissingComponentID: an empty component_id
// is a 400 with nothing written.
func TestReachabilityHandler_Upload_MissingComponentID(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id": "",
				"cve_id":       "CVE-2024-0003",
				"status":       "reachable",
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	h := newTestReachabilityHandler(up, audit, &fakeReachabilityProjectReader{})

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 {
		t.Errorf("upserter received %d rows, want 0 on missing component_id", up.count())
	}
	if len(audit.entries) != 0 {
		t.Errorf("audit emitted %d rows, want 0 on missing component_id", len(audit.entries))
	}
}

// TestReachabilityHandler_Upload_MissingCVEID: an empty cve_id is a 400
// with nothing written.
func TestReachabilityHandler_Upload_MissingCVEID(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id": uuid.New().String(),
				"cve_id":       "   ", // whitespace-only → empty after trim
				"status":       "reachable",
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	h := newTestReachabilityHandler(up, audit, &fakeReachabilityProjectReader{})

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 {
		t.Errorf("upserter received %d rows, want 0 on missing cve_id", up.count())
	}
}

// TestReachabilityHandler_Upload_ConfidenceOutOfRange: a confidence outside
// [0,1] is a 400 with nothing written (validated before the DB round trip).
func TestReachabilityHandler_Upload_ConfidenceOutOfRange(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id": uuid.New().String(),
				"cve_id":       "CVE-2024-0004",
				"status":       "reachable",
				"confidence":   1.5,
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	h := newTestReachabilityHandler(up, &fakeReachabilityAudit{}, &fakeReachabilityProjectReader{})

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 {
		t.Errorf("upserter received %d rows, want 0 on confidence out of range", up.count())
	}
}

// TestReachabilityHandler_Upload_ProjectNotFound: a project the tenant does
// not own (soft-reference project_id, no FK) is a 404 with nothing written
// and no audit row — the F37 guard mirrored from the METI handler.
func TestReachabilityHandler_Upload_ProjectNotFound(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body, _ := json.Marshal(map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"component_id": uuid.New().String(),
				"cve_id":       "CVE-2024-0005",
				"status":       "reachable",
			},
		},
	})

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	proj := &fakeReachabilityProjectReader{err: sql.ErrNoRows}
	h := newTestReachabilityHandler(up, audit, proj)

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, string(body))
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 {
		t.Errorf("upserter received %d rows, want 0 on project not found", up.count())
	}
	if len(audit.entries) != 0 {
		t.Errorf("audit emitted %d rows, want 0 on project not found", len(audit.entries))
	}
}

// TestReachabilityHandler_Upload_EmptyResults: a batch with no results is a
// 400 — a no-op upload that would still emit a misleading audit row is
// rejected rather than silently accepted (loud-failure posture).
func TestReachabilityHandler_Upload_EmptyResults(t *testing.T) {
	tenantID := uuid.New()
	projectID := uuid.New()
	body := `{"results":[]}`

	up := &fakeReachabilityUpserter{}
	audit := &fakeReachabilityAudit{}
	h := newTestReachabilityHandler(up, audit, &fakeReachabilityProjectReader{})

	_, rec, err := doReachabilityUpload(h, tenantID, uuid.New(), projectID, body)
	if err != nil {
		t.Fatalf("Upload returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if up.count() != 0 || len(audit.entries) != 0 {
		t.Errorf("empty batch wrote rows=%d audit=%d, want 0/0", up.count(), len(audit.entries))
	}
}
