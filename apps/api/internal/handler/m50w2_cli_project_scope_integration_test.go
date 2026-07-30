//go:build integration

// Package handler — M50 W2: a project-scoped API key must not act outside its
// project, INCLUDING on the two routes that name the project in the request
// BODY rather than the path.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50 W2' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// Why this file exists. `api_keys.project_id` was written by
// POST /api/v1/projects/:id/apikeys and read by nothing: every authentication
// path derived the request's authority from `key.TenantID` alone. A key the UI
// labelled "project-scoped" therefore carried the whole tenant. The path-param
// half of the fix is a middleware comparison (pinned in
// middleware/project_scope_test.go); this file covers the half a middleware
// keyed on `:id` cannot see —
//
//	POST /api/v1/cli/upload    resolves the project from form field project_name
//	POST /api/v1/cli/projects  resolves the project from JSON body field name
//
// both through CLIService.GetOrCreateProject, which CREATES the project when
// the name is unknown. So the pre-fix escape was not merely "read a sibling
// project": a project-scoped key could mint a brand-new project of its own and
// upload into it, leaving its nominal scope entirely.
//
// Each test asserts the POST-fix contract, so running the file against the
// parent commit is what makes it red. The observed pre-fix behaviour is
// recorded in the comment above each assertion.
package handler

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type m50w2Seed struct {
	tenantID   uuid.UUID
	project1ID uuid.UUID
	project1   string
	project2ID uuid.UUID
	project2   string
}

// m50w2SeedTenant builds one tenant with two projects. The API key under test is
// bound to project 1; project 2 is the sibling that the same tenant owns and
// that RLS therefore cannot separate from project 1.
func m50w2SeedTenant(t *testing.T, migDB *sql.DB, label string) m50w2Seed {
	t.Helper()

	s := m50w2Seed{tenantID: uuid.New()}
	org := "m50w2-" + label + "-" + s.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		s.tenantID, org, "m50w2 "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := s.tenantID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	s.project1ID, s.project1 = uuid.New(), "m50w2-"+label+"-p1"
	s.project2ID, s.project2 = uuid.New(), "m50w2-"+label+"-p2"
	for _, p := range []struct {
		id   uuid.UUID
		name string
	}{{s.project1ID, s.project1}, {s.project2ID, s.project2}} {
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, s.tenantID.String()); err != nil {
			_ = tx.Rollback()
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
			p.id, s.tenantID, p.name); err != nil {
			_ = tx.Rollback()
			t.Fatalf("seed project %s: %v", p.name, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	return s
}

// m50w2ProjectKey is the API key the middleware would have put on the context:
// tenant-authenticated, nominally limited to one project.
func m50w2ProjectKey(tenantID, projectID uuid.UUID) *model.APIKey {
	return &model.APIKey{
		ID:          uuid.New(),
		TenantID:    tenantID,
		ProjectID:   &projectID,
		Name:        "m50w2-project-scoped",
		Permissions: "write",
	}
}

// m50w2TenantKey is the unchanged case: `project_id IS NULL` means the whole
// tenant. That was true of every api_keys row in the development database when
// this wave was written (96 of 96, measured 2026-07-30); the dated count lives in
// docs/UPGRADE.md §2d and nothing here depends on it.
func m50w2TenantKey(tenantID uuid.UUID) *model.APIKey {
	return &model.APIKey{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        "m50w2-tenant-level",
		Permissions: "write",
	}
}

type m50w2Req struct {
	method      string
	target      string
	body        string
	contentType string
	tenantID    uuid.UUID
	key         *model.APIKey
}

// m50w2Call drives one handler through a real echo context inside an app-role
// tenant tx — RLS active, exactly like a live request behind TenantTx. The tx
// is COMMITTED regardless of outcome so "no project was created" assertions
// prove the handler refused rather than that a rollback tidied up after it.
func m50w2Call(t *testing.T, appDB *sql.DB, r m50w2Req, h func(echo.Context) error) (int, string) {
	t.Helper()

	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, r.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL app.current_tenant_id: %v", err)
	}

	e := echo.New()
	var req *http.Request
	if r.body != "" {
		req = httptest.NewRequest(r.method, r.target, strings.NewReader(r.body))
		ct := r.contentType
		if ct == "" {
			ct = echo.MIMEApplicationJSON
		}
		req.Header.Set(echo.HeaderContentType, ct)
	} else {
		req = httptest.NewRequest(r.method, r.target, nil)
	}
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set(middleware.ContextKeyTenantID, r.tenantID)
	if r.key != nil {
		c.Set(middleware.ContextKeyAPI, r.key)
	}

	herr := h(c)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
	committed = true

	if herr != nil {
		var he *echo.HTTPError
		if ok := asEchoHTTPError(herr, &he); ok {
			return he.Code, fmt.Sprintf("%v", he.Message)
		}
		t.Fatalf("handler returned non-HTTP error: %v", herr)
	}
	return rec.Code, rec.Body.String()
}

func m50w2CLIHandler(appDB *sql.DB) *CLIHandler {
	return NewCLIHandler(service.NewCLIService(
		repository.NewProjectRepository(appDB),
		repository.NewSbomRepository(appDB),
		repository.NewComponentRepository(appDB),
	).WithOffline(true))
}

// m50w2CountProjects counts a tenant's projects. `projects` is FORCE RLS, so the
// read has to run inside a tx with app.current_tenant_id bound — an unbound
// read fails with `invalid input syntax for type uuid: ""` rather than
// returning 0, which would silently pass a "nothing was created" assertion.
// m47CountAsTenant (same package) does exactly that.
func m50w2CountProjects(t *testing.T, migDB *sql.DB, tenantID uuid.UUID) int {
	t.Helper()
	return m47CountAsTenant(t, migDB, tenantID,
		`SELECT COUNT(*) FROM projects WHERE tenant_id = $1`, tenantID)
}

// m50w2MultipartSBOM builds the multipart body POST /cli/upload expects.
func m50w2MultipartSBOM(t *testing.T, projectName string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("project_name", projectName); err != nil {
		t.Fatalf("write project_name: %v", err)
	}
	part, err := w.CreateFormFile("sbom", "sbom.json")
	if err != nil {
		t.Fatalf("create sbom part: %v", err)
	}
	if _, err := part.Write([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)); err != nil {
		t.Fatalf("write sbom part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return buf.String(), w.FormDataContentType()
}

// ---------------------------------------------------------------------------
// 1. POST /api/v1/cli/projects — the escape hatch
// ---------------------------------------------------------------------------

// TestM50W2CLICreateProject_ScopedKeyCannotMintANewProject is the core
// reproduction. CLIHandler.CreateProject passes the caller-supplied `name`
// straight to CLIService.GetOrCreateProject, which INSERTs when the name is
// unknown. A project-scoped key could therefore create a project that its
// own scope does not name and then own it outright — the scope was not a
// weaker authority than a tenant key, it was the same authority.
//
// Observed pre-fix (2026-07-30, dev DB, this exact fixture): status 201, body
// `"created":true`, and `SELECT COUNT(*) FROM projects WHERE tenant_id = ...`
// went from 2 to 3.
func TestM50W2CLICreateProject_ScopedKeyCannotMintANewProject(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "mint")
	h := m50w2CLIHandler(appDB)
	before := m50w2CountProjects(t, migDB, seed.tenantID)

	code, body := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     `{"name":"m50w2-escape-hatch"}`,
		tenantID: seed.tenantID,
		key:      m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.CreateProject)

	if code != http.StatusForbidden {
		t.Errorf("project-scoped key created a project outside its scope: status %d body %s, want 403",
			code, body)
	}
	if after := m50w2CountProjects(t, migDB, seed.tenantID); after != before {
		t.Errorf("projects for the tenant went %d -> %d; a project-scoped key must never create one",
			before, after)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM projects WHERE tenant_id = $1 AND name = $2`,
		seed.tenantID, "m50w2-escape-hatch"); n != 0 {
		t.Errorf("the escape project exists (%d rows) — the key left its own scope", n)
	}
}

// TestM50W2CLICreateProject_ScopedKeyCannotTouchTheSiblingProject: the sibling
// name resolves to an EXISTING project of the same tenant, so
// GetOrCreateProject returned it with created=false and 200. Same tenant means
// RLS cannot see the difference; the key's project_id is the only thing that
// can.
func TestM50W2CLICreateProject_ScopedKeyCannotTouchTheSiblingProject(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "sibling")
	h := m50w2CLIHandler(appDB)

	code, body := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     fmt.Sprintf(`{"name":%q}`, seed.project2),
		tenantID: seed.tenantID,
		key:      m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.CreateProject)

	if code != http.StatusForbidden {
		t.Errorf("project-scoped key addressed a SIBLING project by name: status %d body %s, want 403",
			code, body)
	}
	if strings.Contains(body, seed.project2ID.String()) {
		t.Errorf("the refusal echoed the sibling project's UUID: %s", body)
	}
}

// TestM50W2CLICreateProject_UnknownAndSiblingNamesAreIndistinguishable pins the
// no-oracle property of the body-resolved path. An unknown name and a real
// sibling project's name must produce byte-identical responses, otherwise a
// key holder can enumerate the tenant's project NAMES by probing.
func TestM50W2CLICreateProject_UnknownAndSiblingNamesAreIndistinguishable(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "oracle")
	h := m50w2CLIHandler(appDB)
	key := m50w2ProjectKey(seed.tenantID, seed.project1ID)

	codeSibling, bodySibling := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     fmt.Sprintf(`{"name":%q}`, seed.project2),
		tenantID: seed.tenantID,
		key:      key,
	}, h.CreateProject)
	codeUnknown, bodyUnknown := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     `{"name":"m50w2-name-that-does-not-exist"}`,
		tenantID: seed.tenantID,
		key:      key,
	}, h.CreateProject)

	if codeSibling != codeUnknown || bodySibling != bodyUnknown {
		t.Errorf("a real sibling name answers %d %s but an unknown name answers %d %s — "+
			"the difference is a project-NAME oracle for the holder of a project-scoped key",
			codeSibling, bodySibling, codeUnknown, bodyUnknown)
	}
}

// TestM50W2CLICreateProject_ScopedKeyOwnProjectStillWorks: the guard is a scope
// check, not a blanket refusal. The key's OWN project name must still resolve,
// idempotently, exactly as before.
func TestM50W2CLICreateProject_ScopedKeyOwnProjectStillWorks(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "own")
	h := m50w2CLIHandler(appDB)

	code, body := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     fmt.Sprintf(`{"name":%q}`, seed.project1),
		tenantID: seed.tenantID,
		key:      m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.CreateProject)

	if code != http.StatusOK {
		t.Fatalf("project-scoped key naming its OWN project: status %d body %s, want 200", code, body)
	}
	if !strings.Contains(body, seed.project1ID.String()) {
		t.Errorf("response does not name the key's own project: %s", body)
	}
	if !strings.Contains(body, `"created":false`) {
		t.Errorf("the own-project path must be the idempotent get-existing form: %s", body)
	}
}

// TestM50W2CLICreateProject_TenantKeyIsUnchanged is the regression fence around
// the 96 existing keys: `project_id IS NULL` still means the whole tenant,
// including the create-on-unknown-name behaviour that `sbomhub scan` relies on.
func TestM50W2CLICreateProject_TenantKeyIsUnchanged(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "tenantkey")
	h := m50w2CLIHandler(appDB)

	code, body := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     `{"name":"m50w2-tenant-key-new-project"}`,
		tenantID: seed.tenantID,
		key:      m50w2TenantKey(seed.tenantID),
	}, h.CreateProject)

	if code != http.StatusCreated {
		t.Fatalf("tenant-level key creating a new project: status %d body %s, want 201", code, body)
	}
	if !strings.Contains(body, `"created":true`) {
		t.Errorf("tenant-level key must still create: %s", body)
	}
}

// TestM50W2CLICreateProject_NoAPIKeyContextIsUnchanged covers the Clerk /
// self-hosted callers of the same handler: with no API key on the context the
// scope check has nothing to enforce and must not interfere.
func TestM50W2CLICreateProject_NoAPIKeyContextIsUnchanged(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "nokey")
	h := m50w2CLIHandler(appDB)

	code, body := m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodPost,
		target:   "/api/v1/cli/projects",
		body:     `{"name":"m50w2-no-key-new-project"}`,
		tenantID: seed.tenantID,
	}, h.CreateProject)

	if code != http.StatusCreated {
		t.Fatalf("no API key on the context: status %d body %s, want 201", code, body)
	}
}

// ---------------------------------------------------------------------------
// 2. POST /api/v1/cli/upload — the same escape, with an SBOM attached
// ---------------------------------------------------------------------------

// TestM50W2CLIUpload_ScopedKeyCannotUploadIntoANewProject: /cli/upload resolves
// `project_name` through the same GetOrCreateProject, so the escape carries
// data with it — the key mints a project AND writes an SBOM into it.
//
// Observed pre-fix (2026-07-30, dev DB, this exact fixture): status 200,
// `"project_created":true`, one new `projects` row and one new `sboms` row.
func TestM50W2CLIUpload_ScopedKeyCannotUploadIntoANewProject(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "upload-mint")
	h := m50w2CLIHandler(appDB)
	before := m50w2CountProjects(t, migDB, seed.tenantID)

	body, ct := m50w2MultipartSBOM(t, "m50w2-upload-escape")
	code, resp := m50w2Call(t, appDB, m50w2Req{
		method:      http.MethodPost,
		target:      "/api/v1/cli/upload",
		body:        body,
		contentType: ct,
		tenantID:    seed.tenantID,
		key:         m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.Upload)

	if code != http.StatusForbidden {
		t.Errorf("project-scoped key uploaded into a project outside its scope: status %d body %s, want 403",
			code, resp)
	}
	if after := m50w2CountProjects(t, migDB, seed.tenantID); after != before {
		t.Errorf("projects for the tenant went %d -> %d during a refused upload", before, after)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM sboms WHERE tenant_id = $1`, seed.tenantID); n != 0 {
		t.Errorf("sboms written by a refused upload = %d, want 0", n)
	}
}

// TestM50W2CLIUpload_ScopedKeyCannotUploadIntoTheSiblingProject is the
// data-poisoning variant that needs no new project at all: point the key at
// the sibling project's name and its SBOM — and therefore its component
// inventory, its vulnerability posture and its compliance evidence — is
// replaced by whatever the key holder uploads.
func TestM50W2CLIUpload_ScopedKeyCannotUploadIntoTheSiblingProject(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "upload-sibling")
	h := m50w2CLIHandler(appDB)

	body, ct := m50w2MultipartSBOM(t, seed.project2)
	code, resp := m50w2Call(t, appDB, m50w2Req{
		method:      http.MethodPost,
		target:      "/api/v1/cli/upload",
		body:        body,
		contentType: ct,
		tenantID:    seed.tenantID,
		key:         m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.Upload)

	if code != http.StatusForbidden {
		t.Errorf("project-scoped key uploaded into a SIBLING project: status %d body %s, want 403", code, resp)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM sboms WHERE project_id = $1`, seed.project2ID); n != 0 {
		t.Errorf("sboms written into the sibling project = %d, want 0", n)
	}
}

// TestM50W2CLIUpload_ScopedKeyOwnProjectStillWorks: the legitimate per-repo CI
// flow, which is the entire reason project-scoped keys exist.
func TestM50W2CLIUpload_ScopedKeyOwnProjectStillWorks(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "upload-own")
	h := m50w2CLIHandler(appDB)

	body, ct := m50w2MultipartSBOM(t, seed.project1)
	code, resp := m50w2Call(t, appDB, m50w2Req{
		method:      http.MethodPost,
		target:      "/api/v1/cli/upload",
		body:        body,
		contentType: ct,
		tenantID:    seed.tenantID,
		key:         m50w2ProjectKey(seed.tenantID, seed.project1ID),
	}, h.Upload)

	if code != http.StatusOK {
		t.Fatalf("project-scoped key uploading into its OWN project: status %d body %s, want 200", code, resp)
	}
	if !strings.Contains(resp, seed.project1ID.String()) {
		t.Errorf("upload response does not name the key's own project: %s", resp)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM sboms WHERE project_id = $1`, seed.project1ID); n != 1 {
		t.Errorf("sboms in the key's own project = %d, want 1", n)
	}
}

// ---------------------------------------------------------------------------
// 3. What a HANDLER-LEVEL denial costs and leaves behind (Codex R1 Low #2)
// ---------------------------------------------------------------------------

// TestM50W2CLIUpload_HandlerLevelDenialLeavesNoAuditRow pins the one claim in
// apiKeyProjectScopeAllowed's doc comment that is about a code path OUTSIDE that
// function.
//
// A middleware-level scope refusal produces no audit row because the audit
// middleware is never entered. The two body-resolved CLI routes are different:
// the middleware ADMITS them and the handler refuses, by which point TenantTx is
// open and MCPAudit is in the chain. MCPAudit calls next(c) first and then writes
// an `apikey.used` row carrying the observed status, so a row IS attempted for
// the 403 — and TenantTx rolls it back because the status is >= 400. The comment
// asserts the end state ("no audit row survives a denial on either path"); this
// test is what makes that an observation rather than a reading of two files.
//
// The chain assembled here is the cliWrite chain minus RateLimitByAPIKey, which
// needs Redis and cannot affect whether an audit row is committed.
//
// The successful upload in the same test is the anti-vacuity control: if MCPAudit
// were misconfigured and wrote nothing at all, the "0 rows after a denial"
// assertion would pass for the wrong reason.
func TestM50W2CLIUpload_HandlerLevelDenialLeavesNoAuditRow(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "audit")
	h := m50w2CLIHandler(appDB)
	auditRepo := repository.NewAuditRepository(appDB)

	// TenantTx opens the request transaction from ContextKeyTenantID; MCPAudit
	// runs inside it, exactly as `cliWrite` composes them in cmd/server/main.go.
	chain := func(c echo.Context) error {
		return middleware.TenantTx(appDB)(middleware.MCPAudit(auditRepo)(h.Upload))(c)
	}

	countAudit := func() int {
		return m47CountAsTenant(t, migDB, seed.tenantID,
			`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
			seed.tenantID, model.ActionAPIKeyUsed)
	}

	run := func(projectName string) (int, string) {
		body, ct := m50w2MultipartSBOM(t, projectName)
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/upload", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, ct)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetPath("/api/v1/cli/upload")
		c.Set(middleware.ContextKeyTenantID, seed.tenantID)
		c.Set(middleware.ContextKeyAPI, m50w2ProjectKey(seed.tenantID, seed.project1ID))
		if err := chain(c); err != nil {
			t.Fatalf("chain returned a non-HTTP error: %v", err)
		}
		return rec.Code, rec.Body.String()
	}

	// Anti-vacuity control first: a SUCCESSFUL upload must leave a row, so the
	// zero below cannot be MCPAudit simply not working.
	before := countAudit()
	if code, body := run(seed.project1); code != http.StatusOK {
		t.Fatalf("upload into the key's own project: status %d body %s, want 200", code, body)
	}
	afterSuccess := countAudit()
	if afterSuccess != before+1 {
		t.Fatalf("apikey.used audit rows after a SUCCESSFUL upload = %d, want %d "+
			"(MCPAudit must be writing, otherwise the denial assertion below is vacuous)",
			afterSuccess, before+1)
	}

	// Now the denial: sibling project by name.
	code, body := run(seed.project2)
	if code != http.StatusForbidden {
		t.Fatalf("upload naming the sibling project: status %d body %s, want 403", code, body)
	}
	if got := countAudit(); got != afterSuccess {
		t.Errorf("apikey.used audit rows went %d -> %d across a REFUSED upload; the doc "+
			"comment in middleware/project_scope.go claims no audit row survives a "+
			"handler-level scope denial (TenantTx rolls back on status >= 400)",
			afterSuccess, got)
	}
}
