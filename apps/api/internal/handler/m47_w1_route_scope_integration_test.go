//go:build integration

// Package handler — M47 W1: route-level (tenant, project) ownership.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47W1' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// Every test here first REPRODUCES the pre-fix behaviour as an assertion
// ("this write must not have happened"), so running the file against the
// parent commit is what makes it red. The shape is always the same:
//
//	victim  = tenant V, project VP, sbom VS, component + vuln VV
//	caller  = tenant C, project CP, sbom CS, component + vuln CV
//	sibling = a SECOND project of tenant C (CP2) — the cross-project,
//	          same-tenant case that RLS can never catch
//
// and the contract is always the same: unknown, sibling-project and
// foreign-tenant ids are ONE answer (404 / refusal), never distinguishable.
//
// C27: the tenants DELETE cascades to projects / sboms / components /
// public_links / api_keys / license_policies / vex_statements; global
// `vulnerabilities` rows have no tenant and are reaped explicitly.
package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type m47Seed struct {
	tenantID    uuid.UUID
	projectID   uuid.UUID
	project2ID  uuid.UUID // sibling project of the SAME tenant
	sbomID      uuid.UUID
	sbom2ID     uuid.UUID // sbom of the sibling project
	componentID uuid.UUID
	vulnID      uuid.UUID
	cveID       string
}

// m47SeedAll builds one tenant with two projects; project 1 has an SBOM with
// a component linked to a fresh global vulnerability, project 2 has its own
// SBOM (so cross-project sbom ids are available without a second tenant).
func m47SeedAll(t *testing.T, migDB *sql.DB, label string) m47Seed {
	t.Helper()

	s := m47Seed{tenantID: uuid.New()}
	org := "m47-" + label + "-" + s.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		s.tenantID, org, "m47 "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := s.tenantID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	exec := func(query string, args ...any) {
		t.Helper()
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	s.projectID = uuid.New()
	s.project2ID = uuid.New()
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, s.projectID, s.tenantID, "m47-"+label+"-p1")
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, s.project2ID, s.tenantID, "m47-"+label+"-p2")

	s.sbomID = uuid.New()
	s.sbom2ID = uuid.New()
	exec(`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
	      VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())`,
		s.sbomID, s.tenantID, s.projectID)
	exec(`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
	      VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX","secret":"project-2-only"}'::jsonb, NOW())`,
		s.sbom2ID, s.tenantID, s.project2ID)

	s.componentID = uuid.New()
	exec(`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
	      VALUES ($1, $2, $3, 'libm47', '1.0', 'library', 'pkg:generic/libm47@1.0', 'GPL-3.0-only', NOW())`,
		s.componentID, s.tenantID, s.sbomID)
	// A component in the SIBLING project, so a cross-project sbom_id has
	// observable content to leak.
	exec(`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, license, created_at)
	      VALUES ($1, $2, $3, 'sibling-only-component', '9.9', 'library', 'pkg:generic/sibling@9.9', 'GPL-3.0-only', NOW())`,
		uuid.New(), s.tenantID, s.sbom2ID)

	s.cveID = fmt.Sprintf("CVE-2095-%07d", uuid.New().ID()%10000000)
	s.vulnID = uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm47 seeded vuln', 'HIGH', 7.5)`, s.vulnID, s.cveID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	vulnID := s.vulnID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s: %v", vulnID, err)
		}
	})
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
		s.componentID, s.vulnID); err != nil {
		t.Fatalf("link component to vulnerability: %v", err)
	}

	return s
}

// m47CountAsTenant runs one COUNT(*) inside a migrator tx that has
// SET LOCAL app.current_tenant_id, required for FORCE-RLS tables.
func m47CountAsTenant(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) int {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	var n int
	if err := tx.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v\nquery: %s", err, query)
	}
	return n
}

// m47Call drives one handler through a real echo context inside an app-role
// tenant tx — RLS active, exactly like a live request behind TenantTx. The
// tx is COMMITTED regardless of outcome so "no rows were written" assertions
// prove the handler refused, not that a rollback tidied up after it.
type m47Req struct {
	method     string
	target     string
	body       string
	paramNames []string
	paramVals  []string
	tenantID   uuid.UUID
}

func m47Call(t *testing.T, appDB *sql.DB, r m47Req, h func(echo.Context) error) (int, string) {
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
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		req = httptest.NewRequest(r.method, r.target, nil)
	}
	req = req.WithContext(database.WithTx(context.Background(), tx))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames(r.paramNames...)
	c.SetParamValues(r.paramVals...)
	c.Set("tenant_id", r.tenantID)

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

func asEchoHTTPError(err error, out **echo.HTTPError) bool {
	he, ok := err.(*echo.HTTPError)
	if ok {
		*out = he
	}
	return ok
}

// ---------------------------------------------------------------------------
// 1. POST /projects/:id/public-links + PUT /public-links/:id — sbom_id binding
// ---------------------------------------------------------------------------

func m47PublicLinkHandler(appDB *sql.DB) *PublicLinkHandler {
	return NewPublicLinkHandler(service.NewPublicLinkService(
		appDB,
		repository.NewPublicLinkRepository(appDB),
		repository.NewProjectRepository(appDB),
		repository.NewSbomRepository(appDB),
		repository.NewComponentRepository(appDB),
	))
}

func m47CreateLinkBody(sbomID *uuid.UUID) string {
	body := map[string]any{
		"name":       "m47 share",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
	if sbomID != nil {
		body["sbom_id"] = sbomID.String()
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

// TestM47W1PublicLinkCreate_SiblingProjectSbomIsRejected is the core
// reproduction: `public_links.sbom_id` is a bare FK to sboms(id) and
// public_links has no RLS, so pre-fix a link published under project 1 could
// pin project 2's SBOM — and the anonymous /public/:token route would then
// serve project 2's bytes and component inventory to the internet under
// project 1's name.
func TestM47W1PublicLinkCreate_SiblingProjectSbomIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "pl-sibling")
	h := m47PublicLinkHandler(appDB)

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(&seed.sbom2ID),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("create public link pinned to a SIBLING project's sbom: status %d body %s, want 404", code, body)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM public_links WHERE project_id = $1`, seed.projectID); n != 0 {
		t.Errorf("public_links rows after the rejected create = %d, want 0 (the row must never be persisted)", n)
	}
}

// TestM47W1PublicLinkCreate_ForeignTenantSbomIsRejected: the cross-tenant
// variant. RLS on `sboms` made the resulting link render empty, but the ROW
// was still written — public_links has no RLS of its own.
func TestM47W1PublicLinkCreate_ForeignTenantSbomIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "pl-caller")
	victim := m47SeedAll(t, migDB, "pl-victim")
	h := m47PublicLinkHandler(appDB)

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + caller.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(&victim.sbomID),
		paramNames: []string{"id"},
		paramVals:  []string{caller.projectID.String()},
		tenantID:   caller.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("create public link pinned to a FOREIGN TENANT's sbom: status %d body %s, want 404", code, body)
	}
	if n := m47CountAsTenant(t, migDB, caller.tenantID,
		`SELECT COUNT(*) FROM public_links WHERE sbom_id = $1`, victim.sbomID); n != 0 {
		t.Errorf("public_links rows referencing a foreign tenant's sbom = %d, want 0", n)
	}
}

// TestM47W1PublicLinkCreate_OwnSbomAndNilStillWork pins that the guard is a
// scope check and not a blanket rejection: the project's own sbom_id, and
// the legitimate "no sbom_id = always latest" form, both still succeed.
func TestM47W1PublicLinkCreate_OwnSbomAndNilStillWork(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "pl-ok")
	h := m47PublicLinkHandler(appDB)

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(&seed.sbomID),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("create with the project's OWN sbom: status %d body %s, want 201", code, body)
	}

	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(nil),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("create with NO sbom_id (latest-sbom form): status %d body %s, want 201", code, body)
	}
}

// TestM47W1PublicLinkUpdate_CannotRepointAtSiblingProjectSbom: the update
// route is the more dangerous half — it repoints a link that may already be
// shared, so the "leak" needs no new URL distribution at all.
func TestM47W1PublicLinkUpdate_CannotRepointAtSiblingProjectSbom(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "pl-repoint")
	h := m47PublicLinkHandler(appDB)

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(&seed.sbomID),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("seed link: status %d body %s, want 201", code, body)
	}
	var linkID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM public_links WHERE project_id = $1`, seed.projectID).Scan(&linkID); err != nil {
		t.Fatalf("read seeded link id: %v", err)
	}

	updateBody, _ := json.Marshal(map[string]any{
		"name":       "m47 share",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"is_active":  true,
		"sbom_id":    seed.sbom2ID.String(),
	})
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodPut,
		target:     "/api/v1/public-links/" + linkID.String(),
		body:       string(updateBody),
		paramNames: []string{"id"},
		paramVals:  []string{linkID.String()},
		tenantID:   seed.tenantID,
	}, h.Update)
	if code != http.StatusNotFound {
		t.Errorf("repoint a live share link at a SIBLING project's sbom: status %d body %s, want 404", code, body)
	}

	var pinned uuid.UUID
	if err := migDB.QueryRow(`SELECT sbom_id FROM public_links WHERE id = $1`, linkID).Scan(&pinned); err != nil {
		t.Fatalf("re-read link sbom_id: %v", err)
	}
	if pinned != seed.sbomID {
		t.Errorf("link sbom_id after the rejected update = %s, want %s (it must not have moved)", pinned, seed.sbomID)
	}
}

// TestM47W1PublicLinkCreate_ValidationStaysA400 pins the other half of the
// Codex round-1 Medium fix. Create's error bucket used to be a single 400
// covering caller-fixable validation AND token-gen / bcrypt / repository
// failures; those are now 500. This asserts the split did not over-reach —
// the one genuinely caller-fixable error is still a 400, and is still
// distinct from the scope 404.
func TestM47W1PublicLinkCreate_ValidationStaysA400(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "pl-validation")
	h := m47PublicLinkHandler(appDB)

	// Empty name, otherwise valid (and an in-project sbom_id, so the scope
	// check passes and cannot be what produces the status).
	body, _ := json.Marshal(map[string]any{
		"name":       "",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"sbom_id":    seed.sbomID.String(),
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/public-links",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusBadRequest {
		t.Errorf("create with an empty name: status %d body %s, want 400 "+
			"(caller-fixable validation must not have been swept into the 500 bucket)", code, resp)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM public_links WHERE project_id = $1`, seed.projectID); n != 0 {
		t.Errorf("public_links rows after a rejected create = %d, want 0", n)
	}
}

// TestM47W1PublicLinkView_LegacyMisPinnedLinkIsNotServed covers the
// retroactive half. The write-side guard only protects rows created from now
// on; a deployment that already carries a mis-pinned link would otherwise
// keep serving another project's SBOM anonymously forever. This seeds the
// damage DIRECTLY IN SQL (the service refuses to create it any more) and
// asserts the anonymous route refuses to serve it.
//
// Pre-fix this exact fixture returned 200 with `project_name` naming project
// 1 and a components array containing project 2's inventory — verified
// against the parent commit before the fix landed.
func TestM47W1PublicLinkView_LegacyMisPinnedLinkIsNotServed(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "pl-legacy")
	h := m47PublicLinkHandler(appDB)

	token := "m47legacy" + strings.ReplaceAll(uuid.New().String(), "-", "")
	if _, err := migDB.Exec(`
		INSERT INTO public_links
			(id, tenant_id, project_id, sbom_id, token, name, expires_at, is_active,
			 view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'legacy mis-pinned', NOW() + INTERVAL '1 day', true,
			0, 0, NOW(), NOW())`,
		uuid.New(), seed.tenantID, seed.projectID, seed.sbom2ID, token); err != nil {
		t.Fatalf("seed legacy mis-pinned link: %v", err)
	}

	// The anonymous route: no tenant middleware, no tx on the context —
	// the service opens its own tenant-scoped tx from link.TenantID.
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/public/"+token, nil).WithContext(context.Background())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("token")
	c.SetParamValues(token)
	if err := h.PublicGet(c); err != nil {
		t.Fatalf("PublicGet returned a non-HTTP error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("anonymous view of a legacy mis-pinned link: status %d, want 403 "+
			"(the generic share-flow refusal)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "sibling-only-component") {
		t.Errorf("the anonymous share URL leaked the OTHER project's component inventory: %s", rec.Body.String())
	}

	// And the download path, which hands over the raw bytes.
	req = httptest.NewRequest(http.MethodGet, "/public/"+token+"/download", nil).WithContext(context.Background())
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("token")
	c.SetParamValues(token)
	if err := h.PublicDownload(c); err != nil {
		t.Fatalf("PublicDownload returned a non-HTTP error: %v", err)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("anonymous download of a legacy mis-pinned link: status %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "project-2-only") {
		t.Errorf("the anonymous download served the OTHER project's raw SBOM: %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 2. POST /projects/:id/scan — ?sbom_id= binding + tenant-bound goroutine
// ---------------------------------------------------------------------------

// m47RecordingScanner captures the ctx each ScanComponents call receives so
// the test can assert, from INSIDE the goroutine's own transaction, that the
// tenant GUC is actually bound — the half of the fix that makes the scope
// check load-bearing rather than decorative.
type m47RecordingScanner struct {
	done   chan struct{}
	sbomID uuid.UUID
	// guc is the value of app.current_tenant_id observed inside the scan's
	// transaction; "" means the setting was NULL (the pre-fix state, in
	// which RLS silently filtered every component row).
	guc        string
	components int
	scanErr    error
}

func (s *m47RecordingScanner) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	defer close(s.done)
	s.sbomID = sbomID
	tx, ok := database.TxFromContext(ctx)
	if !ok {
		// This IS the pre-fix state: context.Background() carries no tx, so
		// every statement below would run on a pooled connection with no
		// app.current_tenant_id bound.
		s.scanErr = fmt.Errorf("scan ctx carries no transaction (tenant GUC cannot be bound)")
		return s.scanErr
	}
	var q database.Queryable = tx
	var guc sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT current_setting('app.current_tenant_id', true)`).Scan(&guc); err != nil {
		s.scanErr = err
		return err
	}
	if guc.Valid {
		s.guc = guc.String
	}
	// The load-bearing observation: can the scanner actually SEE the
	// components it is supposed to scan?
	if err := q.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM components WHERE sbom_id = $1`, sbomID).Scan(&s.components); err != nil {
		s.scanErr = err
		return err
	}
	return nil
}

// TestM47W1Scan_SiblingProjectSbomIsRejected: pre-fix `?sbom_id=` was parsed
// and handed straight to the scanners with no relation to `:id`.
func TestM47W1Scan_SiblingProjectSbomIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "scan-sibling")
	scanner := &m47RecordingScanner{done: make(chan struct{})}
	h := &VulnerabilityHandler{
		db:         appDB,
		sbomScope:  service.NewSbomService(repository.NewSbomRepository(appDB), repository.NewComponentRepository(appDB)),
		nvdService: scanner,
	}

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/scan?sbom_id=" + seed.sbom2ID.String() + "&sources=nvd",
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Scan)

	if code != http.StatusNotFound {
		t.Errorf("scan aimed at a SIBLING project's sbom: status %d body %s, want 404", code, body)
	}
	select {
	case <-scanner.done:
		t.Errorf("the scanner ran for an out-of-project sbom (%s) — the check must gate the goroutine", scanner.sbomID)
	case <-time.After(300 * time.Millisecond):
		// No goroutine was started. Correct.
	}
}

// TestM47W1Scan_ForeignTenantSbomIsRejected: the cross-tenant variant.
func TestM47W1Scan_ForeignTenantSbomIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "scan-caller")
	victim := m47SeedAll(t, migDB, "scan-victim")
	scanner := &m47RecordingScanner{done: make(chan struct{})}
	h := &VulnerabilityHandler{
		db:         appDB,
		sbomScope:  service.NewSbomService(repository.NewSbomRepository(appDB), repository.NewComponentRepository(appDB)),
		nvdService: scanner,
	}

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + caller.projectID.String() + "/scan?sbom_id=" + victim.sbomID.String() + "&sources=nvd",
		paramNames: []string{"id"},
		paramVals:  []string{caller.projectID.String()},
		tenantID:   caller.tenantID,
	}, h.Scan)

	if code != http.StatusNotFound {
		t.Errorf("scan aimed at a FOREIGN TENANT's sbom: status %d body %s, want 404", code, body)
	}
	select {
	case <-scanner.done:
		t.Error("the scanner ran for a foreign tenant's sbom")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestM47W1Scan_InProjectSbomRunsWithTenantBound is the honesty test for the
// second half of the fix. Pre-fix the goroutine used context.Background(),
// so `app.current_tenant_id` was NULL inside the scan and the FORCE RLS
// policy on `components` matched zero rows — the endpoint answered 202 and
// then did nothing at all, for every caller. This asserts the GUC is bound
// AND that the scanner can see the component it is supposed to scan.
func TestM47W1Scan_InProjectSbomRunsWithTenantBound(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "scan-ok")
	scanner := &m47RecordingScanner{done: make(chan struct{})}
	h := &VulnerabilityHandler{
		db:         appDB,
		sbomScope:  service.NewSbomService(repository.NewSbomRepository(appDB), repository.NewComponentRepository(appDB)),
		nvdService: scanner,
	}

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/scan?sbom_id=" + seed.sbomID.String() + "&sources=nvd",
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Scan)
	if code != http.StatusAccepted {
		t.Fatalf("scan of the project's OWN sbom: status %d body %s, want 202", code, body)
	}

	select {
	case <-scanner.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the scan goroutine never ran")
	}
	if scanner.scanErr != nil {
		t.Fatalf("scanner observation failed: %v", scanner.scanErr)
	}
	if scanner.guc != seed.tenantID.String() {
		t.Errorf("app.current_tenant_id inside the scan tx = %q, want %q "+
			"(context.Background() leaves it unset, which makes RLS filter every component)",
			scanner.guc, seed.tenantID)
	}
	if scanner.components != 1 {
		t.Errorf("components visible to the scanner = %d, want 1 "+
			"(0 is the pre-fix state: the scan 'completed' having seen nothing)", scanner.components)
	}
}

// ---------------------------------------------------------------------------
// 3. POST /projects/:id/vex + PUT/DELETE/GET /projects/:id/vex/:vex_id
// ---------------------------------------------------------------------------

func m47VEXHandler(appDB *sql.DB) *VEXHandler {
	return NewVEXHandler(service.NewVEXService(
		repository.NewVEXRepository(appDB),
		repository.NewVulnerabilityRepository(appDB),
	), nil)
}

// TestM47W1VEXCreate_UnaffectingVulnerabilityIsRejected: `vulnerabilities`
// is a global RLS-free NVD cache, so pre-fix ANY id in it was accepted as
// the subject of a VEX verdict — including CVEs the project has no exposure
// to. The sibling `component_id` field had the F379 guard since M26; this is
// the half that was missing.
func TestM47W1VEXCreate_UnaffectingVulnerabilityIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "vex-caller")
	other := m47SeedAll(t, migDB, "vex-other") // other.vulnID affects a FOREIGN tenant only
	h := m47VEXHandler(appDB)

	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": other.vulnID.String(),
		"status":           "not_affected",
		"justification":    "component_not_present",
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + caller.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{caller.projectID.String()},
		tenantID:   caller.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("VEX verdict for a vulnerability that does not affect the project: status %d body %s, want 404", code, resp)
	}
	if n := m47CountAsTenant(t, migDB, caller.tenantID,
		`SELECT COUNT(*) FROM vex_statements WHERE vulnerability_id = $1`, other.vulnID); n != 0 {
		t.Errorf("vex_statements minted for an unaffecting vulnerability = %d, want 0", n)
	}
}

// TestM47W1VEXCreate_AffectingVulnerabilityStillWorks: the guard must not
// break the legitimate flow.
func TestM47W1VEXCreate_AffectingVulnerabilityStillWorks(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "vex-ok")
	h := m47VEXHandler(appDB)

	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": seed.vulnID.String(),
		"component_id":     seed.componentID.String(),
		"status":           "affected",
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("VEX verdict for an affecting vulnerability: status %d body %s, want 201", code, resp)
	}
}

// TestM47W1VEXCreate_ForeignComponentAnswersTheSame404 closes the last
// distinguishable channel on this route (Codex round 1, Low). The F379
// component-ownership guard predates M47 and rejected with an echoed 400
// ("component does not belong to project") while its sibling checks answered
// 404 — so a caller could tell "that component is elsewhere in my tenant"
// apart from every other out-of-scope rejection. Both now answer 404.
func TestM47W1VEXCreate_ForeignComponentAnswersTheSame404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "vex-comp")
	h := m47VEXHandler(appDB)

	// The sibling project's component, paired with a vulnerability that DOES
	// affect the route's project — so only the component is out of scope.
	// `components` is FORCE RLS, so this read needs the tenant GUC bound.
	var siblingComponent uuid.UUID
	func() {
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if err := tx.QueryRow(`SELECT id FROM components WHERE sbom_id = $1`, seed.sbom2ID).
			Scan(&siblingComponent); err != nil {
			t.Fatalf("read sibling component: %v", err)
		}
	}()

	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": seed.vulnID.String(),
		"component_id":     siblingComponent.String(),
		"status":           "affected",
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("VEX verdict naming a SIBLING project's component: status %d body %s, want 404 "+
			"(400 made this rejection distinguishable from every other out-of-scope one)", code, resp)
	}
	if strings.Contains(resp, "does not belong to project") {
		t.Errorf("the response still echoes the component-specific reason: %s", resp)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM vex_statements WHERE component_id = $1`, siblingComponent); n != 0 {
		t.Errorf("vex_statements minted against a sibling project's component = %d, want 0", n)
	}
}

// TestM47W1VEXCreate_UnlinkedComponentVulnPairIsRejected pins the Codex
// round-2 Medium — the subtlest hole in this wave.
//
// After the first fix, a component-specific VEX statement was validated by
// TWO INDEPENDENT facts: "this vulnerability affects some component of the
// project" and "this component belongs to the project". Their conjunction is
// strictly weaker than the join: a component and a vulnerability can both be
// in the project while having no linkage between them, which let a caller
// record a verdict — typically "not_affected" — against a component the CVE
// does not touch. Nothing in the schema forbids it (components carry no
// project_id; vex_statements.component_id is a bare FK).
//
// The fixture makes exactly that pair: a SECOND component in the same
// project's SBOM that is deliberately NOT linked to seed.vulnID.
func TestM47W1VEXCreate_UnlinkedComponentVulnPairIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "vex-link")
	h := m47VEXHandler(appDB)

	// A component of the SAME project and SAME sbom, with no
	// component_vulnerabilities row for seed.vulnID.
	unlinked := uuid.New()
	func() {
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(`
			INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
			VALUES ($1, $2, $3, 'unaffected-lib', '2.0', 'library', 'pkg:generic/unaffected@2.0', NOW())`,
			unlinked, seed.tenantID, seed.sbomID); err != nil {
			t.Fatalf("seed unlinked component: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}()

	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": seed.vulnID.String(),
		"component_id":     unlinked.String(),
		"status":           "not_affected",
		"justification":    "component_not_present",
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("VEX verdict on an in-project component the vulnerability does NOT affect: "+
			"status %d body %s, want 404 (both ids are individually in scope — only the JOIN rejects it)",
			code, resp)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM vex_statements WHERE component_id = $1`, unlinked); n != 0 {
		t.Errorf("vex_statements minted for an unlinked (component, vulnerability) pair = %d, want 0", n)
	}

	// The genuinely affected component still works, so the join is a scope
	// check and not a blanket refusal.
	body, _ = json.Marshal(map[string]string{
		"vulnerability_id": seed.vulnID.String(),
		"component_id":     seed.componentID.String(),
		"status":           "affected",
	})
	code, resp = m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("VEX verdict on the genuinely affected component: status %d body %s, want 201", code, resp)
	}
}

// TestM47W1PublicLinkUpdate_UnknownLinkIsOneAnd404 pins the Codex round-1
// Medium: an unresolvable link id used to be a 400 that a prober could tell
// apart from every other rejection on this route.
func TestM47W1PublicLinkUpdate_UnknownLinkIsOneAnd404(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "pl-unknown")
	victim := m47SeedAll(t, migDB, "pl-owner")
	h := m47PublicLinkHandler(appDB)

	// Seed a real link owned by the OTHER tenant, so the "exists but not
	// yours" case can be compared against "does not exist at all".
	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + victim.projectID.String() + "/public-links",
		body:       m47CreateLinkBody(&victim.sbomID),
		paramNames: []string{"id"},
		paramVals:  []string{victim.projectID.String()},
		tenantID:   victim.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("seed victim link: status %d body %s, want 201", code, body)
	}
	var victimLinkID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM public_links WHERE project_id = $1`, victim.projectID).
		Scan(&victimLinkID); err != nil {
		t.Fatalf("read victim link id: %v", err)
	}

	updateBody, _ := json.Marshal(map[string]any{
		"name":       "hijack",
		"expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		"is_active":  true,
	})
	for _, tc := range []struct {
		name string
		id   uuid.UUID
	}{
		{"another tenant's link", victimLinkID},
		{"a link that does not exist", uuid.New()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := m47Call(t, appDB, m47Req{
				method:     http.MethodPut,
				target:     "/api/v1/public-links/" + tc.id.String(),
				body:       string(updateBody),
				paramNames: []string{"id"},
				paramVals:  []string{tc.id.String()},
				tenantID:   caller.tenantID,
			}, h.Update)
			if code != http.StatusNotFound {
				t.Errorf("PUT %s: status %d body %s, want 404 (both cases must be indistinguishable)",
					tc.name, code, body)
			}
		})
	}

	// And the victim's link is untouched.
	var name string
	if err := migDB.QueryRow(`SELECT name FROM public_links WHERE id = $1`, victimLinkID).Scan(&name); err != nil {
		t.Fatalf("re-read victim link: %v", err)
	}
	if name == "hijack" {
		t.Error("a cross-tenant PUT rewrote the victim's public link")
	}
}

// m47SeedVEXStatement mints a statement in seed.projectID through the real
// service so the fixture cannot drift from the write path.
func m47SeedVEXStatement(t *testing.T, appDB, migDB *sql.DB, h *VEXHandler, seed m47Seed) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"vulnerability_id": seed.vulnID.String(),
		"component_id":     seed.componentID.String(),
		"status":           "affected",
	})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("seed vex statement: status %d body %s, want 201", code, resp)
	}
	var id uuid.UUID
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if err := tx.QueryRow(`SELECT id FROM vex_statements WHERE project_id = $1`, seed.projectID).Scan(&id); err != nil {
		t.Fatalf("read seeded vex statement id: %v", err)
	}
	return id
}

// TestM47W1VEXMutate_SiblingProjectURLCannotTouchTheStatement: the route
// names a project and the repository ran `WHERE id = $N`. Within a tenant,
// project 2's URL could rewrite or delete project 1's compliance verdict —
// and the audit row would name project 2.
func TestM47W1VEXMutate_SiblingProjectURLCannotTouchTheStatement(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "vex-mutate")
	h := m47VEXHandler(appDB)
	vexID := m47SeedVEXStatement(t, appDB, migDB, h, seed)

	updateBody, _ := json.Marshal(map[string]string{
		"status":        "not_affected",
		"justification": "component_not_present",
	})

	// Same tenant, WRONG project.
	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPut,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/vex/" + vexID.String(),
		body:       string(updateBody),
		paramNames: []string{"id", "vex_id"},
		paramVals:  []string{seed.project2ID.String(), vexID.String()},
		tenantID:   seed.tenantID,
	}, h.Update)
	if code != http.StatusNotFound {
		t.Errorf("PUT through a sibling project's URL: status %d body %s, want 404", code, body)
	}
	var status string
	tx, _ := migDB.Begin()
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String())
	if err := tx.QueryRow(`SELECT status FROM vex_statements WHERE id = $1`, vexID).Scan(&status); err != nil {
		t.Fatalf("re-read statement: %v", err)
	}
	_ = tx.Rollback()
	if status != "affected" {
		t.Errorf("status after a cross-project PUT = %q, want %q (the verdict must not have moved)", status, "affected")
	}

	// GET through the sibling project's URL must not leak it either.
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodGet,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/vex/" + vexID.String(),
		paramNames: []string{"id", "vex_id"},
		paramVals:  []string{seed.project2ID.String(), vexID.String()},
		tenantID:   seed.tenantID,
	}, h.Get)
	if code != http.StatusNotFound {
		t.Errorf("GET through a sibling project's URL: status %d body %s, want 404", code, body)
	}

	// DELETE through the sibling project's URL must keep the row.
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/vex/" + vexID.String(),
		paramNames: []string{"id", "vex_id"},
		paramVals:  []string{seed.project2ID.String(), vexID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNotFound {
		t.Errorf("DELETE through a sibling project's URL: status %d body %s, want 404", code, body)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM vex_statements WHERE id = $1`, vexID); n != 1 {
		t.Errorf("vex_statements rows after a cross-project DELETE = %d, want 1", n)
	}

	// The owning project still works, for all three verbs.
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodPut,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex/" + vexID.String(),
		body:       string(updateBody),
		paramNames: []string{"id", "vex_id"},
		paramVals:  []string{seed.projectID.String(), vexID.String()},
		tenantID:   seed.tenantID,
	}, h.Update)
	if code != http.StatusOK {
		t.Fatalf("PUT through the owning project: status %d body %s, want 200", code, body)
	}
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/vex/" + vexID.String(),
		paramNames: []string{"id", "vex_id"},
		paramVals:  []string{seed.projectID.String(), vexID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNoContent {
		t.Fatalf("DELETE through the owning project: status %d body %s, want 204", code, body)
	}
}

// ---------------------------------------------------------------------------
// 4. POST /projects/:id/apikeys + DELETE /projects/:id/apikeys/:key_id
// ---------------------------------------------------------------------------

func m47APIKeyHandler(appDB *sql.DB) *APIKeyHandler {
	return NewAPIKeyHandler(service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB)))
}

// TestM47W1APIKeyCreate_ForeignProjectIsRejected: `api_keys` has neither RLS
// (migration 028) nor a composite (tenant_id, project_id) FK, so pre-fix the
// single-column FK accepted ANY project UUID in the installation — a key row
// of tenant C hanging off tenant V's project graph, and a 201-vs-400 oracle
// for project UUIDs.
func TestM47W1APIKeyCreate_ForeignProjectIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "key-caller")
	victim := m47SeedAll(t, migDB, "key-victim")
	h := m47APIKeyHandler(appDB)

	body, _ := json.Marshal(map[string]any{"name": "m47 key", "permissions": "write"})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + victim.projectID.String() + "/apikeys",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{victim.projectID.String()},
		tenantID:   caller.tenantID,
	}, h.Create)

	if code != http.StatusNotFound {
		t.Errorf("mint an api key against a FOREIGN TENANT's project: status %d body %s, want 404", code, resp)
	}
	// api_keys has no RLS, so this count is authoritative without a GUC.
	var n int
	if err := migDB.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE project_id = $1`, victim.projectID).Scan(&n); err != nil {
		t.Fatalf("count api_keys: %v", err)
	}
	if n != 0 {
		t.Errorf("api_keys rows hanging off the victim's project = %d, want 0", n)
	}

	// And the unknown-project case must answer identically (no oracle).
	unknown := uuid.New()
	code, resp = m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + unknown.String() + "/apikeys",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{unknown.String()},
		tenantID:   caller.tenantID,
	}, h.Create)
	if code != http.StatusNotFound {
		t.Errorf("mint an api key against an UNKNOWN project: status %d body %s, want 404 "+
			"(it must be indistinguishable from a real project of another tenant)", code, resp)
	}
}

// TestM47W1APIKeyDelete_SiblingProjectURLCannotDestroyTheKey (same-shape
// finding from the re-scan, not in the original list): the repository DELETE
// filtered on (id, tenant_id) only, so an Admin acting through project 2's
// URL destroyed project 1's key and got a 204.
func TestM47W1APIKeyDelete_SiblingProjectURLCannotDestroyTheKey(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "key-del")
	h := m47APIKeyHandler(appDB)

	body, _ := json.Marshal(map[string]any{"name": "m47 key", "permissions": "write"})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/apikeys",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("seed project key: status %d body %s, want 201", code, resp)
	}
	var keyID uuid.UUID
	if err := migDB.QueryRow(`SELECT id FROM api_keys WHERE project_id = $1`, seed.projectID).Scan(&keyID); err != nil {
		t.Fatalf("read seeded key id: %v", err)
	}

	code, resp = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/apikeys/" + keyID.String(),
		paramNames: []string{"id", "key_id"},
		paramVals:  []string{seed.project2ID.String(), keyID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNotFound {
		t.Errorf("delete a key through a SIBLING project's URL: status %d body %s, want 404", code, resp)
	}
	var alive int
	if err := migDB.QueryRow(`SELECT COUNT(*) FROM api_keys WHERE id = $1`, keyID).Scan(&alive); err != nil {
		t.Fatalf("count key: %v", err)
	}
	if alive != 1 {
		t.Errorf("api_keys rows after a cross-project delete = %d, want 1 (the key must survive)", alive)
	}

	// The owning project still deletes it.
	code, resp = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/apikeys/" + keyID.String(),
		paramNames: []string{"id", "key_id"},
		paramVals:  []string{seed.projectID.String(), keyID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNoContent {
		t.Errorf("delete through the owning project: status %d body %s, want 204", code, resp)
	}
}

// ---------------------------------------------------------------------------
// 5. license policy routes
// ---------------------------------------------------------------------------

func m47LicenseHandler(appDB *sql.DB) *LicensePolicyHandler {
	return NewLicensePolicyHandler(service.NewLicensePolicyService(
		repository.NewLicensePolicyRepository(appDB),
		repository.NewComponentRepository(appDB),
		repository.NewSbomRepository(appDB),
	))
}

func m47SeedLicensePolicy(t *testing.T, appDB, migDB *sql.DB, h *LicensePolicyHandler, seed m47Seed) uuid.UUID {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"license_id": "GPL-3.0-only", "policy_type": "denied"})
	code, resp := m47Call(t, appDB, m47Req{
		method:     http.MethodPost,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/licenses",
		body:       string(body),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.Create)
	if code != http.StatusCreated {
		t.Fatalf("seed license policy: status %d body %s, want 201", code, resp)
	}
	var id uuid.UUID
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if err := tx.QueryRow(`SELECT id FROM license_policies WHERE project_id = $1`, seed.projectID).Scan(&id); err != nil {
		t.Fatalf("read seeded policy id: %v", err)
	}
	return id
}

// TestM47W1LicensePolicy_SiblingProjectURLCannotTouchThePolicy: license
// policies drive CheckViolations and the compliance evidence pack, so a
// cross-project edit silently changes another product's compliance verdict.
func TestM47W1LicensePolicy_SiblingProjectURLCannotTouchThePolicy(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "lic-mutate")
	h := m47LicenseHandler(appDB)
	policyID := m47SeedLicensePolicy(t, appDB, migDB, h, seed)

	updateBody, _ := json.Marshal(map[string]string{"policy_type": "allowed", "reason": "hijacked"})
	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPut,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/licenses/" + policyID.String(),
		body:       string(updateBody),
		paramNames: []string{"id", "policy_id"},
		paramVals:  []string{seed.project2ID.String(), policyID.String()},
		tenantID:   seed.tenantID,
	}, h.Update)
	if code != http.StatusNotFound {
		t.Errorf("PUT through a sibling project's URL: status %d body %s, want 404", code, body)
	}

	var policyType string
	tx, _ := migDB.Begin()
	_, _ = tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, seed.tenantID.String())
	if err := tx.QueryRow(`SELECT policy_type FROM license_policies WHERE id = $1`, policyID).Scan(&policyType); err != nil {
		t.Fatalf("re-read policy: %v", err)
	}
	_ = tx.Rollback()
	if policyType != "denied" {
		t.Errorf("policy_type after a cross-project PUT = %q, want %q", policyType, "denied")
	}

	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodGet,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/licenses/" + policyID.String(),
		paramNames: []string{"id", "policy_id"},
		paramVals:  []string{seed.project2ID.String(), policyID.String()},
		tenantID:   seed.tenantID,
	}, h.Get)
	if code != http.StatusNotFound {
		t.Errorf("GET through a sibling project's URL: status %d body %s, want 404", code, body)
	}

	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.project2ID.String() + "/licenses/" + policyID.String(),
		paramNames: []string{"id", "policy_id"},
		paramVals:  []string{seed.project2ID.String(), policyID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNotFound {
		t.Errorf("DELETE through a sibling project's URL: status %d body %s, want 404", code, body)
	}
	if n := m47CountAsTenant(t, migDB, seed.tenantID,
		`SELECT COUNT(*) FROM license_policies WHERE id = $1`, policyID); n != 1 {
		t.Errorf("license_policies rows after a cross-project DELETE = %d, want 1", n)
	}

	// Owning project still works.
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodDelete,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/licenses/" + policyID.String(),
		paramNames: []string{"id", "policy_id"},
		paramVals:  []string{seed.projectID.String(), policyID.String()},
		tenantID:   seed.tenantID,
	}, h.Delete)
	if code != http.StatusNoContent {
		t.Errorf("DELETE through the owning project: status %d body %s, want 204", code, body)
	}
}

// TestM47W1LicenseViolations_SiblingProjectSbomIsRejected (same-shape
// finding from the re-scan): `?sbom_id=` was unbound, so project 1's
// violations report enumerated project 2's ENTIRE component inventory.
func TestM47W1LicenseViolations_SiblingProjectSbomIsRejected(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m47SeedAll(t, migDB, "lic-viol")
	h := m47LicenseHandler(appDB)
	_ = m47SeedLicensePolicy(t, appDB, migDB, h, seed)

	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodGet,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/licenses/violations?sbom_id=" + seed.sbom2ID.String(),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.CheckViolations)
	if code != http.StatusNotFound {
		t.Errorf("violations report aimed at a SIBLING project's sbom: status %d body %s, want 404", code, body)
	}
	if strings.Contains(body, "sibling-only-component") {
		t.Errorf("the response leaked the sibling project's component inventory: %s", body)
	}

	// The project's own sbom still reports.
	code, body = m47Call(t, appDB, m47Req{
		method:     http.MethodGet,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/licenses/violations?sbom_id=" + seed.sbomID.String(),
		paramNames: []string{"id"},
		paramVals:  []string{seed.projectID.String()},
		tenantID:   seed.tenantID,
	}, h.CheckViolations)
	if code != http.StatusOK {
		t.Fatalf("violations report for the project's OWN sbom: status %d body %s, want 200", code, body)
	}
	if !strings.Contains(body, "libm47") {
		t.Errorf("violations report for the own sbom lost its content: %s", body)
	}
}

// ---------------------------------------------------------------------------
// 6. compliance checklist / visualization — project must be in the tenant
// ---------------------------------------------------------------------------

func m47ComplianceHandler(appDB *sql.DB) *ComplianceHandler {
	return NewComplianceHandler(service.NewComplianceServiceFull(
		repository.NewSbomRepository(appDB),
		repository.NewComponentRepository(appDB),
		repository.NewVulnerabilityRepository(appDB),
		repository.NewVEXRepository(appDB),
		repository.NewLicensePolicyRepository(appDB),
		repository.NewDashboardRepository(appDB),
		repository.NewChecklistRepository(appDB),
		repository.NewVisualizationRepository(appDB),
		repository.NewPublicLinkRepository(appDB),
	))
}

// TestM47W1Compliance_ForeignProjectIsRefusedCleanly. These two tables DO
// carry the composite (tenant_id, project_id) FK from migration 041, so the
// cross-tenant WRITE was already rejected — but as an opaque constraint
// error (500), which both leaks "this project exists elsewhere" as a
// distinguishable status AND makes the DELETE path (which the FK cannot
// help) answer 204 for a no-op. Post-fix every one of them is a plain 404.
func TestM47W1Compliance_ForeignProjectIsRefusedCleanly(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	caller := m47SeedAll(t, migDB, "cmp-caller")
	victim := m47SeedAll(t, migDB, "cmp-victim")
	h := m47ComplianceHandler(appDB)

	// A real check id from the fixed 18-item METI catalog: the handler
	// validates it, so a made-up value would short-circuit before the scope
	// check and the test would pass vacuously.
	items := model.GetAllChecklistItems()
	if len(items) == 0 {
		t.Fatal("precondition: the METI checklist catalog is empty")
	}
	checkID := items[0].ID

	for _, tc := range []struct {
		name    string
		project uuid.UUID
	}{
		{"foreign tenant's project", victim.projectID},
		{"unknown project", uuid.New()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := m47Call(t, appDB, m47Req{
				method:     http.MethodPut,
				target:     "/api/v1/projects/" + tc.project.String() + "/checklist/" + checkID,
				body:       `{"response":true}`,
				paramNames: []string{"id", "checkId"},
				paramVals:  []string{tc.project.String(), checkID},
				tenantID:   caller.tenantID,
			}, h.UpdateChecklistResponse)
			if code != http.StatusNotFound {
				t.Errorf("PUT checklist: status %d body %s, want 404", code, body)
			}

			code, body = m47Call(t, appDB, m47Req{
				method:     http.MethodDelete,
				target:     "/api/v1/projects/" + tc.project.String() + "/checklist/" + checkID,
				paramNames: []string{"id", "checkId"},
				paramVals:  []string{tc.project.String(), checkID},
				tenantID:   caller.tenantID,
			}, h.DeleteChecklistResponse)
			if code != http.StatusNotFound {
				t.Errorf("DELETE checklist: status %d body %s, want 404 (204 for a no-op is a lie)", code, body)
			}

			code, body = m47Call(t, appDB, m47Req{
				method:     http.MethodPut,
				target:     "/api/v1/projects/" + tc.project.String() + "/visualization",
				body:       `{"sbom_author_scope":"self","dependency_scope":"direct_only","generation_method":"tool_no_review","data_format":"standard","utilization_scope":[],"utilization_actor":"product_vendor"}`,
				paramNames: []string{"id"},
				paramVals:  []string{tc.project.String()},
				tenantID:   caller.tenantID,
			}, h.UpdateVisualizationSettings)
			if code != http.StatusNotFound {
				t.Errorf("PUT visualization: status %d body %s, want 404", code, body)
			}

			code, body = m47Call(t, appDB, m47Req{
				method:     http.MethodDelete,
				target:     "/api/v1/projects/" + tc.project.String() + "/visualization",
				paramNames: []string{"id"},
				paramVals:  []string{tc.project.String()},
				tenantID:   caller.tenantID,
			}, h.DeleteVisualizationSettings)
			if code != http.StatusNotFound {
				t.Errorf("DELETE visualization: status %d body %s, want 404", code, body)
			}
		})
	}

	// The caller's own project still works, so the guard is a scope check
	// and not a blanket refusal.
	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodPut,
		target:     "/api/v1/projects/" + caller.projectID.String() + "/checklist/" + checkID,
		body:       `{"response":true}`,
		paramNames: []string{"id", "checkId"},
		paramVals:  []string{caller.projectID.String(), checkID},
		tenantID:   caller.tenantID,
	}, h.UpdateChecklistResponse)
	if code != http.StatusOK {
		t.Fatalf("PUT checklist on the caller's own project: status %d body %s, want 200", code, body)
	}
	if n := m47CountAsTenant(t, migDB, caller.tenantID,
		`SELECT COUNT(*) FROM compliance_checklist_responses WHERE project_id = $1`, caller.projectID); n != 1 {
		t.Errorf("checklist rows for the caller's own project = %d, want 1", n)
	}
}
