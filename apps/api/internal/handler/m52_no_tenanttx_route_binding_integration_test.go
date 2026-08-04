//go:build integration

// Package handler — M52: every route classified TenantBindingBindsItself in
// middleware/tenant_binding.go must actually bind, driven against a live
// database on a pooled connection in the state a running server produces.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M52' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # Why these tests exist rather than a comment
//
// TenantBindingBindsItself is a promise about code in another package. Exactly
// such a promise was already written in cmd/server/main.go — "the handler's
// loadDraftScoped → runner.GetDraft now opens its own short read tx" — twelve
// lines above the CRA registration that did NOT do that and answered 500 for
// every input from the day it shipped. A classification nothing drives is the
// same artefact that failed there.
//
// # The connection state being reproduced
//
// A route registered without appmw.TenantTx borrows a connection from the same
// pool every TenantTx route uses. `SET LOCAL app.current_tenant_id` leaves the
// placeholder GUC at the EMPTY STRING on that backend after its transaction
// ends, so an RLS policy predicate
//
//	tenant_id = current_setting('app.current_tenant_id', true)::UUID
//
// casts the empty string to UUID and raises 22P02 — the read errors, and the
// endpoint answers 500 for a row the caller owns as readily as for one that
// does not exist. (On a backend the GUC was NEVER set on, current_setting
// returns NULL, the predicate is NULL and the read returns zero rows: a false
// 404. The second state is what a running server is permanently in; it is the
// one reproduced here because it is the louder of the two and the one that was
// observed in production.)
//
// m52PoisonedApp puts a one-connection pool into exactly that state and
// asserts the precondition rather than assuming it.
//
// # Every drive has a negative control
//
// A test that only shows "the request succeeded" cannot distinguish "the
// binding works" from "the poison did not take". Each drive therefore also
// exercises the same path with the binding removed and observes the failure:
//
//	runner routes  → swap the TxManager for the Passthrough one (which is what
//	                 the runner falls back to when production forgets to wire
//	                 *triage.DBTxManager) and observe the 500.
//	public links   → issue the read the service performs INSIDE its tx, on the
//	                 same poisoned pool with no tx, and observe the error.
//	clerk webhook  → replay TenantRepository.Create's two INSERTs without the
//	                 set_config between them and observe the refusal.
package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/lib/pq"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/service/cra"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

func m52Env(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("M52 tenant-binding drives require DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator). Start postgres, source the .env " +
			"values, then re-run with -tags=integration.")
	}
	return appURL, migURL
}

// m52Open FAILS rather than skips when a URL is configured but unusable.
// m52Env has already skipped the "no integration DB here" case; past that
// point the operator asked for this run, and a silent skip would let a tagged
// CI job report success with the gate untested.
func m52Open(t *testing.T, url, role string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open %s DB: %v", role, err)
		return nil
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping %s DB: %v (the URL is set, so this is a broken environment, "+
			"not an absent one)", role, err)
		return nil
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m52PoisonedApp returns a one-connection sbomhub_app pool whose single
// backend has `app.current_tenant_id` at the empty string, and proves it.
//
// MaxOpenConns(1) is what makes the reproduction deterministic: the handler
// under test must borrow the very backend that was poisoned.
func m52PoisonedApp(t *testing.T, appURL string) *sql.DB {
	t.Helper()
	db := m52Open(t, appURL, "sbomhub_app")
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin poison tx: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`,
		uuid.New().String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("poison SET LOCAL: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit poison tx: %v", err)
	}

	var isNull bool
	var val sql.NullString
	if err := db.QueryRow(
		`SELECT current_setting('app.current_tenant_id', true) IS NULL,
		        current_setting('app.current_tenant_id', true)`).Scan(&isNull, &val); err != nil {
		t.Fatalf("read GUC state: %v", err)
	}
	if isNull || val.String != "" {
		t.Fatalf("precondition not met: app.current_tenant_id is (null=%v, value=%q), want a "+
			"non-NULL empty string. The pooled connection was not poisoned, so nothing "+
			"below can observe the defect it exists to reproduce.", isNull, val.String)
	}
	return db
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

// m52Fixture is one tenant with the full object graph the runner routes walk:
// project → sbom → component, plus a global vulnerability linked to that
// component.
type m52Fixture struct {
	TenantID    uuid.UUID
	UserID      uuid.UUID
	ProjectID   uuid.UUID
	SbomID      uuid.UUID
	ComponentID uuid.UUID
	VulnID      uuid.UUID
	CVEID       string
}

// m52SeedUser inserts the acting user. audit_logs.user_id carries a foreign
// key to `users`, so the runners' Stage 3 audit write — which is inside the
// same transaction as the draft/report INSERT, per the audit-or-nothing
// contract — fails the whole cycle without one. Passing a random UUID instead
// would turn every drive below into a test of the FK rather than of the
// tenant binding.
func m52SeedUser(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tag := "m52-" + label + "-" + id.String()
	if _, err := migDB.Exec(`
		INSERT INTO users (id, clerk_user_id, email, name)
		VALUES ($1, $2, $3, $4)`, id, tag, tag+"@example.test", "m52 "+label); err != nil {
		t.Fatalf("seed user %s: %v", label, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM users WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup user %s: %v", id, err)
		}
	})
	return id
}

func m52SeedTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	tag := "m52-" + label + "-" + id.String()
	if _, err := migDB.Exec(`
		INSERT INTO tenants (id, clerk_org_id, name, slug, plan)
		VALUES ($1, $2, $3, $4, 'free')`, id, tag, "m52 "+label, tag); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	t.Cleanup(func() {
		// The tenant CASCADE reaps every child row, including the FORCE-RLS
		// ones: PostgreSQL referential-integrity triggers bypass row security,
		// so no GUC is needed here.
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup tenant %s: %v", id, err)
		}
	})
	return id
}

// m52AsTenant runs one statement inside a migrator transaction bound to
// tenantID, which the FORCE-RLS tables require even of their owner.
func m52AsTenant(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin seed tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`,
		tenantID.String()); err != nil {
		t.Fatalf("seed SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(query, args...); err != nil {
		t.Fatalf("seed exec: %v\nquery: %s", err, query)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed tx: %v", err)
	}
}

func m52SeedGraph(t *testing.T, migDB *sql.DB, label string) m52Fixture {
	t.Helper()
	f := m52Fixture{
		TenantID:    m52SeedTenant(t, migDB, label),
		UserID:      m52SeedUser(t, migDB, label),
		ProjectID:   uuid.New(),
		SbomID:      uuid.New(),
		ComponentID: uuid.New(),
		VulnID:      uuid.New(),
	}
	// A CVE id unique per fixture: `vulnerabilities` is global (no tenant
	// column, no RLS) and shared with every other test in the package.
	f.CVEID = "CVE-2099-" + strings.ToUpper(f.VulnID.String()[:8])

	m52AsTenant(t, migDB, f.TenantID,
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`,
		f.ProjectID, f.TenantID, "m52-"+label+"-project")
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{"bomFormat":"CycloneDX"}'::jsonb, NOW())`,
		f.SbomID, f.TenantID, f.ProjectID)
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl)
		VALUES ($1, $2, $3, 'm52-lib', '1.0.0', 'library', 'pkg:golang/m52-lib@1.0.0')`,
		f.ComponentID, f.TenantID, f.SbomID)

	// `vulnerabilities` is not tenant-scoped and is NOT reaped by the tenant
	// CASCADE, so it gets its own cleanup. Registered AFTER the tenant's, and
	// t.Cleanup is LIFO, so the tenant (and with it component_vulnerabilities)
	// goes first.
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source)
		VALUES ($1, $2, 'm52 fixture', 'HIGH', 7.5, 'NVD')`, f.VulnID, f.CVEID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, f.VulnID); err != nil {
			t.Errorf("cleanup vulnerability %s: %v", f.VulnID, err)
		}
	})

	// component_vulnerabilities has no tenant column and no RLS; it is reaped
	// by the component (and by the vulnerability) CASCADE.
	if _, err := migDB.Exec(`
		INSERT INTO component_vulnerabilities (component_id, vulnerability_id)
		VALUES ($1, $2)`, f.ComponentID, f.VulnID); err != nil {
		t.Fatalf("seed component_vulnerabilities: %v", err)
	}

	// tenant_llm_config is FORCE RLS and is read by the production
	// ProviderResolver on EVERY runner request — the first statement Stage 1
	// issues, before any of the reads above. A row has to exist for the read
	// to evaluate the policy predicate at all: an empty table scans nothing
	// and raises nothing, which would make the resolver's presence in the
	// drives decorative.
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO tenant_llm_config (tenant_id, mode, provider, model)
		VALUES ($1, 'byok', 'ollama', 'm52-model')`, f.TenantID)
	return f
}

// m52ProviderResolver reproduces the shape of production's per-tenant provider
// resolution (cmd/server/main.go newTenantLLMProviderResolver): a
// tenant_llm_config read, issued inside whatever transaction the runner's
// TxManager has opened.
//
// It returns the disabled provider whatever the row says, because the point
// under test is the tenant BINDING, not provider selection — and a resolver
// that actually built an Ollama client would send Stage 2 at a network
// endpoint that does not exist in CI. What it does keep is the READ, which is
// the first RLS-protected statement a runner route issues.
func m52ProviderResolver(t *testing.T, appDB *sql.DB) func(context.Context, uuid.UUID) (llm.Provider, error) {
	repo := repository.NewTenantLLMConfigRepository(appDB)
	return func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error) {
		if _, err := repo.Get(ctx, tenantID); err != nil &&
			!errors.Is(err, repository.ErrTenantLLMConfigNotFound) {
			// Production wraps and propagates this, which is what turns an
			// unbound read into the 500 the negative controls observe.
			return nil, fmt.Errorf("m52: load tenant_llm_config: %w", err)
		}
		return &llm.DisabledProvider{Reason: "M52 integration test"}, nil
	}
}

// m52SeedApprovedVEXDraft inserts the approved draft cra.Runner auto-picks as
// the source for a report on (project, cve).
func m52SeedApprovedVEXDraft(t *testing.T, migDB *sql.DB, f m52Fixture) {
	t.Helper()
	id := uuid.New()
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id, cve_id,
			state, detail, evidence, decision
		) VALUES ($1, $2, $3, $4, $5, $6, 'not_affected', 'm52 source draft',
			'[{"kind":"m52_fixture","source":"test"}]'::jsonb, 'approved')`,
		id, f.TenantID, f.ProjectID, f.ComponentID, f.VulnID, f.CVEID)
}

func m52SeedCRAReport(t *testing.T, migDB *sql.DB, f m52Fixture) uuid.UUID {
	t.Helper()
	id := uuid.New()
	// The report_type / lang wire values come from the cra package's
	// constants rather than string literals. That is the discipline the
	// F341 registry-parity census asks for, and it keeps this file out of
	// the census's hand-maintained file list.
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id, cve_id,
			report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4, $5, $6, $7, 'm52 fixture',
			'[{"kind":"m52_fixture"}]'::jsonb)`,
		id, f.TenantID, f.ProjectID, f.VulnID, f.CVEID,
		string(cra.ReportTypeEarlyWarning), string(cra.LangEN))
	return id
}

func m52SeedVEXDraftRow(t *testing.T, migDB *sql.DB, f m52Fixture) uuid.UUID {
	t.Helper()
	id := uuid.New()
	m52AsTenant(t, migDB, f.TenantID, `
		INSERT INTO vex_drafts (
			id, tenant_id, project_id, component_id, vulnerability_id, cve_id,
			state, detail, evidence, decision
		) VALUES ($1, $2, $3, $4, $5, $6, 'under_investigation', 'm52 fixture',
			'[{"kind":"m52_fixture","source":"test"}]'::jsonb, 'pending')`,
		id, f.TenantID, f.ProjectID, f.ComponentID, f.VulnID, f.CVEID)
	return id
}

// ---------------------------------------------------------------------------
// Wiring — mirrors cmd/server/main.go, with the TxManager left injectable so
// each drive can run its own negative control.
// ---------------------------------------------------------------------------

func m52TriageHandler(t *testing.T, appDB *sql.DB, txm triage.TxManager) *VexDraftsHandler {
	return NewVexDraftsHandler(triage.NewRunner(triage.RunnerConfig{
		Drafts:                   repository.NewVEXDraftsRepository(appDB),
		Advisories:               &triage.AdvisoryExcerptsAdapter{Repo: repository.NewAdvisoryExcerptsRepository(appDB)},
		Reachability:             &triage.ReachabilityAdapter{Repo: repository.NewReachabilityResultsRepository(appDB)},
		LLMCalls:                 &triage.LLMCallsAdapter{Repo: repository.NewLLMCallsRepository(appDB)},
		Audit:                    repository.NewAuditRepository(appDB),
		ComponentVulnerabilities: repository.NewComponentRepository(appDB),
		VulnerabilityCVE:         repository.NewVulnerabilityRepository(appDB),
		Provider:                 &llm.DisabledProvider{Reason: "M52 integration test"},
		ProviderResolver:         m52ProviderResolver(t, appDB),
		TxManager:                txm,
	}))
}

func m52CRAHandler(t *testing.T, appDB *sql.DB, txm cra.TxManager) *CRAReportsHandler {
	reports := repository.NewCRAReportsRepository(appDB)
	return NewCRAReportsHandler(
		cra.NewRunner(cra.RunnerConfig{
			VEXDrafts:           repository.NewVEXDraftsRepository(appDB),
			AdvisoryExcerpts:    repository.NewAdvisoryExcerptsRepository(appDB),
			ReachabilityResults: repository.NewReachabilityResultsRepository(appDB),
			CRAReports:          reports,
			LLMCalls:            repository.NewLLMCallsRepository(appDB),
			VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
			Audit:               repository.NewAuditRepository(appDB),
			Provider:            &llm.DisabledProvider{Reason: "M52 integration test"},
			ProviderResolver:    m52ProviderResolver(t, appDB),
			TxManager:           txm,
		}),
		reports,
		repository.NewAuditRepository(appDB),
		repository.NewCRASubmissionsRepository(appDB),
	)
}

func m52PublicLinkHandler(appDB *sql.DB) *PublicLinkHandler {
	return NewPublicLinkHandler(service.NewPublicLinkService(appDB,
		repository.NewPublicLinkRepository(appDB),
		repository.NewProjectRepository(appDB),
		repository.NewSbomRepository(appDB),
		repository.NewComponentRepository(appDB)))
}

// m52Call drives one handler through a real echo context with the tenant
// context the auth middleware would have populated.
func m52Call(t *testing.T, h echo.HandlerFunc, method, target string,
	tenantID, userID uuid.UUID, params map[string]string, body string) (int, string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	names := make([]string, 0, len(params))
	values := make([]string, 0, len(params))
	for k, v := range params {
		names = append(names, k)
		values = append(values, v)
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	if tenantID != uuid.Nil {
		c.Set(appmw.ContextKeyTenantID, tenantID)
		c.Set(appmw.ContextKeyUserID, userID)
		c.Set(appmw.ContextKeyRole, model.RoleAdmin)
	}
	if err := h(c); err != nil {
		t.Fatalf("handler returned a transport error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

// m52IsUnboundGUCError reports whether err is the failure an unbound RLS read
// produces on a poisoned connection: `invalid input syntax for type uuid: ""`
// (SQLSTATE 22P02), raised when the policy casts the empty-string placeholder.
func m52IsUnboundGUCError(err error) bool {
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		return false
	}
	// 22P02 is the cast of the empty-string placeholder on a READ; 42501 is
	// what a policy raises when it refuses a WRITE instead of casting.
	return pqErr.Code == "22P02" || pqErr.Code == "42501"
}

// ---------------------------------------------------------------------------
// The drives
// ---------------------------------------------------------------------------

// TestM52ClerkTenantCreateBindsOnAPoisonedConnection covers
// POST /api/webhooks/clerk.
//
// The webhook itself issues no set_config, and four of the five tables it
// reaches need none. The fifth does: TenantRepository.Create writes a default
// `scan_settings` row for every new tenant, and migration 048 gave that table
// the ENABLE+FORCE+policy triple. Create binds the new tenant's id between the
// two INSERTs (F187), which is what this drives — against the pooled
// connection state that turns a missing binding into a refusal.
//
// The route reaches Create from organization.created and from the create
// branch of organizationMembership.created.
func TestM52ClerkTenantCreateBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	repo := repository.NewTenantRepository(appDB)
	id := uuid.New()
	tag := "m52-clerk-" + id.String()
	now := time.Now().UTC()
	tenant := &model.Tenant{
		ID: id, ClerkOrgID: tag, Name: "m52 clerk", Slug: tag,
		Plan: "free", CreatedAt: now, UpdatedAt: now,
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup tenant %s: %v", id, err)
		}
	})

	if err := repo.Create(context.Background(), tenant); err != nil {
		t.Fatalf("TenantRepository.Create failed on a poisoned connection: %v\n"+
			"POST /api/webhooks/clerk is classified TenantBindingBindsItself on the "+
			"strength of the set_config Create issues before its scan_settings INSERT. "+
			"If that binding is gone, every organization.created delivery answers 500 "+
			"and the tenant is never provisioned.", err)
	}

	// The count itself needs the GUC: scan_settings is FORCE ROW LEVEL
	// SECURITY, which applies to the owning migrator role too.
	n := m52CountRows(t, migDB, id, `SELECT count(*) FROM scan_settings WHERE tenant_id = $1`, id)
	if n != 1 {
		t.Errorf("scan_settings rows for the new tenant = %d, want 1 — Create returned nil "+
			"without writing the RLS-protected row the binding exists for", n)
	}

	// --- negative control: the same two INSERTs with no binding between them.
	t.Run("negative control: without the set_config the scan_settings INSERT is refused", func(t *testing.T) {
		other := uuid.New()
		otherTag := "m52-clerk-nc-" + other.String()
		t.Cleanup(func() {
			if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, other); err != nil {
				t.Errorf("cleanup control tenant %s: %v", other, err)
			}
		})
		tx, err := appDB.Begin()
		if err != nil {
			t.Fatalf("begin control tx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`
			INSERT INTO tenants (id, clerk_org_id, name, slug, plan, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'free', NOW(), NOW())`,
			other, otherTag, "m52 clerk nc", otherTag); err != nil {
			t.Fatalf("control: tenants INSERT should succeed (the table has no RLS): %v", err)
		}
		_, err = tx.Exec(`
			INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour,
			                           notify_critical, notify_high, next_scan_at)
			VALUES (uuid_generate_v4(), $1, true, 'daily', 6, true, true, NOW())`, other)
		if err == nil {
			t.Fatal("control: the scan_settings INSERT succeeded with no tenant bound. " +
				"scan_settings is supposed to be FORCE ROW LEVEL SECURITY (migration 048); " +
				"if it is not, TenantRepository.Create's binding is not load-bearing and " +
				"the positive case above proves nothing.")
		}
		t.Logf("control observed: %v", err)
	})
}

// TestM52PublicGetBindsOnAPoisonedConnection covers GET /api/v1/public/:token.
func TestM52PublicGetBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "publicget")
	token := m52SeedPublicLink(t, migDB, f)

	h := m52PublicLinkHandler(appDB)
	code, body := m52Call(t, h.PublicGet, http.MethodGet, "/api/v1/public/"+token,
		uuid.Nil, uuid.Nil, map[string]string{"token": token}, "")
	if code != http.StatusOK {
		t.Fatalf("PublicGet = %d %s, want 200.\nThe anonymous share route carries no "+
			"TenantTx; PublicLinkService.runWithTenantTx is the only thing binding the "+
			"tenant for the projects/sboms/components reads. A 403 here is what an "+
			"unbound read looks like from outside (the handler folds every load failure "+
			"into one generic refusal).", code, body)
	}
	if !strings.Contains(body, "m52-publicget-project") {
		t.Errorf("PublicGet body does not carry the seeded project name, so the "+
			"RLS-protected read did not return the row: %s", body)
	}

	t.Run("negative control: the same projects read outside the tx fails", func(t *testing.T) {
		_, err := repository.NewProjectRepository(appDB).Get(context.Background(), f.ProjectID)
		if err == nil {
			t.Fatal("control: reading `projects` on the poisoned pool with no tenant bound " +
				"succeeded. Either the poison did not take or `projects` lost its RLS " +
				"policy; either way the positive case above proves nothing.")
		}
		if !m52IsUnboundGUCError(err) {
			t.Logf("control failed with a non-22P02 error (still a failure, still the "+
				"point): %v", err)
		} else {
			t.Logf("control observed: %v", err)
		}
	})
}

// TestM52PublicDownloadBindsOnAPoisonedConnection covers
// GET /api/v1/public/:token/download — driven separately from its twin
// because it is the path that hands over the raw SBOM bytes.
func TestM52PublicDownloadBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "publicdl")
	token := m52SeedPublicLink(t, migDB, f)

	h := m52PublicLinkHandler(appDB)
	code, body := m52Call(t, h.PublicDownload, http.MethodGet,
		"/api/v1/public/"+token+"/download", uuid.Nil, uuid.Nil, map[string]string{"token": token}, "")
	if code != http.StatusOK {
		t.Fatalf("PublicDownload = %d %s, want 200 (see PublicGet's message)", code, body)
	}
	if !strings.Contains(body, "CycloneDX") {
		t.Errorf("PublicDownload did not return the seeded SBOM bytes: %s", body)
	}

	t.Run("negative control: the same sboms read outside the tx fails", func(t *testing.T) {
		_, err := repository.NewSbomRepository(appDB).GetByID(context.Background(), f.SbomID)
		if err == nil {
			t.Fatal("control: reading `sboms` on the poisoned pool with no tenant bound " +
				"succeeded — the positive case above proves nothing.")
		}
		t.Logf("control observed: %v", err)
	})
}

// m52SeedPublicLink inserts an active, uncapped share link for the fixture.
// public_links has had no RLS since migration 030, which is what lets the
// anonymous route resolve the token at all.
func m52SeedPublicLink(t *testing.T, migDB *sql.DB, f m52Fixture) string {
	t.Helper()
	token := strings.ReplaceAll(uuid.New().String()+uuid.New().String(), "-", "")
	if _, err := migDB.Exec(`
		INSERT INTO public_links (id, tenant_id, project_id, sbom_id, token, name,
			expires_at, is_active, allowed_downloads, password_hash,
			view_count, download_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, '2099-01-01T00:00:00Z', true, NULL, NULL,
			0, 0, NOW(), NOW())`,
		uuid.New(), f.TenantID, f.ProjectID, f.SbomID, token, "m52-link"); err != nil {
		t.Fatalf("seed public link: %v", err)
	}
	return token
}

// TestM52TriageRunBindsOnAPoisonedConnection covers
// POST /api/v1/projects/:id/triage/run.
//
// The whole F19 cycle runs here: Stage 1's resolveComponentIDs joins
// `components` and `sboms` (both FORCE RLS), and Stage 3 inserts a
// `vex_drafts` row. Both go through the TxManager.
func TestM52TriageRunBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "triagerun")
	body := fmt.Sprintf(`{"vulnerability_id":%q,"cve_id":%q}`, f.VulnID, f.CVEID)

	h := m52TriageHandler(t, appDB, triage.NewDBTxManager(appDB))
	code, resp := m52Call(t, h.RunTriage, http.MethodPost,
		"/api/v1/projects/"+f.ProjectID.String()+"/triage/run",
		f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String()}, body)
	if code != http.StatusCreated {
		t.Fatalf("RunTriage = %d %s, want 201.\n/triage/run carries no TenantTx by design "+
			"(the runner must not hold a connection across the LLM call), so "+
			"triage.DBTxManager is the only thing binding the tenant for the "+
			"components/sboms reads and the vex_drafts write.", code, resp)
	}
	if n := m52CountRows(t, migDB, f.TenantID,
		`SELECT count(*) FROM vex_drafts WHERE tenant_id = $1 AND project_id = $2`,
		f.TenantID, f.ProjectID); n != 1 {
		t.Errorf("vex_drafts rows after the run = %d, want 1 — the 201 did not correspond "+
			"to a persisted draft", n)
	}

	t.Run("negative control: PassthroughTxManager binds nothing and the run fails", func(t *testing.T) {
		nc := m52TriageHandler(t, appDB, triage.PassthroughTxManager{})
		code, resp := m52Call(t, nc.RunTriage, http.MethodPost,
			"/api/v1/projects/"+f.ProjectID.String()+"/triage/run",
			f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String()}, body)
		if code < 500 {
			t.Fatalf("control: with the binding removed the run answered %d %s, want a 5xx. "+
				"If an unbound run succeeds, the DBTxManager wiring is not what makes the "+
				"positive case above work and this test measures nothing.", code, resp)
		}
		t.Logf("control observed: %d %s", code, strings.TrimSpace(resp))
	})
}

// TestM52VexDraftReanalyseBindsOnAPoisonedConnection covers
// POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse.
//
// This is the route whose fix was NOT carried across to the CRA twin. Its
// gatekeeper read of `vex_drafts` goes through triage.Runner.GetDraft
// (TxManager.RunRead) rather than straight to the repository, and that
// indirection is what this drives.
func TestM52VexDraftReanalyseBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "vexre")
	draftID := m52SeedVEXDraftRow(t, migDB, f)

	h := m52TriageHandler(t, appDB, triage.NewDBTxManager(appDB))
	code, resp := m52Call(t, h.Reanalyse, http.MethodPost,
		"/api/v1/projects/"+f.ProjectID.String()+"/vex-drafts/"+draftID.String()+"/reanalyse",
		f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String(), "draft_id": draftID.String()}, "{}")
	if code != http.StatusCreated {
		t.Fatalf("Reanalyse = %d %s, want 201. A 500 is the unbound gatekeeper read; a 404 "+
			"is the same read returning zero rows for a draft the caller owns.", code, resp)
	}
	if n := m52CountRows(t, migDB, f.TenantID,
		`SELECT count(*) FROM vex_drafts WHERE tenant_id = $1 AND project_id = $2`,
		f.TenantID, f.ProjectID); n != 2 {
		t.Errorf("vex_drafts rows after reanalyse = %d, want 2 (the source plus the fresh "+
			"draft the cycle mints)", n)
	}

	t.Run("negative control: PassthroughTxManager binds nothing and the load fails", func(t *testing.T) {
		nc := m52TriageHandler(t, appDB, triage.PassthroughTxManager{})
		code, resp := m52Call(t, nc.Reanalyse, http.MethodPost,
			"/api/v1/projects/"+f.ProjectID.String()+"/vex-drafts/"+draftID.String()+"/reanalyse",
			f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String(), "draft_id": draftID.String()}, "{}")
		if code < 400 {
			t.Fatalf("control: with the binding removed the reanalyse answered %d %s, want a "+
				"refusal (500 from the errored read, or 404 from a zero-row one)", code, resp)
		}
		t.Logf("control observed: %d %s", code, strings.TrimSpace(resp))
	})
}

// TestM52CRAReportRunBindsOnAPoisonedConnection covers
// POST /api/v1/projects/:id/cra-reports/run.
func TestM52CRAReportRunBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "crarun")
	m52SeedApprovedVEXDraft(t, migDB, f)
	body := fmt.Sprintf(
		`{"vulnerability_id":%q,"cve_id":%q,"report_type":%q,"lang":%q}`,
		f.VulnID, f.CVEID, cra.ReportTypeEarlyWarning, cra.LangEN)

	h := m52CRAHandler(t, appDB, triage.NewDBTxManager(appDB))
	code, resp := m52Call(t, h.RunReport, http.MethodPost,
		"/api/v1/projects/"+f.ProjectID.String()+"/cra-reports/run",
		f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String()}, body)
	if code != http.StatusCreated {
		t.Fatalf("RunReport = %d %s, want 201. cra.Runner shares the very same "+
			"*triage.DBTxManager as the triage runner (main.go passes triageTxManager to "+
			"both); a 5xx here means Stage 1's components/sboms join ran unbound.",
			code, resp)
	}
	if n := m52CountRows(t, migDB, f.TenantID,
		`SELECT count(*) FROM cra_reports WHERE tenant_id = $1 AND project_id = $2`,
		f.TenantID, f.ProjectID); n != 1 {
		t.Errorf("cra_reports rows after the run = %d, want 1", n)
	}

	t.Run("negative control: PassthroughTxManager binds nothing and the run fails", func(t *testing.T) {
		nc := m52CRAHandler(t, appDB, cra.PassthroughTxManager{})
		code, resp := m52Call(t, nc.RunReport, http.MethodPost,
			"/api/v1/projects/"+f.ProjectID.String()+"/cra-reports/run",
			f.TenantID, f.UserID, map[string]string{"id": f.ProjectID.String()}, body)
		if code < 400 {
			t.Fatalf("control: with the binding removed the run answered %d %s, want a refusal",
				code, resp)
		}
		t.Logf("control observed: %d %s", code, strings.TrimSpace(resp))
	})
}

// TestM52CRAReanalyseBindsOnAPoisonedConnection covers
// POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse — the route this
// whole gate exists because of.
//
// handler/m51_cra_reanalyse_tenant_binding_integration_test.go holds the
// original reproduction (three invisible reports answering a byte-identical
// 404, plus "the caller's own report reaches the runner"). This one is the
// M52-shaped complement: the full cycle against real repositories, and a
// negative control that removes the binding.
func TestM52CRAReanalyseBindsOnAPoisonedConnection(t *testing.T) {
	appURL, migURL := m52Env(t)
	migDB := m52Open(t, migURL, "sbomhub_migrator")
	appDB := m52PoisonedApp(t, appURL)

	f := m52SeedGraph(t, migDB, "crare")
	m52SeedApprovedVEXDraft(t, migDB, f)
	reportID := m52SeedCRAReport(t, migDB, f)

	h := m52CRAHandler(t, appDB, triage.NewDBTxManager(appDB))
	code, resp := m52Call(t, h.Reanalyse, http.MethodPost,
		"/api/v1/projects/"+f.ProjectID.String()+"/cra-reports/"+reportID.String()+"/reanalyse",
		f.TenantID, f.UserID,
		map[string]string{"id": f.ProjectID.String(), "report_id": reportID.String()}, "{}")
	if code != http.StatusCreated {
		t.Fatalf("Reanalyse = %d %s, want 201. This is the exact shape that shipped broken: "+
			"loadReportScoped read cra_reports straight from the repository, so the "+
			"endpoint answered 500 for every input including the caller's own report.",
			code, resp)
	}
	if n := m52CountRows(t, migDB, f.TenantID,
		`SELECT count(*) FROM cra_reports WHERE tenant_id = $1 AND project_id = $2`,
		f.TenantID, f.ProjectID); n != 2 {
		t.Errorf("cra_reports rows after reanalyse = %d, want 2 (the source plus the fresh "+
			"report the cycle mints)", n)
	}

	t.Run("negative control: PassthroughTxManager binds nothing and the load fails", func(t *testing.T) {
		nc := m52CRAHandler(t, appDB, cra.PassthroughTxManager{})
		code, resp := m52Call(t, nc.Reanalyse, http.MethodPost,
			"/api/v1/projects/"+f.ProjectID.String()+"/cra-reports/"+reportID.String()+"/reanalyse",
			f.TenantID, f.UserID,
			map[string]string{"id": f.ProjectID.String(), "report_id": reportID.String()}, "{}")
		if code < 400 {
			t.Fatalf("control: with the binding removed the reanalyse answered %d %s, want "+
				"a refusal — that refusal IS the production defect, reproduced", code, resp)
		}
		t.Logf("control observed: %d %s", code, strings.TrimSpace(resp))
	})
}

// m52CountRows runs a counting query inside a tenant-bound migrator tx.
func m52CountRows(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) int {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin count tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`,
		tenantID.String()); err != nil {
		t.Fatalf("count SET LOCAL: %v", err)
	}
	var n int
	if err := tx.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// The join between the table and these drives
// ---------------------------------------------------------------------------

// m52DrivenRoutes maps each BindsItself route to the test above that drives
// it. It is the local half of the cross-check: the middleware package can see
// that ProvedBy names an existing function, but only this package can say
// whether the function drives THIS route.
var m52DrivenRoutes = map[string]string{
	"POST /api/webhooks/clerk":                                   "TestM52ClerkTenantCreateBindsOnAPoisonedConnection",
	"GET /api/v1/public/:token":                                  "TestM52PublicGetBindsOnAPoisonedConnection",
	"GET /api/v1/public/:token/download":                         "TestM52PublicDownloadBindsOnAPoisonedConnection",
	"POST /api/v1/projects/:id/triage/run":                       "TestM52TriageRunBindsOnAPoisonedConnection",
	"POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse":   "TestM52VexDraftReanalyseBindsOnAPoisonedConnection",
	"POST /api/v1/projects/:id/cra-reports/run":                  "TestM52CRAReportRunBindsOnAPoisonedConnection",
	"POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse": "TestM52CRAReanalyseBindsOnAPoisonedConnection",
}

// TestM52EveryBindsItselfRouteIsDriven is what stops the classification from
// being fail-open with only a procedural guard.
//
// Without it, adding a route to noTenantTxRouteBinding as BindsItself and
// pointing ProvedBy at any existing test name would satisfy every check in the
// middleware package while nothing ever drove the new route. With it, the new
// route has to be run against a live database before the suite is green.
func TestM52EveryBindsItselfRouteIsDriven(t *testing.T) {
	table := appmw.NoTenantTxRouteBindings()

	for key, rule := range table {
		if rule.Kind != appmw.TenantBindingBindsItself {
			continue
		}
		driver, ok := m52DrivenRoutes[key]
		if !ok {
			t.Errorf("%s is classified TenantBindingBindsItself but no test in this file "+
				"drives it. Add one — a drive on a poisoned connection plus a negative "+
				"control — and register it in m52DrivenRoutes. A BindsItself rule with no "+
				"drive is the comment that was already in main.go when /reanalyse shipped "+
				"broken.", key)
			continue
		}
		if driver != rule.ProvedBy {
			t.Errorf("%s: the table says ProvedBy %q, this file drives it with %q. One of "+
				"the two is stale.", key, rule.ProvedBy, driver)
		}
	}

	for key := range m52DrivenRoutes {
		rule, ok := table[key]
		if !ok {
			t.Errorf("m52DrivenRoutes drives %q, which middleware.noTenantTxRouteBinding no "+
				"longer classifies. Drop the drive or restore the classification.", key)
			continue
		}
		if rule.Kind != appmw.TenantBindingBindsItself {
			t.Errorf("m52DrivenRoutes drives %q, which is now classified %q rather than "+
				"BindsItself.", key, rule.Kind)
		}
	}
}

// TestM52TableIsNotSilentlyEmpty guards the two sweeps above against a table
// that has been emptied: every assertion in both is a range over it.
func TestM52TableIsNotSilentlyEmpty(t *testing.T) {
	if n := len(appmw.NoTenantTxRouteBindings()); n < 5 {
		t.Fatalf("middleware.NoTenantTxRouteBindings() has %d entries; main.go has had at "+
			"least the two provider webhooks, /health and the two share-link routes for "+
			"the whole life of this gate. A table this small means the sweeps are "+
			"asserting nothing.", n)
	}
	if n := len(m52DrivenRoutes); n == 0 {
		t.Fatal("m52DrivenRoutes is empty, so TestM52EveryBindsItselfRouteIsDriven's second " +
			"loop asserts nothing and its first loop would report every route as undriven " +
			"— which is loud, but the emptiness itself should be caught here.")
	}
}
