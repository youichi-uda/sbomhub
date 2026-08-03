//go:build integration

// Package handler — POST /projects/:id/cra-reports/:report_id/reanalyse must
// answer 404 for a report it cannot see, exactly like every other route that
// shares loadReportScoped.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'CRAReanalyseTenantBinding' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # WHAT THIS PINS DOWN
//
// /reanalyse is one of the four F19 routes registered WITHOUT appmw.TenantTx
// (cmd/server/main.go) because the drafting cycle must not hold a Postgres
// transaction across the LLM call. Its gatekeeper — loadReportScoped —
// nevertheless read cra_reports through the repository's ctx-less fallback,
// i.e. on a pooled connection with no `app.current_tenant_id` bound.
// cra_reports is FORCE ROW LEVEL SECURITY (migration 038) and its policy
// predicate is
//
//	tenant_id = current_setting('app.current_tenant_id', true)::UUID
//
// which behaves in two different ways on an unbound connection:
//
//   - the GUC was NEVER set on that backend  → current_setting returns NULL,
//     the predicate is NULL, the read returns ZERO rows. Every report, valid
//     or not, answers a FALSE 404.
//   - the GUC was set once by an earlier `SET LOCAL` (any TenantTx request
//     that borrowed the same pooled connection) → after that transaction ends
//     the placeholder reverts to the EMPTY STRING, so the UUID cast receives
//     an empty string and raises `invalid input syntax for type uuid: ""`.
//     The read errors
//     and the endpoint answers 500 — for a valid report as much as for an
//     unallocated id.
//
// Measured on the live schema as sbomhub_app (2026-08-04): a running server
// hits the second branch on every request, because the read/decide/awareness/
// submissions routes all run TenantTx over the same pool. /reanalyse was
// therefore 500 for EVERY input, and 500 is neither the M47 W1 "unknown and
// not-yours are indistinguishable" contract nor a working endpoint.
//
// The three "invisible" cases below assert 404 with a BYTE-IDENTICAL body;
// the fourth asserts the opposite direction — a report the caller DOES own is
// admitted (the runner is reached) rather than silently swallowed by an
// unbound-GUC zero-row read. Without that fourth case a fix that merely
// remapped the storage error to 404 would look green while the endpoint
// stayed inert.
package handler

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/cra"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// craReanalyseEnv mirrors m46b1HandlerEnv: both URLs or skip.
func craReanalyseEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("cra reanalyse tenant-binding integration test requires DATABASE_URL (sbomhub_app) " +
			"and MIGRATE_DATABASE_URL (sbomhub_migrator). Run postgres, source the .env values, " +
			"then re-run with -tags=integration.")
	}
	return appURL, migURL
}

func craReanalyseOpen(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open %s failed: %v -- skipping", url, err)
		return nil
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("ping failed: %v -- skipping (is postgres up?)", err)
		return nil
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// craReanalyseSeedTenant inserts one tenant and registers its deletion.
func craReanalyseSeedTenant(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(`
		INSERT INTO tenants (id, clerk_org_id, name, slug, plan)
		VALUES ($1, $2, $3, $4, 'free')`,
		id, "cra-reanalyse-"+label+"-"+id.String(),
		"cra-reanalyse-"+label, "cra-reanalyse-"+label+"-"+id.String()[:8]); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, id); err != nil {
			t.Errorf("cleanup tenant %s: %v", id, err)
		}
	})
	return id
}

// craReanalyseSeedReport inserts one cra_reports row inside a tenant-bound tx
// (the table is FORCE RLS, so even the owning migrator role needs the GUC).
func craReanalyseSeedReport(t *testing.T, db *sql.DB, tenantID, projectID uuid.UUID, cveID string) uuid.UUID {
	t.Helper()
	reportID := uuid.New()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin seed tx: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO cra_reports (
			id, tenant_id, project_id, vulnerability_id,
			cve_id, report_type, lang, draft_text, evidence
		) VALUES ($1, $2, $3, $4, $5, 'early_warning', 'en', 'reanalyse fixture',
			'[{"kind":"vex_draft"}]'::jsonb)`,
		reportID, tenantID, projectID, uuid.New(), cveID); err != nil {
		_ = tx.Rollback()
		t.Fatalf("seed cra_reports: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed tx: %v", err)
	}
	t.Cleanup(func() {
		// FORCE RLS applies to the owning role too, and this connection's
		// placeholder GUC is back to '' after the seed tx — so the delete
		// needs its own tenant-bound tx, exactly like the insert.
		ctx := context.Background()
		dtx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Errorf("cleanup cra_report %s: begin: %v", reportID, err)
			return
		}
		if _, err := dtx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			_ = dtx.Rollback()
			t.Errorf("cleanup cra_report %s: SET LOCAL: %v", reportID, err)
			return
		}
		if _, err := dtx.ExecContext(ctx, `DELETE FROM cra_reports WHERE id = $1`, reportID); err != nil {
			_ = dtx.Rollback()
			t.Errorf("cleanup cra_report %s: %v", reportID, err)
			return
		}
		if err := dtx.Commit(); err != nil {
			t.Errorf("cleanup cra_report %s: commit: %v", reportID, err)
		}
	})
	return reportID
}

// craReanalyseVulnStub stands in for repository.VulnerabilityRepository's
// GetCVEIDByIDInProject. It records whether the RUNNER was reached at all,
// which is how the "own report is admitted" case is judged without standing
// up an LLM: sql.ErrNoRows is the M47 W1 sentinel the runner maps to
// ErrVulnerabilityNotInProject → 404 {"error":"cra report target not found"},
// a body distinct from the gatekeeper's {"error":"cra report not found"}.
type craReanalyseVulnStub struct{ calls int }

func (s *craReanalyseVulnStub) GetCVEIDByIDInProject(_ context.Context, _, _, _ uuid.UUID) (string, error) {
	s.calls++
	return "", sql.ErrNoRows
}

// poisonTenantGUC reproduces what a live server's connection pool does to
// itself: one committed transaction that ran `SET LOCAL app.current_tenant_id`
// leaves the placeholder GUC at the EMPTY STRING on that backend. With
// MaxOpenConns(1) the connection the handler later borrows is the same one.
func poisonTenantGUC(t *testing.T, appDB *sql.DB, tenantID uuid.UUID) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin poison tx: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("poison SET LOCAL: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit poison tx: %v", err)
	}

	// Assert the precondition rather than assuming it: the test is only
	// meaningful if the pooled connection really is in the ''-not-NULL state.
	var isNull bool
	var val sql.NullString
	if err := appDB.QueryRow(
		`SELECT current_setting('app.current_tenant_id', true) IS NULL,
		        current_setting('app.current_tenant_id', true)`).Scan(&isNull, &val); err != nil {
		t.Fatalf("read GUC state: %v", err)
	}
	if isNull || val.String != "" {
		t.Fatalf("precondition not met: app.current_tenant_id is (null=%v, value=%q), "+
			"want a non-NULL empty string — the pooled connection was not poisoned, "+
			"so this test cannot observe the 500", isNull, val.String)
	}
}

func TestCRAReanalyseTenantBinding_UnseenReportIs404NotServerError(t *testing.T) {
	appURL, migURL := craReanalyseEnv(t)
	migDB := craReanalyseOpen(t, migURL)
	appDB := craReanalyseOpen(t, appURL)

	// One connection only: the handler must borrow the very backend the
	// poison step below leaves in the '' state.
	appDB.SetMaxOpenConns(1)
	appDB.SetMaxIdleConns(1)

	tenant := craReanalyseSeedTenant(t, migDB, "own")
	foreignTenant := craReanalyseSeedTenant(t, migDB, "foreign")

	projectOwn := uuid.New()
	projectSibling := uuid.New()
	projectForeign := uuid.New()

	ownReport := craReanalyseSeedReport(t, migDB, tenant, projectOwn, "CVE-2099-0001")
	siblingReport := craReanalyseSeedReport(t, migDB, tenant, projectSibling, "CVE-2099-0002")
	foreignReport := craReanalyseSeedReport(t, migDB, foreignTenant, projectForeign, "CVE-2099-0003")
	unallocated := uuid.New()

	poisonTenantGUC(t, appDB, uuid.New())

	reportsRepo := repository.NewCRAReportsRepository(appDB)
	vulnStub := &craReanalyseVulnStub{}
	runner := cra.NewRunner(cra.RunnerConfig{
		VEXDrafts:           repository.NewVEXDraftsRepository(appDB),
		AdvisoryExcerpts:    repository.NewAdvisoryExcerptsRepository(appDB),
		ReachabilityResults: repository.NewReachabilityResultsRepository(appDB),
		CRAReports:          reportsRepo,
		LLMCalls:            repository.NewLLMCallsRepository(appDB),
		VulnerabilityCVE:    vulnStub,
		Audit:               repository.NewAuditRepository(appDB),
		Provider:            &llm.DisabledProvider{Reason: "integration test"},
		// The production wiring (cmd/server/main.go) shares this exact
		// TxManager between the triage and CRA runners; it is what binds
		// app.current_tenant_id when no ambient TenantTx exists.
		TxManager: triage.NewDBTxManager(appDB),
	})
	h := NewCRAReportsHandler(runner, reportsRepo,
		repository.NewAuditRepository(appDB),
		repository.NewCRASubmissionsRepository(appDB))

	call := func(t *testing.T, reportID uuid.UUID) (int, string) {
		t.Helper()
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/projects/"+projectOwn.String()+"/cra-reports/"+reportID.String()+"/reanalyse",
			strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id", "report_id")
		c.SetParamValues(projectOwn.String(), reportID.String())
		c.Set(middleware.ContextKeyTenantID, tenant)
		c.Set(middleware.ContextKeyUserID, uuid.New())
		c.Set(middleware.ContextKeyRole, model.RoleAdmin)
		if err := h.Reanalyse(c); err != nil {
			t.Fatalf("Reanalyse returned a transport error: %v", err)
		}
		return rec.Code, strings.TrimRight(rec.Body.String(), "\n")
	}

	// --- The three inputs the caller must not be able to tell apart. -------
	invisible := []struct {
		name     string
		reportID uuid.UUID
	}{
		{"unallocated report id", unallocated},
		{"report in a sibling project of the same tenant", siblingReport},
		{"real report belonging to another tenant", foreignReport},
	}
	bodies := make(map[string]string, len(invisible))
	for _, tc := range invisible {
		code, body := call(t, tc.reportID)
		if code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 (body=%s)", tc.name, code, body)
		}
		bodies[tc.name] = body
	}
	if vulnStub.calls != 0 {
		t.Errorf("the gatekeeper let %d invisible report(s) through to the runner; want 0", vulnStub.calls)
	}
	// M47 W1: byte identity, not merely equal status codes.
	var first string
	for _, tc := range invisible {
		if first == "" {
			first = bodies[tc.name]
			continue
		}
		if bodies[tc.name] != first {
			t.Errorf("refusal bodies differ — the endpoint is an existence oracle:\n  %q\n  %q",
				first, bodies[tc.name])
		}
	}

	// --- And the direction a status-only fix would break: a report the -----
	// caller DOES own must be admitted through the same unbound connection.
	code, body := call(t, ownReport)
	if vulnStub.calls != 1 {
		t.Fatalf("own report: runner reached %d time(s), want 1 — the gatekeeper could not see a "+
			"report the caller owns (status=%d body=%s)", vulnStub.calls, code, body)
	}
	if body == first {
		t.Errorf("own report produced the same body as an invisible one (%q) — the load did not "+
			"succeed, it was refused", body)
	}
	if got := fmt.Sprintf("%d", code); got != "404" {
		// 404 here comes from the STUB (ErrVulnerabilityNotInProject), not
		// from the gatekeeper; assert it so an unrelated change to the stub
		// contract does not silently weaken the check above.
		t.Errorf("own report: status = %s, want 404 from the vulnerability stub (body=%s)", got, body)
	}
}
