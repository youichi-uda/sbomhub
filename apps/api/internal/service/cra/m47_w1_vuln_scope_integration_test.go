//go:build integration

// Package cra — M47 W1: the CRA report runner must verify that the target
// vulnerability actually belongs to the (tenant, project) it is drafting for.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47W1CRA' ./internal/service/cra
//
// Why this needs a live database: the whole point of the fix is which SQL
// the runner issues. Pre-fix it called the UNSCOPED
// VulnerabilityRepository.GetCVEIDByID (`SELECT cve_id FROM vulnerabilities
// WHERE id = $1`) against the GLOBAL, RLS-free NVD cache — so the only thing
// it proved was that the UUID exists somewhere in the installation.
// triage.Runner never had this hole because resolveComponentIDs establishes
// (tenant, project, vulnerability) membership one step earlier; cra.Runner
// had no such predecessor, and F12's ErrCVEIDMismatch only caught
// MISMATCHED pairs, never an out-of-scope pair that agrees with itself
// (cve_id is public data, so supplying the matching one is trivial).
//
// The runner is wired with the REAL *repository.VulnerabilityRepository and
// everything else from the existing unit-test harness, inside a tenant-bound
// transaction — which is what makes the RLS half of the belt-and-braces
// observable.
package cra

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type m47CRAFixture struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
	// linked is affected by the project (component_vulnerabilities row);
	// unlinked exists in the global cache but touches nothing of this tenant.
	linkedVuln     uuid.UUID
	linkedCVE      string
	unlinkedVuln   uuid.UUID
	unlinkedCVE    string
	componentID    uuid.UUID
	sbomIDForDebug uuid.UUID
}

func m47CRAEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL, migURL = os.Getenv("DATABASE_URL"), os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("cra vuln-scope integration test requires DATABASE_URL and MIGRATE_DATABASE_URL")
	}
	return appURL, migURL
}

func m47CRAOpen(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) - skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func m47CRASeed(t *testing.T, migDB *sql.DB, label string) m47CRAFixture {
	t.Helper()
	f := m47CRAFixture{tenantID: uuid.New()}
	org := "m47cra-" + label + "-" + f.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		f.tenantID, org, "m47cra "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := f.tenantID
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

	f.projectID = uuid.New()
	f.sbomIDForDebug = uuid.New()
	f.componentID = uuid.New()
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, f.projectID, f.tenantID, "m47cra-"+label)
	exec(`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
	      VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{}'::jsonb, NOW())`, f.sbomIDForDebug, f.tenantID, f.projectID)
	exec(`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
	      VALUES ($1, $2, $3, 'libcra', '1.0', 'library', 'pkg:generic/libcra@1.0', NOW())`,
		f.componentID, f.tenantID, f.sbomIDForDebug)

	sfx := uuid.New().ID() % 10000000
	f.linkedCVE = fmt.Sprintf("CVE-2092-%07d", sfx)
	f.unlinkedCVE = fmt.Sprintf("CVE-2091-%07d", sfx)
	f.linkedVuln, f.unlinkedVuln = uuid.New(), uuid.New()
	for _, v := range []struct {
		id  uuid.UUID
		cve string
	}{{f.linkedVuln, f.linkedCVE}, {f.unlinkedVuln, f.unlinkedCVE}} {
		if _, err := migDB.Exec(`
			INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
			VALUES ($1, $2, 'm47 cra vuln', 'HIGH', 7.5)`, v.id, v.cve); err != nil {
			t.Fatalf("seed vulnerability %s: %v", v.cve, err)
		}
		id := v.id
		t.Cleanup(func() {
			if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, id); err != nil {
				t.Errorf("C27 cleanup: delete vulnerability %s: %v", id, err)
			}
		})
	}
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
		f.componentID, f.linkedVuln); err != nil {
		t.Fatalf("link component to vulnerability: %v", err)
	}
	return f
}

// m47CRARunTx executes fn inside a tenant-bound app-role transaction. The
// runner's default PassthroughTxManager forwards this ctx straight through,
// so the repository picks up the tx (and therefore the GUC that the FORCE
// RLS policies on components / sboms depend on).
func m47CRARunTx(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	fn(database.WithTx(context.Background(), tx))
}

// m47CRARunInput builds a RunInput whose every non-scope field is already
// known-good, so the only thing under test is the (tenant, project,
// vulnerability) binding.
func m47CRARunInput(h *testHarness, f m47CRAFixture, vulnID uuid.UUID, cveID string) RunInput {
	draftID := h.sourceDraft.ID
	return RunInput{
		TenantID:         f.tenantID,
		ProjectID:        f.projectID,
		VulnerabilityID:  vulnID,
		CVEID:            cveID,
		SourceVEXDraftID: &draftID,
		ReportType:       ReportTypeEarlyWarning,
		Lang:             LangEN,
		ProductName:      "m47",
		ProductVersion:   "1.0",
		VendorName:       "m47 vendor",
		AwarenessTime:    "2026-06-25T00:00:00Z",
	}
}

// TestM47W1CRARunner_OutOfProjectVulnerabilityIs404NoWrites is the
// reproduction: `unlinkedVuln` exists in the global cache, the caller
// supplies its own (correct, public) cve_id so F12 is satisfied, and it
// touches nothing of the caller's project. Pre-fix this drafted a real CRA
// report. Post-fix it is ErrVulnerabilityNotInProject (handler: 404), and
// nothing is written.
func TestM47W1CRARunner_OutOfProjectVulnerabilityIs404NoWrites(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	f := m47CRASeed(t, migDB, "scope")
	h := newTestHarness(t)

	// Re-point the harness's fixtures at the live tenant/project/vuln so the
	// source VEX draft resolves, and swap in the REAL repository as the CVE
	// lookup — that swap is the whole subject of this test.
	h.sourceDraft.TenantID = f.tenantID
	h.sourceDraft.ProjectID = f.projectID
	h.sourceDraft.VulnerabilityID = f.unlinkedVuln
	h.sourceDraft.CVEID = f.unlinkedCVE
	h.drafts.byID[h.sourceDraft.ID] = h.sourceDraft

	runner := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            h.llmCalls,
		VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
		Audit:               h.audit,
		Provider:            h.provider,
		GeneratedBy:         "SBOMHub/test",
	})

	var runErr error
	m47CRARunTx(t, appDB, f.tenantID, func(ctx context.Context) {
		_, runErr = runner.Run(ctx, m47CRARunInput(h, f, f.unlinkedVuln, f.unlinkedCVE))
	})

	if !errors.Is(runErr, ErrVulnerabilityNotInProject) {
		t.Errorf("Run for a vulnerability outside the project: err = %v, want ErrVulnerabilityNotInProject "+
			"(the caller supplied the matching cve_id, so the F12 mismatch guard cannot catch this)", runErr)
	}
	if n := len(h.craReports.inserted); n != 0 {
		t.Errorf("cra_reports written for an out-of-project vulnerability = %d, want 0", n)
	}
	if n := len(h.llmCalls.records); n != 0 {
		t.Errorf("llm_calls written for an out-of-project vulnerability = %d, want 0", n)
	}
	if n := len(h.audit.entries); n != 0 {
		t.Errorf("audit rows written for an out-of-project vulnerability = %d, want 0", n)
	}
}

// TestM47W1CRARunner_ForeignTenantVulnerabilityIs404: the vulnerability IS
// linked to a component — but in another tenant's project. The membership
// join runs through the RLS-protected components / sboms tables with
// explicit tenant/project predicates, so a foreign linkage can never vouch
// for scope.
func TestM47W1CRARunner_ForeignTenantVulnerabilityIs404(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	caller := m47CRASeed(t, migDB, "caller")
	foreign := m47CRASeed(t, migDB, "foreign")
	h := newTestHarness(t)

	h.sourceDraft.TenantID = caller.tenantID
	h.sourceDraft.ProjectID = caller.projectID
	h.sourceDraft.VulnerabilityID = foreign.linkedVuln
	h.sourceDraft.CVEID = foreign.linkedCVE
	h.drafts.byID[h.sourceDraft.ID] = h.sourceDraft

	runner := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            h.llmCalls,
		VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
		Audit:               h.audit,
		Provider:            h.provider,
		GeneratedBy:         "SBOMHub/test",
	})

	var runErr error
	m47CRARunTx(t, appDB, caller.tenantID, func(ctx context.Context) {
		_, runErr = runner.Run(ctx, m47CRARunInput(h, caller, foreign.linkedVuln, foreign.linkedCVE))
	})
	if !errors.Is(runErr, ErrVulnerabilityNotInProject) {
		t.Errorf("Run for another tenant's vulnerability: err = %v, want ErrVulnerabilityNotInProject", runErr)
	}
	if n := len(h.craReports.inserted); n != 0 {
		t.Errorf("cra_reports written for a foreign tenant's vulnerability = %d, want 0", n)
	}
}

// TestM47W1CRARunner_InProjectVulnerabilityStillDrafts pins that the scoped
// lookup is a scope check and not a regression: the project's own affected
// vulnerability still produces a report.
func TestM47W1CRARunner_InProjectVulnerabilityStillDrafts(t *testing.T) {
	appURL, migURL := m47CRAEnv(t)
	migDB := m47CRAOpen(t, migURL)
	appDB := m47CRAOpen(t, appURL)

	f := m47CRASeed(t, migDB, "ok")
	h := newTestHarness(t)

	h.sourceDraft.TenantID = f.tenantID
	h.sourceDraft.ProjectID = f.projectID
	h.sourceDraft.VulnerabilityID = f.linkedVuln
	h.sourceDraft.CVEID = f.linkedCVE
	h.drafts.byID[h.sourceDraft.ID] = h.sourceDraft

	runner := NewRunner(RunnerConfig{
		VEXDrafts:           h.drafts,
		AdvisoryExcerpts:    h.advisories,
		ReachabilityResults: h.reach,
		CRAReports:          h.craReports,
		LLMCalls:            h.llmCalls,
		VulnerabilityCVE:    repository.NewVulnerabilityRepository(appDB),
		Audit:               h.audit,
		Provider:            h.provider,
		GeneratedBy:         "SBOMHub/test",
	})

	var runErr error
	m47CRARunTx(t, appDB, f.tenantID, func(ctx context.Context) {
		_, runErr = runner.Run(ctx, m47CRARunInput(h, f, f.linkedVuln, f.linkedCVE))
	})
	if runErr != nil {
		t.Fatalf("Run for the project's OWN affected vulnerability: err = %v, want nil", runErr)
	}
	if n := len(h.craReports.inserted); n != 1 {
		t.Errorf("cra_reports written for a legitimate run = %d, want 1", n)
	}
}
