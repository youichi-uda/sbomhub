//go:build integration

// Package repository — M47 W2 integration tests for the "0 rows treated as
// success" defect class.
//
// `ExecContext` returns a nil error for an UPDATE/DELETE that matched no
// row. Every tenant-scoped mutation whose result was discarded therefore
// reported a BLOCKED cross-tenant write as a completed one — the exact
// mechanism behind the M46 cross-tenant plan escalation
// (repository/subscription.go, commit 08f98ae).
//
// These tests drive the representative member of each contract group
// against real Postgres (the mock-based unit tests cannot observe that the
// victim's row survived). Groups that share one contract get one test; the
// per-group rationale is on each test.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// writeAsTenantTx opens a tx on db, pins the tenant GUC, attaches the tx to
// ctx via database.WithTx (so repository q(ctx) routes through it), runs fn
// and COMMITs when fn succeeded. fn's error is returned verbatim so callers
// can errors.Is it; a failing fn rolls the tx back.
func writeAsTenantTx(t *testing.T, db *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context) error) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("writeAsTenantTx begin tx (tenant=%s): %v", tenantID, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenantID.String() + `'`); err != nil {
		t.Fatalf("writeAsTenantTx SET LOCAL app.current_tenant_id=%s: %v", tenantID, err)
	}
	fnErr := fn(database.WithTx(context.Background(), tx))
	if fnErr != nil {
		return fnErr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("writeAsTenantTx commit (tenant=%s): %v", tenantID, err)
	}
	committed = true
	return nil
}

// seedIntegrationUser inserts a users row (no RLS on `users`) and registers
// an error-visible cleanup. tenant_users rows for this user die with either
// parent via ON DELETE CASCADE.
func seedIntegrationUser(t *testing.T, migDB *sql.DB, label string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := migDB.Exec(
		`INSERT INTO users (id, clerk_user_id, email, name) VALUES ($1, $2, $3, $4)`,
		id, "itest-repo-user-"+id.String(), "itest+"+id.String()+"@localhost", "itest "+label,
	); err != nil {
		t.Fatalf("seed user %s: %v", label, err)
	}
	registerCleanupExec(t, migDB, "delete user "+label,
		`DELETE FROM users WHERE id = $1`, id)
	return id
}

// m47MigratorDB opens the migrator handle used by every test below. The
// app role is NOBYPASSRLS; these tables (users / tenant_users / tenants)
// carry no RLS at all (verified against pg_class), which is precisely why
// the application-layer WHERE predicate is the ONLY tenant guard and why a
// silently-0-row statement is a security defect rather than a nuisance.
func m47MigratorDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("MIGRATE_DATABASE_URL")
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	return openIntegrationDB(t, url)
}

// TestM47W2_RemoveFromTenant_CrossTenantIsNotSuccess is the headline case:
// `tenant_users` has no RLS, so `DELETE ... WHERE tenant_id = $1 AND
// user_id = $2` is the entire tenant boundary for membership removal. With
// the result discarded, removing a member of ANOTHER tenant returned nil —
// "member removed" — while the membership survived untouched.
func TestM47W2_RemoveFromTenant_CrossTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)
	ctx := context.Background()

	attacker := seedIntegrationTenant(t, migDB, "m47-remove-attacker")
	victim := seedIntegrationTenant(t, migDB, "m47-remove-victim")
	user := seedIntegrationUser(t, migDB, "m47-remove")

	if _, err := migDB.Exec(
		`INSERT INTO tenant_users (tenant_id, user_id, role) VALUES ($1, $2, 'owner')`,
		victim, user,
	); err != nil {
		t.Fatalf("seed victim membership: %v", err)
	}

	repo := NewUserRepository(migDB)

	// The attacker names the victim's user under its OWN tenant id.
	err := repo.RemoveFromTenant(ctx, attacker, user)
	if err == nil {
		t.Fatalf("RemoveFromTenant across tenants returned nil error " +
			"(0-row DELETE reported as a completed removal)")
	}
	if !errors.Is(err, ErrTenantUserNotFound) {
		t.Fatalf("RemoveFromTenant error = %v, want ErrTenantUserNotFound", err)
	}

	var role string
	if err := migDB.QueryRow(
		`SELECT role FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`,
		victim, user,
	).Scan(&role); err != nil {
		t.Fatalf("victim membership must survive the refused removal: %v", err)
	}
	if role != "owner" {
		t.Fatalf("victim role = %q, want %q", role, "owner")
	}
}

// TestM47W2_RemoveFromTenant_OwnTenantStillSucceeds pins that the guard
// only fires on a genuine 0-row statement — the legitimate removal path
// must keep returning nil.
func TestM47W2_RemoveFromTenant_OwnTenantStillSucceeds(t *testing.T) {
	migDB := m47MigratorDB(t)
	ctx := context.Background()

	tenant := seedIntegrationTenant(t, migDB, "m47-remove-ok")
	user := seedIntegrationUser(t, migDB, "m47-remove-ok")
	if _, err := migDB.Exec(
		`INSERT INTO tenant_users (tenant_id, user_id, role) VALUES ($1, $2, 'member')`,
		tenant, user,
	); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	repo := NewUserRepository(migDB)
	if err := repo.RemoveFromTenant(ctx, tenant, user); err != nil {
		t.Fatalf("RemoveFromTenant on own tenant: %v", err)
	}

	var n int
	if err := migDB.QueryRow(
		`SELECT COUNT(*) FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`,
		tenant, user,
	).Scan(&n); err != nil {
		t.Fatalf("count membership: %v", err)
	}
	if n != 0 {
		t.Fatalf("membership rows after removal = %d, want 0", n)
	}
}

// TestM47W2_UpdateRole_CrossTenantIsNotSuccess is the sibling of
// RemoveFromTenant on the same table: a role change aimed at another
// tenant's member reported success and changed nothing.
func TestM47W2_UpdateRole_CrossTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)
	ctx := context.Background()

	attacker := seedIntegrationTenant(t, migDB, "m47-role-attacker")
	victim := seedIntegrationTenant(t, migDB, "m47-role-victim")
	user := seedIntegrationUser(t, migDB, "m47-role")

	if _, err := migDB.Exec(
		`INSERT INTO tenant_users (tenant_id, user_id, role) VALUES ($1, $2, 'member')`,
		victim, user,
	); err != nil {
		t.Fatalf("seed victim membership: %v", err)
	}

	repo := NewUserRepository(migDB)

	err := repo.UpdateRole(ctx, attacker, user, model.RoleOwner)
	if err == nil {
		t.Fatalf("UpdateRole across tenants returned nil error " +
			"(0-row UPDATE reported as a completed role change)")
	}
	if !errors.Is(err, ErrTenantUserNotFound) {
		t.Fatalf("UpdateRole error = %v, want ErrTenantUserNotFound", err)
	}

	var role string
	if err := migDB.QueryRow(
		`SELECT role FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`,
		victim, user,
	).Scan(&role); err != nil {
		t.Fatalf("read victim role: %v", err)
	}
	if role != "member" {
		t.Fatalf("victim role = %q, want %q (unchanged)", role, "member")
	}
}

// TestM47W2_TenantUpdatePlan_UnknownTenantIsNotSuccess covers the
// `tenants` group (Update / UpdatePlan / Delete share one contract:
// `WHERE id = $N`, no RLS). UpdatePlan is the representative because it is
// the write the M46 escalation actually landed on.
func TestM47W2_TenantUpdatePlan_UnknownTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)
	ctx := context.Background()

	repo := NewTenantRepository(migDB)

	err := repo.UpdatePlan(ctx, uuid.New(), model.PlanEnterprise)
	if err == nil {
		t.Fatalf("UpdatePlan on a non-existent tenant returned nil error")
	}
	if !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("UpdatePlan error = %v, want ErrTenantNotFound", err)
	}

	// The legitimate path must still succeed.
	tenant := seedIntegrationTenant(t, migDB, "m47-plan")
	if err := repo.UpdatePlan(ctx, tenant, model.PlanEnterprise); err != nil {
		t.Fatalf("UpdatePlan on an existing tenant: %v", err)
	}
}

// TestM47W2_IssueTrackerConnection_CrossTenantIsNotSuccess covers the
// issue-tracker connection group (UpdateConnection / DeleteConnection /
// UpdateConnectionSyncTime). Pre-fix, DeleteConnection was
// `DELETE ... WHERE id = $1` with the result discarded: RLS blocked the
// cross-tenant row, the statement matched 0 rows, and
// `DELETE /api/v1/integrations/:id` answered 204 for a connection that
// still exists (M47 W1 carry-over).
//
// The delete runs on the APP role inside a tenant tx so migration 042's
// FORCE RLS policy is the braces the explicit tenant_id belt backs up.
func TestM47W2_IssueTrackerConnection_CrossTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)
	appDB := openIntegrationDB(t, os.Getenv("DATABASE_URL"))

	attacker := seedIntegrationTenant(t, migDB, "m47-conn-attacker")
	victim := seedIntegrationTenant(t, migDB, "m47-conn-victim")

	connID := uuid.New()
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO issue_tracker_connections
			 (id, tenant_id, tracker_type, name, base_url, auth_type, auth_token_encrypted)
			 VALUES ($1, $2, 'jira', $3, 'https://example.atlassian.net', 'api_token', 'x')`,
			connID, victim, "itest-"+connID.String(),
		); err != nil {
			t.Fatalf("seed victim connection: %v", err)
		}
	})

	repo := NewIssueTrackerRepository(appDB)

	err := writeAsTenantTx(t, appDB, attacker, func(txCtx context.Context) error {
		return repo.DeleteConnection(txCtx, attacker, connID)
	})
	if err == nil {
		t.Fatalf("DeleteConnection across tenants returned nil error " +
			"(0-row DELETE reported as a completed deletion → HTTP 204)")
	}
	if !errors.Is(err, ErrIssueTrackerConnectionNotFound) {
		t.Fatalf("DeleteConnection error = %v, want ErrIssueTrackerConnectionNotFound", err)
	}

	// issue_tracker_connections is ENABLE + FORCE RLS and the migrator role
	// is NOBYPASSRLS, so the verification read must carry the tenant GUC.
	var n int
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if err := tx.QueryRow(
			`SELECT COUNT(*) FROM issue_tracker_connections WHERE id = $1`, connID,
		).Scan(&n); err != nil {
			t.Fatalf("count connection: %v", err)
		}
	})
	if n != 1 {
		t.Fatalf("victim connection rows = %d, want 1 (must survive)", n)
	}

	// The owner's delete still works.
	if err := writeAsTenantTx(t, appDB, victim, func(txCtx context.Context) error {
		return repo.DeleteConnection(txCtx, victim, connID)
	}); err != nil {
		t.Fatalf("DeleteConnection by the owning tenant: %v", err)
	}
}

// TestM47W2_UpdateReport_CrossTenantIsNotSuccess covers generated_reports.
// service/report.go already documents the consequence in prose ("the report
// stuck at generating with the UI showing 'generating now...' forever")
// because UpdateReport discarded its result; this pins the fix and the new
// tenant_id belt at the same time.
func TestM47W2_UpdateReport_CrossTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)

	victim := seedIntegrationTenant(t, migDB, "m47-report-victim")
	attacker := seedIntegrationTenant(t, migDB, "m47-report-attacker")

	reportID := uuid.New()
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO generated_reports
			 (id, tenant_id, report_type, format, title, period_start, period_end, status)
			 VALUES ($1, $2, 'vulnerability', 'pdf', 'itest', $3, $4, 'generating')`,
			reportID, victim, time.Now().Add(-24*time.Hour), time.Now(),
		); err != nil {
			t.Fatalf("seed victim report: %v", err)
		}
	})

	repo := NewReportRepository(migDB)

	// TenantID is what the belt binds; an attacker-owned struct pointing at
	// the victim's report id must not land.
	//
	// The tenant GUC is deliberately bound to the VICTIM here, not the
	// attacker: under the victim's GUC, migration 023's FORCE RLS makes the
	// row fully VISIBLE, so RLS cannot be what refuses this statement. The
	// only thing left that can is the explicit `AND tenant_id = $10` belt
	// this wave added. Binding the attacker's GUC instead would pass even
	// if the belt were deleted (RLS alone would hide the row), which is
	// exactly the weak-test shape this arrangement avoids.
	spoofed := &model.GeneratedReport{
		ID:       reportID,
		TenantID: attacker,
		Status:   model.ReportStatusCompleted,
	}
	err := writeAsTenantTx(t, migDB, victim, func(txCtx context.Context) error {
		return repo.UpdateReport(txCtx, spoofed)
	})
	if err == nil {
		t.Fatalf("UpdateReport across tenants returned nil error")
	}
	if !errors.Is(err, ErrGeneratedReportNotFound) {
		t.Fatalf("UpdateReport error = %v, want ErrGeneratedReportNotFound", err)
	}

	// generated_reports is ENABLE + FORCE RLS and the migrator role is
	// NOBYPASSRLS, so the verification read must itself carry the tenant GUC
	// (outside one, current_setting('app.current_tenant_id') is '' and the
	// policy's ''::uuid cast errors).
	var status string
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if err := tx.QueryRow(
			`SELECT status FROM generated_reports WHERE id = $1`, reportID,
		).Scan(&status); err != nil {
			t.Fatalf("read victim report: %v", err)
		}
	})
	if status != "generating" {
		t.Fatalf("victim report status = %q, want %q (unchanged)", status, "generating")
	}
}

// TestM47W2_SSVCUpdateAssessment_CrossTenantIsNotSuccess covers the
// ssvc_assessments group. Pre-fix the UPDATE was `WHERE id = $13` — the
// route's :id project segment and the session tenant were both decorative,
// and migration 042's FORCE RLS was the sole guard. When RLS fired the
// statement matched 0 rows and returned nil, so the service reported a
// saved assessment and went on to stamp the denormalised
// vulnerabilities.ssvc_decision from it (that second write was removed in
// M47 W4; migration 062 dropped the column). The explicit
// `AND tenant_id AND project_id` belt added here mirrors the belt its
// sibling DeleteAssessment already carried.
func TestM47W2_SSVCUpdateAssessment_CrossTenantIsNotSuccess(t *testing.T) {
	migDB := m47MigratorDB(t)

	victim := seedIntegrationTenant(t, migDB, "m47-ssvc-victim")
	attacker := seedIntegrationTenant(t, migDB, "m47-ssvc-attacker")
	user := seedIntegrationUser(t, migDB, "m47-ssvc")

	// Global CVE row (no tenant column) — reaped by its own cleanup.
	vulnID := uuid.New()
	cveID := "CVE-M47W2-" + uuidHex(vulnID)[:8]
	if _, err := migDB.Exec(
		`INSERT INTO vulnerabilities (id, cve_id, description, severity, source) VALUES ($1, $2, 'itest', 'HIGH', 'NVD')`,
		vulnID, cveID,
	); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	registerCleanupExec(t, migDB, "delete m47 vulnerability",
		`DELETE FROM vulnerabilities WHERE id = $1`, vulnID)

	projectID := uuid.New()
	assessmentID := uuid.New()
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if _, err := tx.Exec(
			`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'itest m47 ssvc')`,
			projectID, victim,
		); err != nil {
			t.Fatalf("seed victim project: %v", err)
		}
		if _, err := tx.Exec(`
			INSERT INTO ssvc_assessments (
				id, project_id, tenant_id, vulnerability_id, cve_id,
				exploitation, automatable, technical_impact, mission_prevalence,
				safety_impact, decision, assessed_by, notes
			) VALUES ($1, $2, $3, $4, $5, 'none', 'no', 'partial', 'minimal', 'minimal', 'defer', $6, 'victim')`,
			assessmentID, projectID, victim, vulnID, cveID, user,
		); err != nil {
			t.Fatalf("seed victim assessment: %v", err)
		}
	})

	repo := NewSSVCRepository(migDB)

	// The attacker names the victim's assessment id but binds its own
	// tenant — the exact shape the belt now refuses.
	spoofed := &model.SSVCAssessment{
		ID:                assessmentID,
		TenantID:          attacker,
		ProjectID:         projectID,
		VulnerabilityID:   vulnID,
		CVEID:             cveID,
		Exploitation:      model.SSVCExploitationActive,
		Automatable:       model.SSVCAutomatableYes,
		TechnicalImpact:   model.SSVCTechnicalImpactTotal,
		MissionPrevalence: model.SSVCMissionPrevalenceEssential,
		SafetyImpact:      model.SSVCSafetyImpactSignificant,
		Decision:          model.SSVCDecisionImmediate,
		AssessedBy:        &user,
		Notes:             "attacker",
	}
	// Bound to the VICTIM's GUC on purpose: under it the row is visible to
	// RLS, so only the new `AND tenant_id AND project_id` belt can refuse
	// the write. See the same note in TestM47W2_UpdateReport_*.
	err := writeAsTenantTx(t, migDB, victim, func(txCtx context.Context) error {
		return repo.UpdateAssessment(txCtx, spoofed)
	})
	if err == nil {
		t.Fatalf("UpdateAssessment across tenants returned nil error")
	}
	if !errors.Is(err, ErrSSVCAssessmentNotFound) {
		t.Fatalf("UpdateAssessment error = %v, want ErrSSVCAssessmentNotFound", err)
	}

	var notes, decision string
	withTenantGUC(t, migDB, victim, func(tx *sql.Tx) {
		if err := tx.QueryRow(
			`SELECT COALESCE(notes, ''), decision::text FROM ssvc_assessments WHERE id = $1`, assessmentID,
		).Scan(&notes, &decision); err != nil {
			t.Fatalf("read victim assessment: %v", err)
		}
	})
	if notes != "victim" || decision != "defer" {
		t.Fatalf("victim assessment mutated: notes=%q decision=%q, want %q / %q",
			notes, decision, "victim", "defer")
	}

	// The owning tenant's update still lands.
	legit := *spoofed
	legit.TenantID = victim
	legit.Notes = "victim-updated"
	if err := writeAsTenantTx(t, migDB, victim, func(txCtx context.Context) error {
		return repo.UpdateAssessment(txCtx, &legit)
	}); err != nil {
		t.Fatalf("UpdateAssessment by the owning tenant: %v", err)
	}
}
