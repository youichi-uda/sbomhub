//go:build integration

// Package repository — M46 Track A wave 3 nullable-column scan regression
// tests for projects / sboms / audit_logs / compliance_checklist_responses /
// license_policies / users / subscriptions / subscription_events /
// sbom_visualization_settings / notification_logs / analytics reads.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'Wave3' ./internal/repository
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's
// test cache.
//
// What these tests pin down (same class as
// vulnerability_null_scan_integration_test.go / f97c7fa):
//
// The schema leaves projects.description / created_at / updated_at,
// sboms.version / created_at, audit_logs.user_agent,
// compliance_checklist_responses.updated_by / updated_at,
// license_policies.reason, users.name / avatar_url,
// subscriptions.ls_product_id, subscription_events.ls_event_id /
// previous_status / new_status / previous_plan / new_plan and every
// sbom_visualization_settings classification column nullable, while the
// models scan them into NULL-intolerant Go types. One NULL row used to
// abort the whole read with `converting NULL to <type> is unsupported`.
// projects.description is NOT hypothetical: 514/556 rows on the dev DB were
// NULL at fix time (measured 2026-07-26), so ProjectRepository.Get /
// ListByTenant 500'd for most real projects.
//
// notification_logs is a separate, worse class: GetLogs / CreateLog
// referenced a `payload` column that does not exist (the real column is
// `message`, plus a NOT NULL `notification_type` the INSERT never set), so
// both were dead queries failing with `column "payload" does not exist`
// on every call.
//
// Fix contract (wave 3, mirroring f97c7fa):
//   - nullable string columns → COALESCE(col, ”) in the SELECT; columns
//     with a semantic DDL default keep that default instead
//     (sbom_visualization_settings.* — read-time application of the DDL
//     default, 0 NULL rows measured).
//   - nullable timestamps with DDL default now() and 0 measured NULL rows →
//     COALESCE(col, NOW()) (components.created_at precedent).
//   - notification_logs reads/writes target the real columns
//     (message ↔ model Payload, notification_type supplied on INSERT).
package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// TestWave3ProjectSbomReads_NullableColumnScan seeds an all-NULL and a
// fully-populated (project, sbom) pair and drives every project.go /
// sbom.go read that used to scan the nullable columns directly.
func TestWave3ProjectSbomReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "projects") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3proj")

	nullProjID := uuid.New()
	popProjID := uuid.New()
	nullSbomID := uuid.New()
	popSbomID := uuid.New()

	// NULL project: description / created_at / updated_at all forced NULL
	// (created_at / updated_at carry DDL default now(), so they must be
	// forced).
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name, description, created_at, updated_at)
		VALUES ($1, $2, 'wave3-null-project', NULL, NULL, NULL)
	`, nullProjID, tenant); err != nil {
		t.Fatalf("seed NULL project: %v", err)
	}
	// Populated project: distinct value per column so a SELECT/Scan order
	// regression lands a value in the wrong field.
	popCreatedAt := time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)
	popUpdatedAt := time.Date(2026, 7, 2, 13, 45, 0, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name, description, created_at, updated_at)
		VALUES ($1, $2, 'wave3-pop-project', 'pop description', $3, $4)
	`, popProjID, tenant, popCreatedAt, popUpdatedAt); err != nil {
		t.Fatalf("seed populated project: %v", err)
	}

	// NULL sbom under the populated project: version / created_at NULL.
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format, version, created_at)
		VALUES ($1, $2, $3, 'cyclonedx', NULL, NULL)
	`, nullSbomID, popProjID, tenant); err != nil {
		t.Fatalf("seed NULL sbom: %v", err)
	}
	popSbomCreatedAt := time.Date(2026, 6, 5, 6, 7, 8, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sboms (id, project_id, tenant_id, format, version, raw_data, created_at)
		VALUES ($1, $2, $3, 'spdx', '1.5', '{"pop":true}', $4)
	`, popSbomID, popProjID, tenant, popSbomCreatedAt); err != nil {
		t.Fatalf("seed populated sbom: %v", err)
	}

	projRepo := NewProjectRepository(appDB)
	sbomRepo := NewSbomRepository(appDB)

	assertNullProj := func(t *testing.T, p *model.Project, via string) {
		t.Helper()
		if p.Description != "" {
			t.Errorf("%s: Description = %q, want \"\" for NULL", via, p.Description)
		}
		if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
			t.Errorf("%s: CreatedAt/UpdatedAt zero; COALESCE(col, NOW()) should yield real timestamps", via)
		}
	}
	assertPopProj := func(t *testing.T, p *model.Project, via string) {
		t.Helper()
		if p.Name != "wave3-pop-project" || p.Description != "pop description" {
			t.Errorf("%s: populated project round-trip mismatch: name=%q description=%q",
				via, p.Name, p.Description)
		}
		if !p.CreatedAt.UTC().Equal(popCreatedAt) || !p.UpdatedAt.UTC().Equal(popUpdatedAt) {
			t.Errorf("%s: CreatedAt/UpdatedAt = %v/%v, want %v/%v",
				via, p.CreatedAt, p.UpdatedAt, popCreatedAt, popUpdatedAt)
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- ProjectRepository.Get on the all-NULL row: the measured
		// production 500 (514/556 dev rows have NULL description).
		np, err := projRepo.Get(ctx, nullProjID)
		if err != nil {
			t.Errorf("Project Get on a NULL-column row must not fail, got: %v", err)
		} else {
			assertNullProj(t, np, "Project Get(null)")
		}
		pp, err := projRepo.Get(ctx, popProjID)
		if err != nil {
			t.Errorf("Project Get (populated row): %v", err)
		} else {
			assertPopProj(t, pp, "Project Get(pop)")
		}

		// --- GetByTenant / GetByName (NULL + populated).
		if np, err := projRepo.GetByTenant(ctx, tenant, nullProjID); err != nil {
			t.Errorf("GetByTenant on a NULL-column row must not fail, got: %v", err)
		} else {
			assertNullProj(t, np, "GetByTenant(null)")
		}
		if pp, err := projRepo.GetByTenant(ctx, tenant, popProjID); err != nil {
			t.Errorf("GetByTenant (populated row): %v", err)
		} else {
			assertPopProj(t, pp, "GetByTenant(pop)")
		}
		if np, err := projRepo.GetByName(ctx, tenant, "wave3-null-project"); err != nil {
			t.Errorf("GetByName on a NULL-column row must not fail, got: %v", err)
		} else if np == nil {
			t.Errorf("GetByName(null) returned nil for seeded project")
		} else {
			assertNullProj(t, np, "GetByName(null)")
		}
		if pp, err := projRepo.GetByName(ctx, tenant, "wave3-pop-project"); err != nil {
			t.Errorf("GetByName (populated row): %v", err)
		} else if pp == nil {
			t.Errorf("GetByName(pop) returned nil for seeded project")
		} else {
			assertPopProj(t, pp, "GetByName(pop)")
		}

		// --- ListByTenant: one poisoned row used to abort the whole list.
		projects, err := projRepo.ListByTenant(ctx, tenant)
		if err != nil {
			t.Errorf("ListByTenant with a NULL row must not fail, got: %v", err)
		} else if len(projects) != 2 {
			t.Errorf("ListByTenant returned %d rows, want 2", len(projects))
		} else {
			for i := range projects {
				switch projects[i].ID {
				case nullProjID:
					assertNullProj(t, &projects[i], "ListByTenant(null)")
				case popProjID:
					assertPopProj(t, &projects[i], "ListByTenant(pop)")
				}
			}
		}

		// --- SbomRepository.GetLatest: sboms ORDER BY created_at DESC puts
		// the NULL created_at row first (Postgres DESC default NULLS FIRST),
		// so the latest-SBOM read hits the poisoned row directly.
		ns, err := sbomRepo.GetLatest(ctx, popProjID)
		if err != nil {
			t.Errorf("Sbom GetLatest on a NULL-column row must not fail, got: %v", err)
		} else {
			if ns.Version != "" {
				t.Errorf("GetLatest: Version = %q, want \"\" for NULL", ns.Version)
			}
			if ns.CreatedAt.IsZero() {
				t.Errorf("GetLatest: CreatedAt zero; COALESCE(created_at, NOW()) should yield a real timestamp")
			}
		}

		// --- GetByID (NULL + populated round-trip / column-order pin).
		if ns, err := sbomRepo.GetByID(ctx, nullSbomID); err != nil {
			t.Errorf("Sbom GetByID on a NULL-column row must not fail, got: %v", err)
		} else if ns.Version != "" || ns.CreatedAt.IsZero() {
			t.Errorf("Sbom GetByID(null): version=%q createdAtZero=%v, want \"\"/false",
				ns.Version, ns.CreatedAt.IsZero())
		}
		ps, err := sbomRepo.GetByID(ctx, popSbomID)
		if err != nil {
			t.Errorf("Sbom GetByID (populated row): %v", err)
		} else {
			// jsonb normalizes to `{"pop": true}` (space added) on read-back.
			if ps.Format != "spdx" || ps.Version != "1.5" || string(ps.RawData) != `{"pop": true}` {
				t.Errorf("Sbom GetByID(pop) round-trip mismatch: format=%q version=%q raw=%q",
					ps.Format, ps.Version, ps.RawData)
			}
			if !ps.CreatedAt.UTC().Equal(popSbomCreatedAt) {
				t.Errorf("Sbom GetByID(pop): CreatedAt = %v, want %v", ps.CreatedAt, popSbomCreatedAt)
			}
		}

		// --- ListByProject (both rows on one page).
		sboms, err := sbomRepo.ListByProject(ctx, popProjID)
		if err != nil {
			t.Errorf("Sbom ListByProject with a NULL row must not fail, got: %v", err)
		} else if len(sboms) != 2 {
			t.Errorf("Sbom ListByProject returned %d rows, want 2", len(sboms))
		}
	})
}

// TestWave3AuditReads_NullableColumnScan drives the audit_logs reads that
// scan user_agent (DDL-nullable) and unmarshal details (30 real dev rows
// carry JSON null). audit_logs has no RLS (migration 029) — tenant scope is
// the explicit WHERE clause, so reads run on the plain app connection.
func TestWave3AuditReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "projects") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3audit")

	// users is a global table (no tenant CASCADE) — reap explicitly, and
	// register before the INSERT so a mid-seed t.Fatal cannot strand it.
	userID := uuid.New()
	registerCleanupExec(t, migDB, "wave3 audit user",
		`DELETE FROM users WHERE id = $1`, userID)
	if _, err := migDB.Exec(`
		INSERT INTO users (id, clerk_user_id, email, name)
		VALUES ($1, $2, $3, 'wave3 audit user')
	`, userID, "wave3-audit-"+tenant.String(), "wave3-audit+"+tenant.String()+"@localhost"); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	nullLogID := uuid.New()
	popLogID := uuid.New()
	resourceID := uuid.New()
	// audit_logs cascades off tenants; rows die with the tenant cleanup.
	// NULL row: user_agent NULL, ip NULL, details JSON null (the shape 30
	// real dev rows carry — json.Unmarshal("null") must stay a no-op, not
	// an error).
	if _, err := migDB.Exec(`
		INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, 'wave3.null', 'wave3res', $4, 'null'::jsonb, NULL, NULL, NOW() - INTERVAL '1 minute')
	`, nullLogID, tenant, userID, resourceID); err != nil {
		t.Fatalf("seed NULL audit log: %v", err)
	}
	// Populated row: distinct values per column (order pinning).
	if _, err := migDB.Exec(`
		INSERT INTO audit_logs (id, tenant_id, user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, 'wave3.pop', 'wave3res', $4, '{"k":"wave3"}'::jsonb, '10.1.2.3', 'wave3-agent/1.0', NOW())
	`, popLogID, tenant, userID, resourceID); err != nil {
		t.Fatalf("seed populated audit log: %v", err)
	}

	auditRepo := NewAuditRepository(appDB)
	ctx := context.Background()

	checkLogs := func(t *testing.T, logs []model.AuditLog, via string) {
		t.Helper()
		if len(logs) != 2 {
			t.Errorf("%s returned %d rows, want 2", via, len(logs))
			return
		}
		for i := range logs {
			switch logs[i].ID {
			case nullLogID:
				if logs[i].UserAgent != "" {
					t.Errorf("%s(null): UserAgent = %q, want \"\" for NULL", via, logs[i].UserAgent)
				}
				if logs[i].Details != nil {
					t.Errorf("%s(null): Details = %v, want nil for JSON null", via, logs[i].Details)
				}
			case popLogID:
				if logs[i].Action != "wave3.pop" || logs[i].UserAgent != "wave3-agent/1.0" {
					t.Errorf("%s(pop): action=%q user_agent=%q round-trip mismatch",
						via, logs[i].Action, logs[i].UserAgent)
				}
				if logs[i].Details["k"] != "wave3" {
					t.Errorf("%s(pop): Details = %v, want map with k=wave3", via, logs[i].Details)
				}
				if logs[i].IPAddress == nil || logs[i].IPAddress.String() != "10.1.2.3" {
					t.Errorf("%s(pop): IPAddress = %v, want 10.1.2.3", via, logs[i].IPAddress)
				}
			}
		}
	}

	logs, err := auditRepo.List(ctx, tenant, 10, 0)
	if err != nil {
		t.Errorf("audit List with a NULL user_agent row must not fail, got: %v", err)
	} else {
		checkLogs(t, logs, "List")
	}

	logs, err = auditRepo.ListByUser(ctx, tenant, userID, 10, 0)
	if err != nil {
		t.Errorf("audit ListByUser with a NULL user_agent row must not fail, got: %v", err)
	} else {
		checkLogs(t, logs, "ListByUser")
	}

	logs, err = auditRepo.ListByResource(ctx, tenant, "wave3res", resourceID, 10, 0)
	if err != nil {
		t.Errorf("audit ListByResource with a NULL user_agent row must not fail, got: %v", err)
	} else {
		checkLogs(t, logs, "ListByResource")
	}

	logs, total, err := auditRepo.ListWithFilter(ctx, tenant, AuditFilter{Limit: 10})
	if err != nil {
		t.Errorf("audit ListWithFilter with a NULL user_agent row must not fail, got: %v", err)
	} else {
		if total != 2 {
			t.Errorf("ListWithFilter total = %d, want 2", total)
		}
		checkLogs(t, logs, "ListWithFilter")
	}
}

// TestWave3ChecklistLicenseReads_NullableColumnScan drives checklist.go
// (updated_by / updated_at) and license.go (reason) reads. Both tables are
// FORCE RLS, so seeds go through execAsTenant and reads through the tenant
// tx.
func TestWave3ChecklistLicenseReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "compliance_checklist_responses") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3check")

	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'wave3-check-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// --- Checklist rows: NULL (updated_by / updated_at / note) + populated.
	nullRespID := uuid.New()
	popRespID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO compliance_checklist_responses (id, tenant_id, project_id, check_id, response, note, updated_by, updated_at)
		VALUES ($1, $2, $3, 'wave3-null-check', true, NULL, NULL, NULL)
	`, nullRespID, tenant, projectID); err != nil {
		t.Fatalf("seed NULL checklist response: %v", err)
	}
	popUpdatedAt := time.Date(2026, 7, 3, 9, 10, 11, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO compliance_checklist_responses (id, tenant_id, project_id, check_id, response, note, updated_by, updated_at)
		VALUES ($1, $2, $3, 'wave3-pop-check', false, 'pop note', 'pop-editor', $4)
	`, popRespID, tenant, projectID, popUpdatedAt); err != nil {
		t.Fatalf("seed populated checklist response: %v", err)
	}

	// --- License policy rows: NULL reason + populated.
	nullPolicyID := uuid.New()
	popPolicyID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO license_policies (id, tenant_id, project_id, license_id, license_name, policy_type, reason)
		VALUES ($1, $2, $3, 'MIT', 'MIT License', 'allowed', NULL)
	`, nullPolicyID, tenant, projectID); err != nil {
		t.Fatalf("seed NULL license policy: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO license_policies (id, tenant_id, project_id, license_id, license_name, policy_type, reason)
		VALUES ($1, $2, $3, 'GPL-3.0', 'GNU GPL v3', 'denied', 'pop reason')
	`, popPolicyID, tenant, projectID); err != nil {
		t.Fatalf("seed populated license policy: %v", err)
	}

	checkRepo := NewChecklistRepository(appDB)
	licenseRepo := NewLicensePolicyRepository(appDB)

	assertNullResp := func(t *testing.T, r *model.ChecklistResponse, via string) {
		t.Helper()
		if r.UpdatedBy != "" {
			t.Errorf("%s: UpdatedBy = %q, want \"\" for NULL", via, r.UpdatedBy)
		}
		if r.UpdatedAt.IsZero() {
			t.Errorf("%s: UpdatedAt zero; COALESCE(updated_at, NOW()) should yield a real timestamp", via)
		}
		if r.Note != nil {
			t.Errorf("%s: Note = %v, want nil for NULL", via, *r.Note)
		}
	}
	assertPopResp := func(t *testing.T, r *model.ChecklistResponse, via string) {
		t.Helper()
		if r.CheckID != "wave3-pop-check" || r.Response || r.UpdatedBy != "pop-editor" {
			t.Errorf("%s: round-trip mismatch: check_id=%q response=%v updated_by=%q",
				via, r.CheckID, r.Response, r.UpdatedBy)
		}
		if r.Note == nil || *r.Note != "pop note" {
			t.Errorf("%s: Note = %v, want pop note", via, r.Note)
		}
		if !r.UpdatedAt.UTC().Equal(popUpdatedAt) {
			t.Errorf("%s: UpdatedAt = %v, want %v", via, r.UpdatedAt, popUpdatedAt)
		}
	}

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- ChecklistRepository.ListByProject / ListByTenant / GetByCheckID.
		resps, err := checkRepo.ListByProject(ctx, tenant, projectID)
		if err != nil {
			t.Errorf("checklist ListByProject with a NULL row must not fail, got: %v", err)
		} else if len(resps) != 2 {
			t.Errorf("checklist ListByProject returned %d rows, want 2", len(resps))
		} else {
			for i := range resps {
				switch resps[i].ID {
				case nullRespID:
					assertNullResp(t, &resps[i], "ListByProject(null)")
				case popRespID:
					assertPopResp(t, &resps[i], "ListByProject(pop)")
				}
			}
		}
		if resps, err := checkRepo.ListByTenant(ctx, tenant); err != nil {
			t.Errorf("checklist ListByTenant with a NULL row must not fail, got: %v", err)
		} else if len(resps) != 2 {
			t.Errorf("checklist ListByTenant returned %d rows, want 2", len(resps))
		}
		if nr, err := checkRepo.GetByCheckID(ctx, tenant, projectID, "wave3-null-check"); err != nil {
			t.Errorf("checklist GetByCheckID on a NULL row must not fail, got: %v", err)
		} else if nr == nil {
			t.Errorf("checklist GetByCheckID(null) returned nil for seeded row")
		} else {
			assertNullResp(t, nr, "GetByCheckID(null)")
		}
		if pr, err := checkRepo.GetByCheckID(ctx, tenant, projectID, "wave3-pop-check"); err != nil {
			t.Errorf("checklist GetByCheckID (populated row): %v", err)
		} else if pr == nil {
			t.Errorf("checklist GetByCheckID(pop) returned nil for seeded row")
		} else {
			assertPopResp(t, pr, "GetByCheckID(pop)")
		}

		// --- LicensePolicyRepository reads.
		if np, err := licenseRepo.GetByID(ctx, nullPolicyID); err != nil {
			t.Errorf("license GetByID on a NULL-reason row must not fail, got: %v", err)
		} else if np == nil {
			t.Errorf("license GetByID(null) returned nil for seeded row")
		} else if np.Reason != "" {
			t.Errorf("license GetByID(null): Reason = %q, want \"\"", np.Reason)
		}
		if pp, err := licenseRepo.GetByID(ctx, popPolicyID); err != nil {
			t.Errorf("license GetByID (populated row): %v", err)
		} else if pp == nil || pp.Reason != "pop reason" || pp.LicenseID != "GPL-3.0" ||
			pp.LicenseName != "GNU GPL v3" || string(pp.PolicyType) != "denied" {
			t.Errorf("license GetByID(pop) round-trip mismatch: %+v", pp)
		}
		policies, err := licenseRepo.ListByProject(ctx, projectID)
		if err != nil {
			t.Errorf("license ListByProject with a NULL-reason row must not fail, got: %v", err)
		} else if len(policies) != 2 {
			t.Errorf("license ListByProject returned %d rows, want 2", len(policies))
		}
		if np, err := licenseRepo.GetByLicenseID(ctx, projectID, "MIT"); err != nil {
			t.Errorf("license GetByLicenseID on a NULL-reason row must not fail, got: %v", err)
		} else if np == nil || np.Reason != "" {
			t.Errorf("license GetByLicenseID(null) = %+v, want Reason \"\"", np)
		}
		if m, err := licenseRepo.GetPoliciesForLicenses(ctx, projectID, []string{"MIT", "GPL-3.0"}); err != nil {
			t.Errorf("license GetPoliciesForLicenses with a NULL-reason row must not fail, got: %v", err)
		} else if len(m) != 2 {
			t.Errorf("license GetPoliciesForLicenses returned %d entries, want 2", len(m))
		}
	})
}

// TestWave3UserReads_NullableColumnScan drives user.go reads that scan
// users.name / avatar_url. users / tenant_users have no RLS; users has no
// tenant CASCADE either, so rows are reaped explicitly (C27).
func TestWave3UserReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "projects") {
		return
	}
	appDB := openIntegrationDB(t, appURL)

	tenant := seedIntegrationTenant(t, migDB, "wave3user")

	nullUserID := uuid.New()
	popUserID := uuid.New()
	registerCleanupExec(t, migDB, "wave3 users",
		`DELETE FROM users WHERE id IN ($1, $2)`, nullUserID, popUserID)

	nullClerkID := "wave3-null-" + tenant.String()
	popClerkID := "wave3-pop-" + tenant.String()
	nullEmail := "wave3-null+" + tenant.String() + "@localhost"
	popEmail := "wave3-pop+" + tenant.String() + "@localhost"

	if _, err := migDB.Exec(`
		INSERT INTO users (id, clerk_user_id, email, name, avatar_url)
		VALUES ($1, $2, $3, NULL, NULL)
	`, nullUserID, nullClerkID, nullEmail); err != nil {
		t.Fatalf("seed NULL user: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO users (id, clerk_user_id, email, name, avatar_url)
		VALUES ($1, $2, $3, 'Pop User', 'https://example.com/pop.png')
	`, popUserID, popClerkID, popEmail); err != nil {
		t.Fatalf("seed populated user: %v", err)
	}
	// tenant_users cascades off both tenants and users.
	for _, link := range []struct {
		user uuid.UUID
		role string
	}{{nullUserID, "member"}, {popUserID, "admin"}} {
		if _, err := migDB.Exec(`
			INSERT INTO tenant_users (tenant_id, user_id, role, created_at)
			VALUES ($1, $2, $3, NOW())
		`, tenant, link.user, link.role); err != nil {
			t.Fatalf("seed tenant_users: %v", err)
		}
	}

	userRepo := NewUserRepository(appDB)
	ctx := context.Background()

	assertNullUser := func(t *testing.T, u *model.User, via string) {
		t.Helper()
		if u.Name != "" || u.AvatarURL != "" {
			t.Errorf("%s: name=%q avatar_url=%q, want \"\"/\"\" for NULL", via, u.Name, u.AvatarURL)
		}
	}
	assertPopUser := func(t *testing.T, u *model.User, via string) {
		t.Helper()
		if u.Name != "Pop User" || u.AvatarURL != "https://example.com/pop.png" ||
			u.Email != popEmail || u.ClerkUserID != popClerkID {
			t.Errorf("%s: round-trip mismatch: %+v", via, u)
		}
	}

	if nu, err := userRepo.GetByID(ctx, nullUserID); err != nil {
		t.Errorf("user GetByID on a NULL-column row must not fail, got: %v", err)
	} else {
		assertNullUser(t, nu, "GetByID(null)")
	}
	if pu, err := userRepo.GetByID(ctx, popUserID); err != nil {
		t.Errorf("user GetByID (populated row): %v", err)
	} else {
		assertPopUser(t, pu, "GetByID(pop)")
	}
	if nu, err := userRepo.GetByClerkUserID(ctx, nullClerkID); err != nil {
		t.Errorf("user GetByClerkUserID on a NULL-column row must not fail, got: %v", err)
	} else {
		assertNullUser(t, nu, "GetByClerkUserID(null)")
	}
	if nu, err := userRepo.GetByEmail(ctx, nullEmail); err != nil {
		t.Errorf("user GetByEmail on a NULL-column row must not fail, got: %v", err)
	} else {
		assertNullUser(t, nu, "GetByEmail(null)")
	}
	users, err := userRepo.GetTenantUsers(ctx, tenant)
	if err != nil {
		t.Errorf("GetTenantUsers with a NULL-column row must not fail, got: %v", err)
	} else if len(users) != 2 {
		t.Errorf("GetTenantUsers returned %d rows, want 2", len(users))
	} else {
		for i := range users {
			switch users[i].ID {
			case nullUserID:
				assertNullUser(t, &users[i].User, "GetTenantUsers(null)")
				if users[i].Role != "member" {
					t.Errorf("GetTenantUsers(null): Role = %q, want member", users[i].Role)
				}
			case popUserID:
				assertPopUser(t, &users[i].User, "GetTenantUsers(pop)")
				if users[i].Role != "admin" {
					t.Errorf("GetTenantUsers(pop): Role = %q, want admin", users[i].Role)
				}
			}
		}
	}
}

// TestWave3SubscriptionReads_NullableColumnScan drives subscription.go
// reads that scan subscriptions.ls_product_id and the five nullable
// subscription_events columns. Both tables lost RLS in migration 031 and
// cascade off tenants.
func TestWave3SubscriptionReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "projects") {
		return
	}
	appDB := openIntegrationDB(t, appURL)

	tenantNull := seedIntegrationTenant(t, migDB, "wave3subn")
	tenantPop := seedIntegrationTenant(t, migDB, "wave3subp")

	nullSubID := uuid.New()
	popSubID := uuid.New()
	nullLSID := "wave3-ls-null-" + tenantNull.String()[:8]
	popLSID := "wave3-ls-pop-" + tenantPop.String()[:8]

	if _, err := migDB.Exec(`
		INSERT INTO subscriptions (id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id, status, plan)
		VALUES ($1, $2, $3, 'cust-null', 'var-null', NULL, 'active', 'free')
	`, nullSubID, tenantNull, nullLSID); err != nil {
		t.Fatalf("seed NULL subscription: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO subscriptions (id, tenant_id, ls_subscription_id, ls_customer_id, ls_variant_id, ls_product_id, status, plan)
		VALUES ($1, $2, $3, 'cust-pop', 'var-pop', 'prod-777', 'on_trial', 'pro')
	`, popSubID, tenantPop, popLSID); err != nil {
		t.Fatalf("seed populated subscription: %v", err)
	}

	nullEventID := uuid.New()
	popEventID := uuid.New()
	// NULL event: all five nullable columns + metadata NULL.
	if _, err := migDB.Exec(`
		INSERT INTO subscription_events (id, subscription_id, tenant_id, event_type, ls_event_id,
			previous_status, new_status, previous_plan, new_plan, metadata, created_at)
		VALUES ($1, $2, $3, 'wave3_null_event', NULL, NULL, NULL, NULL, NULL, NULL, NOW() - INTERVAL '1 minute')
	`, nullEventID, nullSubID, tenantNull); err != nil {
		t.Fatalf("seed NULL subscription event: %v", err)
	}
	// Populated event: distinct value per column (order pinning).
	if _, err := migDB.Exec(`
		INSERT INTO subscription_events (id, subscription_id, tenant_id, event_type, ls_event_id,
			previous_status, new_status, previous_plan, new_plan, metadata, created_at)
		VALUES ($1, $2, $3, 'wave3_pop_event', 'evt-42', 'on_trial', 'active', 'free', 'pro', '{"m":"v"}'::jsonb, NOW())
	`, popEventID, nullSubID, tenantNull); err != nil {
		t.Fatalf("seed populated subscription event: %v", err)
	}

	subRepo := NewSubscriptionRepository(appDB)
	ctx := context.Background()

	// --- GetByTenantID on the NULL ls_product_id row (the webhook-written
	// shape: Create writes NULL when LSProductID is unset... the point is
	// the read must not 500).
	ns, err := subRepo.GetByTenantID(ctx, tenantNull)
	if err != nil {
		t.Errorf("GetByTenantID on a NULL ls_product_id row must not fail, got: %v", err)
	} else if ns.LSProductID != "" {
		t.Errorf("GetByTenantID(null): LSProductID = %q, want \"\"", ns.LSProductID)
	}
	ps, err := subRepo.GetByTenantID(ctx, tenantPop)
	if err != nil {
		t.Errorf("GetByTenantID (populated row): %v", err)
	} else if ps.LSProductID != "prod-777" || ps.LSCustomerID != "cust-pop" ||
		ps.LSVariantID != "var-pop" || ps.Status != "on_trial" || ps.Plan != "pro" {
		t.Errorf("GetByTenantID(pop) round-trip mismatch: %+v", ps)
	}

	// --- GetByLSSubscriptionID (the Lemon Squeezy webhook lookup).
	if ns, err := subRepo.GetByLSSubscriptionID(ctx, nullLSID); err != nil {
		t.Errorf("GetByLSSubscriptionID on a NULL ls_product_id row must not fail, got: %v", err)
	} else if ns.LSProductID != "" {
		t.Errorf("GetByLSSubscriptionID(null): LSProductID = %q, want \"\"", ns.LSProductID)
	}

	// --- GetEvents: one poisoned row used to abort the whole event list.
	events, err := subRepo.GetEvents(ctx, tenantNull, 10)
	if err != nil {
		t.Errorf("GetEvents with a NULL-column row must not fail, got: %v", err)
	} else if len(events) != 2 {
		t.Errorf("GetEvents returned %d rows, want 2", len(events))
	} else {
		// created_at DESC: pop first, null second.
		if events[0].ID != popEventID || events[1].ID != nullEventID {
			t.Errorf("GetEvents order = [%s, %s], want [pop %s, null %s]",
				events[0].ID, events[1].ID, popEventID, nullEventID)
		}
		pe, ne := events[0], events[1]
		if pe.LSEventID != "evt-42" || pe.PreviousStatus != "on_trial" || pe.NewStatus != "active" ||
			pe.PreviousPlan != "free" || pe.NewPlan != "pro" || pe.Metadata["m"] != "v" {
			t.Errorf("GetEvents(pop) round-trip mismatch: %+v", pe)
		}
		if ne.LSEventID != "" || ne.PreviousStatus != "" || ne.NewStatus != "" ||
			ne.PreviousPlan != "" || ne.NewPlan != "" {
			t.Errorf("GetEvents(null): got %+v, want all five nullable strings \"\"", ne)
		}
	}
}

// TestWave3VisualizationReads_NullableColumnScan drives
// VisualizationRepository.GetByProject over an all-NULL row (every
// classification column NULL) and a fully-populated row. The NULL contract
// here differs from the ” convention: each column carries a semantic DDL
// default ('self', 'direct_only', ...) so the read applies that default —
// a NULL row reads back exactly like a freshly-defaulted row (0 NULL rows
// measured on the dev DB, defaults verified against migration 040 DDL).
func TestWave3VisualizationReads_NullableColumnScan(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "sbom_visualization_settings") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3viz")

	nullProjID := uuid.New()
	popProjID := uuid.New()
	for _, p := range []struct {
		id   uuid.UUID
		name string
	}{{nullProjID, "wave3-viz-null"}, {popProjID, "wave3-viz-pop"}} {
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)
		`, p.id, tenant, p.name); err != nil {
			t.Fatalf("seed project %s: %v", p.name, err)
		}
	}

	nullVizID := uuid.New()
	popVizID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sbom_visualization_settings (id, tenant_id, project_id,
			sbom_author_scope, dependency_scope, generation_method, data_format,
			utilization_scope, utilization_actor, created_at, updated_at)
		VALUES ($1, $2, $3, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)
	`, nullVizID, tenant, nullProjID); err != nil {
		t.Fatalf("seed NULL visualization settings: %v", err)
	}
	popVizCreatedAt := time.Date(2026, 7, 4, 1, 2, 3, 0, time.UTC)
	popVizUpdatedAt := time.Date(2026, 7, 5, 4, 5, 6, 0, time.UTC)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO sbom_visualization_settings (id, tenant_id, project_id,
			sbom_author_scope, dependency_scope, generation_method, data_format,
			utilization_scope, utilization_actor, created_at, updated_at)
		VALUES ($1, $2, $3, 'pop-author', 'pop-deps', 'pop-method', 'pop-format',
			'["pop_use"]'::jsonb, 'pop-actor', $4, $5)
	`, popVizID, tenant, popProjID, popVizCreatedAt, popVizUpdatedAt); err != nil {
		t.Fatalf("seed populated visualization settings: %v", err)
	}

	vizRepo := NewVisualizationRepository(appDB)

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		nv, err := vizRepo.GetByProject(ctx, tenant, nullProjID)
		if err != nil {
			t.Errorf("viz GetByProject on an all-NULL row must not fail, got: %v", err)
		} else if nv == nil {
			t.Errorf("viz GetByProject(null) returned nil for seeded row")
		} else {
			if nv.SBOMAuthorScope != "self" || nv.DependencyScope != "direct_only" ||
				nv.GenerationMethod != "tool_no_review" || nv.DataFormat != "standard" ||
				nv.UtilizationActor != "product_vendor" {
				t.Errorf("viz GetByProject(null): got %q/%q/%q/%q/%q, want the DDL defaults "+
					"self/direct_only/tool_no_review/standard/product_vendor",
					nv.SBOMAuthorScope, nv.DependencyScope, nv.GenerationMethod,
					nv.DataFormat, nv.UtilizationActor)
			}
			if nv.CreatedAt.IsZero() || nv.UpdatedAt.IsZero() {
				t.Errorf("viz GetByProject(null): CreatedAt/UpdatedAt zero, want read-time defaults")
			}
		}

		pv, err := vizRepo.GetByProject(ctx, tenant, popProjID)
		if err != nil {
			t.Errorf("viz GetByProject (populated row): %v", err)
		} else if pv == nil {
			t.Errorf("viz GetByProject(pop) returned nil for seeded row")
		} else {
			if pv.SBOMAuthorScope != "pop-author" || pv.DependencyScope != "pop-deps" ||
				pv.GenerationMethod != "pop-method" || pv.DataFormat != "pop-format" ||
				pv.UtilizationActor != "pop-actor" {
				t.Errorf("viz GetByProject(pop) round-trip mismatch: %+v", pv)
			}
			if len(pv.UtilizationScope) != 1 || pv.UtilizationScope[0] != "pop_use" {
				t.Errorf("viz GetByProject(pop): UtilizationScope = %v, want [pop_use]", pv.UtilizationScope)
			}
			if !pv.CreatedAt.UTC().Equal(popVizCreatedAt) || !pv.UpdatedAt.UTC().Equal(popVizUpdatedAt) {
				t.Errorf("viz GetByProject(pop): CreatedAt/UpdatedAt = %v/%v, want %v/%v",
					pv.CreatedAt, pv.UpdatedAt, popVizCreatedAt, popVizUpdatedAt)
			}
		}
	})
}

// TestWave3NotificationLogs_BrokenPayloadColumn pins the notification_logs
// dead-query fix: GetLogs / CreateLog used to reference a `payload` column
// that does not exist (real column: `message`; and the INSERT never set the
// NOT NULL `notification_type`), so both failed on EVERY call with
// `column "payload" does not exist` — notification history was silently
// empty and send logging always errored.
func TestWave3NotificationLogs_BrokenPayloadColumn(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "notification_logs") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3notif")

	projectID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'wave3-notif-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// Pre-existing rows: one with NULL message / error_message (nullable
	// text), one populated — both must read back through GetLogs.
	nullLogID := uuid.New()
	popLogID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO notification_logs (id, tenant_id, project_id, notification_type, channel, status, message, error_message, created_at)
		VALUES ($1, $2, $3, 'vulnerability', 'slack', 'sent', NULL, NULL, NOW() - INTERVAL '1 minute')
	`, nullLogID, tenant, projectID); err != nil {
		t.Fatalf("seed NULL notification log: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO notification_logs (id, tenant_id, project_id, notification_type, channel, status, message, error_message, created_at)
		VALUES ($1, $2, $3, 'vulnerability', 'discord', 'failed', 'pop payload', 'pop error', NOW())
	`, popLogID, tenant, projectID); err != nil {
		t.Fatalf("seed populated notification log: %v", err)
	}

	notifRepo := NewNotificationRepository(appDB)

	// --- GetLogs (the dead read): must return both rows.
	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		logs, err := notifRepo.GetLogs(ctx, projectID, 10)
		if err != nil {
			t.Errorf("GetLogs must not fail (dead `payload` column query), got: %v", err)
			return
		}
		if len(logs) != 2 {
			t.Errorf("GetLogs returned %d rows, want 2", len(logs))
			return
		}
		// created_at DESC: pop first.
		if logs[0].ID != popLogID || logs[1].ID != nullLogID {
			t.Errorf("GetLogs order = [%s, %s], want [pop %s, null %s]",
				logs[0].ID, logs[1].ID, popLogID, nullLogID)
		}
		if logs[0].Payload != "pop payload" || logs[0].Status != "failed" ||
			string(logs[0].Channel) != "discord" || logs[0].ErrorMessage != "pop error" {
			t.Errorf("GetLogs(pop) round-trip mismatch: %+v", logs[0])
		}
		if logs[1].Payload != "" || logs[1].ErrorMessage != "" {
			t.Errorf("GetLogs(null): payload=%q error=%q, want \"\"/\"\"", logs[1].Payload, logs[1].ErrorMessage)
		}
	})

	// --- CreateLog (the dead write): drive it inside an app-role tenant tx
	// and read the row back through GetLogs in the SAME tx, then roll back
	// so nothing persists (C27: no residue by construction).
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("begin CreateLog tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL app.current_tenant_id = '` + tenant.String() + `'`); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	ctx := database.WithTx(context.Background(), tx)
	created := &model.NotificationLog{
		ID:        uuid.New(),
		TenantID:  tenant,
		ProjectID: projectID,
		Channel:   model.NotificationChannelEmail,
		Payload:   "created payload",
		Status:    "sent",
		CreatedAt: time.Now(),
	}
	if err := notifRepo.CreateLog(ctx, created); err != nil {
		t.Fatalf("CreateLog must not fail (dead `payload` column INSERT), got: %v", err)
	}
	logs, err := notifRepo.GetLogs(ctx, projectID, 10)
	if err != nil {
		t.Fatalf("GetLogs after CreateLog: %v", err)
	}
	var found bool
	for i := range logs {
		if logs[i].ID == created.ID {
			found = true
			if logs[i].Payload != "created payload" || string(logs[i].Channel) != "email" ||
				logs[i].Status != "sent" {
				t.Errorf("CreateLog round-trip mismatch: %+v", logs[i])
			}
		}
	}
	if !found {
		t.Errorf("CreateLog row not visible through GetLogs in the same tx")
	}
}

// TestWave3AnalyticsReads_NullableExpressions pins the two analytics
// expression findings:
//
//   - GetComplianceTrend's percentage is (overall_score::float /
//     NULLIF(max_score, 0)) * 100 — genuinely NULL when max_score = 0, which
//     is exactly the "no checklist configured yet" snapshot shape. The read
//     COALESCEs it to 0 (0% compliant with an empty scorecard).
//
//   - GetSLOAchievement's achievement_pct CASE is a nullscan false
//     positive: the WHEN COALESCE(r.total_count, 0) = 0 guard routes every
//     NULL-side LEFT JOIN row (and every zero row) to the literal 100.0, so
//     the ELSE division only ever sees non-NULL, non-zero total_count. The
//     severity with no resolved rows below proves the guard path; the
//     late-resolved severity proves the ELSE path.
func TestWave3AnalyticsReads_NullableExpressions(t *testing.T) {
	appURL, migURL := llmCallsTestEnv(t)

	migDB := openIntegrationDB(t, migURL)
	if !schemaReadyNullScan(t, migDB, "compliance_snapshots") {
		return
	}
	appDB := openIntegrationDB(t, appURL)
	assertAppRoleEnforcesRLS(t, appDB)

	tenant := seedIntegrationTenant(t, migDB, "wave3ana")

	// --- Compliance snapshots: today's row has max_score=0 (NULL
	// percentage — the real bug), yesterday's is populated with distinct
	// sub-scores (column-order pin).
	zeroSnapID := uuid.New()
	popSnapID := uuid.New()
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO compliance_snapshots (id, tenant_id, project_id, snapshot_date, overall_score, max_score,
			sbom_generation_score, vulnerability_management_score, license_management_score)
		VALUES ($1, $2, NULL, CURRENT_DATE, 0, 0, 0, 0, 0)
	`, zeroSnapID, tenant); err != nil {
		t.Fatalf("seed zero-max snapshot: %v", err)
	}
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO compliance_snapshots (id, tenant_id, project_id, snapshot_date, overall_score, max_score,
			sbom_generation_score, vulnerability_management_score, license_management_score)
		VALUES ($1, $2, NULL, CURRENT_DATE - 1, 80, 100, 30, 40, 10)
	`, popSnapID, tenant); err != nil {
		t.Fatalf("seed populated snapshot: %v", err)
	}

	// --- SLO targets + resolution events: CRITICAL has a target but no
	// resolved rows (guard path → 100.0); HIGH has one late resolution
	// (ELSE path → 0%). The event needs a project + a global vulnerability
	// row (FK) — the latter is reaped explicitly (C27).
	projectID := uuid.New()
	vulnID := uuid.New()
	registerCleanupExec(t, migDB, "wave3 analytics vulnerability",
		`DELETE FROM vulnerabilities WHERE id = $1`, vulnID)
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, 'wave3-ana-project')
	`, projectID, tenant); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id) VALUES ($1, $2)
	`, vulnID, "CVE-WAVE3-ANA-"+tenant.String()[:8]); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	for _, sev := range []string{"CRITICAL", "HIGH"} {
		if err := execAsTenant(t, migDB, tenant, `
			INSERT INTO slo_targets (id, tenant_id, severity, target_hours) VALUES ($1, $2, $3, 24)
		`, uuid.New(), tenant, sev); err != nil {
			t.Fatalf("seed slo_target %s: %v", sev, err)
		}
	}
	// HIGH event resolved 90h after detection (>24h target → off-target).
	if err := execAsTenant(t, migDB, tenant, `
		INSERT INTO vulnerability_resolution_events (id, tenant_id, vulnerability_id, project_id, cve_id, severity, detected_at, resolved_at)
		VALUES ($1, $2, $3, $4, 'CVE-WAVE3-ANA', 'HIGH', NOW() - INTERVAL '100 hours', NOW() - INTERVAL '10 hours')
	`, uuid.New(), tenant, vulnID, projectID); err != nil {
		t.Fatalf("seed resolution event: %v", err)
	}

	anaRepo := NewAnalyticsRepository(appDB)

	readAsTenantTx(t, appDB, tenant, func(ctx context.Context) {
		// --- GetComplianceTrend: the max_score=0 row used to abort the
		// whole trend read with a NULL float64 scan.
		points, err := anaRepo.GetComplianceTrend(ctx, tenant, 7)
		if err != nil {
			t.Errorf("GetComplianceTrend with a max_score=0 row must not fail, got: %v", err)
		} else if len(points) != 2 {
			t.Errorf("GetComplianceTrend returned %d points, want 2", len(points))
		} else {
			// snapshot_date ASC: populated (yesterday) first, zero-max today.
			pop, zero := points[0], points[1]
			if pop.Score != 80 || pop.MaxScore != 100 || pop.Percentage != 80.0 ||
				pop.SBOMScore != 30 || pop.VulnerabilityScore != 40 || pop.LicenseScore != 10 {
				t.Errorf("GetComplianceTrend(pop) round-trip mismatch: %+v", pop)
			}
			if zero.MaxScore != 0 {
				t.Errorf("GetComplianceTrend(zero): MaxScore = %d, want 0", zero.MaxScore)
			}
			if zero.Percentage != 0 {
				t.Errorf("GetComplianceTrend(zero): Percentage = %v, want 0 (NULL ratio reads as 0%%)", zero.Percentage)
			}
		}

		// --- GetSLOAchievement: both CASE paths.
		achievements, err := anaRepo.GetSLOAchievement(ctx, tenant,
			time.Now().Add(-14*24*time.Hour), time.Now())
		if err != nil {
			t.Errorf("GetSLOAchievement must not fail, got: %v", err)
			return
		}
		bySev := map[string]model.SLOAchievement{}
		for _, a := range achievements {
			bySev[a.Severity] = a
		}
		if crit, ok := bySev["CRITICAL"]; !ok {
			t.Errorf("GetSLOAchievement missing CRITICAL row")
		} else if crit.TotalCount != 0 || crit.AchievementPct != 100.0 {
			t.Errorf("GetSLOAchievement CRITICAL = %+v, want total 0 / pct 100 (guard path)", crit)
		}
		if high, ok := bySev["HIGH"]; !ok {
			t.Errorf("GetSLOAchievement missing HIGH row")
		} else if high.TotalCount != 1 || high.OnTargetCount != 0 || high.AchievementPct != 0.0 {
			t.Errorf("GetSLOAchievement HIGH = %+v, want total 1 / on-target 0 / pct 0 (ELSE path)", high)
		}
	})
}
