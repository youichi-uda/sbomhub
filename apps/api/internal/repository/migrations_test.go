package repository

// Migration content sanity tests.
//
// These run without a database (no //go:build integration tag) so the
// regression check fires on every `go test ./...` invocation, not only
// on the rls-integration CI lane. They parse the .sql files directly
// from apps/api/migrations/ to assert that the load-bearing security
// statements have not been edited away.
//
// In particular, M1 Codex review round 1 finding F1 was that
// 036_tenant_llm_config landed without RLS while storing
// encrypted_api_key. Migration 037 added ENABLE + FORCE RLS + a
// tenant_isolation policy. If a future refactor moves/removes those
// statements (e.g. consolidating 036+037 into a single rewritten 036)
// this test fires loudly instead of silently regressing the BYOK
// credential isolation guarantee.

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// migrationsDir returns the absolute path to apps/api/migrations relative
// to this test file. Using runtime.Caller keeps it working regardless of
// the directory `go test` is invoked from.
func migrationsDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller(0) failed")
	}
	// thisFile = .../apps/api/internal/repository/migrations_test.go
	// migrations = .../apps/api/migrations
	apiDir := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	return filepath.Join(apiDir, "migrations")
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(migrationsDir(t), name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// Test037_TenantLLMConfigRLS_ContainsHardening guards the M1 Codex F1
// fix. If anyone edits 037_tenant_llm_config_rls.up.sql to remove one of
// the four load-bearing statements (ENABLE, FORCE, FOR ALL policy with
// USING + WITH CHECK), this test fires before review.
func Test037_TenantLLMConfigRLS_ContainsHardening(t *testing.T) {
	up := readMigration(t, "037_tenant_llm_config_rls.up.sql")
	upUpper := strings.ToUpper(up)

	mustContain := []struct {
		needle string
		why    string
	}{
		{
			needle: "ALTER TABLE TENANT_LLM_CONFIG ENABLE ROW LEVEL SECURITY",
			why:    "RLS must be ENABLED on tenant_llm_config (F1 fix)",
		},
		{
			needle: "ALTER TABLE TENANT_LLM_CONFIG FORCE",
			why:    "RLS must be FORCED so the migrator/owner role does not bypass policy",
		},
		{
			needle: "ROW LEVEL SECURITY",
			why:    "must reference ROW LEVEL SECURITY",
		},
		{
			needle: "CREATE POLICY TENANT_ISOLATION_TENANT_LLM_CONFIG ON TENANT_LLM_CONFIG",
			why:    "policy name must match convention used by other tenant_isolation_<table> policies",
		},
		{
			needle: "FOR ALL",
			why:    "policy must cover all command types (SELECT/INSERT/UPDATE/DELETE)",
		},
		{
			needle: "USING",
			why:    "policy must have USING (read predicate)",
		},
		{
			needle: "WITH CHECK",
			why:    "policy must have WITH CHECK (write predicate) -- this is what blocks cross-tenant INSERT",
		},
		{
			needle: "CURRENT_SETTING('APP.CURRENT_TENANT_ID', TRUE)::UUID",
			why:    "must read app.current_tenant_id GUC with missing_ok=true and cast to UUID",
		},
		{
			needle: "TENANT_ID = CURRENT_SETTING",
			why:    "predicate must compare tenant_id column against the GUC",
		},
	}
	for _, m := range mustContain {
		if !strings.Contains(upUpper, m.needle) {
			t.Errorf("037_tenant_llm_config_rls.up.sql missing %q: %s",
				m.needle, m.why)
		}
	}

	// And the down migration must clean up in the right order.
	down := readMigration(t, "037_tenant_llm_config_rls.down.sql")
	downUpper := strings.ToUpper(down)
	for _, m := range []struct {
		needle string
		why    string
	}{
		{"DROP POLICY IF EXISTS TENANT_ISOLATION_TENANT_LLM_CONFIG ON TENANT_LLM_CONFIG",
			"down must drop the policy"},
		{"NO FORCE ROW LEVEL SECURITY",
			"down must unforce RLS"},
		{"DISABLE", "down must disable RLS"},
	} {
		if !strings.Contains(downUpper, m.needle) {
			t.Errorf("037_tenant_llm_config_rls.down.sql missing %q: %s",
				m.needle, m.why)
		}
	}
}

// Test036_TenantLLMConfig_TableStillExists ensures 036 still creates the
// table 037 depends on. If 036 is later renamed/removed without merging
// 037 forward, this test surfaces the dependency immediately.
func Test036_TenantLLMConfig_TableStillExists(t *testing.T) {
	up := readMigration(t, "036_tenant_llm_config.up.sql")
	if !regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?tenant_llm_config`).MatchString(up) {
		t.Fatal("036_tenant_llm_config.up.sql no longer creates tenant_llm_config; " +
			"037 RLS hardening will fail to apply")
	}
}

// Test040_ComplianceVisualizationRLS_ContainsHardening guards the M4
// Codex round 13 F73 fix. compliance_checklist_responses and
// sbom_visualization_settings shipped in migration 018 without RLS,
// so a tenant-A user that knew or guessed a tenant-B project UUID
// could read / overwrite / delete tenant B's manual METI checklist
// responses and visualization settings. Migration 040 ENABLE + FORCE
// RLS on both tables with WITH CHECK policies. If anyone edits 040 to
// remove a load-bearing statement (or merges it into 018 forward),
// this test fires before review.
func Test040_ComplianceVisualizationRLS_ContainsHardening(t *testing.T) {
	up := readMigration(t, "040_rls_compliance_visualization.up.sql")
	upUpper := strings.ToUpper(up)

	mustContain := []struct {
		needle string
		why    string
	}{
		// compliance_checklist_responses half.
		{
			needle: "ALTER TABLE COMPLIANCE_CHECKLIST_RESPONSES ENABLE ROW LEVEL SECURITY",
			why:    "RLS must be ENABLED on compliance_checklist_responses (F73 fix)",
		},
		{
			needle: "ALTER TABLE COMPLIANCE_CHECKLIST_RESPONSES FORCE",
			why:    "RLS must be FORCED on compliance_checklist_responses so the owner does not bypass",
		},
		{
			needle: "CREATE POLICY TENANT_ISOLATION_COMPLIANCE_CHECKLIST ON COMPLIANCE_CHECKLIST_RESPONSES",
			why:    "policy name must match the tenant_isolation_<table> convention",
		},
		// sbom_visualization_settings half.
		{
			needle: "ALTER TABLE SBOM_VISUALIZATION_SETTINGS ENABLE ROW LEVEL SECURITY",
			why:    "RLS must be ENABLED on sbom_visualization_settings (F73 fix)",
		},
		{
			needle: "ALTER TABLE SBOM_VISUALIZATION_SETTINGS FORCE",
			why:    "RLS must be FORCED on sbom_visualization_settings so the owner does not bypass",
		},
		{
			needle: "CREATE POLICY TENANT_ISOLATION_VISUALIZATION ON SBOM_VISUALIZATION_SETTINGS",
			why:    "policy name must match the tenant_isolation_<table> convention",
		},
		// Shared shape (both policies use these).
		{needle: "FOR ALL", why: "policies must cover all command types"},
		{needle: "USING", why: "policies must have USING (read predicate)"},
		{needle: "WITH CHECK", why: "policies must have WITH CHECK (write predicate) -- blocks cross-tenant INSERT/UPDATE"},
		{needle: "CURRENT_SETTING('APP.CURRENT_TENANT_ID', TRUE)::UUID",
			why: "predicate must read app.current_tenant_id GUC with missing_ok=true and cast to UUID"},
	}
	for _, m := range mustContain {
		if !strings.Contains(upUpper, m.needle) {
			t.Errorf("040_rls_compliance_visualization.up.sql missing %q: %s",
				m.needle, m.why)
		}
	}

	// Down migration must clean up in the right order.
	down := readMigration(t, "040_rls_compliance_visualization.down.sql")
	downUpper := strings.ToUpper(down)
	for _, m := range []struct {
		needle string
		why    string
	}{
		{"DROP POLICY IF EXISTS TENANT_ISOLATION_VISUALIZATION ON SBOM_VISUALIZATION_SETTINGS",
			"down must drop the visualization policy"},
		{"DROP POLICY IF EXISTS TENANT_ISOLATION_COMPLIANCE_CHECKLIST ON COMPLIANCE_CHECKLIST_RESPONSES",
			"down must drop the checklist policy"},
		{"NO FORCE ROW LEVEL SECURITY", "down must unforce RLS on both tables"},
		{"DISABLE", "down must disable RLS"},
	} {
		if !strings.Contains(downUpper, m.needle) {
			t.Errorf("040_rls_compliance_visualization.down.sql missing %q: %s",
				m.needle, m.why)
		}
	}
}

// Test018_ComplianceChecklist_TablesStillExist ensures migration 018
// still creates the two tables migration 040 depends on. If 018 is
// later renamed/removed without merging 040 forward, this test
// surfaces the dependency immediately.
func Test018_ComplianceChecklist_TablesStillExist(t *testing.T) {
	up := readMigration(t, "018_compliance_checklist.up.sql")
	for _, table := range []string{"compliance_checklist_responses", "sbom_visualization_settings"} {
		pattern := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?` + table)
		if !pattern.MatchString(up) {
			t.Fatalf("018_compliance_checklist.up.sql no longer creates %s; "+
				"040 RLS hardening will fail to apply", table)
		}
	}
}

// Test041_ComplianceVisualizationTenantFK_ContainsHardening guards the
// M4 Codex round 15 F75 fix. F73 (migration 040) installed RLS so a
// tenant-A session cannot write a row with tenant_id=B, but the WITH
// CHECK predicate only enforces (inserted row's tenant_id =
// app.current_tenant_id) -- it says nothing about whether project_id
// actually belongs to that tenant. A tenant-A session that submits
// tenant_id=A + project_id=<B's project UUID> still slips through,
// landing a polluted child row that (a) carries tenant-A audit content
// hanging off a tenant-B project graph and (b) DoSes tenant B by
// occupying the UNIQUE(project_id, [check_id]) slot that tenant B's
// own future write would need. Migration 041 closes this with a
// composite FOREIGN KEY child(tenant_id, project_id) ->
// projects(tenant_id, id), backed by an explicit composite UNIQUE on
// projects (PostgreSQL FK targets must reference a PK or UNIQUE). The
// up migration also runs an orphan / mismatch sanity check that
// aborts loudly rather than failing with a generic FK violation when
// pre-existing pollution is detected. If anyone edits 041 to remove a
// load-bearing statement (or merges it forward into 040 / 018), this
// test fires before review.
func Test041_ComplianceVisualizationTenantFK_ContainsHardening(t *testing.T) {
	up := readMigration(t, "041_compliance_visualization_tenant_fk.up.sql")
	upUpper := strings.ToUpper(up)

	mustContain := []struct {
		needle string
		why    string
	}{
		// Step 1: composite UNIQUE on projects so the FKs below have a
		// valid target. id-only PRIMARY KEY does NOT cover (tenant_id, id).
		{
			needle: "ALTER TABLE PROJECTS",
			why:    "must alter projects to add the composite UNIQUE that anchors the FKs (F75 fix)",
		},
		{
			needle: "ADD CONSTRAINT PROJECTS_TENANT_ID_ID_UNIQUE UNIQUE (TENANT_ID, ID)",
			why:    "composite UNIQUE (tenant_id, id) on projects is the load-bearing FK target",
		},
		// Step 2: orphan sanity check must run before any FK installation.
		{
			needle: "DO $$",
			why:    "pre-flight orphan / mismatch check block must exist (F75 ops diagnostic)",
		},
		{
			needle: "RAISE EXCEPTION",
			why:    "orphan check must abort the migration loudly, not log-and-continue",
		},
		{
			needle: "COMPLIANCE_CHECKLIST_RESPONSES CCR",
			why:    "orphan check must scan compliance_checklist_responses for tenant_id mismatch",
		},
		{
			needle: "SBOM_VISUALIZATION_SETTINGS SVS",
			why:    "orphan check must scan sbom_visualization_settings for tenant_id mismatch",
		},
		// Step 3a: composite FK on compliance_checklist_responses.
		{
			needle: "ALTER TABLE COMPLIANCE_CHECKLIST_RESPONSES",
			why:    "must add the composite FK on compliance_checklist_responses (F75 fix)",
		},
		{
			needle: "ADD CONSTRAINT COMPLIANCE_CHECKLIST_TENANT_PROJECT_FK",
			why:    "composite FK constraint name must follow the documented convention",
		},
		{
			needle: "FOREIGN KEY (TENANT_ID, PROJECT_ID)",
			why:    "composite FK must reference the (tenant_id, project_id) pair, not project_id alone",
		},
		{
			needle: "REFERENCES PROJECTS (TENANT_ID, ID)",
			why:    "FK must target the composite UNIQUE on projects(tenant_id, id)",
		},
		{
			needle: "ON DELETE CASCADE",
			why:    "FK must CASCADE on parent delete to keep parity with the existing project_id FK from migration 018",
		},
		// Step 3b: composite FK on sbom_visualization_settings.
		{
			needle: "ALTER TABLE SBOM_VISUALIZATION_SETTINGS",
			why:    "must add the composite FK on sbom_visualization_settings (F75 fix)",
		},
		{
			needle: "ADD CONSTRAINT SBOM_VISUALIZATION_TENANT_PROJECT_FK",
			why:    "composite FK constraint name must follow the documented convention",
		},
	}
	for _, m := range mustContain {
		if !strings.Contains(upUpper, m.needle) {
			t.Errorf("041_compliance_visualization_tenant_fk.up.sql missing %q: %s",
				m.needle, m.why)
		}
	}

	// Down migration must drop in the reverse order (child FKs before
	// the parent's UNIQUE) and must use IF EXISTS so repeated downs do
	// not fail.
	down := readMigration(t, "041_compliance_visualization_tenant_fk.down.sql")
	downUpper := strings.ToUpper(down)
	for _, m := range []struct {
		needle string
		why    string
	}{
		{"DROP CONSTRAINT IF EXISTS SBOM_VISUALIZATION_TENANT_PROJECT_FK",
			"down must drop the visualization composite FK"},
		{"DROP CONSTRAINT IF EXISTS COMPLIANCE_CHECKLIST_TENANT_PROJECT_FK",
			"down must drop the checklist composite FK"},
		{"DROP CONSTRAINT IF EXISTS PROJECTS_TENANT_ID_ID_UNIQUE",
			"down must drop the composite UNIQUE on projects (after dependent FKs are gone)"},
	} {
		if !strings.Contains(downUpper, m.needle) {
			t.Errorf("041_compliance_visualization_tenant_fk.down.sql missing %q: %s",
				m.needle, m.why)
		}
	}

	// Ordering guard: the down migration MUST drop the child FKs before
	// the parent's UNIQUE constraint. Reversing this order makes the
	// UNIQUE drop fail because dependent FKs still reference it.
	childIdx := strings.Index(downUpper, "DROP CONSTRAINT IF EXISTS COMPLIANCE_CHECKLIST_TENANT_PROJECT_FK")
	parentIdx := strings.Index(downUpper, "DROP CONSTRAINT IF EXISTS PROJECTS_TENANT_ID_ID_UNIQUE")
	if childIdx == -1 || parentIdx == -1 {
		// already covered by the per-needle assertions above
	} else if childIdx > parentIdx {
		t.Error("041 down migration drops projects_tenant_id_id_unique before the dependent " +
			"compliance_checklist_tenant_project_fk; PostgreSQL will reject the parent drop " +
			"because the child FK still references it")
	}
}
