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

// Test042_RLSForceUniformity_ContainsHardening guards the M5 Wave M5-1
// (issue #50) FORCE + WITH CHECK harmonisation sweep over 9 tables
// originally shipped in migrations 012 / 013 / 014 / 021 with USING-
// only policies and no FORCE. If anyone edits 042 to remove a load-
// bearing FORCE / policy recreation (or merges it forward into the
// originals), this test fires before review.
func Test042_RLSForceUniformity_ContainsHardening(t *testing.T) {
	up := readMigration(t, "042_rls_force_uniformity.up.sql")
	upUpper := strings.ToUpper(up)

	// All 9 tables in M5-1 (b) must get FORCE.
	forceTables := []string{
		"vulnerability_resolution_events",
		"slo_targets",
		"vulnerability_snapshots",
		"compliance_snapshots",
		"report_settings",
		"generated_reports",
		"ipa_sync_settings",
		"ssvc_project_defaults",
		"ssvc_assessments",
	}
	for _, tbl := range forceTables {
		needle := strings.ToUpper("ALTER TABLE " + tbl + " FORCE ROW LEVEL SECURITY")
		if !strings.Contains(upUpper, needle) {
			t.Errorf("042_rls_force_uniformity.up.sql missing %q -- M5-1 (b) FORCE sweep regression", needle)
		}
	}

	// All 9 must get a renamed tenant_isolation_<table> policy.
	policyTables := []string{
		"vulnerability_resolution_events",
		"slo_targets",
		"vulnerability_snapshots",
		"compliance_snapshots",
		"report_settings",
		"generated_reports",
		"ipa_sync_settings",
		"ssvc_project_defaults",
		"ssvc_assessments",
	}
	for _, tbl := range policyTables {
		needle := strings.ToUpper("CREATE POLICY tenant_isolation_" + tbl + " ON " + tbl)
		if !strings.Contains(upUpper, needle) {
			t.Errorf("042_rls_force_uniformity.up.sql missing %q -- M5-1 policy rename regression", needle)
		}
	}

	// Every new policy must use the missing-OK GUC read and explicit
	// WITH CHECK so an unset GUC fails closed (zero rows / rejected
	// INSERT) rather than raising a SQL error.
	if !strings.Contains(upUpper, "CURRENT_SETTING('APP.CURRENT_TENANT_ID', TRUE)::UUID") {
		t.Error("042: must use current_setting('app.current_tenant_id', true)::UUID (M4 convention)")
	}
	if !strings.Contains(upUpper, "WITH CHECK") {
		t.Error("042: must contain explicit WITH CHECK clauses (M4 convention)")
	}

	// slo_targets special case: WRITE-side WITH CHECK must require
	// tenant_id IS NOT NULL so a tenant cannot forge new global rows.
	if !strings.Contains(upUpper, "TENANT_ID IS NOT NULL") {
		t.Error("042: slo_targets policy must require tenant_id IS NOT NULL on the WRITE side " +
			"so tenants cannot forge new NULL-tenant global defaults")
	}

	// slo_targets READ side must preserve the NULL-tenant global
	// defaults, otherwise every tenant loses visibility to
	// CRITICAL=24h / HIGH=168h / MEDIUM=720h / LOW=2160h seeded in
	// migration 012.
	if !strings.Contains(upUpper, "TENANT_ID IS NULL") {
		t.Error("042: slo_targets USING side must keep `tenant_id IS NULL` so global default " +
			"rows (CRITICAL=24h / HIGH=168h / ... seeded in migration 012) remain readable")
	}

	// Down migration sanity: must restore the original USING-only
	// policy names so 042 is fully reversible.
	down := readMigration(t, "042_rls_force_uniformity.down.sql")
	downUpper := strings.ToUpper(down)
	for _, m := range []struct {
		needle string
		why    string
	}{
		{"NO FORCE ROW LEVEL SECURITY", "down must unforce RLS on every table"},
		{`"VULN_RESOLUTION_TENANT_ISOLATION"`,
			"down must restore the original vuln_resolution policy name"},
		{`"SLO_TARGETS_TENANT_ISOLATION"`,
			"down must restore the original slo_targets policy name"},
		{`"SSVC_ASSESSMENTS_TENANT_ISOLATION"`,
			"down must restore the original ssvc_assessments policy name"},
	} {
		if !strings.Contains(downUpper, m.needle) {
			t.Errorf("042_rls_force_uniformity.down.sql missing %q: %s", m.needle, m.why)
		}
	}
}

// Test043_RLSEnableGitHubSSVCHistory_ContainsHardening guards the M5
// Wave M5-1 ENABLE + FORCE + policy sweep over three previously-
// unguarded tenant-scoped tables: github_connections,
// github_repositories, ssvc_assessment_history. If anyone edits 043 to
// remove a load-bearing statement, this test fires before review.
func Test043_RLSEnableGitHubSSVCHistory_ContainsHardening(t *testing.T) {
	up := readMigration(t, "043_rls_enable_github_ssvc_history.up.sql")
	upUpper := strings.ToUpper(up)

	for _, tbl := range []string{
		"github_connections",
		"github_repositories",
		"ssvc_assessment_history",
	} {
		enableNeedle := strings.ToUpper("ALTER TABLE " + tbl + " ENABLE ROW LEVEL SECURITY")
		if !strings.Contains(upUpper, enableNeedle) {
			t.Errorf("043 missing %q -- M5-1 (a) ENABLE regression", enableNeedle)
		}
		// Note we tolerate both single- and double-space between
		// FORCE and ROW (the original migration uses a double space
		// for alignment with ENABLE).
		if !strings.Contains(upUpper, strings.ToUpper("ALTER TABLE "+tbl+" FORCE")) ||
			!strings.Contains(upUpper, "ROW LEVEL SECURITY") {
			t.Errorf("043 missing FORCE ROW LEVEL SECURITY on %s -- M5-1 (a) FORCE regression", tbl)
		}
		policyNeedle := strings.ToUpper("CREATE POLICY tenant_isolation_" + tbl + " ON " + tbl)
		if !strings.Contains(upUpper, policyNeedle) {
			t.Errorf("043 missing %q -- M5-1 (a) policy regression", policyNeedle)
		}
	}

	// ssvc_assessment_history-specific: the policy MUST use an
	// EXISTS subquery to ssvc_assessments because the table has no
	// tenant_id column. If a future refactor adds a tenant_id column
	// and switches to the standard pattern, this test will fire and
	// the maintainer should rewrite this assertion to match.
	if !strings.Contains(upUpper, "FROM SSVC_ASSESSMENTS A") {
		t.Error("043: ssvc_assessment_history policy must use EXISTS subquery to ssvc_assessments " +
			"(no tenant_id column on the history table). If you intentionally moved to a tenant_id " +
			"column, update this assertion.")
	}

	// Every policy must use the missing-OK GUC read.
	if !strings.Contains(upUpper, "CURRENT_SETTING('APP.CURRENT_TENANT_ID', TRUE)::UUID") {
		t.Error("043: must use current_setting('app.current_tenant_id', true)::UUID (M4 convention)")
	}
	if !strings.Contains(upUpper, "WITH CHECK") {
		t.Error("043: must contain explicit WITH CHECK clauses (M4 convention)")
	}

	// Down migration sanity.
	down := readMigration(t, "043_rls_enable_github_ssvc_history.down.sql")
	downUpper := strings.ToUpper(down)
	for _, tbl := range []string{
		"github_connections",
		"github_repositories",
		"ssvc_assessment_history",
	} {
		policyDrop := strings.ToUpper("DROP POLICY IF EXISTS tenant_isolation_" + tbl + " ON " + tbl)
		if !strings.Contains(downUpper, policyDrop) {
			t.Errorf("043 down missing %q -- reversibility regression", policyDrop)
		}
		if !strings.Contains(downUpper, strings.ToUpper("ALTER TABLE "+tbl+" DISABLE")) {
			t.Errorf("043 down missing DISABLE on %s -- reversibility regression", tbl)
		}
	}
}

// Test044_CompositeFKTenantProject_ContainsHardening guards the M5
// Wave M5-1 composite (tenant_id, project_id) FK sweep over the five
// remaining tables with hard project_id FKs (github_repositories,
// vulnerability_resolution_events, compliance_snapshots,
// ssvc_project_defaults, ssvc_assessments). F75 pattern from migration
// 041, horizontally applied.
func Test044_CompositeFKTenantProject_ContainsHardening(t *testing.T) {
	up := readMigration(t, "044_composite_fk_tenant_project.up.sql")
	upUpper := strings.ToUpper(up)

	// Pre-flight orphan check must exist and abort loudly. If anyone
	// removes it, ops would get an opaque generic FK violation
	// instead of a precise diagnostic.
	if !strings.Contains(upUpper, "DO $$") {
		t.Error("044: pre-flight orphan check DO $$ block must exist")
	}
	if !strings.Contains(upUpper, "RAISE EXCEPTION 'MIGRATION 044") {
		t.Error("044: orphan check must RAISE EXCEPTION with the migration tag so ops can grep logs")
	}

	for _, fkPair := range []struct {
		table, fkName string
	}{
		{"github_repositories", "github_repositories_tenant_project_fk"},
		{"vulnerability_resolution_events", "vuln_resolution_events_tenant_project_fk"},
		{"compliance_snapshots", "compliance_snapshots_tenant_project_fk"},
		{"ssvc_project_defaults", "ssvc_project_defaults_tenant_project_fk"},
		{"ssvc_assessments", "ssvc_assessments_tenant_project_fk"},
	} {
		fkNeedle := strings.ToUpper("ADD CONSTRAINT " + fkPair.fkName)
		if !strings.Contains(upUpper, fkNeedle) {
			t.Errorf("044 missing %q -- M5-1 (c) composite FK regression on %s",
				fkNeedle, fkPair.table)
		}
	}

	if !strings.Contains(upUpper, "FOREIGN KEY (TENANT_ID, PROJECT_ID)") {
		t.Error("044: every FK must reference the (tenant_id, project_id) pair, not project_id alone")
	}
	if !strings.Contains(upUpper, "REFERENCES PROJECTS (TENANT_ID, ID)") {
		t.Error("044: every FK must target the composite UNIQUE on projects(tenant_id, id) " +
			"(installed in migration 041)")
	}
	if !strings.Contains(upUpper, "ON DELETE CASCADE") {
		t.Error("044: every composite FK must CASCADE to keep parity with the existing project_id FK")
	}

	// Down migration must drop FKs in a safe order (children before
	// parents) and must use IF EXISTS for idempotency.
	down := readMigration(t, "044_composite_fk_tenant_project.down.sql")
	downUpper := strings.ToUpper(down)
	for _, fkName := range []string{
		"github_repositories_tenant_project_fk",
		"vuln_resolution_events_tenant_project_fk",
		"compliance_snapshots_tenant_project_fk",
		"ssvc_project_defaults_tenant_project_fk",
		"ssvc_assessments_tenant_project_fk",
	} {
		dropNeedle := strings.ToUpper("DROP CONSTRAINT IF EXISTS " + fkName)
		if !strings.Contains(downUpper, dropNeedle) {
			t.Errorf("044 down missing %q -- reversibility regression", dropNeedle)
		}
	}
}

// Test045_CompositeFKExtension_ContainsHardening guards the M5 Phase D
// Round 1 F81 extension over the seven older project-child tables missed
// by migration 044. It follows the F73/F75 content sanity pattern: no DB
// required, but the load-bearing pre-flight, tenant_id promotion, and
// composite FK statements must stay present.
func Test045_CompositeFKExtension_ContainsHardening(t *testing.T) {
	up := readMigration(t, "045_composite_fk_extension.up.sql")
	upUpper := strings.ToUpper(up)

	// Pre-flight orphan check must exist and abort loudly before the FK
	// statements run, otherwise existing cross-tenant rows would fail with
	// an opaque generic FK violation.
	if !strings.Contains(upUpper, "DO $$") {
		t.Error("045: pre-flight orphan check DO $$ block must exist")
	}
	if !strings.Contains(upUpper, "RAISE EXCEPTION 'MIGRATION 045") {
		t.Error("045: orphan check must RAISE EXCEPTION with the migration tag so ops can grep logs")
	}
	if !strings.Contains(up, "M5 Phase D Round 4 / F87") {
		t.Error("045: header must document the F87 RLS-bypassed diagnostic rationale")
	}

	for _, table := range []string{
		"sboms",
		"vulnerability_tickets",
	} {
		disableRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table +
			`\s+NO\s+FORCE\s+ROW\s+LEVEL\s+SECURITY\s*;\s*ALTER\s+TABLE\s+` + table +
			`\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY`)
		if !disableRe.MatchString(up) {
			t.Errorf("045 missing Step 1 RLS lift for %s before diagnostic SELECTs", table)
		}

		restoreRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table +
			`\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\s*;\s*ALTER\s+TABLE\s+` + table +
			`\s+FORCE\s+ROW\s+LEVEL\s+SECURITY`)
		if !restoreRe.MatchString(up) {
			t.Errorf("045 missing Step 5 ENABLE + FORCE RLS restore for %s", table)
		}
	}

	for _, fkPair := range []struct {
		table, fkName string
	}{
		{"sboms", "sboms_tenant_project_fk"},
		{"vex_statements", "vex_statements_tenant_project_fk"},
		{"license_policies", "license_policies_tenant_project_fk"},
		{"notification_settings", "notification_settings_tenant_project_fk"},
		{"notification_logs", "notification_logs_tenant_project_fk"},
		{"public_links", "public_links_tenant_project_fk"},
		{"vulnerability_tickets", "vulnerability_tickets_tenant_project_fk"},
	} {
		fkRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + fkPair.table +
			`\s+ADD\s+CONSTRAINT\s+` + fkPair.fkName +
			`\s+FOREIGN\s+KEY\s*\(\s*tenant_id\s*,\s*project_id\s*\)` +
			`\s+REFERENCES\s+projects\s*\(\s*tenant_id\s*,\s*id\s*\)` +
			`\s+ON\s+DELETE\s+CASCADE`)
		if !fkRe.MatchString(up) {
			t.Errorf("045 missing complete composite FK body for %s (%s) -- expected child(tenant_id, project_id) -> projects(tenant_id, id) ON DELETE CASCADE",
				fkPair.table, fkPair.fkName)
		}
	}

	for _, table := range []string{
		"vex_statements",
		"license_policies",
		"notification_settings",
		"notification_logs",
	} {
		notNullRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table + `\s+ALTER\s+COLUMN\s+tenant_id\s+SET\s+NOT\s+NULL`)
		if !notNullRe.MatchString(up) {
			t.Errorf("045 missing ALTER TABLE %s ALTER COLUMN tenant_id SET NOT NULL -- legacy nullable tenant_id was not promoted",
				table)
		}
	}
}

func Test045_CompositeFKExtension_DownReversibility(t *testing.T) {
	down := readMigration(t, "045_composite_fk_extension.down.sql")

	for _, fkPair := range []struct {
		table, fkName string
	}{
		{"sboms", "sboms_tenant_project_fk"},
		{"vex_statements", "vex_statements_tenant_project_fk"},
		{"license_policies", "license_policies_tenant_project_fk"},
		{"notification_settings", "notification_settings_tenant_project_fk"},
		{"notification_logs", "notification_logs_tenant_project_fk"},
		{"public_links", "public_links_tenant_project_fk"},
		{"vulnerability_tickets", "vulnerability_tickets_tenant_project_fk"},
	} {
		dropRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + fkPair.table +
			`\s+DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+` + fkPair.fkName)
		if !dropRe.MatchString(down) {
			t.Errorf("045 down missing DROP CONSTRAINT IF EXISTS %s on %s -- reversibility regression",
				fkPair.fkName, fkPair.table)
		}
	}

	for _, table := range []string{
		"vex_statements",
		"license_policies",
		"notification_settings",
		"notification_logs",
	} {
		dropNotNullRe := regexp.MustCompile(`(?is)ALTER\s+TABLE\s+` + table + `\s+ALTER\s+COLUMN\s+tenant_id\s+DROP\s+NOT\s+NULL`)
		if !dropNotNullRe.MatchString(down) {
			t.Errorf("045 down missing ALTER TABLE %s ALTER COLUMN tenant_id DROP NOT NULL -- nullable legacy shape not restored",
				table)
		}
	}
}

// Test048_LegacyScanSettingsLogsRLS_ContainsHardening guards the M13
// Phase D round 2 F185 fix. scan_settings + scan_logs shipped in
// migration 010 (legacy schema, pre-023 hardening sweep) carrying
// tenant_id but no RLS partner — the lint
// (tools/lint-migration-rls/main.go) exempted them with a F185 follow-up
// tracking note. Migration 048 added ENABLE + FORCE RLS + a FOR ALL
// USING+WITH CHECK policy on both tables, matching the 037/047 partner-
// migration pattern. If anyone edits 048 to remove a load-bearing
// statement (or merges it into 010 forward), this test fires before
// review.
func Test048_LegacyScanSettingsLogsRLS_ContainsHardening(t *testing.T) {
	up := readMigration(t, "048_legacy_scan_settings_logs_rls.up.sql")
	upUpper := strings.ToUpper(up)

	mustContain := []struct {
		needle string
		why    string
	}{
		// scan_settings half.
		{
			needle: "ALTER TABLE SCAN_SETTINGS ENABLE ROW LEVEL SECURITY",
			why:    "RLS must be ENABLED on scan_settings (F185 fix)",
		},
		{
			needle: "ALTER TABLE SCAN_SETTINGS FORCE",
			why:    "RLS must be FORCED on scan_settings so the migrator/owner does not bypass policy",
		},
		{
			needle: "CREATE POLICY TENANT_ISOLATION_SCAN_SETTINGS ON SCAN_SETTINGS",
			why:    "policy name must match the tenant_isolation_<table> convention used by 037/047",
		},
		// scan_logs half.
		{
			needle: "ALTER TABLE SCAN_LOGS ENABLE ROW LEVEL SECURITY",
			why:    "RLS must be ENABLED on scan_logs (F185 fix)",
		},
		{
			needle: "ALTER TABLE SCAN_LOGS FORCE",
			why:    "RLS must be FORCED on scan_logs so the migrator/owner does not bypass policy",
		},
		{
			needle: "CREATE POLICY TENANT_ISOLATION_SCAN_LOGS ON SCAN_LOGS",
			why:    "policy name must match the tenant_isolation_<table> convention used by 037/047",
		},
		// Shared shape (both policies use these).
		{needle: "FOR ALL", why: "policies must cover all command types (SELECT/INSERT/UPDATE/DELETE)"},
		{needle: "USING", why: "policies must have USING (read predicate)"},
		{needle: "WITH CHECK",
			why: "policies must have WITH CHECK (write predicate) -- blocks cross-tenant INSERT/UPDATE"},
		{
			needle: "CURRENT_SETTING('APP.CURRENT_TENANT_ID', TRUE)::UUID",
			why:    "predicate must read app.current_tenant_id GUC with missing_ok=true and cast to UUID",
		},
	}
	for _, m := range mustContain {
		if !strings.Contains(upUpper, m.needle) {
			t.Errorf("048_legacy_scan_settings_logs_rls.up.sql missing %q: %s",
				m.needle, m.why)
		}
	}

	// Down migration must clean up in the right order.
	down := readMigration(t, "048_legacy_scan_settings_logs_rls.down.sql")
	downUpper := strings.ToUpper(down)
	for _, m := range []struct {
		needle string
		why    string
	}{
		{"DROP POLICY IF EXISTS TENANT_ISOLATION_SCAN_LOGS ON SCAN_LOGS",
			"down must drop the scan_logs policy"},
		{"DROP POLICY IF EXISTS TENANT_ISOLATION_SCAN_SETTINGS ON SCAN_SETTINGS",
			"down must drop the scan_settings policy"},
		{"NO FORCE ROW LEVEL SECURITY", "down must unforce RLS on both tables"},
		{"DISABLE", "down must disable RLS"},
	} {
		if !strings.Contains(downUpper, m.needle) {
			t.Errorf("048_legacy_scan_settings_logs_rls.down.sql missing %q: %s",
				m.needle, m.why)
		}
	}
}

// Test010_ScanSettingsLogs_TablesStillExist ensures migration 010 still
// creates the two tables migration 048 depends on. If 010 is later
// renamed/removed without merging 048 forward, this test surfaces the
// dependency immediately (matches the Test018/Test036 pattern).
func Test010_ScanSettingsLogs_TablesStillExist(t *testing.T) {
	up := readMigration(t, "010_scan_settings.up.sql")
	for _, table := range []string{"scan_settings", "scan_logs"} {
		pattern := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?` + table)
		if !pattern.MatchString(up) {
			t.Fatalf("010_scan_settings.up.sql no longer creates %s; "+
				"048 RLS hardening will fail to apply", table)
		}
	}
}
