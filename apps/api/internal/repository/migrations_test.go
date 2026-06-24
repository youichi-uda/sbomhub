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
