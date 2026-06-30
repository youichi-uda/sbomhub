// Tests for the migration RLS lint.
//
// The lint operates on a directory, so each scenario assembles its own
// temp directory from one or more fixtures under `testdata/`. We do NOT
// run the lint against `testdata/` itself because the negative fixture
// (`bad_no_rls.up.sql`) would always fail in that combined view — keeping
// scenarios in temp dirs lets us assert specific outcomes per fixture.
//
// Fixtures kept in `testdata/` (Go's special path the toolchain ignores
// for build) and copied into TempDir per test:
//
//	good_with_rls.up.sql     — CREATE TABLE + RLS triple in same file
//	bad_no_rls.up.sql        — CREATE TABLE only, no RLS, no suppression
//	suppress_comment.up.sql  — CREATE TABLE only, with `-- lint:no-rls-required:` marker
//
// We additionally build a "partner file" scenario inline (not stored as a
// reusable fixture, since it's two files coupled by name) so that the
// 036/037 + 046/047 production pattern has explicit test coverage.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyFixture copies one file out of testdata/ into dstDir under its
// original basename. Returns the destination path. Aborts the test on I/O
// error — fixture I/O failures point at a broken checkout, not at the
// code under test, so there is no benefit to letting downstream
// assertions also fail.
func copyFixture(t *testing.T, fixture, dstDir string) string {
	t.Helper()
	src := filepath.Join("testdata", fixture)
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	dst := filepath.Join(dstDir, fixture)
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write fixture copy %s: %v", dst, err)
	}
	return dst
}

// runLint drives the package-level `run` function with stdout/stderr
// buffers so assertions can inspect the produced text. Mirrors the
// CLI entry point's argv shape (no program name).
func runLint(t *testing.T, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	exit = run(args, &outBuf, &errBuf)
	return exit, outBuf.String(), errBuf.String()
}

// TestPositive_RLSInSameFile asserts the canonical happy path:
// a tenant_* table whose CREATE TABLE and ENABLE/FORCE/POLICY statements
// all live in the same migration file. Exit code 0, no findings.
func TestPositive_RLSInSameFile(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "good_with_rls.up.sql", dir)

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("expected exit 0 (clean), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "ok") {
		t.Errorf("expected stdout to contain 'ok' summary, got: %s", stdout)
	}
	if !strings.Contains(stdout, "1 tenant_* table(s) checked") {
		t.Errorf("expected count of 1, stdout=%q", stdout)
	}
	if stderr != "" {
		t.Errorf("expected clean stderr, got: %s", stderr)
	}
}

// TestNegative_NoRLS asserts that a CREATE TABLE without any RLS and
// without a suppression marker yields exit 1 and prints all three
// "missing" lines (ENABLE, FORCE, POLICY). The exact text is asserted so
// CI log scrapers can rely on a stable contract.
func TestNegative_NoRLS(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "bad_no_rls.up.sql", dir)

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 1 {
		t.Fatalf("expected exit 1 (fail), got %d; stdout=%q stderr=%q", exit, stdout, stderr)
	}
	wantStderrSubstrings := []string{
		"FAIL",
		"tenant_bad_example",
		"ALTER TABLE ... ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE ... FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation_... ON ...",
		// Fix hint must reference the partner-file pattern by name so a
		// reviewer following the error message lands on the actual
		// remediation precedent.
		"_rls.up.sql",
	}
	for _, want := range wantStderrSubstrings {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q; got: %s", want, stderr)
		}
	}
}

// TestSuppress_InlineComment asserts that the
// `-- lint:no-rls-required: <reason>` marker turns a missing-RLS table
// into a clean entry. The lint exits 0 and the verbose summary echoes the
// suppression reason verbatim — that echo is the audit trail.
func TestSuppress_InlineComment(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "suppress_comment.up.sql", dir)

	exit, stdout, stderr := runLint(t, "--dir", dir, "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0 (suppressed → clean), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "1 suppressed") {
		t.Errorf("expected '1 suppressed' in summary, got: %s", stdout)
	}
	if !strings.Contains(stdout, "shared global cache mirroring upstream advisory data") {
		t.Errorf("verbose output must echo suppression reason, got: %s", stdout)
	}
}

// TestPartnerFile_RLSInSiblingFile asserts the production
// 036→037 / 046→047 pattern: a CREATE TABLE in one file and the RLS
// triple in a sibling `<n>_<table>_rls.up.sql` file. Both files share a
// directory; the lint must aggregate evidence across them.
func TestPartnerFile_RLSInSiblingFile(t *testing.T) {
	dir := t.TempDir()

	const createBody = `
CREATE TABLE IF NOT EXISTS tenant_partner_example (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    payload TEXT NOT NULL
);
`
	const rlsBody = `
ALTER TABLE tenant_partner_example ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_partner_example FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenant_partner_example ON tenant_partner_example
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
`
	if err := os.WriteFile(filepath.Join(dir, "100_partner_table.up.sql"), []byte(createBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "101_partner_table_rls.up.sql"), []byte(rlsBody), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("expected exit 0 (partner file pattern), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stdout, "1 tenant_* table(s) checked") {
		t.Errorf("expected count of 1, stdout=%q", stdout)
	}
}

// TestPartialRLS_MissingForce verifies that a table with ENABLE + POLICY
// but NO FORCE still fails. This is the subtle 007-style miss that the
// lint exists to catch alongside the wholesale-missing case: without
// FORCE, the table owner silently bypasses the policy during ad-hoc
// maintenance / fixture loads, which is exactly how the 037 fix file
// justifies its FORCE statement.
func TestPartialRLS_MissingForce(t *testing.T) {
	dir := t.TempDir()
	const body = `
CREATE TABLE IF NOT EXISTS tenant_partial_example (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE
);
ALTER TABLE tenant_partial_example ENABLE ROW LEVEL SECURITY;
-- intentionally NO FORCE statement
CREATE POLICY tenant_isolation_tenant_partial_example ON tenant_partial_example
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
`
	if err := os.WriteFile(filepath.Join(dir, "001_partial.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, _, stderr := runLint(t, "--dir", dir)
	if exit != 1 {
		t.Fatalf("expected exit 1 (missing FORCE), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "FORCE ROW LEVEL SECURITY") {
		t.Errorf("expected FORCE-missing line, got: %s", stderr)
	}
	// And it must NOT complain about the two statements that ARE present.
	if strings.Contains(stderr, "missing: ALTER TABLE ... ENABLE") {
		t.Errorf("ENABLE was present, lint should not flag it: %s", stderr)
	}
	if strings.Contains(stderr, "missing: CREATE POLICY") {
		t.Errorf("POLICY was present, lint should not flag it: %s", stderr)
	}
}

// TestStructuralExemption asserts that the hardcoded `tenant_users`
// exemption pre-empts an otherwise-failing scan. The exemption mirrors
// production migration 007 — `tenant_users` is the tenant membership
// join table and cannot self-host an RLS policy.
func TestStructuralExemption(t *testing.T) {
	dir := t.TempDir()
	const body = `
CREATE TABLE tenant_users (
    tenant_id UUID NOT NULL,
    user_id   UUID NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);
`
	if err := os.WriteFile(filepath.Join(dir, "001_membership.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, _ := runLint(t, "--dir", dir, "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0 (structural exemption), got %d; stdout=%q", exit, stdout)
	}
	if !strings.Contains(stdout, "exempt:") {
		t.Errorf("expected verbose 'exempt:' line for tenant_users, got: %s", stdout)
	}
	if !strings.Contains(stdout, "self-referential") {
		t.Errorf("expected exemption justification in stdout, got: %s", stdout)
	}
}

// TestDownSqlIgnored makes sure rollback files don't pollute the scan.
// A `.down.sql` file that DROPs the policy must NOT count as missing
// RLS — those files describe rollback, not state.
func TestDownSqlIgnored(t *testing.T) {
	dir := t.TempDir()
	const upBody = `
CREATE TABLE IF NOT EXISTS tenant_down_example (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE
);
ALTER TABLE tenant_down_example ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_down_example FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenant_down_example ON tenant_down_example
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
`
	const downBody = `
DROP POLICY tenant_isolation_tenant_down_example ON tenant_down_example;
DROP TABLE tenant_down_example;
`
	if err := os.WriteFile(filepath.Join(dir, "001_x.up.sql"), []byte(upBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "001_x.down.sql"), []byte(downBody), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, _, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("expected exit 0 (down.sql ignored), got %d; stderr=%q", exit, stderr)
	}
}

// TestBadDir asserts that --dir pointing at a non-existent path yields
// the configuration-error exit code (2), not the fail exit code (1).
// This separation matters in CI: a misconfigured workflow should look
// distinct from a real RLS regression.
func TestBadDir(t *testing.T) {
	exit, _, stderr := runLint(t, "--dir", "/nonexistent/migrations/path")
	if exit != 2 {
		t.Fatalf("expected exit 2 (config error), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "read migrations directory") {
		t.Errorf("expected I/O error in stderr, got: %s", stderr)
	}
}

// TestLegacyNoRLS_NonPrefixDetected asserts F183 (M13-5 #91): a table
// whose name does NOT start with `tenant_` but whose CREATE TABLE body
// declares a `tenant_id` column is now detected by the lint. The fixture
// has no RLS evidence anywhere, so the lint must FAIL with the canonical
// missing-triple — proving the scope extension actually catches the
// non-prefixed failure class that the old prefix-only detector missed.
func TestLegacyNoRLS_NonPrefixDetected(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "legacy_no_rls.up.sql", dir)

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 1 {
		t.Fatalf("expected exit 1 (non-prefix tenant_id table missing RLS), got %d; stdout=%q stderr=%q",
			exit, stdout, stderr)
	}
	wantSubstrings := []string{
		"FAIL",
		"billing_records",
		"ALTER TABLE ... ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE ... FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_isolation_... ON ...",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q; got: %s", want, stderr)
		}
	}
}

// TestLegacyAlterPromote_RLSInSameFile asserts F183 (M13-5 #91): a table
// CREATEd without a tenant_id column but promoted to tenant-scoped by a
// later `ALTER TABLE … ADD COLUMN tenant_id` is detected and accepted
// when the same file provides the RLS triple. This mirrors how the lint
// behaves on the production 007 multitenancy migration once F183
// detection lands.
func TestLegacyAlterPromote_RLSInSameFile(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "legacy_alter_promote.up.sql", dir)

	exit, stdout, stderr := runLint(t, "--dir", dir, "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0 (legacy ALTER promote with RLS in same file), got %d; stderr=%q",
			exit, stderr)
	}
	if !strings.Contains(stdout, "1 tenant_* table(s) checked") {
		t.Errorf("expected count of 1, stdout=%q", stdout)
	}
	if !strings.Contains(stdout, "clean:      legacy_widget") {
		t.Errorf("expected verbose 'clean: legacy_widget' line, got: %s", stdout)
	}
}

// TestPartnerFile_AlterPromote asserts F183 (M13-5 #91): the production
// 007-style pattern where one migration ALTERs an existing tenantless
// table to add tenant_id and a PARTNER migration supplies the RLS triple.
// The lint's directory-wide evidence aggregation must accept this just
// like the existing 036→037 / 046→047 partner pattern for CREATE TABLE.
func TestPartnerFile_AlterPromote(t *testing.T) {
	dir := t.TempDir()

	const createBody = `
CREATE TABLE legacy_widget (
    id   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL
);
ALTER TABLE legacy_widget ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE;
`
	const rlsBody = `
ALTER TABLE legacy_widget ENABLE ROW LEVEL SECURITY;
ALTER TABLE legacy_widget FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_legacy_widget ON legacy_widget
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
`
	if err := os.WriteFile(filepath.Join(dir, "200_widget.up.sql"), []byte(createBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "201_widget_rls.up.sql"), []byte(rlsBody), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("expected exit 0 (partner RLS for ALTER-promoted table), got %d; stderr=%q",
			exit, stderr)
	}
	if !strings.Contains(stdout, "1 tenant_* table(s) checked") {
		t.Errorf("expected count of 1, stdout=%q", stdout)
	}
}

// TestStripBlockComments_LineCommentWithStarSlash regression-tests F183
// (M13-5 #91): a `--` line comment containing `/*` (e.g. a path like
// `service/llm/*` or `repository/*` in a header docstring) must NOT open
// a phantom block comment that swallows the rest of the file's RLS
// statements. The migrations 032 and 043 trip this exact pattern.
//
// Before the F183 stripBlockComments rewrite, the lint silently lost
// the RLS evidence past line 8 of 032 and line 65 of 043, which had
// gone undetected only because the legacy detector ignored non-prefix
// tables. F183 widened detection to cover them and immediately
// surfaced the lurking phantom-comment bug.
func TestStripBlockComments_LineCommentWithStarSlash(t *testing.T) {
	dir := t.TempDir()
	const body = `-- header note: service/llm/* writes one row here

CREATE TABLE phantom_test (
    id        UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);

ALTER TABLE phantom_test ENABLE ROW LEVEL SECURITY;
ALTER TABLE phantom_test FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_phantom_test ON phantom_test
    FOR ALL
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::UUID)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
`
	if err := os.WriteFile(filepath.Join(dir, "001_phantom.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("expected exit 0 (line-comment with /* must not swallow RLS), got %d; stdout=%q stderr=%q",
			exit, stdout, stderr)
	}
	if !strings.Contains(stdout, "1 tenant_* table(s) checked") {
		t.Errorf("expected count of 1, stdout=%q", stdout)
	}
}

// TestVulnerabilitiesExemption_NonPrefix asserts F183 (M13-5 #91): the
// 007-legacy `vulnerabilities` table (non-prefix, ALTER-promoted to
// carry tenant_id, intentionally NOT RLS-protected because CVE data is
// global) is recognised as a structural exemption — not flagged as a
// missing-RLS failure.
func TestVulnerabilitiesExemption_NonPrefix(t *testing.T) {
	dir := t.TempDir()
	const body = `
CREATE TABLE vulnerabilities (
    id     UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(50) NOT NULL
);
ALTER TABLE vulnerabilities ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL;
`
	if err := os.WriteFile(filepath.Join(dir, "001_vulns.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	exit, stdout, _ := runLint(t, "--dir", dir, "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0 (vulnerabilities structural exemption), got %d; stdout=%q",
			exit, stdout)
	}
	if !strings.Contains(stdout, "exempt:") || !strings.Contains(stdout, "vulnerabilities") {
		t.Errorf("expected verbose 'exempt: vulnerabilities' line, got: %s", stdout)
	}
	if !strings.Contains(stdout, "global CVE") {
		t.Errorf("expected exemption justification to mention 'global CVE', got: %s", stdout)
	}
}

// TestRealMigrations is the "smoke test against production" — it runs
// the lint against the actual `apps/api/migrations` directory. This
// guards against the failure mode where a refactor of the lint
// accidentally starts flagging a real migration that has been clean for
// months.
//
// We skip the test if the migrations dir cannot be located (e.g. the
// test is invoked from a context where the relative path doesn't
// resolve), so a `go test ./tools/lint-migration-rls/...` invocation
// from a vendored copy doesn't fail spuriously.
func TestRealMigrations(t *testing.T) {
	// The test binary's cwd is the package dir (`tools/lint-migration-rls`)
	// when invoked via `go test`. So `../../apps/api/migrations` resolves
	// to the repo's real migrations dir.
	dir := filepath.Join("..", "..", "apps", "api", "migrations")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("real migrations dir %q not reachable: %v", dir, err)
	}

	exit, stdout, stderr := runLint(t, "--dir", dir)
	if exit != 0 {
		t.Fatalf("real migrations failed lint! This is the regression you came here to fix.\nstdout=%s\nstderr=%s",
			stdout, stderr)
	}
}
