// Tests for the migration lock-discipline lint.
//
// The lint operates on a directory, so each scenario assembles its own
// temp directory from one or more fixtures under `testdata/` — the same
// shape `tools/lint-migration-rls/main_test.go` uses, and for the same
// reason: several fixtures are deliberate failures and would poison a
// combined scan of `testdata/` itself.
//
// Every fixture is driven with `--baseline=false`. The built-in
// legacyBaseline names the 58 real migrations that are grandfathered; in
// a temp dir none of them exist, so leaving the baseline on would produce
// 58 findingUnknownBaseline records in every scenario. The baseline
// machinery is exercised directly against audit() instead, in
// TestBaseline_*.
//
// Fixtures use a `9xx_` prefix precisely so they can never collide with a
// real migration name and accidentally pick up a baseline waiver.
package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyFixture copies one file out of testdata/ into dstDir under its
// original basename. Aborts the test on I/O error — a fixture read
// failure points at a broken checkout, not at the code under test.
func copyFixture(t *testing.T, fixture, dstDir string) {
	t.Helper()
	src := filepath.Join("testdata", fixture)
	body, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, fixture), body, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
}

// runLint drives the package-level `run` with capture buffers, mirroring
// the CLI entry point's argv shape (no program name).
func runLint(t *testing.T, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	exit = run(args, &outBuf, &errBuf)
	return exit, outBuf.String(), errBuf.String()
}

// lintFixtures copies the named fixtures into a temp dir and lints it
// with the legacy baseline switched off.
func lintFixtures(t *testing.T, fixtures ...string) (exit int, stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	for _, f := range fixtures {
		copyFixture(t, f, dir)
	}
	return runLint(t, "--dir", dir, "--baseline=false")
}

// requireContains asserts every wanted substring is present, reporting
// all misses at once so one run shows the full picture.
func requireContains(t *testing.T, what, got string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s missing %q; got:\n%s", what, w, got)
		}
	}
}

// ---------------------------------------------------------------------
// The core rule
// ---------------------------------------------------------------------

func TestPositive_BudgetBeforeHeavy(t *testing.T) {
	exit, stdout, stderr := lintFixtures(t, "900_budget_before_heavy.up.sql")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stdout", stdout, "ok", "1 declare a budget")
	if stderr != "" {
		t.Errorf("expected clean stderr, got: %s", stderr)
	}
}

func TestNegative_NoBudget(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "901_no_budget.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr,
		"FAIL",
		"missing lock budget",
		"901_no_budget.up.sql:3",
		"takes ACCESS EXCLUSIVE on projects",
		"no `SET LOCAL lock_timeout` in the file",
		// The remediation must name the concrete form and the reason the
		// rollback is safe, otherwise the author has to go read the tool.
		"SET LOCAL lock_timeout = '5s';",
		"schema_migrations row back together",
	)
}

func TestNegative_BudgetAfterHeavy(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "902_budget_after_heavy.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr,
		"comes AFTER this statement",
		"only applies to statements that follow it",
	)
}

func TestNegative_SessionScopedBudget(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "903_session_scoped_budget.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr,
		"session-scoped `SET`, not `SET LOCAL`",
		"leaks onto the next migration's connection",
	)
}

func TestNegative_ZeroBudget(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "904_zero_budget.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "which disables the timeout")
}

// A budget that is later reset to 0 must not keep covering the DDL that
// follows the reset. This is why coveredAt() resolves the NEAREST
// preceding budget rather than "any budget in the file".
func TestNegative_BudgetResetBeforeHeavy(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "905_budget_reset_before_heavy.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "which disables the timeout", "'0'")
}

// ---------------------------------------------------------------------
// Same-file relations are exempt
// ---------------------------------------------------------------------

func TestPositive_SameFileRelationsExempt(t *testing.T) {
	exit, stdout, stderr := lintFixtures(t, "906_same_file_only.up.sql")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stdout", stdout, "1 take no contending lock")
}

// The measured asymmetry that CREATE TABLE is NOT automatically safe:
// the inline REFERENCES takes SHARE ROW EXCLUSIVE on the referenced
// table, which conflicts with any writer of that table.
func TestNegative_CreateTableReferencesExistingTable(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "907_references_existing.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "takes SHARE ROW EXCLUSIVE on tenants")
}

func TestPositive_CreateTableReferencesSameFileTable(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "908_references_same_file.up.sql")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
}

func TestPositive_QuotedAndSchemaQualifiedNamesMatch(t *testing.T) {
	// `ALTER TABLE public."sample_quoted"` must resolve to the same
	// relation as `CREATE TABLE public."sample_quoted"` two statements
	// earlier, otherwise the same-file exemption silently stops applying
	// to any migration that quotes or qualifies its names.
	exit, _, stderr := lintFixtures(t, "915_quoted_and_qualified.up.sql")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
}

// ---------------------------------------------------------------------
// The threshold
// ---------------------------------------------------------------------

// SHARE UPDATE EXCLUSIVE and ROW EXCLUSIVE are deliberately below the
// bar. Measured: neither VALIDATE CONSTRAINT nor COMMENT ON blocks behind
// a live SELECT or a live UPDATE.
func TestPositive_BelowThresholdNeedsNoBudget(t *testing.T) {
	exit, stdout, stderr := lintFixtures(t, "909_below_the_bar.up.sql")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stdout", stdout, "1 take no contending lock")
}

func TestNegative_DropForeignIndexIsHeavy(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "914_drop_foreign_index.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr,
		"takes ACCESS EXCLUSIVE on an unnamed pre-existing relation")
}

// ---------------------------------------------------------------------
// Statements the runner's transaction cannot execute
// ---------------------------------------------------------------------

// A budget does not make CONCURRENTLY legal — the fixture declares one
// and must still fail, with the CONCURRENTLY-specific remediation rather
// than the budget remediation.
func TestNegative_ConcurrentlyIsRejectedEvenWithBudget(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "910_concurrently.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr,
		"cannot run in the runner's transaction",
		"CREATE INDEX CONCURRENTLY cannot run inside a transaction block",
		"wrap each migration file in a",
	)
	if strings.Contains(stderr, "missing lock budget") {
		t.Errorf("CONCURRENTLY must not be reported as a budget problem; got:\n%s", stderr)
	}
}

// The baseline waives missing budgets only. A grandfathered file that
// somehow acquired a CONCURRENTLY statement must still fail.
func TestBaseline_DoesNotWaiveNonTransactional(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "910_concurrently.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	findings := audit(scans, map[string]baselineEntry{
		"910_concurrently.up.sql": {uncovered: 0, strongest: lockNone, note: "pretend legacy"},
	})
	var kinds []findingKind
	for _, f := range findings {
		kinds = append(kinds, f.kind)
	}
	if len(kinds) != 1 || kinds[0] != findingNonTransactional {
		t.Fatalf("expected exactly one findingNonTransactional, got %v", kinds)
	}
}

// ---------------------------------------------------------------------
// Unrecognised statements fail safe
// ---------------------------------------------------------------------

func TestNegative_UnclassifiedStatement(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "911_unclassified.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr,
		"unrecognised statement",
		"NOTIFY",
		"classifyStatement",
		"harmlessPrefixes",
	)
}

// ---------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------

// A DO block's body is full of semicolons, `--` comments and quoted text
// containing SQL keywords. If the lexer split on any of those, the
// fragments would surface as unclassified statements.
func TestLexer_DoBlockIsOneStatement(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "912_do_block.up.sql"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	stmts, lexErr := splitStatements(string(body))
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 1 {
		for i, s := range stmts {
			t.Logf("stmt %d @%d: %s", i, s.line, s.display())
		}
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	// The classifier charges every DO block ACCESS EXCLUSIVE (see
	// TestNegative_DoBlockWithStaticDDL), so this read-only fixture still
	// wants a budget — exactly ONE finding, which is the proof that the
	// body did not leak out as extra statements.
	exit, _, stderr := lintFixtures(t, "912_do_block.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	if n := strings.Count(stderr, "["); n != 1 {
		t.Errorf("expected exactly 1 finding from the DO block, got %d; stderr:\n%s", n, stderr)
	}
}

// A DO body that issues dynamic SQL is opaque to a textual scan, so it is
// charged the strongest lock rather than waved through.
func TestNegative_DoBlockWithExecute(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "913_do_execute.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on an unnamed pre-existing relation")
}

func TestLexer_CommentsAndLiterals(t *testing.T) {
	const body = `
-- a line comment with a ; and a /* that must not open a block comment
/* a block
   comment with a ; inside */
SELECT 'a string with a ; and a -- comment marker';
ALTER TABLE t ADD COLUMN c TEXT; -- trailing comment
`
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 2 {
		for i, s := range stmts {
			t.Logf("stmt %d: %q", i, s.text)
		}
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
	if !strings.HasPrefix(stmts[0].text, "SELECT") {
		t.Errorf("statement 0 should start at SELECT, got %q", stmts[0].text)
	}
	// scanText must have the literal CONTENT blanked so a keyword quoted
	// inside a string can never drive classification.
	if strings.Contains(stmts[0].scanText, "ALTER") || strings.Contains(stmts[0].scanText, "comment marker") {
		t.Errorf("string literal content leaked into scanText: %q", stmts[0].scanText)
	}
	// …while text keeps it, because the lock budget's value is a literal.
	if !strings.Contains(stmts[0].text, "comment marker") {
		t.Errorf("string literal content should survive in text, got %q", stmts[0].text)
	}
}

func TestLexer_LineNumbersArePreserved(t *testing.T) {
	// Line numbers drive the CI error output, and a comment-stripping bug
	// that dropped newlines would silently shift every reported line.
	const body = "-- one\n-- two\n\nALTER TABLE t ADD COLUMN c TEXT;\n"
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].line != 4 {
		t.Errorf("expected line 4, got %d", stmts[0].line)
	}
}

func TestLexer_EscapedQuoteStaysInsideLiteral(t *testing.T) {
	const body = `SELECT 'it''s fine; really';
ALTER TABLE t ADD COLUMN c TEXT;`
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 2 {
		for i, s := range stmts {
			t.Logf("stmt %d: %q", i, s.text)
		}
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

func TestLexer_DollarSignIsNotAlwaysAQuote(t *testing.T) {
	// `$1` is a bind placeholder, not a dollar-quote opener. If it were
	// treated as one, the rest of the file would be swallowed.
	const body = `SELECT $1;
ALTER TABLE t ADD COLUMN c TEXT;`
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

func TestLexer_TaggedDollarQuote(t *testing.T) {
	const body = `CREATE FUNCTION f() RETURNS trigger AS $body$
BEGIN
    RETURN NEW;  -- ; inside
END
$body$ LANGUAGE plpgsql;
ALTER TABLE t ADD COLUMN c TEXT;`
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 2 {
		for i, s := range stmts {
			t.Logf("stmt %d: %q", i, s.text)
		}
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

// ---------------------------------------------------------------------
// Budget value parsing
// ---------------------------------------------------------------------

// zeroTimeout is the test-facing wrapper around timeoutIsZero: a value
// the parser cannot read is not a usable budget either, so it counts as
// "does not bound the wait" for these assertions.
func zeroTimeout(v string) bool {
	zero, ok := timeoutIsZero(v)
	return !ok || zero
}

func TestIsZeroTimeout(t *testing.T) {
	zero := []string{"0", "'0'", "'0s'", "'0ms'", "DEFAULT", "default", " 0 "}
	nonZero := []string{"'5s'", "5000", "'500ms'", "'1min'", "'1h'"}
	for _, v := range zero {
		if !zeroTimeout(v) {
			t.Errorf("zeroTimeout(%q) = false, want true", v)
		}
	}
	for _, v := range nonZero {
		if zeroTimeout(v) {
			t.Errorf("zeroTimeout(%q) = true, want false", v)
		}
	}
}

func TestBudgetAcceptsToSyntax(t *testing.T) {
	// PostgreSQL accepts `SET x TO y` as well as `SET x = y`; a lint that
	// only knew `=` would demand a budget from a file that has one.
	dir := t.TempDir()
	const body = "SET LOCAL lock_timeout TO '5s';\nALTER TABLE projects ADD COLUMN c TEXT;\n"
	if err := os.WriteFile(filepath.Join(dir, "999_to_syntax.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
}

// A non-lock_timeout GUC must not be mistaken for a budget.
func TestOtherGucIsNotABudget(t *testing.T) {
	dir := t.TempDir()
	const body = "SET LOCAL statement_timeout = '5s';\nALTER TABLE projects ADD COLUMN c TEXT;\n"
	if err := os.WriteFile(filepath.Join(dir, "999_other_guc.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "no `SET LOCAL lock_timeout` in the file")
}

// ---------------------------------------------------------------------
// Baseline mechanics
// ---------------------------------------------------------------------

func TestBaseline_WaivesMissingBudget(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "901_no_budget.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	got := audit(scans, map[string]baselineEntry{
		"901_no_budget.up.sql": {
			uncovered: 1,
			strongest: lockAccessExclusive,
			digest:    scans[0].fingerprint(),
			note:      "pretend legacy",
		},
	})
	if len(got) != 0 {
		t.Fatalf("expected no findings, got %v", got)
	}
}

func TestBaseline_StaleEntryIsReported(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "900_budget_before_heavy.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	findings := audit(scans, map[string]baselineEntry{
		"900_budget_before_heavy.up.sql": {uncovered: 0, strongest: lockAccessExclusive, note: "pretend legacy"},
	})
	if len(findings) != 1 || findings[0].kind != findingStaleBaseline {
		t.Fatalf("expected one findingStaleBaseline, got %+v", findings)
	}
}

func TestBaseline_UnknownEntryIsReported(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "900_budget_before_heavy.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	findings := audit(scans, map[string]baselineEntry{
		"777_does_not_exist.up.sql": {uncovered: 1, strongest: lockAccessExclusive, note: "typo"},
	})
	if len(findings) != 1 || findings[0].kind != findingUnknownBaseline {
		t.Fatalf("expected one findingUnknownBaseline, got %+v", findings)
	}
}

// The shipped baseline must not name a file that has since been renamed
// or deleted, and every entry must carry a description a reviewer can
// check. Both are cheap invariants that keep the list honest between the
// full-directory runs CI does.
func TestBaseline_EntriesAreWellFormed(t *testing.T) {
	if len(legacyBaseline) == 0 {
		t.Fatal("legacyBaseline is empty")
	}
	for name, entry := range legacyBaseline {
		if !strings.HasSuffix(name, ".up.sql") {
			t.Errorf("baseline key %q is not an *.up.sql filename", name)
		}
		if strings.TrimSpace(entry.note) == "" {
			t.Errorf("baseline entry %q has no description", name)
		}
		if entry.uncovered < 1 {
			t.Errorf("baseline entry %q waives %d statements; an entry that waives nothing is stale", name, entry.uncovered)
		}
		if entry.strongest < budgetRequiredFrom {
			t.Errorf("baseline entry %q records %v, below the bar the lint enforces", name, entry.strongest)
		}
	}
}

// ---------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------

func TestUsageErrors(t *testing.T) {
	if exit, _, _ := runLint(t, "--dir", ""); exit != 2 {
		t.Errorf("empty --dir: expected exit 2, got %d", exit)
	}
	if exit, _, _ := runLint(t, "--dir", filepath.Join(t.TempDir(), "nope")); exit != 2 {
		t.Errorf("missing --dir: expected exit 2, got %d", exit)
	}
	if exit, _, _ := runLint(t, "--nonexistent-flag"); exit != 2 {
		t.Errorf("bad flag: expected exit 2, got %d", exit)
	}
}

func TestVerboseTableListsEveryFile(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "900_budget_before_heavy.up.sql", dir)
	copyFixture(t, "906_same_file_only.up.sql", dir)
	exit, stdout, stderr := runLint(t, "--dir", dir, "--baseline=false", "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stdout", stdout,
		"900_budget_before_heavy.up.sql",
		"906_same_file_only.up.sql",
		"declared",
		"no contending lock",
	)
}

// A directory with no *.up.sql is a usage error, not a clean scan: it
// almost always means --dir points somewhere wrong, and "ok — 0
// migration(s)" would be a green tick for having checked nothing
// . The check must not depend on the baseline flag.
func TestEmptyDirectoryIsUsageError(t *testing.T) {
	for _, args := range [][]string{
		{"--dir", t.TempDir(), "--baseline=false"},
		{"--dir", t.TempDir()},
	} {
		exit, stdout, stderr := runLint(t, args...)
		if exit != 2 {
			t.Errorf("%v: expected exit 2, got %d (stdout=%q)", args, exit, stdout)
		}
		requireContains(t, "stderr", stderr, "no *.up.sql files found")
	}
}

// `.down.sql` files are deliberately out of scope; the scan must not pick
// them up (a rollback is an operator action, never the automatic startup
// path).
func TestDownMigrationsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	body, err := os.ReadFile(filepath.Join("testdata", "901_no_budget.up.sql"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "901_no_budget.down.sql"), body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Paired with one clean *.up.sql so the empty-directory usage error
	// does not mask what this test is actually asserting.
	copyFixture(t, "906_same_file_only.up.sql", dir)
	exit, stdout, stderr := runLint(t, "--dir", dir, "--baseline=false")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stdout", stdout, "1 migration(s)")
}

// ---------------------------------------------------------------------
// Self-review round 1 regressions
// ---------------------------------------------------------------------

// A comma-separated ALTER TABLE action list is one statement, and its
// lock is the strongest of its actions. Classifying on the FIRST action
// alone let `VALIDATE CONSTRAINT c, ADD COLUMN z` — measured ACCESS
// EXCLUSIVE on PostgreSQL 15.18 — pass as SHARE UPDATE EXCLUSIVE, i.e. a
// silent bypass of the whole rule.
func TestNegative_MultiActionAlterIsNotDowngraded(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "916_multi_action_alter.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on components")
}

// `CREATE TABLE … PARTITION OF parent` takes ACCESS EXCLUSIVE on the
// pre-existing parent. Registering the new partition in createdRelations
// and finding no REFERENCES clause used to classify it as harmless.
func TestNegative_CreateTablePartitionOfLocksParent(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "917_partition_of.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on components")
}

// The trailing CASCADE / RESTRICT strip must match a whole word, not a
// substring: `audit_cascade` is a relation name, not a relation named
// `audit_` with a CASCADE modifier.
func TestRelationList_CascadeSuffixIsNotEaten(t *testing.T) {
	got := splitRelationList("audit_cascade")
	if len(got) != 1 || got[0] != "audit_cascade" {
		t.Errorf("splitRelationList(%q) = %v, want [audit_cascade]", "audit_cascade", got)
	}
	if got := splitRelationList("foo CASCADE"); len(got) != 1 || got[0] != "foo" {
		t.Errorf("splitRelationList(%q) = %v, want [foo]", "foo CASCADE", got)
	}
	if got := splitRelationList("foo, bar_restrict"); len(got) != 2 || got[1] != "bar_restrict" {
		t.Errorf("splitRelationList(%q) = %v, want [foo bar_restrict]", "foo, bar_restrict", got)
	}
	// The fixture exercises the same path through the real classifier.
	if exit, _, stderr := lintFixtures(t, "918_cascade_suffix.up.sql"); exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	} else if !strings.Contains(stderr, "audit_cascade") {
		t.Errorf("expected the un-truncated relation name in output; got:\n%s", stderr)
	}
}

// `00` and `0.0s` are both "wait forever" to PostgreSQL. Treating them as
// a real budget would let a migration opt out of the rule while looking
// compliant.
func TestIsZeroTimeout_PaddedAndFractionalZero(t *testing.T) {
	for _, v := range []string{"00", "'00'", "'0.0s'", "'000ms'", "'0.000s'"} {
		if !zeroTimeout(v) {
			t.Errorf("zeroTimeout(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"'0.5s'", "'10s'", "'1ms'"} {
		if zeroTimeout(v) {
			t.Errorf("zeroTimeout(%q) = true, want false", v)
		}
	}
}

// `$` is a legal identifier continuation character, so `begin$$`
// is one token. Opening a dollar quote there swallowed the ALTER TABLE
// between the two decoys.
func TestLexer_DollarInsideIdentifierIsNotAQuote(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "919_dollar_in_identifier.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on components")
}

// E-strings process backslash escapes even though plain strings
// do not (standard_conforming_strings = on). Terminating the literal at
// the escaped quote split the file mid-string and hid the ALTER.
func TestLexer_EStringBackslashEscape(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "920_estring.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on components")
}

// a DO body needs no EXECUTE to run DDL.
func TestNegative_DoBlockWithStaticDDL(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "921_do_static_ddl.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "ACCESS EXCLUSIVE")
}

// harmlessPrefixes waved through statements that take SHARE or
// stronger on a pre-existing object.
func TestNegative_PreviouslyHarmlessPrefixes(t *testing.T) {
	// The assertion has to name the lock, not just the exit code:
	// deleting the classifier rule would turn each fixture into
	// `unrecognised statement`, which also exits 1 and would have kept an
	// exit-only test green.
	cases := map[string]string{
		"922_create_or_replace_view.up.sql": "takes ACCESS EXCLUSIVE on component_summary",
		"923_alter_sequence.up.sql":         "takes SHARE ROW EXCLUSIVE on component_id_seq",
	}
	for f, want := range cases {
		exit, _, stderr := lintFixtures(t, f)
		if exit != 1 {
			t.Errorf("%s: expected exit 1, got %d; stderr=%s", f, exit, stderr)
			continue
		}
		requireContains(t, f+" stderr", stderr, "missing lock budget", want)
		if strings.Contains(stderr, "unrecognised statement") {
			t.Errorf("%s: must be classified, not unrecognised; got:\n%s", f, stderr)
		}
	}
}

// `IF NOT EXISTS` proves nothing about whether the
// relation was created by this file.
func TestNegative_IfNotExistsGrantsNoExemption(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "924_if_not_exists.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on maybe_existing")
}

// REINDEX SCHEMA / DATABASE / SYSTEM cannot run in the runner's
// transaction; a budget does not help.
func TestNegative_ReindexSchemaIsNonTransactional(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "925_reindex_schema.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "cannot run in the runner's transaction", "REINDEX SCHEMA")
}

// an unterminated construct means the lexer's view of the file
// diverged from PostgreSQL's. Certifying whatever survived would be a
// silent pass.
func TestNegative_UnterminatedBlockCommentIsReported(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "926_unterminated_block_comment.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "unterminated")
}

// PostgreSQL block comments nest, so the first `*/` does not
// necessarily close the comment.
func TestLexer_NestedBlockComment(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "927_nested_block_comment.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "takes ACCESS EXCLUSIVE on components")
	if strings.Contains(stderr, "unrecognised statement") {
		t.Errorf("nested comment should not leak SQL fragments; got:\n%s", stderr)
	}
}

// PostgreSQL rounds a lock_timeout value to whole milliseconds,
// so several spellings collapse to "wait forever". Measured on 15.18:
// '+0', '-0ms', '0.0s', '00', '0.4ms' all report an effective 0;
// '0.6ms' reports 1ms.
func TestIsZeroTimeout_MeasuredEffectiveZeroForms(t *testing.T) {
	for _, v := range []string{"'+0'", "'-0ms'", "'0.4ms'", "'0.0s'"} {
		if !zeroTimeout(v) {
			t.Errorf("zeroTimeout(%q) = false, want true", v)
		}
	}
	if zeroTimeout("'0.6ms'") {
		t.Errorf("zeroTimeout('0.6ms') = true, want false (measured effective 1ms)")
	}
}

// ANALYZE takes SHARE UPDATE EXCLUSIVE, not ACCESS SHARE.
// Still below the bar, but the classification must say what was measured.
func TestClassify_AnalyzeIsShareUpdateExclusive(t *testing.T) {
	st := newFileState()
	c := classifyStatement(statement{text: "ANALYZE components", scanText: "ANALYZE components"}, st)
	got, _ := c.maxClass(st)
	if got != lockShareUpdateExclusive {
		t.Errorf("ANALYZE classified as %v, want SHARE UPDATE EXCLUSIVE", got)
	}
}

// the waiver covers a reviewed FOOTPRINT, not a filename.
// Appending an unbudgeted statement to a grandfathered migration must not
// inherit its waiver.
func TestBaseline_DriftIsNotWaived(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "901_no_budget.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}

	// Fingerprint matches → waived.
	matching := map[string]baselineEntry{
		"901_no_budget.up.sql": {
			uncovered: 1,
			strongest: lockAccessExclusive,
			digest:    scans[0].fingerprint(),
			note:      "reviewed",
		},
	}
	if got := audit(scans, matching); len(got) != 0 {
		t.Fatalf("matching fingerprint should waive; got %+v", got)
	}

	// Count drifted (the file grew a statement) → not waived, and every
	// contending statement is reported.
	drifted := map[string]baselineEntry{
		"901_no_budget.up.sql": {
			uncovered: 2,
			strongest: lockAccessExclusive,
			digest:    scans[0].fingerprint(),
			note:      "reviewed",
		},
	}
	got := audit(scans, drifted)
	if len(got) < 2 {
		t.Fatalf("drifted fingerprint should report drift + the statements; got %+v", got)
	}
	if got[0].kind != findingBaselineDrift {
		t.Errorf("first finding should be findingBaselineDrift, got %v", got[0].kind)
	}
	if got[1].kind != findingMissingBudget {
		t.Errorf("second finding should be findingMissingBudget, got %v", got[1].kind)
	}

	// Strength drifted → also not waived.
	weaker := map[string]baselineEntry{
		"901_no_budget.up.sql": {
			uncovered: 1,
			strongest: lockShare,
			digest:    scans[0].fingerprint(),
			note:      "reviewed",
		},
	}
	if got := audit(scans, weaker); len(got) == 0 {
		t.Error("drifted lock class should not be waived")
	}

	// The case count-plus-class cannot see: same number of waived
	// statements at the same class, but a DIFFERENT statement. Only the
	// digest catches it.
	swapped := map[string]baselineEntry{
		"901_no_budget.up.sql": {
			uncovered: 1,
			strongest: lockAccessExclusive,
			digest:    "0000000000000000",
			note:      "reviewed against some other statement",
		},
	}
	got = audit(scans, swapped)
	if len(got) == 0 || got[0].kind != findingBaselineDrift {
		t.Errorf("a changed statement at the same count/class must report drift; got %+v", got)
	}
}

// each uncovered statement is diagnosed against the budget in
// force at ITS OWN position, not against the first uncovered statement's.
func TestBudgetDiagnosis_IsPerStatement(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "931_two_budgets.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr,
		"a_tbl",
		"the file's `SET … lock_timeout` (line 6) comes AFTER this statement",
		"c_tbl",
		"which disables the timeout",
	)
	if strings.Contains(stderr, "b_tbl") {
		t.Errorf("b_tbl is covered by the line-6 budget and must not be reported; got:\n%s", stderr)
	}
}

// findings within a file come out in source order even when the
// kinds interleave, and each kind's remediation is printed once.
func TestFindingsAreEmittedInSourceOrder(t *testing.T) {
	exit, _, stderr := lintFixtures(t, "932_interleaved_kinds.up.sql")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	iUnclassified := strings.Index(stderr, "unrecognised statement")
	iNonTx := strings.Index(stderr, "cannot run in the runner's transaction")
	if iUnclassified < 0 || iNonTx < 0 {
		t.Fatalf("expected both finding kinds; got:\n%s", stderr)
	}
	if iUnclassified > iNonTx {
		t.Errorf("line 3 finding must precede the line 4 finding; got:\n%s", stderr)
	}
	// Assert on a substring that really appears in the remediation block.
	// The earlier `> 1` form of this check passed vacuously against a
	// string the output never contained.
	if n := strings.Count(stderr, "it to classifyStatement"); n != 1 {
		t.Errorf("unclassified remediation printed %d times, want exactly 1; stderr:\n%s", n, stderr)
	}
	if n := strings.Count(stderr, "cannot be used in this repository"); n != 1 {
		t.Errorf("non-transactional remediation printed %d times, want exactly 1", n)
	}
}

// the summary buckets partition the scans exhaustively.
func TestSummariseBucketsArePartition(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{
		"900_budget_before_heavy.up.sql", // budgeted
		"901_no_budget.up.sql",           // missing (no baseline)
		"906_same_file_only.up.sql",      // clean
	} {
		copyFixture(t, f, dir)
	}
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	sum := summarise(scans, nil)
	if sum.total() != len(scans) {
		t.Errorf("buckets sum to %d, want %d (%+v)", sum.total(), len(scans), sum)
	}
	if sum.missing != 1 || sum.budgeted != 1 || sum.clean != 1 {
		t.Errorf("unexpected partition: %+v", sum)
	}
}

// a file the lexer could not finish has no lock conclusion, and
// the verbose table must not print one.
func TestVerboseTableMarksLexErrors(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "926_unterminated_block_comment.up.sql", dir)
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false", "--verbose")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "INVALID (lex error)")
	if strings.Contains(stderr, "no contending lock") {
		t.Errorf("lex-error file must not be certified as lock-free; got:\n%s", stderr)
	}
}

// PostgreSQL rounds lock_timeout half-to-EVEN, so '0.5ms' is an
// effective 0. Measured on 15.18: 0.4→0, 0.5→0, 0.6→1ms, 1.5→2ms,
// 2.5→2ms. Values PostgreSQL rejects outright are not budgets either.
func TestTimeoutIsZero_RoundHalfToEvenAndRange(t *testing.T) {
	cases := []struct {
		in       string
		zero, ok bool
	}{
		{"'0.4ms'", true, true},
		{"'0.5ms'", true, true},
		{"'0.6ms'", false, true},
		{"'1.5ms'", false, true},
		{"'2.5ms'", false, true},
		{"'5s'", false, true},
		{"'0'", true, true},
		{"DEFAULT", true, true},
		// Rejected by PostgreSQL: "outside the valid range for parameter
		// \"lock_timeout\" (0 .. 2147483647)".
		{"'-5s'", false, false},
		{"'2147483648ms'", false, false},
		{"'-0.5ms'", true, true}, // rounds to -0 → 0
		{"'not an interval'", false, false},
	}
	for _, c := range cases {
		zero, ok := timeoutIsZero(c.in)
		if zero != c.zero || ok != c.ok {
			t.Errorf("timeoutIsZero(%q) = (%v,%v), want (%v,%v)", c.in, zero, ok, c.zero, c.ok)
		}
	}
}

// a quoted relation name may contain whitespace; splitting the
// list on whitespace truncated it and silently changed which relation the
// same-file exemption applied to.
func TestSplitRelationList_QuotedWhitespace(t *testing.T) {
	got := splitRelationList(`"a b", "c d" CASCADE`)
	want := []string{"a b", "c d"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("item %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// `ALTER TYPE … ADD VALUE` takes no lock on a user relation
// (measured) and must not be reported.
func TestPositive_AlterTypeAddValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "993_enum.up.sql"),
		[]byte("ALTER TYPE ssvc_decision ADD VALUE 'deferred_v2';\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false"); exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	// Other ALTER TYPE forms stay unclassified rather than being guessed.
	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "994_enum_rename.up.sql"),
		[]byte("ALTER TYPE ssvc_decision RENAME TO ssvc_decision_v2;\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir2, "--baseline=false")
	if exit != 1 {
		t.Fatalf("ALTER TYPE … RENAME should be reported, got exit %d", exit)
	}
	// Specifically unrecognised — not "missing budget", which would mean
	// the lint had invented a lock class for it.
	requireContains(t, "stderr", stderr, "unrecognised statement")
	if strings.Contains(stderr, "missing lock budget") {
		t.Errorf("ALTER TYPE … RENAME must not be given a made-up lock class; got:\n%s", stderr)
	}
}

// the E-string branch must not eat the escape pair out of the
// literal-preserving text, which is what error output quotes back.
func TestLexer_EStringPreservesText(t *testing.T) {
	stmts, lexErr := splitStatements(`SELECT E'a\tb';`)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if !strings.Contains(stmts[0].text, `a\tb`) {
		t.Errorf("escape pair lost from text: %q", stmts[0].text)
	}
	// Exact equality: the earlier `Contains("a") && Contains("tb")` form
	// passed even with the whole literal leaked, because the backslash
	// sits between the two substrings.
	if got := stmts[0].scanText; got != `SELECT E''` {
		t.Errorf("scanText = %q, want %q", got, `SELECT E''`)
	}
}

// a drifted baseline must not be shown as waived in the table.
func TestVerboseTableMarksBaselineDrift(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "901_no_budget.up.sql", dir)
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	drifted := map[string]baselineEntry{
		"901_no_budget.up.sql": {uncovered: 1, strongest: lockAccessExclusive, digest: "deadbeefdeadbeef", note: "x"},
	}
	var buf bytes.Buffer
	printTable(&buf, scans, drifted)
	if !strings.Contains(buf.String(), "INVALID (baseline drift)") {
		t.Errorf("drifted entry must not read as waived; got:\n%s", buf.String())
	}
	// summarise() must agree with printTable and audit().
	if sum := summarise(scans, drifted); sum.waived != 0 || sum.missing != 1 {
		t.Errorf("drifted entry counted as waived: %+v", sum)
	}
}

// the unterminated-construct check covers every lexer state, and
// names the line the construct opened on.
func TestLexer_UnterminatedConstructs(t *testing.T) {
	cases := map[string]string{
		"block comment":     "SELECT 1;\n/* never closed\nSELECT 2;",
		"string literal":    "SELECT 1;\nSELECT 'never closed;",
		"quoted identifier": "SELECT 1;\nSELECT \"never closed;",
		"dollar body":       "SELECT 1;\nDO $$ BEGIN NULL;",
	}
	for name, body := range cases {
		_, lexErr := splitStatements(body)
		if lexErr == "" {
			t.Errorf("%s: expected a lex error", name)
			continue
		}
		if !strings.Contains(lexErr, "line 2") {
			t.Errorf("%s: expected the opening line in %q", name, lexErr)
		}
	}
}

// `CREATE INDEX IF NOT EXISTS` must not register a name that a
// later DROP INDEX then treats as this file's own.
func TestNegative_CreateIndexIfNotExistsThenDrop(t *testing.T) {
	dir := t.TempDir()
	body := "CREATE TABLE fresh (id UUID PRIMARY KEY);\n" +
		"CREATE INDEX IF NOT EXISTS live_idx ON fresh(id);\n" +
		"DROP INDEX live_idx;\n"
	if err := os.WriteFile(filepath.Join(dir, "995_idx.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	requireContains(t, "stderr", stderr, "ACCESS EXCLUSIVE")
}

// the `$`-anchored SUE subcommand regexes must only fire on a
// single-action ALTER TABLE.
func TestClassify_SetStorageAndStatisticsEndAnchors(t *testing.T) {
	cases := []struct {
		sql  string
		want lockClass
	}{
		{"ALTER TABLE t SET (fillfactor = 90)", lockShareUpdateExclusive},
		{"ALTER TABLE t SET (fillfactor = 90), ADD COLUMN z INTEGER", lockAccessExclusive},
		{"ALTER TABLE t ALTER COLUMN c SET STATISTICS 500", lockShareUpdateExclusive},
		{"ALTER TABLE t ALTER COLUMN c SET STATISTICS 500, ADD COLUMN z INTEGER", lockAccessExclusive},
		{"ALTER TABLE t VALIDATE CONSTRAINT c", lockShareUpdateExclusive},
		{"ALTER TABLE t VALIDATE CONSTRAINT c, ADD COLUMN z INTEGER", lockAccessExclusive},
	}
	for _, c := range cases {
		st := newFileState()
		got, _ := classifyStatement(statement{text: c.sql, scanText: c.sql}, st).maxClass(st)
		if got != c.want {
			t.Errorf("%s → %v, want %v", c.sql, got, c.want)
		}
	}
}

// a baselined file that also has a non-waivable finding must
// report that finding, and must not additionally be called stale.
func TestBaseline_DriftPlusNonTransactional(t *testing.T) {
	dir := t.TempDir()
	body := "CREATE INDEX CONCURRENTLY idx_probe ON components(name);\n" +
		"ALTER TABLE components ADD COLUMN drift_probe INTEGER;\n"
	if err := os.WriteFile(filepath.Join(dir, "996_mixed.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	findings := audit(scans, map[string]baselineEntry{
		"996_mixed.up.sql": {uncovered: 1, strongest: lockAccessExclusive, digest: "0000000000000000", note: "stale fingerprint"},
	})
	var kinds []findingKind
	for _, f := range findings {
		kinds = append(kinds, f.kind)
	}
	hasNonTx, hasStale := false, false
	for _, k := range kinds {
		if k == findingNonTransactional {
			hasNonTx = true
		}
		if k == findingStaleBaseline {
			hasStale = true
		}
	}
	if !hasNonTx {
		t.Errorf("non-transactional finding must survive a baseline entry; got %v", kinds)
	}
	if hasStale {
		t.Errorf("a file with other findings must not also be called stale; got %v", kinds)
	}
}

// quoted identifier whitespace is part of the name and must
// survive statement canonicalisation.
func TestLexer_QuotedIdentifierWhitespaceSurvives(t *testing.T) {
	stmts, lexErr := splitStatements(`ALTER TABLE "a  b" ADD COLUMN c TEXT;`)
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if !strings.Contains(stmts[0].scanText, `"a  b"`) {
		t.Errorf("quoted whitespace collapsed: %q", stmts[0].scanText)
	}
}

// The shipped baseline must round-trip: every entry's digest has to match
// what the current classifier computes for that file. This is the check
// that catches a hand-edited digest or a classifier change that silently
// invalidated the map — CI runs the real-directory scan, and this pins
// the same invariant in the unit suite.
func TestBaseline_DigestsAreWellFormed(t *testing.T) {
	for name, e := range legacyBaseline {
		if _, err := hex.DecodeString(e.digest); err != nil || len(e.digest) != 16 {
			t.Errorf("%s: digest %q is not 16 hex characters", name, e.digest)
		}
		if !strings.Contains(e.note, "the lint charges") {
			t.Errorf("%s: note does not describe the charged footprint: %q", name, e.note)
		}
	}
}

// The shipped baseline must still describe the real migrations directory.
// The earlier shape-only checks passed against a hand-edited digest or a
// renamed key; this one recomputes every fingerprint
// against the actual files, which is the same invariant CI enforces by
// running the real-directory scan.
func TestBaseline_MatchesRealMigrationsDirectory(t *testing.T) {
	// Not a t.Skip: the module always sits at tools/<name> in this
	// repository, so an absent directory means a broken checkout, and
	// skipping would make the whole real-directory assertion disappear
	// silently.
	const dir = "../../apps/api/migrations"
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("migrations directory not present at %s: %v", dir, err)
	}
	scans, err := scanDir(dir)
	if err != nil {
		t.Fatalf("scanDir: %v", err)
	}
	seen := make(map[string]bool, len(scans))
	for _, f := range scans {
		seen[f.name] = true
		entry, ok := legacyBaseline[f.name]
		switch {
		case !ok && len(f.uncovered) > 0:
			t.Errorf("%s needs a waiver but is not in legacyBaseline", f.name)
		case ok && len(f.uncovered) == 0:
			t.Errorf("%s is in legacyBaseline but no longer needs a waiver", f.name)
		case ok && !f.matchesBaseline(entry):
			t.Errorf("%s: baseline fingerprint is stale (have %d/%v/%s, file is %d/%v/%s)",
				f.name, entry.uncovered, entry.strongest, entry.digest,
				len(f.uncovered), f.strongest, f.fingerprint())
		}
		if f.lexError != "" {
			t.Errorf("%s: %s", f.name, f.lexError)
		}
	}
	for name := range legacyBaseline {
		if !seen[name] {
			t.Errorf("legacyBaseline names %q, which is not in %s", name, dir)
		}
	}

	// The per-file loop above checks the waiver bookkeeping; this checks
	// the same thing CI checks — that the directory produces NO findings
	// of any kind under the shipped baseline. Without it, appending
	// `NOTIFY probe;` or `VACUUM;` to a clean migration left this test
	// green while the CLI failed.
	if findings := audit(scans, legacyBaseline); len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("%s:%d [%s] %s", f.file, f.line, kindLabel(f.kind), f.detail)
		}
	}

	// The counts quoted in the package doc, the workflow header and
	// apps/api/migrations/CLAUDE.md are regression invariants, not
	// decoration.
	sum := summarise(scans, legacyBaseline)
	if sum.total() != len(scans) {
		t.Errorf("summary buckets sum to %d, want %d", sum.total(), len(scans))
	}
	if len(scans) != 65 || sum.statements != 638 || sum.clean != 5 || sum.budgeted != 2 || sum.waived != 58 || sum.missing != 0 {
		t.Errorf("documented totals drifted: %d migration(s) / %d statement(s), %+v "+
			"(docs say 65 / 638, 5 clean / 2 budgeted / 58 waived); "+
			"update the package doc, the workflow header and migrations/CLAUDE.md together with this assertion",
			len(scans), sum.statements, sum)
	}
}

// the digest is hashed over literal-preserving text, so rewriting
// a DO body from a read-only pre-flight into DDL changes it. Hashing
// scanText left `DO $$$$` for every DO block and the digest unchanged.
func TestBaseline_DigestSeesDoBodyChanges(t *testing.T) {
	fingerprintOf := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "997_do.up.sql"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		scans, err := scanDir(dir)
		if err != nil {
			t.Fatalf("scanDir: %v", err)
		}
		return scans[0].fingerprint()
	}
	readOnly := fingerprintOf(t, "DO $$ BEGIN PERFORM 1 FROM projects; END $$;\n")
	ddl := fingerprintOf(t, "DO $$ BEGIN ALTER TABLE audit_logs ADD COLUMN r4_probe integer; END $$;\n")
	if readOnly == ddl {
		t.Errorf("rewriting a DO body must change the digest; both are %s", readOnly)
	}
	// A comment-only edit must NOT churn the digest — otherwise the
	// baseline would need regenerating on every documentation pass.
	commented := fingerprintOf(t, "-- explanatory comment\nDO $$ BEGIN PERFORM 1 FROM projects; END $$;\n")
	if commented != readOnly {
		t.Errorf("a comment-only edit changed the digest: %s vs %s", commented, readOnly)
	}
}

// `--emit-baseline` regenerates the existing list; it must refuse
// to add a new file or to emit from a scan carrying a non-waivable
// finding.
func TestEmitBaseline_RefusesToBlessNewDebt(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "901_no_budget.up.sql", dir)
	exit, stdout, stderr := runLint(t, "--dir", dir, "--emit-baseline")
	if exit != 2 {
		t.Fatalf("expected exit 2, got %d (stdout=%q)", exit, stdout)
	}
	requireContains(t, "stderr", stderr, "not already grandfathered")

	dir2 := t.TempDir()
	copyFixture(t, "910_concurrently.up.sql", dir2)
	exit, _, stderr = runLint(t, "--dir", dir2, "--emit-baseline")
	if exit != 2 {
		t.Fatalf("non-transactional: expected exit 2, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "cannot run in the runner's transaction")
}

// EXCLUSIVE is its own mode. Measured on PostgreSQL 15.18:
// `LOCK TABLE t IN EXCLUSIVE MODE` and
// `REFRESH MATERIALIZED VIEW CONCURRENTLY mv` both report ExclusiveLock.
func TestClassify_ExclusiveIsDistinctFromAccessExclusive(t *testing.T) {
	cases := map[string]lockClass{
		"LOCK TABLE t IN EXCLUSIVE MODE":            lockExclusive,
		"REFRESH MATERIALIZED VIEW CONCURRENTLY mv": lockExclusive,
		"REFRESH MATERIALIZED VIEW mv":              lockAccessExclusive,
		"LOCK TABLE t IN ACCESS EXCLUSIVE MODE":     lockAccessExclusive,
		"LOCK TABLE t IN SHARE ROW EXCLUSIVE MODE":  lockShareRowExclusive,
	}
	for sql, want := range cases {
		st := newFileState()
		got, _ := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
		if got != want {
			t.Errorf("%s → %v, want %v", sql, got, want)
		}
	}
	if lockExclusive <= lockShareRowExclusive || lockExclusive >= lockAccessExclusive {
		t.Error("lockExclusive must rank between SHARE ROW EXCLUSIVE and ACCESS EXCLUSIVE")
	}
}

// the parameterless `CLUSTER` cannot run in a transaction, while
// `CLUSTER <table>` can (both measured).
func TestClassify_BareClusterIsNonTransactional(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "999_cluster.up.sql"),
		[]byte("SET LOCAL lock_timeout = '5s';\nCLUSTER;\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "CLUSTER without a table name cannot run inside a transaction block")

	st := newFileState()
	const withTable = "CLUSTER components USING idx_components_name"
	got, _ := classifyStatement(statement{text: withTable, scanText: withTable}, st).maxClass(st)
	if got != lockAccessExclusive {
		t.Errorf("CLUSTER <table> → %v, want ACCESS EXCLUSIVE", got)
	}
}

// a newline inside a dollar-quoted body is executable syntax: it
// terminates a `--` comment. Canonicalising it let a lock-taking DO body
// and a lock-free one hash identically, so the fingerprint text has to
// reproduce quoted content byte for byte.
func TestFingerprint_DollarBodyNewlinesAreSignificant(t *testing.T) {
	fp := func(t *testing.T, body string) string {
		t.Helper()
		stmts, lexErr := splitStatements(body)
		if lexErr != "" {
			t.Fatalf("unexpected lex error: %s", lexErr)
		}
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(stmts))
		}
		return stmts[0].fpText
	}
	// Identical text apart from where the newline falls; only the first
	// actually runs the ALTER.
	takesLock := fp(t, "DO $$ BEGIN -- noop\n  ALTER TABLE live_t ADD COLUMN c int;\n  NULL;\nEND $$;")
	commentedOut := fp(t, "DO $$ BEGIN -- noop ALTER TABLE live_t ADD COLUMN c int;\n  NULL;\nEND $$;")
	if takesLock == commentedOut {
		t.Errorf("dollar-body newline collapsed; both hash inputs are %q", takesLock)
	}

	// Outer-SQL formatting must NOT churn the fingerprint, or the baseline
	// would need regenerating on every reindent or comment pass.
	plain := fp(t, "ALTER TABLE t ADD COLUMN c TEXT;")
	reformatted := fp(t, "-- explanatory\nALTER   TABLE  t\n    ADD COLUMN c TEXT;")
	if plain != reformatted {
		t.Errorf("outer formatting churned the fingerprint: %q vs %q", plain, reformatted)
	}
}

// a comment added INSIDE a dollar-quoted body does change the
// digest. That is deliberate: the lint does not parse PL/pgSQL and cannot
// tell a comment there from code, so it treats the body as opaque bytes.
func TestFingerprint_DollarBodyCommentsAreOpaque(t *testing.T) {
	dir1, dir2 := t.TempDir(), t.TempDir()
	write := func(dir, body string) []fileScan {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "980_do.up.sql"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		scans, err := scanDir(dir)
		if err != nil {
			t.Fatalf("scanDir: %v", err)
		}
		return scans
	}
	a := write(dir1, "DO $$ BEGIN PERFORM 1; END $$;\n")
	b := write(dir2, "DO $$ BEGIN -- explanatory\n PERFORM 1; END $$;\n")
	if a[0].fingerprint() == b[0].fingerprint() {
		t.Error("a change inside an opaque DO body must change the digest")
	}
}

// PostgreSQL treats a comment as whitespace, so the fingerprint
// text needs the separator a comment leaves behind. Without it
// `ALTER/**/TABLE` canonicalised to `ALTERTABLE`, and two statements that
// differ only across a comment boundary could hash alike.
func TestFingerprint_CommentIsWhitespace(t *testing.T) {
	fp := func(t *testing.T, body string) string {
		t.Helper()
		stmts, lexErr := splitStatements(body)
		if lexErr != "" {
			t.Fatalf("unexpected lex error: %s", lexErr)
		}
		if len(stmts) != 1 {
			t.Fatalf("expected 1 statement, got %d", len(stmts))
		}
		return stmts[0].fpText
	}
	plain := fp(t, "ALTER TABLE t ADD COLUMN c TEXT;")
	for _, equivalent := range []string{
		"ALTER/**/TABLE t ADD COLUMN c TEXT;",
		"ALTER TABLE t -- note\n ADD COLUMN c TEXT;",
		"ALTER TABLE t /* note */ ADD COLUMN c TEXT;",
	} {
		if got := fp(t, equivalent); got != plain {
			t.Errorf("%q canonicalised to %q, want %q", equivalent, got, plain)
		}
	}
	// …and two genuinely different statements must not collide across a
	// comment boundary.
	withComment := fp(t, "LOCK TABLE stable, ONLY/**/foo IN EXCLUSIVE MODE;")
	fused := fp(t, "LOCK TABLE stable, ONLYfoo IN EXCLUSIVE MODE;")
	if withComment == fused {
		t.Errorf("comment boundary collapsed into a collision: %q", withComment)
	}
}

// Self-review find before round 7 — `LOCK TABLE <relation> IN <mode>
// MODE` was parsed with one regex whose optional trailing mode clause was
// ambiguous against its lazy relation-list group. For a relation
// legitimately named `only` it resolved to a relation called `in`.
func TestClassify_LockTableModeParsing(t *testing.T) {
	cases := []struct {
		sql      string
		relation string
		class    lockClass
	}{
		// `ONLY` is a reserved word, so a relation really named `only`
		// has to be quoted.
		{`LOCK TABLE "only" IN SHARE MODE`, "only", lockShare},
		{"LOCK TABLE live IN SHARE MODE", "live", lockShare},
		{"LOCK TABLE live", "live", lockAccessExclusive},
		{"LOCK live IN ACCESS EXCLUSIVE MODE", "live", lockAccessExclusive},
		{"LOCK TABLE live IN ROW EXCLUSIVE MODE NOWAIT", "live", lockRowExclusive},
		{"LOCK TABLE ONLY live IN EXCLUSIVE MODE", "live", lockExclusive},
		{"LOCK TABLE live NOWAIT", "live", lockAccessExclusive},
	}
	for _, c := range cases {
		st := newFileState()
		cl := classifyStatement(statement{text: c.sql, scanText: c.sql}, st)
		if len(cl.targets) != 1 {
			t.Errorf("%s: got %d targets, want 1 (%+v)", c.sql, len(cl.targets), cl.targets)
			continue
		}
		if cl.targets[0].relation != c.relation || cl.targets[0].class != c.class {
			t.Errorf("%s: got %s at %v, want %s at %v",
				c.sql, cl.targets[0].relation, cl.targets[0].class, c.relation, c.class)
		}
	}
}

// `RESET lock_timeout` and `RESET ALL` restore the server default
// of 0. An earlier `SET LOCAL` must stop counting from there.
func TestNegative_ResetCancelsTheBudget(t *testing.T) {
	for _, reset := range []string{"RESET lock_timeout;", "RESET ALL;"} {
		dir := t.TempDir()
		body := "SET LOCAL lock_timeout = '5s';\n" + reset + "\nALTER TABLE live ADD COLUMN r7_probe integer;\n"
		if err := os.WriteFile(filepath.Join(dir, "986_reset.up.sql"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
		if exit != 1 {
			t.Errorf("%s: expected exit 1, got %d; stderr=%s", reset, exit, stderr)
			continue
		}
		requireContains(t, reset, stderr, "which disables the timeout")
	}
}

// the per-item ONLY strip must be word-bounded, and must leave a
// relation actually named `only` (which has to be quoted, since ONLY is
// reserved) intact.
func TestSplitRelationList_OnlyBoundaries(t *testing.T) {
	cases := map[string][]string{
		`"only"`:           {"only"},
		`"ONLY"`:           {"ONLY"},
		`only_archive`:     {"only_archive"},
		`ONLY "only"`:      {"only"},
		`fresh, ONLY live`: {"fresh", "live"},
		`ONLY fresh, live`: {"fresh", "live"},
		`onlyfoo`:          {"onlyfoo"},
	}
	for in, want := range cases {
		got := splitRelationList(in)
		if len(got) != len(want) {
			t.Errorf("splitRelationList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitRelationList(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

// lintBody writes one statement body to a temp dir and lints it with the
// legacy baseline off. Used by the round-8 table-driven cases.
func lintBody(t *testing.T, body string) (int, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "987_r8.up.sql"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false")
	return exit, stderr
}

// PostgreSQL ends a line comment at a carriage return too.
// Ending only at `\n` let a CR-delimited file hide every statement.
func TestLexer_CarriageReturnEndsLineComment(t *testing.T) {
	stmts, lexErr := splitStatements("-- comment\rALTER TABLE live ADD COLUMN p INTEGER;\r")
	if lexErr != "" {
		t.Fatalf("unexpected lex error: %s", lexErr)
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	requireContains(t, "statement", stmts[0].text, "ALTER TABLE live")
	// CRLF must still count as one line.
	stmts, _ = splitStatements("-- a\r\n-- b\r\nALTER TABLE live ADD COLUMN p INTEGER;\r\n")
	if len(stmts) != 1 || stmts[0].line != 3 {
		t.Errorf("CRLF line counting: got %d statement(s) at line %d, want 1 at line 3",
			len(stmts), stmts[0].line)
	}
}

// not every ALTER TABLE storage parameter takes the weak lock.
// Measured on PostgreSQL 15.18: fillfactor / autovacuum_enabled /
// parallel_workers are SHARE UPDATE EXCLUSIVE, `user_catalog_table` is
// ACCESS EXCLUSIVE.
func TestClassify_StorageParameterLockLevels(t *testing.T) {
	cases := map[string]lockClass{
		"fillfactor = 70":                            lockShareUpdateExclusive,
		"autovacuum_enabled = false":                 lockShareUpdateExclusive,
		"parallel_workers = 2":                       lockShareUpdateExclusive,
		"toast.autovacuum_enabled = false":           lockShareUpdateExclusive,
		"fillfactor = 70, parallel_workers = 2":      lockShareUpdateExclusive,
		"user_catalog_table = true":                  lockAccessExclusive,
		"fillfactor = 70, user_catalog_table = true": lockAccessExclusive,
		"some_future_parameter = 1":                  lockAccessExclusive,
	}
	for params, want := range cases {
		sql := "ALTER TABLE live SET (" + params + ")"
		st := newFileState()
		got, _ := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
		if got != want {
			t.Errorf("%s → %v, want %v", sql, got, want)
		}
	}
}

// ---------------------------------------------------------------------
// Post-deletion review regressions
// ---------------------------------------------------------------------

// `standard_conforming_strings = off` changes whether a backslash escapes
// the following quote, and a session-scoped SET survives COMMIT onto the
// connection the NEXT migration file runs on. Measured: with the setting
// off, `SELECT 'it\'s ready'` returns `it's ready` — so a statement this
// lexer reads as string content is really executable DDL. An author
// importing legacy SQL writes this honestly, so it fails closed.
func TestNegative_StringModeChangeFailsClosed(t *testing.T) {
	for _, stmt := range []string{
		"SET standard_conforming_strings = off;",
		"SET LOCAL standard_conforming_strings = off;",
		`SET "standard_conforming_strings" TO off;`,
		"RESET standard_conforming_strings;",
	} {
		exit, stderr := lintBody(t, stmt+"\n")
		if exit != 1 {
			t.Errorf("%s: expected exit 1, got %d; stderr=%s", stmt, exit, stderr)
			continue
		}
		requireContains(t, stmt, stderr, "standard_conforming_strings")
	}
	// An unrelated GUC is still harmless.
	if exit, stderr := lintBody(t, "SET LOCAL statement_timeout = '5s';\n"+
		"CREATE TABLE fresh (id INTEGER);\n"); exit != 0 {
		t.Errorf("unrelated GUC: expected exit 0, got %d; stderr=%s", exit, stderr)
	}
}

// A `toast.` prefix selects the same parameter on the TOAST relation, so
// it must go through the SAME allowlist rather than being blanket-allowed.
func TestClassify_ToastStorageParameters(t *testing.T) {
	cases := map[string]lockClass{
		"toast.autovacuum_enabled = false":        lockShareUpdateExclusive,
		"toast.autovacuum_vacuum_cost_delay = 10": lockShareUpdateExclusive,
		"toast_tuple_target = 4096":               lockShareUpdateExclusive,
		"toast.user_catalog_table = true":         lockAccessExclusive,
		"toast.some_future_parameter = 1":         lockAccessExclusive,
	}
	for params, want := range cases {
		sql := "ALTER TABLE live SET (" + params + ")"
		st := newFileState()
		got, _ := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
		if got != want {
			t.Errorf("%s → %v, want %v", sql, got, want)
		}
	}
}

// A legacy schema can legitimately have a column named `"x ON decoy"`.
// The trigger target is the relation after the last `ON` OUTSIDE a quoted
// identifier, so the lazy scan must skip quoted spans.
func TestClassify_TriggerTargetSkipsQuotedSpans(t *testing.T) {
	const sql = `CREATE TRIGGER sync BEFORE UPDATE OF "x ON decoy" ON live FOR EACH ROW EXECUTE FUNCTION f()`
	st := newFileState()
	st.createdRelations["decoy"] = true
	got, rel := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
	if rel != "live" || got != lockShareRowExclusive {
		t.Errorf("got %v on %q, want SHARE ROW EXCLUSIVE on live", got, rel)
	}
	if exit, stderr := lintBody(t, "CREATE TABLE decoy (id INTEGER);\n"+sql+";\n"); exit != 1 {
		t.Errorf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
}

// Documented weak ALTER TABLE forms must not fall through to the ACCESS
// EXCLUSIVE default — that is a false positive an honest author hits.
// Measured on PostgreSQL 15.18, all ShareUpdateExclusiveLock.
func TestClassify_WeakAlterTableForms(t *testing.T) {
	cases := map[string]lockClass{
		"ALTER TABLE live CLUSTER ON live_idx": lockShareUpdateExclusive,
		"ALTER TABLE live SET WITHOUT CLUSTER": lockShareUpdateExclusive,
		// Measured: RESET takes the same lock as SET for the same
		// parameter.
		"ALTER TABLE live RESET (fillfactor)":         lockShareUpdateExclusive,
		"ALTER TABLE live RESET (user_catalog_table)": lockAccessExclusive,
		"ALTER TABLE live ADD COLUMN c INTEGER":       lockAccessExclusive,
		// A weak form combined with another action is still the strongest.
		"ALTER TABLE live CLUSTER ON live_idx, ADD COLUMN c INTEGER": lockAccessExclusive,
	}
	for sql, want := range cases {
		st := newFileState()
		got, _ := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
		if got != want {
			t.Errorf("%s → %v, want %v", sql, got, want)
		}
	}
}

// Measured: ATTACH PARTITION holds ShareUpdateExclusiveLock on the PARENT
// and AccessExclusiveLock on the relation being attached.
func TestClassify_AttachPartitionLockSplit(t *testing.T) {
	const sql = "ALTER TABLE live ATTACH PARTITION child FOR VALUES FROM (1) TO (10)"
	st := newFileState()
	c := classifyStatement(statement{text: sql, scanText: sql}, st)
	byRel := map[string]lockClass{}
	for _, tg := range c.targets {
		byRel[tg.relation] = tg.class
	}
	if byRel["live"] != lockShareUpdateExclusive {
		t.Errorf("parent live → %v, want SHARE UPDATE EXCLUSIVE", byRel["live"])
	}
	if byRel["child"] != lockAccessExclusive {
		t.Errorf("attached child → %v, want ACCESS EXCLUSIVE", byRel["child"])
	}
	// ATTACH also takes ACCESS EXCLUSIVE on the parent's DEFAULT
	// partition if one exists (measured). Whether it does is not knowable
	// from the migration text, so an unnamed target stands in for it —
	// which is what keeps the statement above the bar even when both
	// NAMED relations are below it.
	if exit, stderr := lintBody(t, "CREATE TABLE child (id INTEGER);\n"+sql+";\n"); exit != 1 {
		t.Errorf("expected exit 1 (possible default partition), got %d; stderr=%s", exit, stderr)
	}
	if exit, stderr := lintBody(t, "SET LOCAL lock_timeout = '5s';\n"+
		"CREATE TABLE child (id INTEGER);\n"+sql+";\n"); exit != 0 {
		t.Errorf("budgeted variant: expected exit 0, got %d; stderr=%s", exit, stderr)
	}
}

// `CREATE TABLE … INHERITS (parent)` takes SHARE UPDATE EXCLUSIVE on each
// parent (measured). Below the bar, but the reported strongest lock has
// to say what was measured.
func TestClassify_CreateTableInherits(t *testing.T) {
	const sql = "CREATE TABLE child (id INTEGER) INHERITS (live)"
	st := newFileState()
	got, rel := classifyStatement(statement{text: sql, scanText: sql}, st).maxClass(st)
	if got != lockShareUpdateExclusive || rel != "live" {
		t.Errorf("got %v on %q, want SHARE UPDATE EXCLUSIVE on live", got, rel)
	}
}

// A bare CR is a line break in EVERY lexer state, not only in stNormal —
// a file written with classic Mac line endings used to report every
// statement on line 1. Each case puts the break inside a different state
// and asserts the physical line of the statement that follows.
func TestLexer_BareCarriageReturnLineNumbers(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"stNormal":         {"SELECT 1;\rALTER TABLE live ADD COLUMN c INTEGER;\r", 2},
		"stLineComment":    {"-- note\rALTER TABLE live ADD COLUMN c INTEGER;\r", 2},
		"stBlockComment":   {"/* a\rb */\rALTER TABLE live ADD COLUMN c INTEGER;\r", 3},
		"stSingleQuote":    {"SELECT 'a\rb';\rALTER TABLE live ADD COLUMN c INTEGER;\r", 3},
		"stDoubleQuote":    {"SELECT 1 AS \"a\rb\";\rALTER TABLE live ADD COLUMN c INTEGER;\r", 3},
		"stDollarQuote":    {"SELECT $$a\rb$$;\rALTER TABLE live ADD COLUMN c INTEGER;\r", 3},
		"CRLF counts once": {"SELECT 1;\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 2},
	}
	for name, c := range cases {
		stmts, lexErr := splitStatements(c.body)
		if lexErr != "" {
			t.Errorf("%s: unexpected lex error: %s", name, lexErr)
			continue
		}
		if len(stmts) == 0 {
			t.Errorf("%s: no statements", name)
			continue
		}
		// The ALTER is always the LAST statement: a comment-only prefix
		// yields no statement of its own.
		last := stmts[len(stmts)-1]
		if !strings.HasPrefix(last.text, "ALTER TABLE") {
			t.Errorf("%s: last statement is %q, want the ALTER", name, last.text)
			continue
		}
		if last.line != c.want {
			t.Errorf("%s: ALTER at line %d, want %d", name, last.line, c.want)
		}
	}
}

// Findings on the SAME line come out in statement order, not grouped by
// kind.
func TestFindingsOnOneLineKeepSourceOrder(t *testing.T) {
	exit, stderr := lintBody(t, "NOTIFY first; VACUUM; ALTER TABLE live ADD COLUMN c INTEGER;\n")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d; stderr=%s", exit, stderr)
	}
	iNotify := strings.Index(stderr, "NOTIFY first")
	iVacuum := strings.Index(stderr, "VACUUM")
	if iNotify < 0 || iVacuum < 0 {
		t.Fatalf("expected both statements in the output:\n%s", stderr)
	}
	if iNotify > iVacuum {
		t.Errorf("NOTIFY (statement 1) must precede VACUUM (statement 2):\n%s", stderr)
	}
}

// The verbose table must not certify a file the lint could not classify.
func TestVerboseTableMarksUnclassifiedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "989_unclassified.up.sql"),
		[]byte("NOTIFY deployment_channel;\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	exit, _, stderr := runLint(t, "--dir", dir, "--baseline=false", "--verbose")
	if exit != 1 {
		t.Fatalf("expected exit 1, got %d", exit)
	}
	requireContains(t, "stderr", stderr, "INVALID (unclassified statement)")
	if strings.Contains(stderr, "no contending lock") {
		t.Errorf("an unclassified file must not read as lock-free:\n%s", stderr)
	}
}

// A CRLF pair counts as ONE line in every lexer state. Counting `\r` and
// `\n` separately inside a quoted construct reported every later
// statement one line too far.
func TestLexer_CRLFInsideQuotedStates(t *testing.T) {
	cases := map[string]struct {
		body string
		want int
	}{
		"stSingleQuote":               {"SELECT 'a\r\nb';\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 3},
		"stDoubleQuote":               {"SELECT 1 AS \"a\r\nb\";\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 3},
		"stDollarQuote":               {"SELECT $$a\r\nb$$;\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 3},
		"stBlockComment":              {"/* a\r\nb */\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 3},
		"E-string escaping a bare CR": {"SELECT E'a\\\rb';\rALTER TABLE live ADD COLUMN c INTEGER;\r", 3},
		"E-string escaping LF":        {"SELECT E'a\\\nb';\nALTER TABLE live ADD COLUMN c INTEGER;\n", 3},
		"E-string escaping CRLF":      {"SELECT E'a\\\r\nb';\r\nALTER TABLE live ADD COLUMN c INTEGER;\r\n", 3},
	}
	for name, c := range cases {
		stmts, lexErr := splitStatements(c.body)
		if lexErr != "" {
			t.Errorf("%s: unexpected lex error: %s", name, lexErr)
			continue
		}
		last := stmts[len(stmts)-1]
		if !strings.HasPrefix(last.text, "ALTER TABLE") {
			t.Errorf("%s: last statement is %q, want the ALTER", name, last.text)
			continue
		}
		if last.line != c.want {
			t.Errorf("%s: ALTER at line %d, want %d", name, last.line, c.want)
		}
	}
	// The quoted bytes themselves must still survive verbatim, because
	// the baseline digests hash fpText.
	stmts, _ := splitStatements("SELECT $$a\r\nb$$;")
	if !strings.Contains(stmts[0].fpText, "a\r\nb") {
		t.Errorf("dollar body lost its CRLF: %q", stmts[0].fpText)
	}
}

// `ATTACH … DEFAULT` proves the parent had no default partition, and a
// parent this file created can only have partitions this transaction
// made. Neither can hit the unnamed default-partition placeholder.
func TestClassify_AttachDefaultNeedsNoPlaceholder(t *testing.T) {
	// A table cannot have two default partitions, so a successful
	// `ATTACH … DEFAULT` proves there was none to lock.
	if exit, stderr := lintBody(t, "CREATE TABLE child (id INTEGER);\n"+
		"ALTER TABLE live_parent ATTACH PARTITION child DEFAULT;\n"); exit != 0 {
		t.Errorf("ATTACH … DEFAULT: expected exit 0, got %d; stderr=%s", exit, stderr)
	}
	// Every other ATTACH keeps the placeholder — including one whose
	// PARENT this file created, because ATTACH can attach a pre-existing
	// table, so such a parent can still have a default partition it did
	// not create.
	needBudget := map[string]string{
		"pre-existing parent": "CREATE TABLE child (id INTEGER);\n" +
			"ALTER TABLE live_parent ATTACH PARTITION child FOR VALUES FROM (1) TO (10);\n",
		"parent created in this file": "CREATE TABLE parent (id INTEGER) PARTITION BY RANGE (id);\n" +
			"CREATE TABLE child (id INTEGER);\n" +
			"ALTER TABLE parent ATTACH PARTITION child FOR VALUES FROM (1) TO (10);\n",
		"pre-existing table attached as the default of a new parent": "CREATE TABLE new_parent (id INTEGER) PARTITION BY RANGE (id);\n" +
			"SET LOCAL lock_timeout = '5s';\n" +
			"ALTER TABLE new_parent ATTACH PARTITION live_default DEFAULT;\n" +
			"RESET lock_timeout;\n" +
			"CREATE TABLE fresh_child (id INTEGER);\n" +
			"ALTER TABLE new_parent ATTACH PARTITION fresh_child FOR VALUES FROM (0) TO (10);\n",
	}
	for name, body := range needBudget {
		if exit, stderr := lintBody(t, body); exit != 1 {
			t.Errorf("%s: expected exit 1, got %d; stderr=%s", name, exit, stderr)
		}
	}
}
