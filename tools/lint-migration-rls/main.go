// Package main implements the migration RLS lint — a defensive CI gate that
// guarantees every new `tenant_*` table in apps/api/migrations carries a
// matching Row Level Security (RLS) policy.
//
// Why this exists
// ===============
//
// SBOMHub's multi-tenant data model relies on PostgreSQL RLS as the
// authoritative isolation boundary (the application-layer
// `WHERE tenant_id = $1` filter is treated as defense-in-depth, not the
// primary control). Two production migrations historically forgot to
// `ENABLE ROW LEVEL SECURITY` on a tenant-scoped table:
//
//   - 036_tenant_llm_config (encrypted BYOK API keys) → patched by
//     037_tenant_llm_config_rls.
//   - 046_diff_webhook_settings (encrypted webhook secrets) → patched by
//     047_tenant_diff_webhook_settings_rls.
//
// Both were caught only by an external review pass (Codex M11 review F167).
// This lint is the M13-5 follow-up that prevents the same class of miss
// from reaching `main` again — it runs as a hard gate in CI on every PR
// that touches `apps/api/migrations/**`.
//
// Detection rule
// ==============
//
// For every `CREATE TABLE [IF NOT EXISTS] tenant_*` statement in any
// `*.up.sql` under the target directory, the table is considered
// "RLS-clean" iff **all three** of the following statements exist somewhere
// in the same directory (any file, in any order — including a dedicated
// `<n>_<table>_rls.up.sql` partner file):
//
//  1. `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY`
//  2. `ALTER TABLE <table> FORCE  ROW LEVEL SECURITY`
//  3. `CREATE POLICY tenant_isolation_<…> ON <table>`
//
// The "any file in the directory" rule is what lets the partner-file
// pattern (046 + 047) pass without amending 046 in place — operators that
// already migrated past 046 still pick up the RLS transition through the
// normal migrate-up sequence on 047.
//
// Suppression
// ===========
//
// A migration may suppress the lint for a specific table by including an
// inline marker comment on any line of the file that defines the table:
//
//	-- lint:no-rls-required: <reason>
//
// The reason is mandatory and is echoed back in lint output for audit.
// Suppression should be used only for tables that genuinely cannot be RLS-
// protected (e.g. the `tenant_users` membership join table, which IS the
// source of truth for tenant identity and therefore cannot be filtered by
// it). Each suppression should be reviewed at PR time.
//
// Exit codes
// ==========
//
//	0 — all `tenant_*` tables are either RLS-protected or explicitly suppressed.
//	1 — at least one `tenant_*` table is missing RLS and has no suppression.
//	2 — usage / I/O error (bad --dir, unreadable file, etc.).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// rePatterns groups the regexps the lint scans for. They are compiled once
// at package init so the tool can be invoked repeatedly (e.g. by a `go test`
// driver that runs many fixtures) without re-compilation overhead.
//
// Each pattern is intentionally tolerant of whitespace variation
// (`\s+` rather than literal spaces) and case (`(?i)`) because hand-written
// migrations have a long tail of formatting quirks — we want the lint to
// catch the offending CREATE TABLE no matter how it was indented.
var (
	// CREATE TABLE [IF NOT EXISTS] tenant_<something> (
	//
	// Captures the bare table name (the part after the optional
	// IF NOT EXISTS) for cross-file RLS lookup. The trailing `\(` anchor
	// prevents accidental matches against, e.g., a CREATE INDEX line that
	// happens to mention `tenant_foo` in its name.
	reCreateTenantTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(tenant_[a-z0-9_]+)\s*\(`)

	// ALTER TABLE <name> ENABLE ROW LEVEL SECURITY
	reEnableRLS = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z0-9_]+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY`)

	// ALTER TABLE <name> FORCE [ROW LEVEL SECURITY]
	//
	// `FORCE ROW LEVEL SECURITY` is critical: without it the table owner
	// (the migrator role used in tests / fixtures / ad-hoc maintenance)
	// silently bypasses the policy. The 037 / 047 fix files both include
	// this; the lint requires it for forward-compatibility with the same
	// pattern.
	reForceRLS = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z0-9_]+)\s+FORCE\s+(?:ROW\s+LEVEL\s+SECURITY|RLS)`)

	// CREATE POLICY tenant_isolation_<…> ON <table>
	//
	// The `tenant_isolation_` prefix is the project-wide convention (see
	// 007_multitenancy.up.sql, 037_tenant_llm_config_rls.up.sql,
	// 047_tenant_diff_webhook_settings_rls.up.sql). Requiring it keeps the
	// lint from being fooled by an arbitrary CREATE POLICY that doesn't
	// actually implement tenant isolation.
	rePolicyOn = regexp.MustCompile(`(?i)CREATE\s+POLICY\s+tenant_isolation_[a-z0-9_]+\s+ON\s+([a-z0-9_]+)`)

	// -- lint:no-rls-required: <reason>
	//
	// The reason is captured for echo-back. We intentionally do not allow
	// a bare `-- lint:no-rls-required` with no reason — every suppression
	// should be auditable.
	reSuppress = regexp.MustCompile(`(?i)--\s*lint:no-rls-required:\s*(.+?)\s*$`)
)

// statementCoverage records which of the three required RLS statements have
// been seen for a given table name, across every `*.up.sql` file in the
// linted directory. A table is RLS-clean iff all three booleans are true.
type statementCoverage struct {
	enable bool
	force  bool
	policy bool
}

// missing returns the human-readable list of the statements that have NOT
// been seen for this table, in the canonical ENABLE → FORCE → POLICY order
// (so error output is deterministic and easy to grep / diff in CI logs).
func (c statementCoverage) missing() []string {
	var out []string
	if !c.enable {
		out = append(out, "ALTER TABLE ... ENABLE ROW LEVEL SECURITY")
	}
	if !c.force {
		out = append(out, "ALTER TABLE ... FORCE ROW LEVEL SECURITY")
	}
	if !c.policy {
		out = append(out, "CREATE POLICY tenant_isolation_... ON ...")
	}
	return out
}

// tableSite records where a `tenant_*` table was originally defined
// (CREATE TABLE statement) so that error output can point the reader at
// the offending migration file + line, and so the suppression check can
// scan the same file for an inline `-- lint:no-rls-required:` marker.
type tableSite struct {
	name string
	file string
	line int
}

// scanResult is the aggregated output of one directory scan.
type scanResult struct {
	// created holds every `tenant_*` CREATE TABLE found, in stable
	// source-order across files. We do NOT dedupe by table name here:
	// a duplicate CREATE TABLE in two different migrations is itself a
	// red flag the reviewer should see.
	created []tableSite

	// coverage maps table name → which RLS statements have been seen
	// anywhere in the directory.
	coverage map[string]*statementCoverage

	// suppressions maps table name → reason, populated when the file
	// that CREATEd the table includes an inline `-- lint:no-rls-required:`
	// marker. The reason is echoed in --verbose output but does not
	// affect exit code (suppressed tables are treated as clean).
	suppressions map[string]string
}

// newScanResult constructs an empty scanResult with non-nil maps so the
// scanning loop can `result.coverage[name] = …` without per-call nil
// checks.
func newScanResult() *scanResult {
	return &scanResult{
		coverage:     make(map[string]*statementCoverage),
		suppressions: make(map[string]string),
	}
}

// scanDir walks `dir` for every `*.up.sql` file (non-recursive — the
// migrations directory is flat by convention) and aggregates RLS evidence
// across all of them.
//
// The two-pass shape (collect CREATE TABLEs first, then check coverage)
// is deliberate: a `tenant_<foo>` table created in file N can legitimately
// be RLS'd in a partner file N+1 (the 036/037 and 046/047 pattern), so we
// MUST read the whole directory before deciding anything.
func scanDir(dir string) (*scanResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory %q: %w", dir, err)
	}

	// Stable lex sort so output (and any error messages) are deterministic
	// across operating systems — os.ReadDir's order is filesystem-defined.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	result := newScanResult()

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// `.down.sql` files describe rollback steps. RLS state in a down
		// migration would DISABLE the policy (the inverse of what we
		// want), so we skip them entirely.
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}

		path := filepath.Join(dir, name)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", path, err)
		}
		if err := scanFile(name, string(body), result); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// scanFile records, for one migration file's body, every `tenant_*`
// CREATE TABLE it defines AND every RLS evidence statement it contains
// (regardless of which table that statement targets — RLS statements for a
// table created in a different file still count).
//
// The function takes `name` (basename) rather than the full path so that
// fixtures driven from `*_test.go` can pass synthetic names that show up
// nicely in error messages.
func scanFile(name, body string, result *scanResult) error {
	// Pre-strip block comments `/* ... */` so that a sample SQL snippet
	// inside a comment cannot accidentally trip the lint. Line comments
	// are handled in-loop because the suppression marker IS a line comment
	// and we need to find it.
	stripped := stripBlockComments(body)

	lines := strings.Split(stripped, "\n")
	for i, line := range lines {
		lineNumber := i + 1 // 1-indexed, the way editors / git blame show it

		// Suppression marker — recorded against every CREATE TABLE in
		// this file. We attach the reason post-loop after we know which
		// tables were defined.
		if m := reSuppress.FindStringSubmatch(line); m != nil {
			// We tag the suppression by file name; the post-loop fixup
			// resolves which tables it applies to.
			result.suppressions[name] = strings.TrimSpace(m[1])
		}

		// Drop everything after `--` so that an RLS statement quoted
		// inside a line comment doesn't count as evidence.
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}

		if m := reCreateTenantTable.FindStringSubmatch(line); m != nil {
			result.created = append(result.created, tableSite{
				name: strings.ToLower(m[1]),
				file: name,
				line: lineNumber,
			})
		}
		if m := reEnableRLS.FindStringSubmatch(line); m != nil {
			tbl := strings.ToLower(m[1])
			ensureCoverage(result, tbl).enable = true
		}
		if m := reForceRLS.FindStringSubmatch(line); m != nil {
			tbl := strings.ToLower(m[1])
			ensureCoverage(result, tbl).force = true
		}
		if m := rePolicyOn.FindStringSubmatch(line); m != nil {
			tbl := strings.ToLower(m[1])
			ensureCoverage(result, tbl).policy = true
		}
	}
	return nil
}

// ensureCoverage returns the *statementCoverage entry for `table`,
// allocating one if this is the first sighting. Centralising this in a
// helper keeps `scanFile`'s loop body readable.
func ensureCoverage(r *scanResult, table string) *statementCoverage {
	c, ok := r.coverage[table]
	if !ok {
		c = &statementCoverage{}
		r.coverage[table] = c
	}
	return c
}

// stripBlockComments removes `/* … */` spans from a SQL body so that the
// regexps in scanFile cannot match against sample SQL quoted inside a
// header comment. We do this textually (not via a SQL parser) because the
// migrations are otherwise plain text — pulling in a full parser would be
// overkill for a CI lint.
//
// Nesting is NOT supported (PostgreSQL allows nested block comments but
// our migrations never use them in practice). If a future migration starts
// nesting block comments and the lint misbehaves, the fix is to switch to
// a `/\*((?:[^*]|\*[^/])*)\*/` regexp here; for now a simple linear scan
// is fast and clear.
func stripBlockComments(body string) string {
	var b strings.Builder
	b.Grow(len(body))
	i := 0
	for i < len(body) {
		if i+1 < len(body) && body[i] == '/' && body[i+1] == '*' {
			end := strings.Index(body[i+2:], "*/")
			if end < 0 {
				// Unterminated block comment — bail out conservatively
				// and treat the rest of the body as comment. This keeps
				// scanFile from misreading a half-comment as live SQL.
				break
			}
			// Preserve newlines so line numbers in error output stay
			// aligned with the original file.
			for _, r := range body[i : i+2+end+2] {
				if r == '\n' {
					b.WriteByte('\n')
				}
			}
			i = i + 2 + end + 2
			continue
		}
		b.WriteByte(body[i])
		i++
	}
	return b.String()
}

// structuralExemptions enumerates `tenant_*` tables that CANNOT carry
// tenant-isolation RLS by construction. The classic case is the membership
// join table (`tenant_users`) — RLS on that table would need to consult
// itself to decide whether to return its own rows, which is circular.
//
// Each entry must include a one-line justification; the lint echoes it in
// --verbose output so reviewers can confirm the exemption is still valid.
// This map is intentionally tiny and reviewed-by-hand — production tenant
// data tables are NEVER added here. A new entry requires the same care as
// removing an RLS policy.
var structuralExemptions = map[string]string{
	"tenant_users": "tenant membership join table — RLS would be self-referential " +
		"(the policy would need tenant_users to decide who can read tenant_users). " +
		"Source-of-truth for current_setting('app.current_tenant_id') resolution.",
}

// finding is one failure record — a `tenant_*` CREATE TABLE that lacks
// at least one of the required RLS statements and is not suppressed.
type finding struct {
	site    tableSite
	missing []string
}

// audit walks the scanResult and returns the list of findings (empty if
// every `tenant_*` table is RLS-clean or suppressed) plus the count of
// suppressed-but-still-included tables for the verbose summary.
//
// The function is deterministic: findings are returned in
// (file, line, table) order so CI log diffs are stable across runs.
func audit(r *scanResult) (findings []finding, suppressed int) {
	for _, site := range r.created {
		if _, ok := structuralExemptions[site.name]; ok {
			// Structural exemption — table cannot carry RLS by design.
			// Counted as suppressed for the summary line but never
			// produces a finding.
			suppressed++
			continue
		}
		if reason, ok := r.suppressions[site.file]; ok {
			// We don't currently distinguish "file-wide suppression" from
			// "table-specific suppression": once the file containing the
			// CREATE TABLE includes the marker, the lint trusts the
			// human reviewer to have audited it. The reason captured in
			// `reason` is echoed by main() in --verbose mode.
			_ = reason
			suppressed++
			continue
		}
		c := r.coverage[site.name]
		if c == nil {
			c = &statementCoverage{}
		}
		miss := c.missing()
		if len(miss) > 0 {
			findings = append(findings, finding{site: site, missing: miss})
		}
	}
	return findings, suppressed
}

// run is the testable entry point — splitting it out of main() lets
// main_test.go drive the lint with synthetic --dir arguments and capture
// stdout/stderr without forking a subprocess.
//
// The signature mirrors `flag.Parse` semantics: argv excludes the program
// name (i.e. caller passes os.Args[1:]), and the function returns the
// process exit code instead of calling os.Exit directly so test code can
// assert on it.
func run(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint-migration-rls", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dir := fs.String("dir", "apps/api/migrations", "directory containing *.up.sql migration files")
	verbose := fs.Bool("verbose", false, "print suppressed tables and per-table coverage on success")

	if err := fs.Parse(argv); err != nil {
		// flag.ContinueOnError already wrote the usage message to stderr.
		return 2
	}

	if *dir == "" {
		fmt.Fprintln(stderr, "lint-migration-rls: --dir is required")
		return 2
	}

	result, err := scanDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "lint-migration-rls: %v\n", err)
		return 2
	}

	findings, suppressed := audit(result)

	if len(findings) == 0 {
		fmt.Fprintf(stdout, "lint-migration-rls: ok — %d tenant_* table(s) checked, %d suppressed\n",
			len(result.created), suppressed)
		if *verbose {
			for _, site := range result.created {
				if reason, ok := structuralExemptions[site.name]; ok {
					fmt.Fprintf(stdout, "  exempt:     %s (%s:%d) — %s\n",
						site.name, site.file, site.line, reason)
					continue
				}
				if reason, ok := result.suppressions[site.file]; ok {
					fmt.Fprintf(stdout, "  suppressed: %s (%s:%d) — %s\n",
						site.name, site.file, site.line, reason)
				} else {
					fmt.Fprintf(stdout, "  clean:      %s (%s:%d)\n",
						site.name, site.file, site.line)
				}
			}
		}
		return 0
	}

	// Failure path: print every finding to stderr (CI captures stderr
	// separately from stdout, and humans grep stderr first for "what
	// broke") with a deterministic format.
	fmt.Fprintf(stderr, "lint-migration-rls: FAIL — %d tenant_* table(s) missing RLS\n",
		len(findings))
	for _, f := range findings {
		fmt.Fprintf(stderr, "  %s (%s:%d):\n", f.site.name, f.site.file, f.site.line)
		for _, m := range f.missing {
			fmt.Fprintf(stderr, "    - missing: %s\n", m)
		}
		fmt.Fprintf(stderr, "    fix: add the missing statement(s) in the same migration, or in a\n")
		fmt.Fprintf(stderr, "         partner *_rls.up.sql (pattern: 037_tenant_llm_config_rls.up.sql,\n")
		fmt.Fprintf(stderr, "         047_tenant_diff_webhook_settings_rls.up.sql), or document an\n")
		fmt.Fprintf(stderr, "         exemption with an inline `-- lint:no-rls-required: <reason>` comment.\n")
	}
	return 1
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
