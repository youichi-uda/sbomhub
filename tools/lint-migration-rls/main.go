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
// A table is treated as **tenant-scoped** and therefore subject to the RLS
// check if EITHER:
//
//   (a) its name matches the project convention `tenant_*` (the post-036
//       pattern, where every new tenant-scoped table carries the prefix
//       precisely so a textual scan can pick it up), OR
//   (b) its `CREATE TABLE` body declares a `tenant_id` column, OR
//   (c) a later migration runs `ALTER TABLE <name> ADD COLUMN tenant_id`
//       on it (the 007 multitenancy retrofit pattern — promoting an
//       existing table to tenant-scoped after the fact).
//
// (b) and (c) are F183 (M13-5 #91): the original 007/023 legacy schema
// added `tenant_id` to existing tables (`projects`, `sboms`, …) and
// created `audit_logs` with a tenant_id column inline — without the
// `tenant_*` prefix the lint would silently miss the equivalent failure
// mode if a new migration added `billing_records(tenant_id UUID, …)`
// without the prefix and without RLS. (b) + (c) close that gap.
//
// Every tenant-scoped table is considered "RLS-clean" iff **all three** of
// the following statements exist somewhere in the same directory (any
// file, in any order — including a dedicated `<n>_<table>_rls.up.sql`
// partner file):
//
//  1. `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY`
//  2. `ALTER TABLE <table> FORCE  ROW LEVEL SECURITY`
//  3. `CREATE POLICY tenant_isolation_<…> ON <table>`
//
// Legacy 012 / 013 / 014 / 015 / 021 migrations originally used the
// quoted-suffix form `CREATE POLICY "<table>_tenant_isolation" ON <table>`,
// which this lint deliberately does not recognise. Those same tables
// receive a new policy named with the project-standard
// `tenant_isolation_<table>` prefix in migration 042
// (`042_rls_force_uniformity`), so the directory-wide scan still finds
// evidence for them — see the M5 hardening narrative in 042's header.
//
// The "any file in the directory" rule is what lets the partner-file
// pattern (046 + 047, 011 + 043, 010 / 012 / 014 / 021 + 042) pass
// without amending the original migration in place — operators that
// already migrated past the original still pick up the RLS transition
// through the normal migrate-up sequence on the partner.
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
	//
	// Kept for the legacy tenant_*-prefix-only fast path; the F183
	// extension (see reCreateAnyTable + extractCreateTables below) is the
	// primary detector now.
	reCreateTenantTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(tenant_[a-z0-9_]+)\s*\(`)

	// F183 (M13-5 #91): any CREATE TABLE, name only.
	//
	// We then read the table body (paren-balanced) inside
	// extractCreateTables and decide whether the table is tenant-scoped by
	// looking for a `tenant_id` column. This is what lets the lint catch
	// non-tenant_*-prefixed tables — the 007 / 023 legacy schema names
	// (`projects`, `sboms`, `audit_logs`, `reachability_results`, …) that
	// pre-date the project's `tenant_*` naming convention.
	reCreateAnyTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z][a-z0-9_]*)\s*\(`)

	// F183: ALTER TABLE [ONLY] <name> ADD COLUMN tenant_id <type>
	//
	// The 007 multitenancy migration promoted nine previously-tenantless
	// tables (projects / sboms / components / vulnerabilities /
	// vex_statements / license_policies / notification_settings /
	// notification_logs / api_keys) to tenant-scoped via this pattern.
	// The original CREATE TABLE lives in earlier migrations (001-006)
	// without a `tenant_id` column, so a body-scan alone would miss them.
	// We record the ALTER's file:line as the table's "tenant-scoped birth
	// site" instead.
	reAlterAddTenantID = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?([a-z][a-z0-9_]*)\s+ADD\s+COLUMN\s+tenant_id\s+`)

	// F183: `tenant_id` column anchor inside a CREATE TABLE body.
	//
	// Matches `tenant_id` only at the start of a column definition (after
	// the opening paren, after a comma, or after a newline). The "<type
	// starts with an uppercase letter or letter-class follow" gate filters
	// out matches inside an expression like
	// `CONSTRAINT fk_tenant_id_foo FOREIGN KEY (tenant_id) REFERENCES …`
	// — those carry a `(` after the name, not a type keyword. The leading
	// `[A-Za-z]` allows future column types beyond UUID (e.g.
	// `tenant_id BIGINT`) without silently dropping detection.
	reTenantIDColumn = regexp.MustCompile(`(?i)(?:^|,|\n)\s*tenant_id\s+[A-Za-z]`)

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

// scanFile records, for one migration file's body, every tenant-scoped
// CREATE TABLE it defines AND every RLS evidence statement it contains
// (regardless of which table that statement targets — RLS statements for a
// table created in a different file still count).
//
// "Tenant-scoped" is decided by extractCreateTables (full-body scan for a
// `tenant_id` column or a `tenant_*` name prefix) and by an
// `ALTER TABLE … ADD COLUMN tenant_id` retrofit. Both shapes feed into
// `result.created` so the audit() pass below treats them uniformly.
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

	// Phase 1 — full-body CREATE TABLE detection (F183).
	//
	// We walk the entire file with a paren-balanced scan instead of the
	// previous line-by-line regex so that a tenant_id column declared
	// inside a multi-line CREATE TABLE is reliably seen. The legacy
	// tenant_*-prefix case is preserved (a tenant_* table is treated as
	// tenant-scoped even if for some reason its body has no `tenant_id`
	// column yet — e.g. a tenant_<name> table whose tenant_id will be
	// added in a follow-up ALTER, which while exotic should not silently
	// drop off the lint).
	for _, tb := range extractCreateTables(stripped) {
		hasPrefix := strings.HasPrefix(tb.name, "tenant_")
		hasColumn := reTenantIDColumn.MatchString(tb.body)
		if !hasPrefix && !hasColumn {
			continue
		}
		result.created = append(result.created, tableSite{
			name: tb.name,
			file: name,
			line: tb.line,
		})
	}

	// Phase 2 — line-by-line scan for RLS evidence, ADD COLUMN retrofit,
	// and the suppression marker.
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

		// F183: ALTER TABLE … ADD COLUMN tenant_id promotes a previously
		// tenantless table to tenant-scoped. The CREATE TABLE itself
		// lives in an earlier migration (the 007 retrofit pattern); we
		// record a site here so the table participates in the RLS
		// coverage check anyway. Deduplication against an in-file
		// CREATE TABLE site is intentional: a single 007-style migration
		// that both CREATEs the table AND ALTERs it should produce one
		// site, not two.
		if m := reAlterAddTenantID.FindStringSubmatch(line); m != nil {
			tbl := strings.ToLower(m[1])
			alreadyInFile := false
			for _, s := range result.created {
				if s.name == tbl && s.file == name {
					alreadyInFile = true
					break
				}
			}
			if !alreadyInFile {
				result.created = append(result.created, tableSite{
					name: tbl,
					file: name,
					line: lineNumber,
				})
			}
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

// extractCreateTables returns one entry per `CREATE TABLE [IF NOT EXISTS]
// <name> ( … )` statement in `stripped`, paired with the raw body text
// between the outer parentheses. We use this (rather than a single big
// regex with `(?s).*?`) so that nested parens inside a column expression —
// e.g. `DEFAULT uuid_generate_v4()`, `CHECK (x > 0)`, `column_type(20)` —
// don't terminate the body match prematurely.
//
// `stripped` is expected to have block comments already removed. Line
// comments inside the body are dropped on the body-string we return so a
// commented-out tenant_id column cannot register as live SQL during the
// downstream `reTenantIDColumn` check.
func extractCreateTables(stripped string) []tableBody {
	var out []tableBody
	locs := reCreateAnyTable.FindAllStringSubmatchIndex(stripped, -1)
	for _, loc := range locs {
		// loc[0]/[1] = full match (including the trailing `(`)
		// loc[2]/[3] = name capture group
		name := strings.ToLower(stripped[loc[2]:loc[3]])

		// We are positioned at the byte AFTER the opening `(`. Walk
		// forward maintaining a paren-depth counter until we close it.
		bodyStart := loc[1]
		depth := 1
		i := bodyStart
		for i < len(stripped) && depth > 0 {
			switch stripped[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			i++
		}
		if depth != 0 {
			// Unterminated CREATE TABLE — almost certainly a truncated
			// fixture or a stripBlockComments bail-out. Skip
			// conservatively rather than reporting a half-table.
			continue
		}
		body := stripLineCommentsForColumns(stripped[bodyStart : i-1])

		// Convert byte offset to 1-indexed line number for error
		// messages. strings.Count(prefix, "\n") + 1 mirrors what the
		// legacy per-line loop reported.
		line := strings.Count(stripped[:loc[0]], "\n") + 1

		out = append(out, tableBody{name: name, body: body, line: line})
	}
	return out
}

// tableBody is the parsed shape of one CREATE TABLE statement: the bare
// table name (lower-cased), the column-list body between the outer
// parens, and the 1-indexed source line of the `CREATE` keyword.
type tableBody struct {
	name string
	body string
	line int
}

// stripLineCommentsForColumns drops everything after `--` on each line of
// a CREATE TABLE body so that a commented-out column declaration —
// `--  tenant_id UUID,` — does not trip reTenantIDColumn. This is a
// finer-grained version of the in-loop `--` strip; it operates on a
// substring instead of the full file so the per-file line scan still sees
// the comment text it needs (e.g. for the suppression marker).
func stripLineCommentsForColumns(body string) string {
	var b strings.Builder
	b.Grow(len(body))
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		if i != len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
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
// The function is a tiny SQL comment lexer with two states:
//
//   - **inBlock** — currently inside a `/* … */` span. Newlines are
//     preserved (so downstream line numbers stay aligned with the original
//     file) and everything else is dropped.
//   - **inLine**  — currently after a `--` on the same line. The line
//     comment text is preserved verbatim so downstream code can still see
//     the suppression marker (`-- lint:no-rls-required: …`) and the
//     per-line `--` strip in scanFile still works.
//
// The line-comment state matters even though we don't drop its content:
// without it, a URL or path inside a line comment that happens to contain
// `/*` (e.g. `-- service/llm/*` in 032, `-- repository/*` in 043) would
// open a phantom block comment that swallows the rest of the migration —
// including its `ALTER TABLE … ENABLE RLS` evidence. F183 (M13-5 #91)
// widened the lint's table-detection scope to cover non-`tenant_*` tables,
// at which point that phantom-comment behaviour started silently failing
// real migrations (github_connections / github_repositories in 011 →
// 043). The state machine below is the smallest fix that respects
// line-comment boundaries.
//
// Nesting of block comments is NOT supported (PostgreSQL allows it but
// our migrations never use it in practice). An unterminated `/*` causes
// the rest of the body to be treated as comment — same conservative
// behaviour as before; matches a half-comment in a malformed fixture.
func stripBlockComments(body string) string {
	var b strings.Builder
	b.Grow(len(body))

	inBlock := false
	inLine := false

	for i := 0; i < len(body); i++ {
		ch := body[i]
		switch {
		case inBlock:
			if ch == '*' && i+1 < len(body) && body[i+1] == '/' {
				// Close of block comment — skip the `/` too.
				inBlock = false
				i++
				continue
			}
			if ch == '\n' {
				// Preserve newline so downstream line numbers match.
				b.WriteByte('\n')
				// A block comment's content is line-agnostic, but in
				// case a `--` later in this block comment was already
				// noted, reset the line-comment flag — it does not
				// straddle the newline anyway.
				inLine = false
			}
		case inLine:
			b.WriteByte(ch)
			if ch == '\n' {
				inLine = false
			}
		default:
			if ch == '/' && i+1 < len(body) && body[i+1] == '*' {
				// Open block comment — drop the `/*` pair.
				inBlock = true
				i++
				continue
			}
			if ch == '-' && i+1 < len(body) && body[i+1] == '-' {
				// Open line comment — preserve verbatim so the
				// suppression marker and per-line `--` strip downstream
				// still see it.
				inLine = true
				b.WriteByte(ch)
				continue
			}
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// structuralExemptions enumerates tenant-scoped tables (`tenant_*`-prefixed
// or just `tenant_id`-bearing — see the F183 detection extension) that
// CANNOT carry tenant-isolation RLS by construction. The classic case is
// the membership join table (`tenant_users`) — RLS on that table would
// need to consult itself to decide whether to return its own rows, which
// is circular.
//
// Each entry must include a one-line justification; the lint echoes it in
// --verbose output so reviewers can confirm the exemption is still valid.
// This map is intentionally tiny and reviewed-by-hand — production tenant
// data tables are NEVER added here. A new entry requires the same care as
// removing an RLS policy.
//
// The non-`tenant_*`-prefixed entries below are the legacy 007 / 023
// schema accepted by the F183 scope extension. New tenant-scoped tables
// SHOULD use the `tenant_*` prefix (see
// apps/api/migrations/CLAUDE.md) — these entries are documented exceptions
// for tables that pre-date that convention.
var structuralExemptions = map[string]string{
	// `tenant_*`-prefixed structural exemption (pre-F183).
	"tenant_users": "tenant membership join table — RLS would be self-referential " +
		"(the policy would need tenant_users to decide who can read tenant_users). " +
		"Source-of-truth for current_setting('app.current_tenant_id') resolution.",

	// F183 (M13-5 #91) — legacy 007 schema, intentional design.
	//
	// CVE / vulnerability metadata is shared across tenants. Migration 007
	// added a `tenant_id UUID … ON DELETE SET NULL` column for join
	// convenience (a vulnerability "owned" by a tenant that has since
	// deleted itself drops the link, the row stays as global advisory
	// data) but never enabled RLS. See 007_multitenancy.up.sql, the
	// trailing comment "vulnerabilities table doesn't have RLS as
	// vulnerabilities are shared across tenants".
	"vulnerabilities": "global CVE / advisory data shared across tenants. " +
		"tenant_id is a soft-join hint (ON DELETE SET NULL), not an isolation boundary. " +
		"Legacy 007 schema; intentionally not RLS-protected.",

	// F183 — legacy 010 schema, **potential RLS gap** (see F185).
	//
	// `scan_settings` / `scan_logs` were added in migration 010 BEFORE
	// the 023 RLS hardening sweep and never received an RLS partner.
	// Tenant scope is enforced application-side in ScanSettingsRepository.
	// Exempt here so the lint surfaces a clean run on the current tree;
	// the missing RLS posture is tracked as F185 (M13 Phase D round 2)
	// for a follow-up partner migration.
	"scan_settings": "legacy 010 schema; predates the 023 RLS hardening sweep. " +
		"Tenant scope enforced app-side in ScanSettingsRepository. " +
		"Tracked as F185 — partner RLS migration outstanding.",
	"scan_logs": "legacy 010 schema; predates the 023 RLS hardening sweep. " +
		"Tenant scope enforced app-side in ScanSettingsRepository (scan_logs is " +
		"written by the scheduler under the same tenant context). " +
		"Tracked as F185 — partner RLS migration outstanding.",

	// F183 — RLS deliberately removed in 030 (Trust Rescue codex-r5 P1 #19).
	//
	// `public_links` and `public_link_access_logs` need tenant-unscoped
	// access for the anonymous /api/v1/public/:token endpoint — the token
	// IS the auth, and the lookup is what reveals the tenant. RLS would
	// reject the lookup entirely. Tenant scope is enforced app-side via
	// PublicLinkRepository's explicit `WHERE tenant_id = $N` clauses on
	// every authenticated read/mutation.
	"public_links": "RLS removed in migration 030 (Trust Rescue codex-r5 P1 #19). " +
		"Anonymous /api/v1/public/:token endpoint requires tenant-unscoped lookup; " +
		"the token IS the auth. Tenant scope enforced app-side in PublicLinkRepository.",
	"public_link_access_logs": "RLS removed in migration 030 alongside public_links — " +
		"the access log is written by anonymous-flow handlers that have no tenant " +
		"context. Server-only writes, no API exposes reads.",

	// F183 — RLS deliberately removed in 031 (Trust Rescue P0 #18 follow-up / codex-r15).
	//
	// Lemon Squeezy webhook handlers run outside any tenant middleware,
	// and the GetByLSSubscriptionID lookup is what reveals which tenant
	// a webhook event belongs to. RLS rejects the lookup under the
	// app role's NOBYPASSRLS posture, silently breaking subscription
	// lifecycle. Tenant scope is enforced app-side in
	// SubscriptionRepository's explicit `tenant_id = $N` clauses.
	"subscriptions": "RLS removed in migration 031 (Trust Rescue P0 #18 follow-up / codex-r15). " +
		"Lemon Squeezy webhook lookup by ls_subscription_id must run tenant-unscoped " +
		"(the lookup reveals the tenant). Tenant scope enforced app-side in SubscriptionRepository.",
	"subscription_events": "RLS removed in migration 031 alongside subscriptions — " +
		"event history is written from webhook handlers with the tenant_id " +
		"derived from the looked-up subscription. App-layer enforcement via SubscriptionRepository.",
	"usage_records": "RLS removed in migration 031 alongside subscriptions — " +
		"metered billing counters are written by webhook handlers. " +
		"App-layer enforcement via SubscriptionRepository.GetUsage's tenant_id clause.",
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
