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
// inline marker comment on any line of the file that defines the table.
// Two forms are accepted:
//
//	-- lint:no-rls-required: <reason>            (unscoped)
//	-- lint:no-rls-required(<table>): <reason>   (table-scoped)
//
// The reason is mandatory in both forms and is echoed back in lint output
// for audit. The table-scoped form exempts only the named table; the
// unscoped form exempts the file's single tenant-scoped table. In a
// migration that defines more than one tenant-scoped table, the unscoped
// form is treated as a hard error (F195, M13 Phase D round 3) because
// the marker cannot disambiguate which table is being exempted —
// silently widening the suppression to every table in the file would
// defeat the lint gate (the original 036/046 misses were exactly the
// "one table in a multi-table migration" shape).
//
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
//
// Identifier and schema-qualified table reference sub-patterns
// =============================================================
//
// F194 (M13 Phase D round 3): PostgreSQL identifiers can be bare
// (`foo`), double-quoted (`"foo"`), and either form may be
// schema-qualified (`public.foo`, `"public"."foo"`). The old detector
// only matched `[a-z][a-z0-9_]*`, silently bypassing `CREATE TABLE
// public.billing_records (tenant_id UUID, …)` and `CREATE TABLE
// "tenant_foo" (…)`. The sub-patterns below are interpolated into every
// table-name capture so all four forms feed into the same downstream
// normalisation pass (normalizeTableName).
//
// The schema prefix (if present) is consumed by a non-capturing group;
// only the unqualified table name is captured. Quote characters survive
// the regex match and are stripped by normalizeTableName before
// downstream comparison — keeping the regex itself simple and matching
// the same normalisation behaviour for every table-name capture site.
const (
	// identPattern matches one bare-or-quoted SQL identifier. We do NOT
	// support `""`-escaped double quotes inside a quoted identifier
	// (PostgreSQL allows it, our migrations do not use it). A future
	// migration that needs it would surface as a lint miss in code review
	// rather than a silent bypass — same conservative posture as
	// stripBlockComments' no-nesting choice.
	identPattern = `(?:"[^"]+"|[a-zA-Z_][a-zA-Z0-9_]*)`

	// tableRefPattern matches an optionally-schema-qualified table
	// reference. The schema prefix `<schema>.` is non-capturing; the
	// table name is the single capture group. Callers that already
	// have other capture groups should account for an extra match index.
	tableRefPattern = `(?:` + identPattern + `\.)?(` + identPattern + `)`
)

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
	//
	// F194 (M13 Phase D round 3): table-name capture now uses
	// tableRefPattern to cover schema-qualified (`public.foo`) and
	// double-quoted (`"foo"`) identifiers.
	reCreateAnyTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + tableRefPattern + `\s*\(`)

	// F183: ALTER TABLE [ONLY] <name> ADD [COLUMN] tenant_id <type>
	//
	// The 007 multitenancy migration promoted nine previously-tenantless
	// tables (projects / sboms / components / vulnerabilities /
	// vex_statements / license_policies / notification_settings /
	// notification_logs / api_keys) to tenant-scoped via this pattern.
	// The original CREATE TABLE lives in earlier migrations (001-006)
	// without a `tenant_id` column, so a body-scan alone would miss them.
	// We record the ALTER's file:line as the table's "tenant-scoped birth
	// site" instead.
	//
	// F191 (M13 Phase D round 3): `COLUMN` is optional per the SQL
	// standard and PostgreSQL accepts `ALTER TABLE foo ADD tenant_id
	// UUID`. The old `ADD\s+COLUMN\s+tenant_id` requirement silently
	// bypassed the shorter idiomatic form, undermining the F183 widening
	// it was meant to support.
	//
	// F194 (M13 Phase D round 3): table-name capture also widened to
	// tableRefPattern for schema-qualified / quoted forms.
	reAlterAddTenantID = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?` + tableRefPattern + `\s+ADD\s+(?:COLUMN\s+)?tenant_id\s+`)

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
	//
	// F194: schema-qualified / quoted name support via tableRefPattern.
	reEnableRLS = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?` + tableRefPattern + `\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY`)

	// ALTER TABLE <name> FORCE [ROW LEVEL SECURITY]
	//
	// `FORCE ROW LEVEL SECURITY` is critical: without it the table owner
	// (the migrator role used in tests / fixtures / ad-hoc maintenance)
	// silently bypasses the policy. The 037 / 047 fix files both include
	// this; the lint requires it for forward-compatibility with the same
	// pattern.
	//
	// F194: schema-qualified / quoted name support via tableRefPattern.
	reForceRLS = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?` + tableRefPattern + `\s+FORCE\s+(?:ROW\s+LEVEL\s+SECURITY|RLS)`)

	// CREATE POLICY tenant_isolation_<…> ON <table>
	//
	// The `tenant_isolation_` prefix is the project-wide convention (see
	// 007_multitenancy.up.sql, 037_tenant_llm_config_rls.up.sql,
	// 047_tenant_diff_webhook_settings_rls.up.sql). Requiring it keeps the
	// lint from being fooled by an arbitrary CREATE POLICY that doesn't
	// actually implement tenant isolation.
	//
	// F194: schema-qualified / quoted target-table support via
	// tableRefPattern.
	rePolicyOn = regexp.MustCompile(`(?i)CREATE\s+POLICY\s+tenant_isolation_[a-z0-9_]+\s+ON\s+` + tableRefPattern)

	// -- lint:no-rls-required[(<table>)]: <reason>
	//
	// The reason is captured for echo-back. We intentionally do not allow
	// a bare `-- lint:no-rls-required` with no reason — every suppression
	// should be auditable.
	//
	// F195 (M13 Phase D round 3): the optional `(<table>)` qualifier lets
	// a multi-tenant-scoped-table migration suppress exactly one of its
	// tables. The unscoped form remains the common case for single-table
	// files; audit() hard-fails on the unscoped form in a multi-table
	// file because the intent is ambiguous (which table is being
	// exempted?). Match group 1 = table name (empty for unscoped),
	// match group 2 = reason.
	//
	// The pattern is anchored at the start of the (trimmed) line via
	// `\A\s*--\s*` so that an explanatory docstring containing the
	// marker syntax inside a backtick / quote — e.g. a header comment
	// describing the lint itself — cannot accidentally be picked up as
	// a real suppression. The active marker is, by convention, always
	// the leading content of its own line.
	reSuppress = regexp.MustCompile(`(?i)\A\s*--\s*lint:no-rls-required(?:\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\))?:\s*(.+?)\s*$`)
)

// normalizeTableName lower-cases a captured table identifier and strips
// any surrounding double quotes that the F194 regexes preserved during
// matching. We normalise at every capture site (CREATE / ALTER / POLICY /
// extractCreateTables) so that downstream map lookups treat
// `Tenant_Foo`, `tenant_foo`, and `"tenant_foo"` as the same table —
// PostgreSQL itself folds unquoted identifiers to lowercase, and our
// migrations only ever spell tables in lowercase, so the case-insensitive
// posture is consistent with on-disk semantics.
//
// Schema prefixes are already dropped by the regex's non-capturing
// `(?:<schema>\.)?` prefix in tableRefPattern, so this helper only needs
// to strip quotes and lowercase the remaining bare or quoted name.
func normalizeTableName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ToLower(s)
}

// unscopedSuppressionTable is the map key used to record an inline
// `-- lint:no-rls-required: <reason>` marker that did NOT name a
// specific table. An unscoped marker is legal only in a file that
// defines exactly one tenant-scoped table; audit() reports it as a
// hard ambiguity error otherwise (F195).
const unscopedSuppressionTable = ""

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

	// suppressions maps file name → table name → reason. The outer key is
	// the migration file; the inner key is the table name explicitly
	// named by the marker (`-- lint:no-rls-required(<table>): …`), or
	// the sentinel `unscopedSuppressionTable` (the empty string) for the
	// legacy unscoped form (`-- lint:no-rls-required: …`).
	//
	// F195 (M13 Phase D round 3): pre-F195 this was `map[string]string`
	// (file → reason), which silently widened to suppress every
	// tenant-scoped table in a multi-table migration once an unscoped
	// marker appeared anywhere in the file — a real defeat of the lint
	// gate for files with one legitimate-RLS table next to one exempt
	// one. The two-level shape lets audit() route the unscoped form
	// through an explicit single-table check and reject ambiguous use.
	suppressions map[string]map[string]string
}

// newScanResult constructs an empty scanResult with non-nil maps so the
// scanning loop can `result.coverage[name] = …` without per-call nil
// checks.
func newScanResult() *scanResult {
	return &scanResult{
		coverage:     make(map[string]*statementCoverage),
		suppressions: make(map[string]map[string]string),
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

		// Suppression marker — recorded against the file with a per-table
		// key (F195). The optional `(<table>)` qualifier in the marker
		// syntax routes a multi-table migration's suppression to a
		// specific table; an unscoped marker is stored under
		// `unscopedSuppressionTable` and audit() rejects it later if
		// the file defines more than one tenant-scoped table.
		if m := reSuppress.FindStringSubmatch(line); m != nil {
			tbl := normalizeTableName(m[1]) // empty string for unscoped form
			reason := strings.TrimSpace(m[2])
			if result.suppressions[name] == nil {
				result.suppressions[name] = make(map[string]string)
			}
			result.suppressions[name][tbl] = reason
		}

		// Drop everything after `--` so that an RLS statement quoted
		// inside a line comment doesn't count as evidence.
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}

		// F183: ALTER TABLE … ADD [COLUMN] tenant_id promotes a
		// previously tenantless table to tenant-scoped. The CREATE TABLE
		// itself lives in an earlier migration (the 007 retrofit
		// pattern); we record a site here so the table participates in
		// the RLS coverage check anyway. Deduplication against an
		// in-file CREATE TABLE site is intentional: a single 007-style
		// migration that both CREATEs the table AND ALTERs it should
		// produce one site, not two.
		//
		// F191: regex now also matches the shorter `ADD tenant_id`
		// (without the `COLUMN` keyword), which PostgreSQL accepts and
		// which the original detector silently bypassed.
		if m := reAlterAddTenantID.FindStringSubmatch(line); m != nil {
			tbl := normalizeTableName(m[1])
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
			tbl := normalizeTableName(m[1])
			ensureCoverage(result, tbl).enable = true
		}
		if m := reForceRLS.FindStringSubmatch(line); m != nil {
			tbl := normalizeTableName(m[1])
			ensureCoverage(result, tbl).force = true
		}
		if m := rePolicyOn.FindStringSubmatch(line); m != nil {
			tbl := normalizeTableName(m[1])
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
		// loc[2]/[3] = name capture group (F194: bare or `"…"`-quoted;
		// any schema prefix is consumed by tableRefPattern's
		// non-capturing group)
		name := normalizeTableName(stripped[loc[2]:loc[3]])

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
// at least one of the required RLS statements and is not suppressed,
// OR a file-level structural error (F195: an unscoped suppression
// marker in a multi-tenant-scoped-table file).
type finding struct {
	site    tableSite
	missing []string

	// ambiguousMarker is set when the migration file contains an unscoped
	// `-- lint:no-rls-required: <reason>` marker AND defines more than
	// one tenant-scoped table. The marker cannot disambiguate which
	// table is exempt, so it is rejected at audit time and the lint
	// emits a single per-file finding pointing at the first such table.
	// When this flag is true, `missing` is left nil — the lint output
	// switches to a different message (see run()).
	ambiguousMarker bool
}

// audit walks the scanResult and returns the list of findings (empty if
// every `tenant_*` table is RLS-clean or suppressed) plus the count of
// suppressed-but-still-included tables for the verbose summary.
//
// The function is deterministic: findings are returned in
// (file, line, table) order so CI log diffs are stable across runs.
//
// F195 (M13 Phase D round 3) extends audit() with two-tier suppression:
//
//   - A table-scoped marker (`-- lint:no-rls-required(<table>): …`)
//     suppresses only the named table.
//   - An unscoped marker (`-- lint:no-rls-required: …`) suppresses the
//     file's single tenant-scoped table; if the file defines more than
//     one tenant-scoped table the marker is reported as ambiguous and
//     the lint hard-fails for that file.
func audit(r *scanResult) (findings []finding, suppressed int) {
	// Pre-compute how many tenant-scoped tables each file defines so the
	// unscoped-marker check below can reject ambiguous use cheaply.
	tablesPerFile := make(map[string]int)
	for _, site := range r.created {
		tablesPerFile[site.file]++
	}

	// Each ambiguous-marker file emits at most one finding (against the
	// first tenant-scoped table by source order) so CI log noise scales
	// with the count of misconfigured files, not the count of tables in
	// them.
	ambiguousReported := make(map[string]bool)

	for _, site := range r.created {
		if _, ok := structuralExemptions[site.name]; ok {
			// Structural exemption — table cannot carry RLS by design.
			// Counted as suppressed for the summary line but never
			// produces a finding.
			suppressed++
			continue
		}
		if fileSuppressions, ok := r.suppressions[site.file]; ok {
			// Table-scoped marker matches this exact table — accept and
			// move on. The reason is echoed by run() in --verbose mode.
			if reason, ok := fileSuppressions[site.name]; ok {
				_ = reason
				suppressed++
				continue
			}
			// Unscoped marker present in this file. Legal only if this
			// file defines exactly one tenant-scoped table; otherwise
			// emit a single ambiguous-marker finding and stop counting
			// this file's tables as suppressed (audit cannot tell which
			// one the operator meant).
			if reason, ok := fileSuppressions[unscopedSuppressionTable]; ok {
				if tablesPerFile[site.file] > 1 {
					if !ambiguousReported[site.file] {
						findings = append(findings, finding{
							site:            site,
							ambiguousMarker: true,
						})
						ambiguousReported[site.file] = true
					}
					continue
				}
				_ = reason
				suppressed++
				continue
			}
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
				// F195: the suppressions map is now two-level
				// (file → table → reason). We check the table-scoped
				// entry first; if absent, fall back to the unscoped
				// entry (audit() has already guaranteed the unscoped
				// form is legal here, i.e. single-table file).
				if fileSuppressions, ok := result.suppressions[site.file]; ok {
					if reason, ok := fileSuppressions[site.name]; ok {
						fmt.Fprintf(stdout, "  suppressed: %s (%s:%d) — %s\n",
							site.name, site.file, site.line, reason)
						continue
					}
					if reason, ok := fileSuppressions[unscopedSuppressionTable]; ok {
						fmt.Fprintf(stdout, "  suppressed: %s (%s:%d) — %s\n",
							site.name, site.file, site.line, reason)
						continue
					}
				}
				fmt.Fprintf(stdout, "  clean:      %s (%s:%d)\n",
					site.name, site.file, site.line)
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
		// F195: ambiguous unscoped-marker findings get a dedicated
		// remediation message because the fix is to change the marker
		// syntax, not to add ENABLE/FORCE/POLICY statements.
		if f.ambiguousMarker {
			fmt.Fprintf(stderr, "    - error: unscoped `-- lint:no-rls-required:` marker in a migration\n")
			fmt.Fprintf(stderr, "             that defines more than one tenant-scoped table; the marker\n")
			fmt.Fprintf(stderr, "             cannot tell which table is exempt.\n")
			fmt.Fprintf(stderr, "    fix: change the marker to its table-scoped form\n")
			fmt.Fprintf(stderr, "         `-- lint:no-rls-required(<table>): <reason>` so the exemption\n")
			fmt.Fprintf(stderr, "         names the exact table, or split the migration so each\n")
			fmt.Fprintf(stderr, "         tenant-scoped table lives in its own file.\n")
			continue
		}
		for _, m := range f.missing {
			fmt.Fprintf(stderr, "    - missing: %s\n", m)
		}
		fmt.Fprintf(stderr, "    fix: add the missing statement(s) in the same migration, or in a\n")
		fmt.Fprintf(stderr, "         partner *_rls.up.sql (pattern: 037_tenant_llm_config_rls.up.sql,\n")
		fmt.Fprintf(stderr, "         047_tenant_diff_webhook_settings_rls.up.sql), or document an\n")
		fmt.Fprintf(stderr, "         exemption with an inline `-- lint:no-rls-required[(<table>)]: <reason>` comment.\n")
	}
	return 1
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
