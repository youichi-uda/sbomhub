// Package main implements the migration lock-discipline lint — a CI
// check that requires a new migration whose statement text acquires a
// lock conflicting with live application traffic to first declare a
// `SET LOCAL lock_timeout` budget.
//
// THREAT MODEL — read this before extending the tool
// ==================================================
//
// This lint catches the HONEST MISTAKE of a cooperating author. It is NOT
// a boundary against an author who is trying to get around it, and it
// must not be described, extended, or reviewed as if it were.
//
// The reason is structural, not a matter of effort. The rule the lint
// enforces is "declare a budget", and the budget's VALUE is the author's
// to choose. Measured on PostgreSQL 15.18 (2026-08-01):
//
//	SET LOCAL lock_timeout = '5s';   → accepted by PostgreSQL, lint exit 0
//	SET LOCAL lock_timeout = '1h';   → accepted (eff=1h),      lint exit 0
//	SET LOCAL lock_timeout = '24h';  → accepted (eff=1d),      lint exit 0
//
// An author who wants an unbounded wait writes one plausible-looking line
// and has it. Every other evasion route is strictly harder than that one,
// so hardening against them buys nothing: it fortifies the side door
// while the front door stands open. An earlier version of this tool spent
// most of its code on exactly that — tracking `search_path`, `SET ROLE`,
// `RENAME TO`, `U&"…"` identifiers, `set_config()` — and twelve review
// rounds never converged, because the surface is unbounded and the
// premise was wrong.
//
// So the lint is calibrated for the mistake it actually prevents: an
// author adds `ALTER TABLE components ADD COLUMN …` to a new migration,
// does not think about locks at all, and ships a statement that can stall
// a deploy indefinitely. That mistake is common, costly, and caught by a
// one-line rule.
//
// What this lint deliberately does NOT detect
// ===========================================
//
// Enumerated so a future reader knows what to add if the threat model
// ever changes — each was implemented, measured, and then removed as out
// of scope.
//
// Three of them do occur in this directory and are called out where they
// appear: the `DO` blocks in migrations 027 / 041 / 044 / 045 (charged
// conservatively, see item 8), the `CREATE EXTENSION "uuid-ossp"` in
// migration 001 (also item 8 — that extension's script creates only
// functions), and the 65 `.down.sql` files (item 9 — not scanned at
// all). No migration here uses any of the others.
//
//  1. A budget long enough to be no budget: `SET LOCAL lock_timeout =
//     '24h'` passes. The lint checks that a budget EXISTS and is
//     non-zero, not that it is short. A cap would be an invented
//     threshold, and per the note above it would not close the hole
//     anyway.
//  2. A GUC changed by anything other than a `SET` / `RESET` statement:
//     `SELECT set_config('lock_timeout','0',true)`, a write to
//     `pg_settings`, or either of those inside a `DO` body. Measured:
//     all three really do change the setting.
//  3. Anything that changes what an unqualified relation name resolves
//     to mid-file: `SET search_path`, `SET SCHEMA`, `SET ROLE`,
//     `SET SESSION AUTHORIZATION`. The same-file exemption keys on the
//     name as written.
//  4. A relation whose identity moves: `ALTER TABLE … RENAME TO` and
//     `ALTER TABLE … SET SCHEMA`. The exemption follows the old name.
//  5. `U&"…"` Unicode-escape identifiers, whose decoded name depends on
//     a `UESCAPE` clause, and doubled quotes inside a quoted identifier
//     (`"tenant""archive"`).
//  6. Teardown dependencies: `DROP TABLE` of a table this file created
//     re-locks the tables it references, and dropping a partition
//     re-locks its parent. Both need a mid-file budget reset to matter.
//  7. `SAVEPOINT` / `ROLLBACK TO SAVEPOINT`, which cancel a `SET LOCAL`
//     made after the savepoint. These are reported as unrecognised
//     statements rather than modelled.
//  8. Locks taken by user code a statement CALLS — a function body, a
//     trigger fired by DML, an extension install script. Measured: a
//     plain `SELECT ddl_probe();` whose body does `ALTER TABLE live
//     ADD COLUMN` holds ACCESS EXCLUSIVE on `live`. `DO` blocks are the
//     one member of this class charged conservatively, because an honest
//     author really does write them here (migrations 027 / 041 / 044 /
//     045).
//  9. `.down.sql` files. A rollback is a deliberate operator action, not
//     the automatic startup path.
//  10. How long a lock is HELD once acquired. `lock_timeout` bounds
//     acquisition only; the 064 / 065 split is the remedy for a
//     scan-holding statement and is not enforced here.
//
// Why the rule exists at all
// ==========================
//
// `cmd/migrate/main.go` and `internal/database/migrate.go` both wrap each
// migration FILE in a single transaction (BEGIN → exec file body → INSERT
// schema_migrations → COMMIT). Neither sets `lock_timeout`, so the
// migrator role inherits the server default of 0 — wait forever.
//
// Measured on PostgreSQL 15.18 with one session holding a lock and a
// second running the DDL under `SET LOCAL lock_timeout = '1500ms'`:
//
//	holder ACCESS SHARE (open SELECT) vs ALTER TABLE … ADD COLUMN
//	    → canceling statement due to lock timeout
//	holder ACCESS SHARE               vs CREATE INDEX (non-concurrent)
//	    → proceeded
//	holder ROW EXCLUSIVE (open UPDATE) vs CREATE INDEX (non-concurrent)
//	    → canceling statement due to lock timeout
//	holder ROW EXCLUSIVE               vs ALTER TABLE … VALIDATE CONSTRAINT
//	    → proceeded
//	holder ROW EXCLUSIVE on the REFERENCED table
//	                                   vs CREATE TABLE … REFERENCES it
//	    → canceling statement due to lock timeout
//
// With no budget those waits are unbounded, and because PostgreSQL queues
// later lock requests behind a blocked stronger request, one stalled
// `ALTER TABLE` takes the whole table offline rather than just itself.
// With a budget the migration fails fast; the runner's per-file
// transaction rolls the DDL and the `schema_migrations` row back
// together, so the deploy is safe to retry when the table is quiet.
//
// Migrations 063 / 064 / 065 introduced `SET LOCAL lock_timeout = '5s'`
// and 063's own header records the residual: "063 is the FIRST migration
// in this directory to set a lock budget; the other 62 all inherit
// lock_timeout = 0." This lint stops that gap from growing.
//
// What counts as a lock that needs a budget
// =========================================
//
// Lock modes were measured, not assumed: each candidate statement was run
// inside a transaction against PostgreSQL 15.18 and the modes it held on
// the target relation were read out of `pg_locks` (see classifyStatement
// for the per-statement results).
//
// The threshold is `budgetRequiredFrom` = SHARE: a statement needs a
// budget when it takes SHARE or stronger on a relation that already
// exists, because SHARE is the weakest mode in PostgreSQL's conflict
// table that conflicts with ROW EXCLUSIVE — the weakest mode that can
// queue behind an ordinary application INSERT/UPDATE/DELETE.
//
//	ACCESS EXCLUSIVE      conflicts with everything, incl. plain SELECT.
//	EXCLUSIVE             conflicts with everything but a plain reader.
//	SHARE ROW EXCLUSIVE   conflicts with writers, not readers.
//	SHARE                 conflicts with writers, not readers.
//	--------------------- budgetRequiredFrom -------------------------
//	SHARE UPDATE EXCLUSIVE conflicts with neither readers nor writers
//	                       (only with other DDL and VACUUM).
//	ROW EXCLUSIVE and below is ordinary application traffic.
//
// SHARE UPDATE EXCLUSIVE (`VALIDATE CONSTRAINT`, `COMMENT ON`,
// `ALTER TABLE … SET (…)` for the weak-lock storage parameters,
// `SET STATISTICS`, `ANALYZE`) is deliberately BELOW the bar: it cannot
// queue behind a live SELECT or INSERT, so demanding a budget for it
// would put a gate in front of the 80 `COMMENT ON` statements in this
// directory for a risk class the repository has never hit. Migration 065
// budgets its VALIDATE anyway; the lint simply does not require it.
//
// Statements against a table CREATEd in the SAME FILE are exempt: the
// creating transaction is the only session that can see the new relation,
// so its ACCESS EXCLUSIVE lock has nobody to block. The exemption is
// same-file only — a table created in migration N is fully live by the
// time N+1 runs on an instance that already applied N — and it is NOT
// granted for `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT
// EXISTS`, because those prove nothing: if the relation already existed
// the statement was a no-op and everything after it contends with live
// traffic.
//
// CREATE INDEX CONCURRENTLY is not an option here
// ===============================================
//
// The usual advice for a SHARE-taking `CREATE INDEX` is "use
// CONCURRENTLY". That is unavailable in this repository, measured on
// PostgreSQL 15.18:
//
//	BEGIN; CREATE INDEX CONCURRENTLY … ;
//	    ERROR:  CREATE INDEX CONCURRENTLY cannot run inside a transaction block
//	BEGIN; DROP INDEX CONCURRENTLY … ;
//	    ERROR:  DROP INDEX CONCURRENTLY cannot run inside a transaction block
//	BEGIN; REINDEX INDEX CONCURRENTLY … ;
//	    ERROR:  REINDEX CONCURRENTLY cannot run inside a transaction block
//	BEGIN; REINDEX {SCHEMA|DATABASE|SYSTEM} … ;
//	    ERROR:  REINDEX <kind> cannot run inside a transaction block
//	BEGIN; VACUUM … ;    BEGIN; CLUSTER;   (both refused)
//
// Both runners always open a transaction, so any of those is a guaranteed
// runtime failure of the migration rather than a contention risk. The
// lint reports them as a distinct finding kind (findingNonTransactional)
// with its own remediation, and — unlike a missing budget — that finding
// is NOT waivable by the legacy baseline. Measured to run fine inside a
// transaction, and therefore not in that set: `REFRESH MATERIALIZED VIEW
// [CONCURRENTLY]`, `CLUSTER <table>`, `ALTER TYPE … ADD VALUE`.
//
// SET LOCAL, not SET
// ==================
//
// The budget must be `SET LOCAL`. Measured:
//
//	BEGIN; SET       lock_timeout='5s'; COMMIT;  → after commit: 5s
//	BEGIN; SET LOCAL lock_timeout='5s'; COMMIT;  → after commit: 0
//
// Both runners hold a pooled `*sql.DB`, so a plain `SET` leaks the budget
// onto whichever connection runs the NEXT migration file, and the budget
// stops being a property of the file a reviewer is reading. `SET LOCAL`
// is scoped to exactly the transaction the runner rolls back.
//
// The legacy baseline
// ===================
//
// Of the 65 existing `*.up.sql` files the scan finds 5 that take no
// contending lock, 2 that take one and declare a budget (063, 064) and 58
// that need a waiver. The 58 are grandfathered by an explicit baseline
// (legacyBaseline) rather than edited, because a shipped migration is
// immutable by convention once recorded in `schema_migrations`.
//
// A filename allowlist is used in preference to a "version >= 063" cutoff
// because it fails safe: a file not on the list is enforced, full stop. A
// numeric cutoff would silently exempt any future file sorting below it.
// Each entry is a fingerprint — waived-statement count, strongest class,
// and a digest over the ordered statements — so appending an unbudgeted
// statement to a grandfathered migration does not inherit its waiver. The
// baseline is also self-cleaning: a listed file that no longer needs the
// waiver, or that does not exist, is reported.
//
// Exit codes
// ==========
//
//	0 — every migration that takes a contending lock declares a budget
//	    (or is grandfathered by the legacy baseline).
//	1 — at least one finding.
//	2 — the tool cannot answer the question: a usage or I/O error (bad
//	    --dir, a directory with no *.up.sql, an unreadable file), or a
//	    refused `--emit-baseline` request.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------
// Lock classes
// ---------------------------------------------------------------------

// lockClass ranks the table-level lock modes this lint can attribute to a
// statement.
//
// It is a LINT POLICY ordering, not PostgreSQL's conflict lattice, which
// is only a partial order: SHARE UPDATE EXCLUSIVE self-conflicts while
// SHARE does not, so neither dominates the other in the conflict table.
// The single axis below ranks modes by "how much ordinary application
// traffic does acquiring this mode have to wait for", which is the only
// question this lint asks. ACCESS SHARE and ROW SHARE collapse into
// lockNone because no statement that takes at most those modes can ever
// block on ordinary traffic.
type lockClass int

const (
	// lockNone — the statement takes at most ACCESS SHARE / ROW SHARE on
	// pre-existing relations (or touches only relations created in the
	// same file). Nothing to budget.
	lockNone lockClass = iota

	// lockRowExclusive — INSERT / UPDATE / DELETE. Conflicts only with
	// SHARE and above, i.e. with DDL, never with other ordinary traffic.
	lockRowExclusive

	// lockShareUpdateExclusive — VALIDATE CONSTRAINT, COMMENT ON,
	// ALTER TABLE … SET (storage params), SET STATISTICS, ANALYZE.
	// Conflicts with other DDL and with VACUUM, but with neither readers
	// nor writers.
	lockShareUpdateExclusive

	// lockShare — non-concurrent CREATE INDEX. Conflicts with writers
	// (ROW EXCLUSIVE), not with readers.
	//
	// REINDEX is NOT classified here: measured, `REINDEX INDEX` and
	// `REINDEX TABLE` hold ShareLock on the heap AND AccessExclusiveLock
	// on the index, and they cannot run in a transaction at all when the
	// target is partitioned — which a static scan cannot determine. Both
	// forms are therefore reported as unrecognised rather than given a
	// lock class.
	lockShare

	// lockShareRowExclusive — ADD CONSTRAINT … FOREIGN KEY, an inline
	// REFERENCES in CREATE TABLE (taken on the REFERENCED table),
	// CREATE TRIGGER, ALTER SEQUENCE. Conflicts with writers, not with
	// readers.
	lockShareRowExclusive

	// lockExclusive — `LOCK TABLE … IN EXCLUSIVE MODE` and
	// `REFRESH MATERIALIZED VIEW CONCURRENTLY` (measured:
	// ExclusiveLock, alongside AccessShare and RowExclusive). Conflicts
	// with everything except a plain reader.
	lockExclusive

	// lockAccessExclusive — most ALTER TABLE forms, DROP INDEX,
	// DROP TABLE / VIEW, TRUNCATE, CREATE/DROP/ALTER POLICY,
	// ENABLE/DISABLE/FORCE/NO FORCE ROW LEVEL SECURITY, DROP TRIGGER,
	// CREATE OR REPLACE VIEW, CREATE TABLE … PARTITION OF (on the
	// parent), REFRESH MATERIALIZED VIEW, CLUSTER. Conflicts with
	// everything including a plain SELECT.
	lockAccessExclusive
)

// budgetRequiredFrom is the threshold at which a statement must be
// preceded by a `SET LOCAL lock_timeout`. See the package doc for why the
// line is drawn at SHARE and not at SHARE UPDATE EXCLUSIVE.
const budgetRequiredFrom = lockShare

func (c lockClass) String() string {
	switch c {
	case lockNone:
		return "none"
	case lockRowExclusive:
		return "ROW EXCLUSIVE"
	case lockShareUpdateExclusive:
		return "SHARE UPDATE EXCLUSIVE"
	case lockShare:
		return "SHARE"
	case lockShareRowExclusive:
		return "SHARE ROW EXCLUSIVE"
	case lockExclusive:
		return "EXCLUSIVE"
	case lockAccessExclusive:
		return "ACCESS EXCLUSIVE"
	default:
		return "unknown"
	}
}

// ---------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------

// statement is one `;`-terminated SQL statement lifted out of a migration
// file, with comments removed.
//
// Two texts are kept because they serve incompatible purposes:
//
//   - text keeps string-literal and dollar-quoted CONTENT, because the
//     lock budget's value is a string literal and has to be read.
//   - scanText blanks that content out, because classification greps for
//     keywords like REFERENCES and must not see them inside a
//     `RAISE EXCEPTION 'run ALTER TABLE … by hand'` message.
//
// Both have runs of whitespace collapsed to a single space, so the
// regexes below never need to worry about how a migration was indented.
// Quoted identifiers are exempt from that collapse — `"a  b"` and
// `"a b"` are different relations in PostgreSQL.
//
// fpText exists only to be hashed into the baseline fingerprint. It
// canonicalises whitespace in the OUTER SQL exactly as `text` does, but
// reproduces every byte inside a string literal, a quoted identifier or a
// dollar-quoted body — newlines included. That matters because a newline
// is executable syntax inside a `DO $$ … $$` body: it is what terminates
// a `--` comment. Collapsing it let these two DO blocks hash identically
// even though only the first takes a lock:
//
//	DO $$ BEGIN -- noop
//	  ALTER TABLE live_t ADD COLUMN c int;
//	END $$;
//
//	DO $$ BEGIN -- noop ALTER TABLE live_t ADD COLUMN c int;
//	END $$;
type statement struct {
	text     string // literals preserved
	scanText string // literals blanked
	fpText   string // literals preserved BYTE-FOR-BYTE, incl. newlines
	line     int    // 1-indexed line of the statement's first token
}

// display renders a statement for error output: the first 72 characters
// of the literal-preserving text, ellipsised. Deterministic so CI log
// diffs are stable.
func (s statement) display() string {
	const max = 72
	t := s.text
	if len(t) <= max {
		return t
	}
	return t[:max] + " …"
}

// isBlank reports whether the statement carries no SQL at all (e.g. the
// trailing fragment after a file's final `;`).
func (s statement) isBlank() bool { return strings.TrimSpace(s.text) == "" }

// lexer state. Kept as an explicit small state machine rather than a
// regex sweep because SQL comment / literal / dollar-quote nesting is not
// a regular language: a `--` inside a string is not a comment, a `;`
// inside a `$$ … $$` body does not end a statement, and a `/*` inside a
// line comment must not open a block comment (the exact bug
// `lint-migration-rls` had to fix in stripBlockComments).
type lexState int

const (
	stNormal lexState = iota
	stLineComment
	stBlockComment
	stSingleQuote
	stDoubleQuote
	stDollarQuote
)

// splitStatements lexes a migration file body into statements. The second
// return value is a non-empty description when the lexer reached EOF
// inside a comment, literal or dollar-quoted body — i.e. when its view of
// the file provably diverged from PostgreSQL's. Callers must surface that
// rather than certify whatever survived.
//
// Behaviour notes, all measured against PostgreSQL 15.18:
//
//   - Block comments NEST (`SELECT 1 /* a /* b */ c */` is valid and
//     returns 1), so the lexer keeps a depth counter.
//   - Plain string literals do not process backslash escapes when
//     standard_conforming_strings is on, which it is by default and is on
//     this instance. E-strings (`E'…'`) DO: `E'foo\'; SELECT x'` is a
//     single literal containing a semicolon. Both forms are handled.
//   - A doubled straight quote inside a single-quoted literal is the SQL
//     standard escape and keeps the lexer inside the literal.
//   - `$` is a legal identifier continuation character, so `begin$$` is
//     ONE identifier and not a dollar-quote opener. A dollar quote is
//     recognised only where the preceding character cannot continue an
//     identifier. (`SELECT 1 AS begin$$; SELECT 2 AS end$$;` executes as
//     two statements.)
//   - A dollar-quote tag is empty or a PostgreSQL identifier, which may
//     contain non-ASCII letters, and closes only on the identical tag.
func splitStatements(body string) ([]statement, string) {
	var out []statement

	state := stNormal
	line := 1
	openLine := 0 // where the currently-open construct started
	blockDepth := 0
	eString := false // the open single-quoted literal is an E-string
	var cur strings.Builder
	var scan strings.Builder
	var fp strings.Builder
	fpPendingSpace := false
	// fpOuter mirrors cur's canonicalisation for text outside any quoted
	// construct; fpVerbatim copies a byte exactly as it appeared.
	fpOuter := func(ch byte) {
		if isSpaceByte(ch) {
			fpPendingSpace = fp.Len() > 0
			return
		}
		if fpPendingSpace {
			fp.WriteByte(' ')
			fpPendingSpace = false
		}
		fp.WriteByte(ch)
	}
	fpVerbatim := func(ch byte) {
		if fpPendingSpace {
			fp.WriteByte(' ')
			fpPendingSpace = false
		}
		fp.WriteByte(ch)
	}
	var dollarTag string
	startLine := 0 // line of the current statement's first token, 0 = not started

	emit := func() {
		st := statement{
			text:     collapseSQLSpace(cur.String()),
			scanText: collapseSQLSpace(scan.String()),
			fpText:   strings.TrimSpace(fp.String()),
			line:     startLine,
		}
		if !st.isBlank() {
			out = append(out, st)
		}
		cur.Reset()
		scan.Reset()
		fp.Reset()
		fpPendingSpace = false
		startLine = 0
	}

	write := func(ch byte) {
		if startLine == 0 && !isSpaceByte(ch) {
			startLine = line
		}
		cur.WriteByte(ch)
		scan.WriteByte(ch)
		fpOuter(ch)
	}

	// countNewline advances the line counter for the break starting at
	// body[i] and reports how many EXTRA bytes it consumed. A bare CR, a
	// bare LF and a CRLF pair each count as one line — the lexer used to
	// count only LF, so a file written with classic Mac line endings
	// reported every statement on line 1.
	countNewline := func(i int) int {
		line++
		if body[i] == '\r' && i+1 < len(body) && body[i+1] == '\n' {
			return 1
		}
		return 0
	}

	for i := 0; i < len(body); i++ {
		ch := body[i]
		isBreak := ch == '\n' || ch == '\r'

		switch state {
		case stLineComment:
			// PostgreSQL ends a line comment at a carriage return as well
			// as at a newline. Ending only at `\n` let a CR-delimited
			// file hide every statement after the first comment
			//. CRLF still counts as one line.
			if ch == '\r' {
				state = stNormal
				cur.WriteByte(' ')
				scan.WriteByte(' ')
				fpOuter(' ')
				// A bare CR is a line break; a CRLF pair counts once, so
				// the `\n` half is consumed here.
				line++
				if i+1 < len(body) && body[i+1] == '\n' {
					i++
				}
				continue
			}
			if ch == '\n' {
				state = stNormal
				line++
				cur.WriteByte(' ')
				scan.WriteByte(' ')
				// PostgreSQL treats a comment as whitespace, so the
				// fingerprint text needs the separator too — without it
				// `ALTER/**/TABLE` canonicalised to `ALTERTABLE` and two
				// statements that differ only across a comment boundary
				// could hash alike.
				fpOuter(' ')
			}

		case stBlockComment:
			// Nesting: `/*` inside a block comment opens another level and
			// only the matching `*/` at depth 1 closes the whole thing.
			if ch == '/' && i+1 < len(body) && body[i+1] == '*' {
				blockDepth++
				i++
				continue
			}
			if ch == '*' && i+1 < len(body) && body[i+1] == '/' {
				blockDepth--
				i++
				if blockDepth == 0 {
					state = stNormal
					cur.WriteByte(' ')
					scan.WriteByte(' ')
					fpOuter(' ')
				}
				continue
			}
			if isBreak {
				i += countNewline(i)
			}

		case stSingleQuote:
			if isBreak {
				// The break's bytes stay in the literal verbatim, but the
				// line counter must advance exactly once for a CRLF pair.
				// Counting `\r` and `\n` separately reported every later
				// statement one line too far.
				if n := countNewline(i); n > 0 {
					fpVerbatim(ch)
					cur.WriteByte(ch)
					i++
					ch = body[i]
				}
			}
			fpVerbatim(ch)
			if eString && ch == '\\' && i+1 < len(body) {
				// An escaped line break still ends a line. A bare CR and a
				// bare LF each count once here; an escaped CRLF is left to
				// the next iteration, which counts the pair once, so it is
				// not counted twice.
				if body[i+1] == '\n' ||
					(body[i+1] == '\r' && !(i+2 < len(body) && body[i+2] == '\n')) {
					line++
				}
				// Consume the escape pair atomically — in an E-string a
				// backslash-quote does NOT end the literal. Both bytes go
				// into `cur`, which is contractually literal-preserving
				// and is what error output quotes back; `scan` gets
				// nothing, as for any other literal content.
				cur.WriteByte(ch)
				cur.WriteByte(body[i+1])
				fpVerbatim(body[i+1])
				i++
				continue
			}
			if ch == '\'' {
				if i+1 < len(body) && body[i+1] == '\'' {
					i++
					cur.WriteString("''")
					fpVerbatim('\'')
					continue
				}
				state = stNormal
				eString = false
				cur.WriteByte('\'')
				scan.WriteString("''")
				continue
			}
			cur.WriteByte(ch)

		case stDoubleQuote:
			if isBreak {
				if n := countNewline(i); n > 0 {
					fpVerbatim(ch)
					cur.WriteByte(ch)
					scan.WriteByte(ch)
					i++
					ch = body[i]
				}
			}
			fpVerbatim(ch)
			// Quoted identifiers are semantically significant — including
			// their case and internal whitespace — so they go into BOTH
			// accumulators verbatim.
			if ch == '"' && i+1 < len(body) && body[i+1] == '"' {
				// A doubled quote inside a quoted identifier is an
				// escaped quote, not the end of the identifier.
				cur.WriteString(`""`)
				scan.WriteString(`""`)
				fpVerbatim('"')
				i++
				continue
			}
			cur.WriteByte(ch)
			scan.WriteByte(ch)
			if ch == '"' {
				state = stNormal
			}

		case stDollarQuote:
			if isBreak {
				if n := countNewline(i); n > 0 {
					fpVerbatim(ch)
					cur.WriteByte(ch)
					i++
					ch = body[i]
				}
			}
			fpVerbatim(ch)
			if ch == '$' && strings.HasPrefix(body[i:], dollarTag) {
				state = stNormal
				for k := 1; k < len(dollarTag); k++ {
					fpVerbatim(dollarTag[k])
				}
				i += len(dollarTag) - 1
				cur.WriteString(dollarTag)
				scan.WriteString(dollarTag)
				dollarTag = ""
				continue
			}
			cur.WriteByte(ch)

		default: // stNormal
			if isBreak {
				i += countNewline(i)
				write(' ')
				continue
			}
			if ch == '-' && i+1 < len(body) && body[i+1] == '-' {
				state = stLineComment
				i++
				continue
			}
			if ch == '/' && i+1 < len(body) && body[i+1] == '*' {
				state = stBlockComment
				blockDepth = 1
				openLine = line
				i++
				continue
			}
			if ch == '\'' {
				state = stSingleQuote
				openLine = line
				// An `E` immediately before the quote (already written to
				// the accumulators) selects escape-string syntax.
				eString = endsWithEPrefix(cur.String())
				if startLine == 0 {
					startLine = line
				}
				cur.WriteByte('\'')
				fpVerbatim('\'')
				continue
			}
			if ch == '"' {
				state = stDoubleQuote
				openLine = line
				write('"')
				continue
			}
			if tag, ok := dollarTagAt(body, i); ok {
				state = stDollarQuote
				dollarTag = tag
				openLine = line
				if startLine == 0 {
					startLine = line
				}
				i += len(tag) - 1
				cur.WriteString(tag)
				scan.WriteString(tag)
				for k := 0; k < len(tag); k++ {
					fpVerbatim(tag[k])
				}
				continue
			}
			if ch == ';' {
				emit()
				continue
			}
			write(ch)
		}
	}
	emit()

	switch state {
	case stBlockComment:
		return out, fmt.Sprintf("unterminated block comment opened on line %d", openLine)
	case stSingleQuote:
		return out, fmt.Sprintf("unterminated string literal opened on line %d", openLine)
	case stDoubleQuote:
		return out, fmt.Sprintf("unterminated quoted identifier opened on line %d", openLine)
	case stDollarQuote:
		return out, fmt.Sprintf("unterminated dollar-quoted body opened on line %d", openLine)
	}
	return out, ""
}

// endsWithEPrefix reports whether the accumulated text ends with a
// standalone `E` (or `e`), which is what turns the literal about to open
// into an escape string. A trailing `E` that is part of a longer word
// (e.g. `VALUE`) does not count.
func endsWithEPrefix(s string) bool {
	if s == "" {
		return false
	}
	last := s[len(s)-1]
	if last != 'E' && last != 'e' {
		return false
	}
	if len(s) == 1 {
		return true
	}
	return !isIdentContinueByte(s[len(s)-2])
}

// dollarTagAt reports whether a dollar-quote tag opens at body[i], and
// returns the tag text including both `$` characters.
//
// Two rules, both measured: the tag is empty or a PostgreSQL identifier
// (which may contain non-ASCII letters), and the opener must not be a
// continuation of an identifier — `begin$$` is one identifier, not a word
// followed by an empty dollar tag.
func dollarTagAt(body string, i int) (string, bool) {
	if body[i] != '$' {
		return "", false
	}
	if i > 0 && isIdentContinueByte(body[i-1]) {
		return "", false
	}
	j := i + 1
	for j < len(body) {
		c := body[j]
		if c == '$' {
			tag := body[i : j+1]
			// PostgreSQL identifiers cannot start with a digit, so
			// `$1$`-shaped text is not a tag.
			if len(tag) > 2 && isDigitByte(tag[1]) {
				return "", false
			}
			return tag, true
		}
		if !isIdentContinueByte(c) {
			return "", false
		}
		j++
	}
	return "", false
}

// isIdentContinueByte reports whether a byte can continue an unquoted
// PostgreSQL identifier. `$` is included (it is legal after the first
// character) and every non-ASCII byte is included so UTF-8 letters in
// identifiers and dollar-quote tags survive.
func isIdentContinueByte(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c >= 0x80
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// collapseSQLSpace trims the string and reduces every run of whitespace
// to a single space so downstream regexes can be written against a
// canonical single-line form — EXCEPT inside a double-quoted identifier,
// where whitespace is part of the name (`"a  b"` is not `"a b"`).
func collapseSQLSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inQuote := false
	pendingSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '"' && i+1 < len(s) && s[i+1] == '"' {
				b.WriteString(`""`)
				i++
				continue
			}
			b.WriteByte(c)
			if c == '"' {
				inQuote = false
			}
			continue
		}
		if isSpaceByte(c) {
			pendingSpace = b.Len() > 0
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		if c == '"' {
			inQuote = true
		}
		b.WriteByte(c)
	}
	return b.String()
}

// ---------------------------------------------------------------------
// Identifier / statement patterns
// ---------------------------------------------------------------------

const (
	// identPattern matches one bare-or-quoted SQL identifier.
	//
	// The unquoted branch admits `$` and Unicode letters/digits, matching
	// PostgreSQL's rules — without `$`, a capture of `sample$archive`
	// would stop at `sample` and the same-file exemption would then match
	// a completely different relation.
	//
	// Not supported, deliberately: a doubled quote inside a quoted
	// identifier (`"tenant""archive"`) and the Unicode-escape form
	// (`U&"…"`). See "What this lint deliberately does not detect" in the
	// package doc — neither appears in a migration written by a
	// cooperating author, and supporting them cost more machinery than
	// the honest-mistake threat model justifies.
	identPattern = `(?:"[^"]+"|[\p{L}_][\p{L}\p{N}_$]*)`

	// tableRefPattern matches an optionally schema-qualified relation
	// reference and captures it WHOLE, schema included, so
	// `scratch.accounts` and `public.accounts` stay distinct. The cost is
	// that a file spelling the same relation both ways (`CREATE TABLE t`
	// then `ALTER TABLE public.t`) loses the same-file exemption — an
	// over-report, which is the safe direction. No migration in this
	// directory qualifies a relation name.
	tableRefPattern = `((?:` + identPattern + `\s*\.\s*)?` + identPattern + `)`

	// nonQuoteRun matches text that may contain complete double-quoted
	// spans but never enters one, so a lazy `… ON <table>` search cannot
	// land on an `ON` inside a quoted column name — a legacy schema can
	// legitimately have a column named `"x ON decoy"`.
	nonQuoteRun = `(?:[^"]|"[^"]*")*?`
)

var (
	// `SET [LOCAL|SESSION] lock_timeout {=|TO} <value>`. Group 1 is the
	// scope keyword (empty when absent), group 2 the raw value.
	reSetLockTimeout = regexp.MustCompile(`(?i)^SET\s+(LOCAL\s+|SESSION\s+)?"?lock_timeout"?\s*(?:=|\bTO\b)\s*(.+)$`)

	// Any other GUC assignment — harmless, and matched before the generic
	// unclassified fallback so `SET LOCAL statement_timeout` is not
	// mistaken for something that needs a budget.
	reSetAnything = regexp.MustCompile(`(?i)^(?:SET|RESET|SHOW)\b`)

	// `standard_conforming_strings` decides whether a backslash escapes
	// the following quote. This lexer assumes the PostgreSQL default
	// (on). A SESSION-scoped `SET … = off` survives COMMIT and, because
	// both runners hold a pooled *sql.DB whose driver does not reset the
	// session, it changes how the NEXT migration file is lexed — at which
	// point a statement this lint read as part of a string literal is
	// really executable DDL. Measured: with the setting off,
	// `SELECT 'it\'s ready'` returns `it's ready`.
	//
	// An author importing legacy SQL that uses the historical escaping
	// convention writes this honestly, so it fails closed rather than
	// being modelled.
	reSetStringMode = regexp.MustCompile(`(?i)^(?:SET|RESET)\s+(?:LOCAL\s+|SESSION\s+)?"?standard_conforming_strings"?\b`)

	// Groups: 1 = CONCURRENTLY, 2 = IF NOT EXISTS, 3 = index name
	// (optional — `CREATE INDEX ON t (…)` is legal), 4 = table.
	reCreateIndex = regexp.MustCompile(`(?i)^CREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(IF\s+NOT\s+EXISTS\s+)?(?:(` + identPattern + `)\s+)?ON\s+(?:ONLY\s+)?` + tableRefPattern)
	reDropIndex   = regexp.MustCompile(`(?i)^DROP\s+INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(.+)$`)

	// REINDEX grammar (PostgreSQL 15):
	//	REINDEX [ ( option [, …] ) ] { INDEX | TABLE | SCHEMA | DATABASE | SYSTEM } [ CONCURRENTLY ] name
	// Measured: INDEX and TABLE run inside a transaction (ShareLock);
	// SCHEMA, DATABASE and SYSTEM are refused, as is any CONCURRENTLY
	// form.
	reReindex    = regexp.MustCompile(`(?i)^REINDEX\s+(?:\([^()]*\)\s*)?(INDEX|TABLE|SCHEMA|DATABASE|SYSTEM)\s+(CONCURRENTLY\s+)?`)
	reReindexAny = regexp.MustCompile(`(?i)^REINDEX\b`)

	// Groups: 1 = IF NOT EXISTS, 2 = table, 3 = rest of the statement.
	reCreateTable = regexp.MustCompile(`(?i)^CREATE\s+(?:UNLOGGED\s+|GLOBAL\s+|LOCAL\s+|TEMP\s+|TEMPORARY\s+)*TABLE\s+(IF\s+NOT\s+EXISTS\s+)?` + tableRefPattern + `\s*(.*)$`)
	reDropTable   = regexp.MustCompile(`(?i)^DROP\s+(?:TABLE|MATERIALIZED\s+VIEW|VIEW)\s+(?:IF\s+EXISTS\s+)?(.+)$`)
	reTruncate    = regexp.MustCompile(`(?i)^TRUNCATE\s+(?:TABLE\s+)?(?:ONLY\s+)?(.+)$`)

	reAlterTable = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + tableRefPattern + `\s+(.*)$`)

	// The three SHARE UPDATE EXCLUSIVE forms are anchored at BOTH ends.
	// An ALTER TABLE may carry a comma-separated list of actions and
	// takes the strongest lock any of them needs, so matching only the
	// head of the list would downgrade the whole statement to its weakest
	// action. Measured on PostgreSQL 15.18:
	//
	//	ALTER TABLE probe_t VALIDATE CONSTRAINT ckm, ADD COLUMN z int;
	//	    → pg_locks: AccessExclusiveLock
	//	ALTER TABLE probe_t SET (fillfactor = 90), ADD COLUMN z int;
	//	    → AccessExclusiveLock
	//
	// With `$`-anchored patterns any extra action fails the match and the
	// statement falls through to the ACCESS EXCLUSIVE default, which is
	// the safe direction.
	reAlterValidate = regexp.MustCompile(`(?i)^VALIDATE\s+CONSTRAINT\s+` + identPattern + `$`)
	// `SET (…)` and `RESET (…)` take the same lock for the same parameter
	// — measured, `RESET (fillfactor)` is SHARE UPDATE EXCLUSIVE and
	// `RESET (user_catalog_table)` is ACCESS EXCLUSIVE.
	reAlterSetStorage    = regexp.MustCompile(`(?i)^(?:SET|RESET)\s*\(([^()]*)\)$`)
	reAlterSetStatistics = regexp.MustCompile(`(?i)^ALTER\s+(?:COLUMN\s+)?` + identPattern + `\s+SET\s+STATISTICS\s+-?\d+$`)
	// Measured on PostgreSQL 15.18, both ShareUpdateExclusiveLock:
	//	ALTER TABLE t CLUSTER ON idx
	//	ALTER TABLE t SET WITHOUT CLUSTER
	reAlterClusterOn = regexp.MustCompile(`(?i)^(?:CLUSTER\s+ON\s+` + identPattern + `|SET\s+WITHOUT\s+CLUSTER)$`)

	reAlterAddFK = regexp.MustCompile(`(?i)^ADD\s+(?:CONSTRAINT\s+` + identPattern + `\s+)?FOREIGN\s+KEY\b`)

	reReferences = regexp.MustCompile(`(?i)\bREFERENCES\s+` + tableRefPattern)

	// `CREATE TABLE child PARTITION OF parent …` and
	// `ALTER TABLE parent {ATTACH|DETACH} PARTITION child` both take
	// ACCESS EXCLUSIVE on the OTHER relation named — the parent in the
	// first case, the partition in the second. Measured on PostgreSQL
	// 15.18: creating a partition showed AccessExclusiveLock on the
	// parent. Without this the CREATE TABLE branch would register the
	// partition in createdRelations, find no REFERENCES clause, and pass.
	// `CREATE TABLE child () INHERITS (parent)` takes
	// ShareUpdateExclusiveLock on each parent (measured). Below the
	// budget threshold, but the classification should report what was
	// measured rather than "no lock".
	reInherits = regexp.MustCompile(`(?i)\bINHERITS\s*\(([^()]*)\)`)

	rePartitionOf = regexp.MustCompile(`(?i)\bPARTITION\s+OF\s+` + tableRefPattern)
	// `ATTACH PARTITION <rel> DEFAULT` — the attached relation becomes
	// the parent's default partition, which proves the parent had none.
	reAttachDefault = regexp.MustCompile(`(?i)^ATTACH\s+PARTITION\s+` + identPattern + `(?:\s*\.\s*` + identPattern + `)?\s+DEFAULT\s*$`)

	rePartitionAttach = regexp.MustCompile(`(?i)^(?:ATTACH|DETACH)\s+PARTITION\s+` + tableRefPattern)

	// Measured on PostgreSQL 15.18:
	//	ALTER TABLE p DETACH PARTITION c CONCURRENTLY;
	//	    ERROR:  ALTER TABLE ... DETACH CONCURRENTLY cannot run inside
	//	            a transaction block
	reDetachConcurrent = regexp.MustCompile(`(?i)^DETACH\s+PARTITION\s+` + tableRefPattern + `\s+CONCURRENTLY\b`)

	// `ALTER TYPE <t> ADD VALUE …` takes no lock on any user relation
	// (measured) and runs inside a transaction, though the new value
	// cannot be USED until that transaction commits. Other ALTER TYPE
	// forms are left unclassified rather than guessed at.
	reAlterTypeAddValue = regexp.MustCompile(`(?i)^ALTER\s+TYPE\s+` + tableRefPattern + `\s+ADD\s+VALUE\b`)

	rePolicy = regexp.MustCompile(`(?i)^(?:CREATE|DROP|ALTER)\s+POLICY\s+(?:IF\s+EXISTS\s+)?` + identPattern + `\s+ON\s+(?:ONLY\s+)?` + tableRefPattern)

	// The trigger's target relation is the one after the LAST keyword
	// `ON` that is not inside a quoted identifier. `nonQuoteRun` is what
	// keeps a quoted column name such as `"x ON decoy"` from redirecting
	// the capture.
	reCreateTrig = regexp.MustCompile(`(?i)^CREATE\s+(?:OR\s+REPLACE\s+)?(?:CONSTRAINT\s+)?TRIGGER\s+` + identPattern + `\s+` + nonQuoteRun + `\sON\s+` + tableRefPattern)
	reDropTrig   = regexp.MustCompile(`(?i)^DROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?` + identPattern + `\s+ON\s+(?:ONLY\s+)?` + tableRefPattern)

	reRefreshMVConcurrent = regexp.MustCompile(`(?i)^REFRESH\s+MATERIALIZED\s+VIEW\s+CONCURRENTLY\s+` + tableRefPattern)
	reRefreshMV           = regexp.MustCompile(`(?i)^REFRESH\s+MATERIALIZED\s+VIEW\s+` + tableRefPattern)

	// Measured: `CLUSTER <table> USING <index>` runs inside a
	// transaction, but the parameterless `CLUSTER` (re-cluster every
	// previously clustered table in the database) does not —
	// "ERROR: CLUSTER cannot run inside a transaction block".
	reCluster     = regexp.MustCompile(`(?i)^CLUSTER\s+(?:VERBOSE\s+)?` + tableRefPattern)
	reBareCluster = regexp.MustCompile(`(?i)^CLUSTER\s*(?:VERBOSE\s*)?$`)
	// `LOCK` is parsed in two steps rather than with one regex carrying an
	// optional trailing group. A single lazy `(.+?)` followed by an
	// OPTIONAL `IN <mode> MODE` is ambiguous, and it resolved the wrong
	// way for a relation legitimately named `only`: the old pattern's
	// leading `(?:ONLY\s+)?` ate the relation name and the lazy group then
	// captured `IN SHARE MODE`, so `LOCK TABLE only IN SHARE MODE` was
	// charged against a relation called `in` (found in self-review before
	// round 7). Anchoring the mode clause at `$` removes the ambiguity,
	// and the per-relation `ONLY` is handled by splitRelationList.
	reLockStmt   = regexp.MustCompile(`(?i)^LOCK\s+(?:TABLE\s+)?(.+)$`)
	reLockInMode = regexp.MustCompile(`(?i)\s+IN\s+(.+?)\s+MODE(?:\s+NOWAIT)?\s*$`)
	reLockNowait = regexp.MustCompile(`(?i)\s+NOWAIT\s*$`)
	reVacuum     = regexp.MustCompile(`(?i)^VACUUM\b`)
	reAnalyze    = regexp.MustCompile(`(?i)^ANALYZE\b`)

	// `CREATE SCHEMA` accepts SCHEMA ELEMENTS: `CREATE SCHEMA s CREATE
	// TABLE child (id int REFERENCES live(id))` is one statement that
	// takes ShareRowExclusiveLock on the pre-existing `live` (measured).
	// Only the element-free form is harmless; anything else falls through
	// to findingUnclassified.
	reCreateSchema       = regexp.MustCompile(`(?i)^CREATE\s+SCHEMA\b`)
	reCreateSchemaSimple = regexp.MustCompile(`(?i)^CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:` + identPattern + `\s*)?(?:AUTHORIZATION\s+` + identPattern + `\s*)?$`)

	// `RESET lock_timeout` / `RESET ALL` restore the server default,
	// which is 0 — "wait forever". The parameter name may
	// be quoted.
	reResetLockTimeout = regexp.MustCompile(`(?i)^RESET\s+(?:"lock_timeout"|lock_timeout|ALL)\s*$`)

	reCommentOn = regexp.MustCompile(`(?i)^COMMENT\s+ON\b`)
	reDML       = regexp.MustCompile(`(?i)^(?:INSERT|UPDATE|DELETE|MERGE)\b`)
	reDoBlock   = regexp.MustCompile(`(?i)^DO\b`)

	// Measured on PostgreSQL 15.18:
	//	CREATE OR REPLACE VIEW over an existing view → AccessExclusiveLock
	//	ALTER SEQUENCE                               → ShareRowExclusiveLock
	reReplaceView = regexp.MustCompile(`(?i)^CREATE\s+OR\s+REPLACE\s+(?:TEMP\s+|TEMPORARY\s+)?VIEW\s+` + tableRefPattern)
	reAlterSeq    = regexp.MustCompile(`(?i)^ALTER\s+SEQUENCE\s+(?:IF\s+EXISTS\s+)?` + tableRefPattern)

	// Trailing `CASCADE` / `RESTRICT` on a DROP / TRUNCATE relation list.
	// Anchored and word-bounded so a relation legitimately named
	// `audit_cascade` keeps its suffix.
	reDropBehaviour = regexp.MustCompile(`(?i)\s+(?:CASCADE|RESTRICT)\s*$`)

	// `TRUNCATE` and `LOCK TABLE` accept `ONLY` per relation, not just on
	// the first one: `LOCK TABLE fresh, ONLY live IN SHARE MODE` really
	// does take ShareLock on `live` (measured). Reading `ONLY` as the
	// relation name resolved the target to `only` instead.
	reItemOnly = regexp.MustCompile(`(?i)^ONLY\s+`)

	// A lock_timeout value: optional sign, digits with an optional
	// fractional part, optional unit.
	reTimeoutValue = regexp.MustCompile(`(?i)^([+-]?)(\d+(?:\.\d+)?)\s*(us|ms|s|min|h|d)?$`)
)

// harmlessPrefixes enumerates statement shapes that acquire no lock above
// ROW EXCLUSIVE on a pre-existing relation. Anything NOT matched by a
// specific rule and NOT starting with one of these is reported as
// findingUnclassified — the fallback fails safe, so extending this list
// is a deliberate act with a review attached, not a silent widening.
//
// The list is deliberately restricted to READ paths and to statements
// that create a BRAND NEW object. `ALTER …` / `DROP …` of an existing
// catalogue object is NOT here: an earlier version of this lint listed
// them as "catalogue objects, no table-level lock", which measurement
// refuted —
//
//	CREATE OR REPLACE VIEW existing_view … → AccessExclusiveLock on it
//	ALTER SEQUENCE existing_seq …          → ShareRowExclusiveLock on it
//	ALTER DOMAIN d ADD CONSTRAINT …        → ShareLock on every table
//	                                          whose column uses the domain
//
// The first two now have their own rules; the rest fall through to
// findingUnclassified so the author has to measure and teach the lint
// rather than get a silent pass.
//
// Rationale per surviving entry:
//   - SELECT / WITH / TABLE / VALUES / EXPLAIN — read paths, at most
//     ACCESS SHARE.
//   - CREATE VIEW / CREATE MATERIALIZED VIEW (without OR REPLACE) —
//     ACCESS SHARE on the sources; the new relation is invisible to other
//     sessions.
//   - CREATE of TYPE, DOMAIN, EXTENSION, FUNCTION, PROCEDURE, AGGREGATE,
//     SEQUENCE, ROLE, CAST, COLLATION — brand new objects. Some of them
//     ARE relations in the pg_class sense (a composite type and a
//     sequence both get an entry), but the entry is the one this
//     transaction just made, so nothing an application query holds can
//     queue against it. `CREATE OR REPLACE FUNCTION` is included because
//     it locks a pg_proc entry, not a relation, and is the form migration
//     046 uses.
//   - `CREATE SCHEMA` is NOT on this list: it accepts schema elements and
//     is classified by its own rule, which admits only the element-free
//     form.
//   - GRANT / REVOKE — measured twice, including against a non-owner
//     role: no lock on the target relation appears in pg_locks.
//
// Transaction-control statements are deliberately NOT here. `SAVEPOINT` /
// `ROLLBACK TO SAVEPOINT` cancel a `SET LOCAL` made after the savepoint —
// measured, the budget goes back to 0 — which the positional coveredAt()
// walk cannot model. The runner owns the transaction and no migration in
// this directory issues one, so they fail closed as findingUnclassified.
var harmlessPrefixes = []string{
	"SELECT", "WITH", "VALUES", "TABLE ", "EXPLAIN",
	"CREATE VIEW", "CREATE MATERIALIZED VIEW",
	"CREATE TEMP VIEW", "CREATE TEMPORARY VIEW",
	"CREATE TYPE", "CREATE DOMAIN", "CREATE EXTENSION",
	"CREATE FUNCTION", "CREATE OR REPLACE FUNCTION",
	"CREATE PROCEDURE", "CREATE OR REPLACE PROCEDURE",
	"CREATE AGGREGATE", "CREATE SEQUENCE",
	"CREATE ROLE", "CREATE CAST", "CREATE COLLATION",
	"GRANT", "REVOKE",
}

// ---------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------

// lockTarget is one relation a statement locks, at one strength.
// `relation` is empty when the statement's target could not be resolved
// (e.g. DROP INDEX on an index created by an earlier migration) — the
// lint still counts the lock, it just cannot name the table.
type lockTarget struct {
	relation string
	class    lockClass
}

// fileState is the running knowledge a single-file scan accumulates as it
// walks the statements in order. Both maps are same-file scope only: a
// relation created in migration N is fully live by the time migration N+1
// runs against an instance that already applied N, so nothing carries
// across files.
type fileState struct {
	createdRelations map[string]bool   // relation → provably created in this file
	createdIndexes   map[string]string // index → relation it was created on

}

func newFileState() *fileState {
	return &fileState{
		createdRelations: make(map[string]bool),
		createdIndexes:   make(map[string]string),
	}
}

// classification is what classifyStatement decides about one statement.
type classification struct {
	targets []lockTarget

	// nonTransactional is a non-empty reason when the statement cannot
	// run inside the runner's per-file transaction at all.
	nonTransactional string

	// unclassified marks a statement whose shape the lint does not know.
	// Reported separately so the fix is "measure it and teach the lint",
	// not "add a budget and move on". unclassifiedReason overrides the
	// generic message when the lint knows exactly why it is refusing.
	unclassified       bool
	unclassifiedReason string

	// budget is set for a `SET … lock_timeout …` statement.
	budget *budgetStatement
}

// budgetStatement is a parsed `SET [LOCAL] lock_timeout` statement.
type budgetStatement struct {
	local    bool   // false for a session-scoped `SET` (leaks across files)
	value    string // raw value text, e.g. `'5s'`
	zero     bool   // value resolves to an effective timeout of 0
	unparsed bool   // value could not be read as an interval at all
}

// usable reports whether this budget actually bounds the wait.
func (b budgetStatement) usable() bool { return b.local && !b.zero && !b.unparsed }

// maxClass returns the strongest lock in a classification that lands on a
// relation NOT created in this file. Relations created here are excluded
// because the creating transaction is the only session that can see them.
func (c classification) maxClass(st *fileState) (lockClass, string) {
	best := lockNone
	bestRel := ""
	for _, t := range c.targets {
		if t.relation != "" && st.createdRelations[t.relation] {
			continue
		}
		if t.class > best {
			best = t.class
			bestRel = t.relation
		}
	}
	return best, bestRel
}

// classifyStatement decides which relations a statement locks and how
// strongly. Every mapping below was measured on PostgreSQL 15.18 by
// running the statement inside a transaction and reading the modes held
// on the target relation out of pg_locks:
//
//	ALTER TABLE … ADD COLUMN [DEFAULT …]      AccessExclusiveLock
//	ALTER TABLE … DROP COLUMN                 AccessExclusiveLock
//	ALTER TABLE … ADD CONSTRAINT … CHECK      AccessExclusiveLock
//	ALTER TABLE … ADD … CHECK … NOT VALID     AccessExclusiveLock
//	ALTER TABLE … ADD CONSTRAINT … UNIQUE     AccessExclusiveLock (+Share)
//	ALTER TABLE … ALTER COLUMN SET NOT NULL   AccessExclusiveLock
//	ALTER TABLE … ALTER COLUMN DROP NOT NULL  AccessExclusiveLock
//	ALTER TABLE … ALTER COLUMN SET/DROP DEFAULT AccessExclusiveLock
//	ALTER TABLE … ALTER COLUMN TYPE           AccessExclusiveLock (+Share)
//	ALTER TABLE … RENAME COLUMN               AccessExclusiveLock
//	ALTER TABLE … DROP CONSTRAINT             AccessExclusiveLock
//	ALTER TABLE … OWNER TO                    AccessExclusiveLock
//	ALTER TABLE … SET UNLOGGED                AccessExclusiveLock (+Share)
//	ALTER TABLE … ENABLE/DISABLE ROW LEVEL SECURITY   AccessExclusiveLock
//	ALTER TABLE … FORCE/NO FORCE ROW LEVEL SECURITY   AccessExclusiveLock
//	CREATE POLICY / DROP POLICY               AccessExclusiveLock
//	DROP INDEX                                AccessExclusiveLock
//	TRUNCATE                                  AccessExclusiveLock (+Share)
//	CREATE TABLE … PARTITION OF parent        AccessExclusiveLock on parent
//	CREATE OR REPLACE VIEW existing_view      AccessExclusiveLock
//	DO $$ … ALTER TABLE … $$                  AccessExclusiveLock
//	ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY
//	                    ShareRowExclusiveLock on BOTH tables
//	CREATE TABLE … REFERENCES <existing>
//	                    ShareRowExclusiveLock on the REFERENCED table
//	CREATE TRIGGER                            ShareRowExclusiveLock
//	ALTER SEQUENCE                            ShareRowExclusiveLock
//	CREATE [UNIQUE] INDEX (non-concurrent)    ShareLock
//	LOCK TABLE … IN EXCLUSIVE MODE            ExclusiveLock
//	REFRESH MATERIALIZED VIEW CONCURRENTLY    ExclusiveLock
//	ALTER TABLE … VALIDATE CONSTRAINT         ShareUpdateExclusiveLock
//	ALTER TABLE … SET (fillfactor=…)          ShareUpdateExclusiveLock
//	ALTER TABLE … SET STATISTICS              ShareUpdateExclusiveLock
//	COMMENT ON TABLE                          ShareUpdateExclusiveLock
//	ANALYZE                                   ShareUpdateExclusiveLock
//	INSERT / UPDATE                           RowExclusiveLock
//	SELECT                                    AccessShareLock
//	GRANT, REVOKE                             no lock on any relation
//	CREATE TYPE                               no lock on a PRE-EXISTING
//	                                           relation (a composite type
//	                                           does get its own pg_class
//	                                           entry, which nothing else
//	                                           can see yet)
//	CREATE FUNCTION (plpgsql string body),
//	CREATE EXTENSION                          no lock on any relation in
//	                                           the probes run here
//	CREATE FUNCTION (sql string body, or the
//	  SQL-standard BEGIN ATOMIC form)          AccessShareLock on the
//	                                           tables the body reads
//	CREATE TABLE … INHERITS (parent)          ShareUpdateExclusiveLock on
//	                                           each parent
//
// A brand-new `CREATE TABLE` DOES take AccessExclusiveLock on the
// relation it creates — measured, a plain `CREATE TABLE t (id int)` holds
// exactly AccessExclusiveLock on `t` (a table with an inline FK also
// shows AccessShare and ShareRowExclusive, but those come from the FK,
// not from the CREATE). That lock is free of contention because no other
// session can see the relation yet, which is exactly what the same-file
// exemption in maxClass encodes — it is not that the lock is absent.
//
// `CREATE FUNCTION` locks whatever its body is PARSED against at
// definition time: measured, the SQL-standard `BEGIN ATOMIC` form and an
// SQL-language string body both held AccessShareLock on the table they
// read, while the plpgsql string body migration 046 uses held none (a
// plpgsql body is not parsed until it runs). All three are below the
// SHARE threshold, so the classification is the same either way.
// `CREATE EXTENSION` runs an arbitrary install script, so what it locks
// depends on the extension — the one this directory uses (`uuid-ossp`)
// creates only functions, and the general case is covered by the
// user-code limitation in the package doc, not by this row.
//
// The default for an unrecognised `ALTER TABLE` action is ACCESS
// EXCLUSIVE — the strongest mode — because that is the mode almost every
// ALTER TABLE subform takes, and over-reporting strength can only cause a
// budget to be demanded, never skipped.
func classifyStatement(s statement, st *fileState) classification {
	text := s.scanText
	upper := strings.ToUpper(text)

	// --- lock budget ------------------------------------------------
	// Parsed from `text` (literals preserved) because the value IS a
	// string literal.
	if m := reSetLockTimeout.FindStringSubmatch(s.text); m != nil {
		scope := strings.ToUpper(strings.TrimSpace(m[1]))
		value := strings.TrimSpace(m[2])
		zero, ok := timeoutIsZero(value)
		return classification{budget: &budgetStatement{
			local:    scope == "LOCAL",
			value:    value,
			zero:     ok && zero,
			unparsed: !ok,
		}}
	}
	if reResetLockTimeout.MatchString(text) {
		// Represented as a budget statement so coveredAt()'s "nearest
		// preceding budget" walk sees it and stops treating an earlier
		// `SET LOCAL` as still in force.
		c := classification{budget: &budgetStatement{
			local: true,
			value: collapseSQLSpace(text),
			zero:  true,
		}}
		return c
	}
	if reSetStringMode.MatchString(text) {
		return classification{
			unclassified:       true,
			unclassifiedReason: "changes standard_conforming_strings, which decides how the lint must lex every following statement; a session-scoped SET also survives COMMIT onto the next migration file",
		}
	}
	if reSetAnything.MatchString(text) {
		return classification{}
	}
	if reCreateSchema.MatchString(text) {
		if reCreateSchemaSimple.MatchString(text) {
			return classification{}
		}
		return classification{unclassified: true}
	}

	// --- statements the runner's transaction cannot execute ----------
	if m := reCreateIndex.FindStringSubmatch(text); m != nil && m[1] != "" {
		return classification{nonTransactional: "CREATE INDEX CONCURRENTLY cannot run inside a transaction block"}
	}
	if m := reDropIndex.FindStringSubmatch(text); m != nil && m[1] != "" {
		return classification{nonTransactional: "DROP INDEX CONCURRENTLY cannot run inside a transaction block"}
	}
	if reVacuum.MatchString(text) {
		return classification{nonTransactional: "VACUUM cannot run inside a transaction block"}
	}
	if reBareCluster.MatchString(text) {
		return classification{nonTransactional: "CLUSTER without a table name cannot run inside a transaction block"}
	}
	if m := reAlterTable.FindStringSubmatch(text); m != nil && reDetachConcurrent.MatchString(m[2]) {
		return classification{nonTransactional: "ALTER TABLE … DETACH PARTITION … CONCURRENTLY cannot run inside a transaction block"}
	}
	if reReindexAny.MatchString(text) {
		m := reReindex.FindStringSubmatch(text)
		if m == nil {
			// A REINDEX shape the grammar above does not cover. Fail safe
			// rather than guess which object kind it names.
			return classification{unclassified: true}
		}
		kind := strings.ToUpper(m[1])
		if m[2] != "" {
			return classification{nonTransactional: "REINDEX CONCURRENTLY cannot run inside a transaction block"}
		}
		if kind == "SCHEMA" || kind == "DATABASE" || kind == "SYSTEM" {
			return classification{nonTransactional: "REINDEX " + kind + " cannot run inside a transaction block"}
		}
		// REINDEX INDEX / TABLE runs inside a transaction only when the
		// target is NOT partitioned — measured, `REINDEX TABLE <a
		// partitioned table>` is refused with "REINDEX TABLE cannot run
		// inside a transaction block". A static scan
		// cannot know whether a pre-existing relation is partitioned, so
		// the safe answer is "the lint cannot certify this", not a lock
		// class that would let a budget make it green.
		return classification{unclassified: true}
	}

	// --- CREATE TABLE ------------------------------------------------
	if m := reCreateTable.FindStringSubmatch(text); m != nil {
		name := normalizeRelation(m[2])
		// `IF NOT EXISTS` proves nothing: on an instance where the
		// relation already exists this statement is a no-op and every
		// later statement in the file contends with live traffic. Only an
		// unconditional CREATE earns the same-file exemption.
		if m[1] == "" {
			st.createdRelations[name] = true
		}
		c := classification{}
		// `CREATE TABLE … AS SELECT` has no column list, so there is no
		// inline REFERENCES to find; it reads its sources under ACCESS
		// SHARE, which needs no budget.
		for _, ref := range reReferences.FindAllStringSubmatch(m[3], -1) {
			c.targets = append(c.targets, lockTarget{
				relation: normalizeRelation(ref[1]),
				class:    lockShareRowExclusive,
			})
		}
		if p := rePartitionOf.FindStringSubmatch(m[3]); p != nil {
			c.targets = append(c.targets, lockTarget{
				relation: normalizeRelation(p[1]),
				class:    lockAccessExclusive,
			})
		}
		if inh := reInherits.FindStringSubmatch(m[3]); inh != nil {
			for _, rel := range splitRelationList(inh[1]) {
				c.targets = append(c.targets, lockTarget{relation: rel, class: lockShareUpdateExclusive})
			}
		}
		return c
	}

	// --- CREATE INDEX (non-concurrent) -------------------------------
	if m := reCreateIndex.FindStringSubmatch(text); m != nil {
		table := normalizeRelation(m[4])
		// Same `IF NOT EXISTS` reasoning as CREATE TABLE: a skipped
		// CREATE INDEX must not register a name that a later DROP INDEX
		// would then treat as this file's own.
		if idx := normalizeRelation(m[3]); idx != "" && m[2] == "" {
			st.createdIndexes[idx] = table
		}
		return classification{targets: []lockTarget{{relation: table, class: lockShare}}}
	}

	// --- DROP INDEX --------------------------------------------------
	if m := reDropIndex.FindStringSubmatch(text); m != nil {
		c := classification{}
		for _, name := range splitRelationList(m[2]) {
			// An index this file created, on a table this file created,
			// is invisible to every other session — no contention.
			if table, ok := st.createdIndexes[name]; ok && st.createdRelations[table] {
				continue
			}
			// Otherwise DROP INDEX takes ACCESS EXCLUSIVE on the index's
			// parent table, which this static scan cannot name.
			c.targets = append(c.targets, lockTarget{relation: "", class: lockAccessExclusive})
		}
		return c
	}

	// --- ALTER TABLE -------------------------------------------------
	if m := reAlterTable.FindStringSubmatch(text); m != nil {
		table := normalizeRelation(m[1])
		rest := m[2]
		c := classification{}

		switch {
		case reAlterValidate.MatchString(rest),
			reAlterClusterOn.MatchString(rest),
			reAlterSetStatistics.MatchString(rest):
			c.targets = append(c.targets, lockTarget{relation: table, class: lockShareUpdateExclusive})
		case reAlterSetStorage.MatchString(rest):
			// Not every storage parameter takes the weak lock. Measured
			// on PostgreSQL 15.18: fillfactor, autovacuum_enabled and
			// parallel_workers each take ShareUpdateExclusiveLock, while
			// `SET (user_catalog_table = true)` takes
			// AccessExclusiveLock. A parameter the
			// allowlist does not name is charged ACCESS EXCLUSIVE.
			c.targets = append(c.targets, lockTarget{
				relation: table,
				class:    storageParamClass(reAlterSetStorage.FindStringSubmatch(rest)[1]),
			})
		case reAlterAddFK.MatchString(rest):
			c.targets = append(c.targets, lockTarget{relation: table, class: lockShareRowExclusive})
		default:
			c.targets = append(c.targets, lockTarget{relation: table, class: lockAccessExclusive})
		}

		if p := rePartitionAttach.FindStringSubmatch(rest); p != nil {
			// Measured: ATTACH holds ShareUpdateExclusiveLock on the
			// PARENT and AccessExclusiveLock on the relation being
			// attached. The default branch above already charged the
			// parent ACCESS EXCLUSIVE, so downgrade it and charge the
			// attached relation instead.
			//
			// DETACH keeps the ACCESS EXCLUSIVE default on both — measured
			// for the plain form. `DETACH … FINALIZE` is documented to
			// take only SHARE UPDATE EXCLUSIVE on the parent, but that
			// could not be reproduced here (it needs a pending concurrent
			// detach, and a concurrent detach cannot run in the runner's
			// transaction at all), so it is left at the stronger, unmeasured
			// default rather than downgraded on documentation alone. The
			// effect is an over-report on a form no migration here uses.
			if strings.HasPrefix(strings.ToUpper(rest), "ATTACH") {
				c.targets = []lockTarget{{relation: table, class: lockShareUpdateExclusive}}
				// If the parent already has a DEFAULT partition, ATTACH
				// takes ACCESS EXCLUSIVE on it too — measured. Whether one
				// exists is not knowable from the migration text, so an
				// unnamed target stands in for it. That is what keeps
				// `CREATE TABLE child …; ALTER TABLE parent ATTACH
				// PARTITION child …` above the bar even though both named
				// relations are below it.
				//
				// One case where a default partition provably cannot be
				// hit, and the placeholder would be a false positive an
				// honest author runs into: `ATTACH … DEFAULT` itself. A
				// table cannot have two default partitions, so a
				// successful ATTACH proves there was none. Measured:
				// parent SHARE UPDATE EXCLUSIVE, attached relation ACCESS
				// EXCLUSIVE.
				//
				// "The parent was CREATEd in this file" is NOT such a
				// case, even though it looks like one: ATTACH can attach a
				// PRE-EXISTING table, so a parent this file created can
				// still have a default partition it did not create, and
				// re-attaching around it takes ACCESS EXCLUSIVE on that
				// pre-existing relation.
				if !reAttachDefault.MatchString(rest) {
					c.targets = append(c.targets, lockTarget{relation: "", class: lockAccessExclusive})
				}
			}
			c.targets = append(c.targets, lockTarget{
				relation: normalizeRelation(p[1]),
				class:    lockAccessExclusive,
			})
		}

		// A REFERENCES clause anywhere in the action list also locks the
		// referenced table at SHARE ROW EXCLUSIVE, whichever ALTER form
		// carries it (ADD CONSTRAINT … FOREIGN KEY, or an inline
		// `ADD COLUMN x UUID REFERENCES y(id)`).
		for _, ref := range reReferences.FindAllStringSubmatch(rest, -1) {
			c.targets = append(c.targets, lockTarget{
				relation: normalizeRelation(ref[1]),
				class:    lockShareRowExclusive,
			})
		}
		return c
	}

	// --- policies / triggers / views / sequences ----------------------
	if m := rePolicy.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockAccessExclusive}}}
	}
	if m := reDropTrig.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockAccessExclusive}}}
	}
	if m := reCreateTrig.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockShareRowExclusive}}}
	}
	if m := reReplaceView.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockAccessExclusive}}}
	}
	if m := reAlterSeq.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockShareRowExclusive}}}
	}

	// --- whole-relation ACCESS EXCLUSIVE forms -----------------------
	if m := reTruncate.FindStringSubmatch(text); m != nil {
		return classification{targets: relationTargets(m[1], lockAccessExclusive)}
	}
	if m := reDropTable.FindStringSubmatch(text); m != nil {
		return classification{targets: relationTargets(m[1], lockAccessExclusive)}
	}
	if m := reRefreshMVConcurrent.FindStringSubmatch(text); m != nil {
		// Measured: `REFRESH MATERIALIZED VIEW CONCURRENTLY` runs fine
		// inside a transaction (unlike CREATE INDEX CONCURRENTLY) and
		// takes ExclusiveLock — still above the bar, but not ACCESS
		// EXCLUSIVE, and the table should say what was measured.
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockExclusive}}}
	}
	if m := reRefreshMV.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockAccessExclusive}}}
	}
	if m := reCluster.FindStringSubmatch(text); m != nil {
		return classification{targets: []lockTarget{{relation: normalizeRelation(m[1]), class: lockAccessExclusive}}}
	}
	if m := reLockStmt.FindStringSubmatch(text); m != nil {
		rest, mode := m[1], ""
		if loc := reLockInMode.FindStringSubmatchIndex(rest); loc != nil {
			mode = rest[loc[2]:loc[3]]
			rest = rest[:loc[0]]
		} else {
			rest = reLockNowait.ReplaceAllString(rest, "")
		}
		// An omitted mode means ACCESS EXCLUSIVE, which is also what
		// lockModeFromName returns for a mode name it does not recognise.
		return classification{targets: relationTargets(rest, lockModeFromName(mode))}
	}

	// --- below the bar ------------------------------------------------
	if reCommentOn.MatchString(text) {
		return classification{targets: []lockTarget{{relation: "", class: lockShareUpdateExclusive}}}
	}
	if reAnalyze.MatchString(text) {
		return classification{targets: []lockTarget{{relation: "", class: lockShareUpdateExclusive}}}
	}
	if reDML.MatchString(text) {
		return classification{targets: []lockTarget{{relation: "", class: lockRowExclusive}}}
	}
	if reAlterTypeAddValue.MatchString(text) {
		// Measured: no lock on any user relation, and legal inside a
		// transaction. Note for authors: the added value cannot be USED
		// until the transaction commits, so a migration that adds an enum
		// value and then writes it in the same file will fail — that is a
		// different rule from this lint's, and is called out in
		// apps/api/migrations/CLAUDE.md.
		return classification{}
	}

	// --- DO blocks ----------------------------------------------------
	if reDoBlock.MatchString(text) {
		// A DO body is PL/pgSQL, not SQL, and this lint does not parse
		// it. It needs no EXECUTE to run DDL — measured on PostgreSQL
		// 15.18, `DO $$ BEGIN ALTER TABLE t ADD COLUMN c int; END $$;`
		// takes AccessExclusiveLock on t — so the block is charged the
		// strongest lock against an unnamed relation and the file needs a
		// budget. Every DO block in this directory is a read-only
		// pre-flight assertion, but "usually read-only" is not something
		// a gate can rely on.
		//
		// This is the one member of the "locks taken by code a statement
		// invokes" class that IS charged, because a DO block is a shape
		// honest authors really write here — migrations 027 / 041 / 044 /
		// 045 all use one as a pre-flight assertion.
		return classification{targets: []lockTarget{{relation: "", class: lockAccessExclusive}}}
	}

	// --- known-harmless prefixes --------------------------------------
	for _, p := range harmlessPrefixes {
		if strings.HasPrefix(upper, p) {
			return classification{}
		}
	}

	return classification{unclassified: true}
}

// lockTimeoutMaxMS is PostgreSQL's upper bound for lock_timeout.
// Measured: `SET LOCAL lock_timeout='-5s'` and `'2147483648ms'` are both
// rejected with "outside the valid range for parameter "lock_timeout"
// (0 .. 2147483647)". A value PostgreSQL refuses is not a budget — the
// migration would abort on the SET itself.
const lockTimeoutMaxMS = 2147483647

// timeoutIsZero reports whether a lock_timeout value resolves to an
// effective timeout of zero — PostgreSQL's "wait forever", which is
// exactly the state this lint exists to prevent. `ok` is false when the
// value could not be read as an interval PostgreSQL would accept.
//
// PostgreSQL rounds the value to whole milliseconds using round-half-to-
// EVEN, not round-half-away-from-zero. Measured on 15.18:
//
//	'0.4ms' → 0    '0.5ms' → 0    '0.6ms' → 1ms
//	'1.5ms' → 2ms  '2.5ms' → 2ms
//	'+0' → 0       '-0ms' → 0     '00' → 0      '0.0s' → 0
//
// `'0.5ms'` is why math.Round is wrong here: it rounds to 1 and would let
// a value PostgreSQL treats as "no timeout" pass as a budget.
//
// `DEFAULT` restores the server default, which is 0 on this instance and
// on a stock PostgreSQL.
func timeoutIsZero(v string) (zero, ok bool) {
	t := strings.TrimSpace(v)
	if strings.EqualFold(t, "DEFAULT") {
		return true, true
	}
	if len(t) >= 2 && ((t[0] == '\'' && t[len(t)-1] == '\'') || (t[0] == '"' && t[len(t)-1] == '"')) {
		t = t[1 : len(t)-1]
	}
	t = strings.TrimSpace(t)
	m := reTimeoutValue.FindStringSubmatch(t)
	if m == nil {
		return false, false
	}
	n, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return false, false
	}
	var ms float64
	switch strings.ToLower(m[3]) {
	case "us":
		ms = n / 1000
	case "", "ms":
		ms = n
	case "s":
		ms = n * 1000
	case "min":
		ms = n * 60 * 1000
	case "h":
		ms = n * 60 * 60 * 1000
	case "d":
		ms = n * 24 * 60 * 60 * 1000
	}
	if m[1] == "-" {
		ms = -ms
	}
	rounded := math.RoundToEven(ms)
	if rounded < 0 || rounded > lockTimeoutMaxMS {
		// PostgreSQL refuses these outright, so the migration never gets
		// as far as the DDL. Reported as unreadable rather than as a zero
		// budget, because the fix is different.
		return false, false
	}
	return rounded == 0, true
}

// normalizeRelation canonicalises a (possibly schema-qualified) relation
// reference into the key used for the same-file exemption. Each dotted
// component is normalised independently and the qualification is
// preserved — `scratch.accounts` must not compare equal to
// `public.accounts`.
func normalizeRelation(ref string) string {
	parts := splitQualified(ref)
	for i := range parts {
		parts[i] = normalizeIdent(parts[i])
	}
	// Joined with NUL rather than "." so a quoted name that CONTAINS a
	// dot cannot collide with a schema-qualified reference: PostgreSQL
	// reads `"public.foo"` as one relation literally named `public.foo`
	// and `public.foo` as relation `foo` in schema `public`, and the lint
	// must not treat creating one as exempting the other. NUL cannot appear in a PostgreSQL identifier.
	return strings.Join(parts, "\x00")
}

// normalizeIdent canonicalises ONE identifier. PostgreSQL folds unquoted
// identifiers to lower case and leaves double-quoted ones exactly as
// written, so `"Components"` and `components` are different relations and
// must not be conflated — folding both would let a file that creates the
// quoted one exempt a lock on the unquoted one.
func normalizeIdent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return foldASCII(s)
}

// foldASCII lower-cases only A-Z, which is what PostgreSQL's default
// (non-ICU) identifier folding does. `strings.ToLower` would additionally
// fold non-ASCII letters — measured on PostgreSQL 15.18 UTF-8, an
// unquoted `ÄBC` is stored as `Äbc`, so folding it to `äbc` in Go would
// make the lint treat two genuinely different relations as one.
func foldASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// splitQualified splits `schema.relation` on dots that are outside a
// double-quoted identifier, so a quoted name containing a dot survives.
func splitQualified(ref string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c == '"' {
			if inQuote && i+1 < len(ref) && ref[i+1] == '"' {
				cur.WriteString(`""`)
				i++
				continue
			}
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == '.' && !inQuote {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}

// splitRelationList parses the comma-separated relation list that
// TRUNCATE / DROP TABLE / DROP INDEX accept, dropping a trailing
// CASCADE / RESTRICT. Commas and the drop-behaviour keyword are only
// recognised outside quoted identifiers.
func splitRelationList(s string) []string {
	s = reDropBehaviour.ReplaceAllString(strings.TrimSpace(s), "")

	var items []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			if inQuote && i+1 < len(s) && s[i+1] == '"' {
				cur.WriteString(`""`)
				i++
				continue
			}
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inQuote {
			items = append(items, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	items = append(items, cur.String())

	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// `ONLY <relation>` is a per-item modifier in TRUNCATE and LOCK.
		item = reItemOnly.ReplaceAllString(item, "")
		// Keep only the leading relation reference, dropping any
		// per-item modifier that followed it. Splitting on whitespace
		// would truncate a quoted name that contains a space, so the
		// leading reference is scanned quote-aware.
		if ref := leadingRelationRef(item); ref != "" {
			out = append(out, normalizeRelation(ref))
		}
	}
	return out
}

// leadingRelationRef returns the (possibly schema-qualified, possibly
// quoted) relation reference at the start of `item`, stopping at the
// first whitespace that is OUTSIDE a double-quoted identifier.
func leadingRelationRef(item string) string {
	inQuote := false
	for i := 0; i < len(item); i++ {
		c := item[i]
		if c == '"' {
			if inQuote && i+1 < len(item) && item[i+1] == '"' {
				i++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if !inQuote && isSpaceByte(c) {
			return item[:i]
		}
	}
	return item
}

// weakLockStorageParams are the ALTER TABLE storage parameters
// PostgreSQL documents as taking only SHARE UPDATE EXCLUSIVE. Anything
// not on this list — including `user_catalog_table`, measured at ACCESS
// EXCLUSIVE — is charged the strong lock.
//
// The `autovacuum_` family is matched by prefix in storageParamClass,
// which also strips an optional `toast.` qualifier before matching.
var weakLockStorageParams = map[string]bool{
	"fillfactor":                  true,
	"parallel_workers":            true,
	"log_autovacuum_min_duration": true,
	"vacuum_index_cleanup":        true,
	"vacuum_truncate":             true,
	"toast_tuple_target":          true,
}

// storageParamClass returns the lock class an `ALTER TABLE … SET (…)`
// parameter list takes: the weak lock only if EVERY named parameter is on
// the allowlist.
func storageParamClass(list string) lockClass {
	for _, item := range strings.Split(list, ",") {
		name := strings.TrimSpace(item)
		if i := strings.IndexAny(name, "= \t"); i >= 0 {
			name = name[:i]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		// A `toast.` prefix selects the same parameter on the TOAST
		// relation, so it is stripped and the SAME allowlist applied —
		// blanket-allowing everything under `toast.` would have waved
		// through a name that is not a weak-lock parameter at all.
		name = strings.TrimPrefix(name, "toast.")
		if weakLockStorageParams[name] || strings.HasPrefix(name, "autovacuum_") {
			continue
		}
		return lockAccessExclusive
	}
	return lockShareUpdateExclusive
}

// relationTargets builds one lockTarget per relation in a comma list.
func relationTargets(list string, class lockClass) []lockTarget {
	var out []lockTarget
	for _, r := range splitRelationList(list) {
		out = append(out, lockTarget{relation: r, class: class})
	}
	return out
}

// lockModeFromName maps an explicit `LOCK TABLE … IN <mode> MODE` mode
// name onto a lockClass. An omitted mode means ACCESS EXCLUSIVE, which is
// also the fallback for a mode this lint does not recognise.
func lockModeFromName(mode string) lockClass {
	switch strings.ToUpper(collapseSQLSpace(mode)) {
	case "ACCESS SHARE", "ROW SHARE":
		return lockNone
	case "ROW EXCLUSIVE":
		return lockRowExclusive
	case "SHARE UPDATE EXCLUSIVE":
		return lockShareUpdateExclusive
	case "SHARE":
		return lockShare
	case "SHARE ROW EXCLUSIVE":
		return lockShareRowExclusive
	case "EXCLUSIVE":
		return lockExclusive
	default:
		return lockAccessExclusive
	}
}

// ---------------------------------------------------------------------
// Per-file scan
// ---------------------------------------------------------------------

// heavyStatement is one statement that needs a budget, with the evidence
// needed to explain why.
type heavyStatement struct {
	stmt     statement
	class    lockClass
	relation string
	index    int // position in the file's statement list
}

// fileScan is everything the lint learned about one migration file.
type fileScan struct {
	name string

	// lexError is non-empty when the lexer reached EOF inside a comment,
	// literal or dollar-quoted body. Everything else in this struct is
	// then unreliable, so audit() reports it and nothing else.
	lexError string

	// heavy holds every statement at or above budgetRequiredFrom on a
	// relation not created in this file, in source order.
	heavy []heavyStatement

	// uncovered holds the subset of heavy whose effective lock_timeout at
	// that point in the file is absent, zero, unparseable or
	// session-scoped.
	uncovered []heavyStatement

	// budgets holds every `SET … lock_timeout` statement in source order.
	budgets []budgetAt

	// nonTransactional / unclassified are per-statement problems that are
	// independent of the budget rule.
	nonTransactional []problemStatement
	unclassified     []problemStatement

	// strongest is the strongest lock the file takes on a pre-existing
	// relation, for the --verbose classification table.
	strongest lockClass

	// statements is the total statement count, reported so the scan's
	// coverage is auditable rather than implied.
	statements int
}

type budgetAt struct {
	budget budgetStatement
	stmt   statement
	index  int
}

type problemStatement struct {
	stmt   statement
	reason string
	index  int // position in the file's statement list
}

// needsBudget reports whether the file contains any statement the rule
// applies to.
func (f fileScan) needsBudget() bool { return len(f.heavy) > 0 }

// scanFile classifies every statement in one migration body and works out
// which of them run without an effective lock budget.
//
// "Effective" is computed positionally: `SET LOCAL` applies from its own
// statement to the end of the transaction, so the budget in force at
// statement i is the LAST budget statement before i. Re-checking at every
// heavy statement (rather than only the first) is what catches a file
// that sets a budget, then resets it to 0, and then does the DDL.
func scanFile(name, body string) fileScan {
	f := fileScan{name: name}
	stmts, lexErr := splitStatements(body)
	if lexErr != "" {
		f.lexError = lexErr
		f.statements = len(stmts)
		return f
	}
	st := newFileState()
	f.statements = len(stmts)

	for i, s := range stmts {
		c := classifyStatement(s, st)

		if c.budget != nil {
			f.budgets = append(f.budgets, budgetAt{budget: *c.budget, stmt: s, index: i})
			continue
		}
		if c.nonTransactional != "" {
			f.nonTransactional = append(f.nonTransactional, problemStatement{stmt: s, reason: c.nonTransactional, index: i})
			continue
		}
		if c.unclassified {
			reason := c.unclassifiedReason
			if reason == "" {
				reason = "statement shape not recognised by the lint"
			}
			f.unclassified = append(f.unclassified, problemStatement{stmt: s, reason: reason, index: i})
			continue
		}

		class, rel := c.maxClass(st)
		if class > f.strongest {
			f.strongest = class
		}
		if class < budgetRequiredFrom {
			continue
		}
		h := heavyStatement{stmt: s, class: class, relation: rel, index: i}
		f.heavy = append(f.heavy, h)
		if !f.coveredAt(i) {
			f.uncovered = append(f.uncovered, h)
		}
	}
	return f
}

// coveredAt reports whether a usable budget is in force at statement
// index i: the nearest preceding `SET … lock_timeout` must exist, be
// LOCAL, and resolve to a non-zero interval.
func (f fileScan) coveredAt(i int) bool {
	var eff *budgetStatement
	for k := range f.budgets {
		if f.budgets[k].index < i {
			eff = &f.budgets[k].budget
		}
	}
	if eff == nil {
		return false
	}
	return eff.usable()
}

// budgetDiagnosis explains, for output, WHY the heavy statement at
// position `at` is uncovered — the causes need different fixes, and a
// file with several budgets can have a different cause per statement.
func (f fileScan) budgetDiagnosis(at int) string {
	if len(f.budgets) == 0 {
		return "no `SET LOCAL lock_timeout` in the file"
	}
	var preceding *budgetAt
	for k := range f.budgets {
		if f.budgets[k].index < at {
			preceding = &f.budgets[k]
		}
	}
	if preceding == nil {
		return fmt.Sprintf("the file's `SET … lock_timeout` (line %d) comes AFTER this statement; "+
			"a budget only applies to statements that follow it", f.budgets[0].stmt.line)
	}
	if !preceding.budget.local {
		return fmt.Sprintf("the budget in force (line %d) is session-scoped `SET`, not `SET LOCAL`; "+
			"a plain SET survives COMMIT and leaks onto the next migration's connection",
			preceding.stmt.line)
	}
	if preceding.budget.unparsed {
		return fmt.Sprintf("the budget in force (line %d) is `%s`, which the lint cannot read as an interval",
			preceding.stmt.line, preceding.budget.value)
	}
	return fmt.Sprintf("the budget in force (line %d) is `%s`, which disables the timeout",
		preceding.stmt.line, preceding.budget.value)
}

// ---------------------------------------------------------------------
// Legacy baseline
// ---------------------------------------------------------------------

// legacyBaselineRationale is the single shared justification for every
// entry in legacyBaseline. It is one paragraph rather than 60 copies of
// the same sentence because the reason genuinely is identical for all of
// them — unlike lint-migration-rls's structuralExemptions, where each
// table is exempt for its own product-specific reason.
const legacyBaselineRationale = "" +
	"predates the lock-budget convention introduced by migration 063. " +
	"These files are grandfathered rather than edited because a shipped " +
	"migration is immutable by convention once it is recorded in " +
	"schema_migrations: an instance that already applied it will never " +
	"re-execute it, so a retroactive budget would be dead text there, and a " +
	"fresh install runs the whole sequence against a database with no " +
	"application traffic yet. (That second half assumes ONE runner: nothing " +
	"in cmd/migrate or internal/database/migrate.go takes an advisory lock, " +
	"so two replicas booting against the same empty database can both read " +
	"an empty schema_migrations and race.) " +
	"RESIDUAL RISK, stated rather than papered over: an " +
	"instance that is BEHIND — applied through, say, 025 — really will " +
	"execute 026 onwards on its next upgrade, and those files will run with " +
	"lock_timeout = 0 against live traffic. This baseline accepts that for " +
	"the already-shipped files; it does not claim the risk is zero. Closing " +
	"it would mean rewriting 58 applied migrations, which is a separate " +
	"decision from gating the next one."

// baselineEntry is the reviewed FOOTPRINT of one grandfathered
// migration, not merely permission to skip it.
//
// A filename-only allowlist (the first version of this map) waived
// whatever the named file happened to contain, so appending a fresh
// unbudgeted `ALTER TABLE` to a baselined migration would have been
// waived too — the waiver would have covered statements nobody reviewed
// . Recording the count and the strongest class turns
// the entry into a fingerprint: audit() waives the file only while it
// still matches, and reports drift otherwise.
//
// `uncovered` counts statements as the LINT charges them, which is
// deliberately not the same as what the SQL provably does: a `DO` block
// is charged ACCESS EXCLUSIVE because its body is opaque, and a relation
// introduced by `CREATE TABLE IF NOT EXISTS` is treated as possibly
// pre-existing. The note text is phrased in those terms rather than
// asserting facts about the SQL that the scanner did not establish
// .
type baselineEntry struct {
	// uncovered is len(fileScan.uncovered) at review time. Human-readable
	// and cross-checkable against the --verbose table.
	uncovered int
	// strongest is fileScan.strongest at review time.
	strongest lockClass
	// digest is the machine check: a hash over the ORDERED sequence of
	// waived statements — for each one its lock class, its resolved
	// relation, and statement.fpText.
	//
	// Count-plus-strongest alone is not a fingerprint — a file can budget
	// its old statement and add a new unbudgeted one of the same class and
	// keep both numbers identical, which would silently shift the waiver
	// onto DDL nobody reviewed.
	//
	// What the digest is INSENSITIVE to, by construction: comments in the
	// outer SQL, and how much whitespace separates two outer tokens
	// (indentation, line breaks between tokens that were already
	// separated). It is NOT insensitive to whitespace APPEARING or
	// DISAPPEARING between tokens: `ON t(id)` and `ON t (id)` are the same
	// statement to PostgreSQL but hash differently, because canonicalising
	// that would need a tokeniser rather than a whitespace pass. What it
	// IS sensitive to: every byte inside a string literal, a quoted
	// identifier or a `$$ … $$` body.
	//
	// Known gap: PostgreSQL concatenates two adjacent string literals when
	// a NEWLINE separates them and not when a comment does. The digest
	// canonicalises both to one space, so those two spellings hash alike
	//. No migration in this directory uses adjacent
	// literal concatenation. So editing `DEFAULT 'a'` to
	// `DEFAULT 'b'`, or adding a comment INSIDE a DO body, changes it. That
	// asymmetry is deliberate — the lint does not parse PL/pgSQL and
	// cannot tell a comment inside a dollar-quoted body from code, and an
	// already-shipped migration should not be changing anyway.
	digest string
	// note is the human-readable footprint, echoed in --verbose.
	note string
}

// fingerprint hashes the ordered set of statements a waiver would cover.
// Truncated to 16 hex characters: this is a change detector for
// hand-edited source, not a security primitive.
func (f fileScan) fingerprint() string {
	h := sha256.New()
	for _, u := range f.uncovered {
		// Hashed over `fpText` — see the statement type's doc comment.
		// Not scanText: that blanks literal and dollar-quoted CONTENT, so
		// every `DO $$ … $$` block collapsed to `DO $$$$` and rewriting a
		// body from a read-only pre-flight into `ALTER TABLE … ADD
		// COLUMN` left the digest unchanged. Not
		// `text` either: that canonicalises whitespace everywhere, and a
		// newline inside a dollar-quoted body is executable syntax — it
		// terminates a `--` comment — so collapsing it produced a second
		// collision.
		fmt.Fprintf(h, "%d\x00%s\x00%s\n", u.class, u.relation, u.stmt.fpText)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// matchesBaseline reports whether the file still looks exactly like what
// the baseline entry was reviewed against. Shared by audit(), summarise()
// and printTable() so the three can never disagree about whether a file
// is waived.
func (f fileScan) matchesBaseline(e baselineEntry) bool {
	return len(f.uncovered) == e.uncovered &&
		f.strongest == e.strongest &&
		f.fingerprint() == e.digest
}

// legacyBaseline grandfathers the migrations that already shipped without
// a lock budget, keyed by filename and constrained by the fingerprint
// above. The list doubles as the audit table that produced it — a
// reviewer can check an entry without re-running the scan.
//
// A filename allowlist is used rather than a numeric cutoff because it
// fails safe: anything not on this list is enforced. Entries are verified
// on every run — see findingStaleBaseline / findingBaselineDrift /
// findingUnknownBaseline.
//
// This list should only ever SHRINK. A new migration belongs in the
// directory with a budget, never in this map.
var legacyBaseline = map[string]baselineEntry{
	"002_add_vulnerability_source.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "07317d2c5fe05783",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"003_add_vex_statements.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "3fdf5c4308cf3965",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"004_add_license_policies.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "a30ea7037e499f3b",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"005_add_api_keys.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "01da447340427d81",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"006_notification_settings.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "9bc5a99c7b40cd4a",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"007_multitenancy.up.sql": {
		uncovered: 34,
		strongest: lockAccessExclusive,
		digest:    "ce0a855cb29410f7",
		note:      "the lint charges 34 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN, CREATE INDEX, ALTER TABLE … ENABLE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"008_subscriptions.up.sql": {
		uncovered: 3,
		strongest: lockShareRowExclusive,
		digest:    "0fdc3bafca660401",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"009_public_links.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "0f1fff4369723569",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"010_scan_settings.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "0a6d48ce5e85ed86",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"011_github_integration.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "36575fa668b4f737",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"012_analytics.up.sql": {
		uncovered: 4,
		strongest: lockShareRowExclusive,
		digest:    "59b5341eb83f8416",
		note:      "the lint charges 4 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"013_report_generation.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "597d637209ee5ace",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"014_ipa_integration.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "e15e1ee7cc571ba6",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"015_issue_tracker.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "6eafd61c6ffc1eef",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"016_report_content.up.sql": {
		uncovered: 2,
		strongest: lockAccessExclusive,
		digest:    "8491282b6cbf9615",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN, ALTER TABLE … ALTER COLUMN … DROP NOT NULL",
	},
	"017_tenant_apikeys.up.sql": {
		uncovered: 2,
		strongest: lockAccessExclusive,
		digest:    "1d196869d249584b",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ALTER COLUMN … DROP NOT NULL, ALTER TABLE … ALTER COLUMN … SET NOT NULL",
	},
	"018_compliance_checklist.up.sql": {
		uncovered: 2,
		strongest: lockShareRowExclusive,
		digest:    "d379c0c49c212234",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"019_email_notifications.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "f9c5527d9eaa76e4",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"020_kev_integration.up.sql": {
		uncovered: 5,
		strongest: lockAccessExclusive,
		digest:    "266b891d698462cc",
		note:      "the lint charges 5 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN, CREATE INDEX",
	},
	"021_ssvc_integration.up.sql": {
		uncovered: 5,
		strongest: lockAccessExclusive,
		digest:    "b4ac73c914502536",
		note:      "the lint charges 5 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create, ALTER TABLE … ADD COLUMN, CREATE INDEX",
	},
	"022_eol_integration.up.sql": {
		uncovered: 9,
		strongest: lockAccessExclusive,
		digest:    "43867e5aee4c681b",
		note:      "the lint charges 9 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN, CREATE INDEX",
	},
	"023_rls_security_hardening.up.sql": {
		uncovered: 33,
		strongest: lockAccessExclusive,
		digest:    "bacc881c3e61d0e6",
		note:      "the lint charges 33 statement(s) against relations it cannot prove this file creates: ALTER TABLE … FORCE ROW LEVEL SECURITY, DROP POLICY, CREATE POLICY, ALTER TABLE … ENABLE ROW LEVEL SECURITY",
	},
	"026_system_settings.up.sql": {
		uncovered: 1,
		strongest: lockShare,
		digest:    "1082e4c3826f7db9",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE INDEX IF NOT EXISTS (target not provably created here)",
	},
	"027_sbom_tenant_id_not_null.up.sql": {
		uncovered: 15,
		strongest: lockAccessExclusive,
		digest:    "075cd8acc877d069",
		note:      "the lint charges 15 statement(s) against relations it cannot prove this file creates: ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY, a DO $$…$$ block (body opaque to the lint, charged the strongest lock), ALTER TABLE … ALTER COLUMN … SET NOT NULL, ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY",
	},
	"028_api_keys_remove_rls.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "f4a2543f4a322dbf",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: DROP POLICY, ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY",
	},
	"029_audit_logs_remove_rls.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "0f8c3ca333fcd598",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: DROP POLICY, ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY",
	},
	"030_public_links_remove_rls.up.sql": {
		uncovered: 6,
		strongest: lockAccessExclusive,
		digest:    "2ecb9820a4978efc",
		note:      "the lint charges 6 statement(s) against relations it cannot prove this file creates: DROP POLICY, ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY",
	},
	"031_subscriptions_remove_rls.up.sql": {
		uncovered: 9,
		strongest: lockAccessExclusive,
		digest:    "3cbfa16e47b1d775",
		note:      "the lint charges 9 statement(s) against relations it cannot prove this file creates: DROP POLICY, ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY",
	},
	"032_llm_calls.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "a782b1bbc6126fba",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"033_advisory_excerpts.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "d77ff038637f1f45",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"034_reachability_results.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "597f68e081bd829b",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"035_vex_drafts.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "f3f4ed653259bd24",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"036_tenant_llm_config.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "8d7dae306d973148",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"037_tenant_llm_config_rls.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "8ea825bd25ea479a",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"038_cra_reports.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "03dcd03bb16a5cb5",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"039_meti_assessments.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "35910d1a51c93dd8",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"040_rls_compliance_visualization.up.sql": {
		uncovered: 6,
		strongest: lockAccessExclusive,
		digest:    "d824304004d2b34b",
		note:      "the lint charges 6 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"041_compliance_visualization_tenant_fk.up.sql": {
		uncovered: 4,
		strongest: lockAccessExclusive,
		digest:    "09a8544202d1614d",
		note:      "the lint charges 4 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD CONSTRAINT (CHECK / UNIQUE), a DO $$…$$ block (body opaque to the lint, charged the strongest lock), ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY",
	},
	"042_rls_force_uniformity.up.sql": {
		uncovered: 36,
		strongest: lockAccessExclusive,
		digest:    "b7f4749309be6697",
		note:      "the lint charges 36 statement(s) against relations it cannot prove this file creates: ALTER TABLE … FORCE ROW LEVEL SECURITY, DROP POLICY, CREATE POLICY",
	},
	"043_rls_enable_github_ssvc_history.up.sql": {
		uncovered: 9,
		strongest: lockAccessExclusive,
		digest:    "83b755cf1e3fb041",
		note:      "the lint charges 9 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"044_composite_fk_tenant_project.up.sql": {
		uncovered: 6,
		strongest: lockAccessExclusive,
		digest:    "c39be9eb03040f1e",
		note:      "the lint charges 6 statement(s) against relations it cannot prove this file creates: a DO $$…$$ block (body opaque to the lint, charged the strongest lock), ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY",
	},
	"045_composite_fk_extension.up.sql": {
		uncovered: 40,
		strongest: lockAccessExclusive,
		digest:    "a9cc6e54b708a463",
		note:      "the lint charges 40 statement(s) against relations it cannot prove this file creates: ALTER TABLE … NO FORCE ROW LEVEL SECURITY, ALTER TABLE … DISABLE ROW LEVEL SECURITY, a DO $$…$$ block (body opaque to the lint, charged the strongest lock), ALTER TABLE … ALTER COLUMN … SET NOT NULL, ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY",
	},
	"046_diff_webhook_settings.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "f3996d7922f166f1",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create, DROP TRIGGER IF EXISTS TRG_TENANT_DIFF_WEBHOOK_SETTINGS_UPDATED_AT ON TENANT_DIFF_WEBHOOK_SETTINGS, CREATE TRIGGER",
	},
	"047_tenant_diff_webhook_settings_rls.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "5dde79fa1948e7c8",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"048_legacy_scan_settings_logs_rls.up.sql": {
		uncovered: 6,
		strongest: lockAccessExclusive,
		digest:    "e04075439061926e",
		note:      "the lint charges 6 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ENABLE ROW LEVEL SECURITY, ALTER TABLE … FORCE ROW LEVEL SECURITY, CREATE POLICY",
	},
	"050_issue_tracker_type_check.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "5ba420d07964c404",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD CONSTRAINT (CHECK / UNIQUE)",
	},
	"051_ticket_external_project_key.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "6a9d4d6c18861674",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"052_vex_statement_provenance.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "d98a589976791445",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"053_cra_submissions.up.sql": {
		uncovered: 1,
		strongest: lockShareRowExclusive,
		digest:    "1595b9f121dd4374",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create",
	},
	"054_cra_reports_awareness_time.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "d4574798b705f553",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"055_vulnerabilities_epss.up.sql": {
		uncovered: 4,
		strongest: lockAccessExclusive,
		digest:    "e132998675f2e0c3",
		note:      "the lint charges 4 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN, CREATE INDEX IF NOT EXISTS (target not provably created here)",
	},
	"056_advisory_excerpts_source_osv.up.sql": {
		uncovered: 2,
		strongest: lockAccessExclusive,
		digest:    "7345738729a954cc",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: ALTER TABLE … DROP CONSTRAINT, ALTER TABLE … ADD CONSTRAINT (CHECK / UNIQUE)",
	},
	"057_advisory_excerpts_vuln_funcs_scoped.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "24276628fb6085e7",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"058_public_links_not_null.up.sql": {
		uncovered: 3,
		strongest: lockAccessExclusive,
		digest:    "deac6046d796e5e4",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ALTER COLUMN … SET NOT NULL",
	},
	"059_vulnerabilities_epss_checked_at.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "544cab17ebff682a",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"060_subscription_checkout_claims.up.sql": {
		uncovered: 3,
		strongest: lockShareRowExclusive,
		digest:    "377c9837f5a12139",
		note:      "the lint charges 3 statement(s) against relations it cannot prove this file creates: CREATE TABLE … REFERENCES a relation the file does not create, CREATE INDEX IF NOT EXISTS (target not provably created here)",
	},
	"061_subscriptions_provider_revision.up.sql": {
		uncovered: 1,
		strongest: lockAccessExclusive,
		digest:    "51bfb0181dc49f3a",
		note:      "the lint charges 1 statement(s) against relations it cannot prove this file creates: ALTER TABLE … ADD COLUMN",
	},
	"062_drop_vulnerabilities_ssvc_decision.up.sql": {
		uncovered: 2,
		strongest: lockAccessExclusive,
		digest:    "f39d04a6e2270f24",
		note:      "the lint charges 2 statement(s) against relations it cannot prove this file creates: DROP INDEX, ALTER TABLE … DROP COLUMN",
	},
}

// ---------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------

type findingKind int

const (
	findingMissingBudget findingKind = iota
	findingNonTransactional
	findingUnclassified
	findingLexError
	findingBaselineDrift
	findingStaleBaseline
	findingUnknownBaseline
)

// finding is one failure record.
type finding struct {
	// index orders findings WITHIN a file. Sorting by line alone left
	// several statements written on one line grouped by finding kind
	// instead of by source position.
	index  int
	kind   findingKind
	file   string
	line   int
	detail string
	stmt   string
}

// audit turns per-file scans plus a baseline into an ordered finding
// list. Deterministic: files are visited in lexical order and statements
// in source order, so CI log diffs are stable.
//
// `baseline` may be nil, which enforces the rule on every file — that is
// what generated the current legacyBaseline contents, and what the tool's
// own fixture tests use.
func audit(scans []fileScan, baseline map[string]baselineEntry) []finding {
	var findings []finding

	seen := make(map[string]bool, len(scans))

	for _, f := range scans {
		seen[f.name] = true
		entry, grandfathered := baseline[f.name]

		// A lexer divergence invalidates every other conclusion about the
		// file, so it is reported alone and is not waivable: a baseline
		// entry means "this file's locks were reviewed", which is exactly
		// what a failed lex makes impossible.
		if f.lexError != "" {
			findings = append(findings, finding{
				kind:   findingLexError,
				file:   f.name,
				detail: f.lexError,
			})
			continue
		}

		// Per-file findings are collected here and emitted in source
		// order, so a reader walking the CI log walks the file top to
		// bottom instead of jumping between finding kinds.
		var perFile []finding

		// A non-transactional statement is a guaranteed runtime failure,
		// not a contention risk, so the baseline does not waive it. No
		// existing migration contains one.
		for _, p := range f.nonTransactional {
			perFile = append(perFile, finding{
				index:  p.index,
				kind:   findingNonTransactional,
				file:   f.name,
				line:   p.stmt.line,
				detail: p.reason,
				stmt:   p.stmt.display(),
			})
		}

		// Likewise for a statement the lint cannot classify: waiving it
		// would mean the baseline entry silently covers a shape nobody
		// has reasoned about.
		for _, p := range f.unclassified {
			perFile = append(perFile, finding{
				index:  p.index,
				kind:   findingUnclassified,
				file:   f.name,
				line:   p.stmt.line,
				detail: p.reason,
				stmt:   p.stmt.display(),
			})
		}

		switch {
		case !grandfathered:
			perFile = append(perFile, missingBudgetFindings(f)...)

		case len(f.uncovered) == 0:
			// Staleness is only a reliable verdict on an otherwise clean
			// file. If the file already produced a finding, fixing that
			// finding can put the waiver back in play — e.g. replacing a
			// rejected `CREATE INDEX CONCURRENTLY` with the plain form
			// reintroduces a SHARE lock that the waiver covers. Reporting
			// "your baseline entry is stale" alongside would send the
			// author to delete an entry they are about to need again.
			if len(perFile) == 0 {
				perFile = append(perFile, finding{
					kind:   findingStaleBaseline,
					file:   f.name,
					detail: "file no longer needs the legacy waiver",
				})
			}

		case !f.matchesBaseline(entry):
			// The waiver covers a reviewed footprint. Once the file no
			// longer matches it, every contending statement is reported —
			// including the ones the old fingerprint did cover, because
			// the lint cannot tell which of them the author added.
			perFile = append(perFile, finding{
				kind: findingBaselineDrift,
				file: f.name,
				detail: fmt.Sprintf(
					"waives %d statement(s) at %s (digest %s), but the file now has %d at %s (digest %s)",
					entry.uncovered, entry.strongest, entry.digest,
					len(f.uncovered), f.strongest, f.fingerprint()),
			})
			perFile = append(perFile, missingBudgetFindings(f)...)
		}

		sort.SliceStable(perFile, func(i, j int) bool {
			if perFile[i].line != perFile[j].line {
				return perFile[i].line < perFile[j].line
			}
			return perFile[i].index < perFile[j].index
		})
		findings = append(findings, perFile...)
	}

	// Baseline entries with no matching file: a typo, or a migration that
	// was renamed or removed. Either way the list is lying about the
	// directory and must be corrected.
	var orphans []string
	for name := range baseline {
		if !seen[name] {
			orphans = append(orphans, name)
		}
	}
	sort.Strings(orphans)
	for _, name := range orphans {
		findings = append(findings, finding{
			kind:   findingUnknownBaseline,
			file:   name,
			detail: "baseline names a file that does not exist in --dir",
		})
	}

	return findings
}

// missingBudgetFindings renders one finding per uncovered statement.
// Each is diagnosed against ITS OWN position in the file — a file may
// have several budgets, so the reason statement 9 is uncovered can differ
// from the reason statement 2 is.
func missingBudgetFindings(f fileScan) []finding {
	out := make([]finding, 0, len(f.uncovered))
	for _, h := range f.uncovered {
		out = append(out, finding{
			index: h.index,
			kind:  findingMissingBudget,
			file:  f.name,
			line:  h.stmt.line,
			detail: fmt.Sprintf("takes %s on %s; %s",
				h.class, relationLabel(h.relation), f.budgetDiagnosis(h.index)),
			stmt: h.stmt.display(),
		})
	}
	return out
}

// relationLabel renders a lock target for output, naming the placeholder
// used when the static scan could not resolve the relation.
func relationLabel(rel string) string {
	if rel == "" {
		return "an unnamed pre-existing relation"
	}
	return rel
}

// ---------------------------------------------------------------------
// Directory scan + CLI
// ---------------------------------------------------------------------

// scanDir reads every `*.up.sql` in `dir` (non-recursive — the migrations
// directory is flat by convention) in lexical order.
//
// `.down.sql` files are skipped. A down migration is executed only by a
// deliberate operator rollback, never by the automatic startup path in
// internal/database/migrate.go, so it is not the "silently stalls a
// deploy" shape this lint targets. Bringing them in scope would also mean
// baselining another 65 files. Recorded as a known gap, not an oversight.
func scanDir(dir string) ([]fileScan, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations directory %q: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	scans := make([]fileScan, 0, len(names))
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", filepath.Join(dir, name), err)
		}
		scans = append(scans, scanFile(name, string(body)))
	}
	return scans, nil
}

func kindLabel(k findingKind) string {
	switch k {
	case findingMissingBudget:
		return "missing lock budget"
	case findingNonTransactional:
		return "statement cannot run in the runner's transaction"
	case findingUnclassified:
		return "unrecognised statement"
	case findingLexError:
		return "file could not be lexed"
	case findingBaselineDrift:
		return "baseline entry no longer matches the file"
	case findingStaleBaseline:
		return "stale baseline entry"
	case findingUnknownBaseline:
		return "unknown baseline entry"
	default:
		return "finding"
	}
}

// remediation returns the fix hint printed under each finding. Kept next
// to kindLabel so the two never drift.
func remediation(k findingKind) []string {
	switch k {
	case findingMissingBudget:
		return []string{
			"fix: add `SET LOCAL lock_timeout = '5s';` as the first statement of the",
			"     migration (the form 063 / 064 / 065 use). The runner wraps each file",
			"     in one transaction, so a timeout rolls the DDL and the",
			"     schema_migrations row back together and the deploy can be retried",
			"     when the table is quiet.",
		}
	case findingNonTransactional:
		return []string{
			"fix: this statement cannot be used in this repository — cmd/migrate/main.go",
			"     and internal/database/migrate.go both wrap each migration file in a",
			"     single transaction. Use the non-CONCURRENTLY form together with",
			"     `SET LOCAL lock_timeout`, or run the operation outside the migration",
			"     runner as a documented operator step.",
		}
	case findingUnclassified:
		return []string{
			"fix: the lint does not know this statement's lock behaviour, so it cannot",
			"     certify the migration. Measure the statement's pg_locks modes and add",
			"     it to classifyStatement (or to harmlessPrefixes if it takes nothing",
			"     above ROW EXCLUSIVE), in the same PR as the migration.",
		}
	case findingLexError:
		return []string{
			"fix: the lint reached end-of-file inside a comment, string literal or",
			"     dollar-quoted body, so its view of the file diverged from",
			"     PostgreSQL's and it cannot certify any statement in it. Close the",
			"     construct. If the file is well-formed PostgreSQL, the lexer in",
			"     tools/lint-migration-locks needs the missing rule — fix it in the",
			"     same PR rather than working around it.",
		}
	case findingBaselineDrift:
		return []string{
			"fix: the legacy waiver covers a reviewed footprint, not just a filename.",
			"     This file's contending statements changed, so all of them are now",
			"     reported. A shipped migration should not change at all; if this is a",
			"     deliberate rewrite, give the new statements a `SET LOCAL lock_timeout`",
			"     and update (or delete) the legacyBaseline entry in the same PR.",
		}
	case findingStaleBaseline:
		return []string{
			"fix: remove the entry from legacyBaseline in tools/lint-migration-locks/main.go.",
			"     The baseline is verified on every run so it cannot rot silently.",
		}
	case findingUnknownBaseline:
		return []string{
			"fix: the migration was renamed or removed. Update or drop the legacyBaseline",
			"     entry in tools/lint-migration-locks/main.go to match the directory.",
		}
	default:
		return nil
	}
}

// run is the testable entry point — splitting it out of main() lets
// main_test.go drive the lint with synthetic --dir arguments and capture
// stdout/stderr without forking a subprocess. Mirrors the shape of the
// other two lints in tools/.
func run(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint-migration-locks", flag.ContinueOnError)
	fs.SetOutput(stderr)

	dir := fs.String("dir", "apps/api/migrations", "directory containing *.up.sql migration files")
	verbose := fs.Bool("verbose", false, "print the per-file lock classification table on success")
	useBaseline := fs.Bool("baseline", true, "apply the built-in legacy baseline (set false to see the unfiltered state of the directory)")
	emitBaseline := fs.Bool("emit-baseline", false, "regenerate the legacyBaseline map literal for the current --dir (exit 2 if the request is refused); the digests cannot be written by hand")

	if err := fs.Parse(argv); err != nil {
		// flag.ContinueOnError already wrote the usage message to stderr.
		return 2
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "lint-migration-locks: --dir is required")
		return 2
	}

	scans, err := scanDir(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "lint-migration-locks: %v\n", err)
		return 2
	}

	// An empty scan is a usage error whatever the baseline setting: it
	// almost always means --dir points somewhere wrong, and reporting
	// "ok — 0 migration(s)" would be a green tick for having checked
	// nothing.
	if len(scans) == 0 {
		fmt.Fprintf(stderr, "lint-migration-locks: no *.up.sql files found in %q\n", *dir)
		return 2
	}

	if *emitBaseline {
		if err := emitBaselineSource(stdout, scans); err != nil {
			fmt.Fprintf(stderr, "lint-migration-locks: %v\n", err)
			return 2
		}
		return 0
	}

	baseline := legacyBaseline
	if !*useBaseline {
		baseline = nil
	}
	findings := audit(scans, baseline)

	if len(findings) == 0 {
		sum := summarise(scans, baseline)
		fmt.Fprintf(stdout,
			"lint-migration-locks: ok — %d migration(s) / %d statement(s) scanned; "+
				"%d take no contending lock, %d declare a budget, %d waived by legacy baseline\n",
			len(scans), sum.statements, sum.clean, sum.budgeted, sum.waived)
		if *verbose {
			printTable(stdout, scans, baseline)
		}
		return 0
	}

	fmt.Fprintf(stderr, "lint-migration-locks: FAIL — %d finding(s)\n", len(findings))
	// Remediation text is printed at most once per kind. A per-kind set
	// rather than a "same as last" check, because findings are now
	// emitted in source order and kinds can interleave.
	explained := make(map[findingKind]bool)
	for _, f := range findings {
		loc := f.file
		if f.line > 0 {
			loc = fmt.Sprintf("%s:%d", f.file, f.line)
		}
		fmt.Fprintf(stderr, "  [%s] %s\n", kindLabel(f.kind), loc)
		fmt.Fprintf(stderr, "    - %s\n", f.detail)
		if f.stmt != "" {
			fmt.Fprintf(stderr, "      statement: %s\n", f.stmt)
		}
		if !explained[f.kind] {
			for _, line := range remediation(f.kind) {
				fmt.Fprintf(stderr, "    %s\n", line)
			}
			explained[f.kind] = true
		}
	}
	if *verbose {
		printTable(stderr, scans, baseline)
	}
	return 1
}

// scanSummary is the exhaustive partition of the scanned files. Every
// fileScan lands in exactly one of clean / budgeted / waived / missing,
// so the four always sum to len(scans) — the previous three-bucket
// version silently dropped a file that needed a budget and had no
// baseline entry. `missing` is zero on the success
// path by construction (such a file produces a finding), and is carried
// anyway so the invariant is checkable rather than assumed.
type scanSummary struct {
	clean      int
	budgeted   int
	waived     int
	missing    int
	statements int
}

// total is the invariant the caller can assert against len(scans).
func (s scanSummary) total() int { return s.clean + s.budgeted + s.waived + s.missing }

// summarise partitions the scans for the success line.
func summarise(scans []fileScan, baseline map[string]baselineEntry) scanSummary {
	var sum scanSummary
	for _, f := range scans {
		sum.statements += f.statements
		switch {
		case !f.needsBudget():
			sum.clean++
		case len(f.uncovered) == 0:
			sum.budgeted++
		default:
			if e, ok := baseline[f.name]; ok && f.matchesBaseline(e) {
				sum.waived++
			} else {
				sum.missing++
			}
		}
	}
	return sum
}

// printTable emits the per-file classification the audit is based on:
// statement count, strongest lock taken on a pre-existing relation, how
// many statements need a budget, and the file's budget status. This is
// the evidence a reviewer needs to check the baseline without re-running
// the scan by hand.
func printTable(w io.Writer, scans []fileScan, baseline map[string]baselineEntry) {
	fmt.Fprintf(w, "  %-48s %5s %5s  %-22s %s\n", "migration", "stmts", "heavy", "strongest lock", "budget")
	waivedAny := false
	for _, f := range scans {
		// A file the lexer could not finish has no lock conclusion at
		// all; printing "no contending lock" for it would be the table
		// certifying what the audit just refused to.
		if f.lexError != "" {
			fmt.Fprintf(w, "  %-48s %5s %5s  %-22s %s\n",
				f.name, "?", "?", "unknown", "INVALID (lex error)")
			continue
		}
		// A file carrying a statement the lint could not classify, or one
		// that cannot run in the runner's transaction, has no reliable
		// lock conclusion — saying "no contending lock" would contradict
		// the finding the audit just emitted.
		if len(f.unclassified) > 0 || len(f.nonTransactional) > 0 {
			fmt.Fprintf(w, "  %-48s %5d %5d  %-22s %s\n",
				f.name, f.statements, len(f.heavy), "unknown", "INVALID (unclassified statement)")
			continue
		}
		status := "n/a (no contending lock)"
		switch {
		case !f.needsBudget():
			status = "n/a (no contending lock)"
		case len(f.uncovered) == 0:
			status = "declared"
		default:
			e, ok := baseline[f.name]
			switch {
			case ok && f.matchesBaseline(e):
				status = "waived (legacy baseline)"
			case ok:
				status = "INVALID (baseline drift)"
			default:
				status = "MISSING"
			}
		}
		strongest := f.strongest.String()
		if !f.needsBudget() && f.strongest < budgetRequiredFrom {
			strongest = "≤ " + strongest
		}
		fmt.Fprintf(w, "  %-48s %5d %5d  %-22s %s\n",
			f.name, f.statements, len(f.heavy), strongest, status)
		// Echo the waived footprint so the CI log carries the evidence a
		// reviewer would otherwise have to open the source to see. The
		// note is what the fingerprint was reviewed against, so printing
		// it here is the audit trail for the waiver.
		if entry, ok := baseline[f.name]; ok && len(f.uncovered) > 0 && f.matchesBaseline(entry) {
			waivedAny = true
			fmt.Fprintf(w, "  %-48s      → %s\n", "", entry.note)
		}
	}
	if waivedAny {
		fmt.Fprintf(w, "\n  Every waived migration above %s\n", legacyBaselineRationale)
	}
}

// emitBaselineSource prints a legacyBaseline literal covering every file
// in the scan that currently needs a waiver.
//
// This exists because baselineEntry.digest cannot be produced by hand.
// Regenerating the map is a deliberate, reviewable act: the diff shows
// exactly which files changed footprint, and the note text next to each
// digest is what a human actually reads.
//
// It is REGENERATION, not bootstrapping, and two guards keep it that way
// :
//
//   - A file that needs a waiver but is not already in legacyBaseline is
//     refused. Otherwise the documented "this list should only ever
//     shrink" rule would be one command away from being false, and a new
//     unbudgeted migration could be laundered green.
//   - A scan carrying a lex error, a non-transactional statement or an
//     unclassified statement is refused, because none of those are
//     waivable — emitting a map from such a scan would produce something
//     that still cannot go green, with no hint as to why.
//
// Two limits worth naming:
//
//   - If a classifier CORRECTION newly finds a contending lock in a
//     migration that was previously clean, regeneration refuses it,
//     because the guard cannot tell that case from a new migration. The
//     path is two steps and both are visible in review: hand-add the
//     filename with a placeholder digest, then re-run to fill it in.
//   - The guards do not stop a maintainer who EDITS an
//     already-grandfathered migration and then regenerates: the filename
//     is already in the map, so the emit succeeds and the digest changes.
//     What that costs the maintainer is a visible digest diff that a
//     reviewer has to approve. This tool is a change detector, not an
//     access control; the enforcement boundary is the committed map plus
//     code review.
func emitBaselineSource(w io.Writer, scans []fileScan) error {
	var blocked []string
	for _, f := range scans {
		switch {
		case f.lexError != "":
			blocked = append(blocked, f.name+" (lex error: "+f.lexError+")")
		case len(f.nonTransactional) > 0:
			blocked = append(blocked, f.name+" (statement cannot run in the runner's transaction)")
		case len(f.unclassified) > 0:
			blocked = append(blocked, f.name+" (unrecognised statement)")
		case len(f.uncovered) > 0:
			if _, ok := legacyBaseline[f.name]; !ok {
				blocked = append(blocked, f.name+" (needs a budget and is not already grandfathered)")
			}
		}
	}
	if len(blocked) > 0 {
		return fmt.Errorf("--emit-baseline regenerates the EXISTING waiver list; it refuses to add or paper over:\n  %s\n"+
			"give these migrations a `SET LOCAL lock_timeout` instead",
			strings.Join(blocked, "\n  "))
	}

	fmt.Fprintln(w, "var legacyBaseline = map[string]baselineEntry{")
	for _, f := range scans {
		if len(f.uncovered) == 0 {
			continue
		}
		kinds := make([]string, 0, 4)
		seenKind := make(map[string]bool)
		for _, u := range f.uncovered {
			k := statementKind(u.stmt.scanText)
			if !seenKind[k] {
				seenKind[k] = true
				kinds = append(kinds, k)
			}
		}
		fmt.Fprintf(w, "\t%q: {\n", f.name)
		fmt.Fprintf(w, "\t\tuncovered: %d,\n", len(f.uncovered))
		fmt.Fprintf(w, "\t\tstrongest: %s,\n", lockClassIdent(f.strongest))
		fmt.Fprintf(w, "\t\tdigest:    %q,\n", f.fingerprint())
		fmt.Fprintf(w, "\t\tnote:      %q,\n", fmt.Sprintf(
			"the lint charges %d statement(s) against relations it cannot prove this file creates: %s",
			len(f.uncovered), strings.Join(kinds, ", ")))
		fmt.Fprintln(w, "\t},")
	}
	fmt.Fprintln(w, "}")
	return nil
}

// lockClassIdent renders a lockClass as the Go identifier that names it,
// so emitted source compiles.
func lockClassIdent(c lockClass) string {
	switch c {
	case lockRowExclusive:
		return "lockRowExclusive"
	case lockShareUpdateExclusive:
		return "lockShareUpdateExclusive"
	case lockShare:
		return "lockShare"
	case lockShareRowExclusive:
		return "lockShareRowExclusive"
	case lockExclusive:
		return "lockExclusive"
	case lockAccessExclusive:
		return "lockAccessExclusive"
	default:
		return "lockNone"
	}
}

// statementKind is a short human label for the emitted baseline note. It
// is descriptive only — nothing in the audit depends on it.
func statementKind(scanText string) string {
	u := strings.ToUpper(collapseSQLSpace(scanText))
	switch {
	case strings.HasPrefix(u, "DO "), u == "DO":
		return "a DO $$…$$ block (body opaque to the lint, charged the strongest lock)"
	case strings.HasPrefix(u, "CREATE TABLE"):
		return "CREATE TABLE … REFERENCES a relation the file does not create"
	case strings.Contains(u, "INDEX IF NOT EXISTS"):
		return "CREATE INDEX IF NOT EXISTS (target not provably created here)"
	case strings.HasPrefix(u, "CREATE INDEX"), strings.HasPrefix(u, "CREATE UNIQUE INDEX"):
		return "CREATE INDEX"
	case strings.HasPrefix(u, "DROP INDEX"):
		return "DROP INDEX"
	case strings.HasPrefix(u, "CREATE POLICY"):
		return "CREATE POLICY"
	case strings.HasPrefix(u, "DROP POLICY"):
		return "DROP POLICY"
	case strings.HasPrefix(u, "CREATE TRIGGER"):
		return "CREATE TRIGGER"
	case strings.HasPrefix(u, "ALTER TABLE"):
		for _, pair := range [][2]string{
			{"ADD COLUMN", "ALTER TABLE … ADD COLUMN"},
			{"DROP COLUMN", "ALTER TABLE … DROP COLUMN"},
			{"ENABLE ROW LEVEL SECURITY", "ALTER TABLE … ENABLE ROW LEVEL SECURITY"},
			{"NO FORCE ROW LEVEL SECURITY", "ALTER TABLE … NO FORCE ROW LEVEL SECURITY"},
			{"DISABLE ROW LEVEL SECURITY", "ALTER TABLE … DISABLE ROW LEVEL SECURITY"},
			{"FORCE ROW LEVEL SECURITY", "ALTER TABLE … FORCE ROW LEVEL SECURITY"},
			{"SET NOT NULL", "ALTER TABLE … ALTER COLUMN … SET NOT NULL"},
			{"DROP NOT NULL", "ALTER TABLE … ALTER COLUMN … DROP NOT NULL"},
			{"DROP CONSTRAINT", "ALTER TABLE … DROP CONSTRAINT"},
			{"FOREIGN KEY", "ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY"},
			{"ADD CONSTRAINT", "ALTER TABLE … ADD CONSTRAINT (CHECK / UNIQUE)"},
		} {
			if strings.Contains(u, pair[0]) {
				return pair[1]
			}
		}
		return "ALTER TABLE … (other)"
	}
	if i := strings.Index(u, "("); i > 0 {
		u = u[:i]
	}
	return strings.TrimSpace(u)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
