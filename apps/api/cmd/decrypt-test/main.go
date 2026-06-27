// Command decrypt-test is the ENCRYPTION_KEY round-trip smoke test that
// verify-encryption.sh wraps. It connects to the SBOMHub Postgres DB, fetches
// one encrypted-column row, and tries to decrypt it with the supplied
// ENCRYPTION_KEY using the SAME AES-256-GCM helper the API server uses at
// runtime (internal/service/llm.Decrypt — single source of truth for the
// ciphertext format). On success the SHA256 hash of the plaintext is printed
// so the operator can confirm round-trip without leaking the plaintext API
// token / secret to stdout / log files.
//
// M5 Wave M5-5 / issue youichi-uda/sbomhub#53. Pairs with
// docker/scripts/verify-encryption.sh (shell wrapper around this binary) and
// the post-restore Step 8 in restore.sh.
//
// Why a Go binary and not pure shell:
//
//   - The ciphertext format (nonce || sealed) is owned by internal/service/llm
//     and may evolve. Sharing the Go helper guarantees the smoke test cannot
//     diverge from production decrypt logic — a regression in either side
//     surfaces here first.
//   - openssl-CLI based AES-256-GCM decryption requires nonce / tag splitting
//     that is fiddly to keep portable across coreutils versions. A static Go
//     binary built once is reliable across distros.
//   - llm.Decrypt has battle-tested coverage for the "key too short" /
//     "ciphertext too short" / "GCM auth tag mismatch" branches that the
//     smoke test cares about (crypto_test.go).
//
// Exit code contract (mirrored by verify-encryption.sh):
//
//	0  ok                       — decrypt succeeded; SHA256(plaintext) printed.
//	1  key mismatch / corrupt   — decrypt failed (wrong ENCRYPTION_KEY, tampered
//	                              ciphertext, or wrong column format).
//	2  db error                 — connection / query failure (DSN typo,
//	                              network, role missing permissions).
//	3  no encrypted row to test — table is empty or every row has NULL/empty
//	                              ciphertext; setup not yet complete.
//	64 usage error              — flag parse / missing required flag.
//
// SECURITY:
//
//   - The plaintext NEVER leaves the process. We only print SHA256(plaintext)
//     so the operator (and CI) can confirm "key A and key B both decrypted to
//     the same hash" without ever materialising the secret to log files.
//   - The 32-byte key is zeroed out from local memory before exit (best-effort
//     — Go does not give true zero-on-exit guarantees, but we avoid leaving it
//     in the active local for longer than needed). Same posture as
//     cmd/server/main.go around cfg.GetEncryptionKey().
//   - DB rows are fetched with LIMIT 1 and the raw ciphertext bytes are not
//     logged. On decrypt failure the error message names "GCM authentication
//     failed" without leaking the ciphertext (llm.Decrypt already enforces
//     this).
//
// Usage:
//
//	ENCRYPTION_KEY="$(cat key.txt)" decrypt-test --db-url "$DATABASE_URL"
//
// Alternatively:
//
//	decrypt-test --key-file key.txt --db-url "$DATABASE_URL"
//
// The --key flag is still accepted for backward compatibility, but it is
// discouraged because argv is visible via /proc/<pid>/cmdline on typical Linux
// hosts.
//
// The default table / column pair targets the BYOK LLM API key (BYTEA, raw
// nonce||sealed bytes from llm.Encrypt — see migration 036_tenant_llm_config).
// The wrapper script may also point this binary at
// issue_tracker_connections.auth_token_encrypted (TEXT, base64-encoded) for
// installs that have not yet configured BYOK LLM; format auto-detection looks
// at information_schema.columns.data_type.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// Exit code contract. Kept as package-level consts so unit tests and the
// wrapper script can reference them without scraping the doc comment. Anything
// outside this set is a bug.
const (
	exitOK         = 0
	exitKeyError   = 1
	exitDBError    = 2
	exitNoRow      = 3
	exitUsageError = 64
)

// cliFlags is the parsed command-line surface. Held in a struct so the test
// harness can drive realMain without re-parsing os.Args. Mirrors the
// llm-bench/main.go pattern.
type cliFlags struct {
	key     string
	keyFile string
	dbURL   string
	table   string
	column  string
	// format pins the ciphertext encoding: "bytea" (raw nonce||sealed) or
	// "base64" (base64-encoded nonce||sealed). Empty string means
	// auto-detect from information_schema.columns.data_type at run time.
	format string
}

func parseFlags(args []string, stderr io.Writer) (*cliFlags, error) {
	fs := flag.NewFlagSet("decrypt-test", flag.ContinueOnError)
	fs.SetOutput(stderr)

	f := &cliFlags{}
	fs.StringVar(&f.key, "key", "",
		"32-byte ENCRYPTION_KEY (raw or longer; first 32 bytes are used, mirroring config.Config.GetEncryptionKey)")
	fs.StringVar(&f.keyFile, "key-file", "",
		"Path to file containing ENCRYPTION_KEY (preferred over --key)")
	fs.StringVar(&f.dbURL, "db-url", "",
		"Postgres DSN, e.g. postgres://sbomhub_app:...@localhost:5432/sbomhub?sslmode=disable (env DATABASE_URL also accepted)")
	fs.StringVar(&f.table, "table", "tenant_llm_config",
		"table to fetch a sample encrypted row from")
	fs.StringVar(&f.column, "column", "encrypted_api_key",
		"encrypted column to decrypt (BYTEA or TEXT base64)")
	fs.StringVar(&f.format, "format", "",
		"ciphertext format: 'bytea' (raw) or 'base64' (TEXT). Empty = auto-detect via information_schema.")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: decrypt-test [--db-url DSN] [--key-file PATH] [--table NAME] [--column NAME]")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "ENCRYPTION_KEY env var is the recommended way to pass the key.")
		fmt.Fprintln(stderr, "Smoke-tests that ENCRYPTION_KEY decrypts a sample encrypted-column row.")
		fmt.Fprintln(stderr, "Prints SHA256(plaintext) on success; the plaintext itself is never emitted.")
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(stderr, "")
		fmt.Fprintln(stderr, "Exit codes:")
		fmt.Fprintln(stderr, "  0   Decrypt succeeded (SHA256 hash printed to stdout)")
		fmt.Fprintln(stderr, "  1   Key mismatch / ciphertext corrupt (auth tag failed)")
		fmt.Fprintln(stderr, "  2   DB connection or query error")
		fmt.Fprintln(stderr, "  3   No encrypted row to test (table empty, ciphertext NULL/empty)")
		fmt.Fprintln(stderr, "  64  Usage / flag validation error")
	}

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("parse flags: %w", err)
	}

	// env fallback for DB DSN (matches the canonical migrate/server contract).
	if f.dbURL == "" {
		f.dbURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	// Key precedence: explicit --key wins for backward compatibility, then
	// --key-file for operator-friendly direct invocation, then env fallback.
	if f.key == "" && f.keyFile != "" {
		keyBytes, err := os.ReadFile(f.keyFile)
		if err != nil {
			return nil, fmt.Errorf("read --key-file %q: %w", f.keyFile, err)
		}
		f.key = string(keyBytes)
	}
	// env fallback for key — the wrapper script may have already exported it.
	if f.key == "" {
		f.key = os.Getenv("ENCRYPTION_KEY")
	}

	if f.key == "" {
		return nil, fmt.Errorf("--key, --key-file, or env ENCRYPTION_KEY is required")
	}
	if f.dbURL == "" {
		return nil, fmt.Errorf("--db-url (or env DATABASE_URL) is required")
	}
	if f.table == "" {
		return nil, fmt.Errorf("--table must be non-empty")
	}
	if f.column == "" {
		return nil, fmt.Errorf("--column must be non-empty")
	}
	switch f.format {
	case "", "bytea", "base64":
		// ok
	default:
		return nil, fmt.Errorf("--format must be empty, 'bytea', or 'base64' (got %q)", f.format)
	}

	// Defensive identifier validation: --table / --column are interpolated
	// into SQL without parameter binding (Postgres does not allow $1 to
	// stand in for an identifier). Accept only [A-Za-z0-9_] to keep the
	// surface trivially injection-proof. The defaults pass this check; an
	// operator who needs a more exotic identifier can extend this.
	if !safeIdent(f.table) {
		return nil, fmt.Errorf("--table %q contains characters outside [A-Za-z0-9_]", f.table)
	}
	if !safeIdent(f.column) {
		return nil, fmt.Errorf("--column %q contains characters outside [A-Za-z0-9_]", f.column)
	}

	return f, nil
}

// safeIdent enforces the [A-Za-z0-9_]+ identifier allow-list. Postgres does
// not let $1 substitute table/column names, so the smoke test interpolates the
// flag value directly; restrict the allowed set so the interpolation cannot
// smuggle SQL.
func safeIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_':
			// ok
		default:
			return false
		}
	}
	return true
}

// exitError carries the typed exit code. main reads .Code to choose the
// os.Exit value; tests inspect .Code rather than scraping stderr.
type exitError struct {
	Code int
	Err  error
}

func (e *exitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *exitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func newExitError(code int, err error) *exitError {
	if err == nil {
		return nil
	}
	return &exitError{Code: code, Err: err}
}

func main() {
	if ee := realMain(os.Args[1:], os.Stdout, os.Stderr); ee != nil {
		fmt.Fprintln(os.Stderr, "decrypt-test:", ee.Err)
		os.Exit(ee.Code)
	}
}

// realMain is the test-friendly entry point.
func realMain(args []string, stdout, stderr io.Writer) *exitError {
	flags, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return newExitError(exitUsageError, err)
	}

	// 32-byte slice. config.Config.GetEncryptionKey() trims to the first 32
	// bytes when the key is longer; do the same here so an operator who set
	// ENCRYPTION_KEY to a base64-encoded 44-char string still gets the same
	// "use first 32 bytes" semantics as the API server.
	if len(flags.key) < 32 {
		return newExitError(exitKeyError,
			fmt.Errorf("ENCRYPTION_KEY too short: need >= 32 bytes, got %d", len(flags.key)))
	}
	key := []byte(flags.key)[:32]
	// Best-effort: zero the local key slice once we exit realMain. Go does
	// not give true secure-erase semantics, but this keeps the secret out
	// of the live local frame for the (small) window between successful
	// decrypt and process exit. Same pattern as the server hot path.
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	db, err := sql.Open("postgres", flags.dbURL)
	if err != nil {
		return newExitError(exitDBError, fmt.Errorf("sql.Open: %w", err))
	}
	defer db.Close()

	// Cap connection ping so a wrong host doesn't hang CI for the default 2m.
	pingCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return newExitError(exitDBError, fmt.Errorf("db ping: %w", err))
	}

	// Decide the ciphertext format. Operator override wins so a DB schema
	// that doesn't sit in the default information_schema view (e.g.
	// search_path quirks) can be unblocked.
	format := flags.format
	if format == "" {
		detected, derr := detectFormat(db, flags.table, flags.column)
		if derr != nil {
			return newExitError(exitDBError,
				fmt.Errorf("detect format for %s.%s: %w", flags.table, flags.column, derr))
		}
		format = detected
	}

	// Fetch one row. We accept (and prefer) the first non-NULL ciphertext.
	ciphertext, found, err := fetchSampleCiphertext(db, flags.table, flags.column, format)
	if err != nil {
		return newExitError(exitDBError,
			fmt.Errorf("fetch sample from %s.%s: %w", flags.table, flags.column, err))
	}
	if !found {
		return newExitError(exitNoRow,
			fmt.Errorf("no decryptable %s.%s row found (table empty or all rows have NULL/empty ciphertext)",
				flags.table, flags.column))
	}

	plaintext, err := llm.Decrypt(ciphertext, key)
	if err != nil {
		// Generic "key mismatch / corrupt" — llm.Decrypt already redacts the
		// ciphertext and key from the wrapped error. Do not log raw bytes.
		return newExitError(exitKeyError, fmt.Errorf("decrypt failed: %w", err))
	}

	// SHA256(plaintext). Hex-encoded for human + diff friendliness.
	sum := sha256.Sum256(plaintext)
	// Zero the plaintext slice as soon as possible.
	for i := range plaintext {
		plaintext[i] = 0
	}

	fmt.Fprintf(stdout, "ok table=%s column=%s format=%s sha256=%s\n",
		flags.table, flags.column, format, hex.EncodeToString(sum[:]))
	return nil
}

// detectFormat looks up the column's data_type in information_schema and maps
// it to the ciphertext encoding the API server uses:
//
//	bytea           → "bytea"   (raw nonce||sealed, e.g. tenant_llm_config.encrypted_api_key)
//	text / varchar  → "base64"  (base64-encoded nonce||sealed, e.g.
//	                  issue_tracker_connections.auth_token_encrypted)
//
// Other types are rejected so we don't silently misinterpret a numeric column.
func detectFormat(db *sql.DB, table, column string) (string, error) {
	const q = `
SELECT data_type
  FROM information_schema.columns
 WHERE table_name = $1
   AND column_name = $2
 LIMIT 1`
	var dt string
	if err := db.QueryRow(q, table, column).Scan(&dt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("column %s.%s not found in information_schema.columns", table, column)
		}
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(dt)) {
	case "bytea":
		return "bytea", nil
	case "text", "character varying", "varchar":
		return "base64", nil
	default:
		return "", fmt.Errorf("unsupported data_type %q for %s.%s (expected bytea/text/varchar)",
			dt, table, column)
	}
}

// fetchSampleCiphertext pulls one non-NULL, non-empty ciphertext from
// table.column. For BYTEA it returns the raw bytes; for TEXT it base64-decodes
// the row before returning. The `found` return distinguishes "table empty"
// from "row exists but is NULL/empty"; both currently map to !found which the
// caller turns into exit code 3 (no encrypted row to test).
//
// SECURITY: the raw ciphertext is returned to the caller (decrypted by
// llm.Decrypt next) but never logged. Errors here may surface the column name
// — never the bytes.
func fetchSampleCiphertext(db *sql.DB, table, column, format string) ([]byte, bool, error) {
	// IMPORTANT: --table / --column have already been validated by safeIdent
	// ([A-Za-z0-9_]+ allow-list, see parseFlags). Postgres does not allow $1
	// to substitute for an identifier so parameter binding is not available
	// here. The #nosec G201 annotation acknowledges gosec's static analysis
	// that flags any fmt.Sprintf into a SQL string; the safeIdent gate
	// converts the dynamic input into a closed alphabet that cannot smuggle
	// SQL.
	q := fmt.Sprintf( //nolint:gosec // G201: identifiers gated by safeIdent allow-list above; no untrusted SQL.
		`SELECT %s FROM %s WHERE %s IS NOT NULL AND length(%s::text) > 0 LIMIT 1`,
		column, table, column, column,
	)

	switch format {
	case "bytea":
		var raw []byte
		err := db.QueryRow(q).Scan(&raw)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, false, nil
			}
			return nil, false, err
		}
		if len(raw) == 0 {
			return nil, false, nil
		}
		return raw, true, nil

	case "base64":
		var s string
		err := db.QueryRow(q).Scan(&s)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, false, nil
			}
			return nil, false, err
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, false, nil
		}
		raw, derr := base64.StdEncoding.DecodeString(s)
		if derr != nil {
			// A row that has TEXT but isn't base64 is corruption, not "no row".
			// Surface as DB error so it does not get silently classified as
			// "key mismatch" downstream (a wrong-format row would also fail
			// llm.Decrypt, but the operator needs to know it's a column-format
			// problem, not a key problem).
			return nil, false, fmt.Errorf("base64 decode of %s.%s row failed: %w", table, column, derr)
		}
		if len(raw) == 0 {
			return nil, false, nil
		}
		return raw, true, nil

	default:
		return nil, false, fmt.Errorf("internal: unsupported format %q", format)
	}
}
