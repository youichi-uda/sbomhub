// Command migrate-encryption rotates SBOMHub application-layer ciphertext from
// OLD_ENCRYPTION_KEY to NEW_ENCRYPTION_KEY without printing plaintext.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

const (
	exitOK           = 0
	exitPartial      = 1
	exitDBError      = 2
	exitNoRows       = 3
	exitUsageError   = 64
	exitPrecondition = 65

	defaultBatchSize      = 1000
	dryRunMaxAge          = 24 * time.Hour
	defaultReportTimeForm = "20060102-150405"
	reportSchemaVersion   = "1"
	verifyMissingLogLimit = 100
)

var openDB = sql.Open

type mode string

const (
	modeDryRun mode = "dry-run"
	modeApply  mode = "apply"
	modeVerify mode = "verify"
)

type target struct {
	Table    string
	Column   string
	RowID    string
	Format   string
	UpdateTS bool
}

type cliFlags struct {
	dbURL           string
	dryRun          bool
	apply           bool
	verify          bool
	allowNoDryRun   bool
	continueOnError bool
	reportPath      string
	reportInput     string
	resumeFrom      string
	batchSize       int
	tables          repeatedFlag
	columns         repeatedFlag
}

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

type options struct {
	Mode             mode
	ContinueOnError  bool
	ReportPath       string
	ReportInput      string
	ResumeFrom       string
	ResumeSigningKey []byte
	BatchSize        int
	Targets          []target
}

type rowReport struct {
	Table       string `json:"table"`
	Column      string `json:"column"`
	TenantID    string `json:"tenant_id"`
	RowID       string `json:"row_id"`
	ResumeToken string `json:"resume_token,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Status      string `json:"status"`
	Error       string `json:"error,omitempty"`
}

type report struct {
	SchemaVersion    string      `json:"schema_version"`
	StartedAt        time.Time   `json:"started_at"`
	FinishedAt       time.Time   `json:"finished_at"`
	Mode             mode        `json:"mode"`
	Tables           []string    `json:"tables"`
	TotalRows        int         `json:"total_rows"`
	Succeeded        int         `json:"succeeded"`
	Failed           int         `json:"failed"`
	Skipped          int         `json:"skipped,omitempty"`
	Rows             []rowReport `json:"rows"`
	inputPath        string      `json:"-"`
	resumeSigningKey []byte      `json:"-"`
}

type dryRunExpectations struct {
	digests    map[string]string
	rows       map[string]rowReport
	seen       map[string]struct{}
	reportPath string
}

type resumeToken struct {
	Table    string `json:"table"`
	Column   string `json:"column"`
	TenantID string `json:"tenant_id"`
	RowID    string `json:"row_id"`
}

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

func newExitError(code int, err error) *exitError {
	if err == nil {
		return nil
	}
	return &exitError{Code: code, Err: err}
}

func main() {
	if ee := realMain(os.Args[1:], os.Stdout, os.Stderr); ee != nil {
		fmt.Fprintln(os.Stderr, "migrate-encryption:", ee.Err)
		os.Exit(ee.Code)
	}
}

func parseFlags(args []string, stderr io.Writer, now time.Time) (*cliFlags, []target, error) {
	fs := flag.NewFlagSet("migrate-encryption", flag.ContinueOnError)
	fs.SetOutput(stderr)

	f := &cliFlags{dryRun: true, batchSize: defaultBatchSize}
	defaultReport := fmt.Sprintf("./migrate-encryption-report-%s.json", now.UTC().Format(defaultReportTimeForm))
	fs.BoolVar(&f.dryRun, "dry-run", true, "decrypt all rows with OLD_ENCRYPTION_KEY and write SHA256 report without DB writes")
	fs.BoolVar(&f.apply, "apply", false, "rotate rows from OLD_ENCRYPTION_KEY to NEW_ENCRYPTION_KEY")
	fs.BoolVar(&f.verify, "verify", false, "decrypt all rows with NEW_ENCRYPTION_KEY and compare with --report-input")
	fs.BoolVar(&f.allowNoDryRun, "allow-no-dry-run", false, "allow --apply without a recent successful dry-run report")
	fs.BoolVar(&f.continueOnError, "continue-on-error", false, "continue after row-level decrypt/encrypt failures")
	fs.StringVar(&f.dbURL, "db-url", "", "Postgres DSN; env DATABASE_URL is used when omitted")
	fs.Var(&f.tables, "table", "encrypted table name; repeat with --column")
	fs.Var(&f.columns, "column", "encrypted column name; repeat with --table")
	fs.StringVar(&f.reportPath, "report", defaultReport, "JSON report output path")
	fs.StringVar(&f.reportInput, "report-input", "", "dry-run JSON report path for --apply/--verify")
	fs.StringVar(&f.resumeFrom, "resume-from", "", "resume processing after a structured base64 JSON token from a prior report row")
	fs.IntVar(&f.batchSize, "batch-size", defaultBatchSize, "maximum rows per tenant transaction")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: migrate-encryption [--dry-run|--apply|--verify] [--db-url DSN] [--report PATH]")
		fmt.Fprintln(stderr, "Keys are env-only: OLD_ENCRYPTION_KEY and NEW_ENCRYPTION_KEY use the first 32 bytes of the raw value, matching ENCRYPTION_KEY runtime semantics.")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, nil, fmt.Errorf("parse flags: %w", err)
	}
	if fs.NArg() != 0 {
		return nil, nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if f.dbURL == "" {
		f.dbURL = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if f.dbURL == "" {
		return nil, nil, fmt.Errorf("--db-url or env DATABASE_URL is required")
	}
	if f.batchSize <= 0 {
		return nil, nil, fmt.Errorf("--batch-size must be > 0")
	}
	if f.apply && f.verify {
		return nil, nil, fmt.Errorf("--apply and --verify are mutually exclusive")
	}
	if !f.dryRun && !f.apply && !f.verify {
		return nil, nil, fmt.Errorf("one of --dry-run, --apply, or --verify is required")
	}
	if f.verify && f.reportInput == "" {
		return nil, nil, fmt.Errorf("--verify requires --report-input")
	}
	targets, err := parseTargets(f.tables, f.columns)
	if err != nil {
		return nil, nil, err
	}
	if f.resumeFrom != "" && len(targets) != 1 {
		return nil, nil, fmt.Errorf("--resume-from requires exactly one --table/--column target")
	}
	return f, targets, nil
}

func parseTargets(tables, columns []string) ([]target, error) {
	if len(tables) == 0 && len(columns) == 0 {
		return []target{
			{Table: "tenant_llm_config", Column: "encrypted_api_key", RowID: "tenant_id", Format: "bytea", UpdateTS: true},
			{Table: "issue_tracker_connections", Column: "auth_token_encrypted", RowID: "id", Format: "base64", UpdateTS: true},
		}, nil
	}
	if len(tables) == 0 || len(columns) == 0 || len(tables) != len(columns) {
		return nil, fmt.Errorf("--table and --column must be supplied the same number of times")
	}
	out := make([]target, 0, len(tables))
	for i := range tables {
		table := tables[i]
		column := columns[i]
		if !safeIdent(table) {
			return nil, fmt.Errorf("--table %q contains characters outside [A-Za-z0-9_]", table)
		}
		if !safeIdent(column) {
			return nil, fmt.Errorf("--column %q contains characters outside [A-Za-z0-9_]", column)
		}
		switch {
		case table == "tenant_llm_config" && column == "encrypted_api_key":
			out = append(out, target{Table: table, Column: column, RowID: "tenant_id", Format: "bytea", UpdateTS: true})
		case table == "issue_tracker_connections" && column == "auth_token_encrypted":
			out = append(out, target{Table: table, Column: column, RowID: "id", Format: "base64", UpdateTS: true})
		default:
			return nil, fmt.Errorf("unsupported target %s.%s", table, column)
		}
	}
	return out, nil
}

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
		default:
			return false
		}
	}
	return true
}

func realMain(args []string, stdout, stderr io.Writer) *exitError {
	now := time.Now().UTC()
	flags, targets, err := parseFlags(args, stderr, now)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return newExitError(exitUsageError, err)
	}

	oldKey, newKey, err := readKeysFromEnv()
	if err != nil {
		return newExitError(exitPrecondition, err)
	}
	defer zero(oldKey)
	defer zero(newKey)
	if string(oldKey) == string(newKey) {
		return newExitError(exitPrecondition, fmt.Errorf("OLD_ENCRYPTION_KEY and NEW_ENCRYPTION_KEY must differ"))
	}

	selectedMode := modeDryRun
	if flags.apply {
		selectedMode = modeApply
	}
	if flags.verify {
		selectedMode = modeVerify
	}
	if selectedMode == modeApply && flags.reportInput == "" && !flags.allowNoDryRun {
		return newExitError(exitPrecondition, fmt.Errorf("--apply requires --report-input from a recent successful --dry-run (or --allow-no-dry-run)"))
	}

	opts := options{
		Mode:            selectedMode,
		ContinueOnError: flags.continueOnError,
		ReportPath:      flags.reportPath,
		ReportInput:     flags.reportInput,
		ResumeFrom:      flags.resumeFrom,
		BatchSize:       flags.batchSize,
		Targets:         targets,
	}

	var expected *dryRunExpectations
	if opts.Mode == modeApply && !flags.allowNoDryRun || opts.Mode == modeVerify {
		dry, err := loadDryRunReport(opts.ReportInput, now, opts.Targets)
		if err != nil {
			return newExitError(exitPrecondition, err)
		}
		opts.ResumeSigningKey = dry.resumeSigningKey
		expected = newDryRunExpectations(dry)
	}

	db, err := openDB("postgres", flags.dbURL)
	if err != nil {
		return newExitError(exitDBError, fmt.Errorf("sql.Open: %w", err))
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return newExitError(exitDBError, fmt.Errorf("db ping: %w", err))
	}

	rep, code, err := run(ctx, db, oldKey, newKey, opts, expected, now)
	if rep != nil {
		rep.FinishedAt = time.Now().UTC()
		if werr := writeReport(opts.ReportPath, rep); werr != nil && err == nil {
			return newExitError(exitDBError, werr)
		}
		fmt.Fprintf(stdout, "report=%s mode=%s total=%d succeeded=%d failed=%d skipped=%d\n",
			opts.ReportPath, rep.Mode, rep.TotalRows, rep.Succeeded, rep.Failed, rep.Skipped)
	}
	if err != nil {
		return newExitError(code, err)
	}
	return nil
}

func readKeysFromEnv() ([]byte, []byte, error) {
	oldKey, err := readKey("OLD_ENCRYPTION_KEY")
	if err != nil {
		return nil, nil, err
	}
	newKey, err := readKey("NEW_ENCRYPTION_KEY")
	if err != nil {
		return nil, nil, err
	}
	return oldKey, newKey, nil
}

func readKey(name string) ([]byte, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	// Runtime semantics: take the first 32 bytes of the raw string verbatim.
	// Base64-decoding here would diverge from internal/config.Config.GetEncryptionKey
	// and cmd/decrypt-test.
	if len(raw) < 32 {
		return nil, fmt.Errorf("%s too short: need >= 32 bytes, got %d", name, len(raw))
	}
	return []byte(raw)[:32], nil
}

func run(ctx context.Context, db *sql.DB, oldKey, newKey []byte, opts options, expected *dryRunExpectations, now time.Time) (*report, int, error) {
	rep := &report{SchemaVersion: reportSchemaVersion, StartedAt: now, Mode: opts.Mode, Tables: tableNames(opts.Targets)}
	tenantIDs, err := queryTenants(ctx, db)
	if err != nil {
		return rep, exitDBError, err
	}
	resume, err := parseResumeConstraint(opts, tenantIDs)
	if err != nil {
		if isPreconditionErr(err) {
			return rep, exitPrecondition, err
		}
		return rep, exitUsageError, err
	}
	for _, tenantID := range tenantIDs {
		for _, tgt := range opts.Targets {
			if resume != nil && (tenantID != resume.TenantID || tgt.Table != resume.Table || tgt.Column != resume.Column) {
				continue
			}
			if err := processTarget(ctx, db, tenantID, tgt, oldKey, newKey, opts, expected, resumeAfter(resume, tenantID, tgt), rep); err != nil {
				if opts.ContinueOnError && isContinuableRowErr(err) {
					rep.Failed++
					continue
				}
				return rep, classifyErr(err), err
			}
		}
	}
	if opts.Mode == modeVerify && expected != nil {
		if err := verifyExpectedCoverage(expected); err != nil {
			return rep, exitPartial, err
		}
	}
	if rep.TotalRows == 0 {
		return rep, exitNoRows, fmt.Errorf("no encrypted rows to migrate")
	}
	if rep.Failed > 0 {
		return rep, exitPartial, fmt.Errorf("%d row(s) failed", rep.Failed)
	}
	return rep, exitOK, nil
}

func queryTenants(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT id FROM tenants ORDER BY id`)
	if err != nil {
		return nil, dbErr{fmt.Errorf("query tenants: %w", err)}
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, dbErr{fmt.Errorf("scan tenant id: %w", err)}
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, dbErr{fmt.Errorf("iterate tenants: %w", err)}
	}
	return ids, nil
}

func processTarget(ctx context.Context, db *sql.DB, tenantID string, tgt target, oldKey, newKey []byte, opts options, expected *dryRunExpectations, after string, rep *report) error {
	last := after
	for {
		n, next, err := processBatch(ctx, db, tenantID, tgt, last, oldKey, newKey, opts, expected, rep)
		if err != nil {
			return err
		}
		if n < opts.BatchSize {
			return nil
		}
		last = next
	}
}

func processBatch(ctx context.Context, db *sql.DB, tenantID string, tgt target, after string, oldKey, newKey []byte, opts options, expected *dryRunExpectations, rep *report) (int, string, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, after, dbErr{fmt.Errorf("begin tx tenant=%s target=%s.%s: %w", tenantID, tgt.Table, tgt.Column, err)}
	}
	committed := false
	rolledBack := false
	defer func() {
		if !committed && !rolledBack {
			_ = tx.Rollback()
		}
	}()
	rollbackDBErr := func(cause error) error {
		if rerr := tx.Rollback(); rerr != nil {
			rolledBack = true
			return dbErr{fmt.Errorf("%w; rollback failed: %v", cause, rerr)}
		}
		rolledBack = true
		return cause
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.current_tenant_id', $1, true)`, tenantID); err != nil {
		return 0, after, dbErr{fmt.Errorf("set tenant context %s: %w", tenantID, err)}
	}

	q := fmt.Sprintf( //nolint:gosec // identifiers come from a closed allow-list in parseTargets.
		`SELECT %s, %s FROM %s WHERE %s IS NOT NULL AND length(%s::text) > 0 AND %s > $1 ORDER BY %s LIMIT $2 FOR UPDATE`,
		tgt.RowID, tgt.Column, tgt.Table, tgt.Column, tgt.Column, tgt.RowID, tgt.RowID,
	)
	rows, err := tx.QueryContext(ctx, q, after, opts.BatchSize)
	if err != nil {
		return 0, after, dbErr{fmt.Errorf("query %s.%s tenant=%s: %w", tgt.Table, tgt.Column, tenantID, err)}
	}
	defer rows.Close()

	count := 0
	last := after
	for rows.Next() {
		var rowID string
		var raw []byte
		var text string
		if tgt.Format == "bytea" {
			if err := rows.Scan(&rowID, &raw); err != nil {
				return count, last, dbErr{fmt.Errorf("scan row: %w", err)}
			}
		} else {
			if err := rows.Scan(&rowID, &text); err != nil {
				return count, last, dbErr{fmt.Errorf("scan row: %w", err)}
			}
			raw = []byte(text)
		}
		count++
		last = rowID
		rep.TotalRows++

		rr, err := processRow(ctx, tx, tenantID, rowID, tgt, raw, oldKey, newKey, opts, expected)
		rep.Rows = append(rep.Rows, rr)
		switch rr.Status {
		case "ok", "re-encrypted":
			rep.Succeeded++
		case "already-new":
			rep.Succeeded++
			rep.Skipped++
		default:
			rep.Failed++
		}
		if err != nil && !opts.ContinueOnError {
			if isDBErr(err) {
				return count, last, rollbackDBErr(err)
			}
			return count, last, err
		}
		if err != nil && isDBErr(err) {
			return count, last, rollbackDBErr(err)
		}
		if err != nil && isPreconditionErr(err) {
			return count, last, err
		}
	}
	if err := rows.Err(); err != nil {
		return count, last, dbErr{fmt.Errorf("iterate rows: %w", err)}
	}
	if err := tx.Commit(); err != nil {
		return count, last, dbErr{fmt.Errorf("commit tenant=%s target=%s.%s: %w", tenantID, tgt.Table, tgt.Column, err)}
	}
	committed = true
	return count, last, nil
}

func processRow(ctx context.Context, tx *sql.Tx, tenantID, rowID string, tgt target, ciphertext []byte, oldKey, newKey []byte, opts options, expected *dryRunExpectations) (rowReport, error) {
	rr := rowReport{Table: tgt.Table, Column: tgt.Column, TenantID: tenantID, RowID: rowID}
	rr.ResumeToken = encodeResumeToken(rr, opts.ResumeSigningKey)
	key := reportKey(tgt.Table, tgt.Column, tenantID, rowID)
	switch opts.Mode {
	case modeDryRun:
		plain, err := decryptForTarget(ciphertext, oldKey, tgt)
		if err != nil {
			rr.Status = "failed"
			rr.Error = "old-key decrypt failed"
			return rr, err
		}
		defer zero(plain)
		rr.SHA256 = digest(plain)
		rr.Status = "ok"
		return rr, nil
	case modeVerify:
		plain, err := decryptForTarget(ciphertext, newKey, tgt)
		if err != nil {
			rr.Status = "failed"
			rr.Error = "new-key decrypt failed"
			return rr, err
		}
		defer zero(plain)
		rr.SHA256 = digest(plain)
		if want, ok := expected.digests[key]; !ok {
			rr.Status = "failed"
			rr.Error = "row missing from dry-run report"
			return rr, fmt.Errorf("row %s.%s tenant=%s row=%s missing from dry-run report", tgt.Table, tgt.Column, tenantID, rowID)
		} else if want != rr.SHA256 {
			rr.Status = "failed"
			rr.Error = "sha256 mismatch"
			return rr, fmt.Errorf("sha256 mismatch for %s.%s tenant=%s row=%s", tgt.Table, tgt.Column, tenantID, rowID)
		}
		expected.seen[key] = struct{}{}
		rr.Status = "ok"
		return rr, nil
	case modeApply:
		plain, err := decryptForTarget(ciphertext, oldKey, tgt)
		if err != nil {
			newPlain, nerr := decryptForTarget(ciphertext, newKey, tgt)
			if nerr != nil {
				rr.Status = "failed"
				rr.Error = "old-key and new-key decrypt failed"
				return rr, err
			}
			defer zero(newPlain)
			rr.SHA256 = digest(newPlain)
			if expected != nil {
				want, ok := expected.digests[key]
				if !ok {
					rr.Status = "failed"
					rr.Error = "row missing from dry-run report"
					return rr, preconditionErr{fmt.Errorf("apply row %s.%s tenant=%s row=%s missing from dry-run report", tgt.Table, tgt.Column, tenantID, rowID)}
				}
				if want != rr.SHA256 {
					rr.Status = "failed"
					rr.Error = "sha256 mismatch on already-new row"
					return rr, fmt.Errorf("sha256 mismatch on already-new row for %s.%s tenant=%s row=%s", tgt.Table, tgt.Column, tenantID, rowID)
				}
			}
			rr.Status = "already-new"
			return rr, nil
		}
		defer zero(plain)
		rr.SHA256 = digest(plain)
		if expected != nil {
			want, ok := expected.digests[key]
			if !ok {
				rr.Status = "failed"
				rr.Error = "row missing from dry-run report"
				return rr, preconditionErr{fmt.Errorf("apply row %s.%s tenant=%s row=%s missing from dry-run report", tgt.Table, tgt.Column, tenantID, rowID)}
			}
			if want != rr.SHA256 {
				rr.Status = "failed"
				rr.Error = "sha256 mismatch before update"
				return rr, fmt.Errorf("sha256 mismatch before update for %s.%s tenant=%s row=%s", tgt.Table, tgt.Column, tenantID, rowID)
			}
		}
		newCT, err := encryptForTarget(plain, newKey, tgt)
		if err != nil {
			rr.Status = "failed"
			rr.Error = "new-key encrypt failed"
			return rr, err
		}
		if err := updateRow(ctx, tx, tgt, rowID, newCT); err != nil {
			rr.Status = "failed"
			rr.Error = "update failed"
			return rr, err
		}
		rr.Status = "re-encrypted"
		return rr, nil
	default:
		rr.Status = "failed"
		rr.Error = "internal mode error"
		return rr, fmt.Errorf("internal: unsupported mode %q", opts.Mode)
	}
}

func decryptForTarget(ciphertext, key []byte, tgt target) ([]byte, error) {
	switch tgt.Table {
	case "tenant_llm_config":
		return llm.Decrypt(ciphertext, key)
	case "issue_tracker_connections":
		plain, err := service.DecryptIssueTrackerToken(string(ciphertext), key)
		if err != nil {
			return nil, err
		}
		return []byte(plain), nil
	default:
		return nil, fmt.Errorf("unsupported table %s", tgt.Table)
	}
}

func encryptForTarget(plaintext, key []byte, tgt target) (any, error) {
	switch tgt.Table {
	case "tenant_llm_config":
		return llm.Encrypt(plaintext, key)
	case "issue_tracker_connections":
		return service.EncryptIssueTrackerToken(string(plaintext), key)
	default:
		return nil, fmt.Errorf("unsupported table %s", tgt.Table)
	}
}

func updateRow(ctx context.Context, tx *sql.Tx, tgt target, rowID string, ciphertext any) error {
	q := fmt.Sprintf( //nolint:gosec // identifiers come from a closed allow-list in parseTargets.
		`UPDATE %s SET %s = $1, updated_at = NOW() WHERE %s = $2`,
		tgt.Table, tgt.Column, tgt.RowID,
	)
	if _, err := tx.ExecContext(ctx, q, ciphertext, rowID); err != nil {
		return dbErr{fmt.Errorf("update %s.%s row=%s: %w", tgt.Table, tgt.Column, rowID, err)}
	}
	return nil
}

func digest(plain []byte) string {
	sum := sha256.Sum256(plain)
	return hex.EncodeToString(sum[:])
}

func writeReport(path string, rep *report) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open report %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("write report %s: %w", path, err)
	}
	return nil
}

func loadDryRunReport(path string, now time.Time, targets []target) (*report, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open --report-input %s: %w", path, err)
	}
	var rep report
	if err := json.Unmarshal(content, &rep); err != nil {
		return nil, fmt.Errorf("decode --report-input %s: %w", path, err)
	}
	if rep.SchemaVersion == "" {
		return nil, fmt.Errorf("--report-input missing schema_version")
	}
	if rep.SchemaVersion != reportSchemaVersion {
		return nil, fmt.Errorf("--report-input schema_version=%q is not supported", rep.SchemaVersion)
	}
	if rep.Mode != modeDryRun {
		return nil, fmt.Errorf("--report-input must be a dry-run report (got mode=%s)", rep.Mode)
	}
	if rep.Failed != 0 {
		return nil, fmt.Errorf("--report-input is not successful: failed=%d", rep.Failed)
	}
	if rep.TotalRows == 0 || rep.Succeeded != rep.TotalRows {
		return nil, fmt.Errorf("--report-input is not a complete successful dry-run")
	}
	if now.Sub(rep.StartedAt) > dryRunMaxAge {
		return nil, fmt.Errorf("--report-input is older than %s", dryRunMaxAge)
	}
	okRows := 0
	seen := make(map[string]struct{}, len(rep.Rows))
	targetSet := make(map[string]struct{}, len(targets))
	for _, tgt := range targets {
		targetSet[targetKey(tgt.Table, tgt.Column)] = struct{}{}
	}
	reportTargets := make(map[string]struct{}, len(rep.Tables))
	for _, table := range rep.Tables {
		if table == "" {
			return nil, fmt.Errorf("--report-input has empty target in tables")
		}
		if _, exists := reportTargets[table]; exists {
			return nil, fmt.Errorf("--report-input has duplicate target %s in tables", table)
		}
		reportTargets[table] = struct{}{}
	}
	if len(reportTargets) != len(targetSet) {
		return nil, fmt.Errorf("--report-input target set does not match current invocation")
	}
	for key := range reportTargets {
		if _, ok := targetSet[key]; !ok {
			return nil, fmt.Errorf("--report-input target %s not selected in current invocation", key)
		}
	}
	for i, row := range rep.Rows {
		if row.Table == "" || row.Column == "" || row.TenantID == "" || row.RowID == "" {
			return nil, fmt.Errorf("--report-input row %d has empty table/column/tenant_id/row_id", i)
		}
		rowTarget := targetKey(row.Table, row.Column)
		if _, ok := reportTargets[rowTarget]; !ok {
			return nil, fmt.Errorf("--report-input row target %s is not listed in tables", rowTarget)
		}
		key := reportKey(row.Table, row.Column, row.TenantID, row.RowID)
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("--report-input has duplicate row key table=%s column=%s tenant=%s row=%s", row.Table, row.Column, row.TenantID, row.RowID)
		}
		seen[key] = struct{}{}
		if row.Status == "ok" && row.SHA256 != "" {
			okRows++
		}
	}
	if rep.TotalRows != okRows {
		return nil, fmt.Errorf("--report-input total_rows=%d does not match ok rows with sha256=%d", rep.TotalRows, okRows)
	}
	sum := sha256.Sum256(content)
	rep.inputPath = path
	rep.resumeSigningKey = sum[:]
	return &rep, nil
}

func newDryRunExpectations(rep *report) *dryRunExpectations {
	out := &dryRunExpectations{
		digests:    make(map[string]string, len(rep.Rows)),
		rows:       make(map[string]rowReport, len(rep.Rows)),
		seen:       make(map[string]struct{}, len(rep.Rows)),
		reportPath: rep.inputPath,
	}
	for _, row := range rep.Rows {
		if row.Status == "ok" && row.SHA256 != "" {
			key := reportKey(row.Table, row.Column, row.TenantID, row.RowID)
			out.digests[key] = row.SHA256
			out.rows[key] = row
		}
	}
	return out
}

func parseResumeConstraint(opts options, tenantIDs []string) (*resumeToken, error) {
	if opts.ResumeFrom == "" {
		return nil, nil
	}
	if len(opts.Targets) != 1 {
		return nil, fmt.Errorf("--resume-from requires exactly one target")
	}
	if opts.Mode == modeApply && len(opts.ResumeSigningKey) == 0 {
		return nil, preconditionErr{fmt.Errorf("--resume-from with --apply requires --report-input for token signature verification")}
	}
	token, err := decodeResumeToken(opts.ResumeFrom, opts.ResumeSigningKey)
	if err != nil {
		return nil, err
	}
	tgt := opts.Targets[0]
	if token.Table != tgt.Table || token.Column != tgt.Column {
		return nil, fmt.Errorf("--resume-from token target %s.%s does not match current target %s.%s", token.Table, token.Column, tgt.Table, tgt.Column)
	}
	matchedTenant := false
	for _, tenantID := range tenantIDs {
		if tenantID == token.TenantID {
			if matchedTenant {
				return nil, fmt.Errorf("--resume-from tenant %s matched more than once", token.TenantID)
			}
			matchedTenant = true
		}
	}
	if !matchedTenant {
		return nil, fmt.Errorf("--resume-from tenant %s is not present in current tenant set", token.TenantID)
	}
	return token, nil
}

func decodeResumeToken(raw string, signingKey []byte) (*resumeToken, error) {
	payload := raw
	if len(signingKey) > 0 {
		parts := strings.Split(raw, ".")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, preconditionErr{fmt.Errorf("--resume-from must be a signed token")}
		}
		payload = parts[0]
		signature, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, preconditionErr{fmt.Errorf("--resume-from signature must be base64url: %w", err)}
		}
		want := resumeTokenSignature(payload, signingKey)
		if !hmac.Equal(signature, want) {
			return nil, preconditionErr{fmt.Errorf("--resume-from signature is invalid")}
		}
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(payload)
	}
	if err != nil {
		return nil, fmt.Errorf("--resume-from must be a base64 JSON token: %w", err)
	}
	var token resumeToken
	if err := json.Unmarshal(decoded, &token); err != nil {
		return nil, fmt.Errorf("--resume-from must decode to JSON: %w", err)
	}
	if token.Table == "" || token.Column == "" || token.TenantID == "" || token.RowID == "" {
		return nil, fmt.Errorf("--resume-from token requires table, column, tenant_id, and row_id")
	}
	return &token, nil
}

func encodeResumeToken(row rowReport, signingKey []byte) string {
	b, _ := json.Marshal(resumeToken{Table: row.Table, Column: row.Column, TenantID: row.TenantID, RowID: row.RowID})
	payload := base64.RawURLEncoding.EncodeToString(b)
	if len(signingKey) == 0 {
		return payload
	}
	signature := resumeTokenSignature(payload, signingKey)
	return payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func resumeTokenSignature(payload string, signingKey []byte) []byte {
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func resumeAfter(token *resumeToken, tenantID string, tgt target) string {
	if token == nil || token.TenantID != tenantID || token.Table != tgt.Table || token.Column != tgt.Column {
		return ""
	}
	return token.RowID
}

func verifyExpectedCoverage(expected *dryRunExpectations) error {
	var missing []string
	totalMissing := 0
	for key, row := range expected.rows {
		if _, ok := expected.seen[key]; ok {
			continue
		}
		totalMissing++
		if len(missing) < verifyMissingLogLimit {
			missing = append(missing, fmt.Sprintf("%s.%s tenant=%s row=%s", row.Table, row.Column, row.TenantID, row.RowID))
		}
	}
	if totalMissing == 0 {
		return nil
	}
	detail := strings.Join(missing, "; ")
	if totalMissing > len(missing) {
		detail += fmt.Sprintf("; ... and %d more (see report file)", totalMissing-len(missing))
	}
	reportPath := expected.reportPath
	if reportPath == "" {
		reportPath = "<unknown>"
	}
	return fmt.Errorf("dry-run report row(s) missing from current DB result: total=%d report=%s: %s", totalMissing, reportPath, detail)
}

func reportKey(table, column, tenantID, rowID string) string {
	return table + ":" + column + ":" + tenantID + ":" + rowID
}

func targetKey(table, column string) string {
	return table + ":" + column
}

func tableNames(targets []target) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Table+":"+t.Column)
	}
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type dbErr struct{ error }
type preconditionErr struct{ error }

func isDBErr(err error) bool {
	var d dbErr
	var pqe *pq.Error
	var pge *pgconn.PgError
	return errors.As(err, &d) ||
		errors.As(err, &pqe) ||
		errors.As(err, &pge) ||
		errors.Is(err, sql.ErrConnDone) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled)
}

func isPreconditionErr(err error) bool {
	var p preconditionErr
	return errors.As(err, &p)
}

func isContinuableRowErr(err error) bool {
	return !isDBErr(err) && !isPreconditionErr(err)
}

func classifyErr(err error) int {
	if isDBErr(err) {
		return exitDBError
	}
	if isPreconditionErr(err) {
		return exitPrecondition
	}
	return exitPartial
}
