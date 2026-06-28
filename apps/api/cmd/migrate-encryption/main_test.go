package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

var (
	testOldKey = []byte("0123456789abcdef0123456789abcdef")
	testNewKey = []byte("abcdef0123456789abcdef0123456789")
	testNow    = time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
)

func TestParseFlags_DefaultsAndEnvPrecedence(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://env")
	var stderr bytes.Buffer
	f, targets, err := parseFlags(nil, &stderr, testNow)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if f.dbURL != "postgres://env" {
		t.Fatalf("dbURL = %q", f.dbURL)
	}
	if !f.dryRun || f.apply || f.verify {
		t.Fatalf("default mode flags = dry:%v apply:%v verify:%v", f.dryRun, f.apply, f.verify)
	}
	if f.batchSize != defaultBatchSize {
		t.Fatalf("batchSize = %d", f.batchSize)
	}
	if len(targets) != 2 {
		t.Fatalf("default targets = %d", len(targets))
	}
}

func TestParseFlags_CustomTargetsAndValidation(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"db required", nil, "DATABASE_URL"},
		{"table column count", []string{"--db-url", "postgres://x", "--table", "tenant_llm_config"}, "same number"},
		{"unsafe table", []string{"--db-url", "postgres://x", "--table", "x;drop", "--column", "encrypted_api_key"}, "characters outside"},
		{"unsupported target", []string{"--db-url", "postgres://x", "--table", "tenants", "--column", "id"}, "unsupported target"},
		{"bad batch", []string{"--db-url", "postgres://x", "--batch-size", "0"}, "batch-size"},
		{"verify needs report", []string{"--db-url", "postgres://x", "--verify"}, "--report-input"},
		{"positional rejected", []string{"--db-url", "postgres://x", "secret"}, "unexpected positional"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			_, _, err := parseFlags(tc.args, &stderr, testNow)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseFlags_Help(t *testing.T) {
	var stderr bytes.Buffer
	_, _, err := parseFlags([]string{"--help"}, &stderr, testNow)
	if err == nil || !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("--help err = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(stderr.String(), "OLD_ENCRYPTION_KEY") {
		t.Fatalf("help missing env-only key guidance: %s", stderr.String())
	}
}

func TestReadKeysFromEnv_RawFirst32AndEnvOnly(t *testing.T) {
	oldRaw := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	newRaw := "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZmFiY2RlZjAxMjM="
	t.Setenv("OLD_ENCRYPTION_KEY", oldRaw)
	t.Setenv("NEW_ENCRYPTION_KEY", newRaw)
	oldKey, newKey, err := readKeysFromEnv()
	if err != nil {
		t.Fatalf("readKeysFromEnv: %v", err)
	}
	if string(oldKey) != oldRaw[:32] || string(newKey) != newRaw[:32] {
		t.Fatalf("raw first-32 keys mismatch: old=%q new=%q", oldKey, newKey)
	}

	var stderr bytes.Buffer
	_, _, err = parseFlags([]string{"--db-url", "postgres://x", "--old-key", "not-allowed"}, &stderr, testNow)
	if err == nil {
		t.Fatal("argv key-like flag should be rejected as usage error")
	}
}

func TestReadKeyRejectsTooShortRawValue(t *testing.T) {
	t.Setenv("OLD_ENCRYPTION_KEY", strings.Repeat("k", 31))
	_, err := readKey("OLD_ENCRYPTION_KEY")
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("readKey too-short err = %v", err)
	}
}

func TestReadKeyMatchesRuntimeFirst32BytesAndRoundTrip(t *testing.T) {
	cleanBase64 := "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "clean base64", raw: cleanBase64},
		{name: "leading newline", raw: "\n" + cleanBase64},
		{name: "leading whitespace", raw: " \t" + cleanBase64},
		{name: "trailing whitespace", raw: cleanBase64 + " \t"},
		{name: "trailing newline", raw: cleanBase64 + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OLD_ENCRYPTION_KEY", tc.raw)

			migrateKey, err := readKey("OLD_ENCRYPTION_KEY")
			if err != nil {
				t.Fatalf("readKey: %v", err)
			}
			runtimeKey, err := (&config.Config{EncryptionKey: tc.raw}).GetEncryptionKey()
			if err != nil {
				t.Fatalf("GetEncryptionKey: %v", err)
			}
			decryptTestKey := []byte(tc.raw)[:32]

			if string(migrateKey) != string(runtimeKey) || string(migrateKey) != string(decryptTestKey) {
				t.Fatalf("key semantics diverged: migrate=%q runtime=%q decrypt-test=%q", migrateKey, runtimeKey, decryptTestKey)
			}

			plain := []byte("round-trip with raw first-32 key")
			ct, err := llm.Encrypt(plain, migrateKey)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := llm.Decrypt(ct, runtimeKey)
			if err != nil {
				t.Fatalf("decrypt with runtime key: %v", err)
			}
			if string(got) != string(plain) {
				t.Fatalf("round-trip plaintext = %q, want %q", got, plain)
			}
		})
	}
}

func TestRealMain_ExitCodes64And65(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr bytes.Buffer
	if ee := realMain([]string{"--db-url"}, &stdout, &stderr); ee == nil || ee.Code != exitUsageError {
		t.Fatalf("usage ee = %#v", ee)
	}

	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("OLD_ENCRYPTION_KEY", string(testOldKey))
	t.Setenv("NEW_ENCRYPTION_KEY", string(testOldKey))
	if ee := realMain([]string{}, &stdout, &stderr); ee == nil || ee.Code != exitPrecondition {
		t.Fatalf("precondition ee = %#v", ee)
	}
}

func TestDryRun_NoDBWriteAndReport(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("tenant-secret")
	ct, err := llm.Encrypt(plain, testOldKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	expectTenants(mock, "tenant_a")
	expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeDryRun,
		BatchSize: 1000,
		Targets:   []target{defaultLLMTarget()},
	}, nil, testNow)
	if err != nil || code != exitOK {
		t.Fatalf("run dry = code %d err %v", code, err)
	}
	if rep.TotalRows != 1 || rep.Succeeded != 1 || rep.Rows[0].SHA256 != digest(plain) {
		t.Fatalf("unexpected report: %#v", rep)
	}
	assertExpectations(t, mock)
}

func TestApplyRequiresDryRunReport(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("OLD_ENCRYPTION_KEY", string(testOldKey))
	t.Setenv("NEW_ENCRYPTION_KEY", string(testNewKey))
	var stdout, stderr bytes.Buffer
	ee := realMain([]string{"--apply", "--db-url", "postgres://x"}, &stdout, &stderr)
	if ee == nil || ee.Code != exitPrecondition {
		t.Fatalf("apply without report ee = %#v", ee)
	}
}

func TestApply_IdempotencySkipsAlreadyNew(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	oldPlain := []byte("old-row-secret")
	newPlain := []byte("already-new-secret")
	oldCT, _ := llm.Encrypt(oldPlain, testOldKey)
	newCT, _ := llm.Encrypt(newPlain, testNewKey)
	dry := &report{Rows: []rowReport{
		{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "row_old", SHA256: digest(oldPlain), Status: "ok"},
		{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "row_new", SHA256: digest(newPlain), Status: "ok"},
	}}

	expectTenants(mock, "tenant_a")
	expectTenantBatchStart(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).
			AddRow("row_old", oldCT).
			AddRow("row_new", newCT))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenant_llm_config SET encrypted_api_key = $1, updated_at = NOW() WHERE tenant_id = $2`)).
		WithArgs(sqlmock.AnyArg(), "row_old").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeApply,
		BatchSize: 1000,
		Targets:   []target{defaultLLMTarget()},
	}, newDryRunExpectations(dry), testNow)
	if err != nil || code != exitOK {
		t.Fatalf("run apply = code %d err %v", code, err)
	}
	if rep.Succeeded != 2 || rep.Skipped != 1 || rep.Rows[1].Status != "already-new" {
		t.Fatalf("unexpected idempotency report: %#v", rep)
	}
	assertExpectations(t, mock)
}

func TestApplyStrictGateMissingDryRunRowIsPrecondition(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("not-in-report")
	ct, _ := llm.Encrypt(plain, testOldKey)
	dry := &report{Rows: []rowReport{
		{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "different", SHA256: digest([]byte("different")), Status: "ok"},
	}}

	expectTenants(mock, "tenant_a")
	expectTenantBatchNoCommit(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeApply,
		BatchSize: 1000,
		Targets:   []target{defaultLLMTarget()},
	}, newDryRunExpectations(dry), testNow)
	if err == nil || code != exitPrecondition {
		t.Fatalf("run apply missing dry-run row = code %d err %v", code, err)
	}
	if rep.Failed != 1 || rep.Rows[0].Error != "row missing from dry-run report" {
		t.Fatalf("unexpected report: %#v", rep)
	}
	assertExpectations(t, mock)
}

func TestVerifyDigestMismatchIsPartial(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("new-secret")
	ct, _ := llm.Encrypt(plain, testNewKey)
	expected := &dryRunExpectations{
		digests: map[string]string{reportKey("tenant_llm_config", "encrypted_api_key", "tenant_a", "tenant_a"): strings.Repeat("0", 64)},
		rows:    map[string]rowReport{},
		seen:    map[string]struct{}{},
	}

	expectTenants(mock, "tenant_a")
	expectTenantBatchNoCommit(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeVerify,
		BatchSize: 1000,
		Targets:   []target{defaultLLMTarget()},
	}, expected, testNow)
	if err == nil || code != exitPartial {
		t.Fatalf("run verify mismatch = code %d err %v", code, err)
	}
	if rep.Failed != 1 || rep.Rows[0].Error != "sha256 mismatch" {
		t.Fatalf("unexpected report: %#v", rep)
	}
	assertExpectations(t, mock)
}

func TestVerifyReportsDryRunRowsMissingFromCurrentDB(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	expected := &dryRunExpectations{
		digests: map[string]string{reportKey("tenant_llm_config", "encrypted_api_key", "tenant_a", "missing"): strings.Repeat("a", 64)},
		rows: map[string]rowReport{
			reportKey("tenant_llm_config", "encrypted_api_key", "tenant_a", "missing"): {
				Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "missing",
			},
		},
		seen:       map[string]struct{}{},
		reportPath: "dry-run.json",
	}

	expectTenants(mock, "tenant_a")
	expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}))

	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeVerify,
		BatchSize: 1000,
		Targets:   []target{defaultLLMTarget()},
	}, expected, testNow)
	if err == nil || code != exitPartial || !strings.Contains(err.Error(), "missing from current DB result") {
		t.Fatalf("verify missing coverage = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestVerifyExpectedCoverageCapsMissingRows(t *testing.T) {
	expected := &dryRunExpectations{
		digests:    map[string]string{},
		rows:       map[string]rowReport{},
		seen:       map[string]struct{}{},
		reportPath: "/tmp/dry-run.json",
	}
	for i := 0; i < 200; i++ {
		row := rowReport{
			Table:    "tenant_llm_config",
			Column:   "encrypted_api_key",
			TenantID: "tenant_a",
			RowID:    fmt.Sprintf("row_%03d", i),
		}
		key := reportKey(row.Table, row.Column, row.TenantID, row.RowID)
		expected.rows[key] = row
	}
	err := verifyExpectedCoverage(expected)
	if err == nil {
		t.Fatal("expected missing coverage error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "total=200") || !strings.Contains(msg, "report=/tmp/dry-run.json") || !strings.Contains(msg, "... and 100 more (see report file)") {
		t.Fatalf("missing cap summary = %v", err)
	}
	if got := strings.Count(msg, "tenant_llm_config.encrypted_api_key tenant=tenant_a row="); got != 100 {
		t.Fatalf("inline missing rows = %d, want 100: %v", got, err)
	}
}

func TestBatchBoundary(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	ct1, _ := llm.Encrypt([]byte("one"), testOldKey)
	ct2, _ := llm.Encrypt([]byte("two"), testOldKey)
	ct3, _ := llm.Encrypt([]byte("three"), testOldKey)
	tgt := defaultLLMTarget()
	expectTenants(mock, "tenant_a")
	expectTenantBatch(mock, "tenant_a", tgt, "", 2,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("a", ct1).AddRow("b", ct2))
	expectTenantBatch(mock, "tenant_a", tgt, "b", 2,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("c", ct3))

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:      modeDryRun,
		BatchSize: 2,
		Targets:   []target{tgt},
	}, nil, testNow)
	if err != nil || code != exitOK || rep.TotalRows != 3 {
		t.Fatalf("batch run = code %d total %d err %v", code, rep.TotalRows, err)
	}
	assertExpectations(t, mock)
}

func TestPartialFailureContinueVsAbort(t *testing.T) {
	t.Run("abort rolls back", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		expectTenants(mock, "tenant_a")
		expectTenantBatchNoCommit(mock, "tenant_a", defaultLLMTarget(), "", 1000,
			sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", []byte("bad")))
		rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
			Mode:      modeDryRun,
			BatchSize: 1000,
			Targets:   []target{defaultLLMTarget()},
		}, nil, testNow)
		if err == nil || code != exitPartial || rep.Failed != 1 {
			t.Fatalf("abort = code %d failed %d err %v", code, rep.Failed, err)
		}
		assertExpectations(t, mock)
	})

	t.Run("continue commits batch", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		good, _ := llm.Encrypt([]byte("good"), testOldKey)
		expectTenants(mock, "tenant_a")
		expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "", 1000,
			sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).
				AddRow("bad", []byte("bad")).
				AddRow("good", good))

		rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
			Mode:            modeDryRun,
			ContinueOnError: true,
			BatchSize:       1000,
			Targets:         []target{defaultLLMTarget()},
		}, nil, testNow)
		if err == nil || code != exitPartial || rep.Failed != 1 || rep.Succeeded != 1 {
			t.Fatalf("continue = code %d succeeded %d failed %d err %v", code, rep.Succeeded, rep.Failed, err)
		}
		assertExpectations(t, mock)
	})
}

func TestContinueOnErrorDoesNotSwallowDBErrors(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("needs-update")
	ct, _ := llm.Encrypt(plain, testOldKey)
	dry := &report{Rows: []rowReport{
		{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "tenant_a", SHA256: digest(plain), Status: "ok"},
	}}

	expectTenants(mock, "tenant_a")
	expectTenantBatchStart(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenant_llm_config SET encrypted_api_key = $1, updated_at = NOW() WHERE tenant_id = $2`)).
		WithArgs(sqlmock.AnyArg(), "tenant_a").
		WillReturnError(sql.ErrConnDone)
	mock.ExpectRollback()

	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:            modeApply,
		ContinueOnError: true,
		BatchSize:       1000,
		Targets:         []target{defaultLLMTarget()},
	}, newDryRunExpectations(dry), testNow)
	if err == nil || code != exitDBError {
		t.Fatalf("continue-on-error db error = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestRollbackFailureClassifiedAsDBError(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("needs-update")
	ct, _ := llm.Encrypt(plain, testOldKey)
	dry := &report{Rows: []rowReport{
		{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "tenant_a", SHA256: digest(plain), Status: "ok"},
	}}

	expectTenants(mock, "tenant_a")
	expectTenantBatchStart(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenant_llm_config SET encrypted_api_key = $1, updated_at = NOW() WHERE tenant_id = $2`)).
		WithArgs(sqlmock.AnyArg(), "tenant_a").
		WillReturnError(sql.ErrConnDone)
	mock.ExpectRollback().WillReturnError(sql.ErrConnDone)

	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:            modeApply,
		ContinueOnError: true,
		BatchSize:       1000,
		Targets:         []target{defaultLLMTarget()},
	}, newDryRunExpectations(dry), testNow)
	if err == nil || code != exitDBError || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback db error = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestCommitErrorClassifiedAsDBError(t *testing.T) {
	db, mock := newMockDB(t)
	defer db.Close()
	plain := []byte("good")
	ct, _ := llm.Encrypt(plain, testOldKey)
	expectTenants(mock, "tenant_a")
	expectTenantBatchStart(mock, "tenant_a", defaultLLMTarget(), "", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", ct))
	mock.ExpectCommit().WillReturnError(sql.ErrConnDone)

	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:            modeDryRun,
		ContinueOnError: true,
		BatchSize:       1000,
		Targets:         []target{defaultLLMTarget()},
	}, nil, testNow)
	if err == nil || code != exitDBError {
		t.Fatalf("commit db error = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestResumeFromStructuredToken(t *testing.T) {
	token := encodeResumeToken(rowReport{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "b"}, nil)
	db, mock := newMockDB(t)
	defer db.Close()
	ct, _ := llm.Encrypt([]byte("after"), testOldKey)
	expectTenants(mock, "tenant_a", "tenant_b")
	expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "b", 1000,
		sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("c", ct))

	rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:       modeDryRun,
		ResumeFrom: token,
		BatchSize:  1000,
		Targets:    []target{defaultLLMTarget()},
	}, nil, testNow)
	if err != nil || code != exitOK || rep.TotalRows != 1 {
		t.Fatalf("resume run = code %d total %d err %v", code, rep.TotalRows, err)
	}
	assertExpectations(t, mock)
}

func TestApplyResumeFromRequiresSignedToken(t *testing.T) {
	signingKey := []byte("dry-run-report-sha256-32-byte-key")
	manualToken := encodeResumeToken(rowReport{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "b"}, nil)

	db, mock := newMockDB(t)
	defer db.Close()
	expectTenants(mock, "tenant_a")
	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:             modeApply,
		ResumeFrom:       manualToken,
		ResumeSigningKey: signingKey,
		BatchSize:        1000,
		Targets:          []target{defaultLLMTarget()},
	}, nil, testNow)
	if err == nil || code != exitPrecondition || !strings.Contains(err.Error(), "signed token") {
		t.Fatalf("manual resume token = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestApplyResumeFromRejectsTamperedSignature(t *testing.T) {
	signingKey := []byte("dry-run-report-sha256-32-byte-key")
	token := encodeResumeToken(rowReport{Table: "tenant_llm_config", Column: "encrypted_api_key", TenantID: "tenant_a", RowID: "b"}, signingKey)
	replacement := "A"
	if strings.HasSuffix(token, "A") {
		replacement = "B"
	}
	token = token[:len(token)-1] + replacement

	db, mock := newMockDB(t)
	defer db.Close()
	expectTenants(mock, "tenant_a")
	_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
		Mode:             modeApply,
		ResumeFrom:       token,
		ResumeSigningKey: signingKey,
		BatchSize:        1000,
		Targets:          []target{defaultLLMTarget()},
	}, nil, testNow)
	if err == nil || code != exitPrecondition || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("tampered resume token = code %d err %v", code, err)
	}
	assertExpectations(t, mock)
}

func TestApplyAndVerifyAllowZeroRowSelectedTargetFromReportTables(t *testing.T) {
	llmPlain := []byte("llm-secret")
	oldCT, _ := llm.Encrypt(llmPlain, testOldKey)
	newCT, _ := llm.Encrypt(llmPlain, testNewKey)
	targets := []target{defaultLLMTarget(), defaultIssueTrackerTarget()}
	dry := &report{
		SchemaVersion: reportSchemaVersion,
		StartedAt:     testNow.Add(-time.Hour),
		Mode:          modeDryRun,
		Tables:        tableNames(targets),
		TotalRows:     1,
		Succeeded:     1,
		Rows: []rowReport{{
			Table:    "tenant_llm_config",
			Column:   "encrypted_api_key",
			TenantID: "tenant_a",
			RowID:    "tenant_a",
			Status:   "ok",
			SHA256:   digest(llmPlain),
		}},
	}

	t.Run("load validates table-derived target set", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "dry.json")
		writeJSON(t, path, dry)
		if _, err := loadDryRunReport(path, testNow, targets); err != nil {
			t.Fatalf("loadDryRunReport with zero-row target: %v", err)
		}
	})

	t.Run("apply succeeds", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		expectTenants(mock, "tenant_a")
		expectTenantBatchStart(mock, "tenant_a", defaultLLMTarget(), "", 1000,
			sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", oldCT))
		mock.ExpectExec(regexp.QuoteMeta(`UPDATE tenant_llm_config SET encrypted_api_key = $1, updated_at = NOW() WHERE tenant_id = $2`)).
			WithArgs(sqlmock.AnyArg(), "tenant_a").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		expectTenantBatch(mock, "tenant_a", defaultIssueTrackerTarget(), "", 1000,
			sqlmock.NewRows([]string{"id", "auth_token_encrypted"}))

		rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
			Mode:      modeApply,
			BatchSize: 1000,
			Targets:   targets,
		}, newDryRunExpectations(dry), testNow)
		if err != nil || code != exitOK || rep.TotalRows != 1 {
			t.Fatalf("apply with zero-row target = code %d total %d err %v", code, rep.TotalRows, err)
		}
		assertExpectations(t, mock)
	})

	t.Run("verify succeeds", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		expectTenants(mock, "tenant_a")
		expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "", 1000,
			sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}).AddRow("tenant_a", newCT))
		expectTenantBatch(mock, "tenant_a", defaultIssueTrackerTarget(), "", 1000,
			sqlmock.NewRows([]string{"id", "auth_token_encrypted"}))

		rep, code, err := run(context.Background(), db, testOldKey, testNewKey, options{
			Mode:      modeVerify,
			BatchSize: 1000,
			Targets:   targets,
		}, newDryRunExpectations(dry), testNow)
		if err != nil || code != exitOK || rep.TotalRows != 1 {
			t.Fatalf("verify with zero-row target = code %d total %d err %v", code, rep.TotalRows, err)
		}
		assertExpectations(t, mock)
	})
}

func TestExitCodesFromRun(t *testing.T) {
	t.Run("db error", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tenants ORDER BY id`)).
			WillReturnError(sql.ErrConnDone)
		_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{Mode: modeDryRun, BatchSize: 1, Targets: []target{defaultLLMTarget()}}, nil, testNow)
		if err == nil || code != exitDBError {
			t.Fatalf("db error = code %d err %v", code, err)
		}
	})
	t.Run("no rows", func(t *testing.T) {
		db, mock := newMockDB(t)
		defer db.Close()
		expectTenants(mock, "tenant_a")
		expectTenantBatch(mock, "tenant_a", defaultLLMTarget(), "", 1000,
			sqlmock.NewRows([]string{"tenant_id", "encrypted_api_key"}))
		_, code, err := run(context.Background(), db, testOldKey, testNewKey, options{Mode: modeDryRun, BatchSize: 1000, Targets: []target{defaultLLMTarget()}}, nil, testNow)
		if err == nil || code != exitNoRows {
			t.Fatalf("no rows = code %d err %v", code, err)
		}
	})
}

func TestLoadDryRunReportPreconditions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dry.json")
	rep := report{
		SchemaVersion: reportSchemaVersion,
		StartedAt:     testNow.Add(-time.Hour),
		Mode:          modeDryRun,
		Tables:        tableNames([]target{defaultLLMTarget()}),
		TotalRows:     1,
		Succeeded:     1,
		Rows: []rowReport{{
			Table:    "tenant_llm_config",
			Column:   "encrypted_api_key",
			TenantID: "tenant_a",
			RowID:    "tenant_a",
			Status:   "ok",
			SHA256:   strings.Repeat("a", 64),
		}},
	}
	writeJSON(t, path, rep)
	if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err != nil {
		t.Fatalf("loadDryRunReport valid: %v", err)
	}
	rep.StartedAt = testNow.Add(-25 * time.Hour)
	writeJSON(t, path, rep)
	if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("old report err = %v", err)
	}
}

func TestLoadDryRunReportValidatesRowsAndTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dry.json")
	base := report{
		SchemaVersion: reportSchemaVersion,
		StartedAt:     testNow.Add(-time.Hour),
		Mode:          modeDryRun,
		Tables:        tableNames([]target{defaultLLMTarget()}),
		TotalRows:     1,
		Succeeded:     1,
		Rows: []rowReport{{
			Table:    "tenant_llm_config",
			Column:   "encrypted_api_key",
			TenantID: "tenant_a",
			RowID:    "tenant_a",
			Status:   "ok",
			SHA256:   strings.Repeat("a", 64),
		}},
	}

	t.Run("total rows must match ok sha rows", func(t *testing.T) {
		rep := base
		rep.TotalRows = 2
		rep.Succeeded = 2
		writeJSON(t, path, rep)
		if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err == nil || !strings.Contains(err.Error(), "total_rows") {
			t.Fatalf("total rows err = %v", err)
		}
	})

	t.Run("duplicate tuple rejected", func(t *testing.T) {
		rep := base
		rep.TotalRows = 2
		rep.Succeeded = 2
		rep.Rows = append(rep.Rows, rep.Rows[0])
		writeJSON(t, path, rep)
		if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err == nil || !strings.Contains(err.Error(), "duplicate row key") {
			t.Fatalf("duplicate err = %v", err)
		}
	})

	t.Run("target set must match invocation", func(t *testing.T) {
		writeJSON(t, path, base)
		other := target{Table: "issue_tracker_connections", Column: "auth_token_encrypted", RowID: "id", Format: "base64", UpdateTS: true}
		if _, err := loadDryRunReport(path, testNow, []target{other}); err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("target err = %v", err)
		}
	})

	t.Run("row target must be listed in report tables", func(t *testing.T) {
		rep := base
		rep.Tables = tableNames([]target{defaultIssueTrackerTarget()})
		writeJSON(t, path, rep)
		if _, err := loadDryRunReport(path, testNow, []target{defaultIssueTrackerTarget()}); err == nil || !strings.Contains(err.Error(), "row target") {
			t.Fatalf("row target err = %v", err)
		}
	})

	t.Run("schema version required", func(t *testing.T) {
		rep := base
		rep.SchemaVersion = ""
		writeJSON(t, path, rep)
		if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err == nil || !strings.Contains(err.Error(), "schema_version") {
			t.Fatalf("missing schema err = %v", err)
		}
	})

	t.Run("unknown schema version rejected", func(t *testing.T) {
		rep := base
		rep.SchemaVersion = "2"
		writeJSON(t, path, rep)
		if _, err := loadDryRunReport(path, testNow, []target{defaultLLMTarget()}); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("unknown schema err = %v", err)
		}
	})
}

func defaultLLMTarget() target {
	return target{Table: "tenant_llm_config", Column: "encrypted_api_key", RowID: "tenant_id", Format: "bytea", UpdateTS: true}
}

func defaultIssueTrackerTarget() target {
	return target{Table: "issue_tracker_connections", Column: "auth_token_encrypted", RowID: "id", Format: "base64", UpdateTS: true}
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return db, mock
}

func expectTenants(mock sqlmock.Sqlmock, ids ...string) {
	rows := sqlmock.NewRows([]string{"id"})
	for _, id := range ids {
		rows.AddRow(id)
	}
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id FROM tenants ORDER BY id`)).WillReturnRows(rows)
}

func expectTenantBatch(mock sqlmock.Sqlmock, tenantID string, tgt target, after string, limit int, rows *sqlmock.Rows) {
	expectTenantBatchStart(mock, tenantID, tgt, after, limit, rows)
	mock.ExpectCommit()
}

func expectTenantBatchStart(mock sqlmock.Sqlmock, tenantID string, tgt target, after string, limit int, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('app.current_tenant_id', $1, true)`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(selectBatchRegex(tgt)).
		WithArgs(after, limit).
		WillReturnRows(rows)
}

func expectTenantBatchNoCommit(mock sqlmock.Sqlmock, tenantID string, tgt target, after string, limit int, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('app.current_tenant_id', $1, true)`)).
		WithArgs(tenantID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(selectBatchRegex(tgt)).
		WithArgs(after, limit).
		WillReturnRows(rows)
	mock.ExpectRollback()
}

func selectBatchRegex(tgt target) string {
	return regexp.QuoteMeta(`SELECT ` + tgt.RowID + `, ` + tgt.Column + ` FROM ` + tgt.Table + ` WHERE ` + tgt.Column + ` IS NOT NULL AND length(` + tgt.Column + `::text) > 0 AND ($1 = '' OR ` + tgt.RowID + ` > $1::uuid) ORDER BY ` + tgt.RowID + ` LIMIT $2 FOR UPDATE`)
}

func assertExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
