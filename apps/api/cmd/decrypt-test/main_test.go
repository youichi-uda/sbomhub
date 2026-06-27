package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Coverage scope: the pure-Go bits of decrypt-test that do NOT require a live
// Postgres / live llm.Decrypt round-trip. The full smoke (key + DB + sample
// row) is exercised end-to-end by the wrapper script under docker compose; we
// intentionally keep the unit test surface narrow so it can run without
// CGO / pq side effects.

func TestParseFlags_RequiresKeyAndDBURL(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("DATABASE_URL", "")

	cases := []struct {
		name string
		args []string
		want string // substring expected in error
	}{
		{
			name: "no key",
			args: []string{"--db-url", "postgres://x"},
			want: "ENCRYPTION_KEY",
		},
		{
			name: "no db url",
			args: []string{"--key", strings.Repeat("k", 32)},
			want: "DATABASE_URL",
		},
		{
			name: "empty table",
			args: []string{"--key", strings.Repeat("k", 32), "--db-url", "postgres://x", "--table", ""},
			want: "--table must be non-empty",
		},
		{
			name: "bad format",
			args: []string{"--key", strings.Repeat("k", 32), "--db-url", "postgres://x", "--format", "json"},
			want: "--format must be empty",
		},
		{
			name: "sql-injection table",
			args: []string{"--key", strings.Repeat("k", 32), "--db-url", "postgres://x", "--table", "users; DROP TABLE x"},
			want: "characters outside",
		},
		{
			name: "sql-injection column",
			args: []string{"--key", strings.Repeat("k", 32), "--db-url", "postgres://x", "--column", "x' OR '1'='1"},
			want: "characters outside",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			_, err := parseFlags(tc.args, &stderr)
			if err == nil {
				t.Fatalf("parseFlags(%v) = nil, want error containing %q", tc.args, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseFlags(%v) error = %q, want substring %q", tc.args, err, tc.want)
			}
		})
	}
}

func TestParseFlags_EnvFallback(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("e", 32))
	t.Setenv("DATABASE_URL", "postgres://localhost/sbomhub")

	var stderr bytes.Buffer
	f, err := parseFlags([]string{}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags with env fallback: %v", err)
	}
	if f.key != strings.Repeat("e", 32) {
		t.Errorf("key not picked up from env: got %q", f.key)
	}
	if f.dbURL != "postgres://localhost/sbomhub" {
		t.Errorf("dbURL not picked up from env: got %q", f.dbURL)
	}
	if f.table != "tenant_llm_config" {
		t.Errorf("default table: got %q, want tenant_llm_config", f.table)
	}
	if f.column != "encrypted_api_key" {
		t.Errorf("default column: got %q, want encrypted_api_key", f.column)
	}
}

func TestParseFlags_KeyFile(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("DATABASE_URL", "")

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "encryption_key.txt")
	key := strings.Repeat("f", 32)
	if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stderr bytes.Buffer
	f, err := parseFlags([]string{"--key-file", keyPath, "--db-url", "postgres://x"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags with --key-file: %v", err)
	}
	if f.key != key {
		t.Fatalf("key from --key-file = %q, want file contents", f.key)
	}
}

func TestParseFlags_KeyFileNotFound(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("DATABASE_URL", "")

	missingPath := filepath.Join(t.TempDir(), "missing.txt")
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key-file", missingPath, "--db-url", "postgres://x"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with missing --key-file = nil, want error")
	}
	if !strings.Contains(err.Error(), "read --key-file") {
		t.Fatalf("parseFlags error = %q, want read --key-file context", err)
	}
}

func TestParseFlags_KeyFileTrimsTrailingNewline(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("DATABASE_URL", "")

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "encryption_key.txt")
	key := strings.Repeat("n", 32)
	if err := os.WriteFile(keyPath, []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	var stderr bytes.Buffer
	f, err := parseFlags([]string{"--key-file", keyPath, "--db-url", "postgres://x"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags with newline-terminated --key-file: %v", err)
	}
	if f.key != key {
		t.Fatalf("key from newline-terminated --key-file = %q, want trimmed %q", f.key, key)
	}
}

func TestParseFlags_KeyFlagWinsOverKeyFile(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("e", 32))
	t.Setenv("DATABASE_URL", "")

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "encryption_key.txt")
	fileKey := strings.Repeat("f", 32)
	if err := os.WriteFile(keyPath, []byte(fileKey), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	flagKey := strings.Repeat("k", 32)
	var stderr bytes.Buffer
	f, err := parseFlags([]string{
		"--key", flagKey,
		"--key-file", keyPath,
		"--db-url", "postgres://x",
	}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags with --key and --key-file: %v", err)
	}
	if f.key != flagKey {
		t.Fatalf("key precedence = %q, want explicit --key %q", f.key, flagKey)
	}
}

func TestParseFlags_Help(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--help"}, &stderr)
	if err == nil {
		t.Fatal("--help should return an error wrapping flag.ErrHelp so realMain can exit 0")
	}
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("--help: errors.Is(err, flag.ErrHelp) = false, err = %v", err)
	}
	if !strings.Contains(stderr.String(), "Exit codes") {
		t.Errorf("--help should print the Exit codes table; stderr was: %s", stderr.String())
	}
}

func TestSafeIdent(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"tenant_llm_config", true},
		{"encrypted_api_key", true},
		{"auth_token_encrypted", true},
		{"a", true},
		{"a1_b2", true},
		{"", false},
		{"a-b", false},
		{"a.b", false},
		{"a;b", false},
		{"DROP TABLE x", false},
		{"a b", false},
		{"a'b", false},
	}
	for _, tc := range cases {
		if got := safeIdent(tc.in); got != tc.want {
			t.Errorf("safeIdent(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestVerifyEncryptionScript_KeyFile(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "encryption_key.txt")
	key := strings.Repeat("k", 32)
	if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	capturePath := filepath.Join(tmp, "capture.txt")
	fakeBin := filepath.Join(tmp, "decrypt-test")
	fakeScript := `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${ENCRYPTION_KEY}" > "${CAPTURE_PATH}"
printf '%s\n' "${DATABASE_URL}" >> "${CAPTURE_PATH}"
printf '%s\n' "$*" >> "${CAPTURE_PATH}"
`
	if err := os.WriteFile(fakeBin, []byte(fakeScript), 0o700); err != nil {
		t.Fatalf("write fake decrypt-test: %v", err)
	}

	scriptPath := filepath.Join("..", "..", "..", "..", "docker", "scripts", "verify-encryption.sh")
	cmd := exec.Command("bash", scriptPath,
		"--key-file", keyPath,
		"--db-url", "postgres://sbomhub_app:test@127.0.0.1:5432/sbomhub?sslmode=disable",
		"--table", "issue_tracker_connections",
		"--column", "auth_token_encrypted",
	)
	cmd.Env = append(os.Environ(),
		"ENCRYPTION_KEY=",
		"DATABASE_URL=",
		"DECRYPT_TEST_BIN="+fakeBin,
		"CAPTURE_PATH="+capturePath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("verify-encryption.sh --key-file failed: %v\nstderr:\n%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "--key is deprecated") {
		t.Fatalf("--key-file should not emit --key deprecation warning; stderr:\n%s", stderr.String())
	}

	capturedBytes, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(capturedBytes)), "\n")
	if len(lines) != 3 {
		t.Fatalf("capture lines = %q, want key/db-url/args", string(capturedBytes))
	}
	if lines[0] != key {
		t.Fatalf("ENCRYPTION_KEY passed to decrypt-test = %q, want key file contents", lines[0])
	}
	if !strings.Contains(lines[1], "127.0.0.1:5432") {
		t.Fatalf("DATABASE_URL passed to decrypt-test = %q", lines[1])
	}
	if strings.Contains(lines[2], key) {
		t.Fatalf("decrypt-test argv leaked key: %q", lines[2])
	}
	if !strings.Contains(lines[2], "--table issue_tracker_connections") ||
		!strings.Contains(lines[2], "--column auth_token_encrypted") {
		t.Fatalf("decrypt-test argv missing table/column flags: %q", lines[2])
	}
}
