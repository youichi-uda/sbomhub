package main

import (
	"bytes"
	"errors"
	"flag"
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
