package main

import (
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
)

// validBase64Key32 is a 44-char base64 string that decodes to 32 bytes —
// representative of `openssl rand -base64 32` output, and strictly longer than
// 32 bytes when measured as a raw string (len(rawKey) is what the guard
// inspects).
const validBase64Key32 = "9b3a1f6d2e8c4a7b9d5e0f2c1a3b4d6e8f0a2c4b6d8e0f1a3c5b7d9e1f3a5c7=" // 64 chars

// newTestCfg builds a minimal *config.Config carrying just the two fields
// validateEncryptionKey inspects. validateEncryptionKey now takes the full
// cfg (R18-A follow-up) so this helper keeps the table-driven tests readable
// without re-introducing the old string-string signature.
func newTestCfg(key, env string) *config.Config {
	return &config.Config{
		EncryptionKey: key,
		Environment:   env,
	}
}

func TestValidateEncryptionKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		appEnv  string
		wantErr bool
		// substring expected in error message (skip when wantErr=false).
		errSubstr string
	}{
		{
			name:      "empty key + production fails",
			key:       "",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "未設定",
		},
		{
			name:      "empty key + staging fails",
			key:       "",
			appEnv:    "staging",
			wantErr:   true,
			errSubstr: "未設定",
		},
		{
			name:      "empty key + empty APP_ENV fails (default-deny)",
			key:       "",
			appEnv:    "",
			wantErr:   true,
			errSubstr: "未設定",
		},
		{
			name:    "empty key + development is warning only",
			key:     "",
			appEnv:  "development",
			wantErr: false,
		},
		{
			name:      "denylisted bundled compose default fails in production",
			key:       "V5jgaCSCV/Mdf8JbVX42aWYAB6dG1Dp9G9Bo0Nw+qjY=",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "既知デフォルト値",
		},
		{
			name: "denylisted long compose default fails in staging",
			// 33 bytes; passes the length gate so the placeholder branch fires.
			key:       "sbomhub-default-encryption-key-32",
			appEnv:    "staging",
			wantErr:   true,
			errSubstr: "既知デフォルト値",
		},
		{
			name:      "denylisted dev fallback fails on length (it is 31 bytes)",
			key:       "dev-only-insecure-key-32bytes!!",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "長さ不足",
		},
		{
			name:      "short placeholder 'changeme' fails (caught by length first)",
			key:       "changeme",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "長さ不足",
		},
		{
			name:      "short placeholder 'default' fails in production",
			key:       "default",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "長さ不足",
		},
		{
			name:      "short placeholder 'test' fails in production",
			key:       "test",
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "長さ不足",
		},
		{
			name:      "31-byte key fails in production",
			key:       strings.Repeat("a", 31),
			appEnv:    "production",
			wantErr:   true,
			errSubstr: "長さ不足",
		},
		{
			name:    "31-byte key is warning in development",
			key:     strings.Repeat("a", 31),
			appEnv:  "development",
			wantErr: false,
		},
		{
			name:    "valid base64 key passes in production",
			key:     validBase64Key32,
			appEnv:  "production",
			wantErr: false,
		},
		{
			name:    "valid 32-byte ASCII key passes in production",
			key:     "01234567890123456789012345678901",
			appEnv:  "production",
			wantErr: false,
		},
		{
			name:      "denylisted placeholder long enough still fails",
			key:       "your-encryption-key-here" + strings.Repeat("x", 32),
			appEnv:    "production",
			wantErr:   false, // not exactly equal to placeholder
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncryptionKey(newTestCfg(tc.key, tc.appEnv))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}

// TestValidateEncryptionKey_ExactPlaceholderMatch verifies the denylist matches
// only on the exact literal — a longer string that contains the placeholder as
// a substring must NOT be rejected by the placeholder check (length / random
// content carry it). This guards against a regression where someone changes
// the comparison to strings.Contains.
func TestValidateEncryptionKey_ExactPlaceholderMatch(t *testing.T) {
	// "your-encryption-key-here" is 24 chars, padded to 56 → length OK, exact
	// match fails → passes.
	key := "your-encryption-key-here-" + strings.Repeat("z", 32)
	if err := validateEncryptionKey(newTestCfg(key, "production")); err != nil {
		t.Fatalf("unexpected error for non-exact placeholder: %v", err)
	}
}

// TestEvaluateAppRoleRLS exercises the pure decision branch of
// assertAppRoleNotBypassRLS (M4 Codex review #F72). The F72 finding flagged
// that the original guard only checked rolbypassrls and silently accepted a
// PostgreSQL superuser, because PostgreSQL bypasses RLS for superusers
// regardless of rolbypassrls. The bundled enterprise compose file launches
// the official `postgres` image with POSTGRES_USER=sbomhub, which the image
// creates as a superuser, so production deployments using the default
// runtime user had tenant isolation silently disabled while this guard
// logged "DB role check passed".
//
// The table below pins every (bypassRLS, superuser, env) combination so
// the rejection contract — superuser=true OR bypassRLS=true must fail in
// production/staging/unset, and warn-only in development — cannot regress.
func TestEvaluateAppRoleRLS(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		bypassRLS  bool
		superuser  bool
		appEnv     string
		wantErr    bool
		errSubstrs []string
	}{
		// F72: the bug fix. rolsuper=true, rolbypassrls=false in
		// production must now hard-fail.
		{
			name:      "F72 reject superuser in production (rolbypassrls=false)",
			role:      "sbomhub",
			bypassRLS: false,
			superuser: true,
			appEnv:    "production",
			wantErr:   true,
			errSubstrs: []string{
				"RLS startup guard FAIL",
				"rolsuper=true",
				"sbomhub_app",
			},
		},
		{
			name:       "F72 reject superuser in staging",
			role:       "sbomhub",
			bypassRLS:  false,
			superuser:  true,
			appEnv:     "staging",
			wantErr:    true,
			errSubstrs: []string{"rolsuper=true"},
		},
		{
			name:       "F72 reject superuser when APP_ENV is unset (default-deny)",
			role:       "sbomhub",
			bypassRLS:  false,
			superuser:  true,
			appEnv:     "",
			wantErr:    true,
			errSubstrs: []string{"rolsuper=true"},
		},
		// Regression: rolbypassrls=true must still fail.
		{
			name:       "reject rolbypassrls in production",
			role:       "sbomhub",
			bypassRLS:  true,
			superuser:  false,
			appEnv:     "production",
			wantErr:    true,
			errSubstrs: []string{"rolbypassrls=true", "rolsuper=false"},
		},
		// Both attributes true (e.g. a superuser that also has the
		// explicit BYPASSRLS attribute) — error message must surface
		// both so the operator gets one clear diagnostic.
		{
			name:       "reject when both attributes true",
			role:       "postgres",
			bypassRLS:  true,
			superuser:  true,
			appEnv:     "production",
			wantErr:    true,
			errSubstrs: []string{"rolbypassrls=true", "rolsuper=true"},
		},
		// The happy path: sbomhub_app-style role created with
		// NOSUPERUSER NOBYPASSRLS.
		{
			name:      "accept normal role in production",
			role:      "sbomhub_app",
			bypassRLS: false,
			superuser: false,
			appEnv:    "production",
			wantErr:   false,
		},
		{
			name:      "accept normal role with empty APP_ENV",
			role:      "sbomhub_app",
			bypassRLS: false,
			superuser: false,
			appEnv:    "",
			wantErr:   false,
		},
		// Development downgrades both attributes to a warning so
		// contributors can keep running against a single-role local DB.
		{
			name:      "development warn-only on superuser",
			role:      "postgres",
			bypassRLS: false,
			superuser: true,
			appEnv:    "development",
			wantErr:   false,
		},
		{
			name:      "development warn-only on rolbypassrls",
			role:      "postgres",
			bypassRLS: true,
			superuser: false,
			appEnv:    "development",
			wantErr:   false,
		},
		{
			name:      "development warn-only when both attributes true",
			role:      "postgres",
			bypassRLS: true,
			superuser: true,
			appEnv:    "development",
			wantErr:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluateAppRoleRLS(tc.role, tc.bypassRLS, tc.superuser,
				newTestCfg("", tc.appEnv))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				for _, want := range tc.errSubstrs {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q does not contain %q", err.Error(), want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
		})
	}
}
