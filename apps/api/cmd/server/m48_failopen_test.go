package main

import (
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/config"
)

// ---------------------------------------------------------------------------
// M48 — the startup half of the two fail-open findings that were about
// CONFIGURATION rather than about a request path.
//
// Both are regression tests in the strict sense: each case below was measured
// against the pre-M48 binary on this repo's dev Postgres (2026-07-29) before
// the guards existed, and each one started and served traffic.
// ---------------------------------------------------------------------------

// loadCfg drives config.Load through the environment rather than building a
// Config literal, because the field that decides self-hosted vs SaaS
// (Config.mode) is unexported and derived. A literal would test a state the
// server can never actually hold.
//
// Every variable the guards read is set explicitly — including to "" — so a
// case never inherits a value from the developer's shell or from a previous
// subtest.
func loadCfg(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	for _, k := range []string{
		"APP_ENV", "ENVIRONMENT",
		"CLERK_SECRET_KEY", "CLERK_WEBHOOK_SECRET",
		"LEMONSQUEEZY_API_KEY", "LEMONSQUEEZY_WEBHOOK_SECRET", "LEMONSQUEEZY_STORE_ID",
		"LEMONSQUEEZY_STARTER_VARIANT_ID", "LEMONSQUEEZY_PRO_VARIANT_ID", "LEMONSQUEEZY_TEAM_VARIANT_ID",
		"SBOMHUB_ALLOW_ANONYMOUS_AUTH", "SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", "SBOMHUB_AUTH_MODE",
	} {
		t.Setenv(k, env[k])
	}
	return config.Load()
}

// TestM48ValidateAppEnv — FO-4.
//
// Pre-M48, config.Load substituted "development" for an unset APP_ENV, so
// every guard keyed on IsDevelopment() relaxed for a deployment that had said
// nothing at all. Measured with the pre-M48 binary, APP_ENV unset:
//
//	WARN  ENCRYPTION_KEY is unsafe — DO NOT deploy this way
//	WARN  CLERK_WEBHOOK_SECRET is not set: every Clerk webhook delivery will be rejected
//	WARN  DB role bypasses Row-Level Security — tenant isolation is NOT enforced
//
// — three warnings where APP_ENV=production or =staging gives three refusals,
// and the process then served GET /api/v1/health -> 200.
func TestM48ValidateAppEnv(t *testing.T) {
	cases := []struct {
		name      string
		appEnv    string
		legacyEnv string // ENVIRONMENT, the pre-M0 fallback
		wantErr   bool
		errSubstr string
	}{
		{name: "development is accepted", appEnv: "development"},
		{name: "staging is accepted", appEnv: "staging"},
		{name: "production is accepted", appEnv: "production"},
		{
			// The finding itself.
			name:      "unset is refused",
			wantErr:   true,
			errSubstr: "APP_ENV が未設定です",
		},
		{
			// A typo satisfied neither IsProduction() nor IsDevelopment().
			// The main.go guards happen to treat that as strict, but
			// config.Validate's checks were IsProduction()-only, so the
			// combination was strict in one file and lax in the other.
			name:      "a near-miss spelling of production is refused",
			appEnv:    "prod",
			wantErr:   true,
			errSubstr: "未知の値",
		},
		{
			name:      "capitalisation is not normalised away",
			appEnv:    "Production",
			wantErr:   true,
			errSubstr: "未知の値",
		},
		{
			// The legacy fallback still works — it just has to name a
			// known environment like APP_ENV does.
			name:      "the legacy ENVIRONMENT fallback still resolves",
			legacyEnv: "production",
		},
		{
			name:      "the legacy fallback is held to the same allowlist",
			legacyEnv: "prod",
			wantErr:   true,
			errSubstr: "未知の値",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadCfg(t, map[string]string{
				"APP_ENV":     tc.appEnv,
				"ENVIRONMENT": tc.legacyEnv,
			})
			err := validateAppEnv(cfg)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("expected the process to start, got refusal: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("APP_ENV=%q ENVIRONMENT=%q was accepted — an unnamed environment "+
					"silently selects the weakest posture the process has", tc.appEnv, tc.legacyEnv)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("refusal %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

// TestM48AppEnvUnsetDoesNotResolveToDevelopment pins the specific substitution
// that made FO-4 possible, independently of validateAppEnv. The guard is one
// way to observe it; the predicate is the thing that has to change, because
// UnsignedWebhooksAllowed and the middleware-side downgrades read it directly.
func TestM48AppEnvUnsetDoesNotResolveToDevelopment(t *testing.T) {
	cfg := loadCfg(t, nil)
	if cfg.Environment != "" {
		t.Fatalf("config.Load substituted %q for an unset APP_ENV — that default is what made "+
			"\"the operator configured nothing\" the weakest configuration the process has",
			cfg.Environment)
	}
	if cfg.IsDevelopment() {
		t.Fatal("IsDevelopment() is true with APP_ENV unset: every guard keyed on it " +
			"(validateEncryptionKey, evaluateAppRoleRLS, AnonymousAuthAllowed, " +
			"UnsignedWebhooksAllowed) relaxes for a deployment that said nothing")
	}
	if cfg.IsProduction() {
		t.Fatal("IsProduction() is true with APP_ENV unset: unset must be a refusal, " +
			"not a different implicit answer")
	}
}

// TestM48ValidateAuthMode — FO-3.
//
// Measured against the pre-M48 binary, APP_ENV=production, CLERK_SECRET_KEY
// removed, real Postgres: the server started with one WARN, and then
//
//	POST /api/v1/projects   (no Authorization header) -> 201
//	GET  /api/v1/me         (no Authorization header) -> 200 role=owner plan=enterprise
//	POST /api/v1/apikeys    (no Authorization header) -> 201 + a live key
//
// and that key still returned 200 on /api/v1/cli/projects and
// /api/v1/mcp/projects after the server was restarted WITH a Clerk key. That
// is the argument for refusing at startup: supplying the missing variable
// afterwards does not revoke what the window handed out.
func TestM48ValidateAuthMode(t *testing.T) {
	const clerk = "sk_live_x"

	cases := []struct {
		name      string
		env       map[string]string
		wantErr   bool
		errSubstr string
	}{
		// ---- The declaration is required. --------------------------------
		{
			// The core of FO-3 after three review rounds: the mode is
			// DECLARED, never inferred. Rounds 1-3 each broke a version that
			// inferred it, because a SaaS deployment whose secret injection
			// fails entirely is byte-for-byte a self-hosted one.
			name:      "no declaration is refused, even with a clerk key present",
			env:       map[string]string{"APP_ENV": "production", "CLERK_SECRET_KEY": clerk},
			wantErr:   true,
			errSubstr: "SBOMHUB_AUTH_MODE が未設定です",
		},
		{
			name:      "no declaration is refused for a self-hosted deployment",
			env:       map[string]string{"APP_ENV": "production"},
			wantErr:   true,
			errSubstr: "SBOMHUB_AUTH_MODE が未設定です",
		},
		{
			name:      "no declaration is refused in development too",
			env:       map[string]string{"APP_ENV": "development"},
			wantErr:   true,
			errSubstr: "SBOMHUB_AUTH_MODE が未設定です",
		},
		{
			name:      "an unknown declaration is refused",
			env:       map[string]string{"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "none"},
			wantErr:   true,
			errSubstr: "未知の値",
		},

		// ---- The declaration must match reality, both ways. ---------------
		{
			// THE finding round 3 reopened. A Clerk deployment whose secret
			// store injected nothing at all leaves no SaaS signal to
			// contradict — but the declaration lives in the manifest, not the
			// secret store, so it survives and refuses.
			name: "declared clerk with no clerk key is refused",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "clerk",
			},
			wantErr:   true,
			errSubstr: "SBOMHUB_AUTH_MODE=clerk",
		},
		{
			name: "declared anonymous with a clerk key present is refused",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "anonymous",
				"CLERK_SECRET_KEY": clerk, "CLERK_WEBHOOK_SECRET": "whsec_x",
			},
			wantErr:   true,
			errSubstr: "SBOMHUB_AUTH_MODE=anonymous",
		},

		// ---- The retired flag is refused, not ignored. --------------------
		{
			// It never shipped, but an operator following an intermediate M48
			// draft would otherwise believe they had acknowledged something.
			name: "the retired boolean opt-in is refused",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "anonymous",
				"SBOMHUB_ALLOW_ANONYMOUS_AUTH": "true",
			},
			wantErr:   true,
			errSubstr: "SBOMHUB_ALLOW_ANONYMOUS_AUTH は廃止されました",
		},

		// ---- Contradiction: declared anonymous, but SaaS vars present. ----
		{
			// The half-configured accident: the operator meant SaaS and the
			// Clerk key specifically is what went missing, so the declaration
			// still says anonymous from an earlier phase.
			name: "declared anonymous while carrying a clerk webhook secret is refused",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "anonymous",
				"CLERK_WEBHOOK_SECRET": "whsec_x",
			},
			wantErr:   true,
			errSubstr: "CLERK_WEBHOOK_SECRET",
		},
		{
			name: "declared anonymous while carrying a lemonsqueezy key is refused",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "anonymous",
				"LEMONSQUEEZY_API_KEY": "ls_x",
			},
			wantErr:   true,
			errSubstr: "LEMONSQUEEZY_API_KEY",
		},
		{
			name: "the contradiction is refused in development too",
			env: map[string]string{
				"APP_ENV": "development", "SBOMHUB_AUTH_MODE": "anonymous",
				"LEMONSQUEEZY_STORE_ID": "12345",
			},
			wantErr:   true,
			errSubstr: "LEMONSQUEEZY_STORE_ID",
		},
		{
			name: "every saas signal is named in the refusal",
			env: map[string]string{
				"APP_ENV": "staging", "SBOMHUB_AUTH_MODE": "anonymous",
				"CLERK_WEBHOOK_SECRET": "whsec_x",
				"LEMONSQUEEZY_API_KEY": "ls_x", "LEMONSQUEEZY_TEAM_VARIANT_ID": "9",
			},
			wantErr:   true,
			errSubstr: "LEMONSQUEEZY_TEAM_VARIANT_ID",
		},

		// ---- Accepted. ----------------------------------------------------
		{
			name: "declared clerk with the key present starts",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "clerk",
				"CLERK_SECRET_KEY": clerk, "CLERK_WEBHOOK_SECRET": "whsec_x",
				"LEMONSQUEEZY_API_KEY": "ls_x",
			},
		},
		{
			name: "declared anonymous with nothing else set starts",
			env: map[string]string{
				"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "anonymous",
			},
		},
		{
			name: "the same in development",
			env: map[string]string{
				"APP_ENV": "development", "SBOMHUB_AUTH_MODE": "anonymous",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadCfg(t, tc.env)
			err := validateAuthMode(cfg)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("expected the process to start, got refusal: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %v — this deployment may serve unauthenticated requests "+
					"as Owner of the default tenant", tc.env)
			}
			if !strings.Contains(err.Error(), tc.errSubstr) {
				t.Fatalf("refusal %q does not contain %q", err.Error(), tc.errSubstr)
			}
		})
	}
}

// TestM48AnonymousAuthIsDeclaredNotInferred is the property the whole of FO-3
// reduces to after three review rounds.
//
// AnonymousAuthAllowed() must depend ONLY on the declaration. If it consulted
// the presence or absence of CLERK_SECRET_KEY in any way, a deployment whose
// secret injection failed entirely would be indistinguishable from a
// self-hosted one — which is precisely how rounds 1, 2 and 3 each broke the
// previous design.
func TestM48AnonymousAuthIsDeclaredNotInferred(t *testing.T) {
	// No declaration: not allowed, regardless of what else is set.
	for _, env := range []map[string]string{
		{"APP_ENV": "production"},
		{"APP_ENV": "production", "CLERK_SECRET_KEY": "sk_live_x"},
		{"APP_ENV": "development"},
	} {
		if cfg := loadCfg(t, env); cfg.AnonymousAuthAllowed() {
			t.Errorf("AnonymousAuthAllowed() is true with no declaration: %v", env)
		}
	}

	// Declared clerk: never allowed, even with the key missing — that is the
	// case the declaration exists for, and it must refuse rather than degrade.
	cfg := loadCfg(t, map[string]string{"APP_ENV": "production", "SBOMHUB_AUTH_MODE": "clerk"})
	if cfg.AnonymousAuthAllowed() {
		t.Error("AnonymousAuthAllowed() is true under a clerk declaration with no key — " +
			"a failed secret injection must be a refusal, not a downgrade")
	}
	if err := cfg.ValidateAuthMode(); err == nil {
		t.Error("ValidateAuthMode accepted SBOMHUB_AUTH_MODE=clerk with an empty CLERK_SECRET_KEY")
	}

	// Declared anonymous: allowed, in every environment.
	for _, env := range config.KnownEnvironments {
		cfg := loadCfg(t, map[string]string{"APP_ENV": env, "SBOMHUB_AUTH_MODE": "anonymous"})
		if !cfg.AnonymousAuthAllowed() {
			t.Errorf("AnonymousAuthAllowed() is false under APP_ENV=%q with an explicit "+
				"anonymous declaration", env)
		}
		if err := validateAuthMode(cfg); err != nil {
			t.Errorf("APP_ENV=%q refused a well-formed anonymous declaration: %v", env, err)
		}
	}
}

// TestM48EncryptionKeyValidationCoversStaging is the smaller FO-4 sibling my
// own sweep turned up rather than M47's.
//
// The two encryption-key denylists live in different files with different
// contents, and they were guarded by different predicates:
// cmd/server/main.go's validateEncryptionKey refuses outside DEVELOPMENT,
// config.Validate's refused only in PRODUCTION. "00000000...0000" appears only
// in config.Validate's list, so under APP_ENV=staging it passed both — the
// first because it is not on that list, the second because staging is not
// production.
func TestM48EncryptionKeyValidationCoversStaging(t *testing.T) {
	const allZeros = "00000000000000000000000000000000" // 32 bytes, weak

	// The pre-M48 hole: staging accepted it.
	staging := &config.Config{EncryptionKey: allZeros, Environment: "staging"}
	if err := validateEncryptionKey(staging); err != nil {
		// If main.go's denylist ever grows this value the test still holds,
		// it just stops being interesting — say so rather than pass silently.
		t.Logf("note: validateEncryptionKey now rejects the all-zeros key directly: %v", err)
	}
	if err := staging.Validate(); err == nil {
		t.Fatal("config.Validate accepted an all-zeros ENCRYPTION_KEY under APP_ENV=staging — " +
			"the weak-key denylist must relax in development only, matching " +
			"cmd/server/main.go validateEncryptionKey")
	}

	// Development still relaxes, so local work is unaffected.
	dev := &config.Config{EncryptionKey: allZeros, Environment: "development"}
	if err := dev.Validate(); err != nil {
		t.Fatalf("development rejected a weak key: %v — the downgrade is what keeps "+
			"`go run ./cmd/server` usable", err)
	}

	// And an empty key still gets the development-only fallback, not a refusal.
	devEmpty := &config.Config{Environment: "development"}
	if err := devEmpty.Validate(); err != nil {
		t.Fatalf("development rejected an empty key: %v", err)
	}
	if devEmpty.EncryptionKey == "" {
		t.Fatal("the development fallback key was not substituted")
	}
	stagingEmpty := &config.Config{Environment: "staging"}
	if err := stagingEmpty.Validate(); err == nil {
		t.Fatal("config.Validate accepted an empty ENCRYPTION_KEY under APP_ENV=staging")
	}
}
