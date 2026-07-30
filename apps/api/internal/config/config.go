package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Mode represents the application deployment mode
type Mode string

const (
	ModeSelfHosted Mode = "self-hosted"
	ModeSaaS       Mode = "saas"
)

type Config struct {
	// Core settings
	Port        string
	DatabaseURL string
	RedisURL    string
	NVDAPIKey   string
	BaseURL     string
	Environment string // development, staging, production

	// External data-source URL overrides (M40). Empty = use the service's
	// built-in default endpoint. Set to point a source at an internal mirror for
	// air-gapped / firewalled deployments (SBOMHUB_<SRC>_URL).
	EPSSURL string // FIRST.org EPSS
	KEVURL  string // CISA KEV catalog
	NVDURL  string // NVD (shared by the per-SBOM keyword scan and the delta-feed sync)
	EOLURL  string // endoflife.date
	JVNURL  string // JVN / MyJVN
	OSVURL  string // OSV.dev

	// Offline / air-gapped mode (M40, SBOMHUB_OFFLINE). When true, every external
	// vulnerability data-source sync (EPSS, KEV, NVD, EOL, JVN, OSV, IPA) skips
	// its outbound fetch and degrades gracefully (structured log, no error)
	// instead of failing — the product keeps running on already-synced data.
	// Mirrors the LLM "disabled provider" degrade shape. (The GHSA advisory
	// client used for AI-triage grounding is not gated here — see carry-over.)
	Offline bool

	// Clerk authentication (SaaS mode)
	ClerkSecretKey     string
	ClerkWebhookSecret string

	// AllowUnsignedWebhooks (SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS) is the explicit,
	// operator-named opt-in that lets the Clerk / Lemon Squeezy receivers accept
	// webhooks WITHOUT verifying their signature — and only while no secret is
	// configured for that receiver at all.
	//
	// M47: it replaces the inferred bypass those receivers used to apply
	// (`if secret == "" { return !IsProduction() }`), which turned every
	// deployment that had simply not set the secret — APP_ENV resolved to
	// "development" when unset — into an open webhook endpoint. The flag is
	// refused at startup in production (see cmd/server/main.go
	// validateWebhookVerification) AND re-checked at request time, so the
	// bypass cannot be reached there by any combination of env vars.
	//
	// A configured secret always wins: the flag never disables verification
	// for a receiver whose secret is set.
	AllowUnsignedWebhooks bool

	// AuthMode (SBOMHUB_AUTH_MODE) is the REQUIRED declaration of which
	// authentication mode this deployment intends. It is the whole of M48's
	// FO-3 answer, and it took three review rounds to arrive at.
	//
	// Values: "clerk" | "anonymous". There is no default and no inference.
	//
	//   - "clerk"     -> CLERK_SECRET_KEY must be present, or refuse to start.
	//   - "anonymous" -> the acknowledged self-host posture: the Clerk-fronted
	//     route groups serve every request as Owner of the default tenant with
	//     no credential of any kind (middleware.handleSelfHostedAuth). Refused
	//     if a Clerk key IS present, because then the declaration is false.
	//     (The API-key groups /api/v1/cli/* and /api/v1/mcp/* still require a
	//     key; /api/v1/health and /api/v1/public/:token are anonymous in both
	//     modes.)
	//
	// # Why a required declaration, and not a flag
	//
	// The anonymous posture used to be reached purely by INFERENCE from an
	// empty CLERK_SECRET_KEY, so a SaaS deployment whose key was missing or
	// misspelled landed in it silently. M48 first tried to separate intent
	// from accident with a boolean opt-in (SBOMHUB_ALLOW_ANONYMOUS_AUTH), then
	// with that boolean plus an OPTIONAL declaration. Codex rounds 1-3 took
	// both apart, and the reason both failed is the same: as long as the mode
	// is INFERRED from whether a secret arrived, a deployment whose secret
	// injection fails ENTIRELY is indistinguishable from a self-hosted one —
	// there is nothing left to contradict — and any durable "anonymous is
	// fine" artefact left over from an earlier phase then authorises it.
	// Refusing a stale flag at boot does not help, because it only fires on a
	// boot where the key IS present; it says nothing about a first boot, a
	// crash-loop, or a rollout where the key never arrived (round 3, High).
	//
	// A required declaration removes the inference instead of patching it. A
	// Clerk deployment says "clerk" in its (non-secret) manifest, so when the
	// secret store injects nothing, the surviving declaration REFUSES rather
	// than authorising. Staleness now fails in the safe direction: a stale
	// "clerk" is a boot failure, and there is no state a Clerk deployment can
	// carry that permits anonymous mode.
	//
	// SBOMHUB_ALLOW_ANONYMOUS_AUTH, which the first two attempts introduced,
	// is deleted rather than deprecated: it never shipped in a release, and
	// keeping it as an accepted alias would reinstate exactly the hole above.
	// ValidateRetiredEnv refuses it explicitly — called from
	// cmd/server/main.go, not from Load — so an operator who followed an
	// intermediate draft gets told, rather than silently losing the setting.
	AuthMode string

	// Lemon Squeezy billing (SaaS mode)
	LemonSqueezyAPIKey         string
	LemonSqueezyWebhookSecret  string
	LemonSqueezyStoreID        string
	LemonSqueezyStarterVariant string
	LemonSqueezyProVariant     string
	LemonSqueezyTeamVariant    string

	// Security
	EncryptionKey string // For encrypting sensitive data like API tokens

	// Outbound egress policy (M50). Governs the destinations a TENANT may
	// configure: issue tracker base URLs, Slack/Discord notification webhooks,
	// the diff webhook, and the per-tenant Azure OpenAI endpoint. It does NOT
	// govern operator-supplied destinations (SBOMHUB_*_URL feed mirrors, the
	// Ollama base URL from SBOMHUB_LLM_OLLAMA_URL / OLLAMA_HOST, the billing
	// provider API) — the operator already controls those.
	//
	// EgressAllowPrivate (SBOMHUB_EGRESS_ALLOW_PRIVATE) opens RFC1918 /
	// loopback / CGNAT / IPv6-ULA destinations. It defaults to FALSE in every
	// deployment mode, self-hosted included: a tenant-supplied URL is untrusted
	// input wherever it is entered. Self-hosted operators who point tenants at
	// an internal Jira or an internal webhook receiver must opt in here, or use
	// the narrower EgressAllowedInternal below. See docs/UPGRADE.md.
	//
	// Cloud metadata (169.254.169.254 and the rest of link-local, Azure's
	// 168.63.129.16, and the IPv6 tunnel forms that embed them) is refused even
	// when this is true — see internal/egress.ClassBlocked.
	EgressAllowPrivate bool

	// EgressAllowedInternal (SBOMHUB_EGRESS_ALLOWED_INTERNAL) is the narrow
	// form of the same opt-in: a comma/space separated list of hostnames, IP
	// addresses and CIDRs whose internal destinations are permitted while the
	// rest of the internal network stays closed. Raw string; parsed by
	// egress.ParseExemptions at wiring time so a typo is a startup refusal
	// rather than a silently-closed path.
	EgressAllowedInternal string

	// EgressNAT64Prefixes (SBOMHUB_EGRESS_NAT64_PREFIXES) declares the RFC 6052
	// IPv4/IPv6 translation prefixes this deployment's network uses, so that a
	// destination reached through one is judged by the IPv4 address it embeds
	// rather than treated as opaque public IPv6.
	//
	// Only needed on IPv6-only networks that reach IPv4 through a NAT64 with a
	// prefix other than the well-known 64:ff9b::/96 (which is always decoded).
	// Raw string; parsed and validated at wiring time.
	EgressNAT64Prefixes string

	// EgressAllowProxy (SBOMHUB_EGRESS_ALLOW_PROXY) honours HTTP_PROXY /
	// HTTPS_PROXY for tenant-configured egress. Default false.
	//
	// With a proxy in play, Go hands the guarded dialer the PROXY's address —
	// the proxy is the one that resolves and connects to the real destination.
	// The dial-time guarantee the egress guard exists to provide therefore does
	// not hold, so honouring a proxy is an explicit delegation rather than a
	// default. Set it only when the destination policy is enforced on the proxy.
	EgressAllowProxy bool

	// SMTP settings (for email notifications)
	SMTPHost     string
	SMTPPort     string
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	// Derived settings
	mode Mode
}

func Load() *Config {
	// SECURITY (codex-r18 P1): APP_ENV is the canonical deployment-mode env,
	// matching docker-compose.yml and the startup guards in cmd/server/main.go
	// (assertAppRoleNotBypassRLS, validateEncryptionKey). The legacy
	// ENVIRONMENT variable is kept as a backward-compat fallback for pre-M0
	// self-host deployments. Reading APP_ENV first ensures cfg.IsProduction()
	// agrees with the startup gate, so webhook handlers that fall back to
	// "skip signature verification when not production" cannot be tricked into
	// skipping in a production deployment that only sets APP_ENV.
	//
	// M48 (FO-4): NO default is substituted here any more. This used to fall
	// back to "development", which made "operator set nothing" the single
	// weakest configuration the process can hold — validateEncryptionKey
	// accepted a missing key, evaluateAppRoleRLS accepted a BYPASSRLS role,
	// and UnsignedWebhooksAllowed became reachable. Environment stays exactly
	// as the operator spelled it (possibly ""), and ValidateEnvironment below
	// is what turns an unset or unrecognised value into a refusal to start.
	//
	// Every predicate on this type is written so that an unrecognised value is
	// the STRICT side: IsDevelopment() is false, so no guard downgrades.
	env := getEnv("APP_ENV", "")
	if env == "" {
		env = getEnv("ENVIRONMENT", "")
	}

	cfg := &Config{
		// Core
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		NVDAPIKey:   getEnv("NVD_API_KEY", ""),
		BaseURL:     getEnv("BASE_URL", "http://localhost:3000"),
		Environment: env,

		// External data-source URL overrides + offline mode (M40). Defaults are
		// empty so each service falls back to its own built-in const (single
		// source of truth for the default URL — not duplicated here).
		EPSSURL: getEnv("SBOMHUB_EPSS_URL", ""),
		KEVURL:  getEnv("SBOMHUB_KEV_URL", ""),
		NVDURL:  getEnv("SBOMHUB_NVD_URL", ""),
		EOLURL:  getEnv("SBOMHUB_EOL_URL", ""),
		JVNURL:  getEnv("SBOMHUB_JVN_URL", ""),
		OSVURL:  getEnv("SBOMHUB_OSV_URL", ""),
		Offline: getEnvBool("SBOMHUB_OFFLINE", false),

		// Clerk
		ClerkSecretKey:     getEnv("CLERK_SECRET_KEY", ""),
		ClerkWebhookSecret: getEnv("CLERK_WEBHOOK_SECRET", ""),

		// Webhook signature verification (M47). Default false = fail-closed.
		AllowUnsignedWebhooks: getEnvBool("SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS", false),

		// Declared auth mode (M48). Required; empty is a startup refusal, not
		// an inference. See the AuthMode field comment.
		AuthMode: strings.ToLower(strings.TrimSpace(getEnv("SBOMHUB_AUTH_MODE", ""))),

		// Lemon Squeezy
		LemonSqueezyAPIKey:         getEnv("LEMONSQUEEZY_API_KEY", ""),
		LemonSqueezyWebhookSecret:  getEnv("LEMONSQUEEZY_WEBHOOK_SECRET", ""),
		LemonSqueezyStoreID:        getEnv("LEMONSQUEEZY_STORE_ID", ""),
		LemonSqueezyStarterVariant: getEnv("LEMONSQUEEZY_STARTER_VARIANT_ID", ""),
		LemonSqueezyProVariant:     getEnv("LEMONSQUEEZY_PRO_VARIANT_ID", ""),
		LemonSqueezyTeamVariant:    getEnv("LEMONSQUEEZY_TEAM_VARIANT_ID", ""),

		// Security
		// SECURITY: Default key is only for development. Production requires explicit key.
		EncryptionKey: getEnv("ENCRYPTION_KEY", ""),

		// Outbound egress policy (M50). Fail-closed default in every mode.
		EgressAllowPrivate:    getEnvBool("SBOMHUB_EGRESS_ALLOW_PRIVATE", false),
		EgressAllowedInternal: getEnv("SBOMHUB_EGRESS_ALLOWED_INTERNAL", ""),
		EgressAllowProxy:      getEnvBool("SBOMHUB_EGRESS_ALLOW_PROXY", false),
		EgressNAT64Prefixes:   getEnv("SBOMHUB_EGRESS_NAT64_PREFIXES", ""),

		// SMTP
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     getEnv("SMTP_PORT", "587"),
		SMTPUser:     getEnv("SMTP_USER", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "noreply@sbomhub.app"),
	}

	// Determine mode based on configuration.
	//
	// NOTE (Codex round 4, Low): this is still derived from CLERK_SECRET_KEY,
	// and that is fine for what Mode()/IsSaaS()/IsSelfHosted() are used for —
	// whether billing and the provider webhooks are active. It is NOT the
	// authentication decision. AnonymousAuthAllowed() reads only
	// SBOMHUB_AUTH_MODE, and ValidateAuthMode() is what refuses a declaration
	// that disagrees with this derivation.
	//
	// Load() therefore does NOT by itself establish a safe ENVIRONMENT AND
	// AUTHENTICATION decision: it returns whatever the environment says.
	// cmd/server/main.go calls ValidateRetiredEnv, ValidateEnvironment and
	// ValidateAuthMode before anything is wired, and any other consumer must
	// do the same. Those three settle the environment and the auth mode only —
	// a deployment is additionally subject to Config.Validate (encryption key)
	// and to the guards that live in cmd/server/main.go
	// (validateEncryptionKey, validateWebhookVerification,
	// assertAppRoleNotBypassRLS), which this package cannot enforce.
	if cfg.ClerkSecretKey != "" {
		cfg.mode = ModeSaaS
	} else {
		cfg.mode = ModeSelfHosted
	}

	return cfg
}

// Mode returns the current deployment mode
func (c *Config) Mode() Mode {
	return c.mode
}

// IsSaaS returns true if running in SaaS mode
func (c *Config) IsSaaS() bool {
	return c.mode == ModeSaaS
}

// IsSelfHosted returns true if running in self-hosted mode
func (c *Config) IsSelfHosted() bool {
	return c.mode == ModeSelfHosted
}

// IsAuthEnabled returns true if authentication is enabled (Clerk configured)
func (c *Config) IsAuthEnabled() bool {
	return c.ClerkSecretKey != ""
}

// IsBillingEnabled returns true if billing is enabled (Lemon Squeezy configured)
func (c *Config) IsBillingEnabled() bool {
	return c.LemonSqueezyAPIKey != ""
}

// KnownEnvironments is the closed set of values APP_ENV (or the legacy
// ENVIRONMENT) may hold. It is closed on purpose: every guard in this codebase
// branches on IsDevelopment() or IsProduction(), so a value that is neither —
// "prod", "Production", "dev", "" — used to land the process in a state no
// guard was written for. See ValidateEnvironment.
var KnownEnvironments = []string{"development", "staging", "production"}

// ValidateEnvironment reports whether APP_ENV names an environment this
// codebase actually has rules for.
//
// M48 (FO-4). Two things were wrong before, and they are the same thing:
//
//   - UNSET resolved to "development", the weakest setting the process has.
//     "The operator configured nothing" is the one case where we know least
//     about the deployment, and it was being read as a positive assertion
//     that this is a laptop.
//   - A TYPO ("prod", "PRODUCTION") satisfied neither IsProduction() nor
//     IsDevelopment(). That direction is mostly strict — the main.go guards
//     hard-fail — but it is strict by accident rather than by decision, and
//     Validate()'s IsProduction()-only checks did not fire, so an all-zeros
//     ENCRYPTION_KEY was accepted under APP_ENV=prod.
//
// Rejecting both is what lets every other guard read IsDevelopment() as a
// deliberate operator statement rather than as a default.
//
// This is a startup-time check (cmd/server/main.go validateAppEnv), not a
// request-time one; nothing in the request path consults it.
func (c *Config) ValidateEnvironment() error {
	for _, known := range KnownEnvironments {
		if c.Environment == known {
			return nil
		}
	}
	if c.Environment == "" {
		return fmt.Errorf(
			"APP_ENV が未設定です。 デプロイ環境を明示してください: %s "+
				"(例: 開発マシンでは APP_ENV=development)。 "+
				"未設定を development として扱う既定は M48 で廃止しました — "+
				"設定漏れと「開発環境である」という宣言は区別されます",
			strings.Join(KnownEnvironments, " | "))
	}
	return fmt.Errorf(
		"APP_ENV=%q は未知の値です。 使用できるのは %s のみです "+
			"(起動ガードはこの 3 値でしか分岐しないため、それ以外は "+
			"どのルールが適用されるか定義されていません)",
		c.Environment, strings.Join(KnownEnvironments, " | "))
}

// SaaSSignals returns the names of the environment variables that are set and
// only make sense in SaaS mode. It is the evidence used by
// cmd/server/main.go validateAuthMode to tell "this operator meant to run
// self-hosted" apart from "this operator meant to run SaaS and CLERK_SECRET_KEY
// did not arrive".
//
// CLERK_SECRET_KEY itself is deliberately absent: it is the variable whose
// absence selects self-hosted mode, so it can never be a signal here.
//
// The returned names are variable names only — never values — because callers
// log them.
func (c *Config) SaaSSignals() []string {
	var set []string
	for _, s := range []struct {
		name  string
		value string
	}{
		{"CLERK_WEBHOOK_SECRET", c.ClerkWebhookSecret},
		{"LEMONSQUEEZY_API_KEY", c.LemonSqueezyAPIKey},
		{"LEMONSQUEEZY_WEBHOOK_SECRET", c.LemonSqueezyWebhookSecret},
		{"LEMONSQUEEZY_STORE_ID", c.LemonSqueezyStoreID},
		{"LEMONSQUEEZY_STARTER_VARIANT_ID", c.LemonSqueezyStarterVariant},
		{"LEMONSQUEEZY_PRO_VARIANT_ID", c.LemonSqueezyProVariant},
		{"LEMONSQUEEZY_TEAM_VARIANT_ID", c.LemonSqueezyTeamVariant},
	} {
		if s.value != "" {
			set = append(set, s.name)
		}
	}
	return set
}

// AuthMode values for SBOMHUB_AUTH_MODE.
const (
	AuthModeClerk     = "clerk"
	AuthModeAnonymous = "anonymous"
)

// KnownAuthModes is the closed set SBOMHUB_AUTH_MODE may hold. Like
// KnownEnvironments it is closed on purpose: an unrecognised value must be a
// refusal, never a fall-through to the more permissive arm.
var KnownAuthModes = []string{AuthModeClerk, AuthModeAnonymous}

// retiredAnonymousAuthFlag is the boolean opt-in M48 used before settling on a
// required declaration. It is refused rather than ignored so an operator who
// followed an intermediate draft is told their setting no longer applies,
// instead of silently ending up with an unconfigured deployment.
const retiredAnonymousAuthFlag = "SBOMHUB_ALLOW_ANONYMOUS_AUTH"

// AnonymousAuthAllowed reports whether this process may serve requests with no
// credential at all — the self-host posture in which every caller on the
// Clerk-fronted route groups is Owner of the default tenant
// (middleware.handleSelfHostedAuth).
//
// It reads ONLY the declaration. Nothing is inferred from the presence or
// absence of a secret, which is the entire point of M48's third iteration:
// inference is what made a SaaS deployment with a failed secret injection
// indistinguishable from a self-hosted one. See the AuthMode field comment.
//
// It says nothing about whether the process SHOULD start — that decision, and
// the refusal, live in ValidateAuthMode / cmd/server/main.go. This predicate
// exists so the rule has one spelling that tests and the guard share.
func (c *Config) AnonymousAuthAllowed() bool {
	return c.AuthMode == AuthModeAnonymous
}

// ValidateAuthMode checks the REQUIRED SBOMHUB_AUTH_MODE declaration against
// the mode actually derived from CLERK_SECRET_KEY. Both directions are
// refusals, and so is an absent or unrecognised declaration.
//
// The `clerk` arm is the one that earns the whole variable. Nothing else in
// this codebase can distinguish "self-hosted" from "SaaS whose secret
// injection failed entirely", because in the second case there is nothing left
// to notice — no Clerk key, no webhook secret, no billing key. A declaration
// lives in the deployment manifest rather than the secret store, so it
// survives the failure that removed them, and turns it into a boot failure
// instead of an unauthenticated API.
func (c *Config) ValidateAuthMode() error {
	switch c.AuthMode {
	case AuthModeClerk:
		if c.ClerkSecretKey == "" {
			return fmt.Errorf(
				"SBOMHUB_AUTH_MODE=clerk と宣言されていますが CLERK_SECRET_KEY が空です。 " +
					"シークレット注入が失敗している可能性があります。 " +
					"このまま起動すると認証なし (Clerk 前提の route group が Owner 扱い) に " +
					"なるため拒否します")
		}
		return nil
	case AuthModeAnonymous:
		if c.ClerkSecretKey != "" {
			return fmt.Errorf(
				"SBOMHUB_AUTH_MODE=anonymous と宣言されていますが CLERK_SECRET_KEY が設定されています。 " +
					"宣言と実際の構成が矛盾しています。 Clerk 認証で運用するなら " +
					"SBOMHUB_AUTH_MODE=clerk に変更してください")
		}
		return nil
	case "":
		return fmt.Errorf(
			"SBOMHUB_AUTH_MODE が未設定です。 認証モードを明示してください: %s。 "+
				"CLERK_SECRET_KEY の有無からの推論は M48 で廃止しました — "+
				"シークレット注入が完全に失敗した SaaS デプロイと、 意図した自己ホスト構成は、 "+
				"推論では区別できないためです "+
				"(自己ホスト = 認証なしなら SBOMHUB_AUTH_MODE=anonymous)",
			strings.Join(KnownAuthModes, " | "))
	default:
		return fmt.Errorf(
			"SBOMHUB_AUTH_MODE=%q は未知の値です。 使用できるのは %s のみです",
			c.AuthMode, strings.Join(KnownAuthModes, " | "))
	}
}

// ValidateRetiredEnv refuses environment variables that an intermediate draft
// of M48 introduced and the final design removed. Ignoring them silently would
// leave an operator believing a setting is in force when it is not — and in
// this particular case, believing they had acknowledged the anonymous posture
// when the deployment had in fact declared nothing.
func (c *Config) ValidateRetiredEnv() error {
	// Codex round 4 (Low) proposed refusing PRESENCE, i.e. LookupEnv, on the
	// grounds that `SBOMHUB_ALLOW_ANONYMOUS_AUTH=` is still an operator
	// believing they configured something. Refusing an empty value outright is
	// too blunt: this repository's own .env.example carries several empty
	// placeholders (NVD_API_KEY=, CLERK_SECRET_KEY=, ...), so an empty
	// leftover is far more likely to be a harmless remnant than a belief — and
	// an EMPTY value never expressed the acknowledgement anyway, since only
	// `true` did.
	//
	// So: a non-empty value is a refusal, and a present-but-empty one is a
	// warning that names the replacement. The operator is told either way,
	// which was the point, without a boot failure for a blank line.
	if raw, present := os.LookupEnv(retiredAnonymousAuthFlag); present && raw == "" {
		slog.Warn("SBOMHUB_ALLOW_ANONYMOUS_AUTH is present but empty. The variable was retired "+
			"before release and is no longer read; SBOMHUB_AUTH_MODE is what declares the "+
			"authentication mode now. The line can be deleted.",
			"replacement", "SBOMHUB_AUTH_MODE")
	}
	if os.Getenv(retiredAnonymousAuthFlag) != "" {
		return fmt.Errorf(
			"%s は廃止されました。 SBOMHUB_AUTH_MODE=anonymous に置き換えてください "+
				"(boolean のフラグでは、 Clerk 構成でシークレット注入が完全に失敗した際に "+
				"匿名モードを承認してしまう経路を塞げなかったため)",
			retiredAnonymousAuthFlag)
	}
	return nil
}

// IsProduction returns true if running in production environment
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// IsDevelopment returns true if running in the development environment.
// This is the single source of truth for the "warn instead of hard-fail"
// downgrade applied to Trust Rescue startup guards
// (validateEncryptionKey / assertAppRoleNotBypassRLS in cmd/server/main.go).
//
// It is deliberately NOT consulted by AnonymousAuthAllowed: the anonymous-auth
// acknowledgement is required in every environment (Codex round 2, High).
//
// M48 (FO-4): this is now true only when the operator SPELLED
// APP_ENV=development. It is no longer reachable by leaving APP_ENV unset —
// config.Load substitutes nothing, and ValidateEnvironment refuses an unset
// or unrecognised value at startup. Every downgrade keyed on this predicate
// therefore requires a positive statement from the deployment.
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// UnsignedWebhooksAllowed reports whether a webhook receiver with NO secret
// configured may skip signature verification. It is the single source of
// truth shared by the Clerk and Lemon Squeezy receivers.
//
// Both conditions are required: the operator asked for it by name
// (SBOMHUB_ALLOW_UNSIGNED_WEBHOOKS) AND the process is running in
// DEVELOPMENT specifically.
//
// It checks IsDevelopment(), not !IsProduction() (Codex round 3, Low): the
// latter also admits staging and every typo of "production", which is the
// opposite of the fail-closed posture this flag exists inside.
//
// M48 (FO-4) narrowed this further without touching the expression: APP_ENV
// unset no longer resolves to "development", so the bypass now requires the
// local flow to spell APP_ENV=development as well as setting the flag. That
// is the same statement the server already demands to boot at all
// (ValidateEnvironment), so it costs a local developer nothing beyond the
// .env line that .env.example already ships.
//
// The environment term is deliberately redundant with the startup guard in
// cmd/server/main.go, so the runtime decision does not depend on that guard
// having run (tests construct a Config directly; so could a future embedding
// of this package).
//
// Callers must consult this ONLY when their secret is empty. A configured
// secret is always verified.
func (c *Config) UnsignedWebhooksAllowed() bool {
	return c.AllowUnsignedWebhooks && c.IsDevelopment()
}

// IsEmailEnabled returns true if email notifications are configured
func (c *Config) IsEmailEnabled() bool {
	return c.SMTPHost != "" && c.SMTPFrom != ""
}

// Validate checks for security-critical configuration errors
// Returns an error if the configuration is insecure for the current environment
//
// M48 (FO-4): the three checks below used to fire only under IsProduction(),
// while the equivalent startup guard in cmd/server/main.go
// (validateEncryptionKey) downgrades only under IsDevelopment(). The gap
// between the two predicates is staging — and, before ValidateEnvironment, any
// typo of "production". The observed consequence: main.go's denylist does not
// contain "00000000000000000000000000000000", so under APP_ENV=staging that
// key passed validateEncryptionKey and then passed here too, because this
// function only objects in production. The predicate is now IsDevelopment(),
// matching main.go, so development is the only environment that relaxes
// anything.
//
// The two denylists are still separate (main.go's covers placeholder strings
// and previously-bundled defaults; this one covers degenerate keys). Neither
// is a superset of the other, which is why both run.
func (c *Config) Validate() error {
	// SECURITY: Encryption key validation
	if c.EncryptionKey == "" {
		if !c.IsDevelopment() {
			return fmt.Errorf("ENCRYPTION_KEY must be set outside development (APP_ENV=%q)", c.Environment)
		}
		// Use a development-only default key (this is logged as a warning)
		c.EncryptionKey = "dev-only-insecure-key-32bytes!!"
	}

	// SECURITY: Key length validation - AES-256 requires exactly 32 bytes
	if len(c.EncryptionKey) < 32 {
		if !c.IsDevelopment() {
			return fmt.Errorf("ENCRYPTION_KEY must be at least 32 bytes for AES-256 (got %d bytes)", len(c.EncryptionKey))
		}
	}

	// SECURITY: Warn about weak keys that look like defaults
	weakKeys := []string{
		"sbomhub-default-encryption-key-32",
		"dev-only-insecure-key-32bytes!!",
		"00000000000000000000000000000000",
		"11111111111111111111111111111111",
	}
	for _, weak := range weakKeys {
		if c.EncryptionKey == weak && !c.IsDevelopment() {
			return fmt.Errorf("ENCRYPTION_KEY appears to be a default/weak key - please use a cryptographically random key outside development (APP_ENV=%q)", c.Environment)
		}
	}

	return nil
}

// GetEncryptionKey returns the encryption key as a 32-byte slice for AES-256
// SECURITY: This method ensures proper key length without silent zero-padding
func (c *Config) GetEncryptionKey() ([]byte, error) {
	if len(c.EncryptionKey) < 32 {
		return nil, fmt.Errorf("encryption key too short: need 32 bytes, got %d", len(c.EncryptionKey))
	}
	// Use first 32 bytes if key is longer
	return []byte(c.EncryptionKey)[:32], nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBool reads a boolean env var. Accepts 1/true/yes/on (case-insensitive)
// as true and 0/false/no/off as false; any other value (including unset/empty)
// falls back to defaultValue.
//
// Every caller currently passes false, which unparam flags once there are
// enough call sites to be confident about (M50 added the third and tripped it).
// The parameter stays: for a security-relevant switch, the point of writing the
// default at the CALL SITE is that a reviewer reading
// `getEnvBool("SBOMHUB_EGRESS_ALLOW_PRIVATE", false)` can see the fail-closed
// default without navigating to this function. Collapsing it into the helper
// name would move that fact away from where it is read.
//
//nolint:unparam // the explicit default is the reviewable part; see above
func getEnvBool(key string, defaultValue bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}
