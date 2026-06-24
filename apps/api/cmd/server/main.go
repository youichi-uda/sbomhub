package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/handler"
	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/redis"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/scheduler"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
	"github.com/sbomhub/sbomhub/migrations"
)

// newVexDraftsStore returns the concrete vex_drafts store wired
// against the runtime DB pool. Agent A's *repository.VEXDraftsRepository
// satisfies triage.VexDraftStore by construction (matching method set).
func newVexDraftsStore(db *sql.DB) triage.VexDraftStore {
	return repository.NewVEXDraftsRepository(db)
}


// knownDefaultEncryptionKeys enumerates placeholder values that must never be
// used outside development. The list includes:
//   - generic placeholders found in tutorials / sample configs (changeme,
//     default, test, your-encryption-key-here)
//   - keys we historically bundled in docker-compose.yml or config defaults
//     (P0 #5 / Trust Rescue 9.2.1, removed alongside this guard)
//
// Anything matching one of these is treated as if no key were set at all.
var knownDefaultEncryptionKeys = []string{
	"changeme",
	"change-me",
	"default",
	"test",
	"your-encryption-key-here",
	// Previously bundled defaults — kept in the denylist so any operator that
	// copy-pasted them is hard-failed.
	"V5jgaCSCV/Mdf8JbVX42aWYAB6dG1Dp9G9Bo0Nw+qjY=",
	"sbomhub-default-encryption-key-32",
	"dev-only-insecure-key-32bytes!!",
}

// validateEncryptionKey enforces P0 #7 / Trust Rescue 9.2.3: refuse to start
// when ENCRYPTION_KEY is unset, a known default placeholder, or shorter than
// 32 bytes (AES-256 needs 32 bytes). Only the development environment
// downgrades a violation to a warning so contributors can run locally without
// a key.
//
// It reads cfg.EncryptionKey / cfg.Environment so this guard agrees with the
// rest of config (post codex-r18 APP_ENV → ENVIRONMENT precedence) and matches
// the cfg-driven contract of assertAppRoleNotBypassRLS — both guards now share
// a single source of truth for environment classification.
func validateEncryptionKey(cfg *config.Config) error {
	rawKey := cfg.EncryptionKey
	appEnv := cfg.Environment

	var reason string
	switch {
	case rawKey == "":
		reason = "未設定"
	case len(rawKey) < 32:
		reason = fmt.Sprintf("長さ不足 (got %d bytes, need >= 32)", len(rawKey))
	default:
		for _, d := range knownDefaultEncryptionKeys {
			if rawKey == d {
				reason = "既知デフォルト値"
				break
			}
		}
	}

	if reason == "" {
		slog.Info("ENCRYPTION_KEY check passed",
			"length", len(rawKey), "app_env", appEnv)
		return nil
	}

	if appEnv == "development" {
		slog.Warn("ENCRYPTION_KEY is unsafe — DO NOT deploy this way. "+
			"Generate a real key with: openssl rand -base64 32",
			"reason", reason, "app_env", appEnv)
		return nil
	}

	return fmt.Errorf(
		"ENCRYPTION_KEY が未設定または既知デフォルトです (%s)。 "+
			"`openssl rand -base64 32` で生成して .env / 環境変数に設定してください "+
			"(APP_ENV=%q)",
		reason, appEnv,
	)
}

// assertAppRoleNotBypassRLS verifies that the runtime DB role does not have
// the BYPASSRLS attribute. In development we log a warning so contributors
// can keep running against a single-role local DB while they migrate;
// everywhere else (production / staging / unset) we hard-fail.
//
// Environment classification comes from cfg.IsDevelopment() so the
// APP_ENV → ENVIRONMENT precedence resolved by config.Load (codex-r18)
// is the single source of truth — see validateEncryptionKey for the
// matching contract.
func assertAppRoleNotBypassRLS(db *sql.DB, cfg *config.Config) error {
	var bypass bool
	var role string
	if err := db.QueryRow(
		`SELECT current_user, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&role, &bypass); err != nil {
		return fmt.Errorf("failed to query rolbypassrls for current_user: %w", err)
	}
	if !bypass {
		slog.Info("DB role check passed", "role", role, "bypass_rls", false)
		return nil
	}
	if cfg.IsDevelopment() {
		slog.Warn("DB role has BYPASSRLS — tenant isolation is NOT enforced. "+
			"Switch DATABASE_URL to the sbomhub_app role before deploying.",
			"role", role, "app_env", cfg.Environment)
		return nil
	}
	return fmt.Errorf(
		"RLS bypass 権限を持つロールでの起動は禁止です。 sbomhub_app ロールを使用してください "+
			"(current_user=%s, rolbypassrls=true, APP_ENV=%q)",
		role, cfg.Environment,
	)
}

func main() {
	// Load .env file if it exists (for local development)
	_ = godotenv.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	// SECURITY (P0 #7 / Trust Rescue 9.2.3): refuse to start when
	// ENCRYPTION_KEY is unset, a known default placeholder, or under 32 bytes.
	// cfg.EncryptionKey is the raw value loaded from ENCRYPTION_KEY (no default
	// is filled in for it inside config.Load — Validate handles the dev-only
	// fallback after this guard runs), and cfg.Environment honours the codex-r18
	// APP_ENV → ENVIRONMENT precedence so the gate agrees with cfg.IsProduction.
	if err := validateEncryptionKey(cfg); err != nil {
		slog.Error("Refusing to start", "error", err)
		os.Exit(1)
	}

	// SECURITY: Validate configuration before starting
	if err := cfg.Validate(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}

	// SECURITY (P0 #2 / Trust Rescue 9.1.1): Migrations and runtime use
	// distinct DB roles. We open a short-lived migrator connection here, run
	// DDL, then close it. The long-lived runtime connection below uses the
	// non-superuser, NOBYPASSRLS app role.
	migrateURL := os.Getenv("MIGRATE_DATABASE_URL")
	if migrateURL == "" {
		slog.Warn("MIGRATE_DATABASE_URL is not set; falling back to DATABASE_URL for auto-migrations. " +
			"Set MIGRATE_DATABASE_URL to a sbomhub_migrator connection string for proper role separation.")
		migrateURL = cfg.DatabaseURL
	}
	migrateDB, err := database.Connect(migrateURL)
	if err != nil {
		slog.Error("Failed to connect to database for migrations", "error", err)
		os.Exit(1)
	}
	if err := database.Migrate(migrateDB, migrations.FS); err != nil {
		_ = migrateDB.Close()
		slog.Error("Failed to run migrations", "error", err)
		os.Exit(1)
	}
	_ = migrateDB.Close()

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// SECURITY (P0 #2 / Trust Rescue 9.1.1): refuse to serve traffic on a
	// DB role that bypasses Row-Level Security. RLS policies are how we
	// enforce tenant isolation, so a BYPASSRLS runtime role silently breaks
	// the entire multi-tenant boundary.
	if err := assertAppRoleNotBypassRLS(db, cfg); err != nil {
		slog.Error("Refusing to start", "error", err)
		os.Exit(1)
	}

	rdb, err := redis.NewClient(cfg.RedisURL)
	if err != nil {
		slog.Error("Failed to connect to redis", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Initialize Clerk SDK with secret key (required for JWT verification)
	slog.Info("Clerk config check", "secret_key_set", cfg.ClerkSecretKey != "", "secret_key_length", len(cfg.ClerkSecretKey))
	if cfg.ClerkSecretKey != "" {
		clerk.SetKey(cfg.ClerkSecretKey)
		slog.Info("Clerk SDK initialized")
	} else {
		slog.Warn("Clerk secret key not set - running in self-hosted mode")
	}

	// Log startup mode
	slog.Info("Starting SBOMHub", "mode", cfg.Mode(), "auth_enabled", cfg.IsAuthEnabled(), "billing_enabled", cfg.IsBillingEnabled())

	// Repositories
	projectRepo := repository.NewProjectRepository(db)
	sbomRepo := repository.NewSbomRepository(db)
	componentRepo := repository.NewComponentRepository(db)
	vulnRepo := repository.NewVulnerabilityRepository(db)
	statsRepo := repository.NewStatsRepository(db)
	vexRepo := repository.NewVEXRepository(db)
	licensePolicyRepo := repository.NewLicensePolicyRepository(db)
	apiKeyRepo := repository.NewAPIKeyRepository(db)
	dashboardRepo := repository.NewDashboardRepository(db)
	searchRepo := repository.NewSearchRepository(db)
	notificationRepo := repository.NewNotificationRepository(db)
	publicLinkRepo := repository.NewPublicLinkRepository(db)

	// METI Compliance Repositories
	checklistRepo := repository.NewChecklistRepository(db)
	visualizationRepo := repository.NewVisualizationRepository(db)

	// SaaS Repositories
	tenantRepo := repository.NewTenantRepository(db)
	userRepo := repository.NewUserRepository(db)
	subscriptionRepo := repository.NewSubscriptionRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	analyticsRepo := repository.NewAnalyticsRepository(db)
	reportRepo := repository.NewReportRepository(db)
	ipaRepo := repository.NewIPARepository(db)
	issueTrackerRepo := repository.NewIssueTrackerRepository(db)
	kevRepo := repository.NewKEVRepository(db)
	ssvcRepo := repository.NewSSVCRepository(db)
	eolRepo := repository.NewEOLRepository(db)

	// BYOK LLM provider config (issue #22). Stores per-tenant provider
	// selection and an AES-256-GCM encrypted API key. Surface via
	// /api/v1/settings/llm.
	tenantLLMConfigRepo := repository.NewTenantLLMConfigRepository(db)

	// AI VEX triage inputs (Wave M1-1..M1-3 / issue #30).
	// Pre-existing repositories wired through the triage runner below.
	advisoryExcerptsRepo := repository.NewAdvisoryExcerptsRepository(db)
	reachabilityResultsRepo := repository.NewReachabilityResultsRepository(db)
	llmCallsRepo := repository.NewLLMCallsRepository(db)

	// NVD Cache for vulnerability scanning
	nvdCache := cache.NewNVDCache(rdb)

	// Services
	projectService := service.NewProjectService(projectRepo)
	sbomService := service.NewSbomService(sbomRepo, componentRepo)
	sbomDiffService := service.NewSbomDiffService(sbomRepo, componentRepo)
	nvdService := service.NewNVDServiceWithCache(vulnRepo, componentRepo, cfg.NVDAPIKey, nvdCache)
	jvnService := service.NewJVNService(vulnRepo, componentRepo)
	statsService := service.NewStatsService(statsRepo)
	vexService := service.NewVEXService(vexRepo, vulnRepo)
	licensePolicyService := service.NewLicensePolicyService(licensePolicyRepo, componentRepo)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo)
	dashboardService := service.NewDashboardService(dashboardRepo)
	searchService := service.NewSearchServiceWithNVD(searchRepo, nvdService)
	epssService := service.NewEPSSService(vulnRepo)
	notificationService := service.NewNotificationService(notificationRepo, projectRepo, cfg)
	complianceService := service.NewComplianceServiceFull(sbomRepo, componentRepo, vulnRepo, vexRepo, licensePolicyRepo, dashboardRepo, checklistRepo, visualizationRepo, publicLinkRepo)
	publicLinkService := service.NewPublicLinkService(db, publicLinkRepo, projectRepo, sbomRepo, componentRepo)
	auditService := service.NewAuditService(auditRepo, userRepo)
	analyticsService := service.NewAnalyticsService(analyticsRepo, dashboardRepo)
	reportService := service.NewReportService(reportRepo, dashboardRepo, analyticsRepo, tenantRepo, checklistRepo, visualizationRepo, "./reports")
	ipaService := service.NewIPAService(ipaRepo)
	encryptionKey, err := cfg.GetEncryptionKey()
	if err != nil {
		slog.Error("Failed to get encryption key", "error", err)
		os.Exit(1)
	}
	// SECURITY: In SaaS mode, restrict issue tracker URLs to known domains to prevent SSRF
	var issueTrackerAllowedDomains []string
	if cfg.IsSaaS() {
		issueTrackerAllowedDomains = service.AllowedIssueTrackerDomains
		slog.Info("Issue tracker SSRF protection enabled", "allowed_domains", issueTrackerAllowedDomains)
	}
	issueTrackerService := service.NewIssueTrackerService(issueTrackerRepo, vulnRepo, encryptionKey, issueTrackerAllowedDomains)
	remediationService := service.NewRemediationService(vulnRepo, componentRepo)
	kevService := service.NewKEVService(kevRepo)
	ssvcService := service.NewSSVCService(ssvcRepo, vulnRepo, kevRepo)
	eolService := service.NewEOLService(eolRepo)

	// In-memory tracker for background SBOM scans. Observed by
	// GET /api/v1/projects/:id/sboms/:sbom_id/scan-status so the CLI
	// (`sbomhub scan --fail-on <severity>`) can block until scanning
	// completes and then enforce the threshold. Trust Rescue P1 #12.
	scanTracker := service.NewScanTracker()

	// AI VEX triage runner (issue #30 / Wave M1-5). Composes the four
	// input repositories above with the BYOK LLM provider and the
	// guards layer (#29 / agent C).
	//
	// Provider resolution (M1 Codex review #F2): per-request resolver
	// reads tenant_llm_config and decrypts the BYOK key when set; falls
	// back to the env-resolved default (NewProviderFromEnv) for tenants
	// without their own row; final fallback is DisabledProvider which
	// triggers the under_investigation draft path (#F4).
	triageDefaultProvider, err := llm.NewProviderFromEnv(context.Background())
	if err != nil {
		slog.Error("Failed to initialise LLM provider", "error", err)
		os.Exit(1)
	}
	triageProviderResolver := func(ctx context.Context, tenantID uuid.UUID) (llm.Provider, error) {
		cfg, err := tenantLLMConfigRepo.Get(ctx, tenantID)
		if errors.Is(err, repository.ErrTenantLLMConfigNotFound) {
			// Tenant has not configured BYOK — fall back to env default.
			return triageDefaultProvider, nil
		}
		if err != nil {
			return nil, fmt.Errorf("load tenant_llm_config: %w", err)
		}
		// Ollama (M4) has no API key. For everything else, a missing key
		// means "BYOK configured but incomplete" — fall back to env so
		// the runner's #F4 ai_disabled path only fires when BOTH are
		// missing.
		needsKey := strings.ToLower(strings.TrimSpace(cfg.Provider)) != "ollama"
		if needsKey && !cfg.HasAPIKey() {
			return triageDefaultProvider, nil
		}
		var apiKey string
		if cfg.HasAPIKey() {
			plaintext, decErr := llm.Decrypt(cfg.EncryptedAPIKey, encryptionKey)
			if decErr != nil {
				return nil, fmt.Errorf("decrypt tenant llm key: %w", decErr)
			}
			apiKey = string(plaintext)
			// Best-effort: zero the plaintext buffer once we've handed
			// the string to the provider. (Go strings are immutable, so
			// once apiKey is built the byte slice can be wiped.)
			for i := range plaintext {
				plaintext[i] = 0
			}
		}
		p, perr := llm.NewProviderFromConfig(cfg.Provider, cfg.Model, apiKey)
		if perr != nil {
			return nil, fmt.Errorf("build tenant provider: %w", perr)
		}
		return p, nil
	}
	triageRunner := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   newVexDraftsStore(db),
		Advisories:               &triage.AdvisoryExcerptsAdapter{Repo: advisoryExcerptsRepo},
		Reachability:             &triage.ReachabilityAdapter{Repo: reachabilityResultsRepo},
		LLMCalls:                 &triage.LLMCallsAdapter{Repo: llmCallsRepo},
		Audit:                    auditRepo,
		VEXSync:                  &triage.VEXServiceAdapter{Service: vexService},
		ComponentVulnerabilities: componentRepo,
		Provider:                 triageDefaultProvider,
		ProviderResolver:         triageProviderResolver,
		Threshold:                triage.ConfidenceThresholdFromEnv(),
	})
	slog.Info("AI VEX triage runner initialised",
		"default_provider", triageDefaultProvider.Name(),
		"threshold", triage.ConfidenceThresholdFromEnv(),
		"per_tenant_resolver", "tenant_llm_config")

	// Handlers
	projectHandler := handler.NewProjectHandler(projectService)
	// NewSbomHandler needs `db` so the post-upload background scan goroutine
	// can open its own tx with `SET LOCAL app.current_tenant_id` bound —
	// the request's TenantTx has already committed by the time the
	// goroutine starts. Codex R1 fix.
	sbomHandler := handler.NewSbomHandler(db, sbomService, nvdService, jvnService, scanTracker)
	sbomDiffHandler := handler.NewSbomDiffHandler(sbomDiffService)
	vulnHandler := handler.NewVulnerabilityHandler(nvdService, jvnService)
	statsHandler := handler.NewStatsHandler(statsService)
	vexHandler := handler.NewVEXHandler(vexService)
	licensePolicyHandler := handler.NewLicensePolicyHandler(licensePolicyService)
	apiKeyHandler := handler.NewAPIKeyHandler(apiKeyService)
	dashboardHandler := handler.NewDashboardHandler(dashboardService)
	searchHandler := handler.NewSearchHandler(searchService)
	epssHandler := handler.NewEPSSHandler(epssService)
	notificationHandler := handler.NewNotificationHandler(notificationService)
	complianceHandler := handler.NewComplianceHandler(complianceService)
	publicLinkHandler := handler.NewPublicLinkHandler(publicLinkService)

	// AI VEX triage handler (issue #30).
	vexDraftsHandler := handler.NewVexDraftsHandler(triageRunner)

	// SaaS Handlers
	clerkWebhookHandler := handler.NewClerkWebhookHandler(cfg, tenantRepo, userRepo, auditRepo)
	lsWebhookHandler := handler.NewLemonSqueezyWebhookHandler(cfg, tenantRepo, subscriptionRepo, auditRepo)
	billingHandler := handler.NewBillingHandler(cfg, tenantRepo, subscriptionRepo)
	auditHandler := handler.NewAuditHandler(auditService)
	analyticsHandler := handler.NewAnalyticsHandler(analyticsService)
	reportHandler := handler.NewReportHandler(reportService)
	ipaHandler := handler.NewIPAHandler(ipaService)
	issueTrackerHandler := handler.NewIssueTrackerHandler(issueTrackerService)
	remediationHandler := handler.NewRemediationHandler(remediationService)
	kevHandler := handler.NewKEVHandler(kevService)
	ssvcHandler := handler.NewSSVCHandler(ssvcService)
	eolHandler := handler.NewEOLHandler(eolService)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// SECURITY: Limit request body size to prevent memory exhaustion DoS attacks
	// 10MB should be sufficient for most SBOM files while preventing abuse
	e.Use(middleware.BodyLimit("10M"))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:  []string{"http://localhost:3000", "http://localhost:13000", "http://localhost:*", "https://sbomhub.app"},
		AllowMethods:  []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders:  []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Clerk-Org-ID"},
		ExposeHeaders: []string{echo.HeaderContentDisposition, echo.HeaderContentLength, echo.HeaderContentType},
	}))

	// Webhook endpoints (no auth required)
	e.POST("/api/webhooks/clerk", clerkWebhookHandler.Handle)
	e.POST("/api/webhooks/lemonsqueezy", lsWebhookHandler.Handle)

	api := e.Group("/api/v1")

	// Public endpoints (no auth)
	api.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{
			"status": "ok",
			"mode":   string(cfg.Mode()),
		})
	})
	api.GET("/public/:token", publicLinkHandler.PublicGet)
	api.GET("/public/:token/download", publicLinkHandler.PublicDownload)

	// MCP endpoints (API key auth)
	// Trust Rescue 9.1.2 (#3): TenantTx is wedged in between the auth pair
	// (APIKeyAuth + APIKeyTenant) and the rest of the chain so every MCP
	// request runs inside a single Postgres transaction with
	// `SET LOCAL app.current_tenant_id` bound. The MCPAudit middleware runs
	// inside that tx, which means its audit_logs insert (RLS-enforced)
	// sees the GUC; rollback on failure also rolls back the audit record —
	// see TenantTx godoc for the trade-off rationale.
	mcp := api.Group("/mcp",
		appmw.APIKeyAuth(apiKeyService),
		appmw.APIKeyTenant(projectRepo, tenantRepo),
		appmw.TenantTx(db),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.MCPAudit(auditRepo),
	)

	mcp.GET("/projects", projectHandler.List)
	mcp.GET("/dashboard/summary", dashboardHandler.GetSummary)
	mcp.GET("/search/cve", searchHandler.SearchByCVE)
	mcp.GET("/search/component", searchHandler.SearchByComponent)
	mcp.POST("/sbom/diff", sbomDiffHandler.Diff)
	mcp.GET("/projects/:id/vulnerabilities", sbomHandler.GetVulnerabilities)
	mcp.GET("/projects/:id/compliance", complianceHandler.Check)
	mcp.GET("/projects/:id/sboms", sbomHandler.List)

	// CLI Service and Handler
	cliService := service.NewCLIService(projectRepo, sbomRepo, componentRepo)
	cliHandler := handler.NewCLIHandler(cliService)

	// CLI endpoints (API key auth)
	// Trust Rescue 9.1.2 (#3): TenantTx wraps the rest of the chain so
	// rate limit / audit / handler all share the same per-request tx with
	// `SET LOCAL app.current_tenant_id` bound.
	cli := api.Group("/cli",
		appmw.APIKeyAuth(apiKeyService),
		appmw.APIKeyTenant(projectRepo, tenantRepo),
		appmw.TenantTx(db),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.MCPAudit(auditRepo),
	)
	cli.POST("/upload", cliHandler.Upload)
	cli.POST("/check", cliHandler.Check)
	cli.GET("/projects", cliHandler.ListProjects)
	cli.GET("/projects/:id", cliHandler.GetProject)
	cli.POST("/projects", cliHandler.CreateProject)

	// Auth middleware - applies to most endpoints
	authMiddleware := appmw.Auth(cfg, tenantRepo, userRepo)

	// Audit middleware - logs all authenticated requests
	auditMiddleware := appmw.Audit(auditRepo)

	// Authenticated endpoints with audit logging.
	// Trust Rescue 9.1.2 (#3): TenantTx slots between Auth (which populates
	// ContextKeyTenantID) and the audit middleware so every request in this
	// group runs in a single tx with `SET LOCAL app.current_tenant_id`
	// bound. Audit writes hit audit_logs inside that same tx, which is
	// required because audit_logs is FORCE ROW LEVEL SECURITY (migration
	// 023). The trade-off — audit records for failed/4xx requests get
	// rolled back along with the rest of the request — is documented in
	// TenantTx's godoc and flagged in the Trust Rescue follow-up list.
	auth := api.Group("", authMiddleware, appmw.TenantTx(db), auditMiddleware)

	auth.GET("/stats", statsHandler.Get)

	// Billing endpoints
	auth.GET("/subscription", billingHandler.GetSubscription)
	auth.POST("/subscription/checkout", billingHandler.CreateCheckout)
	auth.GET("/subscription/portal", billingHandler.GetPortalURL)
	auth.POST("/subscription/sync", billingHandler.SyncSubscription)
	auth.GET("/plan/usage", billingHandler.GetUsage)
	auth.POST("/plan/select-free", billingHandler.SelectFreePlan)

	// Me endpoint
	auth.GET("/me", func(c echo.Context) error {
		tc := appmw.NewTenantContext(c)
		return c.JSON(200, map[string]interface{}{
			"user":     tc.User(),
			"tenant":   tc.Tenant(),
			"role":     tc.Role(),
			"selfHosted": tc.IsSelfHosted(),
		})
	})

	// Dashboard endpoints
	auth.GET("/dashboard/summary", dashboardHandler.GetSummary)

	// Search endpoints
	auth.GET("/search/cve", searchHandler.SearchByCVE)
	auth.GET("/search/component", searchHandler.SearchByComponent)

	// EPSS endpoints
	auth.POST("/vulnerabilities/sync-epss", epssHandler.SyncScores)
	auth.GET("/vulnerabilities/epss/:cve_id", epssHandler.GetScore)

	// Project endpoints
	auth.POST("/projects", projectHandler.Create)
	auth.GET("/projects", projectHandler.List)
	auth.GET("/projects/:id", projectHandler.Get)
	auth.DELETE("/projects/:id", projectHandler.Delete)

	// SBOM endpoints
	// SBOM upload is the canonical endpoint that both the web UI (Clerk JWT)
	// and the CLI / GitHub Actions (Bearer sbh_... API key) target. Trust
	// Rescue 9.3.1 (#9) unified the two paths behind MultiAuth so we have a
	// single source of truth; the deprecated /api/v1/cli/upload route is kept
	// alive on the legacy CLI group below for one release of overlap.
	// Trust Rescue 9.1.2 (#3): the canonical upload route gets the same
	// per-request transaction treatment as the auth group above. Middleware
	// order here is MultiAuth → RateLimitByAPIKey → TenantTx → audit →
	// handler (Echo applies the variadic middleware list outer-to-inner).
	//
	// Codex R19 fix: the legacy /api/v1/cli/upload route is rate-limited per
	// API key (see the `cli` group above), but the canonical MultiAuth
	// upload was not — a leaked `sbh_...` key could DoS the server with
	// unbounded large-SBOM uploads, and after the 2026-09 sunset of the
	// legacy CLI route all clients land here. RateLimitByAPIKey is a no-op
	// when ContextKeyAPI is unset (i.e. Clerk JWT / self-hosted default
	// path), so this preserves the web UI's existing un-throttled behaviour
	// while matching the legacy CLI guard (60 req/min per API key).
	e.POST("/api/v1/projects/:id/sbom", sbomHandler.Upload,
		appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	// GET /sbom is the companion read-back to the canonical upload above:
	// after a CLI / GitHub Actions client uploads with
	// `Authorization: Bearer sbh_...`, the docs-curl-smoke workflow (and any
	// external verifier — `sbomhub` CLI included) reads back the latest SBOM
	// with the same API key. Codex R11 fix: registered outside the `auth`
	// (Clerk-only) group with MultiAuth so the API-key Bearer header is
	// accepted. Previously the API key was decoded as a Clerk JWT, the
	// request fell through to the default tenant in self-host mode, and the
	// verification step in docs-curl-smoke.yml saw a 404.
	//
	// Codex R21 fix: rate-limit the API-key path to mirror the canonical
	// upload above (60 req/min per API key). RateLimitByAPIKey is a no-op
	// when ContextKeyAPI is unset (i.e. Clerk JWT / self-hosted default
	// path), so this leaves the web UI un-throttled while protecting the
	// SBOM read-back from being used as a content-exfiltration loop with a
	// leaked `sbh_...` key.
	// Middleware chain: MultiAuth -> RateLimitByAPIKey -> TenantTx -> audit -> handler.
	e.GET("/api/v1/projects/:id/sbom",
		sbomHandler.Get,
		appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	auth.GET("/projects/:id/sboms", sbomHandler.List)
	auth.GET("/projects/:id/components", sbomHandler.GetComponents)
	auth.GET("/projects/:id/vulnerabilities", sbomHandler.GetVulnerabilities)
	// Per-SBOM background-scan status endpoint observed by `sbomhub scan
	// --fail-on <severity>` (Trust Rescue P1 #12). It reports
	// running/completed/failed plus current per-severity counts so CLI
	// clients can block CI on threshold violations.
	//
	// Codex R3 fix: registered outside the `auth` (Clerk-only) group with
	// MultiAuth so the CLI's `Authorization: Bearer sbh_...` API-key polling
	// works after the canonical upload. Previously the CLI received 401
	// because the API key was decoded as a Clerk JWT, defeating the purpose
	// of scan-status.
	//
	// Codex R21 fix: rate-limit the API-key path. This endpoint is a polling
	// surface for `sbomhub scan --fail-on <severity>`, so a higher ceiling
	// of 300 req/min per API key (≈5 req/sec, comfortably above a 1s poll
	// cadence even with multiple concurrent CLI invocations) is applied
	// instead of the 60 req/min used for upload / read-back. RateLimitByAPIKey
	// is a no-op for the Clerk JWT path so the web UI is unaffected.
	// Middleware chain: MultiAuth -> RateLimitByAPIKey -> TenantTx -> audit -> handler.
	e.GET("/api/v1/projects/:id/sboms/:sbom_id/scan-status",
		sbomHandler.ScanStatus,
		appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService),
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	auth.POST("/projects/:id/scan", vulnHandler.Scan)

	// SBOM Diff endpoints
	auth.POST("/sbom/diff", sbomDiffHandler.Diff)

	// VEX endpoints
	auth.GET("/projects/:id/vex", vexHandler.List)
	auth.POST("/projects/:id/vex", vexHandler.Create)
	auth.GET("/projects/:id/vex/export", vexHandler.Export)
	auth.GET("/projects/:id/vex/:vex_id", vexHandler.Get)
	auth.PUT("/projects/:id/vex/:vex_id", vexHandler.Update)
	auth.DELETE("/projects/:id/vex/:vex_id", vexHandler.Delete)

	// AI VEX triage endpoints (issue #30 / Wave M1-5). Wired into the
	// existing auth group so tenant id, audit middleware, and
	// TenantTx all apply (Trust Rescue 9.1.3 — vex_drafts INSERT
	// requires the tenant_id GUC bound by TenantTx).
	auth.POST("/projects/:id/triage/run", vexDraftsHandler.RunTriage)
	auth.GET("/projects/:id/vex-drafts", vexDraftsHandler.ListDrafts)
	auth.GET("/projects/:id/vex-drafts/:draft_id", vexDraftsHandler.GetDraft)
	auth.PUT("/projects/:id/vex-drafts/:draft_id/decision", vexDraftsHandler.Decide)
	auth.POST("/projects/:id/vex-drafts/:draft_id/reanalyse", vexDraftsHandler.Reanalyse)

	// License policy endpoints
	auth.GET("/licenses/common", licensePolicyHandler.GetCommonLicenses)
	auth.GET("/projects/:id/licenses", licensePolicyHandler.List)
	auth.POST("/projects/:id/licenses", licensePolicyHandler.Create)
	auth.GET("/projects/:id/licenses/violations", licensePolicyHandler.CheckViolations)
	auth.GET("/projects/:id/licenses/:policy_id", licensePolicyHandler.Get)
	auth.PUT("/projects/:id/licenses/:policy_id", licensePolicyHandler.Update)
	auth.DELETE("/projects/:id/licenses/:policy_id", licensePolicyHandler.Delete)

	// API key endpoints (tenant-level - recommended)
	auth.GET("/apikeys", apiKeyHandler.ListTenant)
	auth.POST("/apikeys", apiKeyHandler.CreateTenant)
	auth.DELETE("/apikeys/:key_id", apiKeyHandler.DeleteTenant)

	// API key endpoints (project-level - deprecated, for backwards compatibility)
	auth.GET("/projects/:id/apikeys", apiKeyHandler.List)
	auth.POST("/projects/:id/apikeys", apiKeyHandler.Create)
	auth.DELETE("/projects/:id/apikeys/:key_id", apiKeyHandler.Delete)

	// Notification endpoints
	auth.GET("/projects/:id/notifications", notificationHandler.GetSettings)
	auth.PUT("/projects/:id/notifications", notificationHandler.UpdateSettings)
	auth.POST("/projects/:id/notifications/test", notificationHandler.TestNotification)
	auth.GET("/projects/:id/notifications/logs", notificationHandler.GetLogs)

	// Compliance endpoints
	auth.GET("/projects/:id/compliance", complianceHandler.Check)
	auth.GET("/projects/:id/compliance/report", complianceHandler.ExportReport)

	// METI Checklist endpoints (18 items)
	auth.GET("/projects/:id/checklist", complianceHandler.GetChecklist)
	auth.PUT("/projects/:id/checklist/:checkId", complianceHandler.UpdateChecklistResponse)
	auth.DELETE("/projects/:id/checklist/:checkId", complianceHandler.DeleteChecklistResponse)

	// Visualization Framework endpoints
	auth.GET("/projects/:id/visualization", complianceHandler.GetVisualizationSettings)
	auth.PUT("/projects/:id/visualization", complianceHandler.UpdateVisualizationSettings)
	auth.DELETE("/projects/:id/visualization", complianceHandler.DeleteVisualizationSettings)

	// Public link endpoints
	auth.POST("/projects/:id/public-links", publicLinkHandler.Create)
	auth.GET("/projects/:id/public-links", publicLinkHandler.List)
	auth.PUT("/public-links/:id", publicLinkHandler.Update)
	auth.DELETE("/public-links/:id", publicLinkHandler.Delete)

	// Audit log endpoints (Pro plan and above)
	auditFeatureCheck := appmw.CheckFeature("audit_logs", subscriptionRepo)
	auth.GET("/audit-logs", auditHandler.List, auditFeatureCheck)
	auth.GET("/audit-logs/export", auditHandler.Export, auditFeatureCheck)
	auth.GET("/audit-logs/statistics", auditHandler.GetStatistics, auditFeatureCheck)
	auth.GET("/audit-logs/actions", auditHandler.GetActions, auditFeatureCheck)
	auth.GET("/audit-logs/resource-types", auditHandler.GetResourceTypes, auditFeatureCheck)

	// Analytics endpoints
	auth.GET("/analytics/summary", analyticsHandler.GetSummary)
	auth.GET("/analytics/mttr", analyticsHandler.GetMTTR)
	auth.GET("/analytics/vulnerability-trend", analyticsHandler.GetVulnerabilityTrend)
	auth.GET("/analytics/slo-achievement", analyticsHandler.GetSLOAchievement)
	auth.GET("/analytics/compliance-trend", analyticsHandler.GetComplianceTrend)
	auth.GET("/analytics/slo-targets", analyticsHandler.GetSLOTargets)
	auth.PUT("/analytics/slo-targets", analyticsHandler.UpdateSLOTarget)

	// Report endpoints
	auth.GET("/reports/settings", reportHandler.GetSettings)
	auth.PUT("/reports/settings", reportHandler.UpdateSettings)
	auth.POST("/reports/generate", reportHandler.Generate)
	auth.GET("/reports", reportHandler.List)
	auth.GET("/reports/:id", reportHandler.Get)
	auth.GET("/reports/:id/download", reportHandler.Download)

	// IPA integration endpoints
	auth.GET("/ipa/announcements", ipaHandler.ListAnnouncements)
	auth.POST("/ipa/sync", ipaHandler.SyncAnnouncements)
	auth.GET("/vulnerabilities/:cve_id/ipa", ipaHandler.GetAnnouncementsByCVE)
	auth.GET("/settings/ipa", ipaHandler.GetSyncSettings)
	auth.PUT("/settings/ipa", ipaHandler.UpdateSyncSettings)

	// Scan settings endpoints
	scanSettingsService := service.NewScanSettingsService(db)
	scanSettingsHandler := handler.NewScanSettingsHandler(scanSettingsService)
	auth.GET("/settings/scan", scanSettingsHandler.Get)
	auth.PUT("/settings/scan", scanSettingsHandler.Update)
	auth.GET("/settings/scan/logs", scanSettingsHandler.GetLogs)

	// BYOK LLM provider configuration (issue #22). The handler encrypts the
	// supplied API key with internal/service/llm.Encrypt before persisting;
	// GET returns "***" as a placeholder so plaintext never leaves the
	// process. Admin-only on PUT (enforced inside the handler).
	settingsLLMHandler := handler.NewSettingsLLMHandler(tenantLLMConfigRepo, auditRepo, cfg)
	auth.GET("/settings/llm", settingsLLMHandler.Get)
	auth.PUT("/settings/llm", settingsLLMHandler.Update)

	// KEV (Known Exploited Vulnerabilities) integration endpoints
	auth.POST("/kev/sync", kevHandler.SyncCatalog)
	auth.GET("/kev/catalog", kevHandler.ListCatalog)
	auth.GET("/kev/stats", kevHandler.GetStats)
	auth.GET("/kev/settings", kevHandler.GetSyncSettings)
	auth.GET("/kev/sync/latest", kevHandler.GetLatestSync)
	auth.GET("/kev/:cve_id", kevHandler.GetByCVE)
	auth.GET("/vulnerabilities/:cve_id/kev", kevHandler.CheckCVE)
	auth.GET("/projects/:id/kev", kevHandler.GetProjectKEVVulnerabilities)

	// EOL (End of Life) integration endpoints
	auth.POST("/eol/sync", eolHandler.SyncCatalog)
	auth.GET("/eol/products", eolHandler.ListProducts)
	auth.GET("/eol/products/:name", eolHandler.GetProduct)
	auth.GET("/eol/stats", eolHandler.GetStats)
	auth.GET("/eol/settings", eolHandler.GetSyncSettings)
	auth.GET("/eol/sync/latest", eolHandler.GetLatestSync)
	auth.GET("/eol/check", eolHandler.CheckComponentEOL)
	auth.GET("/projects/:id/eol-summary", eolHandler.GetProjectEOLSummary)
	auth.POST("/projects/:id/eol-check", eolHandler.UpdateProjectComponentsEOL)

	// SSVC (Stakeholder-Specific Vulnerability Categorization) endpoints
	auth.GET("/projects/:id/ssvc/defaults", ssvcHandler.GetProjectDefaults)
	auth.PUT("/projects/:id/ssvc/defaults", ssvcHandler.UpdateProjectDefaults)
	auth.GET("/projects/:id/ssvc/summary", ssvcHandler.GetSummary)
	auth.GET("/projects/:id/ssvc/assessments", ssvcHandler.ListAssessments)
	auth.DELETE("/projects/:id/ssvc/assessments/:assessment_id", ssvcHandler.DeleteAssessment)
	auth.GET("/projects/:id/ssvc/assessments/:assessment_id/history", ssvcHandler.GetAssessmentHistory)
	auth.GET("/projects/:id/ssvc/cve/:cve_id", ssvcHandler.GetAssessmentByCVE)
	auth.GET("/projects/:id/vulnerabilities/:vuln_id/ssvc", ssvcHandler.GetAssessment)
	auth.POST("/projects/:id/vulnerabilities/:vuln_id/ssvc", ssvcHandler.AssessVulnerability)
	auth.POST("/projects/:id/vulnerabilities/:vuln_id/ssvc/auto", ssvcHandler.AutoAssessVulnerability)
	auth.POST("/ssvc/calculate", ssvcHandler.CalculateDecision)
	auth.GET("/ssvc/immediate", ssvcHandler.GetImmediateAssessments)

	// Issue tracker integration endpoints
	auth.POST("/integrations", issueTrackerHandler.CreateConnection)
	auth.GET("/integrations", issueTrackerHandler.ListConnections)
	auth.GET("/integrations/:id", issueTrackerHandler.GetConnection)
	auth.DELETE("/integrations/:id", issueTrackerHandler.DeleteConnection)
	auth.POST("/vulnerabilities/:vuln_id/ticket", issueTrackerHandler.CreateTicket)
	auth.GET("/vulnerabilities/:vuln_id/tickets", issueTrackerHandler.GetTicketsByVulnerability)
	auth.GET("/tickets", issueTrackerHandler.ListTickets)
	auth.POST("/tickets/:id/sync", issueTrackerHandler.SyncTicket)

	// Remediation guidance endpoints
	auth.GET("/remediation/:cve_id", remediationHandler.GetRemediationByCVE)
	auth.GET("/vulnerabilities/:id/remediation", remediationHandler.GetRemediation)

	// Start background jobs
	ctx := context.Background()

	// Ticket sync job - runs every 5 minutes to sync ticket statuses with Jira/Backlog.
	// tenantRepo + db are required for the per-tenant RLS tx wrap (codex-r4 P1).
	ticketSyncJob := scheduler.NewTicketSyncJob(issueTrackerService, issueTrackerRepo, tenantRepo, db, 5*time.Minute)
	go ticketSyncJob.Start(ctx)
	slog.Info("Ticket sync job started", "interval", "5m")

	// Report generation job - runs every hour to check scheduled reports.
	// db is required for per-tenant RLS tx wrap (codex-r4 P1).
	reportGenJob := scheduler.NewReportGenerationJobFull(reportService, reportRepo, tenantRepo, db, cfg, 1*time.Hour)
	go reportGenJob.Start(ctx)
	slog.Info("Report generation job started", "interval", "1h")

	// KEV sync job - runs daily to sync CISA KEV catalog
	kevSyncJob := scheduler.NewKEVSyncJob(kevService, 24*time.Hour)
	go kevSyncJob.Start(ctx)
	slog.Info("KEV sync job started", "interval", "24h")

	// EOL sync job - runs daily to sync endoflife.date catalog
	eolSyncJob := scheduler.NewEOLSyncJob(eolService, 24*time.Hour)
	go eolSyncJob.Start(ctx)
	slog.Info("EOL sync job started", "interval", "24h")

	// CVE sync job - runs daily to fetch new/updated CVEs and match against components.
	// tenantRepo is required for the per-tenant matching loop against RLS-bound
	// `components` (codex-r4 P1).
	cveSyncJob := scheduler.NewCVESyncJob(db, tenantRepo, cfg.NVDAPIKey, 24*time.Hour)
	go cveSyncJob.Start(ctx)
	slog.Info("CVE sync job started", "interval", "24h")

	// Vulnerability scan job - runs hourly to scan components against NVD
	// Uses NVDService with Redis cache for efficient API usage
	vulnScanJob := scheduler.NewVulnerabilityScanJobFull(db, nvdService, notificationService)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		// Run immediately on startup
		if err := vulnScanJob.Run(ctx); err != nil {
			slog.Error("Vulnerability scan failed", "error", err)
		}
		for {
			select {
			case <-ticker.C:
				if err := vulnScanJob.Run(ctx); err != nil {
					slog.Error("Vulnerability scan failed", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	slog.Info("Vulnerability scan job started", "interval", "1h")

	// Force scan endpoint (admin only) - triggers immediate vulnerability scan
	auth.POST("/settings/scan/force", func(c echo.Context) error {
		tenantCtx := appmw.NewTenantContext(c)
		if tenantCtx == nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}
		if !tenantCtx.CanAdmin() {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "admin required"})
		}

		// Force run scan for this tenant
		go func() {
			if err := vulnScanJob.ForceRunTenant(context.Background(), tenantCtx.TenantID()); err != nil {
				slog.Error("Force scan failed", "tenant_id", tenantCtx.TenantID(), "error", err)
			}
		}()

		return c.JSON(http.StatusOK, map[string]string{"status": "scan started"})
	})

	slog.Info("Starting server", "port", cfg.Port)
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
