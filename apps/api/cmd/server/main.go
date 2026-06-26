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
	"github.com/sbomhub/sbomhub/internal/service/cra"
	"github.com/sbomhub/sbomhub/internal/service/evidence_pack"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/meti"
	"github.com/sbomhub/sbomhub/internal/service/triage"
	"github.com/sbomhub/sbomhub/migrations"
)

// newVexDraftsStore returns the concrete vex_drafts store wired
// against the runtime DB pool. Agent A's *repository.VEXDraftsRepository
// satisfies triage.VexDraftStore by construction (matching method set).
func newVexDraftsStore(db *sql.DB) triage.VexDraftStore {
	return repository.NewVEXDraftsRepository(db)
}

// metiCatalogAdapter satisfies evidence_pack.METICatalog by routing
// the calls to the meti package's package-level lookups (M3-3, #39).
// The adapter is a stateless struct so the server can construct one
// inline at wiring time without an init pass. M3-6 (#42) wire.
type metiCatalogAdapter struct{}

func (metiCatalogAdapter) GetCriterion(id string) (*meti.Criterion, bool) {
	return meti.GetCriterion(id)
}

func (metiCatalogAdapter) Phases() []meti.Phase {
	return meti.Phases()
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
	vexDraftsRepo := repository.NewVEXDraftsRepository(db)

	// CRA report inputs (Wave M2-2 / issue #32, Wave M2-3 / issue #31).
	// Wired through cra.Runner (constructed below) for RunReport /
	// Reanalyse and through the handler directly for List / Get /
	// UpdateDecision.
	craReportsRepo := repository.NewCRAReportsRepository(db)

	// METI self-assessment store (Wave M3-1 / issue #41). Holds the 27
	// per-criterion verdicts the evaluator (M3-2) writes and the M3-4
	// /meti/assessment endpoints read / override.
	metiAssessmentsRepo := repository.NewMetiAssessmentsRepository(db)

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
	// M1 Codex review #F19: TxManager drives the runner's Stage 1 / Stage
	// 3 transactions so the slow Provider.Complete (Stage 2) runs with
	// NO Postgres tx held — fixing the DB connection pool exhaustion DoS
	// where 25 concurrent triage requests could pin every connection in
	// the pool waiting on the upstream LLM. LLMTimeoutFromEnv bounds the
	// Provider.Complete call (default 90s, override
	// SBOMHUB_LLM_TIMEOUT_SECONDS).
	triageTxManager := triage.NewDBTxManager(db)
	triageLLMTimeout := triage.LLMTimeoutFromEnv()
	triageRunner := triage.NewRunner(triage.RunnerConfig{
		Drafts:                   newVexDraftsStore(db),
		Advisories:               &triage.AdvisoryExcerptsAdapter{Repo: advisoryExcerptsRepo},
		Reachability:             &triage.ReachabilityAdapter{Repo: reachabilityResultsRepo},
		LLMCalls:                 &triage.LLMCallsAdapter{Repo: llmCallsRepo},
		Audit:                    auditRepo,
		VEXSync:                  &triage.VEXServiceAdapter{Service: vexService},
		ComponentVulnerabilities: componentRepo,
		// M1 Codex review #F12: re-resolve cve_id server-side from the
		// (scoped) vulnerability_id so callers cannot pair an in-scope
		// vulnerability_id with an arbitrary cve_id and have the runner
		// fetch / persist mismatched evidence.
		VulnerabilityCVE: vulnRepo,
		Provider:         triageDefaultProvider,
		ProviderResolver: triageProviderResolver,
		Threshold:        triage.ConfidenceThresholdFromEnv(),
		TxManager:        triageTxManager,
		LLMTimeout:       triageLLMTimeout,
	})
	slog.Info("AI VEX triage runner initialised",
		"default_provider", triageDefaultProvider.Name(),
		"threshold", triage.ConfidenceThresholdFromEnv(),
		"per_tenant_resolver", "tenant_llm_config",
		"llm_timeout", triageLLMTimeout,
		"tx_manager", "DBTxManager (F19)")

	// CRA report drafting runner (issue #31 / Wave M2-3, wired in M2-4
	// / issue #36). Reuses the triage TxManager + per-tenant provider
	// resolver so CRA generation inherits the same F19 connection-pool
	// hygiene and #F2 BYOK provider routing as VEX triage.
	craRunner := cra.NewRunner(cra.RunnerConfig{
		VEXDrafts:           vexDraftsRepo,
		AdvisoryExcerpts:    advisoryExcerptsRepo,
		ReachabilityResults: reachabilityResultsRepo,
		CRAReports:          craReportsRepo,
		LLMCalls:            llmCallsRepo,
		VulnerabilityCVE:    vulnRepo,
		Audit:               auditRepo,
		Provider:            triageDefaultProvider,
		ProviderResolver:    triageProviderResolver,
		TxManager:           triageTxManager,
		LLMTimeout:          triageLLMTimeout,
		GeneratedBy:         "SBOMHub (LLM: " + triageDefaultProvider.Name() + "/" + triageDefaultProvider.Model() + ")",
	})
	slog.Info("CRA report drafting runner initialised",
		"default_provider", triageDefaultProvider.Name(),
		"per_tenant_resolver", "tenant_llm_config",
		"llm_timeout", triageLLMTimeout,
		"tx_manager", "DBTxManager (F19, shared with triage)")

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

	// CRA report handler (Wave M2-4 / issue #36). Holds the cra.Runner
	// for RunReport / Reanalyse (the 2-stage LLM path) and the
	// cra_reports repository directly for List / Get / UpdateDecision
	// (pure CRUD). The audit writer is wired for the
	// `cra_report_decided` domain audit row emitted by the Decide
	// endpoint — the AI-generated / AI-disabled audit rows are emitted
	// by the runner inside its Stage 3 write tx.
	craReportsHandler := handler.NewCRAReportsHandler(craRunner, craReportsRepo, auditRepo)

	// METI self-assessment evaluator (Wave M3-2 / issue #40). Runs the
	// catalog (M3-3) over a (tenant, project) pair and returns one
	// CriterionResult per criterion. Local-only: no LLM upstream, so
	// the /refresh handler runs synchronously inside the ambient
	// TenantTx (F19 N/A). Construction takes every read repository the
	// per-criterion functions need — see service/meti/evaluator.go's
	// NewEvaluator for the full dependency list.
	metiEvaluator, err := meti.NewEvaluator(
		sbomRepo,
		componentRepo,
		vulnRepo,
		vexDraftsRepo,
		craReportsRepo,
		publicLinkRepo,
		licensePolicyRepo,
		eolRepo,
		kevRepo,
		auditRepo,
	)
	if err != nil {
		slog.Error("Failed to initialise METI evaluator", "error", err)
		os.Exit(1)
	}

	// METI assessment handler (Wave M3-4 / issue #37). Holds the
	// repository for List / Get / Override / X-Total-Count, the
	// evaluator for /refresh fan-out, and the audit writer for the
	// `meti_assessment_refreshed` + `meti_assessment_overridden` domain
	// audit rows. The request-level audit middleware also runs on
	// these routes but records only path/method/latency — the domain
	// audit captures the criterion verdict changes for the compliance
	// trail.
	metiHandler := handler.NewMetiHandler(metiAssessmentsRepo, metiEvaluator, auditRepo)

	// Evidence Pack builder + handler (Wave M2-6 / issue #34). The
	// builder composes the existing vex_drafts (M1) + cra_reports
	// (M2-2) repositories with project metadata into a single Markdown
	// bundle. Reads run inside the request-scoped TenantTx (route
	// registered below) so RLS bounds every SELECT to the caller's
	// tenant. The repository instances are reused from the triage /
	// cra runner wiring above so a request hits a single shared
	// connection-pool slot per repo type.
	// M3-6 (issue #42): the Evidence Pack METI section is now driven
	// by the live meti_assessments rows (via the M3-1 repository) and
	// the M3-3 catalog. The catalog adapter is a thin wrapper that
	// surfaces the meti package's package-level lookups as a struct
	// satisfying evidence_pack.METICatalog so the builder stays free
	// of package-import order constraints.
	evidencePackBuilder := evidence_pack.NewBuilder(
		vexDraftsRepo,
		craReportsRepo,
		projectRepo,
		metiAssessmentsRepo,
		metiCatalogAdapter{},
	)
	evidencePackHandler := handler.NewEvidencePackHandler(evidencePackBuilder, auditRepo)

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
		AllowOrigins: []string{"http://localhost:3000", "http://localhost:13000", "http://localhost:*", "https://sbomhub.app"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Clerk-Org-ID"},
		// X-Total-Count must be in ExposeHeaders so the Web UI can
		// read it from a cross-origin /api/v1/projects/:id/vulnerabilities
		// fetch — M1 Codex review #F28 (Web UI data integrity). Without
		// the exposure the browser silently strips the header before the
		// fetch handler sees it, and the UI falls back to the old
		// truncated-page behaviour.
		ExposeHeaders: []string{echo.HeaderContentDisposition, echo.HeaderContentLength, echo.HeaderContentType, "X-Total-Count"},
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
	//
	// M1 Codex review #F18: the legacy /api/v1/cli/* group historically
	// used APIKeyAuth + APIKeyTenant only, neither of which consulted
	// api_keys.permissions. That meant a read-scoped sbh_... key could
	// still write through cliHandler.Upload / cliHandler.CreateProject
	// even after F15 locked down the canonical MultiAuth-fronted write
	// routes. APIKeyTenant now populates ContextKeyRole from the API
	// key's permissions (mirroring MultiAuth.handleAPIKeyAuth), and the
	// mutating routes below add appmw.RequireWrite() so a read-scoped
	// key gets the same 403 it would receive on the canonical endpoint.
	// Read-only routes (GET /projects, GET /projects/:id) intentionally
	// remain reachable by every tier including RoleViewer.
	cli := api.Group("/cli",
		appmw.APIKeyAuth(apiKeyService),
		appmw.APIKeyTenant(projectRepo, tenantRepo),
		appmw.TenantTx(db),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.MCPAudit(auditRepo),
	)
	cli.POST("/upload", cliHandler.Upload, appmw.RequireWrite())
	cli.POST("/check", cliHandler.Check)
	cli.GET("/projects", cliHandler.ListProjects)
	cli.GET("/projects/:id", cliHandler.GetProject)
	cli.POST("/projects", cliHandler.CreateProject, appmw.RequireWrite())

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
	// M1 Codex review #F15: appmw.RequireWrite() sits between MultiAuth
	// (which sets ContextKeyRole) and RateLimitByAPIKey/TenantTx so a
	// read-scoped sbh_... key receives a 403 BEFORE pinning the rate
	// limit token bucket and opening a Postgres transaction. SbomHandler.
	// Upload itself never consulted CanWrite — the entire write gate
	// lives in this guard now, and any future write route added to the
	// canonical MultiAuth chain must include it (see role_guard.go for
	// the rationale and body policy).
	e.POST("/api/v1/projects/:id/sbom", sbomHandler.Upload,
		appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService),
		appmw.RequireWrite(),
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
	// M1 Codex review #F20: /api/v1/projects/:id/vulnerabilities used to
	// sit on the Clerk-only `auth` group above, so the CLI's
	// `sbomhub triage` (which sends `Authorization: Bearer sbh_...`)
	// could never enumerate vulnerabilities — every request hit Auth()'s
	// Clerk JWT verifier and returned 401. The MCP-mounted twin at
	// /api/v1/mcp/projects/:id/vulnerabilities exists for the MCP server
	// only and is not what the triage CLI targets.
	//
	// We now register the canonical /vulnerabilities read-back route
	// through MultiAuth + RateLimitByAPIKey + TenantTx + audit, the same
	// chain the SBOM read-back (GET /api/v1/projects/:id/sbom) and
	// scan-status routes use. The Clerk JWT / self-hosted path is
	// preserved by MultiAuth's clerkChain fallback so the web UI's
	// vulnerability list view is unaffected. The handler is read-only so
	// RequireWrite is deliberately omitted — read-scoped (RoleViewer)
	// API keys can enumerate vulnerabilities, matching /sbom GET /
	// /sboms/.../scan-status.
	//
	// Rate-limit budget mirrors the SBOM read-back (60 req/min per API
	// key) — `sbomhub triage` calls this once per session, not in a
	// polling loop. RateLimitByAPIKey is a no-op for the Clerk JWT path
	// so the web UI is unaffected.
	// Middleware chain: MultiAuth -> RateLimitByAPIKey -> TenantTx -> audit -> handler.
	e.GET("/api/v1/projects/:id/vulnerabilities",
		sbomHandler.GetVulnerabilities,
		appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
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

	// AI VEX triage endpoints (issue #30 / Wave M1-5).
	//
	// M1 Codex review #F14: these five routes were originally registered
	// under the `auth` group above, which uses authMiddleware =
	// Clerk-or-self-hosted-only. That made `sbomhub triage` (the CLI
	// command shipped in Wave M1-4) unreachable: the CLI sends
	// `Authorization: Bearer sbh_<api_key>` which the Clerk JWT verifier
	// rejects as invalid, so every call landed on 401. The M1 completion
	// claim ("CLI can run triage") was therefore vacuously false.
	//
	// We now wire each triage / vex-drafts route through MultiAuth +
	// RateLimitByAPIKey + TenantTx + audit, the same chain the canonical
	// SBOM upload (POST /api/v1/projects/:id/sbom) and the SBOM read-back
	// + scan-status routes use. MultiAuth's API-key path was upgraded in
	// the same review (see internal/middleware/multiauth.go) to populate
	// ContextKeyRole + ContextKeyUserID so the handler's CanWrite() guard
	// and the runner's "user identity required" guard both accept
	// sbh_... keys. The Clerk JWT / self-hosted path remains unchanged so
	// the web UI is unaffected.
	//
	// RateLimitByAPIKey is a no-op when ContextKeyAPI is unset, so this
	// throttles only the CLI path (60 req/min for write / decision, 300
	// req/min for the read-back list to mirror the scan-status polling
	// budget). TenantTx wraps the rest so vex_drafts INSERT / UPDATE
	// runs inside the same `SET LOCAL app.current_tenant_id` tx that
	// audit_logs INSERT uses, satisfying Trust Rescue 9.1.3 + 9.1.2.
	// Middleware chain: MultiAuth -> RateLimitByAPIKey -> TenantTx -> audit -> handler.
	// M1 Codex review #F15: the three write routes in this group
	// (triage/run, decision, reanalyse) now sit behind RequireWrite so a
	// read-scoped API key cannot mint AI drafts or apply human
	// decisions. The two read routes (ListDrafts, GetDraft) stay
	// unguarded — reading vex_drafts is a CanWrite-not-required
	// operation by design (the CLI uses the list endpoint to render
	// triage history with a read-only audit key).
	//
	// The handler-side CanWrite() check in VexDraftsHandler.RunTriage /
	// Decide / Reanalyse is retained (defence in depth) but is no longer
	// the sole guard — the route-level RequireWrite stops the request
	// before the handler sees it, which means RateLimitByAPIKey and
	// TenantTx never run for a denied caller.
	triageMultiAuth := appmw.MultiAuth(cfg, tenantRepo, userRepo, apiKeyService)
	// M1 Codex review #F19: TenantTx + auditMiddleware are deliberately
	// stripped from /triage/run and /vex-drafts/:id/reanalyse because
	// those two routes call the runner's 2-stage flow, which manages
	// its own Stage 1 read tx and Stage 3 write tx internally so the
	// slow LLM upstream call (Stage 2) does not pin a Postgres
	// connection. Wrapping them in TenantTx would re-introduce the
	// connection-pool exhaustion DoS. Lifecycle audit_logs rows are
	// still emitted by runner.writeAudit (vex_draft_ai_generated /
	// vex_draft_reanalysed / vex_draft_ai_disabled) inside Stage 3 —
	// the request-level audit middleware (path + method + latency)
	// is the only loss on these specific routes.
	//
	// TriageConcurrencyLimit caps concurrent runs per-tenant and
	// globally (defaults 5 / 20, overridable via env) so the API has
	// route-level back-pressure even when the runner's per-request
	// connection-hygiene fix is doing its job. It sits after the
	// role guard so denied requests do not consume slots, and after
	// the rate limiter so the 60/min budget still gates per-key
	// volume.
	triageConcurrencyLimiter := appmw.NewTriageConcurrencyLimiterFromEnv()
	slog.Info("triage concurrency limiter initialised",
		"per_tenant", triageConcurrencyLimiter.PerTenant(),
		"global", triageConcurrencyLimiter.Global())
	e.POST("/api/v1/projects/:id/triage/run",
		vexDraftsHandler.RunTriage,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		triageConcurrencyLimiter.Middleware())
	e.GET("/api/v1/projects/:id/vex-drafts",
		vexDraftsHandler.ListDrafts,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.GET("/api/v1/projects/:id/vex-drafts/:draft_id",
		vexDraftsHandler.GetDraft,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.PUT("/api/v1/projects/:id/vex-drafts/:draft_id/decision",
		vexDraftsHandler.Decide,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	// /vex-drafts/:id/reanalyse calls runner.Run() like /triage/run, so
	// it gets the same F19 treatment (no TenantTx, concurrency limit).
	// The handler's loadDraftScoped → runner.GetDraft now opens its
	// own short read tx via the runner's TxManager so the lookup
	// still RLS-scopes despite the missing ambient TenantTx.
	e.POST("/api/v1/projects/:id/vex-drafts/:draft_id/reanalyse",
		vexDraftsHandler.Reanalyse,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		triageConcurrencyLimiter.Middleware())

	// CRA report endpoints (Wave M2-4 / issue #36).
	//
	// Same MultiAuth + RequireWrite + per-tenant concurrency cap shape
	// the triage / vex-drafts routes use, with a distinct CRA-scoped
	// concurrency limiter so a CRA drafting burst (compliance deadline
	// rush) cannot starve concurrent VEX triage requests (and
	// vice-versa). The cra.Runner manages its own Stage 1 / Stage 3
	// tx via the shared *triage.DBTxManager (F19), so RunReport and
	// Reanalyse intentionally skip the ambient TenantTx + request-
	// level audit middleware — runner.writeAudit emits the domain-
	// level cra_report_ai_generated / cra_report_ai_disabled rows
	// inside the Stage 3 write tx. The read + decide routes go
	// through TenantTx + audit middleware in the same shape as the
	// vex-drafts read + decide endpoints so cra_reports.Get /
	// ListByProject / UpdateDecision run with `SET LOCAL
	// app.current_tenant_id` bound (cra_reports is FORCE ROW LEVEL
	// SECURITY per migration 038, so the GUC is load-bearing).
	// Middleware chain mirrors vex-drafts for parity: RunReport and
	// Reanalyse skip TenantTx + audit middleware; List / Get / Decide
	// include both. ※要確認: the task brief asks for a single unified
	// chain with no TenantTx on any of the 5 routes, but the
	// read/decide paths interact with FORCE RLS tables — falling back
	// to the vex-drafts split keeps reads functional without
	// requiring a fresh runner-level wrapper for those paths.
	craConcurrencyLimiter := appmw.NewCRAConcurrencyLimiterFromEnv()
	slog.Info("cra concurrency limiter initialised",
		"per_tenant", craConcurrencyLimiter.PerTenant(),
		"global", craConcurrencyLimiter.Global())
	e.POST("/api/v1/projects/:id/cra-reports/run",
		craReportsHandler.RunReport,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		craConcurrencyLimiter.Middleware())
	e.GET("/api/v1/projects/:id/cra-reports",
		craReportsHandler.ListReports,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.GET("/api/v1/projects/:id/cra-reports/:report_id",
		craReportsHandler.GetReport,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.PUT("/api/v1/projects/:id/cra-reports/:report_id/decision",
		craReportsHandler.Decide,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.POST("/api/v1/projects/:id/cra-reports/:report_id/reanalyse",
		craReportsHandler.Reanalyse,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		craConcurrencyLimiter.Middleware())

	// METI self-assessment endpoints (Wave M3-4 / issue #37).
	//
	// Same MultiAuth-fronted chain the triage / CRA / evidence-pack
	// routes use. The evaluator is fully local (no LLM upstream), so
	// /refresh runs synchronously inside the ambient TenantTx — F19
	// (no-TenantTx-for-LLM-stages) is intentionally NOT applied and a
	// per-tenant concurrency limiter is not needed (the catalog is a
	// fixed 27-item fan-out; F25 N/A).
	//
	// Middleware chain:
	//   - GET assessment / GET improvement-actions:
	//       MultiAuth -> RateLimitByAPIKey(300/min) -> TenantTx -> audit -> handler
	//   - POST refresh / PUT override:
	//       MultiAuth -> RequireWrite -> RateLimitByAPIKey(60/min) -> TenantTx -> audit -> handler
	//
	// Rationale:
	//   - RequireWrite (F15) keeps read-scoped (Viewer) API keys out of
	//     refresh / override.
	//   - RateLimitByAPIKey: 60 req/min on writes (same budget as CRA
	//     /decision and evidence-pack /build — refresh is a deliberate
	//     auditor-facing action, not a polling surface); 300 req/min on
	//     reads (matches the CRA /cra-reports list / get budget).
	//   - TenantTx wraps the rest so the refresh fan-out (27 Upserts +
	//     1 audit row) commits atomically with the audit trail, and the
	//     override (1 UPDATE + 1 audit row) honours the F5/F32 audit-
	//     or-nothing contract — audit failure inside the handler
	//     returns 500 so TenantTx rolls back the write.
	//   - audit middleware is the request-level path/method/latency
	//     trail; the domain-level meti_assessment_* audit rows the
	//     handler emits sit on top and capture the criterion-change
	//     details.
	e.GET("/api/v1/projects/:id/meti/assessment",
		metiHandler.ListAssessments,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.POST("/api/v1/projects/:id/meti/assessment/refresh",
		metiHandler.RefreshAssessment,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.PUT("/api/v1/projects/:id/meti/assessment/:criterion_id/override",
		metiHandler.OverrideAssessment,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)
	e.GET("/api/v1/projects/:id/meti/improvement-actions",
		metiHandler.ListImprovementActions,
		triageMultiAuth,
		appmw.RateLimitByAPIKey(rdb, 300, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)

	// Evidence Pack endpoint (Wave M2-6 / issue #34).
	//
	// POST /api/v1/projects/:id/evidence-pack/build renders a Markdown
	// bundle of approved VEX drafts + approved CRA reports + METI
	// placeholder. MVP is synchronous — the builder does ≤ 2 read
	// queries against repositories already cached on the request tx,
	// so even a project at the per-section cap (500 rows each) returns
	// in well under a second. PDF / Zip / background-job + separate
	// download endpoint ship in M3 (issue #34 Acceptance Criteria).
	//
	// Middleware chain mirrors the canonical pattern for write
	// endpoints: MultiAuth → RequireWrite → RateLimitByAPIKey →
	// TenantTx → audit → handler. Rationale:
	//   - RequireWrite: read-scoped (Viewer) API keys must not mint
	//     compliance packets for projects they only have read access to
	//     (see M1 #F15).
	//   - RateLimitByAPIKey: 60 req/min per API key matches the
	//     /cra-reports/decision rate — building a bundle is a deliberate
	//     auditor-facing action, not a polling surface.
	//   - TenantTx wraps the rest so the builder's vex_drafts +
	//     cra_reports SELECTs and the handler's audit_logs INSERT all
	//     share a single `SET LOCAL app.current_tenant_id` tx. Audit-row
	//     failure rolls the whole request back (#F5 fail-closed).
	e.POST("/api/v1/projects/:id/evidence-pack/build",
		evidencePackHandler.Build,
		triageMultiAuth,
		appmw.RequireWrite(),
		appmw.RateLimitByAPIKey(rdb, 60, time.Minute),
		appmw.TenantTx(db),
		auditMiddleware)

	// License policy endpoints
	auth.GET("/licenses/common", licensePolicyHandler.GetCommonLicenses)
	auth.GET("/projects/:id/licenses", licensePolicyHandler.List)
	auth.POST("/projects/:id/licenses", licensePolicyHandler.Create)
	auth.GET("/projects/:id/licenses/violations", licensePolicyHandler.CheckViolations)
	auth.GET("/projects/:id/licenses/:policy_id", licensePolicyHandler.Get)
	auth.PUT("/projects/:id/licenses/:policy_id", licensePolicyHandler.Update)
	auth.DELETE("/projects/:id/licenses/:policy_id", licensePolicyHandler.Delete)

	// M1 Codex review #F16: API-key management is admin-only across
	// every CRUD verb (LIST included). Previously the routes sat on
	// the bare `auth` group, so any authenticated tenant user — a
	// Member or even a Viewer with Clerk JWT auth — could mint a
	// write-capable sbh_... key for themselves and then bypass their
	// own role on every MultiAuth-fronted endpoint (F14 made the API
	// key path map to CanWrite). The escalation chain was
	// Viewer → POST /apikeys → sbh_... write key → triage/run /
	// SBOM upload as if they were a Member. RequireAdmin closes the
	// chain at the management routes themselves.
	//
	// LIST is also Admin-gated because the key metadata (name, last
	// used, expires) is itself an attack surface: a Member who can
	// enumerate the tenant's keys learns who has write access and
	// can target social-engineering attacks at those specific people.
	// The audit log of key creation events stays on the audit-logs
	// endpoint group (which has its own subscription gate).
	adminOnly := appmw.RequireAdmin()
	auth.GET("/apikeys", apiKeyHandler.ListTenant, adminOnly)
	auth.POST("/apikeys", apiKeyHandler.CreateTenant, adminOnly)
	auth.DELETE("/apikeys/:key_id", apiKeyHandler.DeleteTenant, adminOnly)

	// API key endpoints (project-level - deprecated, for backwards compatibility).
	// Same #F16 admin gate — the legacy path is not exempt: it issues
	// keys with the same TenantContext role mapping and the same
	// escalation vector once F14 made permissions live.
	auth.GET("/projects/:id/apikeys", apiKeyHandler.List, adminOnly)
	auth.POST("/projects/:id/apikeys", apiKeyHandler.Create, adminOnly)
	auth.DELETE("/projects/:id/apikeys/:key_id", apiKeyHandler.Delete, adminOnly)

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
