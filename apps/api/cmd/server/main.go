package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/handler"
	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/redis"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/scheduler"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/migrations"
)

func main() {
	// Load .env file if it exists (for local development)
	_ = godotenv.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	// SECURITY: Validate configuration before starting
	if err := cfg.Validate(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Run migrations automatically on startup
	if err := database.Migrate(db, migrations.FS); err != nil {
		slog.Error("Failed to run migrations", "error", err)
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

	// Services
	projectService := service.NewProjectService(projectRepo)
	sbomService := service.NewSbomService(sbomRepo, componentRepo)
	sbomDiffService := service.NewSbomDiffService(sbomRepo, componentRepo)
	nvdService := service.NewNVDService(vulnRepo, componentRepo, cfg.NVDAPIKey)
	jvnService := service.NewJVNService(vulnRepo, componentRepo)
	statsService := service.NewStatsService(statsRepo)
	vexService := service.NewVEXService(vexRepo, vulnRepo)
	licensePolicyService := service.NewLicensePolicyService(licensePolicyRepo, componentRepo)
	apiKeyService := service.NewAPIKeyService(apiKeyRepo)
	dashboardService := service.NewDashboardService(dashboardRepo)
	searchService := service.NewSearchService(searchRepo)
	epssService := service.NewEPSSService(vulnRepo)
	notificationService := service.NewNotificationService(notificationRepo, projectRepo, cfg)
	complianceService := service.NewComplianceServiceFull(sbomRepo, componentRepo, vulnRepo, vexRepo, licensePolicyRepo, dashboardRepo, checklistRepo, visualizationRepo, publicLinkRepo)
	publicLinkService := service.NewPublicLinkService(publicLinkRepo, projectRepo, sbomRepo, componentRepo)
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

	// Handlers
	projectHandler := handler.NewProjectHandler(projectService)
	sbomHandler := handler.NewSbomHandler(sbomService, nvdService, jvnService)
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
	mcp := api.Group("/mcp",
		appmw.APIKeyAuth(apiKeyService),
		appmw.APIKeyTenant(projectRepo, tenantRepo),
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
	cli := api.Group("/cli",
		appmw.APIKeyAuth(apiKeyService),
		appmw.APIKeyTenant(projectRepo, tenantRepo),
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

	// Authenticated endpoints with audit logging
	auth := api.Group("", authMiddleware, auditMiddleware)

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
	auth.POST("/projects/:id/sbom", sbomHandler.Upload)
	auth.GET("/projects/:id/sbom", sbomHandler.Get)
	auth.GET("/projects/:id/sboms", sbomHandler.List)
	auth.GET("/projects/:id/components", sbomHandler.GetComponents)
	auth.GET("/projects/:id/vulnerabilities", sbomHandler.GetVulnerabilities)
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

	// Ticket sync job - runs every 5 minutes to sync ticket statuses with Jira/Backlog
	ticketSyncJob := scheduler.NewTicketSyncJob(issueTrackerService, issueTrackerRepo, 5*time.Minute)
	go ticketSyncJob.Start(ctx)
	slog.Info("Ticket sync job started", "interval", "5m")

	// Report generation job - runs every hour to check scheduled reports
	reportGenJob := scheduler.NewReportGenerationJob(reportService, reportRepo, tenantRepo, 1*time.Hour)
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

	slog.Info("Starting server", "port", cfg.Port)
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
