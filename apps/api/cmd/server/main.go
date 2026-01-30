package main

import (
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
	"github.com/sbomhub/sbomhub/internal/service"
)

func main() {
	// Load .env file if it exists (for local development)
	_ = godotenv.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

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

	// SaaS Repositories
	tenantRepo := repository.NewTenantRepository(db)
	userRepo := repository.NewUserRepository(db)
	subscriptionRepo := repository.NewSubscriptionRepository(db)
	auditRepo := repository.NewAuditRepository(db)
	analyticsRepo := repository.NewAnalyticsRepository(db)
	reportRepo := repository.NewReportRepository(db)
	ipaRepo := repository.NewIPARepository(db)
	issueTrackerRepo := repository.NewIssueTrackerRepository(db)

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
	notificationService := service.NewNotificationService(notificationRepo, projectRepo, cfg.BaseURL)
	complianceService := service.NewComplianceService(sbomRepo, componentRepo, vulnRepo, vexRepo, licensePolicyRepo, dashboardRepo)
	publicLinkService := service.NewPublicLinkService(publicLinkRepo, projectRepo, sbomRepo, componentRepo)
	auditService := service.NewAuditService(auditRepo, userRepo)
	analyticsService := service.NewAnalyticsService(analyticsRepo, dashboardRepo)
	reportService := service.NewReportService(reportRepo, dashboardRepo, analyticsRepo, tenantRepo, "./reports")
	ipaService := service.NewIPAService(ipaRepo)
	issueTrackerService := service.NewIssueTrackerService(issueTrackerRepo, vulnRepo, cfg.EncryptionKey)

	// Handlers
	projectHandler := handler.NewProjectHandler(projectService)
	sbomHandler := handler.NewSbomHandler(sbomService)
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

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://localhost:13000", "http://localhost:*", "https://sbomhub.app"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization, "X-Clerk-Org-ID"},
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

	// Public link endpoints
	auth.POST("/projects/:id/public-links", publicLinkHandler.Create)
	auth.GET("/projects/:id/public-links", publicLinkHandler.List)
	auth.PUT("/public-links/:id", publicLinkHandler.Update)
	auth.DELETE("/public-links/:id", publicLinkHandler.Delete)

	// Audit log endpoints
	auth.GET("/audit-logs", auditHandler.List)
	auth.GET("/audit-logs/export", auditHandler.Export)
	auth.GET("/audit-logs/statistics", auditHandler.GetStatistics)
	auth.GET("/audit-logs/actions", auditHandler.GetActions)
	auth.GET("/audit-logs/resource-types", auditHandler.GetResourceTypes)

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

	// Issue tracker integration endpoints
	auth.POST("/integrations", issueTrackerHandler.CreateConnection)
	auth.GET("/integrations", issueTrackerHandler.ListConnections)
	auth.GET("/integrations/:id", issueTrackerHandler.GetConnection)
	auth.DELETE("/integrations/:id", issueTrackerHandler.DeleteConnection)
	auth.POST("/vulnerabilities/:vuln_id/ticket", issueTrackerHandler.CreateTicket)
	auth.GET("/vulnerabilities/:vuln_id/tickets", issueTrackerHandler.GetTicketsByVulnerability)
	auth.GET("/tickets", issueTrackerHandler.ListTickets)
	auth.POST("/tickets/:id/sync", issueTrackerHandler.SyncTicket)

	slog.Info("Starting server", "port", cfg.Port)
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
