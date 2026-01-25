package main

import (
	"log/slog"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/handler"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()

	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

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

	// Services
	projectService := service.NewProjectService(projectRepo)
	sbomService := service.NewSbomService(sbomRepo, componentRepo)
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

	// Handlers
	projectHandler := handler.NewProjectHandler(projectService)
	sbomHandler := handler.NewSbomHandler(sbomService)
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

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://localhost:13000", "http://localhost:*"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
	}))

	api := e.Group("/api/v1")

	api.GET("/health", func(c echo.Context) error {
		return c.JSON(200, map[string]string{"status": "ok"})
	})
	api.GET("/stats", statsHandler.Get)

	// Dashboard endpoints
	api.GET("/dashboard/summary", dashboardHandler.GetSummary)

	// Search endpoints
	api.GET("/search/cve", searchHandler.SearchByCVE)
	api.GET("/search/component", searchHandler.SearchByComponent)

	// EPSS endpoints
	api.POST("/vulnerabilities/sync-epss", epssHandler.SyncScores)
	api.GET("/vulnerabilities/epss/:cve_id", epssHandler.GetScore)

	// Project endpoints
	api.POST("/projects", projectHandler.Create)
	api.GET("/projects", projectHandler.List)
	api.GET("/projects/:id", projectHandler.Get)
	api.DELETE("/projects/:id", projectHandler.Delete)

	// SBOM endpoints
	api.POST("/projects/:id/sbom", sbomHandler.Upload)
	api.GET("/projects/:id/sbom", sbomHandler.Get)
	api.GET("/projects/:id/components", sbomHandler.GetComponents)
	api.GET("/projects/:id/vulnerabilities", sbomHandler.GetVulnerabilities)
	api.POST("/projects/:id/scan", vulnHandler.Scan)

	// VEX endpoints
	api.GET("/projects/:id/vex", vexHandler.List)
	api.POST("/projects/:id/vex", vexHandler.Create)
	api.GET("/projects/:id/vex/export", vexHandler.Export)
	api.GET("/projects/:id/vex/:vex_id", vexHandler.Get)
	api.PUT("/projects/:id/vex/:vex_id", vexHandler.Update)
	api.DELETE("/projects/:id/vex/:vex_id", vexHandler.Delete)

	// License policy endpoints
	api.GET("/licenses/common", licensePolicyHandler.GetCommonLicenses)
	api.GET("/projects/:id/licenses", licensePolicyHandler.List)
	api.POST("/projects/:id/licenses", licensePolicyHandler.Create)
	api.GET("/projects/:id/licenses/violations", licensePolicyHandler.CheckViolations)
	api.GET("/projects/:id/licenses/:policy_id", licensePolicyHandler.Get)
	api.PUT("/projects/:id/licenses/:policy_id", licensePolicyHandler.Update)
	api.DELETE("/projects/:id/licenses/:policy_id", licensePolicyHandler.Delete)

	// API key endpoints
	api.GET("/projects/:id/apikeys", apiKeyHandler.List)
	api.POST("/projects/:id/apikeys", apiKeyHandler.Create)
	api.DELETE("/projects/:id/apikeys/:key_id", apiKeyHandler.Delete)

	// Notification endpoints
	api.GET("/projects/:id/notifications", notificationHandler.GetSettings)
	api.PUT("/projects/:id/notifications", notificationHandler.UpdateSettings)
	api.POST("/projects/:id/notifications/test", notificationHandler.TestNotification)
	api.GET("/projects/:id/notifications/logs", notificationHandler.GetLogs)

	// Compliance endpoints
	api.GET("/projects/:id/compliance", complianceHandler.Check)
	api.GET("/projects/:id/compliance/report", complianceHandler.ExportReport)

	slog.Info("Starting server", "port", cfg.Port)
	e.Logger.Fatal(e.Start(":" + cfg.Port))
}
