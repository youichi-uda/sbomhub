package handler

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type SbomHandler struct {
	sbomService *service.SbomService
	nvdService  *service.NVDService
	jvnService  *service.JVNService
}

func NewSbomHandler(ss *service.SbomService, nvd *service.NVDService, jvn *service.JVNService) *SbomHandler {
	return &SbomHandler{
		sbomService: ss,
		nvdService:  nvd,
		jvnService:  jvn,
	}
}

func (h *SbomHandler) Upload(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
	}

	sbom, err := h.sbomService.Import(c.Request().Context(), projectID, body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Start vulnerability scan in background
	h.startBackgroundScan(sbom.ID)

	return c.JSON(http.StatusCreated, sbom)
}

// startBackgroundScan initiates vulnerability scanning in the background
func (h *SbomHandler) startBackgroundScan(sbomID uuid.UUID) {
	go func() {
		ctx := context.Background()

		// Scan with NVD
		if h.nvdService != nil {
			if err := h.nvdService.ScanComponents(ctx, sbomID); err != nil {
				slog.Error("Auto NVD scan failed", "sbom_id", sbomID, "error", err)
			} else {
				slog.Info("Auto NVD scan completed", "sbom_id", sbomID)
			}
		}

		// Scan with JVN
		if h.jvnService != nil {
			if err := h.jvnService.ScanComponents(ctx, sbomID); err != nil {
				slog.Error("Auto JVN scan failed", "sbom_id", sbomID, "error", err)
			} else {
				slog.Info("Auto JVN scan completed", "sbom_id", sbomID)
			}
		}
	}()
}

func (h *SbomHandler) Get(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	sbom, err := h.sbomService.GetLatest(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom not found"})
	}

	return c.JSON(http.StatusOK, sbom)
}

func (h *SbomHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	sboms, err := h.sbomService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, sboms)
}

func (h *SbomHandler) GetComponents(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	components, err := h.sbomService.GetComponents(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, components)
}

func (h *SbomHandler) GetVulnerabilities(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	vulns, err := h.sbomService.GetVulnerabilities(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, vulns)
}
