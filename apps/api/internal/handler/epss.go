package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type EPSSHandler struct {
	epssService *service.EPSSService
}

func NewEPSSHandler(es *service.EPSSService) *EPSSHandler {
	return &EPSSHandler{epssService: es}
}

// SyncScores triggers EPSS score synchronization
func (h *EPSSHandler) SyncScores(c echo.Context) error {
	if err := h.epssService.SyncScores(c.Request().Context()); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "sync completed"})
}

// GetScore gets EPSS score for a specific CVE
func (h *EPSSHandler) GetScore(c echo.Context) error {
	cveID := c.Param("cve_id")
	if cveID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cve_id is required"})
	}

	score, err := h.epssService.GetScore(c.Request().Context(), cveID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if score == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "EPSS score not found"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"cve_id":     cveID,
		"score":      score.Score,
		"percentile": score.Percentile,
	})
}
