package handler

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type SbomDiffHandler struct {
	diffService *service.SbomDiffService
}

func NewSbomDiffHandler(ds *service.SbomDiffService) *SbomDiffHandler {
	return &SbomDiffHandler{diffService: ds}
}

type sbomDiffRequest struct {
	BaseSbomID   string `json:"base_sbom_id"`
	TargetSbomID string `json:"target_sbom_id"`
}

func (h *SbomDiffHandler) Diff(c echo.Context) error {
	var req sbomDiffRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	baseID, err := uuid.Parse(req.BaseSbomID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid base sbom id"})
	}
	targetID, err := uuid.Parse(req.TargetSbomID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid target sbom id"})
	}
	if baseID == targetID {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "base and target sbom must be different"})
	}

	diff, err := h.diffService.Diff(c.Request().Context(), service.SbomDiffRequest{
		BaseSbomID:   baseID,
		TargetSbomID: targetID,
	})
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, diff)
}
