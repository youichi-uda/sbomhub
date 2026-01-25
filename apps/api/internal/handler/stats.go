package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type StatsHandler struct {
	statsService *service.StatsService
}

func NewStatsHandler(ss *service.StatsService) *StatsHandler {
	return &StatsHandler{statsService: ss}
}

func (h *StatsHandler) Get(c echo.Context) error {
	stats, err := h.statsService.GetStats(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, stats)
}
