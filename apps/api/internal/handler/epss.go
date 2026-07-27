package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/validation"
)

type EPSSHandler struct {
	epssService *service.EPSSService
}

func NewEPSSHandler(es *service.EPSSService) *EPSSHandler {
	return &EPSSHandler{epssService: es}
}

// SyncScores triggers EPSS score synchronization.
//
// The sync runs on a context with the request's transaction DETACHED (M46
// Codex final round, round 2 Medium). vulnerabilities is a global, non-tenant
// cache, and the job issues one independent UPDATE per CVE across many
// batches; inside the TenantTx that middleware opened, (a) returning an error
// for a late failed batch rolls back every batch that had already succeeded,
// and (b) a single failed statement aborts the Postgres transaction so all
// subsequent ones fail too — which would defeat the service's
// keep-going-and-report-at-the-end contract entirely. The scheduler runs the
// same job on a bare context; this makes the manual trigger equivalent. A
// non-nil error now means at least one batch did not apply, and the caller
// should retry rather than assume the sweep was complete.
func (h *EPSSHandler) SyncScores(c echo.Context) error {
	ctx := database.WithoutTx(c.Request().Context())
	if err := h.epssService.SyncScores(ctx); err != nil {
		// An INCOMPLETE sync is reported as 200 "partial", not 500. The sweep
		// is non-transactional by design (above), so the batches that already
		// applied are committed no matter what this returns — while a 5xx
		// WOULD roll back the request's own audit_logs row, which lives in
		// the TenantTx the audit middleware still holds. Answering 500 would
		// therefore destroy the only record that the sync ran, without
		// undoing any of its writes. The detail stays in the server log; the
		// body carries a machine-readable status only.
		if errors.Is(err, service.ErrEPSSSyncIncomplete) {
			slog.Warn("epss: sync completed with failed batches", "error", err)
			return c.JSON(http.StatusOK, map[string]string{
				"status":  "partial",
				"message": "some batches did not fully apply; retry the sync",
			})
		}
		slog.Warn("epss: sync scores failed", "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to sync EPSS scores"})
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "sync completed"})
}

// GetScore gets EPSS score for a specific CVE
func (h *EPSSHandler) GetScore(c echo.Context) error {
	cveID, err := validation.ValidateCVEID(c.Param("cve_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid CVE ID format"})
	}

	score, err := h.epssService.GetScore(c.Request().Context(), cveID)
	if err != nil {
		slog.Warn("epss: get score failed", "cve_id", cveID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get EPSS score"})
	}
	if score == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "EPSS score not found"})
	}

	// GetScore's contract: a returned entry always has Score != nil (a CVE
	// whose score FIRST served malformed answers 404 above, same as one
	// FIRST did not return at all). Percentile may be nil — FIRST served a
	// malformed percentile alongside a valid score — and marshals as JSON
	// null rather than a fabricated 0.
	return c.JSON(http.StatusOK, map[string]interface{}{
		"cve_id":     cveID,
		"score":      score.Score,
		"percentile": score.Percentile,
	})
}
