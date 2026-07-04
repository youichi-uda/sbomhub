package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
)

// impactService is the read-only surface GetCVEImpact needs from the impact
// service. Declared as an interface (satisfied by *service.ImpactService, which
// main.go still wires in unchanged) so the handler's error handling is
// unit-testable with a stub that returns a raw internal error — verifying that
// error never reaches the client verbatim (F396).
type impactService interface {
	GetCVEImpact(ctx context.Context, tenantID uuid.UUID, cveID string) (*model.CVEImpact, error)
}

type ImpactHandler struct {
	impactService impactService
}

func NewImpactHandler(is impactService) *ImpactHandler {
	return &ImpactHandler{impactService: is}
}

// GetCVEImpact handles GET /api/v1/vulnerabilities/:cve_id/impact — the
// read-only cross-project blast-radius view (M28-A / F388, issue #134).
//
// Tenant scope is taken from the auth context (populated by the auth
// middleware); the underlying aggregation runs inside the request TenantTx so
// it is RLS + belt tenant-scoped. This is a sibling of the existing
// /vulnerabilities/:cve_id/kev and /vulnerabilities/:cve_id/ipa metadata
// endpoints and, like them, adds no new audit action.
//
// Status codes:
//   - 200 with the impact payload (including an empty affected list + count 0
//     when the CVE is known but reaches no project — blast radius 0 is a valid
//     answer, not a 404);
//   - 404 when the CVE is unknown to this instance;
//   - 401 when no tenant context is present.
func (h *ImpactHandler) GetCVEImpact(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	cveID := c.Param("cve_id")
	if cveID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cve_id is required"})
	}

	impact, err := h.impactService.GetCVEImpact(c.Request().Context(), tenantID, cveID)
	if err != nil {
		// F396 (#134/#135): never surface the raw service / repository / SQL
		// error to the caller — it can carry driver text, scan errors
		// (e.g. "converting NULL to string is unsupported") or connection
		// details. Log the specifics server-side and return a stable generic
		// message, matching the settings_llm / billing handler convention.
		slog.Error("impact: get cve impact failed",
			"tenant_id", tenantID, "cve_id", cveID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get vulnerability impact",
		})
	}
	if impact == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "vulnerability not found: " + cveID})
	}

	return c.JSON(http.StatusOK, impact)
}
