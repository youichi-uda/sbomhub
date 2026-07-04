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

// cvePathsService is the read-only surface GetCVEPaths needs from the paths
// service. Declared as an interface (satisfied by *service.CVEPathsService,
// which main.go wires in) so the handler's error handling is unit-testable
// with a stub that returns a raw internal error — verifying that error never
// reaches the client verbatim (F396).
type cvePathsService interface {
	GetCVEPaths(ctx context.Context, tenantID uuid.UUID, cveID string) (*model.CVEPathsResponse, error)
}

type CVEPathsHandler struct {
	svc cvePathsService
}

func NewCVEPathsHandler(svc cvePathsService) *CVEPathsHandler {
	return &CVEPathsHandler{svc: svc}
}

// GetCVEPaths handles GET /api/v1/vulnerabilities/:cve_id/paths — the
// read-only cross-project transitive dependency-path view (M30-A / F402,
// issue #138). It is the on-demand sibling of the M28
// /vulnerabilities/:cve_id/impact blast-radius endpoint: same Auth → TenantTx
// chain, same tenant scoping, and — like it — NO new audit action (a
// read-only GET; the /vulnerabilities GET fallthrough classifies it as
// vulnerability.viewed, mirroring /impact, so WithAudit is not used).
//
// Status codes (identical contract to GetCVEImpact):
//   - 200 with the paths payload (including an empty affected list + count 0
//     when the CVE is known but reaches no project — a blast radius of 0 is a
//     valid answer, not a 404, and is kept distinct from a broken endpoint);
//   - 404 when the CVE is unknown to this instance;
//   - 401 when no tenant context is present;
//   - 500 on any unexpected error, with a STABLE GENERIC message — the raw
//     service / repository / SQL error is logged server-side only (F396: never
//     leak driver text, scan errors or connection details to the caller).
func (h *CVEPathsHandler) GetCVEPaths(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	cveID := c.Param("cve_id")
	if cveID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cve_id is required"})
	}

	paths, err := h.svc.GetCVEPaths(c.Request().Context(), tenantID, cveID)
	if err != nil {
		// F396: never surface the raw service / repository / SQL error to the
		// caller — log the specifics server-side, return a stable generic
		// message (matching the GetCVEImpact / settings_llm convention).
		slog.Error("impact: get cve paths failed",
			"tenant_id", tenantID, "cve_id", cveID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to get vulnerability paths",
		})
	}
	if paths == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "vulnerability not found: " + cveID})
	}

	return c.JSON(http.StatusOK, paths)
}
