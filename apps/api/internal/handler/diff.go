// Package handler — Diff handler for M10-6 (issue #74).
//
// Surfaces the supply-chain churn observability service
// (internal/service/diff) at:
//
//	GET /api/v1/projects/:id/diff?from=<sbom_id>&to=<sbom_id>
//
// Both from and to are optional. See diff.Service.Compute godoc for the
// resolution semantics. Auth + tenant scoping is delegated to the
// surrounding `auth` middleware chain (Auth -> TenantTx -> audit) which
// binds ContextKeyTenantID and `SET LOCAL app.current_tenant_id` on the
// per-request Postgres transaction.
package handler

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service/diff"
)

// DiffHandler exposes the M10-6 project diff endpoint.
type DiffHandler struct {
	svc *diff.Service
}

// NewDiffHandler wires the handler. The svc dependency is constructed
// in cmd/server/main.go alongside the rest of the service graph.
func NewDiffHandler(svc *diff.Service) *DiffHandler {
	return &DiffHandler{svc: svc}
}

// ProjectDiff handles GET /api/v1/projects/:id/diff.
//
//   - 400 invalid project id / invalid from / invalid to
//   - 401 missing tenant context (auth middleware should already 401 first)
//   - 404 project not owned by tenant / no SBOMs in project / sbom not in project
//   - 200 success
func (h *DiffHandler) ProjectDiff(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	req := diff.Request{
		TenantID:  tenantID,
		ProjectID: projectID,
	}
	if raw := c.QueryParam("from"); raw != "" {
		fromID, err := uuid.Parse(raw)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid from sbom id"})
		}
		req.FromSbomID = fromID
	}
	if raw := c.QueryParam("to"); raw != "" {
		toID, err := uuid.Parse(raw)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid to sbom id"})
		}
		req.ToSbomID = toID
	}

	resp, err := h.svc.Compute(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// projectRepo.GetByTenant returned no rows — either the project
			// id is bogus or the tenant does not own it. Either way, 404
			// (do not leak the distinction).
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		case errors.Is(err, diff.ErrNoSboms):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project has no SBOMs to diff"})
		case errors.Is(err, diff.ErrSbomNotInProject):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom does not belong to project"})
		case errors.Is(err, diff.ErrNoNewerSbom):
			// F166: from is already the newest SBOM — no successor to
			// default `to` to. Return 400 (request is structurally
			// fine; project state has no newer revision) so the UI
			// renders an "already most recent" empty state instead of
			// the generic 500.
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "from sbom is already the newest in the project"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
	}

	return c.JSON(http.StatusOK, resp)
}
