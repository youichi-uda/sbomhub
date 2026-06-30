// Package handler — Diff handler for M10-6 (issue #74) and M11-4 (issue #79).
//
// M10-6 surfaces the supply-chain churn observability service
// (internal/service/diff) at:
//
//	GET /api/v1/projects/:id/diff?from=<sbom_id>&to=<sbom_id>
//
// M11-4 extends with three additional surfaces driven from the same
// underlying diff envelope:
//
//	POST /api/v1/projects/:id/diff/summary?from=&to=&lang=ja|en
//	GET  /api/v1/projects/:id/diff.csv?from=&to=
//	GET  /api/v1/projects/:id/diff.pdf?from=&to=&lang=ja|en
//
// All four operate on the same (from, to) query string contract. Auth +
// tenant scoping is delegated to the surrounding `auth` middleware
// chain (Auth -> TenantTx -> audit) which binds ContextKeyTenantID and
// `SET LOCAL app.current_tenant_id` on the per-request Postgres
// transaction.
package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/diff_export"
	"github.com/sbomhub/sbomhub/internal/service/diff_summary"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// DiffAuditWriter is the slice of *repository.AuditRepository used by
// the M12-3 graph handler to record a `diff.graph.view` audit event
// per successful render. We narrow the interface here so the handler
// is unit-testable with a small fake (and so the handler does not
// reach for a repository field that may move package).
type DiffAuditWriter interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// DiffHandler exposes the M10-6 project diff endpoint, the M11-4
// summary / export endpoints, and the M12-3 graph endpoint.
type DiffHandler struct {
	svc        *diff.Service
	summarySvc *diff_summary.Service // optional (nil disables /diff/summary)
	exportSvc  *diff_export.Service  // optional (nil disables /diff.csv|pdf)
	audit      DiffAuditWriter       // optional (nil disables /diff/graph)
}

// NewDiffHandler wires the handler. The svc dependency is constructed
// in cmd/server/main.go alongside the rest of the service graph.
// summarySvc / exportSvc are optional — passing nil yields 503 from the
// corresponding routes so deployments without LLM / PDF support degrade
// gracefully.
func NewDiffHandler(svc *diff.Service) *DiffHandler {
	return &DiffHandler{svc: svc}
}

// WithSummary attaches the AI summary service. Returns the handler for
// fluent wiring.
func (h *DiffHandler) WithSummary(s *diff_summary.Service) *DiffHandler {
	h.summarySvc = s
	return h
}

// WithExport attaches the diff export (CSV + PDF) service.
func (h *DiffHandler) WithExport(s *diff_export.Service) *DiffHandler {
	h.exportSvc = s
	return h
}

// WithAudit attaches the audit log writer used by the M12-3
// /diff/graph endpoint to record a `diff.graph.view` event per
// successful render. Passing nil yields 503 from the graph route so
// the audit pair (F168 audit-or-nothing) is never silently skipped.
func (h *DiffHandler) WithAudit(a DiffAuditWriter) *DiffHandler {
	h.audit = a
	return h
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

// parseFromTo extracts the optional from / to query string params and
// applies the same UUID-parse rules ProjectDiff uses. Returns (zero,
// zero, nil) when both are missing.
func parseFromTo(c echo.Context) (uuid.UUID, uuid.UUID, error) {
	var from, to uuid.UUID
	if raw := c.QueryParam("from"); raw != "" {
		v, err := uuid.Parse(raw)
		if err != nil {
			return uuid.Nil, uuid.Nil, fmt.Errorf("invalid from sbom id")
		}
		from = v
	}
	if raw := c.QueryParam("to"); raw != "" {
		v, err := uuid.Parse(raw)
		if err != nil {
			return uuid.Nil, uuid.Nil, fmt.Errorf("invalid to sbom id")
		}
		to = v
	}
	return from, to, nil
}

// ProjectDiffSummary handles POST /api/v1/projects/:id/diff/summary.
//
// Generates an AI natural-language summary of the diff between the
// (from, to) SBOM pair. Non-idempotent (LLM call has cost), so POST.
//
//   - 400 invalid project id / invalid from-to / invalid lang
//   - 401 missing tenant context
//   - 404 project not owned by tenant / no SBOMs / sbom not in project
//   - 503 AI features disabled (llm.DisabledError) — UI shows the
//     deterministic placeholder envelope that the service still returns
//   - 500 everything else
//
// The successful path includes an llm_calls row + an
// audit_logs row (action=diff_summary_ai_generated) inside the request
// tenant tx so audit-or-nothing (M1 F5) holds.
func (h *DiffHandler) ProjectDiffSummary(c echo.Context) error {
	if h.summarySvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error":  "AI features are disabled",
			"reason": "diff summary service is not wired",
		})
	}
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	from, to, err := parseFromTo(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	lang := c.QueryParam("lang")
	if lang == "" {
		lang = c.QueryParam("locale")
	}

	// Optional user id from middleware (set by Auth / MultiAuth).
	var userPtr *uuid.UUID
	if uid, ok := c.Get(middleware.ContextKeyUserID).(uuid.UUID); ok && uid != uuid.Nil {
		userPtr = &uid
	}

	resp, err := h.summarySvc.Generate(c.Request().Context(), diff_summary.Request{
		TenantID:   tenantID,
		ProjectID:  projectID,
		UserID:     userPtr,
		FromSbomID: from,
		ToSbomID:   to,
		Lang:       lang,
	})
	if err != nil {
		// Diff-level errors share status codes with ProjectDiff above so
		// the UI can render consistent error banners.
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		case errors.Is(err, diff.ErrNoSboms):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project has no SBOMs to diff"})
		case errors.Is(err, diff.ErrSbomNotInProject):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom does not belong to project"})
		case errors.Is(err, diff.ErrNoNewerSbom):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "from sbom is already the newest in the project"})
		}
		var disabled *llm.DisabledError
		if errors.As(err, &disabled) {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{
				"error":  "AI features are disabled",
				"reason": disabled.Reason,
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, resp)
}

// ProjectDiffCSV handles GET /api/v1/projects/:id/diff.csv.
//
// Returns a CSV file with one row per added/removed/changed item.
// Columns: type, kind, name, version, from_version, to_version, purl,
// license, cve_id, severity, policy_name. Reuses the diff envelope —
// no LLM involvement.
func (h *DiffHandler) ProjectDiffCSV(c echo.Context) error {
	if h.exportSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "diff export service is not wired",
		})
	}
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	from, to, err := parseFromTo(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	data, filename, err := h.exportSvc.RenderCSV(c.Request().Context(), diff_export.Request{
		TenantID:   tenantID,
		ProjectID:  projectID,
		FromSbomID: from,
		ToSbomID:   to,
	})
	if err != nil {
		return mapDiffExportError(c, err)
	}
	c.Response().Header().Set("Content-Type", "text/csv; charset=utf-8")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	return c.Blob(http.StatusOK, "text/csv; charset=utf-8", data)
}

// ProjectDiffPDF handles GET /api/v1/projects/:id/diff.pdf.
//
// Returns a single-page PDF report with the diff summary header + 3
// tables (components / vulnerabilities / licenses). The optional `lang`
// query string toggles ja / en headings.
//
// The PDF does NOT include the AI summary — that path is gated on
// approval and is intentionally separate.
func (h *DiffHandler) ProjectDiffPDF(c echo.Context) error {
	if h.exportSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "diff export service is not wired",
		})
	}
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	from, to, err := parseFromTo(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	lang := c.QueryParam("lang")

	data, filename, err := h.exportSvc.RenderPDF(c.Request().Context(), diff_export.Request{
		TenantID:   tenantID,
		ProjectID:  projectID,
		FromSbomID: from,
		ToSbomID:   to,
		Lang:       lang,
	})
	if err != nil {
		return mapDiffExportError(c, err)
	}
	c.Response().Header().Set("Content-Type", "application/pdf")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	return c.Blob(http.StatusOK, "application/pdf", data)
}

// ProjectDiffGraph handles GET /api/v1/projects/:id/diff/graph.
//
// M12-3 (#84) — renders the dependency-graph view that complements
// the M10-6 flat-list diff. Re-parses the (from, to) SBOM raw bytes
// (CycloneDX `dependencies` block), merges them into a single graph
// keyed by the same componentMatchKey identity used by the flat
// diff, and annotates each node with added / removed / version_changed.
//
// Auth + tenant scoping go through the same middleware chain as
// ProjectDiff above. Every successful render writes an audit_logs
// row (action=`diff.graph.view`, resource_type=`sbom_diff`) inside
// the ambient TenantTx so the F168 audit-or-nothing contract holds
// — if the audit insert fails we fail the whole request rather than
// returning a render with no audit trail.
//
//   - 400 invalid project id / invalid from / invalid to
//   - 401 missing tenant context (auth middleware should already 401 first)
//   - 404 project not owned by tenant / no SBOMs / sbom not in project
//   - 503 audit writer not wired (deployment misconfiguration)
//   - 500 audit write failed / unexpected error
//   - 200 success
func (h *DiffHandler) ProjectDiffGraph(c echo.Context) error {
	if h.audit == nil {
		// Misconfiguration: graph endpoint requires audit so we fail
		// closed rather than serving a render without an audit row.
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "diff graph endpoint is not wired (audit writer missing)",
		})
	}
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	from, to, err := parseFromTo(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	req := diff.Request{
		TenantID:   tenantID,
		ProjectID:  projectID,
		FromSbomID: from,
		ToSbomID:   to,
	}
	resp, err := h.svc.ComputeGraph(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
		case errors.Is(err, diff.ErrNoSboms):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "project has no SBOMs to diff"})
		case errors.Is(err, diff.ErrSbomNotInProject):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom does not belong to project"})
		case errors.Is(err, diff.ErrNoNewerSbom):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "from sbom is already the newest in the project"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
	}

	// Audit-or-nothing (F168): record `diff.graph.view` BEFORE flushing
	// the response so a failed audit fails the whole request rather
	// than leaking a render with no audit trail. UserID is optional
	// (the middleware may not have set it on API-key paths).
	details := map[string]interface{}{
		"node_count": len(resp.Nodes),
		"edge_count": len(resp.Edges),
		"added":      len(resp.DiffStatus.Added),
		"removed":    len(resp.DiffStatus.Removed),
		"changed":    len(resp.DiffStatus.VersionChanged),
	}
	if resp.From != nil {
		details["from_sbom_id"] = resp.From.SbomID.String()
	}
	if resp.To != nil {
		details["to_sbom_id"] = resp.To.SbomID.String()
	}
	tID := tenantID
	pid := projectID
	auditInput := &model.CreateAuditLogInput{
		TenantID:     &tID,
		Action:       ActionDiffGraphView,
		ResourceType: diff_summary.ResourceTypeSbomDiff,
		ResourceID:   &pid,
		Details:      details,
	}
	if uid, ok := c.Get(middleware.ContextKeyUserID).(uuid.UUID); ok && uid != uuid.Nil {
		auditInput.UserID = &uid
	}
	if err := h.audit.Log(c.Request().Context(), auditInput); err != nil {
		// F168: do NOT swallow this. The audit log is the only durable
		// proof that the operator viewed the graph; a missing row would
		// silently break the audit chain.
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("audit write failed: %v", err),
		})
	}

	return c.JSON(http.StatusOK, resp)
}

// ActionDiffGraphView is the audit_logs.action emitted by
// ProjectDiffGraph on each successful render. Kept here next to the
// handler so the constant lives with its only emitter.
const ActionDiffGraphView = "diff.graph.view"

// mapDiffExportError centralises the error → HTTP mapping shared by the
// CSV + PDF handlers. Mirrors the ProjectDiff mapping.
func mapDiffExportError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "project not found"})
	case errors.Is(err, diff.ErrNoSboms):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "project has no SBOMs to diff"})
	case errors.Is(err, diff.ErrSbomNotInProject):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom does not belong to project"})
	case errors.Is(err, diff.ErrNoNewerSbom):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "from sbom is already the newest in the project"})
	}
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
