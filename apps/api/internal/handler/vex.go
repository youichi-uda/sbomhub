package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// VEXAuditLogger is the subset of *repository.AuditRepository the Apply
// endpoint uses to emit the vex_statement_reused_cross_project audit row
// (M27-A / F381, issue #132). Same shape / rationale as CRAAuditLogger in
// cra_reports.go: an interface so vex_apply_test.go can substitute a fake
// without a live audit repository.
type VEXAuditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// vexApplyService is the subset of *service.VEXService the Apply endpoint
// uses. Declared as an interface so vex_apply_test.go can substitute a fake
// and assert the audit-or-nothing emit + 409/400 mapping without a live DB.
// In production it is the same *service.VEXService held in vexService.
type vexApplyService interface {
	ApplySuggestion(ctx context.Context, in service.ApplySuggestionInput) (*service.VEXApplyResult, error)
}

// vexWriteService is the subset of *service.VEXService the Create/Update
// endpoints use. Declared as an interface (like vexApplyService) so
// vex_test.go can substitute a fake and assert the F443 validation-vs-
// internal HTTP status split (400 for ValidationErrorf, 500 for a
// %w-wrapped DB error) without a live DB. In production it is the same
// *service.VEXService held in vexService.
type vexWriteService interface {
	CreateStatement(ctx context.Context, input service.CreateVEXStatementInput) (*model.VEXStatement, error)
	UpdateStatement(ctx context.Context, id uuid.UUID, input service.UpdateVEXStatementInput) (*model.VEXStatement, error)
}

type VEXHandler struct {
	vexService *service.VEXService
	// applier drives the cross-project apply flow; it is vexService in
	// production and a fake in the audit unit test.
	applier vexApplyService
	// writer drives the Create/Update statement flow; it is vexService in
	// production and a fake in the F443 status-split unit test.
	writer vexWriteService
	// audit is the writer for the vex_statement_reused_cross_project row.
	// May be nil for the legacy handler construction paths that never call
	// Apply (Create/Update/List/etc. do not touch it).
	audit VEXAuditLogger
}

// NewVEXHandler wires the handler. audit is required for the M27 Apply
// endpoint's audit-or-nothing emit; the other endpoints do not use it.
func NewVEXHandler(vexService *service.VEXService, audit VEXAuditLogger) *VEXHandler {
	return &VEXHandler{vexService: vexService, applier: vexService, writer: vexService, audit: audit}
}

type CreateVEXRequest struct {
	VulnerabilityID string `json:"vulnerability_id"`
	ComponentID     string `json:"component_id,omitempty"`
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Create creates a new VEX statement
func (h *VEXHandler) Create(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	var req CreateVEXRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	vulnID, err := uuid.Parse(req.VulnerabilityID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid vulnerability ID"})
	}

	var compID *uuid.UUID
	if req.ComponentID != "" {
		parsed, err := uuid.Parse(req.ComponentID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid component ID"})
		}
		compID = &parsed
	}

	// Get authenticated user from context
	auth := middleware.GetAuthContext(c)
	user, ok := c.Get(middleware.ContextKeyUser).(*model.User)
	if !ok && c.Get(middleware.ContextKeyUser) != nil {
		// Log unexpected type in context (helps debug middleware issues)
		slog.Warn("context value for user is not of expected type",
			"actual_type", fmt.Sprintf("%T", c.Get(middleware.ContextKeyUser)))
	}
	createdBy := "system"
	if user != nil && user.Email != "" {
		createdBy = user.Email
	} else if auth != nil && auth.ClerkUserID != "" {
		createdBy = auth.ClerkUserID
	}

	input := service.CreateVEXStatementInput{
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		ComponentID:     compID,
		Status:          model.VEXStatus(req.Status),
		Justification:   model.VEXJustification(req.Justification),
		ActionStatement: req.ActionStatement,
		ImpactStatement: req.ImpactStatement,
		CreatedBy:       createdBy,
	}

	statement, err := h.writer.CreateStatement(c.Request().Context(), input)
	if err != nil {
		// F443: split the blanket 400. CreateStatement mixes self-authored
		// validation feedback (bad status, missing justification, duplicate,
		// non-owned component) with %w-wrapped DB errors. Only the former is
		// safe to echo at 400; a DB fault is a 500 with a generic body and the
		// raw error kept in the server log.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("vex: create statement failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save VEX statement"})
	}

	// F208 / M14-1: publish the newly-minted VEX UUID so the audit
	// middleware records audit_logs.resource_id = statement.ID instead
	// of the parent project UUID. POST /projects/:id/vex has :id in
	// the path, so without this override the resourceIDParamPriority
	// list would record the project UUID and forensic joins to
	// vex_statements would silently drop.
	if statement != nil {
		middleware.SetAuditResourceID(c, statement.ID)
	}

	return c.JSON(http.StatusCreated, statement)
}

type UpdateVEXRequest struct {
	Status          string `json:"status"`
	Justification   string `json:"justification,omitempty"`
	ActionStatement string `json:"action_statement,omitempty"`
	ImpactStatement string `json:"impact_statement,omitempty"`
}

// Update updates a VEX statement
func (h *VEXHandler) Update(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	var req UpdateVEXRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	input := service.UpdateVEXStatementInput{
		Status:          model.VEXStatus(req.Status),
		Justification:   model.VEXJustification(req.Justification),
		ActionStatement: req.ActionStatement,
		ImpactStatement: req.ImpactStatement,
	}

	statement, err := h.writer.UpdateStatement(c.Request().Context(), vexID, input)
	if err != nil {
		// F443: split the blanket 400 (see Create). UpdateStatement mixes
		// validation feedback (not found, bad status, missing justification)
		// with %w-wrapped DB errors; only validation is echoed at 400, a DB
		// fault is a generic 500 with the raw error in the server log.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("vex: update statement failed", "vex_id", vexID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save VEX statement"})
	}

	return c.JSON(http.StatusOK, statement)
}

// List returns all VEX statements for a project
func (h *VEXHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	statements, err := h.vexService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list VEX statements"})
	}

	if statements == nil {
		statements = []model.VEXStatementWithDetails{}
	}

	return c.JSON(http.StatusOK, statements)
}

// GetSuggestions returns cross-project VEX reuse suggestions for a project
// (M26-A / F375, issue #130): approved vex_statements from OTHER projects
// of the same tenant that match a vulnerability affecting this project's
// components. This endpoint only reads, so it is a plain GET; reuse is the
// separate human-confirmed POST .../vex/suggestions/apply (Apply, F381).
//
// Auth / tenant scope mirrors the project-scoped VEX List above: the
// request already passed the auth → TenantTx chain, so ContextKeyTenantID
// is bound and every downstream query runs under SET LOCAL
// app.current_tenant_id. The tenant id is also passed explicitly to the
// service so the aggregation query carries a defence-in-depth
// `tenant_id = $1` predicate on top of RLS.
//
// No new audit action is emitted: this is a read, and the request-level
// audit middleware already records path + method + latency. Adding a
// bespoke action here would (needlessly) touch the F281/F271 audit-parity
// surface, which the M26 scope deliberately avoids.
func (h *VEXHandler) GetSuggestions(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	suggestions, err := h.vexService.GetSuggestions(c.Request().Context(), tenantID, projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list VEX suggestions"})
	}

	if suggestions == nil {
		suggestions = []model.VEXSuggestion{}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{"suggestions": suggestions})
}

// ApplyVEXRequest is the POST body for the cross-project VEX reuse apply
// endpoint (M27-A / F381, issue #132). All three ids come from an M26
// suggestion the human 1-click confirmed:
//   - source_statement_id: the approved statement (in another project of
//     the same tenant) being reused — the provenance anchor;
//   - vulnerability_id: the vulnerability the suggestion is about (used to
//     re-verify the match server-side);
//   - component_id: the TARGET project's component the reuse applies to
//     (the suggestion's Component.ComponentID, F377).
type ApplyVEXRequest struct {
	SourceStatementID string `json:"source_statement_id"`
	VulnerabilityID   string `json:"vulnerability_id"`
	ComponentID       string `json:"component_id"`
}

// ApplyVEXProvenance is the provenance block of the 201 response.
type ApplyVEXProvenance struct {
	SourceStatementID uuid.UUID `json:"source_statement_id"`
	SourceProjectID   uuid.UUID `json:"source_project_id"`
	AppliedAt         string    `json:"applied_at"`
}

// ApplyVEXResponse is the 201 body: the newly-created target statement plus
// its provenance.
type ApplyVEXResponse struct {
	Statement  *model.VEXStatement `json:"statement"`
	Provenance ApplyVEXProvenance  `json:"provenance"`
}

// Apply materialises a cross-project VEX reuse suggestion into the target
// project (M27-A / F381, issue #132). A human has 1-click confirmed the
// suggestion (the "Humans approve" product principle — auto-apply is
// forbidden), and this copies the approved judgement from another project
// of the same tenant into a NEW vex_statements row here, records provenance,
// and emits a vex_statement_reused_cross_project audit row.
//
// The route is registered under the TenantTx-wrapped `auth` group
// (cmd/server/main.go), so the source resolve, the CreateStatement INSERT,
// the provenance INSERT, and the audit INSERT all run in ONE transaction;
// the audit-or-nothing hard-fail below returns 500 on audit error, which
// rolls the whole thing back (F32 / M1 F5 precedent).
//
// Security: the service re-verifies the M26 match (verifySuggestionMatch)
// so a client cannot inject an arbitrary status onto an arbitrary component
// by pairing a real source id with a mismatched component id — that path
// returns ErrVEXApplyMatchFailed → 400 here.
func (h *VEXHandler) Apply(c echo.Context) error {
	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok || tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	var req ApplyVEXRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	sourceStatementID, err := uuid.Parse(req.SourceStatementID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid source_statement_id"})
	}
	vulnID, err := uuid.Parse(req.VulnerabilityID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid vulnerability_id"})
	}
	componentID, err := uuid.Parse(req.ComponentID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid component_id"})
	}

	// Resolve the applier identity. createdBy is the human-readable
	// vex_statements.created_by (email / clerk id / "system"), mirroring
	// Create; appliedBy is the user UUID for provenance.applied_by (nil for
	// self-hosted requests without one).
	auth := middleware.GetAuthContext(c)
	user, _ := c.Get(middleware.ContextKeyUser).(*model.User)
	createdBy := "system"
	if user != nil && user.Email != "" {
		createdBy = user.Email
	} else if auth != nil && auth.ClerkUserID != "" {
		createdBy = auth.ClerkUserID
	}
	var appliedBy *uuid.UUID
	if uid := middleware.GetUserID(c); uid != uuid.Nil {
		appliedBy = &uid
	}

	result, err := h.applier.ApplySuggestion(c.Request().Context(), service.ApplySuggestionInput{
		TenantID:          tenantID,
		ProjectID:         projectID,
		SourceStatementID: sourceStatementID,
		TargetComponentID: componentID,
		VulnerabilityID:   vulnID,
		AppliedBy:         appliedBy,
		CreatedBy:         createdBy,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrVEXApplyAlreadyTriaged):
			// Idempotency: never silently overwrite an existing decision
			// (CRA Decide 409 precedent).
			return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
		case errors.Is(err, service.ErrVEXApplySourceNotFound),
			errors.Is(err, service.ErrVEXApplyMatchFailed):
			// Validation / injection guard: source not visible to the
			// tenant, or the re-verified M26 match failed (mismatched
			// vulnerability, mismatched / non-owned component, or purl
			// mismatch). Every client-caused rejection is one of these
			// sentinels, so a 400 here never masks a genuine fault.
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			// Genuine internal fault (DB error, or a should-never-happen
			// invariant violation from CreateStatement). 500 so the ambient
			// TenantTx rolls the partial work back.
			slog.Error("vex apply: internal error", "tenant_id", tenantID, "project_id", projectID,
				"source_statement_id", sourceStatementID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to apply VEX suggestion"})
		}
	}

	statement := result.Statement

	// F208 / M14-1 parity: publish the new VEX UUID so the request-level
	// audit middleware records audit_logs.resource_id = statement.ID rather
	// than the parent project UUID (POST /projects/:id/... has :id in the
	// path). The domain audit row below sets resource_id explicitly too.
	middleware.SetAuditResourceID(c, statement.ID)

	// Domain audit row (vex_statement_reused_cross_project), audit-or-
	// nothing: a failure here hard-fails 500 so the ambient TenantTx rolls
	// back the statement + provenance INSERTs. The compliance record of a
	// reused decision MUST land atomically with the decision itself (F32 /
	// M1 F5 precedent). Details carries the source attribution + match_type
	// so the reuse is reconstructable even after the CASCADE-reaped
	// vex_statement_provenance row is gone.
	if h.audit != nil {
		auditDetails := map[string]interface{}{
			"source_statement_id": sourceStatementID.String(),
			"source_project_id":   result.SourceProjectID.String(),
			"vulnerability_id":    vulnID.String(),
			"component_id":        componentID.String(),
			"match_type":          result.MatchType,
		}
		rid := statement.ID
		if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
			TenantID:     &tenantID,
			UserID:       appliedBy,
			Action:       model.AuditActionVEXReusedCrossProject,
			ResourceType: model.ResourceVEX,
			ResourceID:   &rid,
			Details:      auditDetails,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}); err != nil {
			slog.Error("vex apply: domain audit log failed; rolling back reuse (audit-or-nothing)",
				"tenant_id", tenantID, "project_id", projectID, "statement_id", statement.ID, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to persist VEX reuse audit trail; reuse rolled back",
			})
		}
	}

	return c.JSON(http.StatusCreated, ApplyVEXResponse{
		Statement: statement,
		Provenance: ApplyVEXProvenance{
			SourceStatementID: sourceStatementID,
			SourceProjectID:   result.SourceProjectID,
			AppliedAt:         result.AppliedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		},
	})
}

// Get returns a specific VEX statement
func (h *VEXHandler) Get(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	statement, err := h.vexService.GetStatement(c.Request().Context(), vexID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get VEX statement"})
	}
	if statement == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "VEX statement not found"})
	}

	return c.JSON(http.StatusOK, statement)
}

// Delete removes a VEX statement
func (h *VEXHandler) Delete(c echo.Context) error {
	vexID, err := uuid.Parse(c.Param("vex_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid VEX statement ID"})
	}

	if err := h.vexService.DeleteStatement(c.Request().Context(), vexID); err != nil {
		// DeleteStatement returns the raw repository error (static "not found"
		// for rows==0, or a raw driver error otherwise); never echo it to the
		// client (F442). Generic 404 body + full error to the server log.
		slog.Warn("vex: delete statement failed", "vex_id", vexID, "error", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "VEX statement not found"})
	}

	return c.NoContent(http.StatusNoContent)
}

// Export exports VEX statements in CycloneDX format
func (h *VEXHandler) Export(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project ID"})
	}

	data, err := h.vexService.ExportCycloneDXVEX(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to export VEX"})
	}

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().Header().Set("Content-Disposition", "attachment; filename=vex.json")
	return c.Blob(http.StatusOK, "application/json", data)
}
