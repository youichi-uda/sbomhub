package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/cra"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

// Pagination bounds for ListReports (M2-4 carries over M1 #F24). A
// silent clamp would hide the DoS-probe behaviour from telemetry, so
// the handler rejects out-of-band limit / offset values with 400
// BEFORE the repository runs, and the repository clamps as
// defense-in-depth (cra_reports.go CountByProject / ListByProject
// keep their own bounds).
const (
	// DefaultCRAReportsListLimit / MaxCRAReportsListLimit / MaxCRAReportsListOffset
	// mirror DefaultListLimit / MaxListLimit / MaxListOffset on
	// vex_drafts.go so operators have a single mental model for
	// "deep pagination probe → 400" across both AI artefact surfaces.
	DefaultCRAReportsListLimit = 100
	MaxCRAReportsListLimit     = 500
	MaxCRAReportsListOffset    = 10000
)

// AuditActionCRAReportDecided is the audit_logs.action emitted when a
// human applies an approve / edit / reject decision to a cra_reports
// row. Defined alongside the handler (rather than service/cra/) because
// the decision flow lives entirely in the handler — the runner only
// owns AI-generated / AI-disabled audit actions (see
// cra.AuditActionCRAReportAIGenerated / AuditActionCRAReportAIDisabled).
// ※要確認: lift into internal/model/audit.go once the audit action
// catalogue is consolidated.
const AuditActionCRAReportDecided = "cra_report_decided"

// CRAReportRunner is the subset of *cra.Runner the handler uses for
// RunReport / Reanalyse delegation. Declared as an interface so
// cra_reports_test.go can substitute a fake without spinning up a
// real LLM provider.
type CRAReportRunner interface {
	Run(ctx context.Context, in cra.RunInput) (*cra.RunResult, error)
}

// CRAReportStore is the subset of *repository.CRAReportsRepository the
// handler uses directly. The runner does not expose List / Get /
// CountByProject / UpdateDecision (those are pure repository surface
// area, not 2-stage tx territory), so the handler holds a separate
// reference.
type CRAReportStore interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*repository.CRAReport, error)
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.CRAReportListFilter) ([]repository.CRAReport, error)
	CountByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.CRAReportListFilter) (int, error)
	UpdateDecision(ctx context.Context, tenantID, id uuid.UUID, upd repository.CRAReportDecisionUpdate) error
}

// CRAAuditLogger is the subset of *repository.AuditRepository the
// Decide endpoint uses to emit the `cra_report_decided` audit row.
// The runner has its own audit writer (AuditActionCRAReport*) for
// AI-generated rows; this is the human-decision counterpart.
type CRAAuditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// CRAReportsHandler serves the M2-4 CRA report endpoints (issue #36):
//
//	POST   /api/v1/projects/:id/cra-reports/run
//	GET    /api/v1/projects/:id/cra-reports
//	GET    /api/v1/projects/:id/cra-reports/:report_id
//	PUT    /api/v1/projects/:id/cra-reports/:report_id/decision
//	POST   /api/v1/projects/:id/cra-reports/:report_id/reanalyse
//
// The handler is intentionally thin — it parses input, surfaces auth /
// tenant context from middleware, and delegates to the runner (for
// LLM-touching flows) or the repository (for pure CRUD). Auth (tenant
// binding, write permission, per-tenant concurrency cap) is enforced
// at the route group level via the appmw MultiAuth + RequireWrite +
// CRAConcurrencyLimit + RateLimitByAPIKey middleware chain; see
// cmd/server/main.go for the wire-up.
//
// M1 fix patterns carried over to M2-4 (regression coverage in
// cra_reports_test.go):
//   - F8/F9   loadReportScoped helper enforces (tenant, project) → 404
//   - F10     generic 404 / 400 body; sentinels logged via slog only
//   - F14/F15 MultiAuth + RequireWrite at the route layer; CanWrite
//             defence-in-depth in the handler
//   - F19     no TenantTx for RunReport / Reanalyse (runner manages tx)
//   - F24/F27 limit / offset clamp with explicit reject (no silent clamp)
//   - F28     X-Total-Count via CountByProject for the list endpoint
type CRAReportsHandler struct {
	runner   CRAReportRunner
	reports  CRAReportStore
	audit    CRAAuditLogger
}

// NewCRAReportsHandler wires the handler.
func NewCRAReportsHandler(runner CRAReportRunner, reports CRAReportStore, audit CRAAuditLogger) *CRAReportsHandler {
	return &CRAReportsHandler{runner: runner, reports: reports, audit: audit}
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// runReportRequest mirrors cra.RunInput's wire-shape fields. The
// runner's TenantID / ProjectID / UserID / IPAddress / UserAgent come
// from the request context, not the body, so they are not exposed
// here. The body is intentionally minimal — operator-supplied
// regulatory fields (ProductName / ReporterName / etc.) are pass-
// through because the LLM is forbidden from hallucinating compliance
// identifiers (see service/cra/runner.go buildTemplateData rationale).
type runReportRequest struct {
	VulnerabilityID  string `json:"vulnerability_id"`
	CVEID            string `json:"cve_id"`
	SourceVEXDraftID string `json:"source_vex_draft_id,omitempty"`
	ReportType       string `json:"report_type"`
	Lang             string `json:"lang"`

	ProductName    string `json:"product_name,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	VendorName     string `json:"vendor_name,omitempty"`
	ReporterName   string `json:"reporter_name,omitempty"`
	ReporterRole   string `json:"reporter_role,omitempty"`
	ContactEmail   string `json:"contact_email,omitempty"`
	ContactPhone   string `json:"contact_phone,omitempty"`
	AwarenessTime  string `json:"awareness_time,omitempty"`
	ReportID       string `json:"report_id,omitempty"`
}

// runReportResponse is the wire shape returned by RunReport / Reanalyse.
type runReportResponse struct {
	Report     *repository.CRAReport `json:"report"`
	LLMCallID  string                `json:"llm_call_id,omitempty"`
	AIDisabled bool                  `json:"ai_disabled,omitempty"`
}

// craReportListResponse is the JSON envelope returned by ListReports.
// The total count also lands in the X-Total-Count header (F28).
type craReportListResponse struct {
	Reports []repository.CRAReport `json:"reports"`
}

// craDecisionRequest captures the human decision on a cra_reports row.
type craDecisionRequest struct {
	Decision        string  `json:"decision"` // approved | edited | rejected
	DecisionNote    string  `json:"decision_note,omitempty"`
	EditedDraftText *string `json:"edited_draft_text,omitempty"`
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/cra-reports/run
// ----------------------------------------------------------------------------

// RunReport executes one CRA report drafting cycle and persists a fresh
// cra_reports row + llm_calls row + audit log (all atomic in the
// runner's Stage 3 write tx).
func (h *CRAReportsHandler) RunReport(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanWrite() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "write permission required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	var req runReportRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	in, status, body := h.buildRunInput(tc, projectID, req)
	if status != 0 {
		return c.JSON(status, body)
	}
	in.IPAddress = c.RealIP()
	in.UserAgent = c.Request().UserAgent()

	res, err := h.runner.Run(c.Request().Context(), in)
	if status, body, ok := mapCRARunnerError(err); ok {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusCreated, buildRunReportResponse(res))
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/cra-reports
// ----------------------------------------------------------------------------

// ListReports returns the project's cra_reports filtered by optional
// cve_id / report_type / lang / state / decision. Total count lands
// in the X-Total-Count header (M1 #F28 carried over).
func (h *CRAReportsHandler) ListReports(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	filter := repository.CRAReportListFilter{
		CVEID:      c.QueryParam("cve_id"),
		ReportType: c.QueryParam("report_type"),
		Lang:       c.QueryParam("lang"),
		State:      c.QueryParam("state"),
		Decision:   c.QueryParam("decision"),
		Limit:      DefaultCRAReportsListLimit,
	}
	// F24 carry-over: explicit reject on out-of-band limit. Empty /
	// unparseable / non-positive values fall through to the default
	// so legacy callers without an explicit page keep their behaviour.
	if v := c.QueryParam("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid limit"})
		}
		if n > MaxCRAReportsListLimit {
			slog.Warn("cra_reports: limit exceeds maximum",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"requested_limit", n,
				"max_limit", MaxCRAReportsListLimit,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "limit exceeds maximum"})
		}
		if n >= 1 {
			filter.Limit = n
		}
		// n < 1 falls through to DefaultCRAReportsListLimit (set above).
	}
	// F27 carry-over: explicit reject on out-of-band offset.
	if v := c.QueryParam("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid offset"})
		}
		if n > MaxCRAReportsListOffset {
			slog.Warn("cra_reports: offset exceeds maximum",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"requested_offset", n,
				"max_offset", MaxCRAReportsListOffset,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "offset exceeds maximum"})
		}
		if n >= 0 {
			filter.Offset = n
		}
	}

	reports, err := h.reports.ListByProject(c.Request().Context(), tc.TenantID(), projectID, filter)
	if err != nil {
		slog.Warn("cra_reports: list failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list cra reports"})
	}
	if reports == nil {
		reports = []repository.CRAReport{}
	}

	// F28: emit total count for the queue UI. We deliberately swallow
	// CountByProject errors and fall back to the page length so a count
	// failure does not break the list — slog records the underlying
	// issue. The handler-level cra_reports_test.go pins the success path
	// (X-Total-Count present + correct).
	if total, cerr := h.reports.CountByProject(c.Request().Context(), tc.TenantID(), projectID, filter); cerr != nil {
		slog.Warn("cra_reports: count failed; falling back to page length",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", cerr)
		c.Response().Header().Set("X-Total-Count", strconv.Itoa(len(reports)))
	} else {
		c.Response().Header().Set("X-Total-Count", strconv.Itoa(total))
	}

	return c.JSON(http.StatusOK, craReportListResponse{Reports: reports})
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/cra-reports/:report_id
// ----------------------------------------------------------------------------

// GetReport returns one cra_reports row scoped to the caller's tenant
// AND to the route's project (F8/F9 carried over: repository.Get
// scopes only by (tenant, id), so project membership is the handler's
// to enforce).
func (h *CRAReportsHandler) GetReport(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	reportID, err := uuid.Parse(c.Param("report_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report id"})
	}

	report, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "GetReport")
	if status != 0 {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusOK, report)
}

// ----------------------------------------------------------------------------
// PUT /api/v1/projects/:id/cra-reports/:report_id/decision
// ----------------------------------------------------------------------------

// Decide applies a human approve / edit / reject decision to one
// cra_reports row. The audit row is written immediately after the
// repository update so the (decision, audit) pair lands inside the
// same ambient TenantTx the route is wrapped in — Trust Rescue
// audit-or-nothing carried over from M1 F5 (※要確認: hard tx wrap
// for the (UPDATE + audit) pair could be tightened in M2-6 once
// CRA audit semantics stabilise).
func (h *CRAReportsHandler) Decide(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanWrite() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "write permission required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	reportID, err := uuid.Parse(c.Param("report_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report id"})
	}

	var req craDecisionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	switch req.Decision {
	case "approved", "edited", "rejected":
		// ok
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "decision must be one of: approved, edited, rejected",
		})
	}

	uid := userIDOrNil(tc)
	if uid == nil {
		// repository.UpdateDecision requires a non-nil decision_by uuid
		// (audit trail). Self-hosted requests without a user id cannot
		// apply a decision through this endpoint — fail loudly.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "user identity required to decide a cra report (audit trail)",
		})
	}

	// F8/F9 carry-over: load + enforce project boundary BEFORE the
	// UPDATE. repository.UpdateDecision is scoped only by (tenant, id),
	// so without this pre-flight check a cross-project URL would mutate
	// a foreign-project report.
	report, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "Decide")
	if status != 0 {
		return c.JSON(status, body)
	}

	upd := repository.CRAReportDecisionUpdate{
		Decision:        req.Decision,
		DecisionBy:      *uid,
		DecisionNote:    req.DecisionNote,
		EditedDraftText: req.EditedDraftText,
	}
	if err := h.reports.UpdateDecision(c.Request().Context(), tc.TenantID(), reportID, upd); err != nil {
		slog.Warn("cra_reports: UpdateDecision failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update cra report decision"})
	}

	// Emit the domain-level audit row (cra_report_decided). The
	// request-level audit middleware also runs on this route but
	// records only path/method/latency — the domain audit captures the
	// before/after decision values for the compliance trail.
	auditDetails := map[string]interface{}{
		"cve_id":               report.CVEID,
		"vulnerability_id":     report.VulnerabilityID.String(),
		"project_id":           projectID.String(),
		"report_type":          report.ReportType,
		"lang":                 report.Lang,
		"prior_decision":       report.Decision,
		"new_decision":         req.Decision,
		"edited":               req.EditedDraftText != nil,
	}
	if note := req.DecisionNote; note != "" {
		auditDetails["decision_note_len"] = len(note)
	}
	rid := reportID
	tenantID := tc.TenantID()
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       AuditActionCRAReportDecided,
		ResourceType: cra.ResourceTypeCRAReport,
		ResourceID:   &rid,
		Details:      auditDetails,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		// Audit failure on a successful decision is a soft warning: the
		// data already mutated and the request-level audit middleware
		// will still record the path/method/status. F5 audit-or-nothing
		// would require a tx wrap here (※要確認: tighten in M2-6).
		slog.Warn("cra_reports: domain audit log failed",
			"tenant_id", tc.TenantID(), "report_id", reportID, "error", err)
	}

	// Reload so the response reflects the persisted decision_at / updated_at.
	fresh, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "Decide.reload")
	if status != 0 {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusOK, fresh)
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/cra-reports/:report_id/reanalyse
// ----------------------------------------------------------------------------

// Reanalyse runs a fresh CRA report drafting cycle whose audit row
// carries `cra_report_ai_generated` (or `cra_report_ai_disabled`) and
// whose source context defaults to the existing report. The original
// row is not mutated — a new cra_reports row is inserted so reviewers
// can diff AI verdicts over time.
//
// The caller's body MAY override report_type / lang / source vex
// draft id; if omitted, the runner re-uses the values from the source
// report.
func (h *CRAReportsHandler) Reanalyse(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanWrite() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "write permission required"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	reportID, err := uuid.Parse(c.Param("report_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid report id"})
	}

	// F8/F9: cross-project source report must 404 before we kick off a
	// fresh drafting cycle. Without this check, project B could fan a
	// reanalyse cycle off a project A report and persist the new row
	// against project B (the runner trusts RunInput.ProjectID).
	source, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "Reanalyse")
	if status != 0 {
		return c.JSON(status, body)
	}

	var override runReportRequest
	_ = c.Bind(&override) // tolerated when body is empty

	// Default every RunInput field from the source report; let the
	// caller override the regulatory pass-through fields and the
	// report type / language if they need a different shape.
	in := cra.RunInput{
		TenantID:        tc.TenantID(),
		ProjectID:       projectID,
		VulnerabilityID: source.VulnerabilityID,
		CVEID:           source.CVEID,
		ReportType:      cra.ReportType(source.ReportType),
		Lang:            cra.Lang(source.Lang),
		UserID:          userIDOrNil(tc),
		IPAddress:       c.RealIP(),
		UserAgent:       c.Request().UserAgent(),
		ReportID:        source.ID.String(),
	}
	if source.SourceVEXDraftID != nil {
		v := *source.SourceVEXDraftID
		in.SourceVEXDraftID = &v
	}

	if override.CVEID != "" {
		in.CVEID = override.CVEID
	}
	if override.VulnerabilityID != "" {
		if parsed, err := uuid.Parse(override.VulnerabilityID); err == nil {
			in.VulnerabilityID = parsed
		}
	}
	if override.SourceVEXDraftID != "" {
		if parsed, err := uuid.Parse(override.SourceVEXDraftID); err == nil {
			in.SourceVEXDraftID = &parsed
		}
	}
	if override.ReportType != "" {
		in.ReportType = cra.ReportType(override.ReportType)
	}
	if override.Lang != "" {
		in.Lang = cra.Lang(override.Lang)
	}
	if override.ProductName != "" {
		in.ProductName = override.ProductName
	}
	if override.ProductVersion != "" {
		in.ProductVersion = override.ProductVersion
	}
	if override.VendorName != "" {
		in.VendorName = override.VendorName
	}
	if override.ReporterName != "" {
		in.ReporterName = override.ReporterName
	}
	if override.ReporterRole != "" {
		in.ReporterRole = override.ReporterRole
	}
	if override.ContactEmail != "" {
		in.ContactEmail = override.ContactEmail
	}
	if override.ContactPhone != "" {
		in.ContactPhone = override.ContactPhone
	}
	if override.AwarenessTime != "" {
		in.AwarenessTime = override.AwarenessTime
	}

	res, err := h.runner.Run(c.Request().Context(), in)
	if status, body, ok := mapCRARunnerError(err); ok {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusCreated, buildRunReportResponse(res))
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// buildRunInput translates a runReportRequest into a cra.RunInput,
// returning (input, 0, nil) on success or (zero, status, body) when
// the caller should return a JSON error response.
func (h *CRAReportsHandler) buildRunInput(tc *middleware.TenantContext, projectID uuid.UUID, req runReportRequest) (cra.RunInput, int, map[string]string) {
	if req.CVEID == "" {
		return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "cve_id is required"}
	}
	if req.ReportType == "" {
		return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "report_type is required"}
	}
	if req.Lang == "" {
		return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "lang is required"}
	}
	vulnID, err := uuid.Parse(req.VulnerabilityID)
	if err != nil {
		return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "invalid vulnerability_id"}
	}
	var sourceVEXDraft *uuid.UUID
	if req.SourceVEXDraftID != "" {
		parsed, err := uuid.Parse(req.SourceVEXDraftID)
		if err != nil {
			return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "invalid source_vex_draft_id"}
		}
		sourceVEXDraft = &parsed
	}
	in := cra.RunInput{
		TenantID:         tc.TenantID(),
		ProjectID:        projectID,
		VulnerabilityID:  vulnID,
		CVEID:            req.CVEID,
		SourceVEXDraftID: sourceVEXDraft,
		ReportType:       cra.ReportType(req.ReportType),
		Lang:             cra.Lang(req.Lang),
		UserID:           userIDOrNil(tc),
		ProductName:      req.ProductName,
		ProductVersion:   req.ProductVersion,
		VendorName:       req.VendorName,
		ReporterName:     req.ReporterName,
		ReporterRole:     req.ReporterRole,
		ContactEmail:     req.ContactEmail,
		ContactPhone:     req.ContactPhone,
		AwarenessTime:    req.AwarenessTime,
		ReportID:         req.ReportID,
	}
	return in, 0, nil
}

// buildRunReportResponse projects a cra.RunResult into the wire DTO.
func buildRunReportResponse(res *cra.RunResult) runReportResponse {
	if res == nil {
		return runReportResponse{}
	}
	resp := runReportResponse{
		Report:     res.Report,
		AIDisabled: res.AIDisabled,
	}
	if res.LLMCallID != nil && *res.LLMCallID != uuid.Nil {
		resp.LLMCallID = res.LLMCallID.String()
	}
	return resp
}

// loadReportScoped loads a cra_reports row and enforces the route's
// project boundary (M1 F7/F8/F9 pattern adapted to CRA). It is the
// single gatekeeper for GetReport, Decide, and Reanalyse so the
// project-scope check cannot drift between callers.
//
// Return contract:
//   - (*report, 0, nil) on success.
//   - (nil, status, body) when the handler should return a JSON error
//     response; status is 404 for both "report does not exist" and
//     "report belongs to another project of this tenant", and 500 for
//     storage failures. The body is intentionally identical for the
//     two 404 cases so a probe caller cannot distinguish them (F10).
func (h *CRAReportsHandler) loadReportScoped(
	ctx context.Context,
	tenantID, projectID, reportID uuid.UUID,
	endpointName string,
) (*repository.CRAReport, int, map[string]string) {
	report, err := h.reports.Get(ctx, tenantID, reportID)
	if err != nil {
		slog.Warn("cra_reports: load report failed",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"report_id", reportID,
			"error", err,
		)
		return nil, http.StatusInternalServerError, map[string]string{"error": "failed to load cra report"}
	}
	if report == nil {
		slog.Warn("cra_reports: report not found",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"report_id", reportID,
		)
		return nil, http.StatusNotFound, map[string]string{"error": "cra report not found"}
	}
	if report.ProjectID != projectID {
		// Distinct slog for cross-project probe alarms (F8/F9). User-
		// facing body is identical to the "report does not exist"
		// branch above so the caller cannot tell the difference
		// (would otherwise be a tenant-internal disclosure).
		slog.Warn("cra_reports: report in another project of the same tenant",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"route_project_id", projectID,
			"report_project_id", report.ProjectID,
			"report_id", reportID,
		)
		return nil, http.StatusNotFound, map[string]string{"error": "cra report not found"}
	}
	return report, 0, nil
}

// mapCRARunnerError translates cra.Runner errors into HTTP status +
// JSON body. Returns (status, body, true) when err is non-nil;
// (0, nil, false) otherwise so the caller can fall through to the
// success path.
//
// Status mapping (mirrors vex_drafts.go.mapRunnerError where the
// sentinels overlap):
//   - llm.DisabledError                              → 503
//   - cra.ErrCVEIDMismatch                           → 400 (#F12, generic body)
//   - cra.ErrSourceVEXDraftNotFound                  → 404 (generic body)
//   - cra.ErrSourceVEXDraftCrossProject              → 404 (#F7/F8/F9, generic body)
//   - cra.ErrNoApprovedVEXDraft                      → 409 (operator must triage first)
//   - cra.ErrUnknownTemplate                         → 400
//   - input-validation errors (missing fields)       → 400
//   - everything else                                → 500
func mapCRARunnerError(err error) (int, map[string]string, bool) {
	if err == nil {
		return 0, nil, false
	}
	var disabled *llm.DisabledError
	if errors.As(err, &disabled) {
		return http.StatusServiceUnavailable, map[string]string{
			"error":  "AI features are disabled",
			"reason": disabled.Reason,
		}, true
	}
	// F12 carry-over: generic 400 body so a probe caller cannot
	// distinguish "mismatched cve_id" from other targeting errors via
	// the response. Precise reason stays in server logs.
	if errors.Is(err, cra.ErrCVEIDMismatch) {
		slog.Warn("cra_reports: cve_id mismatch rejected",
			"sentinel", err.Error(),
		)
		return http.StatusBadRequest, map[string]string{
			"error": "cra report target invalid",
		}, true
	}
	// F7/F8/F9 carry-over: cross-project source draft 404. Same generic
	// body as ErrSourceVEXDraftNotFound so the response cannot be used
	// as an oracle for "the draft exists but belongs to a sibling
	// project of the same tenant".
	if errors.Is(err, cra.ErrSourceVEXDraftCrossProject) ||
		errors.Is(err, cra.ErrSourceVEXDraftNotFound) {
		slog.Warn("cra_reports: 404 sentinel mapped to generic body",
			"sentinel", err.Error(),
		)
		return http.StatusNotFound, map[string]string{
			"error": "cra report source not found",
		}, true
	}
	// 409: operator must approve a VEX draft before drafting a CRA
	// report (PRODUCT_REBOOT_PLAN §7.2 "approved な vex_drafts から取得").
	// Body intentionally surfaces the actionable hint so the CLI / UI
	// can render a "triage this CVE first" call-to-action.
	if errors.Is(err, cra.ErrNoApprovedVEXDraft) {
		slog.Warn("cra_reports: no approved vex_draft for this (project, cve)")
		return http.StatusConflict, map[string]string{
			"error": "no approved vex_draft available — approve a VEX triage decision for this (project, cve) first",
		}, true
	}
	if errors.Is(err, cra.ErrUnknownTemplate) {
		return http.StatusBadRequest, map[string]string{
			"error": "unsupported report_type / lang combination",
		}, true
	}
	// Heuristic — runner returns "X is required" / "is not in
	// allowlist" for caller-fixable problems. Anything we do not
	// explicitly recognise becomes 500.
	msg := err.Error()
	for _, marker := range []string{"is required", "is not in the allowlist", "not found", "must be"} {
		if containsSubstring(msg, marker) {
			if marker == "not found" {
				return http.StatusNotFound, map[string]string{"error": msg}, true
			}
			return http.StatusBadRequest, map[string]string{"error": msg}, true
		}
	}
	return http.StatusInternalServerError, map[string]string{"error": msg}, true
}
