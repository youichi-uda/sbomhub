package handler

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// The cra_report_decided audit action emitted by the Decide endpoint
// below lives in internal/model/audit.go as
// model.AuditActionCRAReportDecided. F371 (M25-B) lifted it out of
// this file's former handler-local const together with the
// meti_assessment_* trio in meti.go, in the dedicated audit-universe
// wave the M24-3 F350 note here called for: the four verbs are
// registered in service/audit.go GetAvailableActions() and pinned in
// middleware/audit_test.go's F271 expectedEmit + allModelActionValues()
// sets in the same change (F319/F322 discipline). The wire value is
// unchanged (F276 stability), so audit_logs rows written before the
// lift stay compatible, and the verb is now selectable in the UI
// action filter (the pre-F371 registration gap is closed). The
// decision flow itself still lives entirely in this handler — the
// runner only owns AI-generated / AI-disabled audit actions (see
// cra.AuditActionCRAReportAIGenerated / AuditActionCRAReportAIDisabled).

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
	// UpdateAwarenessTime sets/edits/clears the Art.14 awareness instant
	// on one cra_reports row (M35 F429). A nil awarenessTime clears it to
	// SQL NULL (deadline degrades to not_applicable); a zero RowsAffected
	// is wrapped as sql.ErrNoRows so the handler surfaces a 404.
	UpdateAwarenessTime(ctx context.Context, tenantID, id uuid.UUID, awarenessTime *time.Time) error
}

// CRAAuditLogger is the subset of *repository.AuditRepository the
// Decide endpoint uses to emit the `cra_report_decided` audit row.
// The runner has its own audit writer (AuditActionCRAReport*) for
// AI-generated rows; this is the human-decision counterpart.
type CRAAuditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// craSubmissionEarliestReader is the narrow subset of
// *repository.CRASubmissionsRepository the read endpoints use to
// compute Art.14 deadline status (M34-B / F424). The read endpoints
// need only the earliest (MIN) submitted_at per report to decide
// on_time vs late; the full submissions repository surface is not
// exposed here. Declared as an interface so cra_reports_test.go can
// substitute a fake with a controllable map. The batch signature
// (one call per list page, keyed by report id) keeps ListReports free
// of an N+1 submissions probe.
type craSubmissionEarliestReader interface {
	EarliestSubmittedAtByReports(ctx context.Context, tenantID uuid.UUID, reportIDs []uuid.UUID) (map[uuid.UUID]time.Time, error)
}

// CRAReportsHandler serves the M2-4 CRA report endpoints (issue #36):
//
//	POST   /api/v1/projects/:id/cra-reports/run
//	GET    /api/v1/projects/:id/cra-reports
//	GET    /api/v1/projects/:id/cra-reports/:report_id
//	PUT    /api/v1/projects/:id/cra-reports/:report_id/decision
//	PATCH  /api/v1/projects/:id/cra-reports/:report_id/awareness
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
//     defence-in-depth in the handler
//   - F19     no TenantTx for RunReport / Reanalyse (runner manages tx)
//   - F24/F27 limit / offset clamp with explicit reject (no silent clamp)
//   - F28     X-Total-Count via CountByProject for the list endpoint
type CRAReportsHandler struct {
	runner      CRAReportRunner
	reports     CRAReportStore
	audit       CRAAuditLogger
	submissions craSubmissionEarliestReader
}

// NewCRAReportsHandler wires the handler. `submissions` supplies the
// earliest-submission lookup the read endpoints use to compute the
// Art.14 deadline status (M34-B / F424); *repository.CRASubmissionsRepository
// satisfies it.
func NewCRAReportsHandler(runner CRAReportRunner, reports CRAReportStore, audit CRAAuditLogger, submissions craSubmissionEarliestReader) *CRAReportsHandler {
	return &CRAReportsHandler{runner: runner, reports: reports, audit: audit, submissions: submissions}
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

// craReportWithDeadline is the read-endpoint wire shape: the persisted
// cra_reports row (embedded, so all of its JSON fields — including
// awareness_time — are promoted verbatim) plus the DERIVED Art.14
// deadline fields computed on read (M34-B / F424). Nothing here is
// persisted: deadline_status / deadline_at are recomputed on every read
// from awareness_time + the earliest submission (the 053/054
// stale-derived-column discipline).
//
//	deadline_status: not_applicable | pending | overdue | on_time | late
//	deadline_at:     awareness_time + {24h,72h}; null for not_applicable
//	submitted_at:    earliest cra_submissions.submitted_at; null if none
type craReportWithDeadline struct {
	*repository.CRAReport
	DeadlineStatus string     `json:"deadline_status"`
	DeadlineAt     *time.Time `json:"deadline_at,omitempty"`
	SubmittedAt    *time.Time `json:"submitted_at,omitempty"`
}

// craReportListResponse is the JSON envelope returned by ListReports.
// The total count also lands in the X-Total-Count header (F28). Each
// entry carries the derived Art.14 deadline fields (F424).
type craReportListResponse struct {
	Reports []craReportWithDeadline `json:"reports"`
}

// craDecisionRequest captures the human decision on a cra_reports row.
type craDecisionRequest struct {
	Decision        string  `json:"decision"` // approved | edited | rejected
	DecisionNote    string  `json:"decision_note,omitempty"`
	EditedDraftText *string `json:"edited_draft_text,omitempty"`
}

// craAwarenessRequest carries the operator-attested Art.14 awareness
// instant for SetAwareness (M35 F429). AwarenessTime is a *string so the
// handler can distinguish an ABSENT field / explicit JSON null (both →
// CLEAR to NULL) from a supplied RFC3339 instant. An empty string is also
// treated as CLEAR (the web sends null to unset; empty is tolerated).
type craAwarenessRequest struct {
	AwarenessTime *string `json:"awareness_time"`
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
	// F208 / M14-1: publish the newly-minted cra_report UUID so the
	// audit middleware records audit_logs.resource_id = report.ID
	// instead of the parent project UUID (priority list would
	// otherwise pick up :id and the row would be unjoinable to
	// cra_reports). The runner's own internal audit rows (action
	// cra_report_ai_generated / cra_report_ai_disabled) already carry
	// the new report id correctly; the middleware row that records
	// the resource.created bucket needs this Set to agree.
	if res != nil && res.Report != nil && res.Report.ID != uuid.Nil {
		middleware.SetAuditResourceID(c, res.Report.ID)
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

	// F424: enrich each row with its read-time Art.14 deadline status.
	// One batched submissions lookup for the whole page (no N+1); the
	// query is tenant-scoped both by the explicit tenant_id and by RLS
	// inside the ambient TenantTx the list route runs in.
	earliest, submissionsKnown := h.earliestSubmittedAt(c.Request().Context(), tc.TenantID(), projectID, reports)
	enriched := enrichReportsWithDeadline(reports, earliest, time.Now().UTC(), submissionsKnown)

	return c.JSON(http.StatusOK, craReportListResponse{Reports: enriched})
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

	// F424: enrich the single report with its read-time Art.14 deadline
	// status. The batch reader is reused with a one-element id slice so
	// the on_time/late judgement uses the same MIN(submitted_at) source
	// of truth as ListReports.
	earliest, submissionsKnown := h.earliestSubmittedAt(c.Request().Context(), tc.TenantID(), projectID, []repository.CRAReport{*report})
	return c.JSON(http.StatusOK, enrichOneReport(report, earliest, time.Now().UTC(), submissionsKnown))
}

// ----------------------------------------------------------------------------
// PUT /api/v1/projects/:id/cra-reports/:report_id/decision
// ----------------------------------------------------------------------------

// Decide applies a human approve / edit / reject decision to one
// cra_reports row. The audit row is written immediately after the
// repository update so the (decision, audit) pair lands inside the
// same ambient TenantTx the route is wrapped in — Trust Rescue
// audit-or-nothing carried over from M1 F5 and tightened by M2
// Codex review #F32: a domain audit failure now returns 500 so the
// TenantTx middleware rolls back the cra_reports UPDATE, preventing
// a decision from committing without its CRA Article 14 audit trail.
// State-machine guard (M2 Codex review #F31): an already-decided
// report is rejected with 409 BEFORE the UPDATE attempt (and the
// repository UPDATE also carries `decision = 'pending'` for the
// load-then-update TOCTOU race).
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

	// F31: state-machine pre-check. Reject the re-decide case at the
	// handler layer with a meaningful 409 BEFORE attempting the UPDATE
	// (and surface a distinct slog line for compliance-trail probes).
	// The repository also guards the UPDATE with `decision = 'pending'`
	// as belt-and-braces protection against the load-then-update TOCTOU
	// race; that path is handled below by the sql.ErrNoRows mapping.
	if report.Decision != "pending" {
		slog.Warn("cra_reports: re-decide rejected; report already decided",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"report_id", reportID,
			"prior_decision", report.Decision,
			"requested_decision", req.Decision,
		)
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "cra report has already been decided; re-decision is not permitted",
		})
	}

	upd := repository.CRAReportDecisionUpdate{
		Decision:        req.Decision,
		DecisionBy:      *uid,
		DecisionNote:    req.DecisionNote,
		EditedDraftText: req.EditedDraftText,
	}
	if err := h.reports.UpdateDecision(c.Request().Context(), tc.TenantID(), reportID, upd); err != nil {
		// F31 carry-over: sql.ErrNoRows after the state-machine guard
		// means the row was decided by a concurrent request between our
		// loadReportScoped above and this UPDATE (TOCTOU race). Surface
		// the same 409 as the pre-check so the operator gets a
		// consistent error rather than a misleading 500.
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("cra_reports: re-decide rejected via state-machine guard (TOCTOU)",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"report_id", reportID,
				"requested_decision", req.Decision,
			)
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "cra report has already been decided; re-decision is not permitted",
			})
		}
		slog.Warn("cra_reports: UpdateDecision failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update cra report decision"})
	}

	// Emit the domain-level audit row (cra_report_decided). The
	// request-level audit middleware also runs on this route but
	// records only path/method/latency — the domain audit captures the
	// before/after decision values for the compliance trail.
	auditDetails := map[string]interface{}{
		"cve_id":           report.CVEID,
		"vulnerability_id": report.VulnerabilityID.String(),
		"project_id":       projectID.String(),
		"report_type":      report.ReportType,
		"lang":             report.Lang,
		"prior_decision":   report.Decision,
		"new_decision":     req.Decision,
		"edited":           req.EditedDraftText != nil,
	}
	if note := req.DecisionNote; note != "" {
		auditDetails["decision_note_len"] = len(note)
	}
	rid := reportID
	tenantID := tc.TenantID()
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       model.AuditActionCRAReportDecided,
		ResourceType: model.ResourceCRAReport,
		ResourceID:   &rid,
		Details:      auditDetails,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		// F32 (M2 Codex review): hard-fail on domain audit failure so
		// the ambient TenantTx middleware rolls back the UpdateDecision
		// row. Compliance evidence MUST land atomically with the
		// decision it documents — a "decision applied but audit lost"
		// outcome would silently let an approved / rejected /
		// edited CRA report skip the required CRA Article 14 audit
		// trail. This mirrors M1 F5 (triage audit-or-nothing) and is
		// the wire-up reason the Decide route is wrapped in TenantTx
		// (cmd/server/main.go) — TenantTx rolls back on any 4xx/5xx,
		// including this 500.
		slog.Error("cra_reports: domain audit log failed; rolling back decision (F32 audit-or-nothing)",
			"tenant_id", tc.TenantID(), "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist cra report decision audit trail; decision rolled back",
		})
	}

	// Reload so the response reflects the persisted decision_at / updated_at.
	fresh, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "Decide.reload")
	if status != 0 {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusOK, fresh)
}

// ----------------------------------------------------------------------------
// PATCH /api/v1/projects/:id/cra-reports/:report_id/awareness
// ----------------------------------------------------------------------------

// SetAwareness sets / edits / clears the Art.14 awareness instant on one
// cra_reports row (M35 F429 — web-operator self-serve for the clock start
// that M34 could only capture at generation time). It mirrors Decide's
// F32 audit-or-nothing structure exactly: the domain audit row is written
// immediately after the repository UPDATE so the (awareness, audit) pair
// lands inside the same ambient TenantTx the route is wrapped in — a
// domain audit failure returns 500 so the TenantTx middleware rolls back
// the awareness UPDATE, preventing an Art.14 clock-start change from
// committing without its audit trail.
//
// Validation (full guard, M35):
//   - absent / explicit null / empty (after trim) → CLEAR (write nil, the
//     deadline degrades to not_applicable).
//   - non-empty → time.Parse(RFC3339); malformed → 400 (mirrors buildRunInput).
//   - a parsed instant in the future → 400 (the Art.14 clock start cannot
//     be in the future).
//
// The response is the enriched CRAReport (same shape as GetReport): the
// deadline is recomputed on read (M34-B / F424), so moving awareness moves
// deadline_status / deadline_at in the very same response.
func (h *CRAReportsHandler) SetAwareness(c echo.Context) error {
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

	var req craAwarenessRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	// Full-guard validation. valueToWrite stays nil for the clear path so a
	// nil *time.Time flows straight through to UpdateAwarenessTime (→ SQL NULL).
	// Parse the TRIMMED value so the non-empty gate and time.Parse agree — a
	// whitespace-padded but otherwise-valid RFC3339 instant is accepted, not
	// rejected by a parse of the untrimmed string (M35 F429 Phase D LOW-3).
	var valueToWrite *time.Time
	if req.AwarenessTime != nil {
		trimmed := strings.TrimSpace(*req.AwarenessTime)
		if trimmed != "" {
			t, perr := time.Parse(time.RFC3339, trimmed)
			if perr != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid awareness_time (expected RFC3339)"})
			}
			// The Art.14 clock start is a past/present instant — a future
			// awareness is nonsensical (nothing to have become aware of yet).
			if t.After(time.Now().UTC()) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "awareness_time cannot be in the future"})
			}
			valueToWrite = &t
		}
	}

	// F8/F9 carry-over: load + enforce project boundary BEFORE the UPDATE.
	// repository.UpdateAwarenessTime is scoped only by (tenant, id), so
	// without this pre-flight a cross-project URL would mutate a
	// foreign-project report. Capture the prior awareness for the trail.
	report, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "SetAwareness")
	if status != 0 {
		return c.JSON(status, body)
	}
	priorAwareness := report.AwarenessTime

	if err := h.reports.UpdateAwarenessTime(c.Request().Context(), tc.TenantID(), reportID, valueToWrite); err != nil {
		// A zero-rows UPDATE (row absent, wrong tenant, or RLS-hidden) is
		// wrapped as sql.ErrNoRows by the repository — surface the same 404
		// as loadReportScoped so a TOCTOU delete cannot leak a 500.
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("cra_reports: UpdateAwarenessTime matched zero rows (absent / cross-tenant / RLS-hidden)",
				"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID)
			return c.JSON(http.StatusNotFound, map[string]string{"error": "cra report not found"})
		}
		slog.Warn("cra_reports: UpdateAwarenessTime failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update cra report awareness_time"})
	}

	// Emit the domain-level audit row (cra_report_awareness_updated). The
	// request-level audit middleware is suppressed for this route (the
	// /awareness PATCH skip in middleware/audit.go) so this is the single
	// authoritative row — it captures the before/after awareness instants
	// for the compliance trail.
	auditDetails := map[string]interface{}{
		"project_id":      projectID.String(),
		"prior_awareness": rfc3339OrNil(priorAwareness),
		"new_awareness":   rfc3339OrNil(valueToWrite),
		"cleared":         valueToWrite == nil,
	}
	rid := reportID
	tenantID := tc.TenantID()
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       userIDOrNil(tc),
		Action:       model.AuditActionCRAReportAwarenessUpdated,
		ResourceType: model.ResourceCRAReport,
		ResourceID:   &rid,
		Details:      auditDetails,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		// F32 (M2 Codex review, carried to M35 F429): hard-fail on domain
		// audit failure so the ambient TenantTx middleware rolls back the
		// UpdateAwarenessTime UPDATE. Compliance evidence MUST land
		// atomically with the awareness edit it documents — an "awareness
		// applied but audit lost" outcome would silently let an operator
		// move a CRA report's Article 14 reporting deadline without the
		// required audit trail. This mirrors Decide above and is the
		// wire-up reason the awareness route is wrapped in TenantTx
		// (cmd/server/main.go) — TenantTx rolls back on any 4xx/5xx,
		// including this 500.
		slog.Error("cra_reports: domain audit log failed; rolling back awareness update (F32 audit-or-nothing)",
			"tenant_id", tc.TenantID(), "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist cra report awareness audit trail; awareness update rolled back",
		})
	}

	// Reload + enrich exactly like GetReport so the response reflects the
	// persisted awareness_time / updated_at AND the freshly recomputed
	// Art.14 deadline (compute-on-read, F424): the same MIN(submitted_at)
	// source of truth judges on_time/late/pending/overdue.
	fresh, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "SetAwareness.reload")
	if status != 0 {
		return c.JSON(status, body)
	}
	earliest, submissionsKnown := h.earliestSubmittedAt(c.Request().Context(), tc.TenantID(), projectID, []repository.CRAReport{*fresh})
	return c.JSON(http.StatusOK, enrichOneReport(fresh, earliest, time.Now().UTC(), submissionsKnown))
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
	// F427 (M34 Phase D — Codex 20th unique catch): inherit the source
	// report's awareness_time so a re-analysed report keeps its Art.14
	// deadline clock. Without this the new row's awareness_time is NULL and
	// its deadline collapses to not_applicable. The override below still
	// replaces it when the caller re-attests a corrected instant.
	if source.AwarenessTime != nil {
		in.AwarenessTime = source.AwarenessTime.UTC().Format(time.RFC3339)
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
		// F427 (M34 Phase D): Reanalyse bypasses buildRunInput, so validate
		// the RFC3339 shape here — a mistyped instant is a clean 400 rather
		// than a 500 surfaced from the runner's later parse.
		if _, err := time.Parse(time.RFC3339, override.AwarenessTime); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid awareness_time (expected RFC3339)"})
		}
		in.AwarenessTime = override.AwarenessTime
	}

	res, err := h.runner.Run(c.Request().Context(), in)
	if status, body, ok := mapCRARunnerError(err); ok {
		return c.JSON(status, body)
	}
	// F208 / M14-1: Reanalyse mints a FRESH cra_reports row (history
	// preservation — the source report is never mutated). The audit
	// row's resource_id must point at the new row, NOT the source
	// :report_id from the URL, so a forensic walk of audit_logs ⨝
	// cra_reports lines up "this AI re-judgement produced THIS new
	// report row" rather than misattributing it to the source.
	if res != nil && res.Report != nil && res.Report.ID != uuid.Nil {
		middleware.SetAuditResourceID(c, res.Report.ID)
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
	// F424: awareness_time seeds the Art.14 24h/72h clock. Validate the
	// RFC3339 shape HERE so a mistyped instant is a clean 400 rather than
	// surfacing as a 500 from the runner's later parse. The runner also
	// parses it (belt) — this is the loud, caller-fixable gate.
	if req.AwarenessTime != "" {
		if _, err := time.Parse(time.RFC3339, req.AwarenessTime); err != nil {
			return cra.RunInput{}, http.StatusBadRequest, map[string]string{"error": "invalid awareness_time (expected RFC3339)"}
		}
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

// rfc3339OrNil renders a *time.Time as an RFC3339 string (UTC) for an
// audit Details map, or nil when the pointer is nil. The nil case
// serialises to JSON null so the awareness audit trail distinguishes
// "was/became unset" (null) from an actual instant (F429). Kept as a
// helper so the prior_awareness / new_awareness pair in SetAwareness
// cannot drift in format.
func rfc3339OrNil(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// earliestSubmittedAt batch-loads the earliest (MIN) submitted_at per
// report for a page of reports and returns (report-id → time map, ok).
// ok is false when the submissions lookup errored.
//
// F427 (M34 Phase D — R1 + Codex 20th convergent): a lookup failure must
// NOT be swallowed into an empty map, because the enricher would then read
// "absent" as "not submitted" and assert a FALSE overdue/pending verdict
// for a report that was in fact filed on time — a misleading compliance
// signal. Instead we surface ok=false so the caller emits NO deadline
// verdict (empty status → the UI renders no badge) while the primary
// reports payload still renders (availability preserved — the divergence
// from the CountByProject graceful-degradation pattern is deliberate:
// deadline is compliance-material, a count is cosmetic).
func (h *CRAReportsHandler) earliestSubmittedAt(
	ctx context.Context,
	tenantID, projectID uuid.UUID,
	reports []repository.CRAReport,
) (map[uuid.UUID]time.Time, bool) {
	ids := make([]uuid.UUID, 0, len(reports))
	for i := range reports {
		ids = append(ids, reports[i].ID)
	}
	earliest, err := h.submissions.EarliestSubmittedAtByReports(ctx, tenantID, ids)
	if err != nil {
		slog.Warn("cra_reports: earliest submission lookup failed; deadline verdict suppressed (no false status emitted)",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return nil, false
	}
	return earliest, true
}

// enrichReportsWithDeadline wraps each report with its read-time Art.14
// deadline judgement. `earliest` maps report id → earliest submitted_at
// (a report absent from the map is "not submitted yet"); `now` is
// injected by the caller (time.Now().UTC()).
func enrichReportsWithDeadline(reports []repository.CRAReport, earliest map[uuid.UUID]time.Time, now time.Time, submissionsKnown bool) []craReportWithDeadline {
	out := make([]craReportWithDeadline, 0, len(reports))
	for i := range reports {
		out = append(out, enrichOneReport(&reports[i], earliest, now, submissionsKnown))
	}
	return out
}

// enrichOneReport computes the derived Art.14 deadline fields for a
// single report. report.ReportType is the persisted string form; it is
// converted to the typed cra.ReportType (a string alias) so
// ComputeDeadline switches on the registered consts rather than a bare
// wire literal (F341 discipline). A report whose id is absent from
// `earliest` is treated as not-yet-submitted, so submitted_at is nil.
// submissionsKnown=false (the submissions lookup errored, F427) suppresses
// the verdict entirely: deadline_status is emitted empty (the UI renders no
// badge) rather than computing a false "not submitted" status.
func enrichOneReport(report *repository.CRAReport, earliest map[uuid.UUID]time.Time, now time.Time, submissionsKnown bool) craReportWithDeadline {
	if !submissionsKnown {
		return craReportWithDeadline{CRAReport: report, DeadlineStatus: ""}
	}
	var submittedAt *time.Time
	if t, ok := earliest[report.ID]; ok {
		tt := t
		submittedAt = &tt
	}
	res := cra.ComputeDeadline(cra.ReportType(report.ReportType), report.AwarenessTime, submittedAt, now)
	return craReportWithDeadline{
		CRAReport:      report,
		DeadlineStatus: string(res.Status),
		DeadlineAt:     res.DeadlineAt,
		SubmittedAt:    submittedAt,
	}
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
//   - cra.ErrSourceVEXDraftCVEMismatch               → 409 (#F30, operator must
//     attach a VEX draft for the
//     correct CVE)
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
	// 409 (#F30): caller attached a VEX draft for a DIFFERENT CVE than
	// the CRA report target. The body surfaces an actionable hint —
	// "attach a VEX draft for THIS CVE" — without disclosing which CVE
	// the foreign draft covered (that would let an attacker probe for
	// approved triage decisions across CVEs by URL-stuffing draft ids).
	if errors.Is(err, cra.ErrSourceVEXDraftCVEMismatch) {
		slog.Warn("cra_reports: source vex_draft cve_id mismatch rejected",
			"sentinel", err.Error(),
		)
		return http.StatusConflict, map[string]string{
			"error": "source vex_draft cve_id does not match the CRA report cve_id — attach a VEX draft approved for this CVE",
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
