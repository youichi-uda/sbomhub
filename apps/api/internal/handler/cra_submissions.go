package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// CRASubmissionRecorder is the subset of
// *repository.CRASubmissionsRepository the handler uses. Declared as an
// interface so cra_submissions_test.go can substitute a fake that
// captures the Record input and returns a canned row without a real DB.
type CRASubmissionRecorder interface {
	Record(ctx context.Context, in repository.CRASubmissionInput) (*repository.CRASubmission, error)
	ListByReport(ctx context.Context, tenantID, craReportID uuid.UUID) ([]repository.CRASubmission, error)
}

// CRASubmissionReportStore is the subset of
// *repository.CRAReportsRepository the submissions handler uses: the
// scoped-get (Get, the same method the Decide handler's loadReportScoped
// relies on) to enforce the (tenant, project, report) boundary and the
// approved-only guard, plus MarkSubmitted to flip cra_reports.state ->
// 'submitted' inside the same TenantTx (M33 Wave B / F419). It is a
// distinct interface from CRAReportStore (cra_reports.go) because this
// handler needs only these two methods; the concrete
// *repository.CRAReportsRepository satisfies both.
type CRASubmissionReportStore interface {
	Get(ctx context.Context, tenantID, id uuid.UUID) (*repository.CRAReport, error)
	MarkSubmitted(ctx context.Context, tenantID, reportID uuid.UUID) error
}

// CRASubmissionsHandler serves the M33 CRA submission-tracking endpoints
// (issue M33-B / F419):
//
//	POST /api/v1/projects/:id/cra-reports/:report_id/submissions
//	GET  /api/v1/projects/:id/cra-reports/:report_id/submissions
//
// The Record endpoint is the last-mile of "AI drafts, humans approve":
// the human-attested record that an APPROVED cra_reports row was
// submitted to an authority. The product NEVER auto-submits — Record
// only persists the operator's assertion "I submitted this" (submitted_at
// is human-attested, not system-stamped). Recording a submission is the
// FIRST prod path that flips cra_reports.state -> 'submitted' (via
// MarkSubmitted), so it activates the previously-dead 'submitted' UI
// (hollow-feature avoidance, kickoff core judgment #1).
//
// Auth (tenant binding, write permission, per-tenant rate limit) is
// enforced at the route group level by the MultiAuth + RequireWrite +
// RateLimitByAPIKey + TenantTx + auditMiddleware chain; see
// cmd/server/main.go. The handler carries defence-in-depth tenant / write
// guards mirroring the Decide handler.
type CRASubmissionsHandler struct {
	subs    CRASubmissionRecorder
	reports CRASubmissionReportStore
	audit   CRAAuditLogger
}

// NewCRASubmissionsHandler wires the handler. The argument order mirrors
// NewCRAReportsHandler (domain repo, cra_reports repo, audit repo) so the
// orchestrator can wire it identically in cmd/server/main.go.
func NewCRASubmissionsHandler(subs CRASubmissionRecorder, reports CRASubmissionReportStore, audit CRAAuditLogger) *CRASubmissionsHandler {
	return &CRASubmissionsHandler{subs: subs, reports: reports, audit: audit}
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// recordSubmissionRequest is the POST body. authority is required;
// submitted_at is an optional RFC3339 timestamp (server NOW() when
// omitted, matching the NOT NULL column default); reference_number /
// notes are optional free text. tenant_id (session) and cra_report_id
// (path :report_id) are server-derived and never read from the body.
type recordSubmissionRequest struct {
	Authority       string  `json:"authority"`
	SubmittedAt     *string `json:"submitted_at,omitempty"`
	ReferenceNumber *string `json:"reference_number,omitempty"`
	Notes           *string `json:"notes,omitempty"`
}

// craSubmissionListResponse is the JSON envelope returned by List. The
// slice is always non-nil so an empty timeline serialises as
// {"submissions":[]} rather than {"submissions":null}.
type craSubmissionListResponse struct {
	Submissions []repository.CRASubmission `json:"submissions"`
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/cra-reports/:report_id/submissions
// ----------------------------------------------------------------------------

// Record persists one cra_submissions row attesting that an approved
// cra_reports row was submitted to an authority, flips the report's state
// to 'submitted', and emits the cra_submission_recorded audit row — all
// atomic in the ambient TenantTx the route is wrapped in.
//
// Guard order mirrors Decide (cra_reports.go): tenant (401) → write (403)
// → uuid parse (400) → body / authority validation (400) → user identity
// required (403) → loadReportScoped (404) → approved-only (409) → write.
// The (submission, MarkSubmitted, audit) triple is audit-or-nothing (F32,
// kickoff core judgment #1): a domain audit failure returns 500 so the
// TenantTx middleware rolls back the INSERT + state flip. Compliance
// evidence (the CRA Article 14 submission record) MUST land atomically
// with the row it documents.
func (h *CRASubmissionsHandler) Record(c echo.Context) error {
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

	var req recordSubmissionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	authority := strings.TrimSpace(req.Authority)
	if authority == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "authority is required"})
	}

	// submitted_at is human-attested. Omitted → server NOW() (the column
	// is NOT NULL). A present-but-malformed value is a caller error (400),
	// NOT a silent fallback to now — that would mis-timestamp the Art.14
	// compliance record.
	submittedAt := time.Now().UTC()
	if req.SubmittedAt != nil {
		if raw := strings.TrimSpace(*req.SubmittedAt); raw != "" {
			parsed, perr := time.Parse(time.RFC3339, raw)
			if perr != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": "submitted_at must be an RFC3339 timestamp",
				})
			}
			submittedAt = parsed
		}
	}

	// Normalise the optional free-text fields: trim, and treat an
	// empty / whitespace-only value as absent (nil → SQL NULL) so the
	// has_reference audit flag and the stored row stay meaningful.
	referenceNumber := trimmedPtrOrNil(req.ReferenceNumber)
	notes := trimmedPtrOrNil(req.Notes)

	uid := userIDOrNil(tc)
	if uid == nil {
		// submitted_by anchors the compliance trail. Self-hosted requests
		// without a resolvable user id cannot record a submission through
		// this endpoint — fail loudly rather than write a NULL attester.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "user identity required to record a cra submission (audit trail)",
		})
	}

	// Load + enforce the (tenant, project) boundary BEFORE any write.
	// repository.Get is scoped only by (tenant, id), so without this
	// pre-flight a cross-project URL could attach a submission to a
	// foreign-project report.
	report, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "Record")
	if status != 0 {
		return c.JSON(status, body)
	}

	// approved-only guard (kickoff core judgment #2). "Humans approve
	// before submit": a pending / edited / rejected report is not
	// submittable. Reject at the handler layer with 409 BEFORE the write;
	// MarkSubmitted's `WHERE decision='approved'` is the belt-and-braces
	// counterpart.
	if report.Decision != "approved" {
		slog.Warn("cra_submissions: submission rejected; report not approved",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"report_id", reportID,
			"decision", report.Decision,
		)
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "only approved CRA reports can be recorded as submitted",
		})
	}

	in := repository.CRASubmissionInput{
		TenantID:        tc.TenantID(),
		CRAReportID:     reportID,
		Authority:       authority,
		SubmittedAt:     submittedAt,
		SubmittedBy:     uid,
		ReferenceNumber: referenceNumber,
		Notes:           notes,
	}
	sub, err := h.subs.Record(c.Request().Context(), in)
	if err != nil {
		slog.Warn("cra_submissions: record failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to record cra submission"})
	}

	// Flip cra_reports.state -> 'submitted' inside the same TenantTx. This
	// is the first prod path that makes state='submitted' attainable
	// (hollow-feature avoidance). MarkSubmitted is idempotent (guards on
	// decision='approved', not state) so re-submitting the same report is
	// a tolerated no-op.
	if err := h.reports.MarkSubmitted(c.Request().Context(), tc.TenantID(), reportID); err != nil {
		slog.Warn("cra_submissions: mark report submitted failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to mark cra report submitted"})
	}

	// No SetAuditResourceID here (M33 F419 Phase D): the audit middleware
	// deliberately SKIPS POST .../submissions (determineActionAndResource
	// returns "" for this route) because it cannot name a resource that is
	// join-correct on both a 2xx (the new submission) and a 4xx (no
	// submission exists). The authoritative record is the domain row below,
	// whose ResourceID is set directly to sub.ID.
	//
	// Emit the domain-level audit row (cra_submission_recorded). Written
	// inside the same ambient TenantTx as the INSERT + state flip so the
	// (submission, state, audit) triple commits atomically.
	tenantID := tc.TenantID()
	rid := sub.ID
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       model.AuditActionCRASubmissionRecorded,
		ResourceType: model.ResourceCRASubmission,
		ResourceID:   &rid,
		Details: map[string]interface{}{
			"cra_report_id": reportID.String(),
			"authority":     authority,
			"has_reference": referenceNumber != nil,
		},
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	}); err != nil {
		// F32 audit-or-nothing: hard-fail on domain audit failure so the
		// ambient TenantTx middleware rolls back the cra_submissions INSERT
		// AND the cra_reports state flip. A "submission recorded but audit
		// lost" outcome would silently let a CRA Article 14 submission skip
		// its required audit trail. This mirrors the Decide handler's F32
		// contract and is the wire-up reason this route is wrapped in
		// TenantTx (cmd/server/main.go) — TenantTx rolls back on any 5xx,
		// including this 500.
		slog.Error("cra_submissions: domain audit log failed; rolling back submission (F32 audit-or-nothing)",
			"tenant_id", tc.TenantID(), "report_id", reportID, "submission_id", sub.ID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist cra submission audit trail; submission rolled back",
		})
	}

	return c.JSON(http.StatusCreated, sub)
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/cra-reports/:report_id/submissions
// ----------------------------------------------------------------------------

// List returns the submission timeline for one cra_reports row, most-
// recently-submitted first. Read-only: no audit row, no write guard (the
// route sits behind the same read chain as the cra-reports list). The
// (tenant, project) boundary is enforced by loadReportScoped so a
// cross-project report id 404s.
func (h *CRASubmissionsHandler) List(c echo.Context) error {
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

	if _, status, body := h.loadReportScoped(c.Request().Context(), tc.TenantID(), projectID, reportID, "List"); status != 0 {
		return c.JSON(status, body)
	}

	subs, err := h.subs.ListByReport(c.Request().Context(), tc.TenantID(), reportID)
	if err != nil {
		slog.Warn("cra_submissions: list failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "report_id", reportID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list cra submissions"})
	}
	if subs == nil {
		subs = []repository.CRASubmission{}
	}
	return c.JSON(http.StatusOK, craSubmissionListResponse{Submissions: subs})
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// loadReportScoped loads a cra_reports row and enforces the route's
// (tenant, project) boundary — the same gatekeeper pattern as
// CRAReportsHandler.loadReportScoped, reusing the shared
// CRAReportsRepository.Get so the scope check cannot drift. The 404 body
// is identical for "report does not exist" and "report belongs to another
// project of this tenant" so a probe caller cannot distinguish them.
func (h *CRASubmissionsHandler) loadReportScoped(
	ctx context.Context,
	tenantID, projectID, reportID uuid.UUID,
	endpointName string,
) (*repository.CRAReport, int, map[string]string) {
	report, err := h.reports.Get(ctx, tenantID, reportID)
	if err != nil {
		slog.Warn("cra_submissions: load report failed",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"report_id", reportID,
			"error", err,
		)
		return nil, http.StatusInternalServerError, map[string]string{"error": "failed to load cra report"}
	}
	if report == nil {
		slog.Warn("cra_submissions: report not found",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"report_id", reportID,
		)
		return nil, http.StatusNotFound, map[string]string{"error": "cra report not found"}
	}
	if report.ProjectID != projectID {
		slog.Warn("cra_submissions: report in another project of the same tenant",
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

// trimmedPtrOrNil trims a nullable string field and returns nil when it
// is nil or blank after trimming, so an empty optional field lands as SQL
// NULL rather than an empty string.
func trimmedPtrOrNil(s *string) *string {
	if s == nil {
		return nil
	}
	v := strings.TrimSpace(*s)
	if v == "" {
		return nil
	}
	return &v
}
