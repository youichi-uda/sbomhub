package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	metisvc "github.com/sbomhub/sbomhub/internal/service/meti"
	"github.com/sbomhub/sbomhub/internal/service/meti/criteria"
)

// MetiProjectReader is the subset of *repository.ProjectRepository the
// METI handler uses to confirm that the path :id belongs to the
// authenticated tenant BEFORE any meti_assessments read / write
// happens. Declared as an interface so meti_test.go can supply a fake
// without a real PostgreSQL connection (matches the
// ProjectReader pattern in evidence_pack).
//
// F37 (M3 Codex review round 3): the meti_assessments table treats
// project_id as a soft reference (no FK) so without this check a probe
// caller can persist 27 evaluator rows under an arbitrary or
// non-existent project UUID and pollute List / Override / Evidence
// Pack output. GetByTenant returns sql.ErrNoRows for both
// "row does not exist" and "row belongs to another tenant" — the
// handler maps both to a generic 404 (F10 carry-over: no oracle).
type MetiProjectReader interface {
	GetByTenant(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error)
}

// Override-note bounds enforced by /override (PUT) — and shared by
// the M4 follow-up clear-override endpoint. Required + length-capped
// is the M3 Codex review #F34 fix: a manual override that wins over
// the evaluator in Evidence Pack output must carry a human rationale
// the auditor can review. The 4096-char cap is enough for a paragraph
// of explanation (the production catalog's description_ja strings are
// <500 chars, so 4096 is ~8× headroom) while keeping the
// audit_logs.details JSONB bounded against a probe submitting a
// multi-MB note.
const (
	MinMetiOverrideNoteLen = 1
	MaxMetiOverrideNoteLen = 4096
)

// validateMetiOverrideNote enforces the #F34 contract: trim
// whitespace, reject empty, reject over MaxMetiOverrideNoteLen.
// Returns the cleaned (trimmed) note on success, or (zero, status,
// body) for the caller to forward as the HTTP error. The error body
// is intentionally generic (F10 carry-over) — the precise reason
// lands in slog at the caller's site.
func validateMetiOverrideNote(note string) (string, int, map[string]string) {
	cleaned := strings.TrimSpace(note)
	if len(cleaned) < MinMetiOverrideNoteLen || len(cleaned) > MaxMetiOverrideNoteLen {
		return "", http.StatusBadRequest, map[string]string{
			"error": "override_note is required and must be 1-4096 characters",
		}
	}
	return cleaned, 0, nil
}

// Pagination bounds for ListAssessments / ListImprovementActions
// (M3-4 carries over M1 #F24 / #F27). Explicit reject on out-of-band
// limit / offset values BEFORE the repository runs; the repository
// also clamps as defense-in-depth (meti_assessments.go ListByProject /
// CountByProject bounds).
//
// The METI catalog ships with 27 criterion entries (3 phases × ~9
// items), so DefaultMetiAssessmentsListLimit = 100 covers the full
// project assessment in one page and the dashboard's tabbed phase
// matrix never paginates in practice — the bounds exist purely to keep
// the DoS-probe regression-class out of the repository layer.
const (
	DefaultMetiAssessmentsListLimit = 100
	MaxMetiAssessmentsListLimit     = 500
	MaxMetiAssessmentsListOffset    = 10000
)

// Audit actions emitted by the METI handler. All three verbs are
// product-specific (no existing model.Action* constant covers them)
// so they live alongside the handler — same rationale as
// AuditActionCRAReportDecided in cra_reports.go.
// ※要確認: lift into internal/model/audit.go once the audit action
// catalogue is consolidated (alongside AuditActionCRAReportDecided).
const (
	// AuditActionMetiAssessmentRefreshed is emitted by /refresh after the
	// evaluator's 27-criterion fan-out is persisted.
	AuditActionMetiAssessmentRefreshed = "meti_assessment_refreshed"

	// AuditActionMetiAssessmentOverridden is emitted by /override when the
	// operator's manual verdict is applied. Clear-then-re-override goes
	// through the DELETE override handler path
	// (AuditActionMetiAssessmentOverrideCleared) so each transition
	// emits its own audit_logs row.
	AuditActionMetiAssessmentOverridden = "meti_assessment_overridden"

	// AuditActionMetiAssessmentOverrideCleared is emitted by DELETE
	// /override when the operator clears a prior manual override (M3
	// Codex review #F33 — without this verb, an erroneous override is
	// a one-way trip that continues to win in dashboard + Evidence Pack
	// output). The audit row carries the prior override_status, the
	// prior override_by, and the operator-supplied clear note in
	// details so an auditor can reconstruct who corrected what.
	AuditActionMetiAssessmentOverrideCleared = "meti_assessment_override_cleared"

	// ResourceTypeMetiAssessment is the audit_logs.resource_type for the
	// refresh / override / override-cleared audit rows. The resource_id
	// is the meti_assessments.id (refresh emits one row covering the
	// whole project fan-out; override / clear emit one row per criterion
	// the operator touched).
	// ※要確認: lift into internal/model/audit.go alongside the action verbs.
	ResourceTypeMetiAssessment = "meti_assessment"
)

// MetiAssessmentStore is the subset of *repository.MetiAssessmentsRepository
// the handler uses. Declared as an interface so meti_test.go can substitute
// a fake without standing up a real PostgreSQL connection (matches the
// CRAReportStore / fakeCRAReportStore pattern).
type MetiAssessmentStore interface {
	Upsert(ctx context.Context, a *repository.MetiAssessment) error
	Get(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string) (*repository.MetiAssessment, error)
	ListByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.MetiAssessmentListFilter) ([]repository.MetiAssessment, error)
	CountByProject(ctx context.Context, tenantID, projectID uuid.UUID, filter repository.MetiAssessmentListFilter) (int, error)
	OverrideStatus(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string, upd repository.MetiAssessmentOverrideInput) error
	ClearOverride(ctx context.Context, tenantID, projectID uuid.UUID, criterionID string) error
}

// MetiEvaluator is the subset of *metisvc.Evaluator the refresh
// endpoint needs. Kept narrow so tests can supply a fake fan-out
// without depending on the catalog YAML / per-criterion functions.
type MetiEvaluator interface {
	Evaluate(ctx context.Context, tenantID, projectID uuid.UUID) ([]metisvc.CriterionResult, error)
}

// MetiAuditLogger is the subset of *repository.AuditRepository the
// METI handler uses to emit the refresh / override audit rows.
// Mirrors CRAAuditLogger.
type MetiAuditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// MetiHandler serves the M3-4 METI self-assessment endpoints (issue #37):
//
//	GET    /api/v1/projects/:id/meti/assessment
//	POST   /api/v1/projects/:id/meti/assessment/refresh
//	PUT    /api/v1/projects/:id/meti/assessment/:criterion_id/override
//	GET    /api/v1/projects/:id/meti/improvement-actions
//
// The handler is intentionally thin — it validates input, surfaces
// auth / tenant context from middleware, and delegates to the
// evaluator (for refresh) or the repository (for read / override).
// Auth (tenant binding, write permission) is enforced at the route
// group level via the appmw MultiAuth + RequireWrite + RateLimit +
// TenantTx middleware chain (see cmd/server/main.go).
//
// M1 / M2 fix patterns carried over to M3-4 (regression coverage in
// meti_test.go):
//   - F1/F4   structured input validation; 400 on malformed UUID / phase / status
//   - F5/F32  audit-or-nothing: override audit failure returns 500 so the
//     ambient TenantTx rolls back the OverrideStatus UPDATE
//   - F8/F9   project boundary enforced by the (tenant, project, criterion)
//     composite key in MetiAssessmentsRepository.Get; cross-project
//     lookups naturally miss (vs CRA's UUID-only lookup which needed
//     a separate loadReportScoped helper)
//   - F10     generic 404 / 400 body; precise reason in slog only
//   - F14/F15 MultiAuth + RequireWrite at the route layer; CanWrite
//     defence-in-depth in the handler
//   - F18     write routes (POST /refresh, PUT /override) require write role
//   - F24/F27 limit / offset clamp with explicit reject (no silent clamp)
//   - F26     query-param validation (phase / status / has_override) rejects
//     out-of-allowlist values with 400 BEFORE the repository runs
//   - F28     X-Total-Count via CountByProject for the list endpoints
//   - F29     same WHERE shape shared between ListByProject and CountByProject
//     (repository invariant; the handler just hands the same filter
//     through to both calls so the X-Total-Count and the page length
//     adjudicate on identical units)
//   - F31     state-machine guard at handler layer (already-overridden → 409
//     BEFORE the UPDATE) PLUS the repo's `override_status IS NULL`
//     WHERE clause for the load-then-update TOCTOU race. Clear-then-
//     re-override is an explicit M4 handler path (DELETE override)
//     so each transition emits its own audit_logs row.
//
// F19 / F25 are intentionally NOT in scope:
//   - F19: the evaluator is fully local (no LLM upstream), so /refresh runs
//     synchronously inside the ambient TenantTx. Connection-pool
//     exhaustion DoS does not apply.
//   - F25: the catalog is a fixed 27-item set; fan-out cap does not apply.
type MetiHandler struct {
	store     MetiAssessmentStore
	evaluator MetiEvaluator
	audit     MetiAuditLogger
	projects  MetiProjectReader
}

// NewMetiHandler wires the handler. The projects reader is mandatory
// (F37 round 3): every endpoint calls requireProjectInTenant before
// touching meti_assessments so a probe caller cannot Upsert /
// Read / Override rows for a project that does not belong to the
// authenticated tenant.
func NewMetiHandler(store MetiAssessmentStore, evaluator MetiEvaluator, audit MetiAuditLogger, projects MetiProjectReader) *MetiHandler {
	return &MetiHandler{store: store, evaluator: evaluator, audit: audit, projects: projects}
}

// requireProjectInTenant ensures projectID belongs to tenantID before
// any meti_assessments read / write runs (F37). Returns:
//
//   - (0, nil)           : project exists in tenant; proceed.
//   - (404, generic body) : project not found OR belongs to another
//     tenant. Body is identical to "meti assessment not found" so the
//     response is not an oracle for cross-tenant project enumeration
//     (F10 carry-over).
//   - (500, generic body) : storage failure; slog captures the
//     underlying error.
//
// The handler-level slog line distinguishes the two 404 cases for
// operator forensics — only the JSON body is shared.
func (h *MetiHandler) requireProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID, endpointName string) (int, map[string]string) {
	if h.projects == nil {
		// Defence-in-depth: if the handler was wired without a project
		// reader we MUST refuse to serve rather than fall through to the
		// unscoped fan-out. NewMetiHandler now requires the reader, so
		// this only fires on a future mis-wire regression.
		slog.Error("meti_assessments: project reader not wired; refusing to serve (F37)",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
		)
		return http.StatusInternalServerError, map[string]string{"error": "meti handler misconfigured"}
	}
	_, err := h.projects.GetByTenant(ctx, tenantID, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("meti_assessments: project not in tenant (F37)",
				"endpoint", endpointName,
				"tenant_id", tenantID,
				"project_id", projectID,
			)
			return http.StatusNotFound, map[string]string{"error": "project not found"}
		}
		slog.Warn("meti_assessments: project lookup failed",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"error", err,
		)
		return http.StatusInternalServerError, map[string]string{"error": "failed to verify project"}
	}
	return 0, nil
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// metiAssessmentListResponse is the JSON envelope returned by
// ListAssessments. Total count also lands in the X-Total-Count
// header (F28).
type metiAssessmentListResponse struct {
	Assessments []repository.MetiAssessment `json:"assessments"`
}

// metiRefreshResponse is the JSON envelope returned by RefreshAssessment.
// EvaluatorVersion is surfaced at the top level so the Web UI (M3-5)
// can show a "evaluated by X" pill without scanning the per-row
// evaluator_version fields.
type metiRefreshResponse struct {
	Assessments      []repository.MetiAssessment `json:"assessments"`
	EvaluatorVersion string                      `json:"evaluator_version"`
	Refreshed        int                         `json:"refreshed"`
}

// metiOverrideRequest captures the operator's manual override on a
// meti_assessments row. ImprovementAction is a pointer so the caller
// can distinguish "do not change" (omitted / null) from "set to empty"
// (explicit "") — mirrors the CRA EditedDraftText contract.
//
// OverrideNote is REQUIRED (M3 Codex review #F34): an override that
// wins over the evaluator in Evidence Pack output without a human
// rationale leaves no audit trail for METI auditor review. The
// validation (1..MaxMetiOverrideNoteLen, trimmed) is enforced by
// validateMetiOverrideNote at OverrideAssessment entry.
type metiOverrideRequest struct {
	OverrideStatus    string  `json:"override_status"`              // required: achieved | not_achieved | needs_review | not_applicable
	OverrideNote      string  `json:"override_note"`                // required: 1..4096 chars after trim (#F34)
	ImprovementAction *string `json:"improvement_action,omitempty"` // optional remediation plan
}

// metiClearOverrideRequest captures the operator's clear-override
// request body. The note is the operator's rationale for the clear
// ("re-evaluated, the original override was wrong") and is persisted
// in the audit_logs row so an auditor can reconstruct the correction
// (M3 Codex review #F33 — without this verb, an erroneous override is
// a one-way trip that continues to win in Evidence Pack output).
type metiClearOverrideRequest struct {
	Note string `json:"note"` // required: 1..4096 chars after trim
}

// metiImprovementAction is one row of the improvement-actions response.
// We project the underlying MetiAssessment so the wire shape stays
// stable across repository refactors and explicitly carry the
// criterion's catalog title (UI doesn't have to re-fetch the catalog
// to render the action list).
type metiImprovementAction struct {
	CriterionID       string          `json:"criterion_id"`
	CriterionPhase    string          `json:"criterion_phase"`
	CriterionTitleJA  string          `json:"criterion_title_ja,omitempty"`
	CriterionTitleEN  string          `json:"criterion_title_en,omitempty"`
	Status            string          `json:"status"`
	OverrideStatus    string          `json:"override_status,omitempty"`
	EffectiveStatus   string          `json:"effective_status"` // override_status if set, else status
	Evidence          json.RawMessage `json:"evidence"`
	ImprovementAction string          `json:"improvement_action,omitempty"`
}

type metiImprovementActionsResponse struct {
	Actions []metiImprovementAction `json:"actions"`
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/meti/assessment
// ----------------------------------------------------------------------------

// ListAssessments returns the project's current per-criterion METI
// assessment rows. Optional query params:
//
//	?phase=env_setup|sbom_creation|sbom_operation
//	?status=achieved|not_achieved|needs_review|not_applicable
//	?has_override=true|false
//	?limit=N (1..MaxMetiAssessmentsListLimit, default DefaultMetiAssessmentsListLimit)
//	?offset=N (0..MaxMetiAssessmentsListOffset, default 0)
//
// Total count lands in the X-Total-Count header (M1 #F28 carried
// over) so the Web UI can render "N / total 件".
func (h *MetiHandler) ListAssessments(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	// F37: confirm the project belongs to the authenticated tenant
	// BEFORE any meti_assessments query so a probe caller cannot probe
	// arbitrary project UUIDs and read other tenants' rows. Failure
	// surfaces as a generic 404 (F10 no-oracle).
	if status, body := h.requireProjectInTenant(c.Request().Context(), tc.TenantID(), projectID, "ListAssessments"); status != 0 {
		return c.JSON(status, body)
	}

	filter, status, body := h.parseListFilter(c, tc.TenantID(), projectID)
	if status != 0 {
		return c.JSON(status, body)
	}

	assessments, err := h.store.ListByProject(c.Request().Context(), tc.TenantID(), projectID, filter)
	if err != nil {
		slog.Warn("meti_assessments: list failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list meti assessments"})
	}
	if assessments == nil {
		assessments = []repository.MetiAssessment{}
	}

	// F28: emit total count for the UI matrix. We swallow CountByProject
	// errors and fall back to the page length so a count failure does
	// not break the list view — slog records the underlying issue.
	if total, cerr := h.store.CountByProject(c.Request().Context(), tc.TenantID(), projectID, filter); cerr != nil {
		slog.Warn("meti_assessments: count failed; falling back to page length",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", cerr)
		c.Response().Header().Set("X-Total-Count", strconv.Itoa(len(assessments)))
	} else {
		c.Response().Header().Set("X-Total-Count", strconv.Itoa(total))
	}

	return c.JSON(http.StatusOK, metiAssessmentListResponse{Assessments: assessments})
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/meti/assessment/refresh
// ----------------------------------------------------------------------------

// RefreshAssessment re-runs the evaluator over the project and Upserts
// every criterion result. Operator-applied overrides are preserved by
// the repository (Upsert does NOT touch override_*) so an operator's
// manual verdict survives a refresh cycle.
//
// One audit row is emitted per refresh covering the whole fan-out
// (resource_id = projectID, details.refreshed = N). Per-criterion
// audit rows would balloon the audit log for what is conceptually a
// single user action; the operator can diff before/after by comparing
// the returned assessments slice against the previous list.
//
// Audit-or-nothing (F5 / F32): if the audit Log fails, we return 500
// so the ambient TenantTx middleware rolls back the Upsert fan-out.
// The full 27 rows commit atomically with their audit trail or not at
// all.
func (h *MetiHandler) RefreshAssessment(c echo.Context) error {
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

	// F37: confirm the project belongs to the authenticated tenant
	// BEFORE the evaluator + 27-row Upsert fan-out runs. Without this
	// check the handler would persist meti_assessments rows for an
	// arbitrary / non-existent project UUID (project_id is a soft
	// reference with no FK in the migration).
	if status, body := h.requireProjectInTenant(c.Request().Context(), tc.TenantID(), projectID, "RefreshAssessment"); status != 0 {
		return c.JSON(status, body)
	}

	results, err := h.evaluator.Evaluate(c.Request().Context(), tc.TenantID(), projectID)
	if err != nil {
		slog.Warn("meti_assessments: evaluator failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to evaluate meti assessment"})
	}

	// Persist the fan-out. Upsert is ON CONFLICT (tenant, project,
	// criterion) DO UPDATE so a re-evaluation overwrites the
	// evaluator-owned columns and leaves the operator override_*
	// columns untouched (see MetiAssessmentsRepository.Upsert).
	persisted := make([]repository.MetiAssessment, 0, len(results))
	evaluatorVersion := metisvc.EvaluatorVersion
	for i := range results {
		r := results[i]
		a := &repository.MetiAssessment{
			TenantID:         tc.TenantID(),
			ProjectID:        projectID,
			CriterionID:      r.CriterionID,
			CriterionPhase:   r.Phase,
			Status:           r.Status,
			Evidence:         r.Evidence,
			EvaluatorVersion: r.EvaluatorVersion,
			EvaluatedAt:      r.EvaluatedAt,
		}
		if err := h.store.Upsert(c.Request().Context(), a); err != nil {
			slog.Warn("meti_assessments: upsert failed",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"criterion_id", r.CriterionID,
				"error", err,
			)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to persist meti assessment"})
		}
		if r.EvaluatorVersion != "" {
			evaluatorVersion = r.EvaluatorVersion
		}
		persisted = append(persisted, *a)
	}

	// F5 / F32 audit-or-nothing: a refresh that lands in meti_assessments
	// without its audit row would silently break the "evaluator stamped
	// X criterion at T" compliance evidence chain. We fail the entire
	// request on audit failure; TenantTx rolls back the Upserts.
	uid := userIDOrNil(tc)
	tenantID := tc.TenantID()
	pid := projectID
	details := map[string]interface{}{
		"project_id":        projectID.String(),
		"refreshed":         len(persisted),
		"evaluator_version": evaluatorVersion,
	}
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       AuditActionMetiAssessmentRefreshed,
		ResourceType: ResourceTypeMetiAssessment,
		ResourceID:   &pid,
		Details:      details,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		slog.Error("meti_assessments: domain audit log failed; rolling back refresh (F5/F32 audit-or-nothing)",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist meti assessment refresh audit trail; refresh rolled back",
		})
	}

	return c.JSON(http.StatusOK, metiRefreshResponse{
		Assessments:      persisted,
		EvaluatorVersion: evaluatorVersion,
		Refreshed:        len(persisted),
	})
}

// ----------------------------------------------------------------------------
// PUT /api/v1/projects/:id/meti/assessment/:criterion_id/override
// ----------------------------------------------------------------------------

// OverrideAssessment applies one operator override to a
// meti_assessments row. The evaluator-owned fields are preserved
// unconditionally; only override_status / override_by / override_at /
// override_note (and optionally improvement_action) are written.
//
// State-machine guard (F31 carried over from M2):
//   - The pre-check loads the row and rejects an already-overridden
//     row with 409 BEFORE the UPDATE (and surfaces a distinct slog
//     line for compliance-trail probes).
//   - The repository's OverrideStatus also guards the UPDATE with
//     `override_status IS NULL` as belt-and-braces protection against
//     the load-then-update TOCTOU race. That path is mapped to the
//     same 409 below via sql.ErrNoRows.
//   - Clear-then-re-override is an explicit M4 handler path
//     (DELETE override) so each transition emits its own audit row.
//
// Audit-or-nothing (F5 / F32): same shape as RefreshAssessment — a
// failed audit Log returns 500 so TenantTx rolls back the override.
func (h *MetiHandler) OverrideAssessment(c echo.Context) error {
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
	// F37: confirm the project belongs to the authenticated tenant
	// BEFORE the criterion-id validation / load / UPDATE chain so a
	// probe caller cannot mutate meti_assessments rows for arbitrary or
	// cross-tenant project UUIDs.
	if status, body := h.requireProjectInTenant(c.Request().Context(), tc.TenantID(), projectID, "OverrideAssessment"); status != 0 {
		return c.JSON(status, body)
	}
	criterionID := c.Param("criterion_id")
	if criterionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "criterion_id is required"})
	}
	// F26 carry-over: bound criterion_id to known catalog entries so a
	// probe caller cannot enumerate the meti_assessments table for
	// arbitrary criterion ids. Unknown id → 404 (generic body, matches
	// "row not found" so the response is not an oracle for catalog
	// composition).
	if _, ok := metisvc.GetCriterion(criterionID); !ok {
		slog.Warn("meti_assessments: unknown criterion id",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
		)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "meti assessment not found"})
	}

	var req metiOverrideRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if !isValidStatus(req.OverrideStatus) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "override_status must be one of: achieved, not_achieved, needs_review, not_applicable",
		})
	}
	// F34: every override must carry a human rationale (auditor review
	// requirement). Validate + trim BEFORE the pre-load so an empty /
	// whitespace-only / oversized note never reaches the repository
	// layer. The cleaned note is what we persist + audit.
	cleanedNote, status, body := validateMetiOverrideNote(req.OverrideNote)
	if status != 0 {
		slog.Warn("meti_assessments: override rejected; note failed validation (F34)",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"raw_note_len", len(req.OverrideNote),
		)
		return c.JSON(status, body)
	}
	req.OverrideNote = cleanedNote

	uid := userIDOrNil(tc)
	if uid == nil {
		// repository.OverrideStatus requires a non-nil override_by uuid
		// (audit trail). Self-hosted requests without a user id cannot
		// apply an override through this endpoint — fail loudly so the
		// operator knows to authenticate.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "user identity required to override a meti assessment (audit trail)",
		})
	}

	// Pre-load: confirm the row exists for (tenant, project, criterion)
	// AND that it is not already overridden (F31 state-machine guard at
	// the handler layer — distinct slog line, distinct 409 body before
	// the UPDATE).
	prior, err := h.store.Get(c.Request().Context(), tc.TenantID(), projectID, criterionID)
	if err != nil {
		slog.Warn("meti_assessments: pre-override load failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load meti assessment"})
	}
	if prior == nil {
		// No row yet for this (tenant, project, criterion) — operator must
		// /refresh first so the evaluator seeds the row. Generic body
		// (matches the unknown-criterion 404 above so the response is not
		// an oracle for which criteria the project has evaluated).
		return c.JSON(http.StatusNotFound, map[string]string{"error": "meti assessment not found"})
	}
	if prior.OverrideStatus != "" {
		slog.Warn("meti_assessments: re-override rejected; row already overridden",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"prior_override_status", prior.OverrideStatus,
			"requested_override_status", req.OverrideStatus,
		)
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "meti assessment has already been overridden; clear the existing override first",
		})
	}

	upd := repository.MetiAssessmentOverrideInput{
		OverrideStatus:    req.OverrideStatus,
		OverrideBy:        *uid,
		OverrideNote:      req.OverrideNote,
		ImprovementAction: req.ImprovementAction,
	}
	if err := h.store.OverrideStatus(c.Request().Context(), tc.TenantID(), projectID, criterionID, upd); err != nil {
		// F31 TOCTOU: sql.ErrNoRows after the state-machine pre-check
		// means a concurrent request applied an override between our
		// Get above and this UPDATE. Surface the same 409 as the
		// pre-check so the operator gets a consistent error rather
		// than a misleading 500.
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("meti_assessments: re-override rejected via state-machine guard (TOCTOU)",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"criterion_id", criterionID,
				"requested_override_status", req.OverrideStatus,
			)
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "meti assessment has already been overridden; clear the existing override first",
			})
		}
		slog.Warn("meti_assessments: OverrideStatus failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to apply meti assessment override"})
	}

	// Emit the domain-level audit row. We use the meti_assessments.id
	// from the pre-load as resource_id so the audit row points at the
	// specific (project, criterion) tuple.
	resourceID := prior.ID
	tenantID := tc.TenantID()
	auditDetails := map[string]interface{}{
		"project_id":             projectID.String(),
		"criterion_id":           criterionID,
		"criterion_phase":        prior.CriterionPhase,
		"prior_status":           prior.Status,
		"prior_override_status":  prior.OverrideStatus, // empty for the new-override path
		"new_override_status":    req.OverrideStatus,
		"improvement_action_set": req.ImprovementAction != nil,
		// F34: every override carries a human rationale (validated
		// non-empty at handler entry). The note length lands in audit
		// so an auditor can spot one-character / boilerplate notes
		// without us persisting the raw text in audit_logs.details
		// (the full note already lives in meti_assessments.override_note).
		"override_note_len": len(req.OverrideNote),
	}
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       AuditActionMetiAssessmentOverridden,
		ResourceType: ResourceTypeMetiAssessment,
		ResourceID:   &resourceID,
		Details:      auditDetails,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		// F5 / F32 audit-or-nothing: hard-fail on audit failure so the
		// ambient TenantTx middleware rolls back the OverrideStatus
		// UPDATE. A "override applied but audit lost" outcome would
		// silently let an operator override a METI verdict without the
		// required compliance trail.
		slog.Error("meti_assessments: domain audit log failed; rolling back override (F5/F32 audit-or-nothing)",
			"tenant_id", tenantID, "project_id", projectID, "criterion_id", criterionID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist meti assessment override audit trail; override rolled back",
		})
	}

	// Reload so the response reflects the persisted override_at /
	// updated_at fields written by the UPDATE.
	fresh, err := h.store.Get(c.Request().Context(), tc.TenantID(), projectID, criterionID)
	if err != nil || fresh == nil {
		slog.Warn("meti_assessments: post-override reload failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		// Override + audit have already committed; we just cannot
		// reload. Return the prior row plus the new override fields so
		// the client gets actionable data instead of a 500.
		prior.OverrideStatus = req.OverrideStatus
		prior.OverrideBy = uid
		if req.ImprovementAction != nil {
			prior.ImprovementAction = *req.ImprovementAction
		}
		prior.OverrideNote = req.OverrideNote
		return c.JSON(http.StatusOK, prior)
	}
	return c.JSON(http.StatusOK, fresh)
}

// ----------------------------------------------------------------------------
// DELETE /api/v1/projects/:id/meti/assessment/:criterion_id/override
// ----------------------------------------------------------------------------

// ClearOverride drops a prior operator override on a meti_assessments
// row (M3 Codex review #F33). Without this verb, an erroneous manual
// override is effectively a one-way trip: it continues to win over the
// evaluator's verdict in /meti/assessment, /meti/improvement-actions,
// and the Evidence Pack METI section with no way to correct it through
// the public API/CLI.
//
// Contract:
//   - Request body: {"note": "..."} — the operator's rationale for the
//     clear, REQUIRED (same 1..MaxMetiOverrideNoteLen bounds as the
//     /override note). Persisted in the audit row so an auditor can
//     reconstruct the correction.
//   - 404 (generic body, no oracle) when (tenant, project, criterion)
//     does not match an existing row OR the row exists but has no
//     override to clear. "Nothing to undo" is the same shape as "row
//     not found" so the response is not a probe oracle for prior
//     override state.
//   - 409 only fires from the TOCTOU path (the repository UPDATE found
//     zero rows after the pre-load said the row was overridden) — a
//     concurrent clear / re-override happened between Get and the
//     UPDATE.
//
// Audit-or-nothing (F5 / F32): the audit row is mandatory. If it
// fails, return 500 so the ambient TenantTx rolls back the
// ClearOverride UPDATE. Without that link, an operator could silently
// drop an override without leaving a compliance trail.
func (h *MetiHandler) ClearOverride(c echo.Context) error {
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
	// F37: confirm the project belongs to the authenticated tenant
	// BEFORE the clear-override chain runs.
	if status, body := h.requireProjectInTenant(c.Request().Context(), tc.TenantID(), projectID, "ClearOverride"); status != 0 {
		return c.JSON(status, body)
	}
	criterionID := c.Param("criterion_id")
	if criterionID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "criterion_id is required"})
	}
	// F26 carry-over: bound criterion_id to the production catalog so a
	// probe caller cannot enumerate the meti_assessments table by
	// triggering distinct error shapes for known vs unknown criteria.
	if _, ok := metisvc.GetCriterion(criterionID); !ok {
		slog.Warn("meti_assessments: unknown criterion id (clear-override)",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
		)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "meti assessment not found"})
	}

	var req metiClearOverrideRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	cleanedNote, status, body := validateMetiOverrideNote(req.Note)
	if status != 0 {
		slog.Warn("meti_assessments: clear-override rejected; note failed validation (F33/F34)",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"raw_note_len", len(req.Note),
		)
		return c.JSON(status, body)
	}

	uid := userIDOrNil(tc)
	if uid == nil {
		// Mirrors OverrideAssessment: an audited clear must be tied to a
		// real user identity.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "user identity required to clear a meti assessment override (audit trail)",
		})
	}

	// Pre-load: confirm the row exists AND currently carries an
	// override. The repository UPDATE also guards against the "no
	// override" case (WHERE override_status IS NOT NULL) — the pre-load
	// here gives us the prior override metadata for the audit row.
	prior, err := h.store.Get(c.Request().Context(), tc.TenantID(), projectID, criterionID)
	if err != nil {
		slog.Warn("meti_assessments: pre-clear load failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load meti assessment"})
	}
	if prior == nil || prior.OverrideStatus == "" {
		// Same generic 404 shape so the response is not an oracle for
		// override state. slog distinguishes the two reasons.
		slog.Warn("meti_assessments: clear-override rejected; no override to clear",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"row_exists", prior != nil,
		)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "meti assessment override not found"})
	}

	priorOverrideStatus := prior.OverrideStatus
	var priorOverrideBy string
	if prior.OverrideBy != nil {
		priorOverrideBy = prior.OverrideBy.String()
	}

	if err := h.store.ClearOverride(c.Request().Context(), tc.TenantID(), projectID, criterionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// TOCTOU: a concurrent request cleared / re-overrode between
			// our Get and this UPDATE. 409 (not 404) so the operator can
			// distinguish a race from "nothing was there".
			slog.Warn("meti_assessments: clear-override rejected via state-machine guard (TOCTOU)",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"criterion_id", criterionID,
			)
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "meti assessment override changed concurrently; reload and try again",
			})
		}
		slog.Warn("meti_assessments: ClearOverride failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to clear meti assessment override"})
	}

	// Audit-or-nothing (F5 / F32): hard-fail on audit failure so
	// TenantTx rolls back the clear. An "override cleared but audit
	// lost" outcome would silently let an operator drop an override
	// without leaving the required compliance trail — exactly the gap
	// F33 calls out.
	resourceID := prior.ID
	tenantID := tc.TenantID()
	auditDetails := map[string]interface{}{
		"project_id":            projectID.String(),
		"criterion_id":          criterionID,
		"criterion_phase":       prior.CriterionPhase,
		"prior_status":          prior.Status,
		"prior_override_status": priorOverrideStatus,
		"prior_override_by":     priorOverrideBy,
		"clear_note_len":        len(cleanedNote),
	}
	if err := h.audit.Log(c.Request().Context(), &model.CreateAuditLogInput{
		TenantID:     &tenantID,
		UserID:       uid,
		Action:       AuditActionMetiAssessmentOverrideCleared,
		ResourceType: ResourceTypeMetiAssessment,
		ResourceID:   &resourceID,
		Details:      auditDetails,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}); err != nil {
		slog.Error("meti_assessments: domain audit log failed; rolling back clear (F5/F32 audit-or-nothing)",
			"tenant_id", tenantID, "project_id", projectID, "criterion_id", criterionID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to persist meti assessment override-cleared audit trail; clear rolled back",
		})
	}

	// Reload so the response reflects the post-clear state (override_*
	// fields nulled, updated_at moved). Mirrors the OverrideAssessment
	// post-write reload.
	fresh, err := h.store.Get(c.Request().Context(), tc.TenantID(), projectID, criterionID)
	if err != nil || fresh == nil {
		slog.Warn("meti_assessments: post-clear reload failed",
			"tenant_id", tc.TenantID(),
			"project_id", projectID,
			"criterion_id", criterionID,
			"error", err,
		)
		// Clear + audit have already committed; we just cannot reload.
		// Synthesise the cleared shape from prior so the client gets
		// actionable data instead of a 500.
		prior.OverrideStatus = ""
		prior.OverrideBy = nil
		prior.OverrideAt = nil
		prior.OverrideNote = ""
		return c.JSON(http.StatusOK, prior)
	}
	return c.JSON(http.StatusOK, fresh)
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/meti/improvement-actions
// ----------------------------------------------------------------------------

// ListImprovementActions returns the project's meti_assessments rows
// whose EFFECTIVE status is not "achieved" — i.e. rows the operator
// still needs to act on. "Effective" means override_status wins over
// the evaluator's status (an operator override of "achieved" closes
// the action item, and an operator override of "not_achieved" creates
// one even when the evaluator returned "achieved").
//
// The repository's status filter is a single-value equality check, so
// the "not achieved" filtering happens in the handler. This is a
// server-side filter (vs forcing the Web UI to enumerate every status
// and post-process) — the row count is bounded by the 27-item catalog
// so the post-filter cost is negligible.
//
// X-Total-Count carries the count of returned actions (not the raw
// row count) so the UI can render "N 件の改善アクション" directly.
func (h *MetiHandler) ListImprovementActions(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	// F37: confirm the project belongs to the authenticated tenant
	// BEFORE the improvement-actions read so a probe caller cannot
	// enumerate cross-tenant project rows.
	if status, body := h.requireProjectInTenant(c.Request().Context(), tc.TenantID(), projectID, "ListImprovementActions"); status != 0 {
		return c.JSON(status, body)
	}

	// Optional phase filter (mirrors ListAssessments). Status filter is
	// intentionally NOT exposed — the endpoint's whole point is "status
	// != achieved", so accepting a ?status= query param would be
	// confusing.
	filter := repository.MetiAssessmentListFilter{
		Limit: MaxMetiAssessmentsListLimit, // pull the full catalog in one shot
	}
	if v := c.QueryParam("phase"); v != "" {
		if !isValidPhase(v) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "phase must be one of: env_setup, sbom_creation, sbom_operation",
			})
		}
		filter.CriterionPhase = v
	}

	rows, err := h.store.ListByProject(c.Request().Context(), tc.TenantID(), projectID, filter)
	if err != nil {
		slog.Warn("meti_assessments: improvement-actions list failed",
			"tenant_id", tc.TenantID(), "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list improvement actions"})
	}

	actions := make([]metiImprovementAction, 0, len(rows))
	for _, r := range rows {
		effective := effectiveStatus(r)
		if effective == criteria.StatusAchieved {
			continue
		}
		item := metiImprovementAction{
			CriterionID:       r.CriterionID,
			CriterionPhase:    r.CriterionPhase,
			Status:            r.Status,
			OverrideStatus:    r.OverrideStatus,
			EffectiveStatus:   effective,
			Evidence:          r.Evidence,
			ImprovementAction: r.ImprovementAction,
		}
		if cat, ok := metisvc.GetCriterion(r.CriterionID); ok {
			item.CriterionTitleJA = cat.TitleJA
			item.CriterionTitleEN = cat.TitleEN
		}
		actions = append(actions, item)
	}
	c.Response().Header().Set("X-Total-Count", strconv.Itoa(len(actions)))
	return c.JSON(http.StatusOK, metiImprovementActionsResponse{Actions: actions})
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// parseListFilter parses + validates the query-param filter for
// ListAssessments. Returns (filter, 0, nil) on success or
// (zero, status, body) when the caller should return a JSON error.
// F24 / F26 / F27 carry-over: explicit reject on out-of-band /
// out-of-allowlist values BEFORE the repository runs.
func (h *MetiHandler) parseListFilter(c echo.Context, tenantID, projectID uuid.UUID) (repository.MetiAssessmentListFilter, int, map[string]string) {
	filter := repository.MetiAssessmentListFilter{
		Limit: DefaultMetiAssessmentsListLimit,
	}
	if v := c.QueryParam("phase"); v != "" {
		if !isValidPhase(v) {
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{
				"error": "phase must be one of: env_setup, sbom_creation, sbom_operation",
			}
		}
		filter.CriterionPhase = v
	}
	if v := c.QueryParam("status"); v != "" {
		if !isValidStatus(v) {
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{
				"error": "status must be one of: achieved, not_achieved, needs_review, not_applicable",
			}
		}
		filter.Status = v
	}
	if v := c.QueryParam("has_override"); v != "" {
		switch v {
		case "true":
			t := true
			filter.HasOverride = &t
		case "false":
			f := false
			filter.HasOverride = &f
		default:
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{
				"error": "has_override must be 'true' or 'false'",
			}
		}
	}
	// F24: explicit reject on out-of-band limit. Empty / non-positive
	// values fall through to the default so legacy callers without an
	// explicit page keep their behaviour.
	if v := c.QueryParam("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{"error": "invalid limit"}
		}
		if n > MaxMetiAssessmentsListLimit {
			slog.Warn("meti_assessments: limit exceeds maximum",
				"tenant_id", tenantID,
				"project_id", projectID,
				"requested_limit", n,
				"max_limit", MaxMetiAssessmentsListLimit,
			)
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{"error": "limit exceeds maximum"}
		}
		if n >= 1 {
			filter.Limit = n
		}
	}
	// F27: explicit reject on out-of-band offset.
	if v := c.QueryParam("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{"error": "invalid offset"}
		}
		if n > MaxMetiAssessmentsListOffset {
			slog.Warn("meti_assessments: offset exceeds maximum",
				"tenant_id", tenantID,
				"project_id", projectID,
				"requested_offset", n,
				"max_offset", MaxMetiAssessmentsListOffset,
			)
			return repository.MetiAssessmentListFilter{}, http.StatusBadRequest, map[string]string{"error": "offset exceeds maximum"}
		}
		if n >= 0 {
			filter.Offset = n
		}
	}
	return filter, 0, nil
}

// isValidPhase mirrors the meti_assessments CHECK on criterion_phase.
func isValidPhase(phase string) bool {
	switch phase {
	case "env_setup", "sbom_creation", "sbom_operation":
		return true
	}
	return false
}

// isValidStatus mirrors the meti_assessments CHECK on status (and on
// override_status). The empty string is rejected — clear-override is a
// separate handler path (M4 follow-up).
func isValidStatus(status string) bool {
	switch status {
	case criteria.StatusAchieved,
		criteria.StatusNotAchieved,
		criteria.StatusNeedsReview,
		criteria.StatusNotApplicable:
		return true
	}
	return false
}

// effectiveStatus returns override_status if the operator has applied
// one, otherwise the evaluator-stamped status. Mirrors the precedence
// the UI shows in the assessment matrix ("operator wins").
func effectiveStatus(a repository.MetiAssessment) string {
	if a.OverrideStatus != "" {
		return a.OverrideStatus
	}
	return a.Status
}
