package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// VexDraftsHandler serves the M1-5 VEX draft endpoints (issue #30):
//
//	POST   /api/v1/projects/:id/triage/run
//	GET    /api/v1/projects/:id/vex-drafts
//	GET    /api/v1/projects/:id/vex-drafts/:draft_id
//	PUT    /api/v1/projects/:id/vex-drafts/:draft_id/decision
//	POST   /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse
//
// The handler is intentionally thin — it parses input, surfaces auth /
// tenant context from middleware, and delegates everything else to the
// runner. Authorisation (tenant binding, write permission) is enforced
// at the route group level via the existing Auth + TenantTx + audit
// middleware chain that wraps every other authenticated endpoint; see
// cmd/server/main.go for the wire-up.
type VexDraftsHandler struct {
	runner *triage.Runner
}

// NewVexDraftsHandler wires the handler.
func NewVexDraftsHandler(runner *triage.Runner) *VexDraftsHandler {
	return &VexDraftsHandler{runner: runner}
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

type runTriageRequest struct {
	// VulnerabilityID is the local vulnerabilities row id. CVEID is also
	// required (server uses it both for advisory_excerpts lookup and as
	// the audit log target).
	VulnerabilityID string `json:"vulnerability_id"`
	CVEID           string `json:"cve_id"`
	// ComponentID is optional and now deprecated as a wire field. When
	// omitted, the server resolves component_id(s) from
	// (tenant, project, vulnerability_id) via the
	// ComponentVulnerabilityResolver and fans out one draft per
	// (component, vuln) pair (M1 Codex review #F3). Callers that have a
	// pinned component_id may still supply it; the server uses that one
	// component without fanning out.
	ComponentID string `json:"component_id,omitempty"`
}

type runTriageResponse struct {
	Draft *repository.VEXDraft `json:"draft"`
	// Drafts carries every persisted draft when the run fanned out
	// across multiple components (M1 Codex review #F3). For a single-
	// component triage Drafts is a one-element slice with the same
	// element as Draft.
	Drafts    []*repository.VEXDraft `json:"drafts"`
	LLMCallID string                 `json:"llm_call_id,omitempty"`
	Parsed    *triage.ParsedDecision `json:"parsed_decision,omitempty"`
	Clamped   bool                   `json:"clamped"`
	Threshold float64                `json:"threshold"`
	// AIDisabled reports whether the runner skipped the LLM call because
	// no BYOK provider is configured. The server still persisted
	// under_investigation drafts + audit rows; the CLI uses this flag to
	// surface the "APIキー未設定" hint without inventing a counter-only
	// path (M1 Codex review #F4).
	AIDisabled bool `json:"ai_disabled,omitempty"`
}

type vexDraftListResponse struct {
	Drafts []repository.VEXDraft `json:"drafts"`
}

type decisionRequest struct {
	Decision            string `json:"decision"` // approved | edited | rejected
	EditedState         string `json:"edited_state,omitempty"`
	EditedJustification string `json:"edited_justification,omitempty"`
	EditedDetail        string `json:"edited_detail,omitempty"`
	Note                string `json:"note,omitempty"`
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/triage/run
// ----------------------------------------------------------------------------

// RunTriage executes one AI triage cycle for (project, vulnerability)
// and persists a fresh vex_drafts row + audit log.
func (h *VexDraftsHandler) RunTriage(c echo.Context) error {
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

	var req runTriageRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.CVEID == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cve_id is required"})
	}
	vulnID, err := uuid.Parse(req.VulnerabilityID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid vulnerability_id"})
	}
	var componentID *uuid.UUID
	if req.ComponentID != "" {
		parsed, err := uuid.Parse(req.ComponentID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid component_id"})
		}
		componentID = &parsed
	}

	uid := userIDOrNil(tc)
	res, err := h.runner.Run(c.Request().Context(), triage.RunInput{
		TenantID:        tc.TenantID(),
		ProjectID:       projectID,
		VulnerabilityID: vulnID,
		CVEID:           req.CVEID,
		ComponentID:     componentID,
		UserID:          uid,
		IPAddress:       c.RealIP(),
		UserAgent:       c.Request().UserAgent(),
	})
	if status, body, ok := mapRunnerError(err); ok {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusCreated, buildRunTriageResponse(res))
}

// buildRunTriageResponse projects a triage.RunResult into the wire DTO.
// AI-disabled runs leave LLMCallID and Parsed zero-valued; the JSON
// `omitempty` tags drop them so the response stays compact.
func buildRunTriageResponse(res *triage.RunResult) runTriageResponse {
	if res == nil {
		return runTriageResponse{}
	}
	resp := runTriageResponse{
		Draft:      res.Draft,
		Drafts:     res.Drafts,
		Parsed:     res.Parsed,
		Clamped:    res.Clamped,
		Threshold:  res.Threshold,
		AIDisabled: res.AIDisabled,
	}
	if res.LLMCallID != uuid.Nil {
		resp.LLMCallID = res.LLMCallID.String()
	}
	return resp
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/vex-drafts
// ----------------------------------------------------------------------------

// ListDrafts returns the project's vex_drafts filtered by optional
// cve_id and decision query params.
func (h *VexDraftsHandler) ListDrafts(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	filter := repository.VEXDraftListFilter{
		CVEID:    c.QueryParam("cve_id"),
		Decision: c.QueryParam("decision"),
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			filter.Offset = n
		}
	}

	drafts, err := h.runner.ListDrafts(c.Request().Context(), tc.TenantID(), projectID, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list vex drafts"})
	}
	if drafts == nil {
		drafts = []repository.VEXDraft{}
	}
	return c.JSON(http.StatusOK, vexDraftListResponse{Drafts: drafts})
}

// ----------------------------------------------------------------------------
// GET /api/v1/projects/:id/vex-drafts/:draft_id
// ----------------------------------------------------------------------------

// GetDraft returns one vex_drafts row scoped to the caller's tenant.
func (h *VexDraftsHandler) GetDraft(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if _, err := uuid.Parse(c.Param("id")); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	draftID, err := uuid.Parse(c.Param("draft_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid draft id"})
	}

	draft, err := h.runner.GetDraft(c.Request().Context(), tc.TenantID(), draftID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load vex draft"})
	}
	if draft == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "vex draft not found"})
	}
	return c.JSON(http.StatusOK, draft)
}

// ----------------------------------------------------------------------------
// PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision
// ----------------------------------------------------------------------------

// Decide applies a human approve / edit / reject decision and (on
// approve/edit) mirrors the verdict into vex_statements.
func (h *VexDraftsHandler) Decide(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	if !tc.CanWrite() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "write permission required"})
	}
	if _, err := uuid.Parse(c.Param("id")); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	draftID, err := uuid.Parse(c.Param("draft_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid draft id"})
	}

	var req decisionRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	switch req.Decision {
	case triage.DecisionApproved,
		triage.DecisionEdited,
		triage.DecisionRejected:
		// ok
	default:
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "decision must be one of: approved, edited, rejected",
		})
	}

	uid := userIDOrNil(tc)
	if uid == nil {
		// agent A's VEXDraftDecisionUpdate requires a non-nil
		// decision_by uuid (audit trail). Self-hosted requests without
		// a user id cannot apply a decision through this endpoint —
		// fail loudly so the caller knows why.
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "user identity required to decide a vex draft (audit trail)",
		})
	}
	updated, err := h.runner.UpdateDecision(c.Request().Context(), triage.DecisionInput{
		TenantID:            tc.TenantID(),
		DraftID:             draftID,
		UserID:              uid,
		Decision:            req.Decision,
		EditedState:         req.EditedState,
		EditedJustification: req.EditedJustification,
		EditedDetail:        req.EditedDetail,
		Note:                req.Note,
		IPAddress:           c.RealIP(),
		UserAgent:           c.Request().UserAgent(),
	})
	if status, body, ok := mapRunnerError(err); ok {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusOK, updated)
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/vex-drafts/:draft_id/reanalyse
// ----------------------------------------------------------------------------

// Reanalyse runs a fresh triage cycle whose audit row carries
// `vex_draft_reanalysed`. The original draft is not mutated — a new
// vex_drafts row is inserted so historians can diff AI verdicts over
// time.
//
// The caller's body MAY override CVEID / VulnerabilityID / ComponentID
// (mirroring RunTriage); if omitted, the runner re-uses the values
// from the source draft.
func (h *VexDraftsHandler) Reanalyse(c echo.Context) error {
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
	draftID, err := uuid.Parse(c.Param("draft_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid draft id"})
	}

	// Load the source draft so we can default CVEID / VulnerabilityID
	// / ComponentID from it (the UI typically calls reanalyse with an
	// empty body — "redo what you just did").
	source, err := h.runner.GetDraft(c.Request().Context(), tc.TenantID(), draftID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load source draft"})
	}
	if source == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "source vex draft not found"})
	}
	// F7 (Codex M1 round 2): GetDraft scopes by (tenant, draft_id) only —
	// no project boundary check. Without the equality below a draft from
	// project A could be reanalysed via project B's route, persisting a
	// new draft under project B that still carries project A's
	// component_id (vex_drafts has no composite FK over project_id /
	// component_id). Reject the cross-project case as 404 so the URL's
	// project_id stays authoritative.
	if source.ProjectID != projectID {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "source vex draft not found in project scope"})
	}

	var override runTriageRequest
	_ = c.Bind(&override) // tolerated when body is empty

	cveID := source.CVEID
	if override.CVEID != "" {
		cveID = override.CVEID
	}
	vulnID := source.VulnerabilityID
	if override.VulnerabilityID != "" {
		if parsed, err := uuid.Parse(override.VulnerabilityID); err == nil {
			vulnID = parsed
		}
	}
	// Agent A's VEXDraft stores ComponentID as a non-pointer uuid.UUID
	// (vex_drafts.component_id is NOT NULL). Convert to a pointer for
	// RunInput's optional component override.
	componentID := source.ComponentID
	componentIDPtr := &componentID
	if override.ComponentID != "" {
		if parsed, err := uuid.Parse(override.ComponentID); err == nil {
			componentIDPtr = &parsed
		}
	}

	uid := userIDOrNil(tc)
	src := source.ID
	res, err := h.runner.Run(c.Request().Context(), triage.RunInput{
		TenantID:           tc.TenantID(),
		ProjectID:          projectID,
		VulnerabilityID:    vulnID,
		CVEID:              cveID,
		ComponentID:        componentIDPtr,
		UserID:             uid,
		IPAddress:          c.RealIP(),
		UserAgent:          c.Request().UserAgent(),
		Reanalyse:          true,
		ReanalyseFromDraft: &src,
	})
	if status, body, ok := mapRunnerError(err); ok {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusCreated, buildRunTriageResponse(res))
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// userIDOrNil returns a pointer to the authenticated user id, or nil if
// the request has no user (self-hosted default tenant).
func userIDOrNil(tc *middleware.TenantContext) *uuid.UUID {
	uid := tc.UserID()
	if uid == uuid.Nil {
		return nil
	}
	v := uid
	return &v
}

// mapRunnerError translates runner errors into HTTP status + JSON body.
// Returns (status, body, true) when err is non-nil; (0, nil, false)
// otherwise so the caller can fall through to the success path.
//
// Status mapping:
//   - llm.DisabledError                                → 503
//   - triage.ErrEmptyEvidence                           → 422 (spec §8.5)
//   - triage.ErrInvalidEvidence                         → 422
//   - triage.ErrVulnerabilityNotInTenant                → 404 (#F3)
//   - triage.ErrComponentNotInVulnerabilityScope        → 404 (#F6)
//   - input-validation errors (missing fields)          → 400
//   - everything else                                   → 500
func mapRunnerError(err error) (int, map[string]string, bool) {
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
	if errors.Is(err, triage.ErrEmptyEvidence) {
		return http.StatusUnprocessableEntity, map[string]string{
			"error": err.Error(),
		}, true
	}
	if errors.Is(err, triage.ErrInvalidEvidence) {
		return http.StatusUnprocessableEntity, map[string]string{
			"error": err.Error(),
		}, true
	}
	// F3 / F6 (Codex M1): both surface as 404 so the client cannot
	// distinguish "vuln has no components in this project scope" from
	// "supplied component_id is not in the vuln scope" — that
	// distinction is intentionally hidden to avoid leaking tenant
	// internals via probe responses.
	if errors.Is(err, triage.ErrVulnerabilityNotInTenant) ||
		errors.Is(err, triage.ErrComponentNotInVulnerabilityScope) {
		return http.StatusNotFound, map[string]string{
			"error": err.Error(),
		}, true
	}
	// Heuristic — runner returns "X is required" / "is not in allowlist"
	// for caller-fixable problems. Be conservative: anything we do not
	// explicitly recognise becomes 500.
	msg := err.Error()
	for _, marker := range []string{"is required", "is not in allowlist", "not found", "must be"} {
		if containsSubstring(msg, marker) {
			if marker == "not found" {
				return http.StatusNotFound, map[string]string{"error": msg}, true
			}
			return http.StatusBadRequest, map[string]string{"error": msg}, true
		}
	}
	return http.StatusInternalServerError, map[string]string{"error": msg}, true
}

// containsSubstring is strings.Contains with the import kept local so
// this file does not pull in the strings package solely for one call.
func containsSubstring(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
