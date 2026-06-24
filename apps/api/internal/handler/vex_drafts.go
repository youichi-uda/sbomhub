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
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

// Pagination bounds for ListDrafts (M1 Codex review #F24). The bug was
// that GET /api/v1/projects/:id/vex-drafts accepted any positive int
// from `?limit=` and passed it straight to the repository, which
// reflected it into SQL `LIMIT $N`. A single API-key-reachable request
// such as `?limit=2147483647` would force the DB to scan + materialise
// the full vex_drafts page for the project, then accumulate every row
// in memory before JSON-marshaling — an unauthenticated-grade DoS
// against tenants with a non-trivial backlog. The handler now rejects
// out-of-band values with 400 BEFORE the repository runs, and the
// repository clamps as defense-in-depth in case a future internal caller
// supplies an unfiltered Limit.
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
	// MaxListOffset bounds the `?offset=` query parameter for
	// ListDrafts (M1 Codex review #F27). Same loud-failure posture
	// as the #F24 limit clamp: a request like `?offset=2147483647`
	// would otherwise force the DB to skip billions of rows before
	// producing any output (the underlying vex_drafts query carries
	// a tenant + project + cve_id + decision filter, but Postgres
	// still materialises the offset before discarding rows). The
	// cap mirrors VulnsMaxOffset in sbom.go so operators have a
	// single mental model for "deep pagination probe → 400".
	MaxListOffset = 10000
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
		Limit:    DefaultListLimit,
	}
	// #F24: explicit reject on out-of-band limit. A silent clamp would
	// hide the DoS-probe behaviour from telemetry and could mask buggy
	// clients that hard-code a too-large page. Empty / unparseable /
	// non-positive values fall through to DefaultListLimit so the
	// pre-#F24 callers (CLI, web UI without an explicit page) keep their
	// behaviour.
	if v := c.QueryParam("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid limit"})
		}
		if n > MaxListLimit {
			slog.Warn("vex_drafts: limit exceeds maximum",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"requested_limit", n,
				"max_limit", MaxListLimit,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "limit exceeds maximum"})
		}
		if n >= 1 {
			filter.Limit = n
		}
		// n < 1 falls through to DefaultListLimit (already set above).
	}
	if v := c.QueryParam("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid offset"})
		}
		// #F27: explicit reject on out-of-band offset. Same posture as
		// the #F24 limit clamp — a silent clamp would hide the
		// deep-pagination probe behaviour from telemetry.
		if n > MaxListOffset {
			slog.Warn("vex_drafts: offset exceeds maximum",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"requested_offset", n,
				"max_offset", MaxListOffset,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "offset exceeds maximum"})
		}
		if n >= 0 {
			filter.Offset = n
		}
		// n < 0 falls through to 0 (default zero value on filter.Offset).
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

// GetDraft returns one vex_drafts row scoped to the caller's tenant
// AND to the route's project. M1 Codex review #F8: the previous version
// validated c.Param("id") but discarded it before calling
// runner.GetDraft(tenant, draftID); repository.Get is scoped only to
// (tenant_id, id), so a tenant operator could enumerate drafts from
// another project of the same tenant by guessing draft IDs. We now load
// via loadDraftScoped which enforces draft.ProjectID == route projectID
// and folds both "missing" and "wrong project" into the same opaque 404
// to avoid leaking cross-project draft existence (see also #F10 for the
// equivalent 404-body opacity on runner sentinels).
func (h *VexDraftsHandler) GetDraft(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	if tc == nil || tc.TenantID() == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	draftID, err := uuid.Parse(c.Param("draft_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid draft id"})
	}

	draft, status, body := h.loadDraftScoped(c.Request().Context(), tc.TenantID(), projectID, draftID, "GetDraft")
	if status != 0 {
		return c.JSON(status, body)
	}
	return c.JSON(http.StatusOK, draft)
}

// ----------------------------------------------------------------------------
// PUT /api/v1/projects/:id/vex-drafts/:draft_id/decision
// ----------------------------------------------------------------------------

// Decide applies a human approve / edit / reject decision and (on
// approve/edit) mirrors the verdict into vex_statements.
//
// M1 Codex review #F9: previously the route's project_id was parsed but
// discarded, and runner.UpdateDecision was called with only
// (tenant, draft_id). syncToVEXStatements then used the draft's *own*
// ProjectID, so a caller scoped to project B could approve / edit /
// reject a draft belonging to project A and silently mirror the verdict
// into project A's vex_statements. We now load the draft via
// loadDraftScoped (the same helper #F8 / #F7 use) and reject 404 before
// dispatching the decision — folding "missing draft" and "draft in
// another project" into one opaque body.
func (h *VexDraftsHandler) Decide(c echo.Context) error {
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

	// #F9: load + enforce project boundary BEFORE delegating to the
	// runner. The runner's UpdateDecision is scoped only by (tenant,
	// draft_id), so without this pre-flight check a cross-project URL
	// would mutate the foreign draft and (on approve/edit) sync into the
	// foreign project's vex_statements via syncToVEXStatements.
	if _, status, body := h.loadDraftScoped(c.Request().Context(), tc.TenantID(), projectID, draftID, "Decide"); status != 0 {
		return c.JSON(status, body)
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
	//
	// F7 (Codex M1 round 2) + #F8 / #F9 (round 3): GetDraft scopes by
	// (tenant, draft_id) only — no project boundary check. Without the
	// loadDraftScoped helper below a draft from project A could be
	// reanalysed via project B's route, persisting a new draft under
	// project B that still carries project A's component_id (vex_drafts
	// has no composite FK over project_id / component_id). The helper
	// folds "missing source draft" and "draft in another project" into
	// the same opaque 404 body to avoid leaking cross-project existence.
	source, status, body := h.loadDraftScoped(c.Request().Context(), tc.TenantID(), projectID, draftID, "Reanalyse")
	if status != 0 {
		return c.JSON(status, body)
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

// loadDraftScoped loads a vex_drafts row and enforces the route's
// project boundary (M1 Codex review #F7 / #F8 / #F9). It is the single
// gatekeeper for GetDraft, Decide, and Reanalyse — three endpoints that
// previously each had different (or missing) project-scope checks even
// though they all sit behind the same /projects/:id/vex-drafts/:draft_id
// prefix.
//
// Return contract:
//   - (*draft, 0, nil) on success.
//   - (nil, status, body) when the handler should return a JSON error
//     response; status is 404 for both "draft does not exist" and
//     "draft belongs to another project of this tenant", and 500 for
//     storage failures. The body is intentionally identical for the
//     two 404 cases so a probe caller cannot distinguish them.
//
// The endpointName argument is recorded on the slog warning emitted for
// 404 / 500 cases so operators can trace which endpoint surfaced the
// boundary violation (the user-facing body is generic; the precise
// reason lives in server logs — matches the #F10 contract on sentinel
// 404s).
func (h *VexDraftsHandler) loadDraftScoped(
	ctx context.Context,
	tenantID, projectID, draftID uuid.UUID,
	endpointName string,
) (*repository.VEXDraft, int, map[string]string) {
	draft, err := h.runner.GetDraft(ctx, tenantID, draftID)
	if err != nil {
		slog.Warn("vex_drafts: load draft failed",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"draft_id", draftID,
			"error", err,
		)
		return nil, http.StatusInternalServerError, map[string]string{"error": "failed to load vex draft"}
	}
	if draft == nil {
		slog.Warn("vex_drafts: draft not found",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"project_id", projectID,
			"draft_id", draftID,
		)
		return nil, http.StatusNotFound, map[string]string{"error": "vex draft not found"}
	}
	if draft.ProjectID != projectID {
		// Distinct slog so operators can alarm on cross-project probes
		// (#F8 / #F9). User-facing body is identical to the "draft does
		// not exist" branch above so the caller cannot tell the
		// difference (would otherwise be a tenant-internal disclosure).
		slog.Warn("vex_drafts: draft in another project of the same tenant",
			"endpoint", endpointName,
			"tenant_id", tenantID,
			"route_project_id", projectID,
			"draft_project_id", draft.ProjectID,
			"draft_id", draftID,
		)
		return nil, http.StatusNotFound, map[string]string{"error": "vex draft not found"}
	}
	return draft, 0, nil
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
//   - triage.ErrCVEIDMismatch                           → 400 (#F12)
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
	// F3 / F6 (Codex M1 rounds 1+2): both surface as 404 so the client
	// cannot distinguish "vuln has no components in this project scope"
	// from "supplied component_id is not in the vuln scope".
	//
	// F10 (Codex M1 round 3): the previous version still leaked which
	// sentinel fired through the response body — {"error": err.Error()}
	// yielded "triage: vulnerability not found in tenant scope" vs
	// "triage: component not in vulnerability scope", letting a probe
	// caller infer tenant-internal state (does this vulnerability exist
	// in my scope at all? is the component graph wrong?). We now return
	// a single generic body for both sentinels and keep the precise
	// reason only in server logs so operators can still triage failed
	// requests.
	if errors.Is(err, triage.ErrVulnerabilityNotInTenant) ||
		errors.Is(err, triage.ErrComponentNotInVulnerabilityScope) {
		slog.Warn("triage: 404 sentinel mapped to generic body",
			"sentinel", err.Error(),
		)
		return http.StatusNotFound, map[string]string{
			"error": "triage target not found",
		}, true
	}
	// F12 (Codex M1 round 4): caller-supplied cve_id did not match the
	// authoritative cve_id stored on the vulnerabilities row. We return
	// a generic 400 body ("triage target invalid") rather than echoing
	// the sentinel string so a probe caller cannot distinguish
	// "mismatched cve_id" from other targeting errors via the response.
	// Precise reason stays in server logs.
	if errors.Is(err, triage.ErrCVEIDMismatch) {
		slog.Warn("triage: cve_id mismatch rejected",
			"sentinel", err.Error(),
		)
		return http.StatusBadRequest, map[string]string{
			"error": "triage target invalid",
		}, true
	}
	// F25 (Codex M1 round 16): ComponentID-less request resolved to more
	// components than the configured fan-out cap. We return 413 Payload
	// Too Large with an actionable hint ("supply component_id") rather
	// than truncating the fan-out silently. The full sentinel message
	// (which includes resolved-count and cap) lands in server logs only
	// to avoid leaking the precise project topology back to the caller.
	if errors.Is(err, triage.ErrFanOutExceeded) {
		slog.Warn("triage: fan-out exceeds cap",
			"sentinel", err.Error(),
		)
		return http.StatusRequestEntityTooLarge, map[string]string{
			"error": "too many affected components — supply component_id to triage one (component, vulnerability) pair",
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
