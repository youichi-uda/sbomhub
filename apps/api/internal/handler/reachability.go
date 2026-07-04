package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

// reachabilityUpserter is the narrow write surface the reachability
// upload endpoint depends on. *repository.ReachabilityResultsRepository
// satisfies it via its existing Upsert method. Declared as an interface
// so reachability_test.go can substitute a recording fake without a live
// PostgreSQL connection (mirrors the MetiAssessmentStore / fakeVEXApplier
// pattern).
type reachabilityUpserter interface {
	Upsert(ctx context.Context, rr *repository.ReachabilityResult) error
}

// ReachabilityAuditLogger is the subset of *repository.AuditRepository
// the upload endpoint uses to emit the single reachability_uploaded
// domain audit row. Same shape / rationale as VEXAuditLogger and
// MetiAuditLogger: an interface so the unit test can assert the
// audit-or-nothing emit surface without a live audit repository.
type ReachabilityAuditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
}

// ReachabilityProjectReader is the subset of *repository.ProjectRepository
// the upload endpoint uses to confirm the path :id project belongs to the
// authenticated tenant BEFORE any reachability_results write happens.
//
// reachability_results.project_id is a soft reference (no FK — see
// migration 034 header: "Mirrors the soft-reference convention from
// llm_calls"), so without this check a probe caller could persist verdict
// rows under an arbitrary or non-existent project UUID inside its own
// tenant. GetByTenant returns sql.ErrNoRows for both "row does not exist"
// and "row belongs to another tenant"; the handler maps both to a generic
// 404. This is the exact F37 precedent MetiProjectReader established for
// the sibling soft-reference meti_assessments table.
type ReachabilityProjectReader interface {
	GetByTenant(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error)
}

// reachabilityTargetsReader is the read surface GET /reachability/targets
// depends on: the project-scoped (cve_id, component_id, purl) tuples the CLI
// needs to attach a reachability verdict to each component_id (the upload
// REQUIRES component_id, which the plain GET /vulnerabilities response does
// not carry). *repository.VulnerabilityRepository satisfies it via
// ListReachabilityTargets. Declared as an interface so reachability_targets_test.go
// can substitute a fake without a live PostgreSQL connection (same rationale as
// reachabilityUpserter / ReachabilityProjectReader above).
type reachabilityTargetsReader interface {
	ListReachabilityTargets(ctx context.Context, tenantID, projectID uuid.UUID, ecosystem string) ([]repository.ReachabilityTarget, error)
}

// reachabilityStatuses is the closed set of verdicts the analyser
// contract defines (migration 034 CHECK constraint). Validating in the
// handler surfaces an enum violation as a clean 400 BEFORE the DB round
// trip, rather than mapping a pq CHECK error to 500 after the fact.
var reachabilityStatuses = map[string]bool{
	"not_present": true,
	"import_only": true,
	"reachable":   true,
	"unknown":     true,
}

// ReachabilityHandler persists reachability verdicts uploaded by the CLI,
// which runs the Go analyzer client-side and POSTs the batch here
// (M32 Wave C). This endpoint is the sole production writer of
// reachability_results.
type ReachabilityHandler struct {
	// upserter is the reachability_results write surface (production:
	// *repository.ReachabilityResultsRepository). Each row upserts inside
	// the request's ambient TenantTx so a mid-batch failure rolls the
	// whole batch back.
	upserter reachabilityUpserter
	// audit is the writer for the single reachability_uploaded domain
	// audit row. audit-or-nothing: a failure here hard-fails 500 so the
	// ambient TenantTx rolls the upserts back (F168 precedent).
	audit ReachabilityAuditLogger
	// projects gates the soft-reference 404 (see ReachabilityProjectReader).
	projects ReachabilityProjectReader
	// targets is the read surface for GET /reachability/targets (production:
	// *repository.VulnerabilityRepository). It runs under the ambient TenantTx
	// so its components join is RLS-scoped to the caller's tenant.
	targets reachabilityTargetsReader
}

// NewReachabilityHandler wires the handler. All four dependencies are
// required: the upserter to persist verdicts, the audit logger for the
// mandatory reachability_uploaded row (audit-or-nothing), the project reader
// for the tenant-scoped 404 on the soft-reference project_id, and the targets
// reader for the CLI worklist read endpoint (GET /reachability/targets).
func NewReachabilityHandler(upserter reachabilityUpserter, audit ReachabilityAuditLogger, projects ReachabilityProjectReader, targets reachabilityTargetsReader) *ReachabilityHandler {
	return &ReachabilityHandler{upserter: upserter, audit: audit, projects: projects, targets: targets}
}

// reachabilityResultInput is one uploaded verdict. component_id / cve_id /
// status are required; ecosystem / confidence / analyzer_version /
// analyzed_at / evidence are optional. confidence is a pointer so a
// callgraph-only pass that skips scoring can omit it (distinct from 0.0).
type reachabilityResultInput struct {
	ComponentID     string          `json:"component_id"`
	CVEID           string          `json:"cve_id"`
	Ecosystem       string          `json:"ecosystem"`
	Status          string          `json:"status"`
	Confidence      *float64        `json:"confidence"`
	AnalyzerVersion string          `json:"analyzer_version"`
	AnalyzedAt      *time.Time      `json:"analyzed_at"`
	Evidence        json.RawMessage `json:"evidence"`
}

// reachabilityUploadRequest is the POST body: a batch of verdicts. The
// server fills tenant_id (session) and project_id (path) on every row —
// the client never supplies them.
type reachabilityUploadRequest struct {
	Results []reachabilityResultInput `json:"results"`
}

// reachabilityUploadResponse is the 201 body: the number of rows upserted.
type reachabilityUploadResponse struct {
	Upserted int `json:"upserted"`
}

// Upload persists a batch of reachability verdicts for one project.
//
// POST /api/v1/projects/:id/reachability
//
// Flow: parse project uuid → require tenant context → bind + validate the
// batch → confirm the project belongs to the tenant (soft-reference 404)
// → upsert every row inside the ambient TenantTx → emit exactly one
// reachability_uploaded audit row (audit-or-nothing) → 201 {"upserted": n}.
func (h *ReachabilityHandler) Upload(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	// Tenant context is bound by MultiAuth + TenantTx upstream. Refuse
	// rather than write with an empty tenant (RLS WITH CHECK would reject
	// it anyway, but a clean 401 is the honest surface).
	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	var req reachabilityUploadRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if len(req.Results) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "results is required and must be non-empty"})
	}

	ctx := c.Request().Context()

	// Soft-reference 404: the project must exist in this tenant before we
	// persist any verdict against it (F37 precedent for the no-FK
	// project_id column — see ReachabilityProjectReader).
	if status, body := h.requireProjectInTenant(ctx, tenantID, projectID); status != 0 {
		return c.JSON(status, body)
	}

	// Validate + materialise every row BEFORE any write so a malformed
	// batch fails 400 with nothing persisted (the ambient TenantTx never
	// sees a partial write).
	rows := make([]*repository.ReachabilityResult, 0, len(req.Results))
	for i, in := range req.Results {
		compRaw := strings.TrimSpace(in.ComponentID)
		if compRaw == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: component_id is required", i),
			})
		}
		componentID, err := uuid.Parse(compRaw)
		if err != nil || componentID == uuid.Nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: component_id must be a valid uuid", i),
			})
		}

		cveID := strings.TrimSpace(in.CVEID)
		if cveID == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: cve_id is required", i),
			})
		}

		if !reachabilityStatuses[in.Status] {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: status must be one of not_present|import_only|reachable|unknown", i),
			})
		}

		if in.Confidence != nil && (*in.Confidence < 0 || *in.Confidence > 1) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: confidence must be within [0,1]", i),
			})
		}

		rows = append(rows, &repository.ReachabilityResult{
			TenantID:        tenantID,  // server-filled from session
			ProjectID:       projectID, // server-filled from path
			ComponentID:     componentID,
			CVEID:           cveID,
			Ecosystem:       strings.TrimSpace(in.Ecosystem),
			Status:          in.Status,
			Evidence:        in.Evidence,
			Confidence:      in.Confidence,
			AnalyzerVersion: strings.TrimSpace(in.AnalyzerVersion),
			AnalyzedAt:      in.AnalyzedAt,
		})
	}

	// Upsert every row inside the ambient TenantTx. A failure hard-fails
	// 500 so the transaction (and every prior upsert in this batch) rolls
	// back — the CLI can safely retry the whole batch.
	for i, rr := range rows {
		if err := h.upserter.Upsert(ctx, rr); err != nil {
			slog.Error("reachability upload: upsert failed; rolling back batch",
				"tenant_id", tenantID, "project_id", projectID, "index", i, "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to persist reachability results",
			})
		}
	}

	// Emit exactly one reachability_uploaded audit row for the batch,
	// audit-or-nothing: a failure hard-fails 500 so the ambient TenantTx
	// rolls the upserts back. The compliance record of "the analyser
	// verdicts for project P were persisted" MUST land atomically with the
	// verdicts themselves (F168 / F32 precedent).
	if h.audit != nil {
		var userID *uuid.UUID
		if uid := middleware.GetUserID(c); uid != uuid.Nil {
			userID = &uid
		}
		rid := projectID
		if err := h.audit.Log(ctx, &model.CreateAuditLogInput{
			TenantID:     &tenantID,
			UserID:       userID,
			Action:       model.AuditActionReachabilityUploaded,
			ResourceType: model.ResourceReachability,
			ResourceID:   &rid,
			Details: map[string]interface{}{
				"upserted": len(rows),
			},
			IPAddress: c.RealIP(),
			UserAgent: c.Request().UserAgent(),
		}); err != nil {
			slog.Error("reachability upload: audit log failed; rolling back batch (audit-or-nothing)",
				"tenant_id", tenantID, "project_id", projectID, "upserted", len(rows), "error", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to persist reachability audit trail; upload rolled back",
			})
		}
	}

	return c.JSON(http.StatusCreated, reachabilityUploadResponse{Upserted: len(rows)})
}

// reachabilityTargetItem is one row of the GET /reachability/targets
// response: a (cve_id, component_id) pair the CLI analyzer must judge.
// ecosystem is derived from purl at the edge (repository.EcosystemFromPurl);
// purl may be "" when the component row carries no package URL.
type reachabilityTargetItem struct {
	CVEID            string `json:"cve_id"`
	ComponentID      string `json:"component_id"`
	Purl             string `json:"purl"`
	ComponentName    string `json:"component_name"`
	ComponentVersion string `json:"component_version"`
	Ecosystem        string `json:"ecosystem"`
}

// reachabilityTargetsResponse is the 200 body: the CLI reachability worklist.
type reachabilityTargetsResponse struct {
	Targets []reachabilityTargetItem `json:"targets"`
}

// GetTargets returns the project's (cve_id, component_id, purl) worklist so
// the M32 CLI can run the reachability analyzer per pair and POST a verdict
// keyed on component_id back to /reachability.
//
// GET /api/v1/projects/:id/reachability/targets   (optional ?ecosystem=go)
//
// Read-only: no domain audit row is emitted (the request-level access-log
// middleware is the only trace, matching the GET /vex-drafts read route). The
// tenant-scoped 404 reuses the same F37 soft-reference guard the upload path
// uses. Rows are RLS-scoped to the caller's tenant by the repo's join through
// `components` under the ambient TenantTx.
func (h *ReachabilityHandler) GetTargets(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	tenantID := middleware.GetTenantID(c)
	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "tenant context required"})
	}

	ctx := c.Request().Context()

	// Tenant-scoped 404: the project must exist in this tenant before we
	// enumerate its targets (reuses the upload path's soft-reference guard).
	if status, body := h.requireProjectInTenant(ctx, tenantID, projectID); status != 0 {
		return c.JSON(status, body)
	}

	if h.targets == nil {
		slog.Error("reachability targets: reader not wired; refusing to serve",
			"tenant_id", tenantID, "project_id", projectID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "reachability handler misconfigured"})
	}

	// ?ecosystem=go (optional): filter server-side to the given ecosystem.
	// When absent, every ecosystem is returned.
	ecosystem := strings.TrimSpace(c.QueryParam("ecosystem"))

	rows, err := h.targets.ListReachabilityTargets(ctx, tenantID, projectID, ecosystem)
	if err != nil {
		slog.Error("reachability targets: query failed",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list reachability targets"})
	}

	items := make([]reachabilityTargetItem, 0, len(rows))
	for _, t := range rows {
		items = append(items, reachabilityTargetItem{
			CVEID:            t.CVEID,
			ComponentID:      t.ComponentID.String(),
			Purl:             t.Purl,
			ComponentName:    t.ComponentName,
			ComponentVersion: t.ComponentVersion,
			Ecosystem:        repository.EcosystemFromPurl(t.Purl),
		})
	}

	return c.JSON(http.StatusOK, reachabilityTargetsResponse{Targets: items})
}

// requireProjectInTenant ensures projectID belongs to tenantID before any
// reachability_results write runs (F37 soft-reference guard). Returns
// (0, nil) to proceed, or a (status, generic body) pair to forward. The
// 404 body is intentionally generic so the response is not an oracle for
// cross-tenant project enumeration; the precise reason lands in slog.
func (h *ReachabilityHandler) requireProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) (int, map[string]string) {
	if h.projects == nil {
		// Defence-in-depth: a mis-wire without a project reader must
		// refuse rather than persist against an unverified project.
		slog.Error("reachability upload: project reader not wired; refusing to serve",
			"tenant_id", tenantID, "project_id", projectID)
		return http.StatusInternalServerError, map[string]string{"error": "reachability handler misconfigured"}
	}
	if _, err := h.projects.GetByTenant(ctx, tenantID, projectID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			slog.Warn("reachability upload: project not in tenant",
				"tenant_id", tenantID, "project_id", projectID)
			return http.StatusNotFound, map[string]string{"error": "project not found"}
		}
		slog.Warn("reachability upload: project lookup failed",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return http.StatusInternalServerError, map[string]string{"error": "failed to verify project"}
	}
	return 0, nil
}
