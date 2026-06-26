package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/evidence_pack"
)

// EvidencePackHandler serves the M2-6 Evidence Pack endpoint
// (issue #34):
//
//	POST /api/v1/projects/:id/evidence-pack/build
//
// MVP scope: sync Markdown export only. A POST returns the rendered
// .md body directly with Content-Type: text/markdown and a download-
// friendly Content-Disposition. PDF / Zip / background-job + separate
// download endpoint are deferred to M3 (issue #34 Acceptance
// Criteria).
//
// Middleware chain at the route level (cmd/server/main.go):
//
//	MultiAuth → RequireWrite → RateLimitByAPIKey → TenantTx → audit → handler
//
// Why RequireWrite for a Markdown export: the bundle aggregates
// approved AI artefacts a compliance auditor will receive. Generating
// one is a tenant-administrative action, not a read — read-scoped
// (Viewer) API keys must not be able to mint compliance packets for a
// project they only have read access to. The handler-side CanWrite()
// guard is retained as defence-in-depth alongside the route-level
// RequireWrite.
type EvidencePackHandler struct {
	builder   *evidence_pack.Builder
	auditRepo *repository.AuditRepository
}

// NewEvidencePackHandler wires the handler. nil auditRepo is allowed
// (tests can pass nil to skip audit assertions) but production wiring
// in cmd/server/main.go MUST supply one — see #F14 / #F15 (audit
// rows are required by PRODUCT_REBOOT_PLAN.md §8.5 for any AI
// artefact lifecycle event).
func NewEvidencePackHandler(builder *evidence_pack.Builder, auditRepo *repository.AuditRepository) *EvidencePackHandler {
	if builder == nil {
		panic("handler.NewEvidencePackHandler: builder is required")
	}
	return &EvidencePackHandler{builder: builder, auditRepo: auditRepo}
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// buildEvidencePackRequest is the JSON body for POST .../evidence-pack/build.
// All three Include* fields use pointer types so the handler can
// distinguish "not provided in body" from "explicitly false". Omitted
// defaults to true so a plain `POST {}` returns a complete bundle.
//
// `format` defaults to "markdown" and the handler rejects anything
// else with 400 so PDF / Zip can be added without changing the wire
// shape.
//
// M3-6 (#42): the legacy `include_meti_placeholder` wire key is
// retained as an alias for the renamed `include_meti_assessment`
// field so clients minted against the M2-6 handler keep working.
// The handler resolves them with assessment > placeholder if both
// are present.
type buildEvidencePackRequest struct {
	IncludeVEXApproved     *bool  `json:"include_vex_approved,omitempty"`
	IncludeCRAApproved     *bool  `json:"include_cra_approved,omitempty"`
	IncludeMETIAssessment  *bool  `json:"include_meti_assessment,omitempty"`
	IncludeMETIPlaceholder *bool  `json:"include_meti_placeholder,omitempty"`
	Format                 string `json:"format,omitempty"`
}

// ----------------------------------------------------------------------------
// POST /api/v1/projects/:id/evidence-pack/build
// ----------------------------------------------------------------------------

// Build renders one Evidence Pack synchronously and streams the
// Markdown body to the client.
//
// Error contract (M1 #F10 generic-body discipline):
//   - missing / invalid tenant context        → 401
//   - missing CanWrite                        → 403 ("write permission required")
//   - invalid project id                      → 400 ("invalid project id")
//   - invalid body / unsupported format       → 400 ("invalid request" / "unsupported format")
//   - project not found (cross-tenant or gone) → 404 ("project not found")
//     The body is identical for "does not exist in this tenant" and
//     "tenant_id mismatch", matching the loadDraftScoped pattern in
//     vex_drafts.go so a probe caller cannot enumerate other tenants'
//     projects through this endpoint.
//   - builder / storage failure               → 500 ("failed to build evidence pack")
func (h *EvidencePackHandler) Build(c echo.Context) error {
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

	// Body is optional — a POST with empty body produces a default
	// bundle (all three sections included). Bind never errors on an
	// empty body for Echo; we still tolerate parse failures with 400
	// so a bad client receives a clear signal.
	var req buildEvidencePackRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	includeVEX := true
	if req.IncludeVEXApproved != nil {
		includeVEX = *req.IncludeVEXApproved
	}
	includeCRA := true
	if req.IncludeCRAApproved != nil {
		includeCRA = *req.IncludeCRAApproved
	}
	includeMETI := true
	// M3-6 (#42): prefer the new field name; fall back to the legacy
	// `include_meti_placeholder` so clients minted against M2-6 still
	// resolve correctly.
	if req.IncludeMETIAssessment != nil {
		includeMETI = *req.IncludeMETIAssessment
	} else if req.IncludeMETIPlaceholder != nil {
		includeMETI = *req.IncludeMETIPlaceholder
	}
	format := req.Format
	if format == "" {
		format = evidence_pack.FormatMarkdown
	}
	// Reject non-markdown formats at the handler boundary — the
	// builder's own check is redundant but kept for defence-in-depth.
	if format != evidence_pack.FormatMarkdown {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unsupported format (M2-6 supports markdown only; PDF/Zip ship in M3)",
		})
	}

	res, err := h.builder.Build(c.Request().Context(), evidence_pack.BuildInput{
		TenantID:              tc.TenantID(),
		ProjectID:             projectID,
		IncludeVEXApproved:    includeVEX,
		IncludeCRAApproved:    includeCRA,
		IncludeMETIAssessment: includeMETI,
		Format:                format,
	})
	if status, body, ok := mapEvidencePackError(err, tc.TenantID(), projectID); ok {
		return c.JSON(status, body)
	}

	// Emit audit log BEFORE writing the response body so a failure in
	// the audit write rolls back the TenantTx alongside any other
	// state — M1 #F5 fail-closed posture. Since the Build call is
	// read-only at the DB layer (no row was mutated), a rolled-back
	// tx means the bundle was never "officially" produced; the
	// client receives a 500 and can retry.
	if h.auditRepo != nil {
		uid := userIDOrNilTC(tc)
		details := map[string]interface{}{
			"project_id":               projectID.String(),
			"format":                   res.Format,
			"filename":                 res.Filename,
			"vex_approved_count":       res.VEXApprovedCount,
			"cra_approved_count":       res.CRAApprovedCount,
			"meti_assessment_included": res.METIIncluded,
			"meti_row_count":           res.METIRowCount,
			"meti_achieved_count":      res.METIAchievedCount,
			"include_vex_approved":     includeVEX,
			"include_cra_approved":     includeCRA,
			"include_meti_assessment":  includeMETI,
			"built_at":                 res.BuiltAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		tenantID := tc.TenantID()
		auditInput := &model.CreateAuditLogInput{
			TenantID:     &tenantID,
			UserID:       uid,
			Action:       AuditActionEvidencePackBuilt,
			ResourceType: ResourceTypeEvidencePack,
			ResourceID:   &projectID,
			Details:      details,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}
		if auditErr := h.auditRepo.Log(c.Request().Context(), auditInput); auditErr != nil {
			// F5 fail-closed: surface 500 so the surrounding TenantTx
			// rolls back. Loud slog so operators can alarm on the
			// failure pattern.
			slog.Warn("evidence_pack: audit log failed",
				"tenant_id", tc.TenantID(),
				"project_id", projectID,
				"error", auditErr,
			)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to record audit log for evidence pack",
			})
		}
	}

	// Stream the Markdown body. Content-Disposition: attachment hints
	// the browser to trigger a download rather than render in-place;
	// the filename matches buildFilename in the builder so the audit
	// row and the downloaded file agree.
	c.Response().Header().Set(echo.HeaderContentType, "text/markdown; charset=utf-8")
	c.Response().Header().Set(echo.HeaderContentDisposition,
		fmt.Sprintf("attachment; filename=%q", res.Filename))
	c.Response().Header().Set("X-Evidence-Pack-VEX-Count",
		fmt.Sprintf("%d", res.VEXApprovedCount))
	c.Response().Header().Set("X-Evidence-Pack-CRA-Count",
		fmt.Sprintf("%d", res.CRAApprovedCount))
	return c.Blob(http.StatusOK, "text/markdown; charset=utf-8", res.ContentBytes)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// mapEvidencePackError translates builder errors into HTTP status +
// JSON body. Returns (status, body, true) when err is non-nil;
// (0, nil, false) otherwise.
//
// Status mapping:
//   - sql.ErrNoRows (project not found / wrong tenant) → 404, generic body
//   - "is required" / "unsupported format"             → 400
//   - anything else                                    → 500
func mapEvidencePackError(err error, tenantID, projectID uuid.UUID) (int, map[string]string, bool) {
	if err == nil {
		return 0, nil, false
	}
	if errors.Is(err, sql.ErrNoRows) {
		// Generic body matches the loadDraftScoped pattern in
		// vex_drafts.go (#F10) — a probe caller cannot distinguish
		// "this project does not exist anywhere" from "this project
		// exists but belongs to another tenant".
		slog.Warn("evidence_pack: project not found (or wrong tenant)",
			"tenant_id", tenantID,
			"project_id", projectID,
		)
		return http.StatusNotFound, map[string]string{"error": "project not found"}, true
	}
	msg := err.Error()
	if containsSubstring(msg, "is required") {
		return http.StatusBadRequest, map[string]string{"error": msg}, true
	}
	if containsSubstring(msg, "unsupported format") {
		return http.StatusBadRequest, map[string]string{"error": "unsupported format (M2-6 supports markdown only; PDF/Zip ship in M3)"}, true
	}
	slog.Warn("evidence_pack: build failed",
		"tenant_id", tenantID,
		"project_id", projectID,
		"error", err,
	)
	return http.StatusInternalServerError, map[string]string{"error": "failed to build evidence pack"}, true
}

// userIDOrNilTC mirrors userIDOrNil in vex_drafts.go. Kept as a
// separate helper so this file has zero cross-handler coupling.
func userIDOrNilTC(tc *middleware.TenantContext) *uuid.UUID {
	uid := tc.UserID()
	if uid == uuid.Nil {
		return nil
	}
	v := uid
	return &v
}

// ----------------------------------------------------------------------------
// Audit constants
// ----------------------------------------------------------------------------

const (
	// AuditActionEvidencePackBuilt is the audit_logs.action emitted by
	// every successful POST /evidence-pack/build. Aligned with the
	// convention from triage.AuditActionVexDraft*: <resource>_<verb>.
	AuditActionEvidencePackBuilt = "evidence_pack_built"

	// ResourceTypeEvidencePack is the audit_logs.resource_type for the
	// evidence pack bundle event. The ResourceID column carries the
	// project_id (not a bundle id — bundles are not persisted in M2-6;
	// see M3 for the bundle table proposed by issue #34).
	ResourceTypeEvidencePack = "evidence_pack"
)
