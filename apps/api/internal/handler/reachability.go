package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/validation"
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

// reachabilityVulnFuncsReader is the advisory-excerpt read surface GET
// /reachability/targets uses to enrich each target row with the
// advisory-declared vulnerable symbols (M43 Wave 1 / F465, issue #167).
// *repository.AdvisoryExcerptsRepository satisfies it via
// ListVulnFuncsByCVEs (a single batch read for the whole worklist — one
// CVE may have nvd/ghsa/jvn rows, whose symbol lists are unioned).
// Declared as an interface so reachability_targets_test.go can substitute
// a fake without a live PostgreSQL (same rationale as the other narrow
// interfaces above).
type reachabilityVulnFuncsReader interface {
	ListVulnFuncsByCVEs(ctx context.Context, tenantID uuid.UUID, cveIDs []string) (map[string]repository.CVEVulnFuncs, error)
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
	// vulnFuncs is the advisory-excerpt read surface GET /reachability/targets
	// uses to attach the normalised vuln_funcs symbol list to each target row
	// (production: *repository.AdvisoryExcerptsRepository). It runs under the
	// ambient TenantTx so the read is RLS-scoped to the caller's tenant.
	vulnFuncs reachabilityVulnFuncsReader
}

// NewReachabilityHandler wires the handler. All five dependencies are
// required: the upserter to persist verdicts, the audit logger for the
// mandatory reachability_uploaded row (audit-or-nothing), the project reader
// for the tenant-scoped 404 on the soft-reference project_id, the targets
// reader for the CLI worklist read endpoint (GET /reachability/targets), and
// the vulnFuncs reader for that endpoint's per-target vuln_funcs enrichment
// (M43 Wave 1 / F465).
func NewReachabilityHandler(upserter reachabilityUpserter, audit ReachabilityAuditLogger, projects ReachabilityProjectReader, targets reachabilityTargetsReader, vulnFuncs reachabilityVulnFuncsReader) *ReachabilityHandler {
	return &ReachabilityHandler{upserter: upserter, audit: audit, projects: projects, targets: targets, vulnFuncs: vulnFuncs}
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
		// Validate + normalize the cve_id at the input boundary (M42 Wave 1).
		// All-or-nothing like the other shape checks: one malformed cve_id
		// rejects the whole batch with nothing persisted. The normalized
		// (upper-cased) form is what gets stored and what the grounding-target
		// gate below matches against the canonical target graph.
		cveID, err = validation.ValidateCVEID(cveID)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: invalid CVE ID format", i),
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

	// Grounding-integrity gate (Codex F417, HIGH). reachability_results has
	// no FK to components / component_vulnerabilities (soft reference), and the
	// triage runner consumes these rows as AI-VEX grounding evidence by
	// (tenant, project, cve, component) WITHOUT re-joining the target graph
	// (ReachabilityResultsRepository.ListByProject filters on tenant_id +
	// project_id [+ cve_id] [+ component_id] only). So a write-scoped caller
	// could otherwise persist FORGED verdicts for arbitrary (component, cve)
	// pairs that are not genuine vulnerability targets, and have them counted
	// as grounding (even "verified"). Validate every uploaded tuple against the
	// real, RLS-safe target graph — the same set GET /reachability/targets
	// exposes — BEFORE any write. All-or-nothing, like the shape checks above:
	// one non-target tuple rejects the whole batch with nothing persisted and
	// no audit row emitted.
	if h.targets == nil {
		// Defence-in-depth: a mis-wire without a targets reader must refuse
		// rather than accept unverified verdicts (mirrors the nil-projects guard).
		slog.Error("reachability upload: targets reader not wired; refusing to serve",
			"tenant_id", tenantID, "project_id", projectID)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "reachability handler misconfigured"})
	}
	validTargets, err := h.targets.ListReachabilityTargets(ctx, tenantID, projectID, "")
	if err != nil {
		slog.Error("reachability upload: target graph lookup failed; refusing batch",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "failed to verify reachability targets",
		})
	}
	// Key on the canonical uuid.UUID (comparable — equal regardless of the
	// caller's input formatting/case) paired with the exact cve_id.
	type targetKey struct {
		component uuid.UUID
		cve       string
	}
	targetSet := make(map[targetKey]struct{}, len(validTargets))
	for _, t := range validTargets {
		targetSet[targetKey{component: t.ComponentID, cve: t.CVEID}] = struct{}{}
	}
	for i, rr := range rows {
		if _, ok := targetSet[targetKey{component: rr.ComponentID, cve: rr.CVEID}]; !ok {
			slog.Warn("reachability upload: result references a non-target (component, cve); rejecting batch",
				"tenant_id", tenantID, "project_id", projectID, "index", i,
				"component_id", rr.ComponentID, "cve_id", rr.CVEID)
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("results[%d]: references a (component, cve) that is not a vulnerability target for this project", i),
			})
		}
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
// vuln_funcs is the normalised advisory-declared vulnerable symbol list for
// THIS row (M43 Wave 1 / F465, issue #167): OSV/Go-vulndb symbols scoped to
// the component's purl-derived Go module lead, followed by the unscoped
// (prose-source / legacy) union shared by every row of the CVE (M43 Phase D
// round 8 / R8f — pre-R8f the whole CVE union shipped to every row, leaking
// sibling modules' symbols). The wire shape is unchanged: a flat string
// array, OMITTED (not an empty array) when no well-formed symbol is known
// for this row — the CLI treats both the same way, and omitempty keeps the
// common no-symbols worklist small.
type reachabilityTargetItem struct {
	CVEID            string   `json:"cve_id"`
	ComponentID      string   `json:"component_id"`
	Purl             string   `json:"purl"`
	ComponentName    string   `json:"component_name"`
	ComponentVersion string   `json:"component_version"`
	Ecosystem        string   `json:"ecosystem"`
	VulnFuncs        []string `json:"vuln_funcs,omitempty"`
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
	if h.vulnFuncs == nil {
		// Defence-in-depth, mirroring the nil-targets guard: a mis-wire must
		// refuse loudly rather than silently serve a worklist stripped of the
		// vuln_funcs enrichment (which would silently degrade every CLI run
		// to import-only analysis).
		slog.Error("reachability targets: vuln_funcs reader not wired; refusing to serve",
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

	// vuln_funcs enrichment (M43 Wave 1 / F465): one batch read over the
	// distinct CVE ids in the worklist, then normalise at this edge (the
	// single source of truth for symbol normalisation — see
	// normalizeVulnFuncs). Since M43 Phase D round 8 (R8f) the attachment
	// is per ROW, not per CVE: OSV-derived symbols are scoped to the
	// component's purl-derived Go module (see funcsForRow below).
	cveIDs := make([]string, 0, len(rows))
	seenCVE := make(map[string]struct{}, len(rows))
	for _, t := range rows {
		if _, ok := seenCVE[t.CVEID]; ok {
			continue
		}
		seenCVE[t.CVEID] = struct{}{}
		cveIDs = append(cveIDs, t.CVEID)
	}
	rawFuncsByCVE, err := h.vulnFuncs.ListVulnFuncsByCVEs(ctx, tenantID, cveIDs)
	if err != nil {
		slog.Error("reachability targets: vuln_funcs lookup failed",
			"tenant_id", tenantID, "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list reachability targets"})
	}

	// Per-row symbol projection (M43 Phase D round 8 / R8f): a target row
	// receives (a) the scoped entries whose module matches the row's
	// purl-derived module, then (b) the unscoped union (prose sources /
	// pre-057 legacy rows) — normalised as one list so the delivery cap
	// still trims the tail (structured, module-matched symbols lead). The
	// pre-R8f behaviour attached the CVE-LEVEL union to every row, so one
	// CVE spanning several Go modules leaked component B's symbols into
	// component A's row and a project call into B's package flipped A to a
	// false `reachable` (over-report). Rows whose module cannot be derived
	// (no purl / underivable purl) get only the unscoped union; a row with
	// scoped entries but no module match and no unscoped symbols omits the
	// field entirely (import-only is the correct CLI fallback for it).
	//
	// Both the module derivation and the normalisation dispatch on the
	// row's purl-derived ecosystem (M44 Wave 3 / F471): a pkg:golang row
	// matches scoped entries by Go module path and normalises under the Go
	// selector rules; a pkg:npm row matches by npm package name (W2 stores
	// npm scoped entries under the package name, "@scope/name" included)
	// and normalises under the JS selector rules — which accept the
	// npm-native bare export shape ("defaultsDeep") the Go rules drop.
	// Every other ecosystem conservatively keeps the Go behaviour (no
	// scoped match, Go normalisation), exactly as pre-F471. The unscoped
	// union is normalised by the ROW's normaliser too, so a cross-ecosystem
	// token in a shared prose union drops naturally on the rows it cannot
	// apply to (a bare npm export never reaches a Go row's wire).
	// Results are memoised per (cve, ecosystem, module) so the
	// normalisation (and its cap Warn) runs once per distinct triple, not
	// once per row.
	type cveModuleKey struct{ cve, ecosystem, module string }
	funcsCache := make(map[cveModuleKey][]string)
	funcsForRow := func(cveID, purl, ecosystem string) []string {
		raw, ok := rawFuncsByCVE[cveID]
		if !ok {
			return nil
		}
		var module string
		switch ecosystem {
		case "npm":
			module, _ = npmPackageFromPurl(purl) // "" when not derivable → unscoped only
		default:
			module, _ = goModuleFromPurl(purl) // "" when not derivable → unscoped only
		}
		key := cveModuleKey{cve: cveID, ecosystem: ecosystem, module: module}
		if cached, ok := funcsCache[key]; ok {
			return cached
		}
		var union []string
		if module != "" {
			for _, sc := range raw.Scoped {
				// npm rows match case-insensitively: the registry enforces
				// lowercase for new packages but legacy mixed-case names
				// (jQuery, JSONStream, …) still exist and the CLI analyzer's
				// matchNpmPackages already folds case — a case-sensitive edge
				// here would silently withhold scoped symbols the analyzer
				// could have matched (M44 Phase D R2c). Go module paths keep
				// the exact match (M43 R8f behaviour, case-significant).
				if sc.Module == module || (ecosystem == "npm" && strings.EqualFold(sc.Module, module)) {
					union = append(union, sc.Funcs...)
				}
			}
		}
		union = append(union, raw.Unscoped...)
		out := normalizeVulnFuncsForEcosystem(tenantID, cveID, ecosystem, union)
		funcsCache[key] = out
		return out
	}

	items := make([]reachabilityTargetItem, 0, len(rows))
	for _, t := range rows {
		ecosystem := repository.EcosystemFromPurl(t.Purl)
		items = append(items, reachabilityTargetItem{
			CVEID:            t.CVEID,
			ComponentID:      t.ComponentID.String(),
			Purl:             t.Purl,
			ComponentName:    t.ComponentName,
			ComponentVersion: t.ComponentVersion,
			Ecosystem:        ecosystem,
			VulnFuncs:        funcsForRow(t.CVEID, t.Purl, ecosystem), // nil (field omitted) when no symbol survived
		})
	}

	return c.JSON(http.StatusOK, reachabilityTargetsResponse{Targets: items})
}

// normalizeVulnFuncsForEcosystem dispatches the advisory-declared symbol
// normalisation on the target row's purl-derived ecosystem (M44 Wave 3 /
// F471): "npm" rows take the JS selector rules (normalizeVulnFuncsNpm),
// everything else — "go", "" (no purl) and any other ecosystem — keeps the
// original Go rules (normalizeVulnFuncs), which is exactly the pre-F471
// behaviour for those rows. New ecosystems must add an explicit arm here;
// defaulting to the conservative Go shape check keeps an unknown ecosystem
// from shipping selectors no analyzer requested.
func normalizeVulnFuncsForEcosystem(tenantID uuid.UUID, cveID, ecosystem string, raw []string) []string {
	if ecosystem == "npm" {
		return normalizeVulnFuncsNpm(tenantID, cveID, raw)
	}
	return normalizeVulnFuncs(tenantID, cveID, raw)
}

// normalizeVulnFuncs canonicalises the advisory-declared symbol list for the
// GET /reachability/targets wire (M43 Wave 1 / F465, issue #167) — the GO
// ecosystem rules (npm rows dispatch to normalizeVulnFuncsNpm instead, see
// normalizeVulnFuncsForEcosystem). This edge is the single source of truth
// for the normalisation: the CLI's parseSymbolSelectors treats ONE malformed
// selector ("Foo", "Foo()", 4+ dot-parts) as fatal for the whole symbol walk
// — degrading the entire run to import-only — so anything not shaped like
// "Pkg.Func" / "Pkg.Type.Method" must be dropped before it ships.
//
// Pipeline per element (frozen spec):
//
//	TrimSpace → strip one trailing "()" → dot-split; keep only 2 or 3
//	non-empty parts (1 = bare name, 4+ = over-qualified: drop) → drop
//	elements whose parts are not Go-identifier-shaped (spaces, "/", "$",
//	"<>", ":", "-", ... — conservative) → de-duplicate preserving
//	first-seen order.
//
// After normalisation the list is capped at maxVulnFuncsPerCVE (M43
// Phase D review): the scheduler caps at store time too, but the DB can
// already hold larger unions (pre-cap inventory, other write paths), and
// an unbounded list bloats every worklist response and every CLI symbol
// walk. Defence-in-depth at the serving edge.
//
// Returns nil (not an empty slice) when nothing survives, so the caller's
// omitempty field drops off the wire entirely.
//
// tenantID / cveID are logging context only (M43 Phase D R2 finding 5):
// the cap Warn is the only operator-visible trace that advisory symbols
// were dropped at the serving edge, and without the (tenant, cve) pair the
// line is unactionable in aggregate logs. They play no part in the
// normalisation itself.
func normalizeVulnFuncs(tenantID uuid.UUID, cveID string, raw []string) []string {
	return normalizeVulnFuncsShaped(tenantID, cveID, raw, isGoVulnFuncSelector)
}

// normalizeVulnFuncsNpm is the npm-ecosystem arm of the vuln_funcs
// normalisation (M44 Wave 3 / F471). npm advisories overwhelmingly name
// bare export identifiers ("defaultsDeep") — a shape the Go rules drop 100%
// of the time — so the accepted forms are:
//
//   - a bare JS identifier: "defaultsDeep", "_", "$" ("$" and "_" are valid
//     JS identifier characters);
//   - a dotted receiver selector with 1..3 JS-identifier-shaped parts:
//     "_.merge", "child_process.exec", "a.b.c" (4+ parts: drop).
//
// Shared with the Go arm: TrimSpace, one trailing "()" strip, stable
// first-seen dedupe and the maxVulnFuncsPerCVE cap. Dropped: path/URL
// shapes ("/" or ":" never survive the identifier check), bare version
// strings ("1.2.3" — digit-led parts), whitespace-embedded strings, and
// anything longer than maxNpmVulnFuncBytes (JS minifier blobs / prose
// fragments the extraction heuristics let through).
//
// NOTE: the shape check is deliberately FORM-ONLY. A form-valid but
// semantically generic token like "headers.location" (a property access,
// not a vulnerable function) is the W2 extraction stage's responsibility to
// drop at store time — this edge cannot tell it apart from a genuine
// "recv.method" selector and must not try. Symmetrically, a Go-shaped
// "Pkg.Type.Method" arriving in an npm row's union passes here (3
// identifier parts is a valid JS selector shape): harmless, because the
// CLI's binding-aware matching only fires on symbols the npm package
// actually binds.
func normalizeVulnFuncsNpm(tenantID uuid.UUID, cveID string, raw []string) []string {
	return normalizeVulnFuncsShaped(tenantID, cveID, raw, isNpmVulnFuncSelector)
}

// normalizeVulnFuncsShaped is the shared vuln_funcs pipeline: TrimSpace →
// strip one trailing "()" → drop empties → keep only elements the
// ecosystem's wellFormed shape check accepts → de-duplicate preserving
// first-seen order → cap at maxVulnFuncsPerCVE (with the operator Warn).
// The ecosystem arms differ ONLY in the wellFormed predicate.
func normalizeVulnFuncsShaped(tenantID uuid.UUID, cveID string, raw []string, wellFormed func(string) bool) []string {
	var out []string
	seen := make(map[string]struct{}, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, "()")
		if s == "" {
			continue
		}
		if !wellFormed(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) > maxVulnFuncsPerCVE {
		slog.Warn("reachability targets: vuln_funcs capped",
			"tenant_id", tenantID, "cve_id", cveID,
			"normalized", len(out), "cap", maxVulnFuncsPerCVE)
		out = out[:maxVulnFuncsPerCVE]
	}
	return out
}

// isGoVulnFuncSelector is the Go arm's shape check: 2 or 3 dot-separated
// parts, each Go-identifier-shaped (the frozen M43 spec — see
// normalizeVulnFuncs).
func isGoVulnFuncSelector(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !isGoIdentifier(p) {
			return false
		}
	}
	return true
}

// isNpmVulnFuncSelector is the npm arm's shape check: 1..3 dot-separated
// parts, each JS-identifier-shaped, total length ≤ maxNpmVulnFuncBytes
// (see normalizeVulnFuncsNpm for the rationale and the form-only caveat).
func isNpmVulnFuncSelector(s string) bool {
	if len(s) > maxNpmVulnFuncBytes {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return false
	}
	for _, p := range parts {
		if !isJSIdentifier(p) {
			return false
		}
	}
	return true
}

// maxNpmVulnFuncBytes bounds one npm vuln_funcs selector (M44 Wave 3 /
// F471). Real npm export names and recv.method selectors run well under
// 100 bytes; anything longer is minifier output or a prose fragment the
// extraction heuristics let through, and would only bloat the worklist.
const maxNpmVulnFuncBytes = 256

// maxVulnFuncsPerCVE bounds the advisory-declared symbol list shipped per
// CVE on GET /reachability/targets (M43 Phase D review). 200 comfortably
// covers real advisory unions (Go vulndb symbol lists run in the tens)
// while keeping a pathological union from inflating the worklist response
// and the CLI's AST walk. Keep in sync with the scheduler's store-time cap
// (internal/scheduler/cve_sync.go).
const maxVulnFuncsPerCVE = 200

// goModuleFromPurl extracts the Go module path from a Package URL of the
// form pkg:golang/<namespace>/<name>@<version>?<qualifiers>#<subpath>,
// e.g.
//
//	pkg:golang/github.com/jackc/pgx/v5@v5.5.0 -> github.com/jackc/pgx/v5
//	pkg:golang/example.test/vulnpkg@v1.0.0    -> example.test/vulnpkg
//	pkg:golang/stdlib@go1.22.4                -> stdlib
//
// Returns ("", false) for empty input or a non-golang purl — the caller
// then serves only the unscoped symbol union for that target row (no
// module attribution is possible, and non-Go ecosystems have no scoped
// entries to match anyway).
//
// MUST stay derivation-compatible with the CLI's goModuleFromPurl
// (sbomhub-cli/internal/api/reachability.go): the CLI matches the same
// purl against the local go.mod to pick the module it analyses, so a
// divergence here would scope symbols to a module the CLI resolves
// differently — silently emptying the per-target symbol walk. Both sides:
// strip the exact-case "pkg:" scheme if present, match the purl type
// segment "golang" case-insensitively (scheme-less "golang/" producers
// stay tolerated), cut at the first of '@' (version), '?' (qualifiers),
// '#' (subpath), then percent-decode the remaining path.
func goModuleFromPurl(purl string) (string, bool) {
	s := strings.TrimSpace(purl)
	if s == "" {
		return "", false
	}
	// The purl type is case-insensitive per the purl spec, and
	// repository.EcosystemFromPurl lowercases it before matching — so a
	// pkg:GOLANG/... component row IS served on the ecosystem="go" path
	// and must derive a module here too, or its scoped symbols silently
	// degrade to import_only (M43 Phase D R9 finding 1). The "pkg:"
	// scheme stays exact-case (same premise as EcosystemFromPurl), and
	// the module path itself keeps its case — Go module paths are
	// case-sensitive.
	rest := strings.TrimPrefix(s, "pkg:")
	i := strings.IndexByte(rest, '/')
	if i < 0 || !strings.EqualFold(rest[:i], "golang") {
		return "", false
	}
	s = rest[i+1:]
	// Strip version (@), qualifiers (?) and subpath (#) — the module path
	// is everything before the first of these.
	if i := strings.IndexAny(s, "@?#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", false
	}
	// purl path segments are percent-encoded; decode conservatively.
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	return s, true
}

// npmPackageFromPurl extracts the npm package name from a Package URL of
// the form pkg:npm/<name>@<version> (M44 Wave 3 / F471), e.g.
//
//	pkg:npm/lodash@4.17.21              -> lodash
//	pkg:npm/%40scope%2Fname@1.0.0       -> @scope/name
//	pkg:npm/%40scope/name@1.0.0         -> @scope/name  (Syft encodes only the "@")
//	pkg:npm/@scope/name@1.0.0           -> @scope/name  (literal-@ producer tolerance)
//
// It is the npm counterpart of goModuleFromPurl: the serving edge matches
// the result against the Module slot of the CVE's scoped vuln_funcs entries
// (W2 stores npm scoped entries under the package name, "@scope/name"
// included — no migration needed). Returns ("", false) for empty input or a
// non-npm purl; the caller then serves only the unscoped symbol union for
// that target row.
//
// Same parsing premises as goModuleFromPurl: the "pkg:" scheme stays
// exact-case (parity with repository.EcosystemFromPurl, so a "PKG:" row
// never reaches the scoped-serving path anyway), the purl type segment
// "npm" matches case-insensitively (purl spec; a pkg:NPM row IS served with
// ecosystem "npm"), and the decoded package name keeps its case (npm names
// are compared verbatim against the stored Module).
func npmPackageFromPurl(purl string) (string, bool) {
	s := strings.TrimSpace(purl)
	if s == "" {
		return "", false
	}
	rest := strings.TrimPrefix(s, "pkg:")
	i := strings.IndexByte(rest, '/')
	if i < 0 || !strings.EqualFold(rest[:i], "npm") {
		return "", false
	}
	s = rest[i+1:]
	// Strip qualifiers (?) and subpath (#) first, then the version. The
	// version delimiter is the first '@' — except that a literal leading
	// scope marker ("@scope/name@1.0.0", non-spec but common) must not be
	// mistaken for it, so the search starts after position 0.
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	verFrom := 0
	if strings.HasPrefix(s, "@") {
		verFrom = 1
	}
	if i := strings.IndexByte(s[verFrom:], '@'); i >= 0 {
		s = s[:verFrom+i]
	}
	if s == "" {
		return "", false
	}
	// purl path segments are percent-encoded; decode conservatively (this
	// is what turns %40scope%2Fname into @scope/name).
	if decoded, err := url.PathUnescape(s); err == nil {
		s = decoded
	}
	// A scoped name must carry both the scope and the package part —
	// "@scope/name". A lone "@..." without "/" is a malformed purl
	// ("pkg:npm/@1.0.0"): no scoped entry can be stored under it.
	if strings.HasPrefix(s, "@") && !strings.Contains(s, "/") {
		return "", false
	}
	return s, true
}

// isGoIdentifier reports whether s is shaped like a Go identifier (first
// rune a letter or underscore, rest letters/digits/underscores; Unicode
// letters allowed per the Go spec). Used by normalizeVulnFuncs to drop
// selector parts the advisory heuristics let through that the CLI's AST
// walk could never match (paths with "/", Java-style "Foo$Bar", generics
// noise, embedded spaces, ...).
func isGoIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || unicode.IsLetter(r):
		case i > 0 && unicode.IsDigit(r):
		default:
			return false
		}
	}
	return true
}

// isJSIdentifier reports whether s is shaped like a JavaScript identifier
// (first rune a letter, "_" or "$"; rest may add digits — the conservative
// core of the ECMAScript IdentifierName grammar, Unicode letters allowed).
// Used by the npm arm of the vuln_funcs normalisation: it is a strict
// superset of isGoIdentifier ("$" is the only addition), so every Go-shaped
// selector part also passes here — see the cross-ecosystem note on
// normalizeVulnFuncsNpm.
func isJSIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || r == '$' || unicode.IsLetter(r):
		case i > 0 && unicode.IsDigit(r):
		default:
			return false
		}
	}
	return true
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
