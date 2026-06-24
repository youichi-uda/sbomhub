package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/database"
	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// componentScanner is the narrow interface SbomHandler depends on for the
// post-upload NVD/JVN sweeps. Defining it inside the handler package keeps
// the scanner implementations (service.NVDService, service.JVNService)
// pluggable in tests without exporting an interface across packages.
//
// The interface is intentionally minimal — only the per-SBOM entry point
// the background goroutine calls — so any future scanner that exposes the
// same surface (e.g. a future OSV scanner) drops in without changing the
// handler. *service.NVDService and *service.JVNService both satisfy it
// via their existing `ScanComponents(ctx, sbomID) error` methods.
type componentScanner interface {
	ScanComponents(ctx context.Context, sbomID uuid.UUID) error
}

type SbomHandler struct {
	sbomService *service.SbomService
	nvdService  componentScanner
	jvnService  componentScanner
	scanTracker *service.ScanTracker
	// db is used by startBackgroundScan to open a fresh transaction so the
	// goroutine can bind its own `app.current_tenant_id` GUC. The parent
	// request's tx (TenantTx middleware) commits as soon as Upload returns,
	// so the goroutine must NOT reuse it — it would be closed by then.
	// See startBackgroundScan godoc.
	db *sql.DB
}

// NewSbomHandler wires the handler with the services it needs.
//
// `tracker` is the in-memory ScanTracker (see service/scan_tracker.go)
// observed by `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status`. The
// CLI polls that endpoint after upload so `sbomhub scan --fail-on
// <severity>` can actually fail a CI job on threshold violations — Trust
// Rescue P1 #12.
//
// `db` is required so the post-upload background scan can run inside its
// own transaction with `SET LOCAL app.current_tenant_id` bound — Codex R1
// found that the previous `context.Background()` path stripped the tenant
// GUC, which caused RLS on `components` to filter every row and made
// `--fail-on critical` silently report 0 vulnerabilities.
func NewSbomHandler(db *sql.DB, ss *service.SbomService, nvd *service.NVDService, jvn *service.JVNService, tracker *service.ScanTracker) *SbomHandler {
	return &SbomHandler{
		sbomService: ss,
		nvdService:  nvd,
		jvnService:  jvn,
		scanTracker: tracker,
		db:          db,
	}
}

func (h *SbomHandler) Upload(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "failed to read request body"})
	}

	sbom, err := h.sbomService.Import(c.Request().Context(), projectID, body)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// The background scan goroutine outlives this request and cannot rely
	// on the request's TenantTx (which commits as soon as Upload returns).
	// Capture the tenant ID here so the goroutine can open its own tx and
	// re-bind `app.current_tenant_id` — see startBackgroundScan godoc.
	tenantID := appmw.GetTenantID(c)
	if tenantID == uuid.Nil {
		// Upload should never reach here without a tenant context (it sits
		// behind MultiAuth + TenantTx in main.go) but if it ever does, we
		// refuse to start a scan that would silently run with no GUC and
		// produce an empty result the CLI would then trust.
		slog.Error("Upload reached without tenant context — refusing to start background scan",
			"sbom_id", sbom.ID, "project_id", projectID)
		if h.scanTracker != nil {
			h.scanTracker.MarkFailed(sbom.ID, "tenant context missing")
		}
		return c.JSON(http.StatusCreated, sbom)
	}

	// Start vulnerability scan in background AFTER the request transaction
	// commits.
	//
	// MarkRunning is called synchronously here so that a CLI client polling
	// scan-status immediately after the upload sees "running" rather than
	// "unknown". The actual scan launch is deferred via RegisterPostCommit
	// so the background goroutine never opens its own tx before the parent
	// INSERTs are visible — Codex R2 P1 fix. The previous code launched the
	// goroutine inline, which raced the TenantTx commit: the goroutine
	// opened its own tx, ListBySbom saw zero components, and the scan
	// completed with 0 findings even when the SBOM had vulnerable
	// components. `sbomhub scan --fail-on critical` therefore always exited
	// 0.
	//
	// If the request rolls back (handler error, 4xx, panic, commit failure)
	// the hook will not run — which is what we want: no SBOM, no scan.
	// MarkRunning still happened, but the matching MarkCompleted/MarkFailed
	// won't, so scan-status for that (never-committed) sbom_id will report
	// "running" indefinitely. That window is bounded by the ScanTracker's
	// retention and is acceptable because the sbom_id itself was never
	// persisted — a client polling for it is asking about a row that does
	// not exist.
	if h.scanTracker != nil {
		h.scanTracker.MarkRunning(sbom.ID)
	}
	scanSbomID := sbom.ID
	appmw.RegisterPostCommit(c, func() {
		h.startBackgroundScan(scanSbomID, tenantID)
	})

	return c.JSON(http.StatusCreated, sbom)
}

// startBackgroundScan initiates vulnerability scanning in the background
// and reports completion to the in-memory ScanTracker so the CLI
// scan-status endpoint can return an authoritative state.
//
// The goroutine outlives the request that started it, so it CANNOT borrow
// the request's TenantTx (already committed/rolled back by the time the
// goroutine starts working). Instead it opens its own transaction via
// database.WithTxFunc and binds `app.current_tenant_id` to that tx with
// `set_config(..., true)` (the same pattern as the TenantTx middleware).
// Without this, the inner `ComponentRepository.ListBySbom` call — which is
// tx-aware via database.Querier and protected by FORCE ROW LEVEL SECURITY
// — would see no tenant GUC and the RLS predicate
// `tenant_id = current_setting('app.current_tenant_id', true)::UUID` would
// either reject the cast (NULL → UUID) or evaluate to false, returning 0
// components. The vulnerability scan would then "complete" with 0 findings
// and `sbomhub scan --fail-on critical` would always exit 0 — Codex R1
// production blocker.
//
// Concurrency: the NVD scan internally spawns a worker pool, but those
// workers only touch the global `vulnerabilities` and
// `component_vulnerabilities` tables (no RLS) via the raw `*sql.DB`, not
// the tx — so they do not contend on the single tx connection. Only the
// initial ListBySbom (read on `components`) and the JVN sequential pass
// flow through the tx. The tx therefore stays effectively idle for most
// of the scan but pins one pooled connection for the scan's duration;
// that is an acknowledged trade-off (see ※要確認 in completion report).
func (h *SbomHandler) startBackgroundScan(sbomID, tenantID uuid.UUID) {
	go h.runScan(context.Background(), sbomID, tenantID)
}

// runScan executes the post-upload NVD + JVN sweep synchronously and
// updates ScanTracker with the terminal state. It is the body of the
// goroutine spawned by startBackgroundScan, extracted as a method so tests
// can drive the scan flow without dealing with goroutine timing
// (handler/sbom_test.go).
//
// Error surfacing contract (Codex R15 P2):
//   - Any scanner that returns a non-nil error is recorded in `errs`.
//   - Any tx-level failure (BeginTx / set_config / Commit) is recorded
//     under the "tx:" prefix.
//   - If `errs` is non-empty at the end of the run, ScanTracker.MarkFailed
//     is called with the joined error string. ONLY when every scanner
//     returns nil AND the tx commits cleanly is MarkCompleted called.
//
// Without this contract, a transient NVD/JVN outage would land the
// CLI-observed scan status at "completed, 0 vulnerabilities" and
// `sbomhub scan --fail-on critical` would silently exit 0. See also the
// known limitation in NVDService.processComponentsParallel: per-component
// failures inside the scanner are logged but the function still returns
// nil, so this top-level err propagation is only an upper bound — it
// catches catastrophic failures (cannot reach NVD at all) but not
// partial-result conditions. A stricter threshold (e.g. "N% of components
// failed → return error") belongs inside the scanner itself and is
// tracked separately (※要確認).
func (h *SbomHandler) runScan(ctx context.Context, sbomID, tenantID uuid.UUID) {
	var errs []string

	txErr := database.WithTxFunc(ctx, h.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}

		// Scan with NVD
		if h.nvdService != nil {
			if err := h.nvdService.ScanComponents(txCtx, sbomID); err != nil {
				slog.Error("Auto NVD scan failed", "sbom_id", sbomID, "error", err)
				errs = append(errs, "nvd: "+err.Error())
			} else {
				slog.Info("Auto NVD scan completed", "sbom_id", sbomID)
			}
		}

		// Scan with JVN
		if h.jvnService != nil {
			if err := h.jvnService.ScanComponents(txCtx, sbomID); err != nil {
				slog.Error("Auto JVN scan failed", "sbom_id", sbomID, "error", err)
				errs = append(errs, "jvn: "+err.Error())
			} else {
				slog.Info("Auto JVN scan completed", "sbom_id", sbomID)
			}
		}

		// Always commit so per-component-vulnerability links inserted
		// outside this tx (NVD worker pool uses raw db) and any future
		// tx-aware writes are durable. Per-scan failures are recorded
		// in `errs` and surfaced through ScanTracker, not through tx
		// rollback.
		return nil
	})
	if txErr != nil {
		slog.Error("Background scan tx failed",
			"sbom_id", sbomID, "tenant_id", tenantID, "error", txErr)
		errs = append(errs, "tx: "+txErr.Error())
	}

	if h.scanTracker != nil {
		if len(errs) > 0 {
			h.scanTracker.MarkFailed(sbomID, strings.Join(errs, "; "))
		} else {
			h.scanTracker.MarkCompleted(sbomID)
		}
	}
}

func (h *SbomHandler) Get(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	sbom, err := h.sbomService.GetLatest(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom not found"})
	}

	return c.JSON(http.StatusOK, sbom)
}

func (h *SbomHandler) List(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	sboms, err := h.sbomService.ListByProject(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, sboms)
}

func (h *SbomHandler) GetComponents(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	components, err := h.sbomService.GetComponents(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, components)
}

func (h *SbomHandler) GetVulnerabilities(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	vulns, err := h.sbomService.GetVulnerabilities(c.Request().Context(), projectID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, vulns)
}

// ScanStatusResponse is the JSON shape returned by ScanStatus. It mirrors
// the type the CLI defines client-side in internal/api/client.go; keep
// them in sync.
type ScanStatusResponse struct {
	Status          string                    `json:"status"`
	SbomID          string                    `json:"sbom_id"`
	ProjectID       string                    `json:"project_id"`
	Error           string                    `json:"error,omitempty"`
	Vulnerabilities VulnerabilitySummaryCount `json:"vulnerabilities"`
}

// VulnerabilitySummaryCount aggregates vulnerability counts by severity
// for one SBOM. Severity values are normalised to uppercase to match the
// `vulnerabilities.severity` column convention (CRITICAL/HIGH/...).
//
// `KEV` is an *orthogonal* bucket: it counts vulnerabilities flagged in the
// CISA Known Exploited Vulnerabilities catalogue (migration 020) and is
// emitted alongside the CVSS-derived severity buckets so the CLI's
// `--fail-on kev` threshold has an authoritative source (Codex R1 fix —
// previously the CLI only saw upload-time KEV counts which the canonical
// upload endpoint does not populate, so `--fail-on kev` silently never
// tripped).
type VulnerabilitySummaryCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	KEV      int `json:"kev"`
	Total    int `json:"total"`
}

// ScanStatus reports whether the background vulnerability scan for a
// given SBOM is still running, completed, or failed, and includes the
// current (or final) per-severity vulnerability counts.
//
// Route: GET /api/v1/projects/:id/sboms/:sbom_id/scan-status
//
// Response shape:
//
//	{
//	  "status": "running" | "completed" | "failed" | "unknown",
//	  "sbom_id": "...",
//	  "project_id": "...",
//	  "error": "..." (only when status=failed),
//	  "vulnerabilities": { "critical": N, "high": N, "medium": N,
//	                       "low": N, "unknown": N, "total": N }
//	}
//
// The counts always reflect the current state of the
// component_vulnerabilities join, so a caller polling during a "running"
// scan can see counts climb as NVD/JVN match more components. CLI callers
// (`sbomhub scan --fail-on`) should only trust counts once status =
// "completed" — partial counts under "running" are advisory.
func (h *SbomHandler) ScanStatus(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}
	sbomID, err := uuid.Parse(c.Param("sbom_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sbom id"})
	}

	// Vulnerability counts come from the live join — they reflect whatever
	// the background scan has matched so far. We always return them even
	// for status=running so the CLI can show progress; the threshold check
	// is gated on status=completed by the client.
	//
	// Codex R2 P2: the lookup MUST be scoped by the URL sbom_id rather than
	// by "the latest SBOM for this project". The previous implementation
	// called GetVulnerabilities(projectID), which silently switched to the
	// most recent SBOM — so polling status(sbom1) right after uploading
	// sbom2 returned sbom2's counts and the CLI's threshold check raced.
	vulns, err := h.sbomService.GetVulnerabilitiesBySbom(c.Request().Context(), projectID, sbomID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "sbom not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	summary := summariseVulnerabilities(vulns)

	state := service.ScanStateUnknown
	var errMsg string
	if h.scanTracker != nil {
		state, errMsg = h.scanTracker.Get(sbomID)
	}

	resp := ScanStatusResponse{
		Status:          string(state),
		SbomID:          sbomID.String(),
		ProjectID:       projectID.String(),
		Vulnerabilities: summary,
	}
	if state == service.ScanStateFailed {
		resp.Error = errMsg
	}

	return c.JSON(http.StatusOK, resp)
}

// summariseVulnerabilities collapses a slice of Vulnerability into
// per-severity counts. Severity strings are matched case-insensitively
// against CRITICAL/HIGH/MEDIUM/LOW; anything else (or empty) lands in
// `unknown`. `total` is the input slice length, not the sum of named
// buckets, so callers always get a reliable "any vulnerabilities at all?"
// signal even if a new severity label appears upstream.
//
// `KEV` is incremented orthogonally to the CVSS bucket: a KEV-listed CVE
// also counts in its CRITICAL/HIGH/etc. bucket. The CLI uses this for the
// `--fail-on kev` threshold (see severity.LevelKEV in sbomhub-cli).
func summariseVulnerabilities(vulns []model.Vulnerability) VulnerabilitySummaryCount {
	out := VulnerabilitySummaryCount{Total: len(vulns)}
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			out.Critical++
		case "HIGH":
			out.High++
		case "MEDIUM":
			out.Medium++
		case "LOW":
			out.Low++
		default:
			out.Unknown++
		}
		if v.InKEV {
			out.KEV++
		}
	}
	return out
}
