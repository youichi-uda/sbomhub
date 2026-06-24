package handler

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

type SbomHandler struct {
	sbomService *service.SbomService
	nvdService  *service.NVDService
	jvnService  *service.JVNService
	scanTracker *service.ScanTracker
}

// NewSbomHandler wires the handler with the services it needs.
//
// `tracker` is the in-memory ScanTracker (see service/scan_tracker.go)
// observed by `GET /api/v1/projects/:id/sboms/:sbom_id/scan-status`. The
// CLI polls that endpoint after upload so `sbomhub scan --fail-on
// <severity>` can actually fail a CI job on threshold violations — Trust
// Rescue P1 #12.
func NewSbomHandler(ss *service.SbomService, nvd *service.NVDService, jvn *service.JVNService, tracker *service.ScanTracker) *SbomHandler {
	return &SbomHandler{
		sbomService: ss,
		nvdService:  nvd,
		jvnService:  jvn,
		scanTracker: tracker,
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

	// Start vulnerability scan in background.
	//
	// MarkRunning is called synchronously (before the goroutine) so that a
	// CLI client that polls scan-status immediately after the upload sees
	// "running" rather than "unknown". Without that ordering there is a
	// race where the poller would think the scan never started.
	if h.scanTracker != nil {
		h.scanTracker.MarkRunning(sbom.ID)
	}
	h.startBackgroundScan(sbom.ID)

	return c.JSON(http.StatusCreated, sbom)
}

// startBackgroundScan initiates vulnerability scanning in the background
// and reports completion to the in-memory ScanTracker so the CLI
// scan-status endpoint can return an authoritative state.
func (h *SbomHandler) startBackgroundScan(sbomID uuid.UUID) {
	go func() {
		ctx := context.Background()
		var errs []string

		// Scan with NVD
		if h.nvdService != nil {
			if err := h.nvdService.ScanComponents(ctx, sbomID); err != nil {
				slog.Error("Auto NVD scan failed", "sbom_id", sbomID, "error", err)
				errs = append(errs, "nvd: "+err.Error())
			} else {
				slog.Info("Auto NVD scan completed", "sbom_id", sbomID)
			}
		}

		// Scan with JVN
		if h.jvnService != nil {
			if err := h.jvnService.ScanComponents(ctx, sbomID); err != nil {
				slog.Error("Auto JVN scan failed", "sbom_id", sbomID, "error", err)
				errs = append(errs, "jvn: "+err.Error())
			} else {
				slog.Info("Auto JVN scan completed", "sbom_id", sbomID)
			}
		}

		if h.scanTracker != nil {
			if len(errs) > 0 {
				h.scanTracker.MarkFailed(sbomID, strings.Join(errs, "; "))
			} else {
				h.scanTracker.MarkCompleted(sbomID)
			}
		}
	}()
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
	vulns, err := h.sbomService.GetVulnerabilities(c.Request().Context(), projectID)
	if err != nil {
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
