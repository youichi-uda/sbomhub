package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/database"
	appmw "github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
	"github.com/sbomhub/sbomhub/internal/service/diff"
	"github.com/sbomhub/sbomhub/internal/service/diff_webhook"
)

// Pagination bounds for GetVulnerabilities (M1 Codex review #F26).
//
// The route GET /api/v1/projects/:id/vulnerabilities used to return the
// full matched-vulns slice with no LIMIT/OFFSET — a single read-scoped
// API-key request against a project with thousands of matches forced
// the server to materialise + transmit the entire set, and the CLI then
// io.ReadAll'd the full body before unmarshalling. The handler now:
//
//   - accepts `?limit=N&offset=M` query parameters,
//   - defaults limit to VulnsDefaultLimit when missing / zero / negative,
//   - rejects limit > VulnsMaxLimit with 400 (the same loud-failure
//     posture as #F24's ListDrafts clamp so probes show up in telemetry
//     rather than silent truncation), and
//   - passes the clamped (limit, offset) through to
//     SbomService.GetVulnerabilitiesPaginated.
//
// The response shape stays `[]Vulnerability` (no envelope) so the
// existing Web UI fetch path keeps working unchanged. The CLI pages
// through with limit=VulnsMaxLimit and stops when a page returns fewer
// than VulnsMaxLimit rows (truncation signal).
const (
	VulnsDefaultLimit = 100
	VulnsMaxLimit     = 500
	// VulnsMaxOffset bounds the `?offset=` query parameter (M1 Codex
	// review #F27). Same loud-failure posture as the limit clamp: a
	// request like `?offset=2147483647` would force the DB to skip
	// billions of rows before producing any output, burning CPU /
	// I/O on the server and yielding an empty page to the caller.
	// 10000 is the realistic upper bound for a useful "deep" page
	// (max-limit 500 × 20 pages = 10000) — pagination this deep is
	// already a signal the caller should be using a more targeted
	// query (e.g. filter by severity), so we reject rather than
	// silently clamp so probes show up in telemetry alongside the
	// #F26 limit clamp.
	VulnsMaxOffset = 10000
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

// diffComputer is the narrow surface the M12-4 auto-trigger consumes
// from internal/service/diff.Service. Keeping the dependency as an
// interface lets sbom_test.go drive the auto-trigger flow without
// standing up the full repository graph the diff service requires.
//
// Production wiring binds *diff.Service via WithDiffWebhook in
// cmd/server/main.go.
type diffComputer interface {
	Compute(ctx context.Context, req diff.Request) (*diff.Response, error)
}

// webhookFirer is the narrow surface the M12-4 auto-trigger consumes
// from internal/service/diff_webhook.Service. Tests substitute a
// recording stub.
//
// Production wiring binds *diff_webhook.Service via WithDiffWebhook in
// cmd/server/main.go. FireIfThreshold owns the existing delivery-side
// audit pair (diff_webhook_fired / diff_webhook_failed); the auto-
// trigger ONLY layers the additional diff_webhook_auto_fired row
// describing the auto-trigger decision.
type webhookFirer interface {
	FireIfThreshold(ctx context.Context, tenantID, projectID uuid.UUID, d *diff.Response) (*diff_webhook.FireDecision, error)
}

// auditLogger is the audit-writer surface the M12-4 auto-trigger
// depends on. *repository.AuditRepository.Log satisfies it. F168
// audit-or-nothing: callers MUST propagate errors from Log, never
// swallow them — see runDiffWebhookAutoTrigger.
type auditLogger interface {
	Log(ctx context.Context, input *model.CreateAuditLogInput) error
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

	// M12-4 (#85) optional auto-trigger dependencies. nil → the
	// post-ingest goroutine runs the existing vuln scan only (M11-4
	// behaviour). All three must be non-nil for the auto-trigger to
	// fire (set together via WithDiffWebhook). The "all-or-none" gate
	// is intentional — wiring two of the three but not the audit
	// writer would violate F168 audit-or-nothing the moment the
	// threshold is exceeded.
	diffSvc     diffComputer
	webhookSvc  webhookFirer
	auditWriter auditLogger
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

// WithDiffWebhook enables the M12-4 (#85) auto-trigger that fires the
// per-tenant diff webhook on every SBOM ingest whose diff against the
// immediate predecessor exceeds the configured thresholds.
//
// All three arguments are required for the auto-trigger to engage —
// pass nil for any of them and the handler reverts to the M11-4
// behaviour (NVD/JVN scan only, no webhook auto-fire). main.go wires
// `projectDiffService`, `projectDiffWebhookService`, `auditRepo`.
//
// The audit writer is gated together with the diff+webhook services
// because dropping the diff_webhook_auto_fired row would silently
// violate F168 audit-or-nothing the moment a threshold trips.
// Surfacing the dependency at construction time (rather than as an
// optional later setter) makes the misconfiguration loud at startup.
func (h *SbomHandler) WithDiffWebhook(d diffComputer, w webhookFirer, a auditLogger) *SbomHandler {
	h.diffSvc = d
	h.webhookSvc = w
	h.auditWriter = a
	return h
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
		// F443: only echo the raw service error when it is a caller-fixable
		// validation failure (malformed SBOM → 400 with helpful parser
		// feedback). Everything else is a %w-wrapped internal/DB error — log
		// the specifics server-side and return a generic body so we do not
		// leak the driver error string or misreport a 500 as a 400.
		if errors.Is(err, service.ErrValidation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		slog.Warn("sbom: import failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to import SBOM"})
	}

	// F208 / M14-1: publish the newly-minted sbom UUID so the audit
	// middleware records audit_logs.resource_id = sbom.ID instead of
	// the parent project UUID. POST /api/v1/projects/:id/sbom has :id
	// in the path, so without this override the resource_id would
	// point at the project and forensic joins to sboms would silently
	// drop. The sbom UUID is also what the CLI polls scan-status with,
	// so audit ⨝ sboms ⨝ scan-status traces line up across all three.
	if sbom != nil {
		appmw.SetAuditResourceID(c, sbom.ID)
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
	scanProjectID := projectID
	appmw.RegisterPostCommit(c, func() {
		h.startBackgroundScan(scanSbomID, tenantID, scanProjectID)
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
func (h *SbomHandler) startBackgroundScan(sbomID, tenantID, projectID uuid.UUID) {
	go func() {
		ctx := context.Background()
		// Vuln scan first — the diff webhook auto-trigger downstream
		// reads component_vulnerabilities so it can compute the
		// (new critical / new high) counts that drive threshold
		// evaluation. Running the scan first means a webhook that
		// fires on "new critical vulns >= 1" sees the just-scanned
		// rows rather than a stale snapshot.
		h.runScan(ctx, sbomID, tenantID)

		// M12-4 (#85): auto-fire diff webhook on ingest. nil guard
		// preserves the M11-4 behaviour for deployments that have
		// not opted into the auto-trigger via WithDiffWebhook.
		// Scan-level failures do NOT block the auto-trigger — the
		// diff is computed off whatever components/vulnerabilities
		// were persisted (which may be partial). Operators see the
		// partial scan via scan-status and the partial diff via the
		// webhook, both of which is preferable to silently dropping
		// the webhook altogether.
		if h.diffSvc != nil && h.webhookSvc != nil && h.auditWriter != nil {
			h.runDiffWebhookAutoTrigger(ctx, sbomID, tenantID, projectID)
		}
	}()
}

// runDiffWebhookAutoTrigger is the M12-4 (#85) auto-trigger body. It
// runs in the same background goroutine as the vuln scan, after the
// scan completes, and:
//
//  1. Opens a fresh transaction with `app.current_tenant_id` bound so
//     every downstream repository read (project scope, sbom list,
//     component diff, webhook settings) hits RLS as the correct
//     tenant. Without the GUC the diff service's
//     projectRepo.GetByTenant would short-circuit on a NULL → UUID
//     cast and ALL ingest webhooks would silently drop — the exact
//     class of regression F167 catalogued.
//
//  2. Resolves the diff against the IMMEDIATE PREDECESSOR by passing
//     only ToSbomID to diff.Compute — the service's resolveSboms
//     handles the "first ever ingest" case (From is nil) by returning
//     a baseline diff. The auto-trigger treats baseline ingests as
//     no_predecessor (no webhook fires) so an initial onboarding
//     ingest does not flood operators with a "first SBOM" alert that
//     resembles every component being newly added.
//
//  3. Delegates threshold evaluation + HTTP delivery to
//     webhookSvc.FireIfThreshold (M11-4 service). That call ALREADY
//     writes the delivery-side audit pair
//     (diff_webhook_fired / diff_webhook_failed). The auto-trigger
//     then layers an ADDITIONAL diff_webhook_auto_fired audit row
//     keyed to the ingest sbom_id with the auto-trigger decision
//     status. The two audit rows are the canonical "did this ingest
//     trigger a webhook?" + "did the webhook actually deliver?"
//     records, respectively.
//
//  4. Honours F168 audit-or-nothing: a failed Log returns an error
//     from writeAutoFiredAudit; the background goroutine logs it at
//     slog.Error level (no upstream HTTP frame to abort). Audit gaps
//     would render the auto-trigger's compliance value moot — the
//     whole point of the row is to give operators a durable record
//     mapping ingests → fires they can replay during an incident.
//
//  5. 1 ingest = at most 1 webhook fire. The race-condition guard is
//     structural: each Upload spawns its own goroutine bound to its
//     own sbom_id, and FireIfThreshold's settings read +
//     UpdateFireResult write happen serially inside this goroutine's
//     tx. Two concurrent Uploads for the same tenant produce two
//     INDEPENDENT diffs (each against their own predecessor) — that
//     is the intended behaviour, not a race. A single sbom_id never
//     fires twice because the goroutine runs once per Upload call.
func (h *SbomHandler) runDiffWebhookAutoTrigger(ctx context.Context, sbomID, tenantID, projectID uuid.UUID) {
	txErr := database.WithTxFunc(ctx, h.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}

		// Compute diff (To = ingested SBOM, From = predecessor).
		resp, err := h.diffSvc.Compute(txCtx, diff.Request{
			TenantID:  tenantID,
			ProjectID: projectID,
			ToSbomID:  sbomID,
		})
		if err != nil {
			// ErrNoSboms is impossible because we just ingested
			// `sbomID` above; surfacing it would indicate the
			// ingest never persisted. ErrSbomNotInProject means
			// the project/tenant pairing failed which is a real
			// misconfig. Either way — audit + bail.
			// F445: audit details["error"] is returned to the tenant via the
			// audit viewer, so keep the raw error out of it — log it, store
			// a generic marker.
			slog.Warn("sbom: auto-fire diff compute failed", "sbom_id", sbomID, "error", err)
			return h.writeAutoFiredAudit(txCtx, sbomID, tenantID, projectID, autoFireAuditDetails{
				Status:    model.DiffWebhookAutoFireStatusError,
				ErrorText: "diff compute failed",
			})
		}

		// Baseline ingest (single SBOM): no predecessor → skip fire,
		// emit audit row so the trail records the decision.
		if resp.From == nil {
			return h.writeAutoFiredAudit(txCtx, sbomID, tenantID, projectID, autoFireAuditDetails{
				Status:     model.DiffWebhookAutoFireStatusNoPredecessor,
				FromSbomID: "",
				ToSbomID:   sbomID.String(),
			})
		}

		// Delegate threshold + delivery to the M11-4 webhook service.
		// FireIfThreshold writes its own diff_webhook_fired /
		// diff_webhook_failed audit row; we then layer the
		// auto_fired audit on top.
		decision, fireErr := h.webhookSvc.FireIfThreshold(txCtx, tenantID, projectID, resp)
		if fireErr != nil {
			// Settings read failed OR FireIfThreshold's own audit
			// write failed (F168 propagation from the webhook
			// service). Audit + bail — the inner audit failure
			// already logged via slog inside the webhook service.
			slog.Warn("sbom: auto-fire threshold/delivery failed", "sbom_id", sbomID, "error", fireErr)
			return h.writeAutoFiredAudit(txCtx, sbomID, tenantID, projectID, autoFireAuditDetails{
				Status:     model.DiffWebhookAutoFireStatusError,
				ErrorText:  "fire if threshold failed",
				FromSbomID: resp.From.SbomID.String(),
				ToSbomID:   resp.To.SbomID.String(),
			})
		}

		status := mapDecisionToStatus(decision)
		details := autoFireAuditDetails{
			Status:     status,
			Reason:     decision.Reason,
			HTTPStatus: decision.Status,
			ErrorText:  decision.ErrorMessage,
			FromSbomID: resp.From.SbomID.String(),
			ToSbomID:   resp.To.SbomID.String(),
		}
		return h.writeAutoFiredAudit(txCtx, sbomID, tenantID, projectID, details)
	})
	if txErr != nil {
		slog.Error("diff_webhook auto-trigger failed",
			"sbom_id", sbomID,
			"tenant_id", tenantID,
			"project_id", projectID,
			"error", txErr,
		)
	}
}

// autoFireAuditDetails is the structured detail payload persisted on
// each diff_webhook_auto_fired audit row. Field naming mirrors the
// snake_case convention the delivery-side audit (diff_webhook_fired /
// diff_webhook_failed) uses so downstream operator dashboards can
// pivot on the same keys.
type autoFireAuditDetails struct {
	Status     string // model.DiffWebhookAutoFireStatus*
	Reason     string // FireDecision.Reason verbatim ("no_config", "disabled", ...) when not Triggered
	HTTPStatus int    // FireDecision.Status (0 when not delivered)
	ErrorText  string // FireDecision.ErrorMessage or upstream error
	FromSbomID string // resp.From.SbomID, empty when baseline
	ToSbomID   string // ingested sbom_id
}

// writeAutoFiredAudit persists one diff_webhook_auto_fired row. F168
// audit-or-nothing: the underlying audit.Log error is RETURNED so the
// background tx rolls back — the absence of the audit row is itself
// the durable signal that something went wrong. Without this return
// an audit-write outage would manifest as "webhooks deliver but
// nothing in the trail", which is the exact compliance regression
// F168 was opened to close.
func (h *SbomHandler) writeAutoFiredAudit(
	ctx context.Context, sbomID, tenantID, projectID uuid.UUID,
	d autoFireAuditDetails,
) error {
	details := map[string]interface{}{
		"status":     d.Status,
		"sbom_id":    sbomID.String(),
		"project_id": projectID.String(),
	}
	if d.Reason != "" {
		details["reason"] = d.Reason
	}
	if d.HTTPStatus != 0 {
		details["http_status"] = d.HTTPStatus
	}
	if d.ErrorText != "" {
		details["error"] = d.ErrorText
	}
	if d.FromSbomID != "" {
		details["from_sbom_id"] = d.FromSbomID
	}
	if d.ToSbomID != "" {
		details["to_sbom_id"] = d.ToSbomID
	}
	tenant := tenantID
	input := &model.CreateAuditLogInput{
		TenantID:     &tenant,
		Action:       model.AuditActionDiffWebhookAutoFired,
		ResourceType: model.ResourceDiffWebhook,
		ResourceID:   &projectID,
		Details:      details,
	}
	if err := h.auditWriter.Log(ctx, input); err != nil {
		slog.Error("diff_webhook auto-trigger audit write failed",
			"sbom_id", sbomID,
			"tenant_id", tenantID,
			"project_id", projectID,
			"status", d.Status,
			"error", err,
		)
		return fmt.Errorf("write auto_fired audit (status=%s): %w", d.Status, err)
	}
	return nil
}

// mapDecisionToStatus translates a *diff_webhook.FireDecision into the
// stable model.DiffWebhookAutoFireStatus* string persisted in the
// audit row. Reason → status mapping mirrors the FireDecision.Reason
// vocabulary documented on the webhook service so an operator can
// pivot on either column without a translation table.
func mapDecisionToStatus(d *diff_webhook.FireDecision) string {
	if d == nil {
		return model.DiffWebhookAutoFireStatusError
	}
	if d.Triggered {
		// Webhook was attempted. Status >= 0 with ErrorMessage == ""
		// is the success path; anything else is failure (including
		// the post-decrypt audit-only branch where Status stays 0).
		if d.Status >= 200 && d.Status < 300 && d.ErrorMessage == "" {
			return model.DiffWebhookAutoFireStatusSuccess
		}
		return model.DiffWebhookAutoFireStatusFailure
	}
	switch d.Reason {
	case "no_config":
		return model.DiffWebhookAutoFireStatusNoConfig
	case "disabled":
		return model.DiffWebhookAutoFireStatusDisabled
	case "no_url":
		return model.DiffWebhookAutoFireStatusNoURL
	case "below_thresholds":
		return model.DiffWebhookAutoFireStatusThresholdNotExceeded
	default:
		// Defensive: any future FireDecision.Reason added in
		// diff_webhook without a matching case here surfaces as
		// error so the audit trail still records the ingest.
		return model.DiffWebhookAutoFireStatusError
	}
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
//     is called with a joined GENERIC marker string (F445: the raw scanner /
//     tx error is logged via slog and never stored, because ScanStatus.Error
//     is returned verbatim to the client on a 200 status response). ONLY when
//     every scanner returns nil AND the tx commits cleanly is MarkCompleted
//     called.
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
				// F445: log the raw scanner error server-side only; the
				// string recorded in ScanStatus.Error is returned to the
				// client on a 200 status response, so keep it generic.
				slog.Warn("sbom: scan failed", "sbom_id", sbomID, "scanner", "nvd", "error", err)
				errs = append(errs, "nvd: scan failed")
			} else {
				slog.Info("Auto NVD scan completed", "sbom_id", sbomID)
			}
		}

		// Scan with JVN
		if h.jvnService != nil {
			if err := h.jvnService.ScanComponents(txCtx, sbomID); err != nil {
				// F445: raw scanner error to logs only; stored string is generic.
				slog.Warn("sbom: scan failed", "sbom_id", sbomID, "scanner", "jvn", "error", err)
				errs = append(errs, "jvn: scan failed")
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
		// F445: the tenant-tx error can carry DB/driver internals; log it
		// server-side only and record a generic marker in ScanStatus.Error.
		slog.Warn("sbom: scan failed", "sbom_id", sbomID, "tenant_id", tenantID, "scanner", "tx", "error", txErr)
		errs = append(errs, "tx: scan failed")
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
		// F442: never surface the raw service / repository / SQL error to
		// the caller. Log specifics server-side, return a generic body.
		slog.Warn("sbom: list sboms failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list SBOMs"})
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
		// F442: never surface the raw service / repository / SQL error to
		// the caller. Log specifics server-side, return a generic body.
		slog.Warn("sbom: list components failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list components"})
	}

	return c.JSON(http.StatusOK, components)
}

func (h *SbomHandler) GetVulnerabilities(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	// #F26: parse + clamp `?limit=` / `?offset=` query params. Same
	// "reject out-of-band, default on missing / zero / negative" posture
	// as #F24's ListDrafts clamp so out-of-band probes show up in
	// telemetry rather than getting silently truncated. The response
	// shape stays a bare `[]Vulnerability` so the Web UI's existing
	// fetch path is unaffected — only the CLI is changed to page.
	limit := VulnsDefaultLimit
	if v := c.QueryParam("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid limit"})
		}
		if n > VulnsMaxLimit {
			slog.Warn("vulnerabilities: limit exceeds maximum",
				"project_id", projectID,
				"requested_limit", n,
				"max_limit", VulnsMaxLimit,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "limit exceeds maximum"})
		}
		if n >= 1 {
			limit = n
		}
		// n < 1 falls through to VulnsDefaultLimit (already set above).
	}
	offset := 0
	if v := c.QueryParam("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid offset"})
		}
		// #F27: reject offsets beyond VulnsMaxOffset BEFORE the DB
		// runs. Same posture as the #F26 limit clamp — a silent clamp
		// would hide the probe behaviour from telemetry and a request
		// like `?offset=2147483647` would otherwise force the DB to
		// skip billions of rows on its way to producing zero output.
		if n > VulnsMaxOffset {
			slog.Warn("vulnerabilities: offset exceeds maximum",
				"project_id", projectID,
				"requested_offset", n,
				"max_offset", VulnsMaxOffset,
			)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "offset exceeds maximum"})
		}
		if n >= 0 {
			offset = n
		}
		// n < 0 falls through to 0.
	}

	// F446 (M38): `?sort=` selects the ORDER BY column of the paginated
	// list. Default "cvss" preserves the historical highest-CVSS-first
	// ordering; "epss" sorts by exploitation probability (migration 055's
	// idx_vulnerabilities_epss). Same "reject out-of-band, default on
	// missing" posture as the #F26 limit / #F27 offset clamps above, so an
	// unknown value (typo / probe) surfaces as a 400 rather than silently
	// falling back — this rejects BEFORE CountVulnerabilities runs so the
	// X-Total-Count header path stays untouched on the reject branch.
	sortBy := "cvss"
	if v := c.QueryParam("sort"); v != "" {
		if v != "cvss" && v != "epss" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid sort"})
		}
		sortBy = v
	}

	// #F28 (Web UI data integrity): emit X-Total-Count so the Web UI
	// can render an accurate "N / total 件" indicator and trip a
	// warning banner when there is more than one page of vulns. The
	// count is fetched BEFORE the paginated SELECT — a cheap
	// COUNT(*) over the same join — so the header always reflects the
	// authoritative total even when the caller pages past the end of
	// the result set. CORS must expose this header for cross-origin
	// fetches; see apps/api/cmd/server/main.go ExposeHeaders.
	//
	// The CLI ignores this header (it pages until a short page
	// arrives, see sbomhub-cli #F26), so the addition is
	// backward-compatible.
	total, err := h.sbomService.CountVulnerabilities(c.Request().Context(), projectID)
	if err != nil {
		// F442: never surface the raw service / repository / SQL error to
		// the caller. Log specifics server-side, return a generic body.
		slog.Warn("sbom: count vulnerabilities failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to count vulnerabilities"})
	}
	c.Response().Header().Set("X-Total-Count", strconv.Itoa(total))

	vulns, err := h.sbomService.GetVulnerabilitiesPaginated(c.Request().Context(), projectID, limit, offset, sortBy)
	if err != nil {
		// F442: never surface the raw service / repository / SQL error to
		// the caller. Log specifics server-side, return a generic body.
		slog.Warn("sbom: list vulnerabilities failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list vulnerabilities"})
	}
	if vulns == nil {
		vulns = []model.Vulnerability{}
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
		// F442: never surface the raw service / repository / SQL error to
		// the caller. Log specifics server-side, return a generic body.
		slog.Warn("sbom: get scan status failed",
			"project_id", projectID, "sbom_id", sbomID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get scan status"})
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
