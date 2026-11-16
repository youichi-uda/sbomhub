package handler

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/service"
)

// scanStep is one scanner of an SBOM scan, labelled for the generic marker.
//
// okMsg / failMsg / failLevel keep each route's pre-M62 log lines, which
// operators may alert on: the upload path logs WARN "sbom: scan failed" /
// INFO "Auto NVD scan completed", the manual route ERROR "NVD scan failed" /
// INFO "NVD scan completed".
type scanStep struct {
	source    string
	scanner   componentScanner
	okMsg     string
	failMsg   string
	failLevel slog.Level
}

// scanOutcome is what an SBOM scan reports: generic per-scanner markers (F445:
// never a raw error — these reach clients through scan-status) and the union
// of their reason codes.
type scanOutcome struct {
	markers []string
	reasons []string
	// skipped names the sources the run made no request to because of
	// configuration or the request: switched off (SBOMHUB_JVN=off), offline
	// mode (SBOMHUB_OFFLINE), not requested (`?sources=`), or no scanner
	// configured. Not a failure; reported as scan-status skipped_sources.
	skipped []string
	// checked names the sources whose step ran against the live source and
	// returned no error (service/scan_coverage.go); reported as scan-status
	// checked_sources. A failed step is in neither list.
	checked []string
}

// disableableScanner is a scanner the operator can switch off
// (service.JVNService with SBOMHUB_JVN=off).
type disableableScanner interface {
	ScanDisabled() bool
}

// offlineScanner is a scanner whose sweep is a no-op in offline mode
// (SBOMHUB_OFFLINE): it "succeeds" without a request, so it must be reported
// skipped, never checked.
type offlineScanner interface {
	ScanOffline() bool
}

// stepSkipped reports whether st will make no request because of
// configuration: no scanner, switched off, or offline.
func stepSkipped(st scanStep) (bool, string) {
	if st.scanner == nil {
		return true, "not configured"
	}
	if d, ok := st.scanner.(disableableScanner); ok && d.ScanDisabled() {
		return true, "switched off by the operator"
	}
	if o, ok := st.scanner.(offlineScanner); ok && o.ScanOffline() {
		return true, "offline mode"
	}
	return false, ""
}

// plannedSkippedSources is the sources a scan of these steps will skip: every
// source of service.ScanSources without a step (not requested), and every
// step stepSkipped says makes no request. Ordered as scan-status lists them
// (service.OrderScanSources); empty when none. The 202 of POST .../scan
// reports it, and the run reports the same list to scan-status.
func plannedSkippedSources(steps []scanStep) []string {
	var skipped []string
	for _, src := range service.ScanSources {
		if !slices.ContainsFunc(steps, func(st scanStep) bool { return st.source == src }) {
			skipped = append(skipped, src)
		}
	}
	for _, st := range steps {
		if skip, _ := stepSkipped(st); skip {
			skipped = append(skipped, st.source)
		}
	}
	return service.OrderScanSources(skipped)
}

func (o scanOutcome) failed() bool { return len(o.markers) > 0 }

// message is the generic string stored in ScanTracker / returned as
// scan-status `error`.
func (o scanOutcome) message() string { return strings.Join(o.markers, "; ") }

// runSBOMScan runs the scanners of one SBOM scan under the overall scan
// deadline (M62), sequentially, and reports the outcome. It is shared by the
// upload path (SbomHandler.runScan) and the manual route
// (VulnerabilityHandler.runScan), so both report partial failure — and the
// deadline — identically.
//
// It opens NO transaction (M62): each scanner opens its own short ones and
// refuses a context that carries one (service.ErrScanInTransaction). What it
// hands the scanners is the tenant scope (service.WithScanScope) and the
// deadline (service.WithScanDeadline).
//
// A scanner whose turn comes after the deadline has fired is not started; it
// is reported failed with reason deadline_exceeded rather than run on an
// expired context, where its component read would fail as a generic error.
func runSBOMScan(ctx context.Context, db *sql.DB, tenantID, sbomID uuid.UUID, deadline time.Duration, steps []scanStep) scanOutcome {
	if deadline <= 0 {
		deadline = service.DefaultScanDeadline
	}
	sctx, cancel := service.WithScanDeadline(ctx, deadline)
	defer cancel()
	sctx = service.WithScanScope(sctx, db, tenantID)

	started := time.Now()
	// checked is never nil: the run always reports its coverage, even when
	// it checked nothing (offline, or no slot).
	out := scanOutcome{checked: []string{}}
	// Skipped sources are named before the slot is taken (Codex SBOMHUB_JVN
	// R2 Low-2): a scan that never got a slot must still say it would not
	// have consulted them.
	out.skipped = plannedSkippedSources(steps)
	// M72: at most SBOMHUB_SCAN_TENANT_CONCURRENCY scans of one tenant run at
	// once, so one tenant's burst of scans cannot crowd out the others. The
	// wait counts against this scan's own deadline.
	release, err := service.AcquireTenantScanSlot(sctx, tenantID, sbomID)
	if err != nil {
		reasons := service.ScanReasons(err)
		out.markers = append(out.markers, service.ScanFailureMarker("scan", reasons))
		out.reasons = reasons
		return out
	}
	defer release()
	for _, st := range steps {
		if skip, why := stepSkipped(st); skip {
			// SBOMHUB_JVN=off, offline mode, or no scanner: not run, not a
			// failure, and never silent — it is reported as scan-status
			// skipped_sources (already in out.skipped, above), never as
			// checked.
			if st.scanner != nil {
				slog.Info("scan: source skipped; it makes no request",
					"sbom_id", sbomID, "scanner", st.source, "why", why)
			}
			continue
		}
		var err error
		if sctx.Err() != nil {
			err = context.Cause(sctx)
			if !errors.Is(err, service.ErrScanDeadlineExceeded) {
				err = service.ErrScanCancelled
			}
			slog.Warn("scan: scanner not started; the scan was already interrupted",
				"sbom_id", sbomID, "scanner", st.source, "error", err)
		} else {
			err = st.scanner.ScanComponents(sctx, sbomID)
		}
		if err != nil {
			reasons := service.ScanReasons(err)
			// F445: the raw error goes to the log only.
			msg, level := st.failMsg, st.failLevel
			if msg == "" {
				msg, level = "sbom: scan failed", slog.LevelWarn
			}
			slog.Log(ctx, level, msg, "sbom_id", sbomID, "scanner", st.source, "reasons", reasons, "error", err)
			out.markers = append(out.markers, service.ScanFailureMarker(st.source, reasons))
			out.reasons = service.MergeScanReasons(out.reasons, reasons)
			continue
		}
		okMsg := st.okMsg
		if okMsg == "" {
			okMsg = "scan completed"
		}
		slog.Info(okMsg, "sbom_id", sbomID, "scanner", st.source)
		out.checked = service.MergeScanReasons(out.checked, []string{st.source})
	}
	if errors.Is(context.Cause(sctx), service.ErrScanDeadlineExceeded) {
		slog.Warn("scan: overall scan deadline exceeded; the scan is reported failed",
			"sbom_id", sbomID, "tenant_id", tenantID, "deadline", deadline.String(),
			"elapsed", time.Since(started).Round(time.Second).String())
		// A scanner that finished just as the deadline fired may have
		// returned nil; the scan as a whole still did not finish in time
		// only if some scanner says so, so nothing is added here.
	}
	return out
}

// beginScanRun starts a tracked run (0 without a tracker).
func beginScanRun(tracker *service.ScanTracker, sbomID uuid.UUID) uint64 {
	gen, _ := beginScanRunID(tracker, sbomID)
	return gen
}

// beginScanRunID is beginScanRun plus the scan run of the run's group
// (service.ScanTracker.BeginRun; "" when unknown or without a tracker).
func beginScanRunID(tracker *service.ScanTracker, sbomID uuid.UUID) (uint64, string) {
	if tracker == nil {
		return 0, ""
	}
	return tracker.BeginRun(sbomID)
}

// recordScanOutcome reports run gen's outcome to the tracker. The SBOM's state
// becomes terminal only when no overlapping run is still active (see
// ScanTracker.Begin); Finish returns false only for a run the tracker no
// longer counts as active (ended by a legacy MarkCompleted / MarkFailed).
func recordScanOutcome(tracker *service.ScanTracker, sbomID uuid.UUID, gen uint64, o scanOutcome) {
	if tracker == nil {
		return
	}
	cov := service.ScanCoverage{Checked: append([]string{}, o.checked...), Skipped: o.skipped, Reported: true}
	if !tracker.FinishCoverage(sbomID, gen, o.reasons, o.message(), cov) {
		slog.Info("scan: outcome not recorded; the tracker no longer counts this run as active",
			"sbom_id", sbomID, "failed", o.failed())
	}
}
