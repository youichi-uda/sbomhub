package handler

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
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
	var out scanOutcome
	for _, st := range steps {
		if st.scanner == nil {
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
	if tracker == nil {
		return 0
	}
	return tracker.Begin(sbomID)
}

// recordScanOutcome reports run gen's outcome to the tracker. The SBOM's state
// becomes terminal only when no overlapping run is still active (see
// ScanTracker.Begin); Finish returns false only for a run the tracker no
// longer counts as active (ended by a legacy MarkCompleted / MarkFailed).
func recordScanOutcome(tracker *service.ScanTracker, sbomID uuid.UUID, gen uint64, o scanOutcome) {
	if tracker == nil {
		return
	}
	if !tracker.Finish(sbomID, gen, o.reasons, o.message()) {
		slog.Info("scan: outcome not recorded; the tracker no longer counts this run as active",
			"sbom_id", sbomID, "failed", o.failed())
	}
}
