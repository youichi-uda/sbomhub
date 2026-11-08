package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Scan-incompleteness sentinels (M62). Every error a scanner returns because
// its sweep was less than complete wraps one or more of these, so callers can
// report WHY without parsing messages, and without forwarding a raw error
// (F445: scan-status bodies carry generic markers only).
var (
	// ErrScanDeadlineExceeded: the overall scan deadline
	// (SBOMHUB_SCAN_DEADLINE) fired before every component was looked up.
	ErrScanDeadlineExceeded = errors.New("scan deadline exceeded")
	// ErrScanCancelled: the scan's context was cancelled for another reason
	// (shutdown) before every component was looked up.
	ErrScanCancelled = errors.New("scan cancelled")
	// ErrScanFetchFailed: at least one component's lookup failed (partial or
	// total). Before M62 a PARTIAL fetch failure was reported as success.
	ErrScanFetchFailed = errors.New("component lookup failed")
	// ErrScanTruncated: at least one component's match set is known to be
	// incomplete (paging budget, a page failing partway, a shifting result
	// set, or the deadline firing inside a page walk).
	ErrScanTruncated = errors.New("match set truncated")
	// ErrScanWriteRefused: the database refused at least one write.
	ErrScanWriteRefused = errors.New("database refused writes")
)

// Reason codes as reported in scan status (GET .../scan-status `reasons`,
// scheduler scan_logs.error_message). Stable, lower-snake, generic.
const (
	ScanReasonDeadlineExceeded = "deadline_exceeded"
	ScanReasonCancelled        = "cancelled"
	ScanReasonFetchFailed      = "fetch_failed"
	ScanReasonTruncated        = "truncated"
	ScanReasonWriteRefused     = "write_refused"
	ScanReasonError            = "scan_error"
)

// ScanReasons maps a scanner error to the reason codes it carries, in a fixed
// order. A non-nil error that wraps none of the sentinels (e.g. the component
// list could not be read) is ScanReasonError.
func ScanReasons(err error) []string {
	if err == nil {
		return nil
	}
	var out []string
	for _, p := range []struct {
		sentinel error
		code     string
	}{
		{ErrScanDeadlineExceeded, ScanReasonDeadlineExceeded},
		{ErrScanCancelled, ScanReasonCancelled},
		{ErrScanFetchFailed, ScanReasonFetchFailed},
		{ErrScanTruncated, ScanReasonTruncated},
		{ErrScanWriteRefused, ScanReasonWriteRefused},
	} {
		if errors.Is(err, p.sentinel) {
			out = append(out, p.code)
		}
	}
	if len(out) == 0 {
		out = append(out, ScanReasonError)
	}
	return out
}

// MergeScanReasons unions reason lists, keeping first-seen order.
func MergeScanReasons(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, r := range l {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// ScanFailureMarker is the generic, client-safe marker for a failed scanner:
// "nvd: scan failed (deadline_exceeded, fetch_failed)".
func ScanFailureMarker(source string, reasons []string) string {
	if len(reasons) == 0 {
		return source + ": scan failed"
	}
	return fmt.Sprintf("%s: scan failed (%s)", source, strings.Join(reasons, ", "))
}

// DefaultScanDeadline is the overall deadline of one SBOM scan (NVD + JVN)
// when SBOMHUB_SCAN_DEADLINE is unset. See config.ScanDeadline for why 30m.
const DefaultScanDeadline = 30 * time.Minute

// WithScanDeadline bounds a scan. Expiry is distinguishable from any other
// cancellation through context.Cause == ErrScanDeadlineExceeded. d <= 0 means
// DefaultScanDeadline: a scan always has a deadline.
func WithScanDeadline(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		d = DefaultScanDeadline
	}
	return context.WithTimeoutCause(ctx, d, ErrScanDeadlineExceeded)
}

// scanInterruption classifies why ctx is done: ErrScanDeadlineExceeded for
// the scan deadline, ErrScanCancelled for anything else, nil if it is not.
func scanInterruption(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if errors.Is(context.Cause(ctx), ErrScanDeadlineExceeded) {
		return ErrScanDeadlineExceeded
	}
	return ErrScanCancelled
}

// ScanInterruption is scanInterruption for callers outside the package: why
// ctx is done, as ErrScanDeadlineExceeded / ErrScanCancelled, or nil.
func ScanInterruption(ctx context.Context) error { return scanInterruption(ctx) }

// scanDeadlineFired reports whether ctx ended because the scan deadline did.
func scanDeadlineFired(ctx context.Context) bool {
	return errors.Is(scanInterruption(ctx), ErrScanDeadlineExceeded)
}
