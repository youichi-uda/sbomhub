package service

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

// M62: a failed scan carries machine-readable reasons, and a running scan's
// entry outlives the scan deadline.
func TestM62ScanTracker_FailedCarriesReasons(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()
	tr.MarkRunning(id)
	tr.MarkFailedWithReasons(id, "nvd: scan failed (deadline_exceeded)", []string{ScanReasonDeadlineExceeded})
	st, msg, reasons := tr.GetDetail(id)
	if st != ScanStateFailed || msg != "nvd: scan failed (deadline_exceeded)" || !slices.Equal(reasons, []string{ScanReasonDeadlineExceeded}) {
		t.Fatalf("got %s %q %v", st, msg, reasons)
	}
	// Completed clears them.
	tr.MarkCompleted(id)
	if _, _, r := tr.GetDetail(id); r != nil {
		t.Errorf("completed scan still carries reasons %v", r)
	}
}

func TestM62ScanTracker_RetentionCoversTheDeadline(t *testing.T) {
	if got := NewScanTrackerFor(2 * time.Hour).retention; got < 2*time.Hour+10*time.Minute {
		t.Errorf("retention %s does not outlive a 2h scan deadline", got)
	}
	if got := NewScanTrackerFor(30 * time.Minute).retention; got != time.Hour {
		t.Errorf("retention %s, want the 1h floor", got)
	}
}
