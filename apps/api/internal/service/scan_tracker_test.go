package service

import (
	"testing"

	"github.com/google/uuid"
)

func TestScanTracker_TransitionsRunningToCompleted(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()

	// Unknown before any signal.
	if state, _ := tr.Get(id); state != ScanStateUnknown {
		t.Fatalf("state = %q, want %q", state, ScanStateUnknown)
	}

	tr.MarkRunning(id)
	if state, _ := tr.Get(id); state != ScanStateRunning {
		t.Fatalf("after MarkRunning: state = %q, want %q", state, ScanStateRunning)
	}

	tr.MarkCompleted(id)
	if state, _ := tr.Get(id); state != ScanStateCompleted {
		t.Fatalf("after MarkCompleted: state = %q, want %q", state, ScanStateCompleted)
	}
}

func TestScanTracker_FailedSurfacesErrorMessage(t *testing.T) {
	tr := NewScanTracker()
	id := uuid.New()

	tr.MarkRunning(id)
	tr.MarkFailed(id, "nvd: rate limited")

	state, errMsg := tr.Get(id)
	if state != ScanStateFailed {
		t.Fatalf("state = %q, want %q", state, ScanStateFailed)
	}
	if errMsg != "nvd: rate limited" {
		t.Fatalf("errMsg = %q, want %q", errMsg, "nvd: rate limited")
	}
}

func TestScanTracker_UnknownForDifferentSbom(t *testing.T) {
	tr := NewScanTracker()
	a := uuid.New()
	b := uuid.New()

	tr.MarkCompleted(a)
	if state, _ := tr.Get(b); state != ScanStateUnknown {
		t.Fatalf("unrelated sbom: state = %q, want %q", state, ScanStateUnknown)
	}
}
