package scheduler

import (
	"testing"
	"time"
)

// TestNewEPSSSyncJob verifies the constructor wires the interval and logger.
// EPSSService is a concrete struct with no interface seam, so RunOnce/run
// delegation is not unit-tested here (matching the KEV/EOL/IPA sync jobs,
// which have no dedicated unit tests either) to avoid an out-of-scope refactor.
func TestNewEPSSSyncJob(t *testing.T) {
	interval := 24 * time.Hour

	job := NewEPSSSyncJob(nil, interval)

	if job == nil {
		t.Fatal("NewEPSSSyncJob returned nil")
	}
	if job.interval != interval {
		t.Errorf("interval = %v, want %v", job.interval, interval)
	}
	if job.logger == nil {
		t.Error("logger is nil, want non-nil")
	}
}
