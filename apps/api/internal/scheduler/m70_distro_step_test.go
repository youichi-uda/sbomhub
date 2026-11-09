package scheduler

import (
	"context"
	"errors"
	"testing"

	"github.com/sbomhub/sbomhub/internal/service"
)

// Codex M70 R2 Medium-4: when the scan's context has ended before the distro
// step could run, the project scan is reported incomplete (deadline /
// cancellation), not successful.
func TestM70DistroStep_SkippedStepIsReported(t *testing.T) {
	ctx, cancel := service.WithScanDeadline(context.Background(), 1)
	defer cancel()
	<-ctx.Done()
	ran := false
	err := runDistroStep(ctx, nil, func(context.Context) error { ran = true; return nil })
	if ran {
		t.Error("the step ran on an expired context")
	}
	if !errors.Is(err, service.ErrScanDeadlineExceeded) {
		t.Errorf("err = %v, want ErrScanDeadlineExceeded", err)
	}
	// A live context runs the step and joins its error with the sweep's.
	sweepErr := errors.New("sweep")
	stepErr := errors.New("step")
	err = runDistroStep(context.Background(), sweepErr, func(context.Context) error { return stepErr })
	if !errors.Is(err, sweepErr) || !errors.Is(err, stepErr) {
		t.Errorf("err = %v, want both", err)
	}
	if err := runDistroStep(context.Background(), nil, func(context.Context) error { return nil }); err != nil {
		t.Errorf("clean step: %v", err)
	}
}
