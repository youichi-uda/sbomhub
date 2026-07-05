package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/service"
)

// EPSSSyncJob handles periodic EPSS score synchronization from FIRST.org
type EPSSSyncJob struct {
	epssService *service.EPSSService
	interval    time.Duration
	logger      *slog.Logger
}

// NewEPSSSyncJob creates a new EPSS sync job
func NewEPSSSyncJob(epssService *service.EPSSService, interval time.Duration) *EPSSSyncJob {
	return &EPSSSyncJob{
		epssService: epssService,
		interval:    interval,
		logger:      slog.Default().With("job", "epss_sync"),
	}
}

// Start starts the EPSS sync job
func (j *EPSSSyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("EPSS sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single sync
func (j *EPSSSyncJob) run(ctx context.Context) {
	j.logger.Info("Starting EPSS score sync")
	startTime := time.Now()

	if err := j.epssService.SyncScores(ctx); err != nil {
		j.logger.Error("EPSS sync failed", "error", err)
		return
	}

	duration := time.Since(startTime)
	j.logger.Info("EPSS sync completed",
		"duration_ms", duration.Milliseconds(),
	)
}

// RunOnce runs a single sync operation
func (j *EPSSSyncJob) RunOnce(ctx context.Context) error {
	return j.epssService.SyncScores(ctx)
}
