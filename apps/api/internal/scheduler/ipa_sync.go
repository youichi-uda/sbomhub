package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/service"
)

// IPASyncJob handles periodic IPA announcement synchronization
type IPASyncJob struct {
	ipaService *service.IPAService
	interval   time.Duration
	logger     *slog.Logger
}

// NewIPASyncJob creates a new IPA sync job
func NewIPASyncJob(ipaService *service.IPAService, interval time.Duration) *IPASyncJob {
	return &IPASyncJob{
		ipaService: ipaService,
		interval:   interval,
		logger:     slog.Default().With("job", "ipa_sync"),
	}
}

// Start starts the IPA sync job
func (j *IPASyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("IPA sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single sync
func (j *IPASyncJob) run(ctx context.Context) {
	j.logger.Info("Starting IPA sync")
	startTime := time.Now()

	result, err := j.ipaService.SyncAnnouncements(ctx)
	if err != nil {
		j.logger.Error("IPA sync failed", "error", err)
		return
	}

	duration := time.Since(startTime)
	j.logger.Info("IPA sync completed",
		"new_announcements", result.NewAnnouncements,
		"updated_announcements", result.UpdatedAnnouncements,
		"total_processed", result.TotalProcessed,
		"duration_ms", duration.Milliseconds(),
	)
}

// RunOnce runs a single sync operation
func (j *IPASyncJob) RunOnce(ctx context.Context) (*service.SyncResult, error) {
	return j.ipaService.SyncAnnouncements(ctx)
}
