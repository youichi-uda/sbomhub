package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// KEVSyncJob handles periodic KEV catalog synchronization
type KEVSyncJob struct {
	kevService *service.KEVService
	interval   time.Duration
	logger     *slog.Logger
}

// NewKEVSyncJob creates a new KEV sync job
func NewKEVSyncJob(kevService *service.KEVService, interval time.Duration) *KEVSyncJob {
	return &KEVSyncJob{
		kevService: kevService,
		interval:   interval,
		logger:     slog.Default().With("job", "kev_sync"),
	}
}

// Start starts the KEV sync job
func (j *KEVSyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("KEV sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single sync
func (j *KEVSyncJob) run(ctx context.Context) {
	j.logger.Info("Starting KEV catalog sync")
	startTime := time.Now()

	result, err := j.kevService.SyncCatalog(ctx)
	if err != nil {
		j.logger.Error("KEV sync failed", "error", err)
		return
	}

	duration := time.Since(startTime)
	j.logger.Info("KEV sync completed",
		"new_entries", result.NewEntries,
		"updated_entries", result.UpdatedEntries,
		"total_processed", result.TotalProcessed,
		"catalog_version", result.CatalogVersion,
		"duration_ms", duration.Milliseconds(),
	)
}

// RunOnce runs a single sync operation
func (j *KEVSyncJob) RunOnce(ctx context.Context) (*model.KEVSyncResult, error) {
	return j.kevService.SyncCatalog(ctx)
}
