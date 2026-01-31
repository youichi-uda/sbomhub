package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// EOLSyncJob handles periodic EOL catalog synchronization
type EOLSyncJob struct {
	eolService *service.EOLService
	interval   time.Duration
	logger     *slog.Logger
}

// NewEOLSyncJob creates a new EOL sync job
func NewEOLSyncJob(eolService *service.EOLService, interval time.Duration) *EOLSyncJob {
	return &EOLSyncJob{
		eolService: eolService,
		interval:   interval,
		logger:     slog.Default().With("job", "eol_sync"),
	}
}

// Start starts the EOL sync job
func (j *EOLSyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("EOL sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single sync
func (j *EOLSyncJob) run(ctx context.Context) {
	j.logger.Info("Starting EOL catalog sync")
	startTime := time.Now()

	result, err := j.eolService.SyncCatalog(ctx)
	if err != nil {
		j.logger.Error("EOL sync failed", "error", err)
		return
	}

	duration := time.Since(startTime)
	j.logger.Info("EOL sync completed",
		"products_synced", result.ProductsSynced,
		"cycles_synced", result.CyclesSynced,
		"components_updated", result.ComponentsUpdated,
		"duration_ms", duration.Milliseconds(),
	)
}

// RunOnce runs a single sync operation
func (j *EOLSyncJob) RunOnce(ctx context.Context) (*model.EOLSyncResult, error) {
	return j.eolService.SyncCatalog(ctx)
}
