package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/service"
)

// JVNDBSyncJob periodically reads the JVNDB RSS feeds (migration 072): the
// recent feed every tick, plus at most one backfill year feed. The tick does
// not by itself mean a request: JVNDBRSSService claims each feed in the
// database, so a feed fetched within the interval -- by this process before a
// restart, or by another replica -- is skipped.
type JVNDBSyncJob struct {
	svc      *service.JVNDBRSSService
	interval time.Duration
	logger   *slog.Logger
}

// NewJVNDBSyncJob returns the job; interval must be positive.
func NewJVNDBSyncJob(svc *service.JVNDBRSSService, interval time.Duration) *JVNDBSyncJob {
	return &JVNDBSyncJob{
		svc:      svc,
		interval: interval,
		logger:   slog.Default().With("job", "jvndb_rss_sync"),
	}
}

// Start runs one round immediately, then one per interval until ctx ends.
func (j *JVNDBSyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	j.run(ctx)
	for {
		select {
		case <-ctx.Done():
			j.logger.Info("JVNDB RSS sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

func (j *JVNDBSyncJob) run(ctx context.Context) {
	start := time.Now()
	res, err := j.svc.Sync(ctx)
	if res != nil {
		for _, f := range res.Feeds {
			j.logger.Info("JVNDB RSS feed round",
				"feed", f.Feed, "status", f.Status, "items", f.Seen,
				"written", f.Written, "rejected", f.Rejected, "gap", f.Gap)
		}
	}
	if err != nil {
		j.logger.Error("JVNDB RSS sync failed", "error", err, "duration_ms", time.Since(start).Milliseconds())
		return
	}
	j.logger.Info("JVNDB RSS sync round completed", "duration_ms", time.Since(start).Milliseconds())
}

// RunOnce runs a single round (tests, tools).
func (j *JVNDBSyncJob) RunOnce(ctx context.Context) (*service.JVNDBSyncResult, error) {
	return j.svc.Sync(ctx)
}
