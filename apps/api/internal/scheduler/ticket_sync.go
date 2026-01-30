package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// TicketSyncJob handles periodic ticket synchronization with external issue trackers
type TicketSyncJob struct {
	issueTrackerService *service.IssueTrackerService
	issueTrackerRepo    *repository.IssueTrackerRepository
	interval            time.Duration
	syncOlderThan       time.Duration
	logger              *slog.Logger
}

// NewTicketSyncJob creates a new ticket sync job
func NewTicketSyncJob(
	issueTrackerService *service.IssueTrackerService,
	issueTrackerRepo *repository.IssueTrackerRepository,
	interval time.Duration,
) *TicketSyncJob {
	return &TicketSyncJob{
		issueTrackerService: issueTrackerService,
		issueTrackerRepo:    issueTrackerRepo,
		interval:            interval,
		syncOlderThan:       15 * time.Minute, // Sync tickets not synced in last 15 minutes
		logger:              slog.Default().With("job", "ticket_sync"),
	}
}

// Start starts the ticket sync job
func (j *TicketSyncJob) Start(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.run(ctx)

	for {
		select {
		case <-ctx.Done():
			j.logger.Info("Ticket sync job stopped")
			return
		case <-ticker.C:
			j.run(ctx)
		}
	}
}

// run executes a single sync cycle
func (j *TicketSyncJob) run(ctx context.Context) {
	j.logger.Info("Starting ticket sync")
	startTime := time.Now()

	// Get tickets that need syncing
	tickets, err := j.issueTrackerRepo.GetTicketsToSync(ctx, j.syncOlderThan)
	if err != nil {
		j.logger.Error("Failed to get tickets to sync", "error", err)
		return
	}

	if len(tickets) == 0 {
		j.logger.Debug("No tickets to sync")
		return
	}

	j.logger.Info("Found tickets to sync", "count", len(tickets))

	var synced, failed int
	for _, ticket := range tickets {
		if err := j.issueTrackerService.SyncTicket(ctx, ticket.ID); err != nil {
			j.logger.Warn("Failed to sync ticket",
				"ticket_id", ticket.ID,
				"external_ticket_id", ticket.ExternalTicketID,
				"error", err,
			)
			failed++
		} else {
			synced++
		}
	}

	duration := time.Since(startTime)
	j.logger.Info("Ticket sync completed",
		"synced", synced,
		"failed", failed,
		"total", len(tickets),
		"duration_ms", duration.Milliseconds(),
	)
}

// SyncResult contains the result of a sync operation
type TicketSyncResult struct {
	Synced int
	Failed int
	Total  int
}

// RunOnce runs a single sync operation
func (j *TicketSyncJob) RunOnce(ctx context.Context) (*TicketSyncResult, error) {
	tickets, err := j.issueTrackerRepo.GetTicketsToSync(ctx, j.syncOlderThan)
	if err != nil {
		return nil, err
	}

	result := &TicketSyncResult{
		Total: len(tickets),
	}

	for _, ticket := range tickets {
		if err := j.issueTrackerService.SyncTicket(ctx, ticket.ID); err != nil {
			result.Failed++
		} else {
			result.Synced++
		}
	}

	return result, nil
}
