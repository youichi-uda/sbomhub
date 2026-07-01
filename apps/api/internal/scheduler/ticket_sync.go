package scheduler

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// TicketSyncJob handles periodic ticket synchronization with external issue
// trackers.
//
// codex-r4 P1 fix:
//
//	`vulnerability_tickets` and `issue_tracker_connections` are FORCE
//	ROW LEVEL SECURITY (migration 023). The job used to call
//	`issueTrackerRepo.GetTicketsToSync(ctx, …)` on a bare scheduler context
//	and silently received zero rows on every tick. We now enumerate tenants
//	via TenantRepository and run the fetch + per-ticket sync inside a
//	per-tenant tx that pins `app.current_tenant_id` so RLS policies pass.
type TicketSyncJob struct {
	issueTrackerService *service.IssueTrackerService
	issueTrackerRepo    *repository.IssueTrackerRepository
	tenantRepo          *repository.TenantRepository
	db                  *sql.DB
	interval            time.Duration
	syncOlderThan       time.Duration
	logger              *slog.Logger
}

// NewTicketSyncJob creates a new ticket sync job.
//
// db + tenantRepo are required for the per-tenant tenant tx enumeration that
// keeps the job working under sbomhub_app's RLS. Callers that previously
// constructed without them will fail to compile — that is intentional, since
// the prior behavior was a silent no-op.
func NewTicketSyncJob(
	issueTrackerService *service.IssueTrackerService,
	issueTrackerRepo *repository.IssueTrackerRepository,
	tenantRepo *repository.TenantRepository,
	db *sql.DB,
	interval time.Duration,
) *TicketSyncJob {
	return &TicketSyncJob{
		issueTrackerService: issueTrackerService,
		issueTrackerRepo:    issueTrackerRepo,
		tenantRepo:          tenantRepo,
		db:                  db,
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

// run executes a single sync cycle, iterating every tenant under its own
// RLS-pinned transaction.
func (j *TicketSyncJob) run(ctx context.Context) {
	j.logger.Info("Starting ticket sync")
	startTime := time.Now()

	tenantIDs, err := j.tenantRepo.ListAllIDs(ctx)
	if err != nil {
		j.logger.Error("Failed to list tenants", "error", err)
		return
	}

	var totalTickets, totalSynced, totalFailed int

	for _, tid := range tenantIDs {
		synced, failed, total, terr := j.syncTenant(ctx, tid)
		if terr != nil {
			j.logger.Warn("Tenant ticket sync failed",
				"tenant_id", tid,
				"error", terr,
			)
			// One tenant's failure must not block the rest.
			continue
		}
		totalTickets += total
		totalSynced += synced
		totalFailed += failed
	}

	duration := time.Since(startTime)
	j.logger.Info("Ticket sync completed",
		"tenants", len(tenantIDs),
		"synced", totalSynced,
		"failed", totalFailed,
		"total", totalTickets,
		"duration_ms", duration.Milliseconds(),
	)
}

// syncTenant runs one tenant's ticket fetch + per-ticket sync inside a single
// tx with `app.current_tenant_id` pinned. SyncTicket itself performs HTTP
// calls to Jira/Backlog and updates `vulnerability_tickets` (RLS), so it
// must run inside the tx; the HTTP I/O does keep the tx open for its
// duration, which is acceptable for a background job that runs every 5
// minutes and bounds itself to 100 tickets per cycle.
func (j *TicketSyncJob) syncTenant(ctx context.Context, tenantID uuid.UUID) (synced, failed, total int, err error) {
	err = runWithTenantTx(ctx, j.db, tenantID, func(txCtx context.Context, _ *sql.Tx) error {
		tickets, terr := j.issueTrackerRepo.GetTicketsToSync(txCtx, j.syncOlderThan)
		if terr != nil {
			return terr
		}
		total = len(tickets)
		if total == 0 {
			return nil
		}

		j.logger.Debug("found tickets to sync", "tenant_id", tenantID, "count", total)

		for _, ticket := range tickets {
			if serr := j.issueTrackerService.SyncTicket(txCtx, ticket.ID); serr != nil {
				j.logger.Warn("Failed to sync ticket",
					"tenant_id", tenantID,
					"ticket_id", ticket.ID,
					"external_ticket_id", ticket.ExternalTicketID,
					"error", serr,
				)
				failed++
			} else {
				synced++
			}
		}
		return nil
	})
	return synced, failed, total, err
}

// SyncResult contains the result of a sync operation
type TicketSyncResult struct {
	Synced int
	Failed int
	Total  int
}

// RunOnce runs a single sync operation across every tenant.
func (j *TicketSyncJob) RunOnce(ctx context.Context) (*TicketSyncResult, error) {
	tenantIDs, err := j.tenantRepo.ListAllIDs(ctx)
	if err != nil {
		return nil, err
	}

	result := &TicketSyncResult{}
	for _, tid := range tenantIDs {
		synced, failed, total, terr := j.syncTenant(ctx, tid)
		if terr != nil {
			// Count any unprocessed tickets in this tenant as failed so
			// the result reflects the partial-failure shape callers
			// already expect.
			j.logger.Warn("Tenant ticket sync failed", "tenant_id", tid, "error", terr)
			continue
		}
		result.Total += total
		result.Synced += synced
		result.Failed += failed
	}
	return result, nil
}
