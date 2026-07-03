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
//
// F244 chunk-based tx pattern — permanent defer (F269, M18-3 #112):
//
//	Decision: the F244 chunk-based tx split pattern (established in M15
//	F234 for vulnerability_scan, replicated in M16 F244 for
//	report_generation, and extended to write-heavy per-tenant work in
//	M17 F258 for cve_sync) is deliberately NOT applied to ticket_sync.
//	This defers the pattern for ticket_sync PERMANENTLY. Re-evaluation
//	is not on the M19+ roadmap on its own merits — if operational data
//	ever justifies revisiting, the correct path is a NEW wave under one
//	of the alternative approaches listed below, not a horizontal
//	replication of F244's chunk shape.
//
//	Context (M17 F252 R1 evaluation):
//	  - F234 (vulnerability_scan) and F244 (report_generation) are
//	    read-only per-tenant eligibility enumerations (SELECT-only
//	    inside the tx). Chunking pays back with pool efficiency and a
//	    chunk-scoped tx-abort blast radius, with essentially no
//	    downside because there are no writes to roll back.
//	  - F258 (cve_sync) is write-heavy — per-tenant, per-CVE INSERTs
//	    into component_vulnerabilities inside the chunk tx. Chunking
//	    still pays back at N=1000+ tenant scale because the writes are
//	    fast, local, and rollback-safe (idempotent ON CONFLICT
//	    upserts). The blast radius is intentionally sized down (K=200
//	    vs K=500 for read-only) to keep the write-heavy trade-off
//	    tolerable — see cve_sync.go's cveMatchBatchChunkSizeDefault
//	    docstring for the load-bearing rationale.
//	  - ticket_sync is I/O-bound. syncTenant's per-tenant tx wraps
//	    j.issueTrackerService.SyncTicket(txCtx, ticketID), which
//	    performs a synchronous external HTTP call. See
//	    service.IssueTrackerService.SyncTicket: the
//	    model.TrackerTypeJira, model.TrackerTypeBacklog, and
//	    model.TrackerTypeGitHub switch arms each construct a
//	    per-request client and fetch the external issue synchronously
//	    (GetIssue for all three trackers — the GitHub arm's former
//	    GetIssueStatus state-only wrapper was replaced by a direct
//	    GetIssue in F367/M25-A to sync assignees, and removed) with a
//	    30-second per-request timeout (F274b — M18-3 Phase D R2,
//	    replaced the earlier absolute line-range reference "around
//	    lines 372-398" which drifted with every unrelated edit to
//	    issue_tracker.go and would have silently misled a future
//	    reviewer into looking at the wrong function). Every ticket
//	    sync is one external round-trip; the DB writes that follow
//	    are a single UPDATE via UpdateTicket. The tick's dominant
//	    latency component is external API round-trip time, not DB
//	    pool contention. Per-tenant tx-abort blast radius is already
//	    small (1 tenant scope, bounded to 100 tickets per cycle by
//	    GetTicketsToSync's LIMIT 100).
//
//	Trade-off analysis:
//	  - Chunking benefit for ticket_sync: pool efficiency (small —
//	    at 5-min interval and typical single-digit-thousand tenant
//	    scale, per-tenant BEGIN/COMMIT cycles are sparse against the
//	    connection pool; pool lease is not the bottleneck).
//	  - Chunking cost for ticket_sync (net negative):
//	      (a) External HTTP call in-tx across chunk tenants keeps a
//	          single tx open for the sum of all ticket HTTP latencies
//	          in the chunk. At K=200 tenants × up-to-100 tickets each
//	          × ~1s per external round-trip in the worst case, a
//	          single chunk tx would need to be held for tens of
//	          minutes — well past PG idle_in_transaction_timeout /
//	          statement_timeout / connection idle timeout on managed
//	          PG (RDS default 60s idle-in-tx, 30s Cloud SQL). Chunking
//	          would immediately introduce a tx-timeout failure mode
//	          that the per-tenant shape does not have.
//	      (b) A single poison ticket / tenant inside the chunk rolls
//	          back the UpdateTicket writes of every other tenant in
//	          the chunk whose HTTP call already succeeded. This is a
//	          semantic loss the caller cannot recover from without
//	          replaying the external API call on the next tick,
//	          effectively wasting the successful HTTP round-trips.
//	      (c) The Jira / Backlog / GitHub Issues clients in
//	          apps/api/internal/client/ all implement F277-pattern
//	          rate-limit hardening (429 detection, Retry-After /
//	          X-RateLimit-Reset respect, exponential backoff with retry
//	          cap, and a wrapped ErrRateLimitExhausted sentinel — landed
//	          for Jira/Backlog in M19-1 via client/rate_limit.go, adopted
//	          at birth by the GitHub Issues client in F355/M24-1b).
//	          Chunking would layer on top of this
//	          hardening rather than around a client with zero
//	          hardening. The trade-off remains net negative because
//	          chunking still requires holding a per-chunk tx open
//	          across per-ticket HTTP calls — each of which now
//	          includes potential retry latency from F277 — and the
//	          tx-timeout / rollback-cascade risks from (a)/(b) above
//	          persist regardless of how well the client behaves under
//	          throttling.
//	  - Verdict: chunking would move the per-tenant blast radius
//	    upward (from 1 tenant to K tenants) while adding a new
//	    tx-timeout failure mode, in exchange for a marginal pool
//	    efficiency gain that is dominated by external HTTP latency.
//	    Net negative.
//
//	Alternative approaches (if M19+ operational data reopens this):
//	  (a) Move the HTTP call out of the tx. Fetch tickets under a
//	      short read-only tenant tx, drop the tx, perform the HTTP
//	      calls outside the tx (optionally in parallel, see (c)),
//	      then reopen a short write-only tenant tx to persist the
//	      UpdateTicket batch. This is the scheduler-side analogue of
//	      F258's collect-then-insert shape and is the correct fix if
//	      pool pressure ever becomes measurable.
//	  (b) Rate-limit hardening on the client side. LANDED in M19-1
//	      (F277, Phase D R2 #113): 429 detection, Retry-After /
//	      X-RateLimit-Reset respect, exponential backoff, retry cap,
//	      and a wrapped ErrRateLimitExhausted sentinel are shipped in
//	      apps/api/internal/client/{jira,backlog}.go plus the shared
//	      helper apps/api/internal/client/rate_limit.go. This is
//	      orthogonal to the tx shape and remains the right lever if
//	      the operational pain is external-API throttling rather than
//	      DB pool contention — F277 is the lever, not a chunk-shape
//	      rewrite of this scheduler.
//	  (c) Bounded per-tenant concurrency. Introduce a goroutine
//	      worker pool with a semaphore gate so multiple tenants'
//	      ticket batches can progress in parallel while respecting
//	      the per-external-tracker rate limit. Complementary to (a);
//	      only useful once the HTTP call is outside the tx.
//
//	Decision recap: ticket_sync keeps the per-tenant runWithTenantTx
//	shape. Pool pressure is negligible against I/O latency at
//	realistic tenant scale (5-min interval × per-cycle LIMIT 100
//	tickets × per-tenant tx acquisition/release is sparse).
//	Alternative (b) — client-side rate-limit hardening — is LANDED
//	in M19-1 (F277); alternatives (a) HTTP-out-of-tx and
//	(c) bounded concurrency remain open as future waves if pool
//	pressure or external-latency ever becomes measurable.
//	Horizontal replication of F244's chunk shape is not the right
//	answer for this job and is closed out here.
//
//	Cross-references:
//	  - F234 vulnerability_scan.go   (read-only, K=500)
//	  - F244 report_generation.go    (read-only, K=500)
//	  - F258 cve_sync.go             (write-heavy, K=200)
//	  - M17 F252 R1 finding notes    (initial I/O-bound rationale)
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
// calls to the connected tracker (Jira / Backlog / GitHub Issues) and updates
// `vulnerability_tickets` (RLS), so it
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
			// F269 invariant (M18-3 Phase D R2 #112): this HTTP call
			// intentionally runs inside runWithTenantTx. Do not move it
			// out without also updating the F269 ADR docstring on
			// TicketSyncJob (see the F244-chunk-pattern permanent-defer
			// block above) — the ADR's chunking trade-off analysis
			// depends on the per-tenant tx wrapping the external round-
			// trip. F274b (M18-3 Phase D R2) added this local sign so
			// a future reviewer editing this loop sees the invariant
			// here, before having to trace back to the caller-level
			// ADR on the type declaration.
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
