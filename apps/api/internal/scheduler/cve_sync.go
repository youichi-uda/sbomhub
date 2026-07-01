package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	cveSyncAPIURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cveSyncRateLimitNoKey = 6 * time.Second        // ~5 requests per 30 seconds without API key
	cveSyncRateLimitKey   = 700 * time.Millisecond // ~50 requests per 30 seconds with API key
	cveSyncResultsPerPage = 2000
)

// cveMatchBatchChunkSizeDefault is the production default for how many
// tenants to evaluate inside a single BEGIN / COMMIT envelope in
// matchTenantsChunked (F258, M17-3 #109).
//
// Horizontal replication of F234 (M15-2, vulnerability_scan.go) and F244
// (M16-4, report_generation.go) — this is the FIRST write-heavy application
// of the chunk-based tx split pattern in this package. F234 and F244 were
// both read-only per-tenant eligibility enumerations; F258 flips the same
// pooled-connection + chunked-tx shape onto a write-heavy per-(tenant, CVE)
// matching loop. The pattern maturity is thus verified across three
// scheduler jobs (read-only vulnerability_scan, read-only report_generation,
// write-heavy cve_sync) — anti-pattern 55 scheduler-side discipline.
//
// Selection rationale — chosen 200 (smaller than F234 / F244's 500):
//
//   - Write-heavy per-tenant per-CVE cost: F234 / F244 issue exactly 2
//     round-trips per tenant (SET LOCAL + one SELECT). F258 issues
//     1 (SET LOCAL) + M * (1 SELECT + up to K INSERTs) round-trips per
//     tenant, where M is the number of NVD CVEs fetched this tick and K
//     is the average number of components each CVE's keywords match.
//     Even at M=50 that's ~50x the per-tenant cost of the read-only
//     jobs, so the chunk-hold time budget is spent much faster.
//
//   - Connection long-hold (upper bound): at ~2ms per per-CVE
//     (SELECT + ON CONFLICT INSERT batch) round-trip against a local PG
//     (F213 baseline), M=50 CVEs per tenant means 200 tenants ≈ 20s of
//     connection hold time per chunk. That still stays well below the
//     daily scheduler tick (24h interval, see NewCVESyncJob at
//     main.go:1470) and leaves headroom for network jitter on managed
//     PG (e.g. RDS) where per-round-trip latency is ~1–5ms.
//
//   - Tx-abort blast radius (lower bound, write-heavy specific): ANY
//     PG-side error inside a chunk aborts the whole chunk's tx and
//     rolls back EVERY component_vulnerabilities INSERT for the 200
//     tenants in that chunk (they get retried on the next daily tick).
//     Smaller chunks = smaller blast radius per failure event. At 200,
//     a worst-case cascade (statement timeout on a runaway RLS policy,
//     transient connection blip) skips at most 200 tenants for one
//     tick instead of all N.
//
//   - Write-heavy blast-radius asymmetry vs read-only F234 / F244:
//     rolling back N=200 tenants worth of INSERTs is a heavier
//     operator-visible consequence than rolling back N=500 tenants
//     worth of SELECT eligibility. That's why F258 picks 200 instead
//     of matching F234 / F244's 500 — the blast radius is intentionally
//     smaller for the write path. Still, the pre-F258 per-tenant tx
//     shape already had a POISON tenant taking out that ONE tenant's
//     entire INSERT batch, so F258's chunk shape is strictly better
//     for pool efficiency (fewer connection acquire/release cycles)
//     while only worsening blast radius by ~200x (chunk_size). At
//     production N=1000+ tenant scale that trade-off is intentional —
//     see the load-bearing docstring on matchTenantsChunked below.
//
//   - Round-trip overhead (envelope cost per additional chunk): each
//     extra chunk adds one BEGIN + one COMMIT = 2 round-trips. For
//     N=10000 (50 chunks at K=200) that's +98 round-trips over a
//     hypothetical single-tx path — a rounding-error cost for a
//     linear reduction in blast radius.
//
//   - Production tenant scale: matches the SaaS reopen plan targets
//     (N=1000–10000) and the largest self-host manufacturer
//     deployments. At K=200 the chunk count is 5–50, small enough
//     that per-chunk logging / forensic tracing stays legible.
//
// Tests use cveMatchBatchChunkSize (the var below) to temporarily
// override with smaller values so multi-chunk semantics can be
// exercised without needing N=1000+ mock tenants.
const cveMatchBatchChunkSizeDefault = 200

// cveMatchBatchChunkSize is the effective chunk size used by
// matchTenantsChunked. In production this always equals
// cveMatchBatchChunkSizeDefault. Tests may temporarily override it
// (with a defer-restore) to force multi-chunk behaviour with small
// tenant fixtures. See cve_sync_perf_test.go / cve_sync_integration_test.go
// for the pattern (analogous to eligibilityBatchChunkSize in
// vulnerability_scan.go and reportEligibilityBatchChunkSize in
// report_generation.go).
var cveMatchBatchChunkSize = cveMatchBatchChunkSizeDefault

// CVESyncJob fetches new/updated CVEs from NVD and matches against components.
//
// codex-r4 P1 fix:
//
//	The `components` table is FORCE ROW LEVEL SECURITY (migration 023 /
//	027). The previous matching loop ran a single system-wide LIKE query
//	on `j.db` and silently matched zero rows under sbomhub_app. The fix
//	keeps vulnerability upsert on the non-RLS `vulnerabilities` table at
//	the system level (one row per CVE, shared across tenants) but moves
//	the component-match phase into a per-tenant tx so RLS policies see
//	the right tenant. `component_vulnerabilities` is not RLS-enabled, so
//	the link writes happen on the same tenant tx without further policy
//	plumbing.
//
// F258 (M17-3 #109): the per-tenant runWithTenantTx loop was replaced
// with a chunk-based tx split (matchTenantsChunked). Round-trip cost
// dropped from 1 + N*(3+M) (per-tenant BEGIN + SET LOCAL + M*(SELECT +
// INSERT batch) + COMMIT) to 1 + 2c + N*(1+M) (single pooled connection
// + per-chunk BEGIN/COMMIT + per-tenant SET LOCAL + M*(SELECT + INSERT
// batch)); more importantly, the pool sees exactly one lease per Run()
// tick instead of N leases. Tx-abort blast radius trade-off: pre-F258
// a poison tenant rolled back only that ONE tenant's INSERT batch;
// post-F258 a poison tenant aborts the enclosing chunk's tx and rolls
// back up to chunk_size (default 200) tenants' INSERT batches for
// that tick (they retry on the next daily tick). This is intentional
// — see matchTenantsChunked's docstring for the full write-heavy
// blast-radius rationale. Horizontal replication of F234 (M15-2,
// vulnerability_scan.go, read-only) and F244 (M16-4,
// report_generation.go, read-only); F258 is the first write-heavy
// application of the pattern.
type CVESyncJob struct {
	db         *sql.DB
	tenantRepo *repository.TenantRepository
	httpClient *http.Client
	nvdAPIKey  string
	interval   time.Duration
}

// NewCVESyncJob creates a new CVE sync job.
//
// tenantRepo is required to enumerate tenants for the per-tenant matching
// loop. Constructing without it would re-introduce the silent-no-op bug.
func NewCVESyncJob(db *sql.DB, tenantRepo *repository.TenantRepository, nvdAPIKey string, interval time.Duration) *CVESyncJob {
	return &CVESyncJob{
		db:         db,
		tenantRepo: tenantRepo,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		nvdAPIKey:  nvdAPIKey,
		interval:   interval,
	}
}

// Start starts the CVE sync job
func (j *CVESyncJob) Start(ctx context.Context) {
	slog.Info("CVE sync job started", "interval", j.interval.String())

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on startup
	if err := j.Run(ctx); err != nil {
		slog.Error("CVE sync failed on startup", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := j.Run(ctx); err != nil {
				slog.Error("CVE sync failed", "error", err)
			}
		case <-ctx.Done():
			slog.Info("CVE sync job stopped")
			return
		}
	}
}

// Run executes a single CVE sync cycle
func (j *CVESyncJob) Run(ctx context.Context) error {
	slog.Info("starting CVE sync")
	startTime := time.Now()

	// Get last sync time
	lastSync, err := j.getLastSyncTime(ctx)
	if err != nil {
		slog.Warn("failed to get last sync time, using 24h ago", "error", err)
		lastSync = time.Now().Add(-24 * time.Hour)
	}

	// Fetch CVEs modified since last sync
	cves, err := j.fetchModifiedCVEs(ctx, lastSync)
	if err != nil {
		return fmt.Errorf("failed to fetch CVEs: %w", err)
	}

	slog.Info("fetched modified CVEs", "count", len(cves), "since", lastSync.Format(time.RFC3339))

	// Phase 1: upsert vulnerability rows at the system level
	// (`vulnerabilities` is non-RLS and shared across tenants — one row per
	// CVE). We cache the resulting vuln IDs so the per-tenant matching loop
	// below doesn't have to re-look them up.
	vulnIndex := make(map[string]cveVulnEntry, len(cves))
	for _, cve := range cves {
		if len(cve.Keywords) == 0 {
			continue
		}
		vulnID, isNew, err := j.upsertVulnerability(ctx, cve)
		if err != nil {
			slog.Warn("failed to upsert vulnerability", "cve_id", cve.ID, "error", err)
			continue
		}
		vulnIndex[cve.ID] = cveVulnEntry{id: vulnID, isNew: isNew}
	}

	// Phase 2: per-tenant matching against `components` (RLS-bound).
	// F258 (M17-3 #109): the enumeration is now a chunk-based tx split on
	// a single pooled connection instead of one runWithTenantTx per
	// tenant. See matchTenantsChunked for the round-trip formula
	// (1 + 2c + N*(1+M)) and the write-heavy blast-radius trade-off.
	tenantIDs, terr := j.tenantRepo.ListAllIDs(ctx)
	if terr != nil {
		return fmt.Errorf("failed to list tenants for CVE match: %w", terr)
	}

	matchedCount, newVulnCount, err := j.matchTenantsChunked(ctx, tenantIDs, cves, vulnIndex)
	if err != nil {
		// matchTenantsChunked returns nil unless the whole enumeration
		// cannot proceed (e.g. Conn acquire fails). Per-chunk errors are
		// logged internally and do NOT surface here — they aborted that
		// chunk's tx but the loop continued with the next chunk.
		slog.Warn("CVE match enumeration returned early", "error", err)
	}

	// Update last sync time
	if err := j.updateLastSyncTime(ctx, startTime); err != nil {
		slog.Warn("failed to update last sync time", "error", err)
	}

	duration := time.Since(startTime)
	slog.Info("CVE sync completed",
		"cves_fetched", len(cves),
		"cves_matched", matchedCount,
		"new_vulnerabilities", newVulnCount,
		"duration_ms", duration.Milliseconds(),
	)

	return nil
}

// CVEInfo represents a CVE from NVD
type CVEInfo struct {
	ID          string
	Description string
	Severity    string
	CVSSScore   float64
	PublishedAt time.Time
	ModifiedAt  time.Time
	// Keywords extracted from CVE for matching
	Keywords []string
}

func (j *CVESyncJob) fetchModifiedCVEs(ctx context.Context, since time.Time) ([]CVEInfo, error) {
	var allCVEs []CVEInfo
	startIndex := 0

	// Rate limiting
	rateLimit := cveSyncRateLimitNoKey
	if j.nvdAPIKey != "" {
		rateLimit = cveSyncRateLimitKey
	}

	for {
		params := url.Values{}
		params.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000"))
		params.Set("lastModEndDate", time.Now().UTC().Format("2006-01-02T15:04:05.000"))
		params.Set("startIndex", fmt.Sprintf("%d", startIndex))
		params.Set("resultsPerPage", fmt.Sprintf("%d", cveSyncResultsPerPage))

		req, err := http.NewRequestWithContext(ctx, "GET", cveSyncAPIURL+"?"+params.Encode(), nil)
		if err != nil {
			return nil, err
		}

		if j.nvdAPIKey != "" {
			req.Header.Set("apiKey", j.nvdAPIKey)
		}

		resp, err := j.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("NVD API request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("NVD API error: %d - %s", resp.StatusCode, string(body))
		}

		var nvdResp struct {
			TotalResults    int `json:"totalResults"`
			StartIndex      int `json:"startIndex"`
			ResultsPerPage  int `json:"resultsPerPage"`
			Vulnerabilities []struct {
				CVE struct {
					ID           string `json:"id"`
					Published    string `json:"published"`
					LastModified string `json:"lastModified"`
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
					Metrics struct {
						CvssMetricV31 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								BaseSeverity string  `json:"baseSeverity"`
							} `json:"cvssData"`
						} `json:"cvssMetricV31"`
						CvssMetricV30 []struct {
							CvssData struct {
								BaseScore    float64 `json:"baseScore"`
								BaseSeverity string  `json:"baseSeverity"`
							} `json:"cvssData"`
						} `json:"cvssMetricV30"`
						CvssMetricV2 []struct {
							CvssData struct {
								BaseScore float64 `json:"baseScore"`
							} `json:"cvssData"`
						} `json:"cvssMetricV2"`
					} `json:"metrics"`
					Configurations []struct {
						Nodes []struct {
							CpeMatch []struct {
								Criteria   string `json:"criteria"`
								Vulnerable bool   `json:"vulnerable"`
							} `json:"cpeMatch"`
						} `json:"nodes"`
					} `json:"configurations"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode NVD response: %w", err)
		}
		resp.Body.Close()

		// Convert to CVEInfo
		for _, v := range nvdResp.Vulnerabilities {
			cve := CVEInfo{
				ID: v.CVE.ID,
			}

			// Get English description
			for _, desc := range v.CVE.Descriptions {
				if desc.Lang == "en" {
					cve.Description = desc.Value
					break
				}
			}

			// Extract CVSS score and severity
			cve.CVSSScore, cve.Severity = extractCVSSFromMetrics(v.CVE.Metrics)

			// Parse dates
			if t, err := time.Parse(time.RFC3339, v.CVE.Published); err == nil {
				cve.PublishedAt = t
			}
			if t, err := time.Parse(time.RFC3339, v.CVE.LastModified); err == nil {
				cve.ModifiedAt = t
			}

			// Extract keywords from CPE for matching
			cve.Keywords = extractKeywordsFromCPE(v.CVE.Configurations)

			allCVEs = append(allCVEs, cve)
		}

		// Check if we have more results
		if startIndex+len(nvdResp.Vulnerabilities) >= nvdResp.TotalResults {
			break
		}

		startIndex += cveSyncResultsPerPage
		time.Sleep(rateLimit) // Rate limit between pages
	}

	return allCVEs, nil
}

// extractCVSSFromMetrics extracts CVSS score and severity from NVD metrics
func extractCVSSFromMetrics(metrics struct {
	CvssMetricV31 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV30 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CvssMetricV2 []struct {
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
	} `json:"cvssMetricV2"`
}) (float64, string) {
	if len(metrics.CvssMetricV31) > 0 {
		m := metrics.CvssMetricV31[0].CvssData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV30) > 0 {
		m := metrics.CvssMetricV30[0].CvssData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV2) > 0 {
		score := metrics.CvssMetricV2[0].CvssData.BaseScore
		severity := "LOW"
		if score >= 7.0 {
			severity = "HIGH"
		} else if score >= 4.0 {
			severity = "MEDIUM"
		}
		return score, severity
	}
	return 0, "UNKNOWN"
}

// extractKeywordsFromCPE extracts product names from CPE criteria for matching
func extractKeywordsFromCPE(configs []struct {
	Nodes []struct {
		CpeMatch []struct {
			Criteria   string `json:"criteria"`
			Vulnerable bool   `json:"vulnerable"`
		} `json:"cpeMatch"`
	} `json:"nodes"`
}) []string {
	keywords := make(map[string]bool)

	for _, config := range configs {
		for _, node := range config.Nodes {
			for _, match := range node.CpeMatch {
				if !match.Vulnerable {
					continue
				}
				// Parse CPE: cpe:2.3:a:vendor:product:version:...
				parts := strings.Split(match.Criteria, ":")
				if len(parts) >= 5 {
					product := parts[4]
					if product != "*" && product != "" {
						keywords[strings.ToLower(product)] = true
					}
					// Also include vendor:product combination
					if len(parts) >= 4 && parts[3] != "*" {
						vendor := parts[3]
						keywords[strings.ToLower(vendor)] = true
					}
				}
			}
		}
	}

	result := make([]string, 0, len(keywords))
	for k := range keywords {
		result = append(result, k)
	}
	return result
}

// cveVulnEntry is the lookup record used by the per-tenant matching phase
// to avoid re-querying the system-level `vulnerabilities` table once per
// (tenant, CVE).
type cveVulnEntry struct {
	id    uuid.UUID
	isNew bool
}

// matchTenantsChunked runs the component-match phase across every tenant,
// coalesced onto one pooled connection but split across N/K chunked
// transactions for tx-abort blast-radius containment
// (F258, M17-3 #109).
//
// Horizontal replication of listDueTenantsBatched (F234, M15-2,
// vulnerability_scan.go) and listEnabledSettingsBatched (F244, M16-4,
// report_generation.go). Same pooled-connection + chunked-tx shape, same
// tx-abort blast-radius contract, same anti-pattern-21 sqlmock caveat
// covered by cve_sync_integration_test.go under the `integration` build
// tag. F258 is the FIRST write-heavy application of the pattern in this
// package — F234 / F244 are both read-only per-tenant eligibility
// enumerations, F258 is a per-(tenant, CVE) INSERT loop.
//
// Design rationale:
//
//	The pre-F258 implementation opened one per-tenant runWithTenantTx
//	for the match loop, costing ~ (3 + M) round-trips per tenant where
//	M is the number of NVD CVEs fetched this tick:
//	  BEGIN + SET LOCAL + M * (SELECT components + ON-CONFLICT INSERT
//	  component_vulnerabilities batch) + COMMIT.
//	At N=1000+ tenant scale that's N round-trips of connection pool
//	acquire/release, which competes with concurrent request-serving
//	tenant txs for the same pool budget.
//
//	F258 collapses the enumeration onto ONE pool lease per Run() tick,
//	and splits the SET LOCAL + per-CVE match loop across N/K chunked
//	transactions:
//
//	   - allTenants is split into chunks of cveMatchBatchChunkSize.
//	   - Each chunk gets its own BEGIN / per-tenant (SET LOCAL +
//	     per-CVE (SELECT + INSERT)) loop / COMMIT.
//	   - A PG-side error inside chunk C aborts C's tx and skips the
//	     remaining tenants of C (they retry on the next daily tick);
//	     the loop then opens a fresh tx for chunk C+1 and continues.
//	   - The pooled connection is held across chunks (no reacquire),
//	     so PG-side connection state (search_path, timezone, etc.)
//	     stays consistent and the pool sees exactly one lease per
//	     invocation.
//
// Round-trip accounting (N tenants, M CVEs per tenant, chunk_size K,
// num_chunks c=ceil(N/K)):
//
//	pre-F258 (per-tenant runWithTenantTx):
//	    1 (listAllIDs)
//	  + N * (BEGIN + SET LOCAL + M*(SELECT + INSERT batch) + COMMIT)
//	  = 1 + N*(3 + M)
//
//	F258 (chunked tx split):
//	    1 (listAllIDs)
//	  + c * (BEGIN + COMMIT)              = 2c
//	  + N * (SET LOCAL)                   = N
//	  + N * M * (SELECT + INSERT batch)   = N * M
//	  = 1 + 2c + N*(1 + M)
//
//	Reduction per tenant: 2 round-trips (BEGIN + COMMIT moved from
//	per-tenant to per-chunk). At M=50 that's ~4% of the per-tenant
//	round-trip budget — the real F258 wins are (a) one pool lease
//	instead of N, and (b) chunk-local blast-radius vs "per-tenant
//	poison isolation only" pre-F258.
//
//	Worked examples:
//	  N=100  M=50 K=200 c=1  -> 1 + 2*1  + 100*(1+50)  = 5103
//	                            pre-F258 = 1 + 100*53  = 5301   (∆ = -198)
//	  N=500  M=50 K=200 c=3  -> 1 + 2*3  + 500*(1+50)  = 25507
//	                            pre-F258 = 1 + 500*53  = 26501  (∆ = -994)
//	  N=1000 M=50 K=200 c=5  -> 1 + 2*5  + 1000*(1+50) = 51011
//	                            pre-F258 = 1 + 1000*53 = 53001  (∆ = -1990)
//
//	The chunk envelope cost (F258 vs a hypothetical single-tx path) is
//	exactly 2*(c-1) round-trips. Same shape as F234 / F244.
//
// Per-tenant error handling — F258 chunk-local blast radius:
//
//   - A per-(tenant, CVE) linkCVEToTenantComponents error means PG has
//     aborted the enclosing chunk's tx (e.g. RLS denial on the
//     components SELECT, statement timeout, connection blip, ON
//     CONFLICT constraint violation). The chunk is rolled back — every
//     component_vulnerabilities INSERT performed so far in this chunk
//     is thrown away. The remaining tenants of the chunk are skipped
//     for this tick (retried next daily tick), and the loop starts a
//     fresh BEGIN for the next chunk.
//   - A tenant whose components SELECT returns no matches for every CVE
//     is not an error — matched / newVulns stay 0 for that tenant and
//     the chunk continues.
//   - Go-side matched / newVulns totals accumulate ACROSS chunks; per
//     chunk they are added to the running totals only after the chunk
//     COMMITs successfully. On rollback, that chunk's contribution is
//     discarded so the reported totals match the durable INSERTs.
//
// Write-heavy blast-radius trade-off (load-bearing for operator docs):
//
//   - Pre-F258: a single poison tenant (RLS denial, statement timeout,
//     etc.) rolled back only that ONE tenant's INSERT batch. Other
//     tenants' matches were durable.
//   - Post-F258: a single poison tenant rolls back the entire enclosing
//     chunk's INSERT batches (up to K=200 tenants × M CVEs of INSERTs
//     are thrown away). The affected tenants retry on the next daily
//     tick and re-do the work.
//   - Rationale for accepting the larger blast radius: at production
//     N=1000+ scale the pool efficiency win (1 lease vs N leases per
//     tick) prevents pool-exhaustion cascades that would take out
//     ALL tenants' matches for MULTIPLE hourly ticks, which is a
//     worse operator-visible outcome than "one chunk of 200 tenants
//     retries next tick". K=200 (vs F234 / F244's K=500) intentionally
//     halves the write-heavy blast radius versus what the read-only
//     jobs use.
//   - Operator-facing note: monitor Warn-level "CVE match chunk aborted"
//     log lines with chunk_index for forensic tracing. A single warn
//     per Run() = one chunk rolled back; recurring warns for the same
//     chunk_index = a persistent poison tenant that needs investigation.
//
// Anti-pattern 21 (sqlmock semantics limitation, F234 heritage):
// sqlmock does NOT model the "current transaction is aborted, commands
// ignored until end of transaction block" semantics. The unit tests
// exercise happy-path plus the code-side error paths, but the ACID
// contract that a PG-side error inside chunk C aborts C's tx
// server-side and lets chunk C+1 continue on the same pooled connection
// with a fresh BEGIN is pinned by cve_sync_integration_test.go
// (build tag `integration`), following the same real-PG smoke pattern
// as F234 / F244's integration tests.
//
// Return values:
//   - matched: sum over all committed chunks of per-tenant CVEs that
//     linked to at least one component.
//   - newVulns: sum over all committed chunks of per-tenant CVEs where
//     the underlying vulnerabilities row was newly created this tick.
//   - err: non-nil ONLY when the whole enumeration cannot proceed
//     (e.g. j.db.Conn(ctx) fails). Per-chunk aborts are logged and
//     absorbed — the return err stays nil so the caller keeps the
//     partial-progress totals.
func (j *CVESyncJob) matchTenantsChunked(
	ctx context.Context,
	tenantIDs []uuid.UUID,
	cves []CVEInfo,
	vulnIndex map[string]cveVulnEntry,
) (matched, newVulns int, err error) {
	if len(tenantIDs) == 0 {
		return 0, 0, nil
	}

	conn, cErr := j.db.Conn(ctx)
	if cErr != nil {
		return 0, 0, fmt.Errorf("scheduler: acquire pooled conn for CVE match batch: %w", cErr)
	}
	defer conn.Close()

	chunkSize := cveMatchBatchChunkSize
	if chunkSize <= 0 {
		// Defensive: a mis-set test override should not divide by zero
		// or spin forever. Fall back to the production default.
		chunkSize = cveMatchBatchChunkSizeDefault
	}

	numChunks := (len(tenantIDs) + chunkSize - 1) / chunkSize

	for chunkIndex := 0; chunkIndex < numChunks; chunkIndex++ {
		start := chunkIndex * chunkSize
		end := start + chunkSize
		if end > len(tenantIDs) {
			end = len(tenantIDs)
		}
		chunk := tenantIDs[start:end]

		chunkMatched, chunkNewVulns, chunkErr := j.matchTenantsChunk(
			ctx, conn, chunkIndex, chunk, cves, vulnIndex,
		)
		// A chunk-level error is NOT fatal to the whole tick under F258 —
		// we log + move on so subsequent chunks still get evaluated.
		// matchTenantsChunk has already discarded any per-tenant counters
		// from the aborted chunk (returns 0, 0 on rollback).
		if chunkErr != nil {
			slog.Warn("scheduler: CVE match chunk aborted, continuing with next chunk (F258)",
				"chunk_index", chunkIndex,
				"chunk_size", len(chunk),
				"num_chunks", numChunks,
				"error", chunkErr,
			)
		}
		matched += chunkMatched
		newVulns += chunkNewVulns
	}

	return matched, newVulns, nil
}

// matchTenantsChunk runs one chunk's BEGIN / per-tenant (SET LOCAL +
// per-CVE linkCVEToTenantComponents) loop / COMMIT on the caller's pinned
// connection (F258, M17-3 #109).
//
// Contract mirrors F234's evaluateEligibilityChunk (vulnerability_scan.go)
// and F244's evaluateEnabledSettingsChunk (report_generation.go):
//
//   - Returns the (matched, newVulns) totals for `chunk`, respecting each
//     tenant's components under its own RLS context.
//
//   - Returns (0, 0, error) if a PG-side error aborts the chunk's tx
//     mid-loop. Because a write-heavy chunk rollback means the durable
//     INSERT count for THIS chunk is zero, we deliberately return
//     (0, 0) rather than partial counters — otherwise the caller's
//     aggregate would over-count matches whose backing INSERT rolled
//     back. This is the KEY difference from F234's read-only contract,
//     where partial counts survive rollback because no writes happened.
//
//   - SET LOCAL failure on one tenant is logged + terminates the chunk
//     with (0, 0, error) so the enclosing loop can start a fresh BEGIN
//     for the next chunk.
//
//   - Per-CVE linkCVEToTenantComponents errors terminate the chunk on
//     first error — see docstring note above for why we cannot cleanly
//     continue after the tx is aborted server-side.
func (j *CVESyncJob) matchTenantsChunk(
	ctx context.Context,
	conn *sql.Conn,
	chunkIndex int,
	chunk []uuid.UUID,
	cves []CVEInfo,
	vulnIndex map[string]cveVulnEntry,
) (matched, newVulns int, err error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("scheduler: begin chunk %d CVE match tx: %w", chunkIndex, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Bind the tx onto ctx so linkCVEToTenantComponents (which resolves
	// database.Querier(txCtx, ...) back to the tx) runs its SELECT +
	// INSERT inside the chunk's tx — see F185 GUC + tx-local scoping
	// discipline.
	txCtx := database.WithTx(ctx, tx)
	q := database.Querier(txCtx, j.db)

	// Per-chunk counters — only added to the (matched, newVulns) return
	// values on successful COMMIT. This mirrors the write-heavy contract
	// above: if the chunk rolls back, its INSERTs are discarded, so its
	// counters must also be discarded.
	chunkMatched := 0
	chunkNewVulns := 0

	for _, tenantID := range chunk {
		// F249-style fidelity note (F244 → F258 replication): use the
		// outer `ctx` here to keep the SET LOCAL call literally
		// identical to F234 vulnerability_scan.go and F244
		// report_generation.go. `tx.ExecContext` binds to the tx
		// receiver, not the ctx arg, so passing the outer `ctx` vs
		// `txCtx` is behaviourally equivalent; the txCtx wrap only
		// matters for downstream database.Querier(txCtx, ...) resolution
		// (`q` above). Using `ctx` here preserves line-by-line
		// replication fidelity with the sibling chunk helpers.
		if _, sErr := tx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); sErr != nil {
			slog.Warn("scheduler: failed to bind tenant GUC in chunked CVE match (F258)",
				"chunk_index", chunkIndex, "tenant_id", tenantID, "error", sErr)
			return 0, 0, fmt.Errorf("scheduler: chunk %d SET LOCAL failed for tenant %s: %w",
				chunkIndex, tenantID, sErr)
		}

		for _, cve := range cves {
			entry, ok := vulnIndex[cve.ID]
			if !ok {
				continue
			}

			linked, lerr := j.linkCVEToTenantComponents(txCtx, q, cve, entry.id)
			if lerr != nil {
				slog.Warn("scheduler: failed to link CVE for tenant in chunked CVE match (F258)",
					"chunk_index", chunkIndex,
					"tenant_id", tenantID,
					"cve_id", cve.ID,
					"error", lerr,
				)
				return 0, 0, fmt.Errorf("scheduler: chunk %d link CVE %s for tenant %s failed: %w",
					chunkIndex, cve.ID, tenantID, lerr)
			}
			if linked > 0 {
				chunkMatched++
				if entry.isNew {
					chunkNewVulns++
				}
				slog.Debug("matched CVE to components",
					"chunk_index", chunkIndex,
					"tenant_id", tenantID,
					"cve_id", cve.ID,
					"components_linked", linked,
					"is_new", entry.isNew,
				)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("scheduler: commit chunk %d CVE match tx: %w", chunkIndex, err)
	}
	committed = true
	return chunkMatched, chunkNewVulns, nil
}

// linkCVEToTenantComponents finds tenant-scoped components matching cve.Keywords
// and inserts component_vulnerabilities rows for them. Returns the number of
// link rows inserted (or already present, since ON CONFLICT DO NOTHING).
func (j *CVESyncJob) linkCVEToTenantComponents(
	ctx context.Context,
	q database.Queryable,
	cve CVEInfo,
	vulnID uuid.UUID,
) (int, error) {
	if len(cve.Keywords) == 0 {
		return 0, nil
	}

	query := `
		SELECT DISTINCT c.id
		FROM components c
		WHERE LOWER(c.name) = ANY($1)
		   OR LOWER(c.name) LIKE ANY($2)
	`

	exactMatches := cve.Keywords
	likePatterns := make([]string, len(cve.Keywords))
	for i, kw := range cve.Keywords {
		likePatterns[i] = "%" + kw + "%"
	}

	// pq.Array wraps the []string args in the pq array-marshalling driver
	// value — without this, database/sql rejects `[]string` at runtime
	// with "unsupported type []string, a slice of string" (both against
	// real PG via lib/pq and against sqlmock in the F258 perf test).
	rows, err := q.QueryContext(ctx, query, pq.Array(exactMatches), pq.Array(likePatterns))
	if err != nil {
		return 0, fmt.Errorf("query components: %w", err)
	}
	// F258 (M17-3 orchestrator recovery post-Phase A CI failure):
	// collect componentIDs into an in-memory slice BEFORE closing the
	// rows and issuing the INSERTs. lib/pq (`github.com/lib/pq`)
	// disallows an ExecContext on the same connection while a Rows is
	// still open — it emits `pq: unexpected Parse response 'C'` (the
	// Parse frame arrives while the driver is still expecting the
	// tail of a bind/execute cycle from the outer query) and then
	// invalidates the connection with `driver: bad connection`.
	// Pre-F258 the per-tenant runWithTenantTx pattern hid the bug: each
	// tenant grabbed a fresh conn, so the first (tenant, CVE) hit
	// failed silently and the loop moved on. Post-F258 the chunk pool
	// pins ONE conn across all N/K tenants, so the first bad-conn
	// cascades through every subsequent BEGIN in the chunk with
	// `sql: connection is already closed`. Collecting rows first
	// resolves it while preserving the original semantics (per-match
	// INSERT, ON CONFLICT DO NOTHING, warn-on-error, continue).
	componentIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var componentID uuid.UUID
		if err := rows.Scan(&componentID); err != nil {
			continue
		}
		componentIDs = append(componentIDs, componentID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate components: %w", err)
	}
	rows.Close()

	linkedCount := 0
	for _, componentID := range componentIDs {
		// component_vulnerabilities is not RLS-bound; this write still
		// goes through the tx (q is the tx) which is fine.
		if _, err := q.ExecContext(ctx, `
			INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (component_id, vulnerability_id) DO NOTHING
		`, componentID, vulnID); err != nil {
			slog.Warn("failed to link component to vulnerability",
				"component_id", componentID,
				"vuln_id", vulnID,
				"error", err)
			continue
		}
		linkedCount++
	}
	return linkedCount, nil
}

// upsertVulnerability creates or updates a vulnerability record
func (j *CVESyncJob) upsertVulnerability(ctx context.Context, cve CVEInfo) (uuid.UUID, bool, error) {
	var vulnID uuid.UUID
	var isNew bool

	// Check if vulnerability exists
	err := j.db.QueryRowContext(ctx,
		`SELECT id FROM vulnerabilities WHERE cve_id = $1`,
		cve.ID,
	).Scan(&vulnID)

	if err == sql.ErrNoRows {
		// Create new vulnerability
		vulnID = uuid.New()
		_, err = j.db.ExecContext(ctx, `
			INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score, source, published_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, 'NVD', $6, NOW())
		`, vulnID, cve.ID, cve.Description, cve.Severity, cve.CVSSScore, cve.PublishedAt)
		if err != nil {
			return uuid.Nil, false, err
		}
		isNew = true
	} else if err != nil {
		return uuid.Nil, false, err
	} else {
		// Update existing vulnerability
		_, err = j.db.ExecContext(ctx, `
			UPDATE vulnerabilities
			SET description = $1, severity = $2, cvss_score = $3, updated_at = NOW()
			WHERE id = $4
		`, cve.Description, cve.Severity, cve.CVSSScore, vulnID)
		if err != nil {
			return uuid.Nil, false, err
		}
	}

	return vulnID, isNew, nil
}

// getLastSyncTime returns the last CVE sync time
func (j *CVESyncJob) getLastSyncTime(ctx context.Context) (time.Time, error) {
	var lastSync time.Time
	err := j.db.QueryRowContext(ctx, `
		SELECT value::timestamptz FROM system_settings WHERE key = 'cve_sync_last_run'
	`).Scan(&lastSync)
	if err != nil {
		return time.Now().Add(-24 * time.Hour), err
	}
	return lastSync, nil
}

// updateLastSyncTime updates the last CVE sync time
func (j *CVESyncJob) updateLastSyncTime(ctx context.Context, t time.Time) error {
	_, err := j.db.ExecContext(ctx, `
		INSERT INTO system_settings (key, value, updated_at)
		VALUES ('cve_sync_last_run', $1::text, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $1::text, updated_at = NOW()
	`, t.Format(time.RFC3339))
	return err
}
