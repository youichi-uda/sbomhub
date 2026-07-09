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
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/advisory"
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
// tick instead of N leases.
//
// F264 (M17-3 Phase D R2 #109) + F266 (M17-3 Phase D Codex adjunct v2
// fix): the leading `+1` in both formulas is the listAllIDs SELECT
// issued by Run() itself (Run() calls tenantRepo.ListAllIDs before
// invoking matchTenantsChunked), NOT by matchTenantsChunked.
// matchTenantsChunked receives the pre-materialised tenant ID slice as
// a parameter and its own cost is exactly 2c + N*(1+M). Pool-lease
// scope: ListAllIDs runs via TenantRepository.ListAllIDs → r.db.QueryContext,
// which acquires an ephemeral pool connection (per-query lease), then
// matchTenantsChunked acquires its OWN pinned *sql.Conn for the chunked
// match phase. So the two phases use SEPARATE pool leases at the driver
// level, not one shared lease. F264's initial R2 wording conflated
// "composed at the Run() scope" (a formula-accounting convenience) with
// "single pool lease per Run() tick" (a driver-level claim that does
// not hold). F266 rewrites this section to keep the +1 attribution
// while removing the incorrect single-lease claim — the win of F258 is
// "one pinned lease across ALL chunks" (which stays true), not "one
// lease for the entire Run() tick". See the Round-trip accounting
// block on matchTenantsChunked for the per-chunk derivation.
//
// Tx-abort blast radius trade-off: pre-F258 a poison tenant rolled back
// only that ONE tenant's INSERT batch; post-F258 a poison tenant aborts
// the enclosing chunk's tx and rolls back up to chunk_size (default 200)
// tenants' INSERT batches for that tick (they retry on the next daily
// tick). This is intentional — see matchTenantsChunked's docstring for
// the full write-heavy blast-radius rationale. Horizontal replication of
// F234 (M15-2, vulnerability_scan.go, read-only) and F244 (M16-4,
// report_generation.go, read-only); F258 is the first write-heavy
// application of the pattern.
// advisoryExcerptUpserter is the narrow persistence contract M32 Wave A
// (P1) needs to ground the AI VEX triage LLM: it writes the NVD advisory
// description as an advisory_excerpts row during CVE→tenant linking so the
// M1-5 triage runner has real advisory text to draft against. Before M32
// the advisory.NVDParser was only exercised by unit tests — dead in prod,
// so every VEX draft was produced with zero advisory grounding.
//
// It is deliberately narrower than *repository.AdvisoryExcerptsRepository —
// exactly the two methods the match / OSV passes touch — so the loops can be
// unit-tested with a fake that records calls without a real
// advisory_excerpts table / RLS context. A nil value is treated as "excerpt
// grounding disabled" everywhere it is consulted (see
// upsertNVDAdvisoryExcerpt), so a not-yet-wired DI and the existing perf +
// integration test harnesses never panic.
//
// M43 Phase D R4 widened the contract with GetBySource: the OSV empty-write
// path reads the existing (tenant, cve, source='osv') row before writing, so
// a non-authoritative empty (no GO- record body behind it — true 404, alias
// 404, skeletal `{}`, non-Go record; M43 Phase D R6 authority rule) can
// never clobber an existing non-empty vuln_funcs row (the structural
// replacement for the R3 mass-404 suppression valve — see
// writeOSVVulnFuncsChunk). An AUTHORITATIVE empty (a retrieved GO- record
// body with zero symbols) overwrites the row so upstream retractions
// propagate, Warn-logged when that destroys a positive row.
type advisoryExcerptUpserter interface {
	Upsert(ctx context.Context, e *repository.AdvisoryExcerpt) error
	// GetBySource returns the single (tenant, cve, source) row, or (nil, nil)
	// when none exists — repository.AdvisoryExcerptsRepository's contract.
	// Reads issued with a database.WithTx ctx run on that tx (RLS GUC
	// visible), same F185 discipline as Upsert.
	GetBySource(ctx context.Context, tenantID uuid.UUID, cveID, source string) (*repository.AdvisoryExcerpt, error)
}

type CVESyncJob struct {
	db               *sql.DB
	tenantRepo       *repository.TenantRepository
	httpClient       *http.Client
	nvdAPIKey        string
	interval         time.Duration
	advisoryExcerpts advisoryExcerptUpserter
	// baseURL is the NVD REST base endpoint for the modified-CVE feed. It
	// defaults to cveSyncAPIURL but is overridable (M40 Wave B) from the same
	// orchestrator config value as NVDService.baseURL (cfg.NVDURL), so the
	// scheduled feed and on-demand scans share one override.
	baseURL string
	// offline short-circuits the scheduled feed when true (M40 Wave B
	// air-gapped degrade mode): Run() returns nil before any pagination/network.
	offline bool
	// osv (M43 Wave 3 / F467, #169) fetches OSV records so the post-match
	// vuln_funcs pass (syncOSVVulnFuncs) can persist Go vulndb structured
	// vulnerable symbols as advisory_excerpts source='osv' rows. Constructed
	// by NewCVESyncJob with the same offline flag as the NVD feed (offline
	// => every OSV fetch short-circuits with zero network access); the base
	// URL is overridable via WithOSVBaseURL (air-gapped mirror / httptest).
	osv *client.OSVClient
}

// NewCVESyncJob creates a new CVE sync job.
//
// tenantRepo is required to enumerate tenants for the per-tenant matching
// loop. Constructing without it would re-introduce the silent-no-op bug.
//
// advisoryExcerpts (M32 Wave A / P1) persists NVD advisory descriptions as
// advisory_excerpts rows during CVE→tenant linking so the AI VEX triage
// runner has real advisory grounding. It is appended last and is nil-safe:
// passing nil disables excerpt grounding (the CVE sync otherwise runs
// unchanged), which keeps existing callers/tests that don't wire it green.
//
// baseURL and offline (M40 Wave B) are appended last: baseURL overrides the
// cveSyncAPIURL default (empty => cveSyncAPIURL) and is wired from the same
// orchestrator value (cfg.NVDURL) as NVDService; offline makes Run() a no-op
// so the scheduled feed short-circuits before any network access.
//
// M43 Wave 3 (F467, #169): the job also constructs an OSV client (default
// base URL, same offline flag) for the post-match vuln_funcs pass. The
// signature is deliberately unchanged — the OSV base URL override
// (cfg.OSVURL) is carried by the chainable WithOSVBaseURL, mirroring
// NewCLIService(...).WithOSVBaseURL(cfg.OSVURL) at the main.go call site.
func NewCVESyncJob(db *sql.DB, tenantRepo *repository.TenantRepository, nvdAPIKey string, interval time.Duration, advisoryExcerpts advisoryExcerptUpserter, baseURL string, offline bool) *CVESyncJob {
	if baseURL == "" {
		baseURL = cveSyncAPIURL
	}
	return &CVESyncJob{
		db:               db,
		tenantRepo:       tenantRepo,
		httpClient:       &http.Client{Timeout: 60 * time.Second},
		nvdAPIKey:        nvdAPIKey,
		interval:         interval,
		advisoryExcerpts: advisoryExcerpts,
		baseURL:          baseURL,
		offline:          offline,
		osv:              client.NewOSVClient().WithOffline(offline),
	}
}

// WithOSVBaseURL overrides the OSV API base endpoint used by the M43 Wave 3
// vuln_funcs pass (air-gapped mirror / httptest injection). An empty value is
// a no-op (keeps client.DefaultOSVBaseURL), matching client.OSVClient's
// WithBaseURL and CLIService.WithOSVBaseURL semantics. Returns the receiver
// for chaining at the main.go wiring site.
func (j *CVESyncJob) WithOSVBaseURL(base string) *CVESyncJob {
	if j.osv != nil {
		j.osv.WithBaseURL(base)
	}
	return j
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
	if j.offline {
		slog.Info("sync skipped: offline mode", "source", "nvd")
		return nil
	}

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
		// M43 Phase D R2 finding 6: the OSV vuln_funcs backfill (Phase 3) is
		// independent of the NVD feed, so an NVD outage must not starve it.
		// Run it (best-effort, self-fenced) and THEN surface the NVD error.
		// The last-sync time is deliberately NOT advanced (unchanged early-
		// return contract), so the NVD window is retried in full next tick.
		slog.Warn("CVE sync: NVD fetch failed; running OSV vuln_funcs pass before returning", "error", err)
		if tenantIDs, terr := j.tenantRepo.ListAllIDs(ctx); terr != nil {
			slog.Warn("CVE sync: failed to list tenants for OSV pass after NVD failure", "error", terr)
		} else {
			j.syncOSVVulnFuncs(ctx, tenantIDs)
		}
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

	// Phase 3 (M43 Wave 3 / F467, #169): OSV / Go vulndb structured
	// vulnerable-symbol grounding. Best-effort and self-fenced: every
	// failure inside is logged and absorbed, never failing the sync tick.
	// Scoped to CVEs already linked to Go-ecosystem components (NOT the
	// full NVD feed) — see syncOSVVulnFuncs for the fetch-count bounds.
	j.syncOSVVulnFuncs(ctx, tenantIDs)

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

		req, err := http.NewRequestWithContext(ctx, "GET", j.baseURL+"?"+params.Encode(), nil)
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
// F264 (M17-3 Phase D R2 #109) attribution note: the leading `1
// (listAllIDs)` term in both pre-F258 and F258 formulas is the tenant
// enumeration SELECT issued by Run() at the caller site — it is NOT
// part of matchTenantsChunked's own cost. matchTenantsChunked's cost is
// exactly 2c + N*(1+M); the `+1` is added at the Run() scope so the
// formula composes end-to-end at the Run() tick level. See the
// type-level docstring on CVESyncJob for the same attribution.
//
//	pre-F258 (per-tenant runWithTenantTx):
//	    1 (listAllIDs, from Run())
//	  + N * (BEGIN + SET LOCAL + M*(SELECT + INSERT batch) + COMMIT)
//	  = 1 + N*(3 + M)
//
//	F258 (chunked tx split):
//	    1 (listAllIDs, from Run())
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

	// M32 Wave A (P1): advisory-excerpt candidates collected during the
	// link loop and persisted in ONE batched savepoint AFTER the loop (see
	// writeChunkAdvisoryExcerpts for the subxid-cache rationale). Appended
	// tenant-by-tenant (the outer loop is per-tenant), so same-tenant
	// candidates are contiguous — which lets the batch re-assert the tenant
	// GUC only on tenant boundaries.
	var excerptCandidates []excerptCandidate

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

				// M32 Wave A (P1): this CVE linked to at least one of THIS
				// tenant's components, so its NVD advisory description is a
				// grounding candidate for the AI VEX triage runner. Do NOT
				// write it inline (that would open one savepoint per CVE —
				// see writeChunkAdvisoryExcerpts). Collect it and persist the
				// whole chunk's excerpts under a SINGLE savepoint after the
				// loop. Only collect when an upserter is wired and there is
				// actual advisory text to ground on.
				if j.advisoryExcerpts != nil && strings.TrimSpace(cve.Description) != "" {
					excerptCandidates = append(excerptCandidates, excerptCandidate{
						tenantID: tenantID,
						cve:      cve,
					})
				}
			}
		}
	}

	// M32 Wave A (P1): persist all collected advisory excerpts under ONE
	// savepoint for the whole chunk, AFTER the core links are in the tx and
	// BEFORE COMMIT. Best-effort and self-fenced: a failure rolls back only
	// the excerpt batch, never the core CVE links (which precede the
	// savepoint), and never aborts the chunk.
	j.writeChunkAdvisoryExcerpts(txCtx, q, chunkIndex, excerptCandidates)

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

// excerptCandidate is one {tenant, CVE} pair collected during a chunk's link
// loop for deferred, batched advisory-excerpt persistence (M32 Wave A / P1).
type excerptCandidate struct {
	tenantID uuid.UUID
	cve      CVEInfo
}

const advisoryExcerptSavepoint = "sh_advisory_excerpt"

// writeChunkAdvisoryExcerpts persists all of a chunk's collected NVD advisory
// excerpts under ONE savepoint, so the AI VEX triage runner (M1-5) has real
// advisory grounding instead of drafting blind. It is called after the
// chunk's core link INSERTs are in the tx and before COMMIT.
//
// Why a SINGLE savepoint for the whole chunk (subxid-cache rationale): each
// SAVEPOINT opens a PostgreSQL subtransaction. PGPROC caps the per-top-xact
// subxid cache at PGPROC_MAX_CACHED_SUBXIDS=64, and RELEASE does NOT reclaim
// a slot — so a per-CVE savepoint would, on a first-sync of a many-CVE
// project, cross 64 subxids in a single chunk tx and mark the top xid
// "overflowed", forcing pg_subtrans (SubtransSLRU) lookups on every snapshot
// cluster-wide for the rest of the sync window. Batching bounds the chunk to
// exactly ONE subxid regardless of CVE count. (SET LOCAL and INSERT do not
// create subxids — only SAVEPOINT does.)
//
// Why it still can't regress core CVE sync (isolation preserved): the core
// component_vulnerabilities links were written BEFORE this savepoint. On
// PostgreSQL the first statement error aborts the whole tx, so an unguarded
// excerpt failure (this write carries RLS WITH CHECK — a real failure mode)
// would poison the chunk and roll back every core link. Instead, on ANY
// upsert error we ROLLBACK TO the single savepoint — restoring the tx to its
// exact pre-batch state — and abandon the rest of the batch. The core links
// survive and the chunk commits; abandoned excerpts are retried on the next
// sync (idempotent on the (tenant_id, cve_id, source) unique key).
//
// Best-effort throughout: a nil upserter, an empty candidate set, a
// savepoint/GUC failure, or an upsert error are all logged (slog) and
// swallowed. This never returns an error and never aborts the chunk.
func (j *CVESyncJob) writeChunkAdvisoryExcerpts(
	ctx context.Context,
	q database.Queryable,
	chunkIndex int,
	candidates []excerptCandidate,
) {
	if j.advisoryExcerpts == nil || len(candidates) == 0 {
		return
	}

	if _, err := q.ExecContext(ctx, "SAVEPOINT "+advisoryExcerptSavepoint); err != nil {
		// Could not open the savepoint — do NOT run any Upsert unguarded
		// (that could poison the chunk tx). Skip the whole batch; the core
		// links still commit.
		slog.Warn("scheduler: could not open advisory excerpt savepoint, grounding skipped for chunk (M32)",
			"chunk_index", chunkIndex, "error", err)
		return
	}

	var lastTenant uuid.UUID
	tenantBound := false
	for _, cand := range candidates {
		// Re-assert the tenant GUC on tenant boundaries: the link loop left
		// app.current_tenant_id set to the LAST tenant of the chunk, and
		// candidates may span multiple tenants, so each excerpt's RLS WITH
		// CHECK must run under its own tenant. Candidates are contiguous per
		// tenant (appended in the per-tenant outer loop), so this fires once
		// per tenant. set_config is not a subxid, so it does not affect the
		// single-savepoint bound.
		if !tenantBound || cand.tenantID != lastTenant {
			if _, err := q.ExecContext(ctx,
				`SELECT set_config('app.current_tenant_id', $1, true)`,
				cand.tenantID.String(),
			); err != nil {
				slog.Warn("scheduler: failed to re-bind tenant GUC for advisory excerpt batch, rolling back batch (M32)",
					"chunk_index", chunkIndex, "tenant_id", cand.tenantID, "error", err)
				j.rollbackExcerptSavepoint(ctx, q, chunkIndex)
				return
			}
			lastTenant = cand.tenantID
			tenantBound = true
		}

		excerpt, ok := j.buildNVDAdvisoryExcerpt(ctx, cand.tenantID, cand.cve)
		if !ok {
			// Nothing worth persisting for this candidate (parse error /
			// empty result) — skip it without disturbing the batch.
			continue
		}
		if err := j.advisoryExcerpts.Upsert(ctx, excerpt); err != nil {
			slog.Warn("scheduler: advisory excerpt upsert failed, rolling back excerpt batch; core CVE links preserved (M32 best-effort)",
				"chunk_index", chunkIndex, "tenant_id", cand.tenantID, "cve_id", cand.cve.ID, "error", err)
			// Restore the tx to its pre-batch clean state so the chunk's
			// COMMIT is not poisoned by the aborted Upsert, and abandon the
			// remaining candidates (retried idempotently next sync).
			j.rollbackExcerptSavepoint(ctx, q, chunkIndex)
			return
		}
	}

	// All excerpts persisted — release the single savepoint. A release
	// failure is benign (the savepoint is dropped at COMMIT anyway).
	if _, err := q.ExecContext(ctx, "RELEASE SAVEPOINT "+advisoryExcerptSavepoint); err != nil {
		slog.Warn("scheduler: failed to release advisory excerpt savepoint (benign) (M32)",
			"chunk_index", chunkIndex, "error", err)
	}
}

// rollbackExcerptSavepoint restores the chunk tx to its pre-excerpt-batch
// state. A ROLLBACK TO failure means the tx may be unusable — nothing more
// can be done safely here; the chunk's COMMIT will surface it. Logged loudly.
func (j *CVESyncJob) rollbackExcerptSavepoint(ctx context.Context, q database.Queryable, chunkIndex int) {
	if _, err := q.ExecContext(ctx, "ROLLBACK TO SAVEPOINT "+advisoryExcerptSavepoint); err != nil {
		slog.Error("scheduler: failed to roll back advisory excerpt savepoint, chunk tx may be unusable (M32)",
			"chunk_index", chunkIndex, "error", err)
	}
}

// buildNVDAdvisoryExcerpt parses cve.Description with the NVD advisory parser
// and maps the result to a persistable advisory_excerpts row (source "nvd").
// It returns (nil, false) when there is nothing worth persisting — an
// empty/whitespace description, a parse error, or an empty parse result — so
// the caller skips the write without emitting an empty-excerpt row.
//
// The parser is pure/deterministic and constructed inline. Note the TYPED
// payload: advisory.NVDParser.Parse routes a plain string through
// decodeNVDBytes (which json.Unmarshals and errors on free text), so we MUST
// hand it a *NVDCVEPayload.
func (j *CVESyncJob) buildNVDAdvisoryExcerpt(ctx context.Context, tenantID uuid.UUID, cve CVEInfo) (*repository.AdvisoryExcerpt, bool) {
	desc := strings.TrimSpace(cve.Description)
	if desc == "" {
		return nil, false
	}

	payload := &advisory.NVDCVEPayload{
		ID:           cve.ID,
		Descriptions: []advisory.NVDDescription{{Lang: "en", Value: desc}},
	}
	parsed, perr := (&advisory.NVDParser{}).Parse(ctx, payload)
	if perr != nil {
		slog.Warn("scheduler: advisory excerpt parse failed, grounding skipped (M32)",
			"cve_id", cve.ID, "tenant_id", tenantID, "error", perr)
		return nil, false
	}
	if parsed == nil || strings.TrimSpace(parsed.RawExcerpt) == "" {
		return nil, false
	}

	now := time.Now().UTC()
	return &repository.AdvisoryExcerpt{
		TenantID:       tenantID,
		CVEID:          cve.ID,
		Source:         string(advisory.SourceNVD),
		VulnFuncs:      stringsToJSONArray(parsed.VulnFuncs),
		AffectedPaths:  stringsToJSONArray(parsed.AffectedPaths),
		RequiredConfig: stringsToJSONArray(parsed.RequiredConfig),
		RequiredEnv:    stringsToJSONArray(parsed.RequiredEnv),
		RawExcerpt:     parsed.RawExcerpt,
		FetchedAt:      &now,
	}, true
}

// stringsToJSONArray marshals a []string into the json.RawMessage JSONB
// array shape advisory_excerpts expects. nil/empty maps to nil, which the
// repository's jsonbOrEmptyArray normalises to the column's '[]' default.
func stringsToJSONArray(in []string) json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	return b
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

// ============================================================================
// M43 Wave 3 (F467, issue #169): OSV / Go vulndb structured vulnerable
// symbols → advisory_excerpts.vuln_funcs (source 'osv', migration 056).
//
// Why: until M43 Wave 3 the ONLY vuln_funcs producer was the NVD prose
// heuristic (backtick-anchored regex in service/advisory), so production
// vuln_funcs were almost always empty and the M43 Wave 1 GET
// /reachability/targets enrichment had nothing to serve. Go vulndb publishes
// the same information STRUCTURED, as
// affected[].ecosystem_specific.imports[] = {path, symbols[]}, exposed
// through the OSV API. This pass converts those to the wire-safe
// "Pkg.Func" / "Pkg.Type.Method" selector form the Wave 1 edge
// (handler.normalizeVulnFuncs) forwards and the vendored Go analyzer
// (service/reachability/go_analyzer.go parseSymbolSelectors/matchSelector)
// actually matches against.
//
// Scope + fetch bounds (per daily Run() tick):
//   - Candidates = CVEs linked (component_vulnerabilities) to a component
//     whose purl is Go-ecosystem (repository.EcosystemFromPurl == "go"),
//     enumerated per tenant under RLS — i.e. exactly the CVE set that can
//     appear as Go reachability targets, INCLUDING the backlog linked by
//     earlier ticks (a "this tick's NVD feed only" scope would leave every
//     pre-existing production link empty forever).
//   - Freshness window: a (tenant, cve) whose source='osv' excerpt row was
//     fetched within osvVulnFuncsRefreshInterval is skipped, so steady-state
//     re-fetch load is ~ (distinct Go CVEs) / 7 per day. Definitive
//     negatives (OSV 404 / record with no extractable symbols) are written
//     as EMPTY-vuln_funcs tombstone rows (M43 Phase D R2 finding 1) so the
//     window is a real negative cache — without them, determined negatives
//     sat permanently at the front of the deterministic candidate order and,
//     combined with the fetch cap, starved every CVE sorted after them.
//     Tombstones are wire-inert: ListVulnFuncsByCVEs unions nothing out of
//     an empty array row.
//   - Each distinct CVE is fetched ONCE per tick (plus at most ONE Go vulndb
//     alias follow-up) and the result is fanned out to every tenant that
//     needs it — never re-fetched per tenant.
//   - osvVulnFuncsFetchCap hard-bounds HTTP requests per tick; CVEs beyond
//     the cap stay stale (no row, not even a tombstone) and are retried next
//     tick — the tombstones above are what let the freshness window actually
//     page the backlog through the cap tick over tick.
//   - offline=true short-circuits the whole pass with zero network access
//     (Run() returns before it; the guard here is defence-in-depth and the
//     OSV client itself is also constructed WithOffline).
//
// Failure posture: warn + skip at every level (chunk tx abort, fetch
// failure). TRANSIENT fetch failures (network error / non-404 status / ctx
// abort) write nothing and retry next tick; definitive negatives (404 / no
// symbols) ALWAYS write a tombstone row (M43 Phase D R4 — the R3 valve that
// suppressed tombstones on all-404 ticks re-introduced the R1 starvation for
// a legitimate all-404 backlog and was removed, Codex 42nd [High]). Four
// STRUCTURAL guards replace the valve's threat coverage:
//   - Record LINKAGE (M43 Phase D R7, round 6 High finding): a retrieved
//     body is accepted only when it vouches for the lookup — its own ID is
//     the requested id, or its aliases name the CVE (osvRecordLinked).
//     Unlinked bodies (e.g. one canned GO- record served for every path)
//     are rejected wholesale — symbols, excerpt, aliases, and clobber
//     authority all unused — with one osvUnlinkedRecordWarnMsg Warn, and
//     the CVE tombstones preserve-side;
//   - NON-AUTHORITATIVE empties (goID == "": true 404, alias 404, linked
//     non-GO body with no usable GO- alias, unlinked/skeletal body — M43
//     Phase D R6 authority rule + R7 linkage) never clobber an existing
//     non-empty vuln_funcs row — the write path preserves the row's data
//     wholesale and refreshes only fetched_at (writeOSVVulnFuncsChunk), so
//     neither a misconfigured mirror 404-ing every path nor a partial
//     mirror missing the Go vulndb side can empty previously-positive rows.
//     AUTHORITATIVE empties (goID != "": a retrieved LINKED GO- record body
//     with zero symbols) DO overwrite — an upstream retraction must
//     propagate (M43 Phase D R5/R6) — and destroying a positive row that
//     way emits one retraction Warn (post-COMMIT, M43 Phase D R7);
//   - an ANOMALOUS mass-404 tick (>= osvVulnFuncsMass404WarnThreshold
//     definitive 404s, zero record bodies retrieved — R6 predicate) writes
//     its tombstones with a BACKDATED fetched_at
//     (osvVulnFuncsAnomalyRetryInterval, M43 Phase D R5), so a repaired
//     mirror's blind spot is 2–3 days, not the full 7-day window;
//   - an offline-drifted client (client offline / job online, whose
//     short-circuit is byte-identical to a real 404) skips the whole pass
//     up front via OSVClient.IsOffline — no enumeration, no fetches, no
//     tombstones.
//
// A mass-404 tick (same predicate as the anomaly determination) additionally
// emits ONE observability Warn (no suppression), and a mass-SKELETAL tick —
// threshold-many record bodies retrieved with zero GO- identities and zero
// symbols, the shape the mass-404 predicate cannot see — emits one
// osvMassSkeletalWarnMsg Warn of its own (Warn-only, normal freshness; M43
// Phase D R7). The pass never returns an error and never disturbs the core
// CVE sync; abandoned work self-heals on the next tick via the freshness
// window and the (tenant_id, cve_id, source) idempotent upsert.
// ============================================================================

const (
	// osvVulnFuncsSource is the advisory_excerpts.source value for rows
	// produced by this pass (registry extended by migration 056).
	osvVulnFuncsSource = "osv"

	// osvVulnFuncsRefreshInterval is how long a source='osv' excerpt row is
	// considered fresh. Go vulndb entries do gain/adjust symbols after
	// publication, so rows are re-pulled weekly rather than write-once.
	osvVulnFuncsRefreshInterval = 7 * 24 * time.Hour

	// osvVulnFuncsFetchCapDefault bounds OSV HTTP requests per Run() tick
	// (main lookups + alias follow-ups combined). 500 covers typical
	// self-host deployments' full Go CVE surface in one tick while keeping
	// the worst-case tick duration (cap × (latency + delay)) in minutes.
	osvVulnFuncsFetchCapDefault = 500

	// osvVulnFuncsMaxSymbolsPerCVE caps how many selectors a single OSV
	// record may contribute to one vuln_funcs row (M43 Phase D R2 finding 2).
	// Real Go vulndb records carry a handful to a few dozen symbols; 200
	// leaves headroom while keeping a hostile/degenerate record from
	// ballooning the advisory_excerpts row and every downstream read
	// (ListVulnFuncsByCVEs → wire → CLI AST walk). Extraction truncates at
	// the cap (first-seen order preserved) with a slog.Warn.
	osvVulnFuncsMaxSymbolsPerCVE = 200

	// osvVulnFuncsMaxSelectorBytes caps one selector's byte length (M43
	// Phase D R2 finding 2). Legitimate "Pkg.Type.Method" selectors are tens
	// of bytes; anything past 256 is a crafted or corrupt symbol and is
	// dropped by osvWireSafeSelector like any other non-wire-safe shape.
	osvVulnFuncsMaxSelectorBytes = 256

	// osvExcerptMaxRunes caps the raw_excerpt grounding text persisted by
	// this pass (M43 Phase D R2 finding 2). The NVD path stores the advisory
	// description verbatim (typical NVD descriptions are well under 2000
	// chars and there is no NVD-side cap to inherit), and the triage runner
	// truncates excerpts to 600 chars at prompt-build time anyway — 2000
	// runes keeps full grounding fidelity for real records while bounding
	// hostile OSV summary/details blobs. Rune-based so multibyte (Japanese)
	// text is never cut mid-sequence.
	osvExcerptMaxRunes = 2000

	// osvVulnFuncsMass404WarnThreshold is the observability threshold for
	// the mass-404 anomaly Warn (M43 Phase D R4, replacing the R3 suppression
	// valve): when a tick's definitive-404 count ((nil, nil) from the client)
	// reaches this threshold while ZERO record bodies were retrieved, one
	// slog.Warn is emitted flagging a possible OSV mirror/endpoint anomaly
	// (e.g. a misconfigured air-gapped mirror 404-ing every path).
	// Observation-only: the R3 valve additionally SUPPRESSED the tick's
	// tombstones, but a zero-records tick is ALSO what a LEGITIMATE all-404
	// backlog looks like (the cap-sized head of the deterministic candidate
	// order genuinely absent from OSV), and for that case suppression meant
	// no tombstone was ever written — the same CVEs re-consumed the whole
	// fetch cap tick after tick and starved every CVE sorted after them
	// forever, re-introducing the R1 starvation the tombstones exist to fix
	// (Codex 42nd [High]). R4 therefore ALWAYS writes definitive-404
	// tombstones and covers the valve's original threats structurally
	// instead: the write path never lets a true 404 clobber an existing
	// non-empty vuln_funcs row (writeOSVVulnFuncsChunk), and an
	// offline-drifted client — whose short-circuit is byte-identical to a
	// real 404 — skips the pass entirely via OSVClient.IsOffline (see
	// syncOSVVulnFuncs). Since M43 Phase D R5 the same trigger also marks the
	// tick ANOMALOUS: its tombstones are written with a backdated fetched_at
	// (osvVulnFuncsAnomalyRetryInterval) so a repaired mirror is
	// negative-cached for 2–3 days instead of the full freshness window.
	//
	// Predicate history (M43 Phase D R6, round 5 Low finding 3): R4/R5
	// required notFound == fetches — a 100% not-found RATE — which one
	// transient failure in an otherwise all-404 tick defeated (499×404 +
	// 1×timeout → not anomalous → full 7-day negative cache). R6 keys on the
	// two counts that matter: notFound >= this threshold AND zero record
	// bodies retrieved, so transient failures no longer dilute the
	// denominator. Deliberate trade-off: if even ONE record body was
	// retrieved this tick, the mirror demonstrably serves records, so a
	// 404-heavy tick is judged a legitimate backlog (not anomalous) no
	// matter how many 404s surround it — the write path's clobber guard and
	// preserve semantics bound the damage of a mostly-broken-but-serving
	// mirror.
	osvVulnFuncsMass404WarnThreshold = 20

	// osvVulnFuncsAnomalyRetryInterval is the freshness margin subtracted
	// from an ANOMALOUS tick's tombstone fetched_at so those rows re-enter
	// the candidate set early (M43 Phase D R5). An anomalous tick is the
	// mass-404 Warn's own trigger — at least osvVulnFuncsMass404WarnThreshold
	// definitive 404s with zero record bodies retrieved (R6 predicate) —
	// which is the signature of a misconfigured mirror / endpoint outage as
	// much as of a legitimate all-404 backlog. R4 wrote those tombstones with
	// fetched_at = now, so a mirror repaired minutes after the bad tick still
	// left every affected CVE negative-cached for the full
	// osvVulnFuncsRefreshInterval (7 days) — a blind spot in which freshly
	// published symbols were invisible. R5 keeps writing the tombstones (the
	// R1 starvation fix is untouched: the NOT EXISTS freshness clause still
	// excludes them) but BACKDATES their fetched_at by
	// (osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval), so
	// they age out of the freshness window once this 48h margin elapses.
	// Effective retry horizon (M43 Phase D R6, round 5 Low finding 2 — the
	// old "~2 days" wording overstated the speed): the candidate query keeps
	// rows with fetched_at >= cutoff (INCLUSIVE), so at the +48h tick the
	// backdated stamp still compares fresh, and with write latency pushing
	// the stamp slightly later the first re-fetch on a 24h tick cadence lands
	// at the +72h tick — i.e. 2–3 days, the first daily tick after the 48h
	// margin. Normal ticks (any record retrieved, or fewer than the threshold
	// of 404s) are unaffected.
	osvVulnFuncsAnomalyRetryInterval = 48 * time.Hour
)

// osvMass404WarnMsg is the exact Warn message emitted when a tick reaches at
// least osvVulnFuncsMass404WarnThreshold definitive-404 lookups with zero
// record bodies retrieved (M43 Phase D R4 Warn, R6 predicate — transient
// failures no longer veto the determination) — a signal for a possible OSV
// mirror/endpoint anomaly. Unlike the R3 valve it replaces, it does NOT
// suppress the tick's tombstones: a legitimate all-404 backlog must enter the
// negative cache or the R1 starvation returns (Codex 42nd [High]). Since M43
// Phase D R5 the anomalous tick's tombstones are additionally written with
// SHORTENED freshness — fetched_at backdated so they re-candidate at the
// first daily tick after the osvVulnFuncsAnomalyRetryInterval margin (2–3
// days; see that const for the inclusive-comparison arithmetic) instead of
// the full refresh window — and the message says so. A const so the test
// contract pins operators' grep target verbatim.
const osvMass404WarnMsg = "scheduler: OSV lookups this tick reached the mass-404 threshold with zero records retrieved; possible OSV mirror/endpoint anomaly — tombstones still written but with shortened freshness (fetched_at backdated so affected CVEs retry in 2–3 days, at the first daily tick after the 48h margin, instead of the full 7-day window), existing non-empty rows preserved (M43 Phase D R5)"

// osvOfflineDriftSkipWarnMsg is the exact Warn emitted when the OSV client
// is offline while the CVE sync job itself is online (M43 Phase D R4): the
// client's offline short-circuit returns the same (nil, nil) as a real 404,
// so instead of letting the pass mass-tombstone the candidate set, the whole
// pass is skipped up front — no candidate enumeration, no fetches, no
// tombstones. A const so the test contract pins operators' grep target
// verbatim.
const osvOfflineDriftSkipWarnMsg = "scheduler: OSV client is offline but the CVE sync job is online; skipping OSV vuln_funcs pass (M43 Phase D R4 offline-drift guard)"

// osvTombstonePreserveInfoMsg is the exact Info line emitted when a
// NON-AUTHORITATIVE empty outcome (goID == "" — a true 404, an alias 404, a
// linked non-Go record with no usable GO- alias, or an UNLINKED body
// rejected wholesale by the R7 linkage rule, skeletal `{}` included; M43
// Phase D R6 widened the set from R5's true-404-only, R7 folded in the
// unlinked shapes) lands on an existing POSITIVE (non-empty vuln_funcs) row
// and the R4 clobber guard preserves it: OSV yielded nothing authoritative
// for a CVE whose stored row still carries symbols — a divergence operators
// may want to reconcile (authoritative withdrawals propagate ONLY via a
// linked GO- record body's empty overwrite, so a persistent divergence here
// means the stored symbols have no verifiable upstream source anymore).
// Emitted only after the chunk's COMMIT succeeds (M43 Phase D R7, round 6
// finding 2 — the line describes a write, so it must describe a durable
// one). A const so the test contract pins operators' grep target verbatim.
const osvTombstonePreserveInfoMsg = "scheduler: OSV yielded no authoritative Go vulndb record for a CVE whose stored row carries non-empty vuln_funcs; preserving row data, refreshing fetched_at only (M43 Phase D R5)"

// osvRetractionOverwriteWarnMsg is the exact Warn emitted when an
// AUTHORITATIVE-empty outcome — a retrieved Go vulndb record BODY
// ("GO-"-prefixed ID field) with zero extractable symbols, i.e. an upstream
// withdrawal/correction — overwrites a previously-POSITIVE (non-empty
// vuln_funcs) row (M43 Phase D R6, round 5 High finding). This is the ONE
// write shape that destroys stored symbols, so it must never happen silently:
// a mirror that starts serving degraded GO- bodies would otherwise wipe every
// positive row, one freshness window at a time, with nothing in the logs (the
// mass-404 Warn keys on 404s, not on degraded 200s). Deliberately scoped to
// actual positive-row overwrites — an authoritative empty landing on an
// already-empty or absent row (routine whole-module advisories without symbol
// lists re-tombstoning every window) stays silent, so the Warn keeps its
// mass-wipe signal instead of drowning in weekly refresh noise. Emitted only
// after the chunk's COMMIT succeeds (M43 Phase D R7, round 6 finding 2 — a
// rolled-back overwrite is a false wipe alarm). A const so the test contract
// pins operators' grep target verbatim.
const osvRetractionOverwriteWarnMsg = "scheduler: authoritative Go vulndb retraction is overwriting a previously-positive vuln_funcs row (GO- record body with zero symbols); if this fires en masse, verify the OSV mirror serves complete Go vulndb bodies (M43 Phase D R6)"

// osvUnlinkedRecordWarnMsg is the exact Warn emitted when a lookup RETRIEVES
// a record body that fails the R7 linkage rule (M43 Phase D R7, round 6 High
// finding): the body neither identifies as the id the lookup requested nor
// lists the CVE under determination among its aliases. Every real OSV
// response satisfies the rule (GET /vulns/{id} returns the record for that
// id, or an alias home that names it), so a failing body is crafted or
// mis-routed mirror output — e.g. one canned GO- record served for every
// path, which pre-R7 could either wipe positive rows via the
// authoritative-empty path (canned body without symbols) or inject one
// unrelated advisory's selectors into every tenant row (canned body WITH
// symbols). The record is rejected WHOLESALE — symbols unused, excerpt
// unused, aliases not followed, no clobber authority — and the CVE
// tombstones preserve-side. Attrs are cve_id / got_id / requested_id (the
// fetch stage has no tenant). A const so the test contract pins operators'
// grep target verbatim.
const osvUnlinkedRecordWarnMsg = "scheduler: OSV lookup returned a record body that neither identifies as the requested id nor lists the CVE among its aliases; rejecting the record wholesale (symbols and excerpt unused, no clobber authority) and tombstoning preserve-side — possible crafted or mis-routed OSV mirror response (M43 Phase D R7)"

// osvMassSkeletalWarnMsg is the exact Warn emitted when a tick's lookups
// both reach the mass threshold (osvVulnFuncsMass404WarnThreshold, shared
// with the mass-404 determination) in fetches AND in retrieved record
// bodies, yet not ONE outcome carries a Go vulndb identity (goID) or
// extractable symbols (M43 Phase D R7, round 6 finding 4). The mass-404
// predicate is blind to this shape: a stub mirror answering every path
// `200 {}` (or canned junk bodies) keeps notFound at 0 and recordsRetrieved
// climbing, so no anomaly fires even though the tick determined nothing.
// Warn-ONLY — deliberately NO anomalous fetched_at backdate — because the
// same counters describe a LEGITIMATE backlog of Go-ecosystem CVEs whose
// advisories are GHSA/CVE-home-only: a Go-ecosystem candidate with no GO-
// record in OSV is a normal, permanent state (the alias follow-up 404s, or
// there is no GO- alias at all), and backdating would re-spend the fetch cap
// on that backlog every 2–3 days forever. The R4 clobber guard and the R7
// linkage rule already bound the damage of the hostile reading. A const so
// the test contract pins operators' grep target verbatim.
const osvMassSkeletalWarnMsg = "scheduler: OSV lookups this tick retrieved record bodies at the mass threshold yet yielded zero Go vulndb identities and zero symbols; possible stub/skeletal mirror serving empty or canned bodies — tombstones written with NORMAL freshness (a legitimate GHSA-home-only backlog looks identical, so no backdated retry) (M43 Phase D R7)"

// osvVulnFuncsFetchCap is the effective per-tick fetch cap. Production
// always uses the default; tests may temporarily override (defer-restore)
// to exercise the cap path with small fixtures — same pattern as
// cveMatchBatchChunkSize.
var osvVulnFuncsFetchCap = osvVulnFuncsFetchCapDefault

// osvVulnFuncsFetchDelay is a politeness pause between consecutive OSV
// lookups (osv.dev is unauthenticated; the daily tick is latency-tolerant).
// Tests set it to 0 (defer-restore) so httptest loops stay instant.
var osvVulnFuncsFetchDelay = 100 * time.Millisecond

// osvGoCVECandidateQuery enumerates, for ONE tenant (RLS-scoped via the
// chunk tx's app.current_tenant_id GUC — components is FORCE RLS), the
// distinct (cve_id, purl) pairs of that tenant's component-linked CVEs whose
// component looks Go-ecosystem, excluding pairs whose source='osv' excerpt
// row is still fresh. The purl is re-checked Go-side with
// repository.EcosystemFromPurl so the authoritative ecosystem derivation
// stays in one place (the ILIKE is only a row-transfer prefilter, matching
// the vulnerability.go comment about not trusting purl LIKEs in SQL).
// $1 = tenant id — used BOTH as an explicit c.tenant_id predicate (M43
// Phase D R2 finding 5: the repo layer's belt+braces discipline, so the
// query stays tenant-correct even if the RLS GUC binding ever regresses)
// AND in the advisory_excerpts NOT EXISTS,
// $2 = freshness cutoff (rows with fetched_at >= $2 are fresh; NULL
// fetched_at compares as unknown => NOT EXISTS => stale => re-fetched).
const osvGoCVECandidateQuery = `
	SELECT DISTINCT v.cve_id, COALESCE(c.purl, '')
	FROM components c
	JOIN component_vulnerabilities cv ON cv.component_id = c.id
	JOIN vulnerabilities v ON v.id = cv.vulnerability_id
	WHERE c.tenant_id = $1
	  AND c.purl ILIKE 'pkg:golang%'
	  AND NOT EXISTS (
		SELECT 1 FROM advisory_excerpts ae
		WHERE ae.tenant_id = $1
		  AND ae.cve_id = v.cve_id
		  AND ae.source = 'osv'
		  AND ae.fetched_at >= $2
	  )
	ORDER BY v.cve_id
`

// osvTenantCandidates is one tenant's ordered list of CVE ids needing a
// (fresh) source='osv' excerpt row.
type osvTenantCandidates struct {
	tenantID uuid.UUID
	cveIDs   []string
}

// osvVulnFuncsOutcome is the per-CVE fetch result fanned out to every tenant
// that listed the CVE: the wire-safe selector list plus the OSV summary /
// details text persisted as raw_excerpt grounding.
//
// M43 Phase D R2 finding 1 — tombstone semantics: presence in the outcomes
// map means the CVE reached a DEFINITIVE determination this tick. An entry
// with empty symbols is a negative tombstone (OSV 404 / record with no
// extractable symbols): it is still written as an empty-vuln_funcs 'osv'
// row so its fetched_at enters the freshness window and the CVE leaves the
// candidate set for osvVulnFuncsRefreshInterval. Without that, determined
// negatives sat permanently at the front of the deterministic candidate
// order and — combined with osvVulnFuncsFetchCap — starved every CVE behind
// them forever. Transient failures (network error / non-404 HTTP status /
// ctx abort) produce NO map entry: no tombstone, retried next tick.
type osvVulnFuncsOutcome struct {
	symbols []string
	// scoped is the module-attributed companion of symbols (M43 Phase D
	// round 8 / R8f, migration 057): the same extraction pass that built
	// the flat union attributes each selector to the OSV affected module
	// it was declared under, so the serving edge can hand each component
	// target only its own module's symbols. Empty exactly when symbols is
	// empty (both come from the one extractOSVGoVulnFuncs call), so
	// tombstones and authoritative empties naturally store '[]' for both.
	scoped  []osvScopedVulnFuncs
	excerpt string
	// goID (M43 Phase D R6, narrowing R5's recordFound bool — round 5 High
	// finding) is the clobber-authority token for empty outcomes: the ID of
	// the Go vulndb record BODY this determination came from, set exactly
	// when a retrieved record's own ID field carries the "GO-" prefix (main
	// lookup or alias follow-up) AND the body passed the R7 linkage rule
	// (osvRecordLinked — it identifies as the requested id or aliases the
	// CVE; round 6 High finding: without linkage, one canned GO- record
	// served for every path either wiped positive rows via authoritative
	// emptiness or injected its symbols into every tenant row), "" otherwise.
	// R5's recordFound stood up whenever the MAIN lookup returned ANY
	// non-nil record, which promoted three non-authoritative shapes to
	// authoritative empties: (a) a GHSA/CVE home record whose GO- alias
	// fetch 404s (partial mirror), (b) a skeletal `200 {}` body (ID empty),
	// (c) a non-Go record with no GO- alias at all — each could silently
	// wipe existing positive rows every freshness window. R6 keys the
	// authority on the GO- record body itself, splitting the
	// DEFINITIVE-negative shapes as:
	//   - symbols empty, goID != "": an AUTHORITATIVE empty — a linked Go
	//     vulndb body was retrieved and yields no extractable symbols
	//     (upstream withdrew or corrected the advisory's symbol list). The
	//     write path propagates it: the row is overwritten wholesale (empty
	//     vuln_funcs plus the record's excerpt), and overwriting a
	//     previously-positive row emits osvRetractionOverwriteWarnMsg.
	//   - symbols empty, goID == "": a PRESERVE-side tombstone (true 404,
	//     alias 404, linked non-Go record without a usable GO- alias, or an
	//     UNLINKED body rejected wholesale by R7 — skeletal `{}` included).
	//     The write path treats it exactly like a true 404: it must never
	//     clobber an existing positive row — the row's data is preserved and
	//     only fetched_at refreshes (the R4 clobber guard).
	// Positive outcomes (symbols non-empty) replace the row unconditionally
	// either way; their goID is informational only. Since R7 a positive can
	// only come from a LINKED body — unlinked symbols are never extracted.
	goID string
}

// syncOSVVulnFuncs is the Phase 3 entry point (see the section header above
// for scope/bounds/failure posture). tenantIDs is the same slice Run()
// already enumerated for the match phase.
func (j *CVESyncJob) syncOSVVulnFuncs(ctx context.Context, tenantIDs []uuid.UUID) {
	if j.advisoryExcerpts == nil || j.osv == nil || j.offline {
		return
	}
	// M43 Phase D R4 offline-drift guard (replacing the R3 valve's drift
	// role): a client flipped offline under an online job short-circuits
	// every lookup to (nil, nil) — byte-identical to a definitive 404 — so
	// running the pass would tombstone the entire candidate set. Skip it
	// wholesale: no candidate enumeration, no fetches, no tombstones.
	// Ordered AFTER the j.offline guard above so a coherently-offline job
	// (which constructs its client WithOffline(offline)) stays silent.
	if j.osv.IsOffline() {
		slog.Warn(osvOfflineDriftSkipWarnMsg)
		return
	}
	if j.db == nil || len(tenantIDs) == 0 {
		return
	}
	start := time.Now()

	// Pass A (read-only, chunked, one pooled conn): per-tenant candidate
	// enumeration under RLS. No network happens while any tx is open.
	candidates := j.listOSVCandidates(ctx, tenantIDs)
	if len(candidates) == 0 {
		slog.Debug("OSV vuln_funcs sync: no stale Go-ecosystem CVE candidates (M43 F467)")
		return
	}

	// Dedupe CVE ids across tenants preserving first-seen order: each CVE is
	// fetched exactly once and fanned out per tenant below.
	var orderedCVEs []string
	seen := make(map[string]struct{})
	for _, cand := range candidates {
		for _, id := range cand.cveIDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			orderedCVEs = append(orderedCVEs, id)
		}
	}

	// Network phase: one lookup per distinct CVE (+ ≤1 alias follow-up),
	// hard-capped per tick. anomalousTick (M43 Phase D R5) reports the
	// mass-404 anomaly determination so the write pass can backdate the
	// tick's tombstone fetched_at (shortened negative cache, see
	// osvVulnFuncsAnomalyRetryInterval).
	outcomes, anomalousTick := j.fetchOSVVulnFuncs(ctx, orderedCVEs)

	// Pass B (write, chunked, one pooled conn): fan the per-CVE outcomes out
	// to per-(tenant, cve) source='osv' excerpt rows. Definitive negatives
	// (404 / no symbols) are written as empty-vuln_funcs tombstone rows so
	// the freshness window negative-caches them (M43 Phase D R2 finding 1);
	// undetermined CVEs (transient failure / fetch cap) get no row.
	rowsUpserted, tenantsWritten := j.writeOSVVulnFuncs(ctx, candidates, outcomes, anomalousTick)

	withSymbols, tombstones := 0, 0
	for _, o := range outcomes {
		if len(o.symbols) > 0 {
			withSymbols++
		} else {
			tombstones++
		}
	}
	slog.Info("OSV vuln_funcs sync completed (M43 F467)",
		"tenants_scanned", len(tenantIDs),
		"candidate_cves", len(orderedCVEs),
		"cves_with_symbols", withSymbols,
		"cves_tombstoned", tombstones,
		"rows_upserted", rowsUpserted,
		"tenants_written", tenantsWritten,
		"duration_ms", time.Since(start).Milliseconds(),
	)
}

// listOSVCandidates runs Pass A across every tenant: same pooled-connection
// + chunked-tx shape as matchTenantsChunked (F258 heritage), but read-only —
// so, mirroring F234's read-only contract, tenants already enumerated before
// a chunk abort keep their results and the loop continues with the next
// chunk. Returns tenants in input order, each with its sorted CVE id list.
func (j *CVESyncJob) listOSVCandidates(ctx context.Context, tenantIDs []uuid.UUID) []osvTenantCandidates {
	conn, err := j.db.Conn(ctx)
	if err != nil {
		slog.Warn("scheduler: acquire pooled conn for OSV candidate enumeration failed (M43 F467)", "error", err)
		return nil
	}
	defer conn.Close()

	chunkSize := cveMatchBatchChunkSize
	if chunkSize <= 0 {
		chunkSize = cveMatchBatchChunkSizeDefault
	}
	numChunks := (len(tenantIDs) + chunkSize - 1) / chunkSize
	cutoff := time.Now().UTC().Add(-osvVulnFuncsRefreshInterval)

	var out []osvTenantCandidates
	for chunkIndex := 0; chunkIndex < numChunks; chunkIndex++ {
		start := chunkIndex * chunkSize
		end := start + chunkSize
		if end > len(tenantIDs) {
			end = len(tenantIDs)
		}
		chunkOut, chunkErr := j.listOSVCandidatesChunk(ctx, conn, chunkIndex, tenantIDs[start:end], cutoff)
		out = append(out, chunkOut...)
		if chunkErr != nil {
			slog.Warn("scheduler: OSV candidate chunk aborted, continuing with next chunk (M43 F467)",
				"chunk_index", chunkIndex, "num_chunks", numChunks, "error", chunkErr)
		}
	}
	return out
}

// listOSVCandidatesChunk enumerates one chunk's tenants inside one tx
// (SET LOCAL tenant GUC per tenant, then the candidate SELECT). Read-only:
// tenants read before an error are returned alongside the error (F234
// partial-count contract). Rows are fully drained and closed before the next
// tenant's set_config Exec — same lib/pq open-Rows discipline as
// linkCVEToTenantComponents.
func (j *CVESyncJob) listOSVCandidatesChunk(
	ctx context.Context,
	conn *sql.Conn,
	chunkIndex int,
	chunk []uuid.UUID,
	cutoff time.Time,
) ([]osvTenantCandidates, error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("scheduler: begin chunk %d OSV candidate tx: %w", chunkIndex, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var out []osvTenantCandidates
	for _, tenantID := range chunk {
		if _, sErr := tx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); sErr != nil {
			return out, fmt.Errorf("scheduler: chunk %d OSV candidate SET LOCAL failed for tenant %s: %w",
				chunkIndex, tenantID, sErr)
		}

		rows, qErr := tx.QueryContext(ctx, osvGoCVECandidateQuery, tenantID, cutoff)
		if qErr != nil {
			return out, fmt.Errorf("scheduler: chunk %d OSV candidate query failed for tenant %s: %w",
				chunkIndex, tenantID, qErr)
		}
		// Drain fully before the next round-trip on this pinned conn.
		type cvePurl struct{ cveID, purl string }
		pairs := make([]cvePurl, 0)
		for rows.Next() {
			var p cvePurl
			if sErr := rows.Scan(&p.cveID, &p.purl); sErr != nil {
				continue
			}
			pairs = append(pairs, p)
		}
		if iErr := rows.Err(); iErr != nil {
			rows.Close()
			return out, fmt.Errorf("scheduler: chunk %d OSV candidate rows failed for tenant %s: %w",
				chunkIndex, tenantID, iErr)
		}
		rows.Close()

		// Go-side authoritative ecosystem check + per-tenant CVE dedupe
		// (a CVE can hit several Go purls; the SELECT is DISTINCT on the
		// pair, not the CVE).
		var cveIDs []string
		seenCVE := make(map[string]struct{}, len(pairs))
		for _, p := range pairs {
			if repository.EcosystemFromPurl(p.purl) != "go" {
				continue
			}
			if _, dup := seenCVE[p.cveID]; dup {
				continue
			}
			seenCVE[p.cveID] = struct{}{}
			cveIDs = append(cveIDs, p.cveID)
		}
		if len(cveIDs) > 0 {
			out = append(out, osvTenantCandidates{tenantID: tenantID, cveIDs: cveIDs})
		}
	}

	if cErr := tx.Commit(); cErr != nil {
		return out, fmt.Errorf("scheduler: commit chunk %d OSV candidate tx: %w", chunkIndex, cErr)
	}
	committed = true
	return out, nil
}

// fetchOSVVulnFuncs resolves each candidate CVE against the OSV API exactly
// once and extracts Go vulndb vulnerable symbols in wire-safe selector form.
//
// CVE→OSV resolution: GET /v1/vulns/{id} accepts a CVE id directly (osv.dev
// resolves aliases server-side; this is the same contract
// service/remediation.go has relied on in production since M14). When the
// returned record is NOT the Go vulndb entry (e.g. a GHSA/CVE record with no
// Go ecosystem_specific.imports), ONE follow-up lookup of the first "GO-"
// alias is attempted.
//
// Record LINKAGE (M43 Phase D R7, round 6 High finding): every retrieved
// body must vouch for the lookup that produced it before ANY field is used —
// its own ID is the requested id (the CVE on the main lookup, the GO- alias
// on the follow-up), or its aliases name the CVE under determination
// (osvRecordLinked). An unlinked body is rejected wholesale (symbols /
// excerpt / aliases / clobber authority all unused) with one
// osvUnlinkedRecordWarnMsg Warn, and the CVE tombstones preserve-side.
//
// Outcome classification (M43 Phase D R2 finding 1; R5 split the negative
// shape; R6 re-keyed the split on the GO- record BODY; R7 gated everything
// on linkage — see osvVulnFuncsOutcome.goID):
//   - DEFINITIVE positive — symbols extracted from a LINKED body: outcome
//     with symbols. Replaces the row unconditionally.
//   - DEFINITIVE negative, AUTHORITATIVE empty — a LINKED record whose own
//     ID field is "GO-"-prefixed (main lookup or alias follow-up) was
//     retrieved and yields no symbols: outcome with EMPTY symbols and goID
//     set. The write path propagates it as an upstream retraction,
//     overwriting the row wholesale (and Warn-ing when that destroys a
//     positive row).
//   - DEFINITIVE negative, PRESERVE-side — no linked GO- record body was
//     retrieved: a true 404 (main lookup nil, nil), a GO- alias follow-up
//     that 404s (partial mirror), a linked non-Go body with no usable GO-
//     alias, or an UNLINKED body rejected by R7 (skeletal `200 {}` and
//     canned/mis-routed records). Outcome with EMPTY symbols and goID == "".
//     A tombstone, persisted so the freshness window negative-caches the CVE
//     instead of starving the fetch cap every tick; the write path's clobber
//     guard preserves any existing positive row. (R5 classified the
//     alias-404 / skeletal / no-alias shapes as authoritative — the round 5
//     High finding: partial mirrors silently wiped positive rows.)
//   - UNDETERMINED — transient fetch failure (network error / non-404 HTTP
//     status / ctx abort) or an alias follow-up skipped by the fetch cap: NO
//     outcome. Nothing is written; the CVE stays stale and retries next tick.
//
// Mass-404 observability Warn (M43 Phase D R4, replacing the R3 suppression
// valve; R6 predicate): if the tick accumulated at least
// osvVulnFuncsMass404WarnThreshold definitive 404s while retrieving ZERO
// record bodies, one slog.Warn flags a possible mirror/endpoint anomaly —
// but the tombstones are NOT suppressed (suppression re-introduced the R1
// starvation for legitimate all-404 backlogs; see the threshold const for
// the full rationale, the R6 predicate trade-off, and the structural guards
// that cover the valve's original threats). A mass-SKELETAL tick — at least
// the same threshold of fetches AND retrieved bodies with zero GO-
// identities and zero symbols, the determined-nothing shape the mass-404
// predicate cannot see — additionally draws one osvMassSkeletalWarnMsg Warn
// (Warn-only, normal freshness; M43 Phase D R7, round 6 finding 4).
//
// Bounds: ≤ osvVulnFuncsFetchCap total HTTP requests per call (main +
// follow-ups combined), osvVulnFuncsFetchDelay ctx-aware politeness pause
// between requests (finding 6: a cancelled ctx aborts the pause immediately
// instead of blocking shutdown), ctx cancellation checked per CVE. CVEs left
// beyond the cap stay stale (no row written) and are retried next tick — and
// because determined negatives now leave the candidate set via tombstones,
// the freshness window genuinely pages the backlog through the cap.
//
// The second return value, anomalousTick (M43 Phase D R5), is true exactly
// when the mass-404 Warn fired: at least osvVulnFuncsMass404WarnThreshold
// definitive 404s with zero record bodies retrieved (R6 predicate). The
// write pass uses it to backdate the tick's tombstone fetched_at (see
// osvVulnFuncsAnomalyRetryInterval) so a mirror misconfiguration is
// negative-cached for 2–3 days instead of the full freshness window.
func (j *CVESyncJob) fetchOSVVulnFuncs(ctx context.Context, cveIDs []string) (map[string]osvVulnFuncsOutcome, bool) {
	out := make(map[string]osvVulnFuncsOutcome, len(cveIDs))
	// Defence-in-depth (mirrors syncOSVVulnFuncs' guards): neither an
	// offline job nor an offline-drifted CLIENT (M43 Phase D R4 — its
	// short-circuit returns the same (nil, nil) as a real 404) may ever be
	// classified as a definitive 404 tombstone, no matter who calls this
	// loop directly.
	if j.offline || j.osv == nil || j.osv.IsOffline() {
		return out, false
	}
	fetchCap := osvVulnFuncsFetchCap
	if fetchCap <= 0 {
		fetchCap = osvVulnFuncsFetchCapDefault
	}
	fetches := 0
	// notFound counts lookups that returned (nil, nil) — a definitive 404 —
	// and recordsRetrieved counts lookups that returned a record body (M43
	// Phase D R6). Together they feed the mass-404 anomaly determination
	// below; transient failures increment neither, so they cannot dilute it.
	// (An offline-drifted client used to be the other (nil, nil) producer;
	// since M43 Phase D R4 it can no longer reach this loop — IsOffline is
	// guarded at both entry points.)
	notFound := 0
	recordsRetrieved := 0
	// symbolsSeen / goIDsSeen count DEFINITIVE outcomes carrying extracted
	// symbols / a GO- record-body identity this tick (M43 Phase D R7, round 6
	// finding 4): together with fetches and recordsRetrieved they feed the
	// mass-skeletal determination below — a tick that retrieves plenty of
	// bodies yet determines nothing is the stub-mirror signature the mass-404
	// predicate cannot see (notFound stays 0).
	symbolsSeen := 0
	goIDsSeen := 0

	// fetch performs one capped, delayed lookup. ok=false marks a TRANSIENT
	// failure (network/5xx/timeout/ctx abort — logged): the caller must NOT
	// tombstone. (nil, true) is a definitive 404.
	fetch := func(id string) (*client.OSVVulnerability, bool) {
		if fetches > 0 && osvVulnFuncsFetchDelay > 0 {
			select {
			case <-ctx.Done():
				return nil, false
			case <-time.After(osvVulnFuncsFetchDelay):
			}
		}
		fetches++
		v, err := j.osv.GetVulnerability(ctx, id)
		if err != nil {
			slog.Warn("scheduler: OSV lookup failed, skipping without tombstone (M43 F467)", "id", id, "error", err)
			return nil, false
		}
		if v == nil {
			notFound++
		} else {
			recordsRetrieved++
		}
		return v, true
	}

	for _, cveID := range cveIDs {
		if ctx.Err() != nil {
			slog.Warn("scheduler: OSV vuln_funcs fetch cancelled (M43 F467)", "error", ctx.Err())
			break
		}
		if fetches >= fetchCap {
			slog.Info("scheduler: OSV vuln_funcs fetch cap reached; remaining CVEs deferred to next sync (M43 F467)",
				"cap", fetchCap, "resolved", len(out))
			break
		}

		vuln, ok := fetch(cveID)
		if !ok {
			continue // transient failure — no tombstone, retry next tick
		}
		if vuln == nil {
			// Definitive: OSV has no record for this CVE — a TRUE 404.
			// Tombstone it (goID == "", M43 Phase D R6) so the freshness
			// window stops re-spending fetch budget on it; the write path's
			// clobber guard keys on the empty goID to preserve any existing
			// positive row.
			out[cveID] = osvVulnFuncsOutcome{}
			continue
		}
		// Record linkage verification (M43 Phase D R7, round 6 High finding):
		// the GO- prefix check below trusts the BODY to identify itself, but
		// nothing before R7 tied the body to the CVE the lookup asked about.
		// A crafted or mis-routed mirror answering every /vulns/{cve} path
		// with ONE canned GO- record could therefore (a) wipe positive rows
		// tick over tick via the authoritative-empty path when the canned
		// body carries no symbols, or (b) inject one unrelated advisory's
		// selectors into every tenant row when it does. Accept the body only
		// when it vouches for the request — its own ID is the requested CVE
		// id, or its aliases name the CVE. Anything else is rejected
		// WHOLESALE: symbols unused, excerpt unused, aliases not followed
		// (an unlinked record's alias list is equally untrusted), no clobber
		// authority. The CVE still reaches a definitive outcome — a
		// PRESERVE-side empty tombstone (goID == "", so the write path's
		// clobber guard keeps existing positive rows) — with one operator
		// Warn per rejected lookup.
		if !osvRecordLinked(vuln, cveID, cveID) {
			slog.Warn(osvUnlinkedRecordWarnMsg,
				"cve_id", cveID, "got_id", vuln.ID, "requested_id", cveID)
			out[cveID] = osvVulnFuncsOutcome{}
			continue
		}
		symbols, scoped := extractOSVGoVulnFuncs(vuln)
		excerpt := osvExcerptText(vuln)
		// goID is the clobber-authority token (M43 Phase D R6): set exactly
		// when a retrieved record BODY identifies itself as a Go vulndb
		// record via its own "GO-"-prefixed ID field. Only such a body may
		// authorise an empty-symbols outcome to overwrite positive rows.
		// Since R7 the body must additionally have passed the linkage check
		// above (or the follow-up's below) before its ID is consulted.
		goID := ""
		if strings.HasPrefix(vuln.ID, "GO-") {
			goID = vuln.ID
		}

		// Alias follow-up: the alias-resolved record may be a GHSA/CVE home
		// without Go vulndb's imports[]. One extra lookup of the first GO-
		// alias, still under the cap.
		if len(symbols) == 0 && goID == "" {
			if alias := firstGoVulndbAlias(vuln.Aliases); alias != "" {
				if fetches >= fetchCap {
					// The cap blocked the follow-up, so the determination is
					// incomplete — no tombstone; the CVE retries next tick.
					continue
				}
				av, aok := fetch(alias)
				if !aok {
					continue // transient alias failure — no tombstone
				}
				switch {
				case av == nil:
					// Alias 404 — see the fall-through comment below.
				case !osvRecordLinked(av, alias, cveID):
					// M43 Phase D R7 linkage on the follow-up: the body is
					// neither the record the alias promised (its ID differs
					// from the requested GO- id) nor an alias home naming
					// the CVE — canned junk or a skeletal `{}` under the
					// GO- path. Reject it wholesale like an unlinked main
					// record; only the follow-up body is rejected, so the
					// accepted MAIN record's excerpt is kept and the empty
					// outcome below stays preserve-side (goID == "").
					slog.Warn(osvUnlinkedRecordWarnMsg,
						"cve_id", cveID, "got_id", av.ID, "requested_id", alias)
				default:
					symbols, scoped = extractOSVGoVulnFuncs(av)
					if len(symbols) > 0 {
						if e := osvExcerptText(av); e != "" {
							excerpt = e
						}
					}
					if strings.HasPrefix(av.ID, "GO-") {
						goID = av.ID
					}
					// A LINKED non-GO body here (e.g. the GHSA home served
					// under the GO- path, still aliasing the CVE) leaves
					// goID empty: the empty outcome below stays
					// preserve-side (M43 Phase D R6; unlinked non-GO shapes
					// — skeletal `{}` / foreign junk — are rejected by the
					// R7 linkage arm above instead).
				}
				// av == nil (alias 404) falls through with goID still empty:
				// both lookups were definitive so an empty-symbols outcome
				// below is correct, but nothing GO--bodied was retrieved —
				// the Go vulndb side of the mirror may simply be missing
				// (partial mirror), so the outcome is PRESERVE-side, exactly
				// like a true 404 (M43 Phase D R6; R5 classified this shape
				// as authoritative and let it clobber positive rows — the
				// round 5 High finding).
			}
		}

		// Definitive either way: symbols (positive), an AUTHORITATIVE empty
		// (goID set — a linked Go vulndb body exists and carries nothing
		// selector-shaped for the Go analyzer: an upstream retraction the
		// write path propagates), or a PRESERVE-side empty (goID == "" — no
		// linked Go vulndb body retrieved; the write path treats it like a
		// true 404). See osvVulnFuncsOutcome for the full decision table
		// (M43 Phase D R6/R7).
		if len(symbols) > 0 {
			symbolsSeen++
		}
		if goID != "" {
			goIDsSeen++
		}
		out[cveID] = osvVulnFuncsOutcome{symbols: symbols, scoped: scoped, excerpt: excerpt, goID: goID}
	}

	// Mass-404 observability Warn (M43 Phase D R4, replacing the R3
	// suppression valve): a tick that accumulates many definitive 404s while
	// retrieving NO record body at all is worth an operator ping — it is the
	// signature of a misconfigured mirror or an OSV outage — but it is ALSO
	// exactly what a LEGITIMATE all-404 backlog looks like (the cap-sized
	// head of the candidate order genuinely absent from OSV), so the
	// tombstones are NOT suppressed: suppression starved that backlog's
	// negative cache forever (Codex 42nd [High]). The
	// mirror-misconfiguration threat is covered structurally by the write
	// path's clobber guard (writeOSVVulnFuncsChunk), by the R5 backdated
	// fetched_at on this tick's tombstones (they re-candidate at the first
	// daily tick after the osvVulnFuncsAnomalyRetryInterval margin, so the
	// anomaly's blind spot is 2–3 days, not 7), and offline-client drift
	// never reaches this loop (IsOffline guard above).
	//
	// Predicate (M43 Phase D R6, round 5 Low finding 3): R4/R5 required
	// notFound == fetches, so ONE transient failure in an otherwise all-404
	// tick (499×404 + 1×timeout) defeated the determination. R6 counts what
	// matters — enough definitive 404s AND zero record bodies retrieved;
	// transients increment neither counter. Deliberate trade-off: even one
	// retrieved record body proves the mirror serves records, so a 404-heavy
	// tick with any hit is judged a legitimate backlog, not an anomaly (the
	// clobber guard bounds the damage if that judgement is ever wrong).
	anomalousTick := notFound >= osvVulnFuncsMass404WarnThreshold && recordsRetrieved == 0
	if anomalousTick {
		slog.Warn(osvMass404WarnMsg,
			"fetches", fetches,
			"not_found", notFound,
			"records_retrieved", recordsRetrieved,
			"threshold", osvVulnFuncsMass404WarnThreshold,
			"tombstones", len(out),
			"shortened_freshness_retry", osvVulnFuncsAnomalyRetryInterval.String())
	}

	// Mass-skeletal observability Warn (M43 Phase D R7, round 6 finding 4):
	// the mass-404 predicate above is blind to a mirror that answers every
	// path `200 {}` (or any canned/unlinked junk) — notFound stays 0 while
	// recordsRetrieved climbs, yet the tick determines NOTHING: zero GO-
	// record identities, zero symbols, every outcome a preserve-side
	// tombstone. That shape gets one operator Warn of its own. Warn-ONLY —
	// deliberately no anomalous backdate — because the same counters also
	// describe a LEGITIMATE backlog of Go-ecosystem CVEs whose advisories
	// are GHSA/CVE-home-only: a Go-ecosystem candidate with no GO- record in
	// OSV is a normal, permanent state (the alias follow-up 404s, or there
	// is no GO- alias at all), so backdating would re-spend the fetch cap on
	// that backlog every 2–3 days forever. The write path's clobber guard
	// plus the R7 linkage rule already bound the hostile reading's damage;
	// disjoint from the mass-404 anomaly by construction (that one requires
	// recordsRetrieved == 0, this one requires it at threshold or above).
	if fetches >= osvVulnFuncsMass404WarnThreshold &&
		recordsRetrieved >= osvVulnFuncsMass404WarnThreshold &&
		goIDsSeen == 0 && symbolsSeen == 0 {
		slog.Warn(osvMassSkeletalWarnMsg,
			"fetches", fetches,
			"records_retrieved", recordsRetrieved,
			"not_found", notFound,
			"threshold", osvVulnFuncsMass404WarnThreshold,
			"tombstones", len(out))
	}
	return out, anomalousTick
}

// writeOSVVulnFuncs runs Pass B: fans the per-CVE outcomes out to
// per-(tenant, cve) advisory_excerpts rows (source 'osv') under each
// tenant's RLS GUC, chunked on one pooled connection. Write-heavy contract
// mirrors matchTenantsChunk: a chunk that fails to COMMIT contributes ZERO
// to the returned counters (its upserts rolled back), is logged, and the
// loop continues with the next chunk.
//
// anomalousTick (M43 Phase D R5) is fetchOSVVulnFuncs' mass-404 anomaly
// determination: when true, TOMBSTONE rows are stamped with a BACKDATED
// fetched_at (see osvVulnFuncsAnomalyRetryInterval) so a possible mirror
// misconfiguration is negative-cached for 2–3 days instead of the full
// freshness window.
func (j *CVESyncJob) writeOSVVulnFuncs(
	ctx context.Context,
	candidates []osvTenantCandidates,
	outcomes map[string]osvVulnFuncsOutcome,
	anomalousTick bool,
) (rowsUpserted, tenantsWritten int) {
	// Keep only (tenant, cve) pairs whose CVE reached a definitive outcome
	// this tick — symbols OR a negative tombstone (M43 Phase D R2 finding 1).
	// Undetermined CVEs (transient failure / fetch cap) have no outcome
	// entry, get no row, and retry next tick.
	writes := make([]osvTenantCandidates, 0, len(candidates))
	for _, cand := range candidates {
		cveIDs := make([]string, 0, len(cand.cveIDs))
		for _, id := range cand.cveIDs {
			if _, ok := outcomes[id]; ok {
				cveIDs = append(cveIDs, id)
			}
		}
		if len(cveIDs) > 0 {
			writes = append(writes, osvTenantCandidates{tenantID: cand.tenantID, cveIDs: cveIDs})
		}
	}
	if len(writes) == 0 {
		return 0, 0
	}

	conn, err := j.db.Conn(ctx)
	if err != nil {
		slog.Warn("scheduler: acquire pooled conn for OSV vuln_funcs write failed (M43 F467)", "error", err)
		return 0, 0
	}
	defer conn.Close()

	chunkSize := cveMatchBatchChunkSize
	if chunkSize <= 0 {
		chunkSize = cveMatchBatchChunkSizeDefault
	}
	numChunks := (len(writes) + chunkSize - 1) / chunkSize

	for chunkIndex := 0; chunkIndex < numChunks; chunkIndex++ {
		start := chunkIndex * chunkSize
		end := start + chunkSize
		if end > len(writes) {
			end = len(writes)
		}
		chunkRows, chunkTenants, chunkErr := j.writeOSVVulnFuncsChunk(ctx, conn, chunkIndex, writes[start:end], outcomes, anomalousTick)
		if chunkErr != nil {
			slog.Warn("scheduler: OSV vuln_funcs write chunk aborted, continuing with next chunk (M43 F467)",
				"chunk_index", chunkIndex, "num_chunks", numChunks, "error", chunkErr)
		}
		rowsUpserted += chunkRows
		tenantsWritten += chunkTenants
	}
	return rowsUpserted, tenantsWritten
}

// writeOSVVulnFuncsChunk upserts one chunk's excerpt rows inside one tx:
// per tenant SET LOCAL GUC (advisory_excerpts RLS WITH CHECK), then per
// (tenant, cve) an optional pre-write read plus one Upsert.
//
// Tombstone clobber guard (M43 Phase D R4, the structural replacement for
// the R3 mass-404 suppression valve; R5 split the empty shapes, R6 re-keyed
// the split on the GO- record body and instrumented the retraction): EVERY
// empty write (symbols empty) first reads the existing (tenant, cve, 'osv')
// row via GetBySource ON THIS TX — txCtx routes the repository's
// database.Querier onto the chunk tx, so the read runs under the SET LOCAL
// tenant GUC, same F185 discipline as the Upsert. What happens next depends
// on the outcome's clobber authority (osvVulnFuncsOutcome.goID):
//   - PRESERVE-side empty (goID == "" — true 404, alias 404, linked non-Go
//     record without a usable GO- alias, or an unlinked body rejected by
//     the R7 linkage rule) vs an existing non-empty vuln_funcs row: the
//     write preserves the row's data wholesale (vuln_funcs, the other JSONB
//     fields, raw_excerpt), refreshes ONLY fetched_at, and buffers one
//     osvTombstonePreserveInfoMsg Info line — so neither a mass-404 anomaly
//     nor a partial mirror can ever empty previously-positive rows while
//     the freshness window still advances.
//   - AUTHORITATIVE empty (goID != "" — a linked GO- record body with no
//     symbols, an upstream retraction; M43 Phase D R5/R6): overwrites the
//     row wholesale so retractions propagate. When the prior row was
//     POSITIVE — the one write shape that destroys stored symbols — exactly
//     one buffered osvRetractionOverwriteWarnMsg Warn (tenant_id, cve_id,
//     go_id) makes the wipe operator-visible (round 5 High finding: R5
//     overwrote silently). Already-empty / absent prior rows overwrite
//     silently (routine whole-module advisories re-tombstoning every
//     window).
//   - POSITIVE writes skip the read entirely: fresh symbols are
//     authoritative and replace the row unconditionally.
//
// Both observability lines are BUFFERED (osvVulnFuncsWriteLogEvent) and
// emitted by emitOSVVulnFuncsWriteLogs only after tx.Commit() succeeds (M43
// Phase D R7, round 6 finding 2): they describe writes, and pre-R7 they
// fired mid-tx, so a chunk whose commit then failed had already logged
// preservations/retractions that never became durable.
//
// Round-trip cost of the guard (M43 Phase D R4 round 4 Low finding — the
// earlier "bounded by the fetch cap" wording was wrong; R6 extended the
// read to authoritative empties for the retraction Warn): the pre-write
// read fires once per EMPTY-outcome ROW WRITE, i.e. per (tenant, cve) pair
// AFTER tenant fan-out, not per distinct CVE — a single empty-outcome CVE
// listed by T tenants costs T reads. The fetch cap bounds distinct-CVE
// lookups only, so it does NOT bound this cost; the correct bound is the
// pass's own write count: at most one extra read per row write, i.e. ≤2×
// the pre-R4 per-row round-trips, and strictly less whenever the tick has
// positive outcomes (which never read).
//
// A GetBySource failure aborts the chunk exactly like an Upsert failure:
// with real PG the error has already aborted the tx server-side.
//
// The tx carries ONLY excerpt reads/writes — unlike the M32 batch there are
// no core links to fence, so no savepoint is needed: an abort loses only
// this chunk's excerpt rows, which self-heal next tick.
// Returns (0, 0, err) on rollback so the caller's totals match durable rows.
func (j *CVESyncJob) writeOSVVulnFuncsChunk(
	ctx context.Context,
	conn *sql.Conn,
	chunkIndex int,
	chunk []osvTenantCandidates,
	outcomes map[string]osvVulnFuncsOutcome,
	anomalousTick bool,
) (rowsUpserted, tenantsWritten int, err error) {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("scheduler: begin chunk %d OSV vuln_funcs tx: %w", chunkIndex, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Route the repository Upsert onto this tx (same database.WithTx
	// discipline as matchTenantsChunk) so the SET LOCAL GUC is visible to
	// the RLS WITH CHECK.
	txCtx := database.WithTx(ctx, tx)
	now := time.Now().UTC()
	// M43 Phase D R5: an ANOMALOUS tick (>= the mass-404 Warn threshold of
	// definitive 404s with zero record bodies retrieved — R6 predicate)
	// stamps its empty-outcome rows with a BACKDATED fetched_at so they age
	// out of the freshness window at the first daily tick after the
	// osvVulnFuncsAnomalyRetryInterval margin — effectively 2–3 days (see
	// that const for the inclusive-comparison arithmetic) instead of the
	// full osvVulnFuncsRefreshInterval (7 days): if the tick was a mirror
	// misconfiguration, the blind spot after the mirror is repaired shrinks
	// accordingly. Normal ticks stamp now; positive rows always stamp now
	// (an anomalous tick cannot produce positives OR authoritative empties —
	// zero record bodies were retrieved, so every outcome is a preserve-side
	// tombstone).
	//
	// Deliberate, previously undocumented (M43 Phase D R6, round 5 Low
	// finding 4): the backdated stamp applies to PRESERVE-path rows too — an
	// existing positive row that a 404 lands on during an anomalous tick
	// keeps its data (clobber guard below) but takes the backdated
	// fetched_at, so the 404-vs-positive divergence is itself re-verified on
	// the shortened 2–3 day schedule instead of sitting unexamined for the
	// full window. Pinned by
	// TestCVESyncJob_WriteOSVVulnFuncs_AnomalousTickBackdatesPreservedRow.
	tombstoneFetchedAt := now
	if anomalousTick {
		tombstoneFetchedAt = now.Add(-(osvVulnFuncsRefreshInterval - osvVulnFuncsAnomalyRetryInterval))
	}

	chunkRows, chunkTenants := 0, 0
	// pendingLogs buffers the chunk's preserve-Info / retraction-Warn
	// observability events (M43 Phase D R7, round 6 finding 2): both lines
	// describe writes, so they are emitted only after tx.Commit() succeeds —
	// a chunk that rolls back logged nothing, because nothing happened.
	var pendingLogs []osvVulnFuncsWriteLogEvent
	for _, cand := range chunk {
		if _, sErr := tx.ExecContext(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			cand.tenantID.String(),
		); sErr != nil {
			return 0, 0, fmt.Errorf("scheduler: chunk %d OSV vuln_funcs SET LOCAL failed for tenant %s: %w",
				chunkIndex, cand.tenantID, sErr)
		}
		wrote := false
		for _, cveID := range cand.cveIDs {
			o := outcomes[cveID]
			// fetchedAt is a fresh per-row variable (its address is stored on
			// the excerpt): tombstones take the possibly-backdated anomaly
			// stamp (M43 Phase D R5), positives always take now.
			fetchedAt := now
			if len(o.symbols) == 0 {
				fetchedAt = tombstoneFetchedAt
			}
			excerpt := &repository.AdvisoryExcerpt{
				TenantID:        cand.tenantID,
				CVEID:           cveID,
				Source:          osvVulnFuncsSource,
				VulnFuncs:       stringsToJSONArray(o.symbols),
				VulnFuncsScoped: scopedVulnFuncsToJSON(o.scoped),
				RawExcerpt:      o.excerpt,
				FetchedAt:       &fetchedAt,
			}
			// Empty-write clobber guard + retraction observability (M43
			// Phase D R4/R5/R6) — see the docstring for the full decision
			// table. Every empty write reads the existing row once; the
			// outcome's goID then decides between preserving (goID == "" —
			// no linked GO- record body backs the emptiness, so it must
			// never wipe stored symbols) and overwriting (goID != "" — an
			// authoritative Go vulndb retraction, Warn-logged when it
			// destroys a positive row). Both observability lines are
			// BUFFERED and emitted only after the chunk's COMMIT succeeds
			// (M43 Phase D R7, round 6 finding 2 — a mid-tx emission logged
			// preservations/retractions a failed commit then rolled back).
			var logEvent *osvVulnFuncsWriteLogEvent
			if len(o.symbols) == 0 {
				existing, gErr := j.advisoryExcerpts.GetBySource(txCtx, cand.tenantID, cveID, osvVulnFuncsSource)
				if gErr != nil {
					slog.Warn("scheduler: OSV vuln_funcs pre-write read failed, aborting chunk (M43 Phase D R4)",
						"chunk_index", chunkIndex, "tenant_id", cand.tenantID, "cve_id", cveID, "error", gErr)
					return 0, 0, fmt.Errorf("scheduler: chunk %d OSV vuln_funcs pre-write read for tenant %s cve %s: %w",
						chunkIndex, cand.tenantID, cveID, gErr)
				}
				if existing != nil && jsonArrayNonEmpty(existing.VulnFuncs) {
					if o.goID == "" {
						excerpt.VulnFuncs = existing.VulnFuncs
						excerpt.VulnFuncsScoped = existing.VulnFuncsScoped
						excerpt.AffectedPaths = existing.AffectedPaths
						excerpt.RequiredConfig = existing.RequiredConfig
						excerpt.RequiredEnv = existing.RequiredEnv
						excerpt.RawExcerpt = existing.RawExcerpt
						// M43 Phase D R5 observability: OSV yielded nothing
						// authoritative for a CVE whose stored row still
						// carries symbols. Preserving is the safe call
						// (nothing GO--bodied vouched for the emptiness),
						// but the divergence is operator-relevant — the
						// stored symbols no longer have a verifiable
						// upstream source.
						logEvent = &osvVulnFuncsWriteLogEvent{
							tenantID: cand.tenantID, cveID: cveID}
					} else {
						// M43 Phase D R6 (round 5 High finding): the one
						// write shape that destroys stored symbols — an
						// authoritative Go vulndb retraction overwriting a
						// positive row. It must never happen silently, and
						// the Warn must never lie: emitted post-COMMIT so
						// the log line matches a write that is durable.
						logEvent = &osvVulnFuncsWriteLogEvent{retraction: true,
							tenantID: cand.tenantID, cveID: cveID, goID: o.goID}
					}
				}
			}
			if uErr := j.advisoryExcerpts.Upsert(txCtx, excerpt); uErr != nil {
				slog.Warn("scheduler: OSV vuln_funcs upsert failed, aborting chunk (M43 F467)",
					"chunk_index", chunkIndex, "tenant_id", cand.tenantID, "cve_id", cveID, "error", uErr)
				return 0, 0, fmt.Errorf("scheduler: chunk %d OSV vuln_funcs upsert for tenant %s cve %s: %w",
					chunkIndex, cand.tenantID, cveID, uErr)
			}
			if logEvent != nil {
				pendingLogs = append(pendingLogs, *logEvent)
			}
			chunkRows++
			wrote = true
		}
		if wrote {
			chunkTenants++
		}
	}

	if cErr := tx.Commit(); cErr != nil {
		return 0, 0, fmt.Errorf("scheduler: commit chunk %d OSV vuln_funcs tx: %w", chunkIndex, cErr)
	}
	committed = true
	// Emit the buffered preserve/retraction lines only now (M43 Phase D R7,
	// round 6 finding 2): the COMMIT succeeded, so every line describes a
	// write that is durable. A failed commit returns above and the events
	// are dropped with the rolled-back writes they described.
	emitOSVVulnFuncsWriteLogs(pendingLogs)
	return chunkRows, chunkTenants, nil
}

// jsonArrayNonEmpty reports whether raw holds a JSON array with at least one
// element (M43 Phase D R4 tombstone clobber guard). Foreign shapes — raw
// bytes that are not a JSON array — conservatively count as NON-empty so the
// guard never clobbers data it does not understand; nil / empty / 'null' /
// '[]' count as empty (a tombstone may overwrite them).
func jsonArrayNonEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return true
	}
	return len(arr) > 0
}

// osvScopedVulnFuncs is one module's selector list in the on-disk
// advisory_excerpts.vuln_funcs_scoped shape (migration 057, M43 Phase D
// round 8 / R8f):
//
//	[{"module": "<Go module path>", "vuln_funcs": ["Pkg.Func", ...]}, ...]
//
// Module is the OSV affected[].package.name the selectors were declared
// under — already vetted against imports[].path by
// osvImportPathWithinModule, so a crafted record cannot mis-attribute
// selectors — with Go vulndb's synthetic "stdlib" / "toolchain" modules
// stored verbatim (they match the pkg:golang/stdlib-style purls Syft
// emits for Go binaries). The read side is
// repository.ScopedVulnFuncs / decodeScopedVulnFuncs.
type osvScopedVulnFuncs struct {
	Module    string   `json:"module"`
	VulnFuncs []string `json:"vuln_funcs"`
}

// extractOSVGoVulnFuncs converts an OSV record's Go vulndb structured
// symbols (affected[].ecosystem_specific.imports[] = {path, symbols[]}) to
// the wire-safe selector list, unioned across every affected/import entry
// with first-seen-order dedupe. Non-Go affected entries and malformed
// shapes are skipped leniently (EcosystemSpecific is a decoded
// map[string]interface{}; foreign feeds put arbitrary JSON there).
//
// Returns BOTH shapes the writer stores (M43 Phase D round 8 / R8f):
//
//   - flat: the CVE-level union, unchanged from pre-R8f (it keeps feeding
//     advisory_excerpts.vuln_funcs, the triage prompt / grounding readers,
//     and legacy-row serving);
//   - scoped: the same selectors attributed to the affected module they
//     were declared under (module = affected[].package.name, first-seen
//     module order, per-module first-seen selector order, per-module
//     dedupe). Imports of the SAME module union into one entry. A selector
//     that recurs under a SECOND module (e.g. a fork family like
//     github.com/x/mod and github.com/x/mod/v3 declaring the same
//     "pkg.Func") is a flat-union dup — flat keeps only the first
//     occurrence — but IS attributed to each module it appears under, so
//     neither module's targets lose it; the scoped total is bounded by the
//     same osvVulnFuncsMaxSymbolsPerCVE cap.
//
// Hardening (M43 Phase D R2):
//   - finding 4: an imports[].path must belong to its affected module
//     (osvImportPathWithinModule) — a crafted record cannot attribute
//     unrelated packages' selectors (path "fmt" under github.com/a/b) to a
//     module the tenant actually ships.
//   - finding 2: output is truncated at osvVulnFuncsMaxSymbolsPerCVE
//     selectors (slog.Warn; the truncating return ends the scoped
//     accumulation at the same point), and osvWireSafeSelector drops
//     selectors over osvVulnFuncsMaxSelectorBytes.
func extractOSVGoVulnFuncs(vuln *client.OSVVulnerability) ([]string, []osvScopedVulnFuncs) {
	if vuln == nil {
		return nil, nil
	}
	var out []string
	seen := make(map[string]struct{})
	var scoped []osvScopedVulnFuncs
	scopedIdx := make(map[string]int)       // module → index into scoped
	seenScoped := make(map[string]struct{}) // module + "\x00" + selector
	scopedTotal := 0
	scopedDropped := 0
	// The scoped-cap branch below can drop attributions on BOTH exit paths
	// (the flat-cap truncating return and the normal return), so the Warn
	// fires from a defer — once per record, with the total dropped count
	// (M43 Phase D R9; parity with the flat cap Warn).
	defer func() {
		if scopedDropped > 0 {
			slog.Warn("scheduler: OSV cross-module duplicates exceed per-CVE scoped symbol cap, scoped attributions dropped (M43 Phase D R9)",
				"osv_id", vuln.ID, "cap", osvVulnFuncsMaxSymbolsPerCVE, "dropped", scopedDropped)
		}
	}()
	addScoped := func(module, sel string) {
		key := module + "\x00" + sel
		if _, dup := seenScoped[key]; dup {
			return
		}
		if scopedTotal >= osvVulnFuncsMaxSymbolsPerCVE {
			// Only reachable via cross-module duplicates (the flat cap
			// return below ends both accumulations otherwise); bounded so
			// a hostile record cannot balloon the scoped column past the
			// flat column's own cap. The selector still ships in the flat
			// union, but THIS module's scoped entry loses it — its
			// scoped-routed target rows would miss it silently — so count
			// the drop for the deferred Warn above.
			scopedDropped++
			return
		}
		seenScoped[key] = struct{}{}
		i, ok := scopedIdx[module]
		if !ok {
			scoped = append(scoped, osvScopedVulnFuncs{Module: module})
			i = len(scoped) - 1
			scopedIdx[module] = i
		}
		scoped[i].VulnFuncs = append(scoped[i].VulnFuncs, sel)
		scopedTotal++
	}
	for _, aff := range vuln.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, "Go") {
			continue
		}
		rawImports, ok := aff.EcosystemSpecific["imports"].([]interface{})
		if !ok {
			continue
		}
		for _, ri := range rawImports {
			imp, ok := ri.(map[string]interface{})
			if !ok {
				continue
			}
			path, _ := imp["path"].(string)
			if !osvImportPathWithinModule(aff.Package.Name, path) {
				slog.Debug("scheduler: OSV import path escapes its affected module, symbols dropped (M43 Phase D R2 finding 4)",
					"osv_id", vuln.ID, "module", aff.Package.Name, "path", path)
				continue
			}
			pkgIdent, ok := osvGoPackageIdent(path)
			if !ok {
				// e.g. hyphenated last segments ("github.com/foo/go-bar"):
				// the default source-level package ident is unknowable from
				// the path alone, and a wrong guess would ship selectors the
				// AST walk can never match — skip conservatively
				// (import-level reachability still covers the module via
				// VulnerableModules). gopkg.in-style "<ident>.v<N>" segments
				// ARE resolvable and no longer land here (finding 3).
				slog.Debug("scheduler: OSV import path has no identifier-shaped package segment, symbols skipped (M43 F467)",
					"osv_id", vuln.ID, "path", path)
				continue
			}
			rawSymbols, ok := imp["symbols"].([]interface{})
			if !ok {
				continue // whole-package entry (no symbol list) — nothing selector-shaped to store
			}
			// module is the scoped-attribution key: the affected module
			// name the (validated) import path lives under. TrimSpace
			// mirrors osvImportPathWithinModule's own comparison; the
			// validation above guarantees it is non-empty here.
			module := strings.TrimSpace(aff.Package.Name)
			for _, rs := range rawSymbols {
				sym, ok := rs.(string)
				if !ok {
					continue
				}
				sel, ok := osvWireSafeSelector(pkgIdent, sym)
				if !ok {
					slog.Debug("scheduler: OSV symbol not wire-safe, skipped (M43 F467)",
						"osv_id", vuln.ID, "path", path, "symbol", sym)
					continue
				}
				if _, dup := seen[sel]; dup {
					// Flat-union dup (same CVE, seen under an earlier
					// module or import) — still attribute it to THIS
					// module so its targets receive it too (R8f).
					addScoped(module, sel)
					continue
				}
				if len(out) >= osvVulnFuncsMaxSymbolsPerCVE {
					slog.Warn("scheduler: OSV record exceeds per-CVE symbol cap, truncating (M43 Phase D R2 finding 2)",
						"osv_id", vuln.ID, "cap", osvVulnFuncsMaxSymbolsPerCVE)
					return out, scoped
				}
				seen[sel] = struct{}{}
				out = append(out, sel)
				addScoped(module, sel)
			}
		}
	}
	return out, scoped
}

// scopedVulnFuncsToJSON marshals the module-scoped selector list into the
// json.RawMessage JSONB shape advisory_excerpts.vuln_funcs_scoped expects
// (migration 057). nil/empty maps to nil, which the repository's
// jsonbOrEmptyArray normalises to the column's '[]' default — mirroring
// stringsToJSONArray.
func scopedVulnFuncsToJSON(in []osvScopedVulnFuncs) json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	return b
}

// goStdlibTopLevelPackages is the allowlist of Go standard-library TOP-LEVEL
// package path segments, per `go list std` (M43 Phase D R3 finding 1; R4
// added "simd" — new in go1.26.5, found by Codex 42nd via web check against
// pkg.go.dev). Drift is enforced by
// TestGoStdlibTopLevelPackages_ToolchainDrift, which runs `go list std` on
// the test toolchain and asserts its top-level segments are a SUBSET of this
// allowlist — a Go release adding a new top-level std package fails that
// test and forces an update here; the allowlist MAY run ahead of older
// toolchains. A package missing here is conservatively DROPPED (its symbols
// never reach vuln_funcs — import-level reachability via VulnerableModules
// still covers the finding), never falsely admitted. Deliberately excluded:
// "internal" / "vendor" (not importable by user code, so their symbols can
// never match an app AST walk) and "cmd" (toolchain binaries — same reason).
//
// Operational caveat (M43 Phase D R5, round 4 Low finding):
// GOEXPERIMENT-gated packages — "simd" is the live example, visible in
// `go list std` only under GOEXPERIMENT=simd on toolchains that gate it —
// are INVISIBLE to the drift test's plain `go list std` run, so the drift
// test can never force them into (or notice them missing from) this
// allowlist. When adding a gated package here, ALSO pin it with an explicit
// test the way TestOSVImportPathWithinModule_SimdAllowed pins "simd";
// without that pin, nothing stops a later "cleanup" from silently dropping
// the entry and re-introducing the conservative-drop starvation for that
// package's selectors.
var goStdlibTopLevelPackages = map[string]struct{}{
	"archive": {}, "bufio": {}, "builtin": {}, "bytes": {}, "cmp": {},
	"compress": {}, "container": {}, "context": {}, "crypto": {},
	"database": {}, "debug": {}, "embed": {}, "encoding": {}, "errors": {},
	"expvar": {}, "flag": {}, "fmt": {}, "go": {}, "hash": {}, "html": {},
	"image": {}, "index": {}, "io": {}, "iter": {}, "log": {}, "maps": {},
	"math": {}, "mime": {}, "net": {}, "os": {}, "path": {}, "plugin": {},
	"reflect": {}, "regexp": {}, "runtime": {}, "simd": {}, "slices": {},
	"sort": {}, "strconv": {}, "strings": {}, "structs": {}, "sync": {},
	"syscall": {}, "testing": {}, "text": {}, "time": {}, "unicode": {},
	"unique": {}, "unsafe": {}, "weak": {},
}

// osvImportPathWithinModule reports whether an OSV imports[].path plausibly
// belongs to the affected module it is declared under (M43 Phase D R2
// finding 4): the path must equal the module name or be a "/"-delimited
// subpath of it. Go vulndb's synthetic "stdlib" / "toolchain" modules are the
// exception — their imports[].path values are bare standard-library package
// paths ("html/template") never prefixed by the module name, so for those the
// path's FIRST segment must be a real standard-library top-level package
// (goStdlibTopLevelPackages). The R2 heuristic ("no '.' in the first
// segment") was not enough (R3 finding 1): a record forging package.name
// "stdlib" could smuggle a dot-less external module path like
// "corp/internal/vuln", planting fake selectors ("vuln.X") in vuln_funcs
// that steer the CLI AST walk toward false reachable verdicts.
func osvImportPathWithinModule(module, path string) bool {
	module = strings.TrimSpace(module)
	path = strings.TrimSpace(path)
	if module == "" || path == "" {
		return false
	}
	if module == "stdlib" || module == "toolchain" {
		first := path
		if i := strings.IndexByte(path, '/'); i >= 0 {
			first = path[:i]
		}
		_, ok := goStdlibTopLevelPackages[first]
		return ok
	}
	return path == module || strings.HasPrefix(path, module+"/")
}

// osvGoPackageIdent derives the source-level package identifier the AST
// matcher compares against from a Go vulndb import path. The vendored
// analyzer (go_analyzer.go inspectFileForSelectors) matches
// ast.SelectorExpr.X's *ast.Ident NAME — i.e. the local package ident,
// which for an unaliased import defaults to the package's declared name.
// Heuristic (path-only; the declared name is not in the OSV record):
//
//   - last path segment ("html/template" → "template",
//     "golang.org/x/net/http2" → "http2");
//   - a trailing module MAJOR-version segment v2+ is stripped to the
//     previous segment ("github.com/labstack/echo/v4" → "echo") — Go
//     modules forbid /v0 and /v1 suffixes, so "v1" endings are kept
//     verbatim (k8s.io/api/core/v1 really is package v1);
//   - a versioned segment "<ident>.v<N>" resolves to "<ident>"
//     ("gopkg.in/yaml.v2" → "yaml") ONLY when the path lives under
//     "gopkg.in/" (M43 Phase D R3 finding 4): the dot-version suffix naming
//     the module version while the source package declares the bare ident is
//     gopkg.in's documented convention (M43 Phase D R2 finding 3 —
//     previously the whole gopkg.in/yaml.vN family was dropped, starving
//     those selectors). The same "<ident>.v<N>" shape on any other host
//     ("github.com/foo/bar.v2") is a guess — the package could equally
//     declare bar_v2 or anything else — so it keeps the conservative skip;
//   - any other non-identifier result ("github.com/foo/go-bar" → "go-bar")
//     returns ok=false: the caller skips those imports conservatively.
func osvGoPackageIdent(path string) (string, bool) {
	p := strings.TrimSuffix(strings.TrimSpace(path), "/")
	if p == "" {
		return "", false
	}
	segs := strings.Split(p, "/")
	last := segs[len(segs)-1]
	if len(segs) >= 2 && isGoModuleMajorVersionSegment(last) {
		last = segs[len(segs)-2]
	}
	if !isGoIdentifierShaped(last) {
		if strings.HasPrefix(p, "gopkg.in/") {
			if ident, ok := gopkgInVersionedIdent(last); ok {
				return ident, true
			}
		}
		return "", false
	}
	return last, true
}

// gopkgInVersionedIdent resolves a gopkg.in-style versioned path segment
// "<ident>.v<N>" (N = one or more digits) to "<ident>" (M43 Phase D R2
// finding 3). The CALLER restricts its use to paths under "gopkg.in/" (M43
// Phase D R3 finding 4) — the convention is host-specific. Anything else —
// non-identifier prefix, missing halves, a version tail that is not
// "v"+digits — returns ok=false so the caller keeps its conservative skip.
func gopkgInVersionedIdent(seg string) (string, bool) {
	i := strings.LastIndexByte(seg, '.')
	if i <= 0 || i == len(seg)-1 {
		return "", false
	}
	ident, ver := seg[:i], seg[i+1:]
	if !isGoIdentifierShaped(ident) {
		return "", false
	}
	if len(ver) < 2 || ver[0] != 'v' {
		return "", false
	}
	for j := 1; j < len(ver); j++ {
		if ver[j] < '0' || ver[j] > '9' {
			return "", false
		}
	}
	return ident, true
}

// isGoModuleMajorVersionSegment reports whether s is a module major-version
// path segment ("v2", "v13", ...). v0/v1 return false: Go modules never use
// them as path suffixes, while real packages named v1 (k8s-style versioned
// API groups) are common.
func isGoModuleMajorVersionSegment(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != "v0" && s != "v1"
}

// osvWireSafeSelector joins pkgIdent and a Go vulndb symbol ("Parse" or
// "Decoder.Decode") into the selector form the M43 Wave 1 wire requires and
// validates it against the SAME frozen spec as handler.normalizeVulnFuncs
// (trim → strip one trailing "()" → dot-split → exactly 2..3 parts → every
// part Go-identifier-shaped). Anything that would be dropped at the serving
// edge is rejected here so no dead weight lands in vuln_funcs. Selectors over
// osvVulnFuncsMaxSelectorBytes are additionally rejected (M43 Phase D R2
// finding 2) — a size bound the edge does not enforce but storage should.
func osvWireSafeSelector(pkgIdent, symbol string) (string, bool) {
	s := strings.TrimSpace(symbol)
	s = strings.TrimSuffix(s, "()")
	if s == "" {
		return "", false
	}
	sel := pkgIdent + "." + s
	if len(sel) > osvVulnFuncsMaxSelectorBytes {
		return "", false
	}
	parts := strings.Split(sel, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return "", false
	}
	for _, p := range parts {
		if !isGoIdentifierShaped(p) {
			return "", false
		}
	}
	return sel, true
}

// isGoIdentifierShaped mirrors handler.isGoIdentifier (reachability.go, the
// Wave 1 single source of truth for the wire normalisation): first rune a
// letter/underscore, rest letters/digits/underscores, Unicode letters
// allowed. Duplicated here because the handler's helper is unexported in
// another package; the scheduler test suite pins the produced selectors
// against a re-statement of the same frozen spec.
func isGoIdentifierShaped(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || unicode.IsLetter(r):
		case i > 0 && unicode.IsDigit(r):
		default:
			return false
		}
	}
	return true
}

// osvExcerptText picks the grounding text persisted as raw_excerpt: the OSV
// summary, falling back to details, capped at osvExcerptMaxRunes (M43 Phase D
// R2 finding 2). May be empty (raw_excerpt is nullable; the structured
// symbols are the value of an 'osv' row).
func osvExcerptText(vuln *client.OSVVulnerability) string {
	if vuln == nil {
		return ""
	}
	text := strings.TrimSpace(vuln.Summary)
	if text == "" {
		text = strings.TrimSpace(vuln.Details)
	}
	return truncateRunes(text, osvExcerptMaxRunes)
}

// truncateRunes returns s truncated to at most n runes, never cutting inside
// a UTF-8 sequence.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// firstGoVulndbAlias returns the first "GO-" (Go vulndb) id in aliases, or
// "" when none is present.
func firstGoVulndbAlias(aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(strings.TrimSpace(a), "GO-") {
			return strings.TrimSpace(a)
		}
	}
	return ""
}

// osvAliasesContain reports whether aliases names id — whitespace-trimmed
// exact match; OSV alias lists carry canonical ids (M43 Phase D R7).
func osvAliasesContain(aliases []string, id string) bool {
	for _, a := range aliases {
		if strings.TrimSpace(a) == id {
			return true
		}
	}
	return false
}

// osvRecordLinked reports whether a retrieved OSV record BODY vouches for
// the lookup that produced it (M43 Phase D R7, round 6 High finding): either
// the body's own ID field IS the id the lookup requested (requestedID — the
// CVE id on the main lookup, the GO- alias on the follow-up; Go vulndb
// records often omit their own alias list, so self-identification must
// suffice), or its aliases name the CVE under determination (cveID — how a
// GHSA/GO- alias home vouches for a CVE-keyed request). Every real OSV
// response satisfies one arm; a body failing both is crafted or mis-routed
// mirror output and must be rejected wholesale by the caller — its symbols,
// excerpt, aliases, and clobber authority all belong to some OTHER
// vulnerability.
//
// Known limitations (M43 Phase D R7, documented deliberately):
//   - Linkage is SELF-ATTESTED: a hostile mirror that writes the requested
//     CVE into a forged record's aliases passes this check and can still
//     inject symbols or exercise retraction authority. Linkage closes the
//     canned-response / mis-routing classes only; the configured OSV
//     endpoint (SBOMHUB_OSV_URL, operator-controlled TLS origin) remains
//     inside the trust boundary, same as the NVD/GHSA feeds.
//   - Matching is trim-exact and case-sensitive: OSV ids are canonical
//     uppercase, so a mirror emitting non-canonical ids sees its records
//     rejected as unlinked — the fail-safe direction (preserve-side empty
//     plus Warn; no data loss).
func osvRecordLinked(vuln *client.OSVVulnerability, requestedID, cveID string) bool {
	if vuln == nil {
		return false
	}
	return strings.TrimSpace(vuln.ID) == requestedID || osvAliasesContain(vuln.Aliases, cveID)
}

// osvVulnFuncsWriteLogEvent is one deferred preserve-Info / retraction-Warn
// observability line accumulated by writeOSVVulnFuncsChunk (M43 Phase D R7,
// round 6 finding 2): both lines describe WRITES, so emitting them mid-tx —
// the pre-R7 behaviour — logged preservations/retractions that a failed
// COMMIT then rolled back (an operator-facing lie; a rolled-back retraction
// Warn is a false wipe alarm). Events are buffered per chunk and handed to
// emitOSVVulnFuncsWriteLogs only after tx.Commit() returns nil; an aborted
// chunk emits nothing, because none of its writes happened.
type osvVulnFuncsWriteLogEvent struct {
	retraction bool // false: preserve Info; true: retraction-overwrite Warn
	tenantID   uuid.UUID
	cveID      string
	goID       string // retraction events only
}

// emitOSVVulnFuncsWriteLogs emits a committed chunk's buffered
// preserve/retraction lines in buffered order (M43 Phase D R7, round 6
// finding 2). Split out of the chunk writer so the commit-gated contract is
// unit-testable (TestEmitOSVVulnFuncsWriteLogs); the caller invokes it
// exactly once per chunk, strictly after a successful COMMIT.
func emitOSVVulnFuncsWriteLogs(events []osvVulnFuncsWriteLogEvent) {
	for _, e := range events {
		if e.retraction {
			slog.Warn(osvRetractionOverwriteWarnMsg,
				"tenant_id", e.tenantID, "cve_id", e.cveID, "go_id", e.goID)
		} else {
			slog.Info(osvTombstonePreserveInfoMsg,
				"tenant_id", e.tenantID, "cve_id", e.cveID)
		}
	}
}
