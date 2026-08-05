package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/validation"
)

const (
	nvdAPIBase           = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	rateLimitWithoutKey  = 6 * time.Second        // ~5 requests per 30 seconds
	rateLimitWithKey     = 700 * time.Millisecond // ~50 requests per 30 seconds
	maxConcurrentWithKey = 5                      // Max concurrent workers with API key
	maxConcurrentNoKey   = 1                      // Single worker without API key
)

type NVDService struct {
	httpClient *http.Client
	vulnRepo   *repository.VulnerabilityRepository
	compRepo   *repository.ComponentRepository
	cache      *cache.NVDCache
	apiKey     string
	// baseURL is the NVD REST base endpoint. It defaults to nvdAPIBase but is
	// overridable (M40 Wave B) so the orchestrator can point it at an
	// air-gapped mirror or an httptest server. Empty string falls back to the
	// nvdAPIBase const in the constructor.
	baseURL string
	// offline short-circuits every HTTP fetch entry point when true (M40 Wave B
	// air-gapped degrade mode): scans return empty results with no error so the
	// enclosing SBOM scan continues without network access.
	offline bool
}

// NewNVDService creates a new NVD service (without cache - for backwards compatibility).
//
// baseURL and offline (M40 Wave B) are appended last: baseURL overrides the
// nvdAPIBase default (empty => nvdAPIBase); offline enables air-gapped degrade
// mode where fetches short-circuit to empty results.
func NewNVDService(vr *repository.VulnerabilityRepository, cr *repository.ComponentRepository, apiKey string, baseURL string, offline bool) *NVDService {
	if baseURL == "" {
		baseURL = nvdAPIBase
	}
	return &NVDService{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		vulnRepo:   vr,
		compRepo:   cr,
		apiKey:     apiKey,
		baseURL:    baseURL,
		offline:    offline,
	}
}

// NewNVDServiceWithCache creates a new NVD service with Redis cache.
//
// baseURL and offline (M40 Wave B) carry the same semantics as NewNVDService.
func NewNVDServiceWithCache(vr *repository.VulnerabilityRepository, cr *repository.ComponentRepository, apiKey string, nvdCache *cache.NVDCache, baseURL string, offline bool) *NVDService {
	if baseURL == "" {
		baseURL = nvdAPIBase
	}
	return &NVDService{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		vulnRepo:   vr,
		compRepo:   cr,
		cache:      nvdCache,
		apiKey:     apiKey,
		baseURL:    baseURL,
		offline:    offline,
	}
}

type NVDResponse struct {
	// ResultsPerPage is a POINTER so its ABSENCE is distinguishable from a
	// legitimate zero (M54, Codex R4 Critical). encoding/json decodes a body of
	// `null` or `{}` into a zero-valued struct WITHOUT error — measured — so
	// with a plain int, a 200 response carrying no NVD envelope at all was
	// indistinguishable from "this component genuinely has no CVEs". The worker
	// counted it as processed, persisted nothing, and the scan reported
	// completed with zero findings, sailing straight past the
	// total-fetch-failure guard in processComponentsParallel.
	//
	// That is reachable in the field: baseURL is operator-overridable for
	// air-gapped mirrors (M40 Wave B), and an interposing proxy or a
	// misconfigured mirror answering 200 with an empty body is exactly the
	// shape this now refuses. resultsPerPage is part of every documented NVD
	// response envelope, so requiring it present costs nothing against a real
	// endpoint.
	ResultsPerPage *int `json:"resultsPerPage"`
	StartIndex     int  `json:"startIndex"`
	// TotalResults is a POINTER for the same reason (Codex M54 R6, Critical):
	// as a plain int, `{"resultsPerPage":0,"vulnerabilities":[]}` — no
	// totalResults at all — decoded to zero and passed the R5 consistency
	// check, so a mirror could omit the field and every finding with it. The
	// NVD 2.0 schema lists totalResults as required.
	TotalResults *int `json:"totalResults"`
	// Vulnerabilities is a POINTER TO SLICE for the same reason
	// ResultsPerPage is a pointer: an ABSENT array and a present empty one
	// mean different things. `{"resultsPerPage":0}` used to pass validation
	// and read as an authoritative "this component has no CVEs" (Codex M54 R5,
	// Critical). A real NVD response always carries the array.
	Vulnerabilities *[]NVDVulnEntry `json:"vulnerabilities"`
}

// entries returns the decoded matches, or nil when the array was absent.
// Callers must validate() first; this is only the nil-safe accessor.
func (r *NVDResponse) entries() []NVDVulnEntry {
	if r == nil || r.Vulnerabilities == nil {
		return nil
	}
	return *r.Vulnerabilities
}

// validate rejects a 200 response that is not a well-formed NVD envelope.
//
// The enumeration below is the whole of what it checks — kept exhaustive on
// purpose, because an earlier draft claimed it "rejects a 200 response whose
// body is not an NVD envelope" while testing only the first item, and a later
// one still said "exactly three things" over a list of five (Codex M54 R5
// Critical, R7 Low). A comment stronger than the code is the defect class this
// repo treats as first-class, and a stale COUNT is the cheapest way to
// reintroduce it:
//
//  1. resultsPerPage is PRESENT. `null` and `{}` decode into a zero-valued
//     struct without error, so absence is what distinguishes "not an NVD
//     response" from "no CVEs for this component".
//  2. totalResults is PRESENT, for the same reason — without this,
//     `{"resultsPerPage":0,"vulnerabilities":[]}` read as an authoritative
//     "no CVEs" (Codex M54 R6, Critical).
//  3. the vulnerabilities array is PRESENT (it may be empty — that is the
//     genuine no-matches answer).
//  4. the page carries what it says it carries: len(vulnerabilities) equals
//     resultsPerPage, which the NVD schema defines as the number of records in
//     THIS response. A page declaring two and shipping one is silently short,
//     and the missing one may be the finding that mattered.
//  5. totalResults > 0 with no entries at all is inconsistent even when
//     resultsPerPage agrees (`{"resultsPerPage":0,"totalResults":5,...}`), and
//     must not be read as "no CVEs".
//  6. every entry carries a well-formed cve.id. `[{}]` used to satisfy every
//     check above (Codex M54 R7, Critical): it became a vulnerability with
//     CVEID "", which the VARCHAR NOT NULL column accepts, so a nameless row
//     was stored, components were linked to it, no failure counter moved, and
//     the scan completed having persisted nothing identifiable. Worse, cve_id
//     is the ON CONFLICT key, so every such entry across every component
//     collapses onto the same "" row.
//
// What it still does NOT do is verify that the RESULT SET is complete — see
// the known truncation defect on searchByKeyword. A first page of 20 out of
// totalResults=500 satisfies every check above, because each of them is about
// the page being internally honest, not about the pages that were never
// fetched.
func (r *NVDResponse) validate() error {
	if r == nil || r.ResultsPerPage == nil {
		return fmt.Errorf("NVD response is missing the resultsPerPage envelope field; " +
			"the endpoint returned 200 but the body is not an NVD CVE API response")
	}
	if r.TotalResults == nil {
		return fmt.Errorf("NVD response is missing the totalResults envelope field; " +
			"the endpoint returned 200 but the body is not an NVD CVE API response")
	}
	if r.Vulnerabilities == nil {
		return fmt.Errorf("NVD response is missing the vulnerabilities array; " +
			"the endpoint returned 200 but the body is not an NVD CVE API response")
	}
	if got, want := len(*r.Vulnerabilities), *r.ResultsPerPage; got != want {
		return fmt.Errorf("NVD response declares resultsPerPage=%d but carries %d entries; "+
			"the page is short of what it claims and the missing entries would be "+
			"silently dropped", want, got)
	}
	if *r.TotalResults > 0 && len(*r.Vulnerabilities) == 0 {
		return fmt.Errorf("NVD response claims totalResults=%d but carries no entries; "+
			"treating that as 'no vulnerabilities' would silently under-report", *r.TotalResults)
	}
	for i, e := range *r.Vulnerabilities {
		if !validation.IsValidCVEID(e.CVE.ID) {
			return fmt.Errorf("NVD response entry %d has no well-formed cve.id (got %q); "+
				"storing it would create an unidentifiable finding", i, e.CVE.ID)
		}
	}
	return nil
}

type NVDVulnEntry struct {
	CVE NVDCVE `json:"cve"`
}

type NVDCVE struct {
	ID           string     `json:"id"`
	Published    string     `json:"published"`
	LastModified string     `json:"lastModified"`
	Descriptions []NVDDesc  `json:"descriptions"`
	Metrics      NVDMetrics `json:"metrics"`
}

type NVDDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDMetrics struct {
	CvssMetricV31 []CvssMetric `json:"cvssMetricV31"`
	CvssMetricV30 []CvssMetric `json:"cvssMetricV30"`
	// CvssMetricV40 was missing entirely until M54 (Codex R5, High). A CVE
	// that NVD scores ONLY with CVSS v4 — increasingly common — matched none
	// of the fields above, so extractCvss fell through to (nil, "UNKNOWN") and
	// the finding was stored with no score and no severity. `--fail-on high`
	// cannot see a HIGH that is recorded as UNKNOWN.
	CvssMetricV40 []CvssMetric `json:"cvssMetricV40"`
	CvssMetricV2  []CvssMetric `json:"cvssMetricV2"`
}

type CvssMetric struct {
	// Type is "Primary" or "Secondary". NVD returns several assessments per
	// CVE from different sources and does NOT order them with Primary first
	// (Codex M54 R5, Critical) — a Secondary submitter's lower score can be
	// element zero. Selecting blindly by index therefore stored, for example,
	// a Secondary 6.3/MEDIUM in place of NVD's own Primary 9.8/CRITICAL, and a
	// scan whose only finding was that CVE let `--fail-on critical` exit 0.
	// See preferPrimary.
	Type string `json:"type"`
	// Source is the assessing organisation (e.g. "nvd@nist.gov"). Carried for
	// diagnosis; selection keys off Type.
	Source   string   `json:"source"`
	CvssData CvssData `json:"cvssData"`
}

type CvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// nvdComponentKey is used for deduplication in NVD scanning
type nvdComponentKey struct {
	Name    string
	Version string
}

// ScanComponents scans all components in an SBOM for vulnerabilities
// Uses Redis cache and deduplication for efficiency
func (s *NVDService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return nil
	}

	components, err := s.compRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("failed to get components: %w", err)
	}

	if len(components) == 0 {
		return nil
	}

	slog.Info("starting component scan", "sbom_id", sbomID, "component_count", len(components))

	// Deduplicate components by name+version
	uniqueComponents := make(map[nvdComponentKey][]uuid.UUID)
	for _, comp := range components {
		if comp.Name == "" {
			continue
		}
		key := nvdComponentKey{Name: comp.Name, Version: comp.Version}
		uniqueComponents[key] = append(uniqueComponents[key], comp.ID)
	}

	slog.Info("deduplicated components", "unique_count", len(uniqueComponents), "total_count", len(components))

	// Process components with worker pool
	return s.processComponentsParallel(ctx, uniqueComponents)
}

// processComponentsParallel processes components in parallel with rate limiting.
//
// # Why the database section is serialised (M54)
//
// Every caller of ScanComponents hands this function a context that carries a
// *sql.Tx: VulnerabilityHandler.runScan and SbomHandler.runScan both open one
// via database.WithTxFunc, and scheduler.VulnerabilityScanJob.scanProject runs
// inside runWithTenantTx. They must — `components` FORCEs row-level security,
// so ListBySbom above returns zero rows on a connection with no
// app.current_tenant_id bound. The repositories then resolve that tx through
// database.Querier, which means every statement the workers below issue lands
// on ONE PostgreSQL connection.
//
// *sql.DB is safe for concurrent use. *sql.Tx is not, and the gap is not
// theoretical: an open *sql.Rows (which is what QueryRowContext returns until
// Scan closes it) leaves lib/pq mid-message on the wire, so a second worker's
// Parse is written into the middle of another worker's result set. Measured on
// PostgreSQL 15 (2026-08-05) with two workers whose NVD responses arrived
// together, 400 CVEs each:
//
//	pq: unexpected Parse response 'C'   <- first collision
//	driver: bad connection              <- every statement after it
//	database.WithTxFunc: commit: driver: bad connection
//	durable rows: 0 of 800
//
// The connection is destroyed, the commit fails, and the WHOLE sweep is lost —
// not just the two items that collided. At the time of that measurement
// ScanComponents also returned nil, so "NVD scan completed" was logged in the
// same run as the error (the asymmetry M50 pinned). That second half no longer
// describes this function (Codex M54 R5, Low — the sentence outlived the code
// twice): the R1 follow-up below counts refused writes and returns an error,
// so the contradictory INFO line is not emitted for that case any more.
//
// dbMu closes that window: it is taken for the entire per-item persistence
// section, so at most one goroutine is ever inside a statement on the shared
// tx.
//
// The throughput it gives up is not the concurrency this pool exists for. The
// NVD HTTP round trip (hundreds of ms to seconds) stays OUTSIDE the lock, and
// the shared rate limiter already caps the whole pool at one work item per
// rateLimitWithKey (700ms) no matter how many workers there are. What is
// serialised is only the statements: measured on the same PostgreSQL 15, 200
// statements over 40 work items took 22.4ms across 5 goroutines and 55.4ms on
// one — so serialising costs ~0.8ms per work item against a 700ms tick, near
// 0.1%. (Both figures come from an autocommit pool; a serial baseline for the
// transactional path cannot be measured, because that is the configuration
// that destroys its own connection.)
//
// The rejected alternative was maxConcurrentWithKey = 1, which serialises the
// HTTP round trip as well. Measured end to end at 1.5s NVD latency over 6 work
// items: 5.71s with this fix, 9.75s with one worker — a 1.7x regression paid
// by exactly the operators who configured an API key to make scans faster.
//
// The mutex is per-call rather than a field on NVDService on purpose: one
// NVDService is shared process-wide, and two scans for different tenants run
// on different transactions with nothing to contend over.
//
// What this does NOT fix: a statement that fails on its own merits still
// aborts the shared transaction and discards every row the sweep wrote (M50).
// Serialising the workers removes the concurrency as a CAUSE of that abort; it
// does not change what an abort costs. What it does change, as of the R1
// follow-up below, is that the scanner now REPORTS it instead of returning
// nil.
func (s *NVDService) processComponentsParallel(ctx context.Context, components map[nvdComponentKey][]uuid.UUID) error {
	maxWorkers := maxConcurrentNoKey
	rateLimit := rateLimitWithoutKey
	if s.apiKey != "" {
		maxWorkers = maxConcurrentWithKey
		rateLimit = rateLimitWithKey
	}

	// Create work channel
	type workItem struct {
		key          nvdComponentKey
		componentIDs []uuid.UUID
	}
	workChan := make(chan workItem, len(components))
	for key, ids := range components {
		workChan <- workItem{key: key, componentIDs: ids}
	}
	close(workChan)

	// Rate limiter - shared across workers
	rateLimiter := time.NewTicker(rateLimit)
	defer rateLimiter.Stop()

	var wg sync.WaitGroup
	var mu sync.Mutex
	// dbMu guards every statement issued against the (possibly transactional)
	// ctx — see the "Why the database section is serialised" note above. It is
	// deliberately separate from mu, which only protects the counters: mixing
	// them would hold the database lock across the counter updates for no
	// reason, and would make it easy to later "optimise" the counters and
	// silently drop the correctness guarantee with them.
	var dbMu sync.Mutex
	processedCount := 0
	cacheHits := 0
	apiCalls := 0
	// refusedWrites counts statements the DATABASE refused (Codex M54 R1,
	// Critical); fetchFailures counts work items whose NVD lookup never
	// returned an answer (Codex M54 R2, Critical). See the returns at the
	// bottom of this function for exactly which combinations are escalated.
	refusedWrites := 0
	fetchFailures := 0

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for work := range workChan {
				select {
				case <-ctx.Done():
					return
				case <-rateLimiter.C:
					// Rate limit acquired
				}

				vulns, fromCache, err := s.getVulnerabilitiesWithCache(ctx, work.key.Name, work.key.Version)
				if err != nil {
					slog.Warn("failed to get vulnerabilities",
						"component", work.key.Name,
						"version", work.key.Version,
						"error", err)
					mu.Lock()
					fetchFailures++
					mu.Unlock()
					continue
				}

				mu.Lock()
				processedCount++
				if fromCache {
					cacheHits++
				} else {
					apiCalls++
				}
				mu.Unlock()

				// Link vulnerabilities to all component instances
				refused := s.persistWorkItem(ctx, &dbMu, vulns, work.componentIDs)
				if refused > 0 {
					mu.Lock()
					refusedWrites += refused
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	slog.Info("component scan completed",
		"processed", processedCount,
		"cache_hits", cacheHits,
		"api_calls", apiCalls,
		"refused_writes", refusedWrites,
		"fetch_failures", fetchFailures,
	)

	// A refused WRITE means the database declined to record a match we had
	// already obtained. Reporting success after that is the silent-data-loss
	// failure this product cannot afford: the caller marks the scan completed,
	// the CLI trusts the counts, and `sbomhub scan --fail-on critical` exits 0
	// on an incomplete result. So it is escalated (Codex M54 R1, Critical).
	//
	// This is also the loudest symptom of the M50 abort cascade: once one
	// statement poisons the shared transaction, every subsequent write is
	// refused, so this count goes from 0 to "all of them" and the scanner now
	// says so instead of returning nil.
	//
	if refusedWrites > 0 {
		return fmt.Errorf("nvd: database refused %d vulnerability write(s); scan results are incomplete", refusedWrites)
	}

	// TOTAL fetch failure: every work item was asked about and none answered,
	// so this scan has ZERO coverage. Codex M54 R2 (Critical) was right that
	// the first cut hid this behind the policy argument below — deciding that
	// no component was successfully checked requires no threshold, and
	// reporting "completed, 0 vulnerabilities" for it is the same
	// silent-data-loss shape as the refused writes above. `sbomhub scan
	// --fail-on critical` would exit 0 on an NVD outage.
	//
	// The condition is deliberately processedCount == 0 rather than
	// fetchFailures > 0: it fires only when NOTHING got through.
	if processedCount == 0 && fetchFailures > 0 {
		return fmt.Errorf("nvd: all %d component lookup(s) failed; the scan has no coverage", fetchFailures)
	}

	// STILL NOT escalated, and this is the honest remainder: a PARTIAL fetch
	// failure (some components answered, some did not). Turning that into a
	// scan failure needs a threshold — how many components may fail before the
	// scan is worthless? — and that is a product-policy decision, not a bug
	// fix. It stays tracked as the ※要確認 threshold noted on
	// SbomHandler.runScan.
	//
	// Note that the guard above is `processedCount == 0 && fetchFailures > 0`,
	// not `processedCount == 0`. A scan with NO work at all must not be
	// reported as a failure — there was nothing to look up — and the two
	// clauses are what distinguish it from a scan that tried and got nothing.
	//
	// Those scans arrive here by two different routes, and an earlier draft of
	// this comment claimed both took the first (Codex M54 R7, Low): offline
	// mode and an SBOM with no components return from ScanComponents before
	// this function is called, but an SBOM whose component names are all empty
	// is filtered into an EMPTY work map and does reach here, running the loop
	// zero times and emitting the completion log above.
	// But it does mean "completed" cannot be read as "something was checked"
	// (Codex M54 R3, Critical, against an earlier draft of this comment that
	// promised exactly that). See SbomHandler.runScan for what the status is
	// actually worth.
	return nil
}

// persistWorkItem records one work item's matches: it links every component
// instance that shares the item's (name, version) to each matched CVE, and
// inserts the CVE into the global catalogue if it was not there already.
//
// It is NOT an upsert of the freshly fetched data, and an earlier draft of
// this comment called it one (Codex M54 R3, Critical). Create only runs when
// GetByCVE MISSES. When the CVE is already in the catalogue this function
// writes the LINK and nothing else, so the severity, CVSS score and
// description NVD just returned are discarded and whatever is stored — which
// may be older, or may have come from JVN — is what the project's
// vulnerability page keeps showing. A CVE that NVD has since re-scored from
// LOW to CRITICAL therefore stays LOW until some other path refreshes it.
//
// That refresh gap is pre-existing and is NOT fixed in M54: making the scanner
// overwrite the row on every scan would have it fight the CVE-sync scheduler
// and would let an NVD sweep stamp `source = 'NVD'` over a JVN-authored row.
// Deciding who owns the catalogue's metadata is a design question, not a
// concurrency fix. Reported rather than silently left undocumented.
//
// This is the ONLY place the worker pool touches the database, and it holds
// dbMu for the whole body. That is the M54 correctness boundary described on
// processComponentsParallel: ctx may carry a *sql.Tx shared by up to
// maxConcurrentWithKey goroutines, and *sql.Tx is not safe for concurrent use.
//
// The lock spans GetByCVE as well as the writes, not just the writes:
// QueryRowContext hands back an open *sql.Rows and only Scan closes it, so a
// read left the connection mid-message just as readily as a write does.
//
// It returns the number of statements the DATABASE REFUSED — failed Creates
// plus failed LinkComponents. The caller escalates a non-zero count into a
// scan error (Codex M54 R1, Critical): before that, a run whose every write
// was refused still logged "NVD scan completed" and was marked completed for
// the CLI. A GetByCVE miss is NOT counted: sql.ErrNoRows is this function's
// normal "not in the catalogue yet" branch, i.e. control flow, not failure.
//
// Per-statement failures are logged and skipped rather than aborting the item.
// Do NOT read that as "one bad row only costs that row" — an earlier draft of
// this comment said exactly that and it was wrong (Codex M54 R2, High). On a
// tx-bearing ctx, which is every production caller, PostgreSQL aborts the
// whole transaction at the FIRST refusal: every later statement is refused as
// well, and every earlier one is discarded at rollback. The loss is the whole
// sweep, and TestM54NVDScan_RefusedWritesAreReportedAsFailure measures it at
// 0 durable rows.
//
// What the skipping buys is that the loop keeps going and keeps counting, so
// the returned number does not stop at the first refusal. It is still only a
// count of REFUSALS, not of rows lost (Codex M54 R3, Medium): the writes that
// SUCCEEDED before the first refusal are rolled back too and are counted
// nowhere, so a poison late in a sweep can report "1 refused write" while
// hundreds of rows silently fail to become durable. Treat a non-zero return as
// "this scan lost data, at least this much", never as the size of the loss.
//
// Row-local loss is what the skipping buys on a tx-FREE ctx (Querier falling
// back to the pooled *sql.DB, i.e. autocommit), which no production caller
// uses today.
func (s *NVDService) persistWorkItem(
	ctx context.Context,
	dbMu *sync.Mutex,
	vulns []model.Vulnerability,
	componentIDs []uuid.UUID,
) int {
	dbMu.Lock()
	defer dbMu.Unlock()

	refused := 0
	for i := range vulns {
		vuln := vulns[i]
		existing, err := s.vulnRepo.GetByCVE(ctx, vuln.CVEID)
		if err != nil {
			if err := s.vulnRepo.Create(ctx, &vuln); err != nil {
				slog.Warn("failed to create vulnerability", "cve", vuln.CVEID, "error", err)
				refused++
				continue
			}
			existing = &vuln
		}

		for _, compID := range componentIDs {
			if err := s.vulnRepo.LinkComponent(ctx, compID, existing.ID); err != nil {
				// Kept at Debug for volume (one line per component instance
				// per CVE), but no longer the ONLY trace: the refused count
				// this function returns is what reaches the caller.
				slog.Debug("failed to link component", "component", compID, "vuln", existing.ID, "error", err)
				refused++
			}
		}
	}
	return refused
}

// getVulnerabilitiesWithCache tries cache first, falls back to API
func (s *NVDService) getVulnerabilitiesWithCache(ctx context.Context, name, version string) ([]model.Vulnerability, bool, error) {
	// Try cache first
	if s.cache != nil {
		entry, err := s.cache.Get(ctx, name, version)
		if err != nil {
			slog.Debug("cache get error", "component", name, "error", err)
		} else if entry != nil {
			// Cache hit - convert cached vulns to model
			vulns := make([]model.Vulnerability, len(entry.Vulnerabilities))
			// M46 B2: CachedVuln mirrors the model's pointer fields, so
			// CVSSScore/PublishedAt carry through without sentinels.
			cachedAt := entry.CachedAt
			for i, cv := range entry.Vulnerabilities {
				vulns[i] = model.Vulnerability{
					ID:          uuid.New(),
					CVEID:       cv.CVEID,
					Description: cv.Description,
					Severity:    cv.Severity,
					CVSSScore:   cv.CVSSScore,
					PublishedAt: cv.PublishedAt,
					Source:      "NVD",
					UpdatedAt:   &cachedAt,
				}
			}
			return vulns, true, nil
		}
	}

	// Cache miss - call API
	vulns, err := s.searchByKeyword(ctx, name, version)
	if err != nil {
		return nil, false, err
	}

	// Store in cache
	if s.cache != nil && len(vulns) >= 0 {
		cachedVulns := make([]cache.CachedVuln, len(vulns))
		for i, v := range vulns {
			cachedVulns[i] = cache.CachedVuln{
				CVEID:       v.CVEID,
				Description: v.Description,
				Severity:    v.Severity,
				CVSSScore:   v.CVSSScore,
				PublishedAt: v.PublishedAt,
			}
		}
		if err := s.cache.Set(ctx, name, version, cachedVulns); err != nil {
			slog.Debug("cache set error", "component", name, "error", err)
		}
	}

	return vulns, false, nil
}

// searchByKeyword asks NVD for CVEs matching "<name> <version>".
//
// # Known defect, NOT fixed in M54: the result set is silently truncated
//
// This asks for resultsPerPage=20, decodes ONE response, and returns. It never
// reads NVDResponse.TotalResults and never issues the startIndex follow-ups
// the NVD API requires when totalResults exceeds resultsPerPage. A component
// matching 21+ CVEs therefore contributes its first 20 and the scan reports
// success — the omitted page can hold the critical CVE that should have failed
// the build. Raised by Codex in M54 R2 (Critical) and reported upward rather
// than left undocumented.
//
// It is not fixed here because the repair is a design decision, not a loop.
// Every page costs one rate-limited request (rateLimitWithKey is 700ms), so
// paging exhaustively multiplies a scan's wall time by the match cardinality —
// a keyword like "linux" matches thousands. The real options are to cap
// deliberately and SAY the result is capped, to match on CPE instead of a
// keyword, or to surface truncation as a scan-level warning; picking among
// them is out of scope for a concurrency fix, and doing it badly would make
// every scan of a common library unusably slow.
//
// Until then, callers must read a completed NVD scan as "the first
// resultsPerPage matches per component", not "every match".
func (s *NVDService) searchByKeyword(ctx context.Context, name, version string) ([]model.Vulnerability, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return nil, nil
	}

	keyword := name
	if version != "" {
		keyword = fmt.Sprintf("%s %s", name, version)
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "20")

	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error: %d - %s", resp.StatusCode, string(body))
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}
	if err := nvdResp.validate(); err != nil {
		return nil, err
	}

	return s.convertToVulnerabilities(nvdResp.entries()), nil
}

func (s *NVDService) convertToVulnerabilities(entries []NVDVulnEntry) []model.Vulnerability {
	var vulns []model.Vulnerability

	for _, entry := range entries {
		vuln := model.Vulnerability{
			ID:     uuid.New(),
			CVEID:  entry.CVE.ID,
			Source: "NVD",
		}

		for _, desc := range entry.CVE.Descriptions {
			if desc.Lang == "en" {
				vuln.Description = desc.Value
				break
			}
		}

		score, severity := extractCvss(entry.CVE.Metrics)
		vuln.CVSSScore = score
		vuln.Severity = severity

		vuln.PublishedAt = parseNVDTimestamp(entry.CVE.Published)
		now := time.Now()
		vuln.UpdatedAt = &now

		vulns = append(vulns, vuln)
	}

	return vulns
}

// nvdTimestampLayouts are the shapes NVD actually publishes, most specific
// first.
//
// M54 (Codex R4, Medium): this used to try time.RFC3339 and nothing else.
// RFC3339 REQUIRES an offset, and the NVD CVE API does not send one — its
// `published` / `lastModified` values look like `2024-03-29T17:15:21.150`.
// Measured: time.Parse(time.RFC3339, "2024-03-29T17:15:21.150") fails with
// `cannot parse "" as "Z07:00"`. The error was discarded, so PublishedAt
// stayed nil and EVERY vulnerability this scanner created stored
// published_at = NULL. The API then omitted the field and nothing downstream
// could sort or age a finding by publication date.
//
// The zoneless layouts are read as UTC (time.Parse's default when the layout
// has no zone), which is what the NVD API documents its timestamps to be. The
// offset-bearing RFC3339 form is tried first so a mirror that does send one is
// honoured rather than reinterpreted.
var nvdTimestampLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
}

// parseNVDTimestamp returns nil when the value is absent or in none of the
// known shapes. nil is meaningful here — model.Vulnerability.PublishedAt is a
// pointer precisely so "unknown" is representable rather than being flattened
// to year 1 (M46 B2).
func parseNVDTimestamp(v string) *time.Time {
	if v == "" {
		return nil
	}
	for _, layout := range nvdTimestampLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return &t
		}
	}
	slog.Debug("unparseable NVD timestamp", "value", v)
	return nil
}

// extractCvss returns the CVE's base score and severity. M46 B2: a CVE
// without any CVSS metrics (NVD "Awaiting Analysis") yields a nil score —
// NOT 0.0, which is a real "None" score — so un-scored CVEs are stored as
// NULL and rendered as unscored instead of "safe".
func extractCvss(metrics NVDMetrics) (*float64, string) {
	if m, ok := preferPrimary(metrics.CvssMetricV31); ok {
		return &m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if m, ok := preferPrimary(metrics.CvssMetricV30); ok {
		return &m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	// v4.0 sits BELOW v3.x on purpose (M54, Codex R5 High). Adding it fixes
	// the defect — v4-only CVEs used to land as UNKNOWN — without changing the
	// severity of any CVE that already has a v3 score. Whether v4 should
	// OUTRANK v3 when a CVE carries both is a product decision (it would
	// re-grade existing findings across the whole catalogue), not a bug fix,
	// and is deliberately not taken here.
	if m, ok := preferPrimary(metrics.CvssMetricV40); ok {
		return &m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if m, ok := preferPrimary(metrics.CvssMetricV2); ok {
		// v2 records carry no baseSeverity, so it is derived from the score.
		return &m.BaseScore, scoreToCvss2Severity(m.BaseScore)
	}
	return nil, "UNKNOWN"
}

// preferPrimary picks the assessment to trust from one CVSS version's list.
//
// NVD attaches several assessments to a CVE — its own ("Primary") plus any
// submitted by CNAs and third parties ("Secondary") — and the array order is
// NOT significant. Taking element zero, which this code did until M54, meant
// whichever organisation happened to be listed first decided the severity this
// product reports. Codex R5 (Critical) found a live example where that demotes
// an NVD Primary 9.8/CRITICAL to a Secondary 6.3/MEDIUM.
//
// Primary wins. With no Primary present, the first entry is used, which is the
// previous behaviour and the only thing left to do — every remaining candidate
// is a Secondary and none is privileged over another.
func preferPrimary(metrics []CvssMetric) (CvssData, bool) {
	if len(metrics) == 0 {
		return CvssData{}, false
	}
	for _, m := range metrics {
		if strings.EqualFold(m.Type, "Primary") {
			return m.CvssData, true
		}
	}
	return metrics[0].CvssData, true
}

func scoreToCvss2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// SearchByCVEID searches for a specific CVE by ID from NVD API
// Returns the vulnerability info if found, nil if not found
func (s *NVDService) SearchByCVEID(ctx context.Context, cveID string) (*model.Vulnerability, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return nil, nil
	}

	params := url.Values{}
	params.Set("cveId", cveID)

	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error: %d - %s", resp.StatusCode, string(body))
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %w", err)
	}
	// Same envelope check as searchByKeyword: without it an empty body reads
	// as an authoritative "CVE not found" (Codex M54 R4, Critical).
	if err := nvdResp.validate(); err != nil {
		return nil, err
	}

	if len(nvdResp.entries()) == 0 {
		return nil, nil // CVE not found
	}

	vulns := s.convertToVulnerabilities(nvdResp.entries())
	if len(vulns) == 0 {
		return nil, nil
	}

	// This is a POINT LOOKUP: the request named one cveId, so the answer must
	// be that CVE. Until M54 the first entry was returned unchecked (Codex R7,
	// High), so a mirror — baseURL is operator-overridable for air-gapped
	// deployments — answering a request for CVE-A with CVE-B had its answer
	// accepted, cached and served under A's identity. Substituting a LOW
	// finding for the CRITICAL one that was asked about is the whole attack.
	//
	// Compared through ValidateCVEID's normalisation so case and surrounding
	// whitespace are not treated as a mismatch.
	want, err := validation.ValidateCVEID(cveID)
	if err != nil {
		return nil, fmt.Errorf("SearchByCVEID: %q is not a well-formed CVE ID: %w", cveID, err)
	}
	got, err := validation.ValidateCVEID(vulns[0].CVEID)
	if err != nil {
		return nil, fmt.Errorf("SearchByCVEID: NVD returned a malformed CVE ID %q for %s",
			vulns[0].CVEID, want)
	}
	if got != want {
		return nil, fmt.Errorf("SearchByCVEID: asked NVD for %s and it answered with %s; "+
			"refusing to serve one CVE under another's identity", want, got)
	}

	return &vulns[0], nil
}

// SaveVulnerability saves a vulnerability to the database
func (s *NVDService) SaveVulnerability(ctx context.Context, vuln *model.Vulnerability) error {
	existing, err := s.vulnRepo.GetByCVE(ctx, vuln.CVEID)
	if err != nil {
		// Not found, create new
		return s.vulnRepo.Create(ctx, vuln)
	}
	// Already exists, update ID to use existing
	vuln.ID = existing.ID
	return nil
}
