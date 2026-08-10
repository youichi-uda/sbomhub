package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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

	// nvdPageSize is the resultsPerPage this scanner asks NVD for. It was 20
	// (M55), which is where the silent truncation came from; the value is
	// measured, not guessed.
	//
	// Bigger is strictly better up to the point where ONE page stops fitting
	// inside httpClient.Timeout, because the NVD rate limit counts REQUESTS,
	// not records: a page of 200 and a page of 20 cost the same one token.
	// Measured against the live API on 2026-08-11 (no API key, from this
	// host), keywordSearch=openssl (totalResults=563):
	//
	//	resultsPerPage=20   ->   249 KB   4.4 s
	//	resultsPerPage=200  ->  2.79 MB   1.8 s
	//	resultsPerPage=563  ->  5.87 MB  35.9 s   <- EXCEEDS the 30s client timeout
	//
	// and keywordSearch=linux (totalResults=21670) at resultsPerPage=200:
	// 495 KB in 8.2 s. So the API's own maximum (2000) — and even a single
	// page big enough to hold a 563-match component — is NOT usable here: the
	// request would time out, the component would be counted as a fetch
	// failure, and we would have traded a truncation for a total miss. 200 is
	// the largest size measured to stay well inside the timeout (8.2 s worst
	// observed, 3.6x margin).
	nvdPageSize = 200

	// nvdMaxPagesPerComponent bounds how many pages ONE component may spend.
	// 5 pages x 200 = 1000 matches per component.
	//
	// This is a deliberate budget, not a belief that 1000 is enough for
	// everything — see searchByKeyword for why "fetch everything" is the wrong
	// answer rather than merely the slow one, and for what happens when the
	// budget is exhausted (the result is REPORTED as truncated, never silently
	// returned as complete).
	nvdMaxPagesPerComponent = 5
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
	// StartIndex is a POINTER and is required to equal the startIndex the
	// request asked for (Codex M54 R8, Critical). A mirror returning a
	// DIFFERENT page would otherwise be accepted as a complete, internally
	// consistent answer with the requested page silently missing.
	//
	// M55 made the expected value a parameter rather than the constant 0.
	// searchByKeyword now walks pages, so "which page did I ask for" is no
	// longer always zero — and the check matters MORE once paging exists, not
	// less: a server that answers every follow-up with page 0 would otherwise
	// let the walk collect the same 200 records five times and call the result
	// complete. Measured on the live API 2026-08-11: startIndex is echoed
	// exactly (asked 200 -> answered 200; asked 400 -> answered 400).
	StartIndex *int `json:"startIndex"`
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
//
//  2. totalResults is PRESENT, for the same reason — without this,
//     `{"resultsPerPage":0,"vulnerabilities":[]}` read as an authoritative
//     "no CVEs" (Codex M54 R6, Critical).
//
//  3. the vulnerabilities array is PRESENT (it may be empty — that is the
//     genuine no-matches answer).
//
//  4. the page carries what it says it carries: len(vulnerabilities) equals
//     resultsPerPage, which the NVD schema defines as the number of records in
//     THIS response. A page declaring two and shipping one is silently short,
//     and the missing one may be the finding that mattered.
//
//  5. the page is not empty when the result set says it should not be:
//     totalResults > startIndex with no entries at all is inconsistent even
//     when resultsPerPage agrees (`{"resultsPerPage":0,"totalResults":5,...}`),
//     and must not be read as "no CVEs".
//
//     M55 relaxed the left-hand side from `totalResults > 0` to
//     `totalResults > startIndex`, which is the same rule on page zero and the
//     correct one on a later page. NVD is live data: a result set that SHRINKS
//     between page 1 and page 2 legitimately answers a startIndex=200 request
//     with zero entries and totalResults=150. Under the old form that raced
//     into a hard error and cost the component its whole lookup; it is now the
//     ordinary end-of-walk condition.
//
//  6. startIndex is PRESENT and is the page that was ASKED for — see the field
//     comment. Not "is zero": since M55 the scanner does ask for later pages.
//
//  7. every entry carries a well-formed cve.id. `[{}]` used to satisfy every
//     check above (Codex M54 R7, Critical): it became a vulnerability with
//     CVEID "", which the VARCHAR NOT NULL column accepts, so a nameless row
//     was stored, components were linked to it, no failure counter moved, and
//     the scan completed having persisted nothing identifiable. Worse, cve_id
//     is the ON CONFLICT key, so every such entry across every component
//     collapses onto the same "" row.
//
// What it still does NOT do is verify that the RESULT SET is complete: a page
// of 200 out of totalResults=21670 satisfies every check above, because each of
// them is about THIS page being internally honest, not about the pages that
// were never fetched. Completeness is searchByKeyword's job (M55) and is
// reported through nvdSearchResult.truncated, not through this error.
func (r *NVDResponse) validate(wantStartIndex int) error {
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
	if r.StartIndex == nil {
		return fmt.Errorf("NVD response is missing the startIndex envelope field; " +
			"the endpoint returned 200 but the body is not an NVD CVE API response")
	}
	if *r.StartIndex != wantStartIndex {
		return fmt.Errorf("NVD response is page startIndex=%d; this request asked for "+
			"startIndex=%d, so the requested records would be silently missing",
			*r.StartIndex, wantStartIndex)
	}
	if got, want := len(*r.Vulnerabilities), *r.ResultsPerPage; got != want {
		return fmt.Errorf("NVD response declares resultsPerPage=%d but carries %d entries; "+
			"the page is short of what it claims and the missing entries would be "+
			"silently dropped", want, got)
	}
	if *r.TotalResults > *r.StartIndex && len(*r.Vulnerabilities) == 0 {
		return fmt.Errorf("NVD response claims totalResults=%d from startIndex=%d but carries "+
			"no entries; treating that as 'no vulnerabilities' would silently under-report",
			*r.TotalResults, *r.StartIndex)
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

// NVDScanReport is the accounting for one NVDService sweep.
//
// # Why this type exists (M55)
//
// ScanComponents can only ever tell its caller ONE bit: error or nil. The
// handlers turn that bit into ScanTracker completed/failed, which the CLI turns
// into an exit code and the MCP server into `counts_final`. That is enough for
// the outcomes the product has already decided are failures, and not enough for
// anything it has not.
//
// The specific gap it was added for is the PARTIAL fetch failure: some
// components answered, some did not. Deciding how many may fail before a scan
// is worthless is a product-policy question (a threshold), and this wave
// deliberately does not answer it — but "we have not decided the policy" must
// not mean "the number is unavailable", which is how it was before. The count
// is now returned, so the policy can be written against a number that exists.
//
// Honest limitation: no production caller reads this yet. handler.SbomHandler
// and handler.VulnerabilityHandler both depend on the narrow
// `ScanComponents(ctx, sbomID) error` interface, and ScanTracker has no state
// between completed and failed to carry a partial count into. Wiring it
// through is a change to those files and is out of this wave's scope; what is
// in scope is that the number is counted, logged at WARN, and reachable in-band
// rather than swallowed.
type NVDScanReport struct {
	// UniqueComponents is the number of deduplicated (name, version) work
	// items the sweep was given.
	UniqueComponents int
	// Processed is how many of them produced an answer (from cache or API).
	Processed int
	CacheHits int
	APICalls  int
	// FetchFailures counts work items whose NVD lookup never returned an
	// answer. Processed + FetchFailures == UniqueComponents unless the sweep
	// was cancelled.
	FetchFailures int
	// RefusedWrites counts statements the DATABASE refused. See
	// persistWorkItem: it is a floor on the loss, not its size.
	RefusedWrites int
	// TruncatedComponents counts work items whose match set was provably
	// larger than the paging budget could fetch.
	TruncatedComponents int
	// DroppedMatches is the sum of (totalResults - fetched) over those
	// components: how many matches are known to exist and were not retrieved.
	DroppedMatches int
}

// ScanComponents scans all components in an SBOM for vulnerabilities.
// Uses Redis cache and deduplication for efficiency.
//
// This is the narrow `componentScanner` surface the handlers and the scheduler
// depend on. It is a thin policy wrapper over ScanComponentsWithReport: the
// error it returns is exactly NVDScanReport.incompleteErr, and everything the
// sweep measured is discarded. Callers that want the numbers should use
// ScanComponentsWithReport.
func (s *NVDService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	_, err := s.ScanComponentsWithReport(ctx, sbomID)
	return err
}

// ScanComponentsWithReport is ScanComponents with the sweep's accounting
// returned alongside the error. The report is populated even when the error is
// non-nil — the counts are what the error is derived FROM, so discarding them
// on failure would hide the most interesting cases.
func (s *NVDService) ScanComponentsWithReport(ctx context.Context, sbomID uuid.UUID) (NVDScanReport, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return NVDScanReport{}, nil
	}

	components, err := s.compRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return NVDScanReport{}, fmt.Errorf("failed to get components: %w", err)
	}

	if len(components) == 0 {
		return NVDScanReport{}, nil
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
func (s *NVDService) processComponentsParallel(ctx context.Context, components map[nvdComponentKey][]uuid.UUID) (NVDScanReport, error) {
	report := NVDScanReport{UniqueComponents: len(components)}

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

	// pace is the SAME ticker, handed to searchByKeyword so that the follow-up
	// pages of a multi-page component are rate-limited too (M55).
	//
	// This is the whole reason paging is safe to add. The worker loop below
	// takes one tick per WORK ITEM, which was one request until M55; a walk
	// that issued its extra pages without a tick would let the pool emit up to
	// maxConcurrentWithKey * nvdMaxPagesPerComponent requests inside one tick
	// and blow straight through NVD's published rate (50 requests / 30s with a
	// key). Sharing the ticker keeps the invariant that held before: the whole
	// pool issues at most one NVD request per `rateLimit`, whatever the mix of
	// first pages and follow-ups.
	//
	// A per-worker sleep would NOT do: five workers each pausing rateLimit
	// between their own pages is five times the intended aggregate rate.
	pace := func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rateLimiter.C:
			return nil
		}
	}

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
	// returned an answer (Codex M54 R2, Critical); truncatedComponents and
	// droppedMatches count work items whose match set was provably bigger than
	// the paging budget (M55). See the returns at the bottom of this function
	// for exactly which combinations are escalated.
	refusedWrites := 0
	fetchFailures := 0
	truncatedComponents := 0
	droppedMatches := 0

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

				lookup, err := s.getVulnerabilitiesWithCache(ctx, work.key.Name, work.key.Version, pace)
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

				if lookup.truncated {
					// Per-component, at WARN, with the numbers: an operator
					// reading only the aggregate below cannot tell WHICH
					// component's match set was cut off, and that is the one
					// thing they need in order to act (pin a version, add a
					// purl, or accept the noise).
					slog.Warn("nvd: component match set truncated",
						"component", work.key.Name,
						"version", work.key.Version,
						"fetched", lookup.fetched,
						"total", lookup.total,
						"page_size", nvdPageSize,
						"page_budget", nvdMaxPagesPerComponent)
				}

				mu.Lock()
				processedCount++
				if lookup.fromCache {
					cacheHits++
				} else {
					apiCalls++
				}
				if lookup.truncated {
					truncatedComponents++
					droppedMatches += lookup.total - lookup.fetched
				}
				mu.Unlock()

				// Link vulnerabilities to all component instances
				refused := s.persistWorkItem(ctx, &dbMu, lookup.vulns, work.componentIDs)
				if refused > 0 {
					mu.Lock()
					refusedWrites += refused
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()

	report.Processed = processedCount
	report.CacheHits = cacheHits
	report.APICalls = apiCalls
	report.RefusedWrites = refusedWrites
	report.FetchFailures = fetchFailures
	report.TruncatedComponents = truncatedComponents
	report.DroppedMatches = droppedMatches

	// The summary is WARN, not INFO, whenever the sweep is known to be less
	// than complete (M55). A PARTIAL fetch failure is not escalated into a scan
	// error — that needs a threshold, which is a product decision — but it is
	// not swallowed either: the count is in this line, and it is in the report
	// this function returns.
	//
	// "component scan completed" at INFO with fetch_failures=37 buried in it
	// was the previous shape, and it reads as success to everything that
	// filters on level.
	logArgs := []any{
		"processed", processedCount,
		"unique_components", report.UniqueComponents,
		"cache_hits", cacheHits,
		"api_calls", apiCalls,
		"refused_writes", refusedWrites,
		"fetch_failures", fetchFailures,
		"truncated_components", truncatedComponents,
		"dropped_matches", droppedMatches,
	}
	if fetchFailures > 0 || truncatedComponents > 0 || refusedWrites > 0 {
		slog.Warn("component scan completed with incomplete coverage", logArgs...)
	} else {
		slog.Info("component scan completed", logArgs...)
	}

	return report, report.incompleteErr()
}

// incompleteErr is the ONE bit ScanComponents is able to hand its caller: the
// error that turns into ScanTracker.MarkFailed, scan_state "failed",
// `counts_final: false` in the MCP server, and exit 2 from `sbomhub scan`.
//
// Everything it escalates has the same shape — the scan's results are known to
// be less than what the scan claims to have looked for — and everything it does
// NOT escalate is listed at the bottom, because a reader needs both halves to
// know what a nil return is worth.
func (r NVDScanReport) incompleteErr() error {
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
	if r.RefusedWrites > 0 {
		return fmt.Errorf("nvd: database refused %d vulnerability write(s); scan results are incomplete", r.RefusedWrites)
	}

	// TOTAL fetch failure: every work item was asked about and none answered,
	// so this scan has ZERO coverage. Codex M54 R2 (Critical) was right that
	// the first cut hid this behind the policy argument below — deciding that
	// no component was successfully checked requires no threshold, and
	// reporting "completed, 0 vulnerabilities" for it is the same
	// silent-data-loss shape as the refused writes above. `sbomhub scan
	// --fail-on critical` would exit 0 on an NVD outage.
	//
	// The condition is deliberately Processed == 0 rather than
	// FetchFailures > 0: it fires only when NOTHING got through.
	if r.Processed == 0 && r.FetchFailures > 0 {
		return fmt.Errorf("nvd: all %d component lookup(s) failed; the scan has no coverage", r.FetchFailures)
	}

	// TRUNCATED RESULT SET (M55). At least one component matched more CVEs than
	// the paging budget could fetch, so the findings recorded for it are a
	// PREFIX of its match set and the omitted tail may hold the critical CVE.
	//
	// Escalating needs no threshold, which is what separates it from the
	// partial fetch failure below: we are not estimating how much coverage is
	// enough, we are reporting that NVD itself told us how many matches exist
	// and we did not fetch them. searchByKeyword makes this rare by
	// construction — every versioned component in the measured distribution
	// fits in one page — so what reaches here is the component whose keyword
	// stopped being a match query at all, and that is precisely the case an
	// operator must not read as "checked, clean".
	//
	// The cost of escalating, stated plainly because it is real: ScanTracker
	// marks the whole scan failed, and `sbomhub scan --fail-on <sev>` then
	// exits 2 WITHOUT evaluating the threshold, so a critical that WAS fetched
	// no longer produces exit 1. Exit 2 is still non-zero, so a CI job that
	// checks for success fails either way; what is lost is only the
	// distinction, and what is gained is that a scan which provably did not
	// see everything can never be read as a clean bill of health. The
	// alternative — stay silent and let the count look authoritative — is the
	// failure mode this product exists to prevent.
	if r.TruncatedComponents > 0 {
		return fmt.Errorf("nvd: %d component(s) matched more CVEs than the paging budget "+
			"(%d pages x %d) could fetch; %d known match(es) were not retrieved and the "+
			"findings for those components are incomplete",
			r.TruncatedComponents, nvdMaxPagesPerComponent, nvdPageSize, r.DroppedMatches)
	}

	// STILL NOT escalated, and this is the honest remainder: a PARTIAL fetch
	// failure (some components answered, some did not). Turning that into a
	// scan failure needs a threshold — how many components may fail before the
	// scan is worthless? — and that is a product-policy decision, not a bug
	// fix. It stays tracked as the ※要確認 threshold noted on
	// SbomHandler.runScan.
	//
	// M55 changed what "not escalated" costs, without taking that decision:
	// NVDScanReport.FetchFailures now carries the count out of the sweep, and
	// the summary above logs at WARN when it is non-zero. So the policy, when
	// it is written, can be written against a number that already exists, and
	// in the meantime a partial failure is visible instead of being absorbed
	// into an INFO line that says "completed".
	//
	// Note that the guard above is `Processed == 0 && FetchFailures > 0`,
	// not `Processed == 0`. A scan with NO work at all must not be
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

// nvdLookup is one work item's outcome: the matches plus everything the caller
// needs in order to describe how sound they are.
type nvdLookup struct {
	vulns     []model.Vulnerability
	fromCache bool
	// truncated, total and fetched are always false/0 for a cache hit — see
	// getVulnerabilitiesWithCache for why a truncated result is never cached
	// in the first place.
	truncated bool
	total     int
	fetched   int
}

// getVulnerabilitiesWithCache tries cache first, falls back to API.
func (s *NVDService) getVulnerabilitiesWithCache(ctx context.Context, name, version string, pace nvdPacer) (nvdLookup, error) {
	// Try cache first
	if s.cache != nil {
		entry, err := s.cache.Get(ctx, name, version)
		if err != nil {
			slog.Debug("cache get error", "component", name, "error", err)
		} else if entry != nil {
			// Cache hit - convert cached vulns to model.
			//
			// The cache is NOT a trusted source (Codex M54 R8, Critical). The
			// R7 cve.id check and the R8 canonicalisation both live on the
			// HTTP path, so a cache hit used to reach the database having
			// passed neither. Entries written by a pre-M54 build are still in
			// Redis after an upgrade, and NVD results are cached BEFORE their
			// PostgreSQL writes — so a malformed id could be served from cache
			// indefinitely, stored as CVEID "" (VARCHAR NOT NULL accepts it),
			// and linked to components with no failure counter moving.
			//
			// Same treatment as the wire: canonicalise, and refuse what does
			// not validate.
			//
			// A malformed entry makes the whole cache record untrustworthy, so
			// the record is DISCARDED and the lookup falls through to the API
			// (M54, Codex R9 Critical). The R8 cut filtered the bad entries out
			// and returned the remainder AS A CACHE HIT, which its own comment
			// described as something the scan "can simply re-fetch" — it did
			// not re-fetch. A record whose entries were all malformed became an
			// empty, successful, zero-finding lookup with no HTTP request at
			// all; a mixed one silently lost the malformed findings.
			cachedAt := entry.CachedAt
			vulns := make([]model.Vulnerability, 0, len(entry.Vulnerabilities))
			usable := true
			for _, cv := range entry.Vulnerabilities {
				canonical, err := validation.ValidateCVEID(cv.CVEID)
				if err != nil {
					slog.Warn("discarding cached NVD record: malformed CVE ID",
						"component", name, "version", version, "cve", cv.CVEID)
					usable = false
					break
				}
				// M46 B2: CachedVuln mirrors the model's pointer fields, so
				// CVSSScore/PublishedAt carry through without sentinels.
				vulns = append(vulns, model.Vulnerability{
					ID:          uuid.New(),
					CVEID:       canonical,
					Description: cv.Description,
					Severity:    cv.Severity,
					CVSSScore:   cv.CVSSScore,
					PublishedAt: cv.PublishedAt,
					Source:      "NVD",
					UpdatedAt:   &cachedAt,
				})
			}
			if usable {
				return nvdLookup{vulns: vulns, fromCache: true}, nil
			}
			// Fall through to the API below, exactly as a cache miss would.
		}
	}

	// Cache miss - call API
	res, err := s.searchByKeyword(ctx, name, version, pace)
	if err != nil {
		return nvdLookup{}, err
	}
	vulns := res.vulns

	// Store in cache — but NOT a truncated result (M55).
	//
	// cache.VulnCacheEntry has no field for "this is a prefix of the match
	// set", and it is served back as an ordinary complete answer. Caching a
	// truncated lookup would therefore launder it: the scan that fetched it
	// would report the truncation, and every scan for the next NVDCacheTTL
	// (24h) would serve the same short list and report NOTHING, because the
	// cache branch above returns before searchByKeyword is ever reached. The
	// signal would survive exactly one scan and then disappear.
	//
	// Not caching costs those components a full walk on every scan. That is
	// the right way round: they are the components whose answers we already
	// know to be incomplete, and by the measured distribution there are very
	// few of them (see searchByKeyword).
	if s.cache != nil && !res.truncated {
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

	return nvdLookup{
		vulns:     vulns,
		truncated: res.truncated,
		total:     res.total,
		fetched:   res.fetched,
	}, nil
}

// nvdSearchResult is one component's keyword lookup, including how much of the
// match set it actually managed to see.
//
// `truncated` exists so that "we saw everything" and "we saw the first N" are
// different values rather than the same slice. Before M55 they were the same
// slice.
type nvdSearchResult struct {
	// vulns are the matches, de-duplicated by canonical CVE id.
	vulns []model.Vulnerability
	// fetched is how many RECORDS the walk consumed (pre-dedup), i.e. how far
	// into the result set it got. Compared against total to decide truncation.
	fetched int
	// total is totalResults as NVD last reported it. NVD is live, so a walk
	// can see this change between pages; the last value wins.
	total int
	// pages is the number of HTTP requests this lookup issued.
	pages int
	// truncated is true when the result set is provably larger than what was
	// fetched. It is never inferred from a heuristic — only from NVD's own
	// totalResults.
	truncated bool
}

// nvdPacer blocks until the sweep's shared rate limiter allows one more NVD
// request, or the context ends. nil means "unpaced" (a caller outside the
// worker pool, e.g. a test driving one lookup against an httptest server).
//
// It is a parameter rather than a field on NVDService because the limiter is
// per-SCAN, not per-process: processComponentsParallel creates one ticker for
// the whole sweep, and that is the only thing that keeps the POOL — up to
// maxConcurrentWithKey workers — inside NVD's published rate.
type nvdPacer func(ctx context.Context) error

// searchByKeyword asks NVD for CVEs matching "<name> <version>" and walks the
// result set, up to a budget, reporting whether it saw all of it.
//
// # What was wrong before M55
//
// It asked for resultsPerPage=20, decoded ONE response, and returned. It never
// read NVDResponse.TotalResults and never issued the startIndex follow-ups the
// NVD API requires when totalResults exceeds resultsPerPage, so a component
// matching 21+ CVEs contributed its first 20 and the scan reported success.
// Raised by Codex in M54 R2 (Critical).
//
// That was not a corner case. Measured against the live API on 2026-08-11
// (one request per keyword, resultsPerPage=1, reading totalResults), building
// each keyword exactly as this function does:
//
//	jackson-databind 2.9.10   44      <- 24 matches dropped, silently
//	libxml2 2.9.10             4
//	glibc 2.31                 3
//	tomcat 9.0.30              3
//	openssl 1.1.1k             2
//	express 4.17.1             2
//	lodash 4.17.20             1
//	log4j-core 2.14.1          0
//	spring-core 5.3.18         0
//	curl 7.68.0                0
//	busybox 1.32.0             0
//	python 3.8.10              0
//	zlib 1.2.11                0
//	lodash                    16
//	log4j                     32
//	curl                     322      <- 302 dropped
//	openssl                  563      <- 543 dropped
//	linux                  21670      <- 21650 dropped
//
// Two things follow, and they pull in opposite directions.
//
// # Why the fix is mostly a bigger page, not a longer loop
//
// A VERSIONED keyword is precise: NVD's keywordSearch requires every word to
// appear in the CVE description, so "jackson-databind 2.9.10" matches 44 and
// the rest match single digits. Everything in that half of the table fits in
// ONE page of nvdPageSize=200 — which costs exactly the same single
// rate-limited request as the old page of 20. For the SBOMs this product
// actually scans (syft / trivy output, where components carry versions), the
// truncation is therefore repaired at zero additional request cost and zero
// additional wall time.
//
// # Why "just fetch everything" is wrong, not merely slow
//
// An UNVERSIONED keyword is not a match query at all, it is a text search:
// "linux" matches 21670 CVEs. Fetching them all would cost 109 pages
// (76 seconds of rate limit for ONE component with an API key, 11 minutes
// without one) — and then LINK ALL 21670 to that component, because that is
// what persistWorkItem does with whatever this function returns. The product
// would report twenty-one thousand findings against one component, none of
// them evidence of anything. Exhaustive paging makes the answer worse, not
// just later.
//
// So the budget is not a compromise between correctness and speed. It is the
// line past which the query has stopped being a vulnerability match, and the
// honest thing to do at that line is to say the result is incomplete rather
// than to keep spending requests on noise. That is what `truncated` is for and
// what processComponentsParallel escalates.
//
// # What the budget costs, in requests
//
// Requests for one component = min(ceil(totalResults / 200), 5). Against the
// measured table above: every versioned component costs 1 (as today), "curl"
// costs 2, "openssl" costs 3, "linux" costs 5 and is reported truncated. A
// 500-component SBOM of versioned components therefore still costs 500
// requests — 350 s with an API key at rateLimitWithKey, unchanged from before
// this fix. The pathological upper bound is 5x that, and it requires an SBOM
// whose components are ALL unversioned generic words.
//
// # What is deliberately NOT done here
//
// Matching on CPE (cpeName / virtualMatchString) instead of a keyword is the
// real root fix for the precision half of the problem — it would replace a
// description text search with NVD's own affected-configuration data, and the
// unversioned blow-up above would simply not exist. It is out of this wave's
// scope because it changes what a "match" MEANS for every component in the
// product (and needs component CPE/purl mapping that this function does not
// have), not because it was overlooked.
func (s *NVDService) searchByKeyword(ctx context.Context, name, version string, pace nvdPacer) (nvdSearchResult, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return nvdSearchResult{}, nil
	}

	keyword := name
	if version != "" {
		keyword = fmt.Sprintf("%s %s", name, version)
	}

	var out nvdSearchResult
	// seen de-duplicates by canonical CVE id ACROSS pages. NVD is live and
	// ordering is not promised to be stable, so a record can legitimately
	// appear on two pages of one walk; without this the component would be
	// linked to it twice and the finding count would be inflated.
	seen := make(map[string]struct{})

	for out.pages < nvdMaxPagesPerComponent {
		// Every page after the first is an EXTRA request that the worker
		// pool's per-work-item tick did not pay for, so it takes its own tick.
		// Without this the pool would issue up to maxConcurrentWithKey * 5
		// requests per tick and blow through NVD's published rate.
		if out.pages > 0 && pace != nil {
			if err := pace(ctx); err != nil {
				return nvdSearchResult{}, err
			}
		}

		page, err := s.fetchPage(ctx, keyword, out.fetched)
		if err != nil {
			// A failure partway through a walk is a failure of the whole
			// lookup, not a partial success: returning the pages we did get
			// would be exactly the silent under-report this function exists to
			// stop, only with a nicer-looking count.
			return nvdSearchResult{}, err
		}
		out.pages++
		out.total = *page.TotalResults

		entries := page.entries()
		for _, v := range s.convertToVulnerabilities(entries) {
			if _, dup := seen[v.CVEID]; dup {
				continue
			}
			seen[v.CVEID] = struct{}{}
			out.vulns = append(out.vulns, v)
		}
		out.fetched += len(entries)

		// No progress. Reachable when the result set SHRANK mid-walk (see
		// validate's totalResults > startIndex rule) and as a belt-and-braces
		// guard against a mirror that answers a later page with an empty one:
		// without it the walk would re-request the same startIndex until the
		// budget ran out and then call the component truncated.
		if len(entries) == 0 {
			break
		}
		if out.fetched >= out.total {
			break
		}
	}

	out.truncated = out.fetched < out.total
	return out, nil
}

// fetchPage issues ONE NVD keyword request and returns the validated envelope.
//
// startIndex is sent explicitly on every page, page zero included. The
// alternative — omitting it on the first page, as the pre-M55 code did — would
// leave validate with nothing to compare against on the request that matters
// most, and the parameter is documented as defaulting to 0 anyway (verified
// against the live API on 2026-08-11: an explicit startIndex=0 answers
// identically to omitting it).
func (s *NVDService) fetchPage(ctx context.Context, keyword string, startIndex int) (*NVDResponse, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", strconv.Itoa(nvdPageSize))
	params.Set("startIndex", strconv.Itoa(startIndex))

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

	return decodeNVDResponse(resp.Body, startIndex)
}

// decodeNVDResponse decodes exactly ONE JSON value from r, requires nothing to
// follow it, and validates the envelope.
//
// The "nothing to follow it" half is not pedantry (Codex M54 R8, Critical).
// json.Decoder.Decode reads a single value and stops; a body such as
// `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`
// followed by a second document, or by garbage, decodes without error. So a
// proxy or mirror could prefix an empty-result envelope to anything at all and
// have the scan accept it as an authoritative "this component has no CVEs".
//
// The check is a SECOND Decode that must return io.EOF, not dec.More()
// (Codex M54 R9, Critical). More() returns a bool and collapses every error
// from its lookahead into false, so a transfer that was cut short right after
// a complete envelope — a server that declared a longer body and closed —
// reported "nothing follows" and the truncated response was accepted as
// authoritative. Measured: with a reader that returns io.ErrUnexpectedEOF
// after the body, More() is false while a second Decode returns
// "unexpected EOF". Requiring io.EOF separates the three outcomes that matter:
// clean end, trailing content, and a broken transfer.
func decodeNVDResponse(r io.Reader, wantStartIndex int) (*NVDResponse, error) {
	dec := json.NewDecoder(r)
	var out NVDResponse
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	var trailing json.RawMessage
	switch err := dec.Decode(&trailing); {
	case errors.Is(err, io.EOF):
		// The only acceptable outcome: the body held exactly one value.
	case err == nil:
		return nil, fmt.Errorf("NVD response has trailing content after the JSON body; " +
			"the endpoint returned 200 but the body is not a single NVD CVE API response")
	default:
		return nil, fmt.Errorf("NVD response body did not end cleanly: %w", err)
	}
	if err := out.validate(wantStartIndex); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *NVDService) convertToVulnerabilities(entries []NVDVulnEntry) []model.Vulnerability {
	var vulns []model.Vulnerability

	for _, entry := range entries {
		// Store the CANONICAL id, not the wire form (Codex M54 R8, High).
		// validate() accepts an id after trimming and upper-casing, but
		// `vulnerabilities.cve_id` is UNIQUE and compared exactly, and
		// GetByCVE matches exactly — so persisting "cve-2021-44228" would
		// create a SECOND catalogue row alongside "CVE-2021-44228", splitting
		// the component links, the KEV/EPSS enrichment and the severity
		// metadata across two identities for one vulnerability.
		//
		// Unparseable ids cannot reach here: validate() rejects the whole
		// response first. The error branch is a belt-and-braces skip rather
		// than a silent pass-through of the raw value.
		canonical, err := validation.ValidateCVEID(entry.CVE.ID)
		if err != nil {
			slog.Warn("dropping NVD entry with a malformed CVE ID", "cve", entry.CVE.ID)
			continue
		}
		vuln := model.Vulnerability{
			ID:     uuid.New(),
			CVEID:  canonical,
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

	// Same decode + envelope contract as searchByKeyword: without it an empty
	// body reads as an authoritative "CVE not found" (Codex M54 R4, Critical)
	// and a body with trailing content is accepted whole (R8, Critical).
	//
	// startIndex 0: this is a POINT lookup by cveId, it sends no startIndex,
	// and it does not page — a cveId query answers with at most one record, so
	// there is nothing to walk.
	nvdResp, err := decodeNVDResponse(resp.Body, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %w", err)
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
