package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// 5 pages reach offset 996: nvdPageSize on the first page and
	// nvdPageSize-1 on each of the rest, because every follow-up page spends
	// its first record on the boundary anchor (see nvdSearchResult.shifted).
	//
	// This is a deliberate budget, not a belief that 996 is enough for
	// everything — see searchByKeyword for why "fetch everything" is the wrong
	// answer rather than merely the slow one, and for what happens when the
	// budget is exhausted (the result is REPORTED as truncated, never silently
	// returned as complete).
	nvdMaxPagesPerComponent = 5

	// nvdCPEMaxPagesPerComponent is the page budget of ONE CPE lookup walk
	// (cpeName or the product walk) — M60 decision 2. It is larger than the
	// keyword budget because the reason the keyword budget is small does not
	// apply: a keyword match set past ~1000 records is text-search noise
	// (anti-pattern 117), while a CPE answer is NVD's affected-configuration
	// data, verified record by record.
	//
	// Sized from measurement plus margin. Measured 2026-11-08 (live NVD):
	// cpeName for linux_kernel 5.10.46 has totalResults=7059, i.e. 36 pages.
	// 60 pages reach 200 + 59*199 = 11,941 records (69% headroom; kernel CVE
	// counts grow by thousands a year). Past that the answer is reported
	// truncated exactly as before.
	//
	// Cost: every page is one NVD request paced by the sweep's shared limiter
	// (walkNVD's pacer), so the published rate limit holds: a full kernel is
	// ~36 requests = ~3.6 min without an API key (6 s/request) or ~25 s with
	// one; the 60-page worst case is 6 min / 42 s. Each page is one request
	// under the 30 s client timeout (a 200-record kernel page measured 2.0 s,
	// 2 MB). The whole scan is bounded by SBOMHUB_SCAN_DEADLINE (M62).
	nvdCPEMaxPagesPerComponent = 60

	// nvdClientTimeout bounds ONE NVD request. It was 30 s; the M60 kernel run
	// (2026-11-08, live NVD) measured deep kernel pages of 200 records at
	// 15-36 s, one of them 35.8 s at NVD itself, so 30 s failed a full kernel
	// walk. 60 s covers the measured worst case with headroom. It bounds a
	// single request; the scan is bounded by SBOMHUB_SCAN_DEADLINE (M62).
	nvdClientTimeout = 60 * time.Second
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
	// paceInterval, when > 0, overrides the rate-limit interval (tests only;
	// production always paces at rateLimitWithKey / rateLimitWithoutKey).
	paceInterval time.Duration
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
		httpClient: &http.Client{Timeout: nvdClientTimeout},
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
		httpClient: &http.Client{Timeout: nvdClientTimeout},
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
	// total-fetch-failure guard in fetchComponents.
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
	// Configurations is NVD's affected-configuration data, read by the CPE
	// path (M60, verifyCPEMatch). The keyword path ignores it.
	Configurations []NVDConfiguration `json:"configurations"`
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
	// baseScoreMissing is set by UnmarshalJSON (nvd_cvss.go) when the wire
	// carried no baseScore or null — NOT a 0.0 score (Codex M67 R3, High).
	baseScoreMissing bool
}

// nvdComponentKey is used for deduplication in NVD scanning.
//
// M60: two components with the same (name, version) but different CPE lists
// or a different distro-ness are different work — their candidates differ —
// so both are part of the key. CPEKey is a length-prefixed encoding of the
// ordered CPE candidate queries (injective for the same reason nvdCacheName
// is); see nvdWorkKey.
type nvdComponentKey struct {
	Name    string
	Version string
	CPEKey  string
	Distro  bool
}

// nvdWorkItem is one deduplicated unit of NVD work.
type nvdWorkItem struct {
	key          nvdComponentKey
	componentIDs []uuid.UUID
	// candidates are the CPE candidates to try (M60); empty means the
	// keyword path only.
	candidates []cpeCandidate
	distro     bool
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
// Since M62 the scheduler reads it (NewVulnerabilities), and every reason the
// sweep is incomplete reaches the handlers through the error's sentinels
// (ScanReasons), so a partial count is reported as scan-status `reasons`.
type NVDScanReport struct {
	// UniqueComponents is the number of deduplicated (name, version) work
	// items the sweep was given.
	UniqueComponents int
	// Processed is how many of them produced an answer (from cache or API).
	Processed int
	// CacheHits is how many were served from Redis without any HTTP request.
	// Processed - CacheHits is therefore the number of lookups that went to
	// the network, which is NOT the same as APICalls below.
	CacheHits int
	// APICalls is how many NVD HTTP REQUESTS the sweep issued — not how many
	// lookups went to the network (Codex M55 R1, Low). One lookup can spend up
	// to nvdMaxPagesPerComponent requests, and a lookup that FAILED partway
	// still spent the requests it made. This is the number to compare against
	// NVD's published rate limit.
	APICalls int
	// FetchFailures counts work items whose NVD lookup never returned an
	// answer. Processed + FetchFailures + Unscanned == UniqueComponents.
	FetchFailures int
	// RefusedWrites counts writes the DATABASE refused: catalogue inserts
	// (resolveMatches) plus links (ScanScope.writeLinks — a refused link
	// counts every link of its work item, which is rolled back to its
	// savepoint). It is a floor on the loss, not its size.
	RefusedWrites int
	// TruncatedComponents counts work items whose match set the sweep could
	// not prove it saw in full — the paging budget ran out, or the result set
	// shifted underneath the page walk.
	TruncatedComponents int
	// DroppedMatches is the sum of (totalResults - fetched) over those
	// components: how many matches are known to exist and were not retrieved.
	// It is a FLOOR, not the size of the loss: a shifted walk contributes 0
	// because it cannot say how many records slid past its offsets.
	DroppedMatches int

	// M60 — how the work items were matched.
	//
	// CPEMatched counts work items answered by the CPE path (including a
	// verified "no CVE at this version"). KeywordOnly counts items that had
	// no CPE candidate at all; KeywordFallback counts items that HAD
	// candidates, none of which named a product NVD knows. Both of the
	// latter produce nvd_keyword (low-confidence) links.
	CPEMatched      int
	KeywordOnly     int
	KeywordFallback int
	// CPERejected counts records NVD returned for a cpeName query that the
	// local configuration check refused (the product only appears as a
	// vulnerable=false platform, or no range covers the version).
	CPERejected int
	// CPEUndecidable counts records KEPT although the local version
	// comparison could not decide them (NVD's own evaluation returned them).
	CPEUndecidable int

	// M62 — interruption and the write phase.
	//
	// Unscanned counts work items never looked up because the scan's context
	// ended first (an item whose lookup was cut off by it counts here, not
	// in FetchFailures). DeadlineExceeded / Cancelled say which: the overall
	// scan deadline (SBOMHUB_SCAN_DEADLINE) or another cancellation.
	Unscanned        int
	DeadlineExceeded bool
	Cancelled        bool
	// NewVulnerabilities is how many distinct vulnerabilities became linked
	// to the SBOM in this sweep's write transaction (0 if it did not commit).
	NewVulnerabilities int
	// LinksWritten counts links the write phase attempted and committed.
	LinksWritten int
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
	// M62: no transaction may be open while this sweep talks to NVD. The
	// scope check refuses a tx-bearing context outright; see scan_scope.go.
	// It runs before the offline short-circuit so the contract does not
	// depend on the mode (Codex M62 R1 Low).
	scope, err := scanScopeFrom(ctx)
	if err != nil {
		return NVDScanReport{}, err
	}
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return NVDScanReport{}, nil
	}

	// Phase 1 — read, in a short tenant transaction.
	var components []model.Component
	if err := scope.readTx(ctx, func(txCtx context.Context) error {
		var lerr error
		components, lerr = s.compRepo.ListScanTargetsBySbom(txCtx, sbomID)
		return lerr
	}); err != nil {
		return NVDScanReport{}, fmt.Errorf("failed to get components: %w", err)
	}

	if len(components) == 0 {
		return NVDScanReport{}, nil
	}

	slog.Info("starting component scan", "sbom_id", sbomID, "component_count", len(components))

	// Deduplicate components by name+version (+ CPE list and distro-ness,
	// which decide the CPE candidates — M60).
	uniqueComponents := make(map[nvdComponentKey]*nvdWorkItem)
	for _, comp := range components {
		if comp.Name == "" {
			continue
		}
		distro := isDistroComponent(comp.Purl)
		key := nvdWorkKey(comp.Name, comp.Version, comp.CPEs, comp.Purl)
		item, ok := uniqueComponents[key]
		if !ok {
			item = &nvdWorkItem{
				key:        key,
				candidates: cpeCandidates(comp.CPEs, comp.Version, comp.Purl),
				distro:     distro,
			}
			uniqueComponents[key] = item
		}
		item.componentIDs = append(item.componentIDs, comp.ID)
	}

	slog.Info("deduplicated components", "unique_count", len(uniqueComponents), "total_count", len(components))

	// Phase 2 — fetch, with no transaction. Each answer's catalogue rows are
	// resolved as it arrives (autocommit / catalogue pool) and its links are
	// queued for phase 3.
	var mu sync.Mutex
	var groups [][]pendingLink
	catalogueRefused := 0
	report := s.fetchComponents(ctx, uniqueComponents, func(item *nvdWorkItem, l nvdLookup) {
		g, refused := s.resolveMatches(ctx, l, item.componentIDs)
		mu.Lock()
		groups = append(groups, g)
		catalogueRefused += refused
		mu.Unlock()
	})

	// Phase 3 — write, one short locked tenant transaction. It runs even when
	// the deadline fired: what was verified before it is committed (M60's
	// "keep verified pages, report truncated" rule), and the report says the
	// scan is incomplete.
	refused, newVulns, werr := scope.writeLinks(ctx, sbomID, groups, func(txCtx context.Context, l pendingLink) error {
		return s.vulnRepo.LinkComponent(txCtx, l.componentID, l.vulnID, l.method)
	})
	if werr != nil {
		slog.Warn("nvd: write phase failed; no link of this sweep was committed", "sbom_id", sbomID, "error", werr)
	}
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	report.RefusedWrites = catalogueRefused + refused
	report.LinksWritten = total - refused
	report.NewVulnerabilities = newVulns

	s.logSweepSummary(sbomID, report)
	return report, report.incompleteErr()
}

// fetchComponents is phase 2 of a sweep: it looks every work item up on NVD in
// parallel under the sweep's shared rate limiter and hands each answer to
// onLookup. It touches no database itself and must not be called with a
// transaction open (ScanComponentsWithReport guarantees that).
//
// # Concurrency (M54, revised M62)
//
// Until M62 every worker wrote its links on the caller's *sql.Tx, which is not
// safe for concurrent use (lib/pq desynchronised — `pq: unexpected Parse
// response 'C'` — and the whole sweep was lost; measured 2026-08-05), so a
// per-sweep mutex serialised the database section. Workers no longer share a
// transaction: onLookup resolves catalogue rows on the pool (safe for
// concurrent use) and only queues links, which phase 3 writes from one
// goroutine. The mutex is gone because what it protected is gone.
//
// # Interruption (M62)
//
// When ctx ends — the scan deadline or a cancellation — workers stop taking
// items, an in-flight lookup returns what it may keep (a CPE walk — not a
// keyword walk — cut off by the DEADLINE keeps its validated pages as a
// truncated answer;
// see partialWalk) or an error, and the items never answered are counted in
// Unscanned rather than FetchFailures: they did not fail, they were not
// tried. Before M62 an interrupted sweep returned nil — "completed" — for the
// items it never reached.
func (s *NVDService) fetchComponents(ctx context.Context, components map[nvdComponentKey]*nvdWorkItem, onLookup func(*nvdWorkItem, nvdLookup)) NVDScanReport {
	report := NVDScanReport{UniqueComponents: len(components)}

	maxWorkers := maxConcurrentNoKey
	rateLimit := rateLimitWithoutKey
	if s.apiKey != "" {
		maxWorkers = maxConcurrentWithKey
		rateLimit = rateLimitWithKey
	}
	if s.paceInterval > 0 {
		rateLimit = s.paceInterval
	}

	workChan := make(chan *nvdWorkItem, len(components))
	for _, item := range components {
		workChan <- item
	}
	close(workChan)

	// Rate limiter - shared across workers
	rateLimiter := time.NewTicker(rateLimit)
	defer rateLimiter.Stop()

	// pace is the SAME ticker, handed to the page walks so that follow-up
	// pages are rate-limited too (M55): the whole pool issues at most one NVD
	// request per `rateLimit`, whatever the mix of first pages and follow-ups.
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

				lookup, err := s.lookupComponent(ctx, *work, pace)
				if err != nil {
					if scanInterruption(ctx) != nil {
						// Cut off by the deadline / cancellation, not a
						// failure of NVD: counted in Unscanned below.
						mu.Lock()
						report.APICalls += lookup.requests
						mu.Unlock()
						return
					}
					slog.Warn("failed to get vulnerabilities",
						"component", work.key.Name,
						"version", work.key.Version,
						"error", err)
					mu.Lock()
					report.FetchFailures++
					// The requests a FAILED walk already spent still count
					// against NVD's rate limit (Codex M55 R1, Low).
					report.APICalls += lookup.requests
					mu.Unlock()
					continue
				}

				if lookup.partialFailure && scanDeadlineFired(ctx) {
					// The deadline cut this walk short. Every item may still
					// have answered (Unscanned == 0), so this is what makes
					// the report say the deadline fired (Codex M62 R1 High).
					mu.Lock()
					report.DeadlineExceeded = true
					mu.Unlock()
				}
				if lookup.truncated {
					// Per-component, at WARN, with the numbers: an operator
					// reading only the aggregate cannot tell WHICH component's
					// match set was cut off.
					reason := "paging budget exhausted"
					switch {
					case lookup.partialFailure && scanDeadlineFired(ctx):
						reason = "the scan deadline fired partway through the walk; the pages before it were kept"
					case lookup.partialFailure:
						reason = "a page failed partway through the walk; the pages before it were kept"
					case lookup.shifted:
						reason = "result set changed underneath the page walk"
					}
					slog.Warn("nvd: component match set truncated",
						"component", work.key.Name,
						"version", work.key.Version,
						"reason", reason,
						"fetched", lookup.fetched,
						"total", lookup.total,
						"page_size", nvdPageSize,
						"page_budget", lookup.pageBudget)
				}

				mu.Lock()
				report.Processed++
				if lookup.fromCache {
					report.CacheHits++
				}
				report.APICalls += lookup.requests
				switch {
				case lookup.method != model.MatchNVDKeyword:
					report.CPEMatched++
				case lookup.keywordFallback:
					report.KeywordFallback++
				default:
					report.KeywordOnly++
				}
				report.CPERejected += lookup.cpeRejected
				report.CPEUndecidable += lookup.cpeUndecidable
				if lookup.truncated {
					report.TruncatedComponents++
					// A shifted walk knows it lost records but not how many,
					// so it contributes 0 here rather than a negative number.
					if d := lookup.total - lookup.fetched; d > 0 {
						report.DroppedMatches += d
					}
				}
				mu.Unlock()

				onLookup(work, lookup)
			}
		}()
	}

	wg.Wait()

	report.Unscanned = report.UniqueComponents - report.Processed - report.FetchFailures
	if report.Unscanned > 0 {
		if scanDeadlineFired(ctx) {
			report.DeadlineExceeded = true
		} else {
			report.Cancelled = true
		}
	}
	// What the deadline does NOT cover: the write phase (phase 3) runs on a
	// detached context so that what was fetched in time is committed. A sweep
	// that fetched everything before the deadline but whose write finished
	// after it (e.g. waiting on the per-SBOM lock) is complete, and is
	// reported complete: "failed" means the results are incomplete (UPGRADE
	// §9.3), and these are not. The write is bounded by scanWriteTimeout.
	return report
}

// logSweepSummary logs one sweep's accounting: WARN whenever the sweep is
// known to be less than complete (M55), INFO otherwise. The deadline is named
// in the message so it can be found without reading the counters (M62).
func (s *NVDService) logSweepSummary(sbomID uuid.UUID, r NVDScanReport) {
	logArgs := []any{
		"sbom_id", sbomID,
		"processed", r.Processed,
		"unique_components", r.UniqueComponents,
		"unscanned", r.Unscanned,
		"cache_hits", r.CacheHits,
		"api_calls", r.APICalls,
		"refused_writes", r.RefusedWrites,
		"fetch_failures", r.FetchFailures,
		"truncated_components", r.TruncatedComponents,
		"dropped_matches", r.DroppedMatches,
		"cpe_matched", r.CPEMatched,
		"keyword_only", r.KeywordOnly,
		"keyword_fallback", r.KeywordFallback,
		"cpe_rejected", r.CPERejected,
		"cpe_undecidable", r.CPEUndecidable,
		"links_written", r.LinksWritten,
		"new_vulnerabilities", r.NewVulnerabilities,
		"deadline_exceeded", r.DeadlineExceeded,
		"cancelled", r.Cancelled,
	}
	switch {
	case r.DeadlineExceeded:
		slog.Warn("nvd: scan deadline exceeded; findings verified before it were committed and the scan is reported incomplete", logArgs...)
	case r.Cancelled || r.FetchFailures > 0 || r.TruncatedComponents > 0 || r.RefusedWrites > 0:
		slog.Warn("component scan completed with incomplete coverage", logArgs...)
	default:
		slog.Info("component scan completed", logArgs...)
	}
}

// incompleteErr is the ONE bit ScanComponents is able to hand its caller: the
// error that turns into ScanTracker.MarkFailed, scan_state "failed",
// `counts_final: false` in the MCP server, exit 2 from `sbomhub scan`, and a
// failed scheduler scan_logs row.
//
// Everything it escalates has the same shape — the scan's results are known to
// be less than what the scan claims to have looked for — and since M62 it
// reports EVERY applicable reason (errors.Join), each wrapping its sentinel
// (ErrScanWriteRefused, ErrScanDeadlineExceeded, ErrScanCancelled,
// ErrScanFetchFailed, ErrScanTruncated) so ScanReasons can name them.
//
//   - Refused writes: the database declined to record a match we had already
//     obtained (Codex M54 R1, Critical).
//   - Deadline / cancellation: components were never looked up (M62; before,
//     an interrupted sweep returned nil).
//   - Fetch failures, TOTAL (Codex M54 R2, Critical) and, since M62, PARTIAL.
//     The partial case was left as success through M55-M61 pending "a
//     threshold policy". M62 takes the decision M55 deferred, with the
//     threshold the product already applies to truncation: zero. A scan
//     that did not check a component cannot report it clean, and a partial
//     answer must not be readable as a clean one (UPGRADE §9.3). The CPE
//     path already escalated a page failing partway (as truncation, keeping
//     the validated pages). On the keyword path a page failing partway
//     discards the walk, as before, and is now escalated as fetch_failed.
//   - Truncated result sets (M55): NVD's totalResults proves the set is
//     incomplete.
//
// A scan with NO work (offline, no components, all components nameless) is
// not a failure: there was nothing to look up.
func (r NVDScanReport) incompleteErr() error {
	var errs []error
	if r.RefusedWrites > 0 {
		errs = append(errs, fmt.Errorf("nvd: database refused %d vulnerability write(s); scan results are incomplete: %w",
			r.RefusedWrites, ErrScanWriteRefused))
	}
	if r.DeadlineExceeded {
		errs = append(errs, fmt.Errorf("nvd: the scan deadline fired with %d of %d component(s) never looked up "+
			"(and any walk it cut short reported truncated); scan results are incomplete: %w",
			r.Unscanned, r.UniqueComponents, ErrScanDeadlineExceeded))
	}
	if r.Cancelled {
		errs = append(errs, fmt.Errorf("nvd: the scan was cancelled with %d of %d component(s) never looked up; "+
			"scan results are incomplete: %w", r.Unscanned, r.UniqueComponents, ErrScanCancelled))
	}
	if r.FetchFailures > 0 {
		if r.Processed == 0 && r.Unscanned == 0 {
			errs = append(errs, fmt.Errorf("nvd: all %d component lookup(s) failed; the scan has no coverage: %w",
				r.FetchFailures, ErrScanFetchFailed))
		} else {
			errs = append(errs, fmt.Errorf("nvd: %d of %d component lookup(s) failed; the findings for those "+
				"components are missing: %w", r.FetchFailures, r.UniqueComponents, ErrScanFetchFailed))
		}
	}
	if r.TruncatedComponents > 0 {
		errs = append(errs, fmt.Errorf("nvd: %d component(s) could not be enumerated completely "+
			"(the paging budget ran out — %d pages x %d for a keyword lookup, %d pages for a CPE "+
			"lookup — a page failed or the scan deadline fired partway through a walk, or the result set changed "+
			"underneath the walk); at least %d known "+
			"match(es) were not retrieved and the findings for those components are incomplete: %w",
			r.TruncatedComponents, nvdMaxPagesPerComponent, nvdPageSize, nvdCPEMaxPagesPerComponent, r.DroppedMatches,
			ErrScanTruncated))
	}
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}

// resolveMatches turns one work item's answer into links: it finds (or
// inserts) each matched CVE in the global catalogue and pairs it with every
// component instance that shares the item.
//
// # When and where the catalogue is touched (M57, M62)
//
// GetByCVE runs on the pool (autocommit) and Create on the catalogue pool
// (VulnerabilityRepository.Create never joins a caller's transaction). Both
// run right after the lookup, which is when they ran before M62 — so the row
// becomes visible to cve_sync as soon as the scanner has it, and
// cveSyncReplayOverlap's argument (the row is created while its cache entry
// is still live) still holds. Only the LINKS wait for phase 3.
//
// It is NOT an upsert of the freshly fetched data (Codex M54 R3, Critical):
// when the CVE is already in the catalogue the metadata NVD just returned is
// discarded; the catalogue's metadata belongs to cve_sync (M55).
//
// ctx may already be past the scan deadline when an answer the deadline cut
// short is resolved, so the statements run on scanWriteContext (detached from
// the scan's cancellation, bounded on its own).
//
// It returns the links and the number of matches the catalogue refused (those
// matches cannot be linked).
func (s *NVDService) resolveMatches(ctx context.Context, l nvdLookup, componentIDs []uuid.UUID) ([]pendingLink, int) {
	if len(l.vulns) == 0 {
		return nil, 0
	}
	cctx, cancel := scanWriteContext(ctx)
	defer cancel()

	refused := 0
	links := make([]pendingLink, 0, len(l.vulns)*len(componentIDs))
	for i := range l.vulns {
		vuln := l.vulns[i]
		linkMethod := l.method
		if i < len(l.methods) {
			linkMethod = l.methods[i]
		}
		existing, err := s.vulnRepo.GetByCVE(cctx, vuln.CVEID)
		if err != nil {
			if err := s.vulnRepo.Create(cctx, &vuln); err != nil {
				slog.Warn("failed to create vulnerability", "cve", vuln.CVEID, "error", err)
				refused++
				continue
			}
			existing = &vuln
		}
		for _, compID := range componentIDs {
			links = append(links, pendingLink{componentID: compID, vulnID: existing.ID, method: linkMethod})
		}
	}
	return links, refused
}

// nvdLookup is one work item's outcome: the matches plus everything the caller
// needs in order to describe how sound they are.
type nvdLookup struct {
	vulns     []model.Vulnerability
	fromCache bool
	// truncated, shifted, total, fetched and requests are all zero for a cache
	// hit — a cache hit issues no request, and a truncated result is never
	// cached in the first place (see getVulnerabilitiesWithCache).
	truncated bool
	shifted   bool
	total     int
	fetched   int
	// requests is how many NVD HTTP requests this lookup spent.
	requests int
	// pageBudget is the page budget of the walk that produced the answer
	// (keyword or CPE, M60 decision 2); logged with a truncation.
	pageBudget int
	// partialFailure: the truncation is a page that failed partway, not the
	// budget (Codex M60 R23 Low).
	partialFailure bool
	// method is how the vulns were matched (M60): nvd_cpe / nvd_cpe_distro
	// for the CPE path, nvd_keyword for the keyword path. It is what the
	// links are labelled with, unless methods overrides it per CVE.
	method model.MatchMethod
	// methods, when non-nil, is index-aligned with vulns and labels each
	// CVE individually (the CPE path: an unverifiable CVE is
	// nvd_cpe_unverified while its siblings are nvd_cpe).
	methods []model.MatchMethod
	// uncacheable is set when the answer must not be cached.
	uncacheable bool
	// productEvidence counts records that name the candidate's product as
	// vulnerable (CPE path only; Codex M60 R17).
	productEvidence int
	// keywordFallback: the item HAD CPE candidates, none of which named a
	// product NVD knows, so the keyword path answered.
	keywordFallback bool
	// cpeRejected / cpeUndecidable: see NVDScanReport.
	cpeRejected    int
	cpeUndecidable int
}

// nvdCacheSchema namespaces every cache key this build reads or writes.
//
// # Why (Codex M55 R1, High)
//
// Redis entries written by a PRE-M55 build hold the first 20 matches and carry
// no completeness metadata, and cache.VulnCacheEntry has nowhere to put any.
// After an upgrade — and for the whole of a rolling deployment, where an older
// instance is still writing into the same Redis — a component with 563 matches
// would be served its stale 20-record prefix as a complete cache hit: no HTTP
// request, no page walk, no truncation, and no way for anything downstream to
// tell. The fix this wave shipped (do not CACHE a truncated result) does
// nothing about entries that are already there.
//
// Changing the key namespace makes every pre-M55 entry a miss, so the first
// scan after the upgrade re-walks and re-decides. The orphaned old keys expire
// on their own 24h TTL (cache.NVDCacheTTL) and cost nothing but Redis memory
// until then.
const nvdCacheSchema = "m55."

// nvdCacheName is the cache identity for one (name, version) pair.
//
// # Why it hashes rather than prefixes (Codex M55 R2, High)
//
// The first cut passed `"m55/" + name` to cache.NVDCache, which builds its key
// as `nvd:vuln:<name>[:<version>]`. Component names come from uploaded SBOMs
// and are arbitrary strings, so that namespace is not disjoint from the legacy
// one at all: a pre-M55 entry for a component literally named `m55/openssl`
// occupies exactly the key this build computes for `openssl`, and the stale
// 20-record prefix is served as a complete answer for the wrong component.
// Prefixing an attacker- (or merely user-) controlled field is not namespacing.
//
// Hashing the pair fixes that and a pre-existing ambiguity with it: the legacy
// scheme cannot tell `("a:b", "")` from `("a", "b")`, because it joins name and
// version with a colon and neither is escaped.
//
// The digest input is LENGTH-PREFIXED rather than separator-joined, which is
// what makes it injective. A separator only works if it cannot occur inside
// either field, and component names and versions are arbitrary strings from an
// uploaded SBOM — the first cut joined them with \x1f and inherited exactly the
// ambiguity it was meant to remove: `("a\x1fb", "c")` and `("a", "b\x1fc")`
// produce the same joined string, so two different components would share one
// cached result and one of them could be served an empty answer with no HTTP
// request at all (Codex M55 R6, Medium). `<len(name)>:<name><version>` has no
// such pair: the digits before the first colon are the name length, and they
// determine where the name ends whatever either field contains.
//
// # What this closes, and what it does NOT (Codex M55 R4, High)
//
// Between instances running THIS build, two different (name, version) pairs
// cannot share a key: every read and every write goes through this function,
// and the digest is injective over the pair (modulo a SHA-256 collision).
//
// Across BUILDS it is not closed, and an earlier draft of this comment claimed
// otherwise — it called the remaining preimage "not a plausible component
// name", which is wrong, because the preimage is not a search problem: an
// attacker computes sha256("openssl\x1f1.1.1") offline, names a component
// `m55.<that digest>`, and uploads it. A PRE-M55 instance keys that component
// by its RAW name, lands on exactly the key this build reads for
// `openssl@1.1.1`, and caches whatever NVD answers for that nonsense keyword —
// which is nothing. This build then serves an empty, complete-looking result
// for openssl to every tenant (the NVD cache is global, not tenant-scoped)
// until the 24h TTL expires.
//
// The window was a mixed-version deployment: a rolling upgrade, or a pre-M55
// instance left pointed at the same Redis.
//
// It could not be shut from THIS file. Every key any caller can construct has
// the form `NVDCachePrefix + X`, and a pre-M55 writer produces
// `NVDCachePrefix + X` for any X simply by scanning a component named X with no
// version — so no encoding chosen here is unreachable.
//
// # It is shut now, in internal/cache (M55 follow-up)
//
// `cache.NVDCachePrefix` moved from `nvd:vuln:` to `nvdv2:`, which shares no
// prefix with the old spelling. Because the two prefixes are prefix-incomparable
// and both builds compose keys as `<prefix> + <arbitrary component name>`, the
// two key spaces are disjoint: no component name lets a pre-M55 writer construct
// a key this build reads. Note that the obvious bump — `nvd:vuln:v2:` — would
// NOT have worked, since a pre-M55 writer reaches it by scanning a component
// named `v2:m55.<digest>`. The property is pinned by
// TestNVDCacheKeySpaceIsDisjointFromTheLegacyOne and
// TestNVDCacheKeyIsUnreachableFromALegacyComponentName in internal/cache, both
// of which fail on either spelling above.
//
// The cost is one cold cache: entries written by an older build are orphaned and
// expire on their own 24h TTL. See cache.NVDCachePrefix's doc comment.
func nvdCacheName(name, version string) string {
	sum := sha256.Sum256([]byte(strconv.Itoa(len(name)) + ":" + name + version))
	return nvdCacheSchema + hex.EncodeToString(sum[:])
}

// getVulnerabilitiesWithCache tries cache first, falls back to API.
func (s *NVDService) getVulnerabilitiesWithCache(ctx context.Context, name, version string, pace nvdPacer) (nvdLookup, error) {
	return s.keywordLookup(ctx, name, version, pace, false)
}

// cachedNVDVulns converts one cache record back into vulnerabilities, or
// reports it unusable. Shared by the keyword path and (M60) the CPE path, so
// both treat the cache as the same untrusted source.
func cachedNVDVulns(entry *cache.VulnCacheEntry, name, version string) ([]model.Vulnerability, bool) {
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
		// M67 (Codex R1, High): an entry stamped with an older CVSS rule
		// (0 = written before M67) holds scores cvss.Select never chose.
		// Re-fetch it rather than create a catalogue row no later scan would
		// repair (Create is ON CONFLICT DO NOTHING).
		if entry.CVSSRule != cache.CVSSRuleCurrent {
			slog.Debug("discarding cached NVD record written under an older CVSS rule",
				"component", name, "version", version, "cve_rule", entry.CVSSRule)
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
			CVSSVersion: cv.CVSSVersion,
			PublishedAt: cv.PublishedAt,
			Source:      "NVD",
			UpdatedAt:   &cachedAt,
		})
	}
	return vulns, usable
}

// keywordLookup is getVulnerabilitiesWithCache with the pacing of its first
// request made explicit (M60): when the CPE path already spent requests for
// this work item, the keyword fallback's first page must take a tick too.
func (s *NVDService) keywordLookup(ctx context.Context, name, version string, pace nvdPacer, paceFirst bool) (nvdLookup, error) {
	// Try cache first
	if s.cache != nil {
		entry, err := s.cache.Get(ctx, nvdCacheName(name, version), "")
		if err != nil {
			slog.Debug("cache get error", "component", name, "error", err)
		} else if entry != nil {
			if vulns, usable := cachedNVDVulns(entry, name, version); usable {
				return nvdLookup{vulns: vulns, fromCache: true}, nil
			}
			// Fall through to the API below, exactly as a cache miss would.
		}
	}

	// Cache miss - call API
	res, err := s.searchByKeywordPaced(ctx, name, version, pace, paceFirst)
	if err != nil {
		// The requests the failed walk already spent are still charged against
		// NVD's rate limit, so they are still reported (Codex M55 R2, Low —
		// the R1 fix propagated them out of searchByKeyword and this wrapper
		// then threw them away again).
		return nvdLookup{requests: res.pages}, err
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
				CVSSVersion: v.CVSSVersion,
				PublishedAt: v.PublishedAt,
			}
		}
		if err := s.cache.Set(ctx, nvdCacheName(name, version), "", cachedVulns); err != nil {
			slog.Debug("cache set error", "component", name, "error", err)
		}
	}

	return nvdLookup{
		vulns:      vulns,
		truncated:  res.truncated,
		shifted:    res.shifted,
		total:      res.total,
		fetched:    res.fetched,
		requests:   res.pages,
		pageBudget: res.pageBudget,
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
	// entries are the raw NVD records behind vulns, index-aligned with it
	// (entries[i] is the record vulns[i] was converted from, its cve.id
	// canonicalised). The CPE path (M60) verifies them against their
	// configurations; the keyword path ignores them.
	entries []NVDVulnEntry
	// fetched is how many RECORDS the walk consumed (pre-dedup), i.e. how far
	// into the result set its offsets got. Compared against total.
	fetched int
	// total is totalResults as NVD last reported it. NVD is live, so a walk
	// can see this change between pages; the last value wins.
	total int
	// pages is the number of HTTP requests this lookup issued, INCLUDING the
	// one that failed when the walk ends in an error.
	pages int
	// pageBudget is the page limit this walk ran under (M60 decision 2).
	pageBudget int
	// partialFailure: a page failed after earlier pages validated and the CPE
	// path kept those pages as a truncated answer (partialWalk).
	partialFailure bool
	// shifted records that the result set moved underneath the walk.
	//
	// # Why an offset walk needs this at all (Codex M55 R1/R2, Critical)
	//
	// Paging is by OFFSET. A record removed from the middle of a live result
	// set slides every later record down one position, so the record that
	// occupied the next startIndex is returned by NO request. Concretely: 350
	// matches, page 1 fetches offsets 0-199, record #0 is then removed, page 2
	// asks for offset 200 and receives what is now offsets 200-348 — the
	// record that WAS at offset 200 is now at 199 and is silently skipped. The
	// walk ends with the arithmetic coming out even and looks complete.
	//
	// Counting records cannot see that, and neither can counting DISTINCT
	// records: a simultaneous removal and insertion keeps totalResults
	// identical and every delivered id distinct while still skipping one
	// (Codex M55 R2, Critical, against the first cut of this field, which
	// checked only those two things).
	//
	// # How it is detected
	//
	// Three signals, cheapest first:
	//
	//  1. totalResults changing between pages.
	//  2. a record arriving twice where no overlap was requested.
	//  3. the BOUNDARY ANCHOR: every page after the first is requested at
	//     `fetched - 1`, i.e. deliberately overlapping the previous page by one
	//     record, and its first entry must be the record that ended the
	//     previous page. If the window moved, that record is no longer at that
	//     offset and the mismatch is visible. This costs no extra REQUEST (the
	//     overlap record rides inside a page that was going to be fetched
	//     anyway) — only one record of the per-component budget per page, so
	//     the reachable depth is nvdPageSize + (nvdMaxPagesPerComponent-1) *
	//     (nvdPageSize-1) = 996 rather than 1000.
	//
	// # What it still does not prove
	//
	// Nothing here makes offset pagination over a mutable set sound; that is
	// not achievable without a stable cursor, and the NVD CVE API 2.0 does not
	// offer one. The anchor detects any shift that moves records ACROSS a page
	// boundary, which is the shape that loses records. A rewrite that keeps the
	// anchor at its offset while moving some other record backwards past an
	// offset the walk has already passed would still slip through. So this
	// field means "an inconsistency was observed", and its absence means "none
	// was observed" — not "none occurred". The claim the product makes on top
	// of it is deliberately the weak one; see SbomHandler.runScan.
	shifted bool
	// truncated is true when the walk cannot prove it saw the whole match set:
	// either the result set is larger than what was fetched (the paging budget
	// ran out) or it shifted underneath the walk. Never a heuristic — the
	// first is NVD's own totalResults, the second is an observed
	// inconsistency.
	truncated bool
}

// nvdPacer blocks until the sweep's shared rate limiter allows one more NVD
// request, or the context ends. nil means "unpaced" (a caller outside the
// worker pool, e.g. a test driving one lookup against an httptest server).
//
// It is a parameter rather than a field on NVDService because the limiter is
// per-SCAN, not per-process: fetchComponents creates one ticker for
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
// what resolveMatches does with whatever this function returns. The product
// would report twenty-one thousand findings against one component, none of
// them evidence of anything. Exhaustive paging makes the answer worse, not
// just later.
//
// So the budget is not a compromise between correctness and speed. It is the
// line past which the query has stopped being a vulnerability match, and the
// honest thing to do at that line is to say the result is incomplete rather
// than to keep spending requests on noise. That is what `truncated` is for and
// what fetchComponents escalates.
//
// # What the budget costs, in requests
//
// One request covers the first nvdPageSize records and each further request
// covers nvdPageSize-1 more (the first record of every follow-up page is the
// boundary anchor — see nvdSearchResult.shifted), so the budget reaches offset
// 996 and costs at most nvdMaxPagesPerComponent requests. Against the measured
// table above: every versioned component costs 1 (as before this change),
// "curl" costs 2, "openssl" costs 3, "linux" costs 5 and is reported truncated.
// A 500-component SBOM of versioned components therefore still costs 500
// requests — 350 s with an API key at rateLimitWithKey, unchanged from before
// this fix. The pathological upper bound is 5x that, and it requires an SBOM
// whose components are ALL unversioned generic words.
//
// # CPE matching (M60)
//
// This keyword search is no longer the only matcher. Since M60 a component
// whose SBOM entry carries a CPE NVD knows is matched by cpeName and verified
// against NVD's configurations instead (nvd_cpe.go, lookupComponent); this
// function now serves components with no usable CPE, and its links are
// labelled nvd_keyword (low confidence). Everything above about the budget
// still holds for it — and for the CPE walk, which goes through the same
// walkNVD.
func (s *NVDService) searchByKeyword(ctx context.Context, name, version string, pace nvdPacer) (nvdSearchResult, error) {
	return s.searchByKeywordPaced(ctx, name, version, pace, false)
}

// searchByKeywordPaced is searchByKeyword with walkNVD's paceFirst exposed.
func (s *NVDService) searchByKeywordPaced(ctx context.Context, name, version string, pace nvdPacer, paceFirst bool) (nvdSearchResult, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "nvd")
		return nvdSearchResult{}, nil
	}

	keyword := name
	if version != "" {
		keyword = fmt.Sprintf("%s %s", name, version)
	}
	q := url.Values{}
	q.Set("keywordSearch", keyword)
	res, err := s.walkNVD(ctx, q, pace, paceFirst, nvdMaxPagesPerComponent)
	if err != nil {
		// A failed keyword walk is a failed lookup, records and all (M55);
		// only the page count survives, for the request accounting. Since
		// M62 a failed lookup escalates the scan even when other components
		// answered (NVDScanReport.incompleteErr).
		return nvdSearchResult{pages: res.pages}, err
	}
	return res, nil
}

// walkNVD pages one NVD CVE query — keywordSearch (searchByKeyword) or
// cpeName (the M60 CPE path) — through the budget described on
// searchByKeyword, with the same truncation, shift and page-identity
// discipline for both. The walk logic was searchByKeyword's body until M60;
// only the query it sends was made a parameter.
//
// paceFirst says whether the FIRST page must also take a pacer tick. The
// worker loop pays one tick per work item, which covers the first request of
// the item and nothing else; since M60 one item can issue several queries
// (CPE candidates, the product probe, the keyword fallback), and every query
// after the item's first must pay for its first page too.
//
// maxPages is the walk's page budget: nvdMaxPagesPerComponent for keyword
// walks, nvdCPEMaxPagesPerComponent for CPE walks (M60 decision 2).
func (s *NVDService) walkNVD(ctx context.Context, query url.Values, pace nvdPacer, paceFirst bool, maxPages int) (nvdSearchResult, error) {
	out := nvdSearchResult{pageBudget: maxPages}
	// seen de-duplicates by canonical CVE id ACROSS pages, and — see the
	// shifted-window discussion on nvdSearchResult.shifted — a hit that is not
	// the deliberate overlap record is also evidence that the offsets this walk
	// used are no longer coherent.
	seen := make(map[string]struct{})
	firstTotal := -1
	// anchorID is the last record of the previous page, and start is the
	// offset this page asks for. Every page after the first DELIBERATELY
	// overlaps the previous one by a single record (start = fetched - 1) so
	// that the alignment can be checked rather than assumed. See the
	// "boundary anchor" note on nvdSearchResult.shifted.
	anchorID := ""
	start := 0

	for out.pages < maxPages {
		// Every page after the first is an EXTRA request that the worker
		// pool's per-work-item tick did not pay for, so it takes its own tick.
		// Without this the pool would issue up to maxConcurrentWithKey * 5
		// requests per tick and blow through NVD's published rate.
		if (out.pages > 0 || paceFirst) && pace != nil {
			if err := pace(ctx); err != nil {
				// M62: a walk the scan DEADLINE cuts off between pages
				// returns the pages already validated with the error, so a
				// CPE walk can keep them (partialWalk). Every caller still
				// treats a non-nil error as a failed lookup unless
				// partialWalk says otherwise.
				if scanDeadlineFired(ctx) {
					out.truncated = true
					return out, err
				}
				return nvdSearchResult{pages: out.pages}, err
			}
		}

		page, err := s.fetchPage(ctx, query, start, nvdPageSize)
		out.pages++
		if err != nil {
			// A failure partway through a walk is a failure of the whole
			// lookup, not a partial success: returning the records we did get
			// would be exactly the silent under-report this function exists to
			// stop, only with a nicer-looking count. The PAGE COUNT is still
			// returned, so the sweep's request accounting includes the
			// requests that were actually spent (Codex M55 R1, Low).
			//
			// The records of the pages that DID validate are returned with
			// the error too (M60). The keyword path ignores them and fails
			// the lookup as before; the CPE path turns a mid-walk failure
			// into an escalated truncation instead of losing every verified
			// page (lookupCPECandidate). out.fetched still marks the end of
			// the last VALIDATED page (Codex M60 R23 Low).
			return out, err
		}
		out.total = *page.TotalResults
		if firstTotal < 0 {
			firstTotal = out.total
		} else if out.total != firstTotal {
			out.shifted = true
		}

		entries := page.entries()
		fresh, freshEntries := s.convertEntries(entries)

		// Boundary anchor. This page was asked to START with the record that
		// ended the previous one; if it does not, the window moved.
		if anchorID != "" {
			if len(fresh) == 0 || fresh[0].CVEID != anchorID {
				out.shifted = true
			}
			if len(fresh) > 0 {
				fresh = fresh[1:]
				freshEntries = freshEntries[1:]
			}
		}

		for i, v := range fresh {
			if _, dup := seen[v.CVEID]; dup {
				// A repeat that is NOT the deliberate overlap: the window
				// moved backwards, so something moved forwards past an offset
				// this walk had already passed.
				out.shifted = true
				continue
			}
			seen[v.CVEID] = struct{}{}
			out.vulns = append(out.vulns, v)
			out.entries = append(out.entries, freshEntries[i])
		}
		// fetched is an ABSOLUTE position, not a running sum, because the
		// pages overlap by one record.
		out.fetched = start + len(entries)

		// No progress: this page carried nothing the walk had not already
		// seen. Reachable when the result set SHRANK mid-walk (see validate's
		// totalResults > startIndex rule) and as a belt-and-braces guard
		// against a mirror that answers a later page with an empty or
		// anchor-only one — without it the walk would re-request the same
		// offset until the budget ran out.
		if len(fresh) == 0 {
			break
		}
		if out.fetched >= out.total {
			break
		}
		anchorID = fresh[len(fresh)-1].CVEID
		start = out.fetched - 1
	}

	out.truncated = out.fetched < out.total || out.shifted
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
//
// query carries the search itself (keywordSearch, cpeName or
// virtualMatchString); resultsPerPage and startIndex are always set here.
func (s *NVDService) fetchPage(ctx context.Context, query url.Values, startIndex, pageSize int) (*NVDResponse, error) {
	params := url.Values{}
	for k, v := range query {
		params[k] = append([]string(nil), v...)
	}
	params.Set("resultsPerPage", strconv.Itoa(pageSize))
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
	vulns, _ := s.convertEntries(entries)
	return vulns
}

// convertEntries is convertToVulnerabilities plus the source records,
// index-aligned with the result and with cve.id replaced by its canonical
// form (M60: the CPE path verifies the records after conversion).
func (s *NVDService) convertEntries(entries []NVDVulnEntry) ([]model.Vulnerability, []NVDVulnEntry) {
	var vulns []model.Vulnerability
	var kept []NVDVulnEntry

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

		sel := SelectNVDCVSS(entry.CVE.Metrics)
		vuln.CVSSScore = sel.Score
		vuln.Severity = sel.Severity
		vuln.CVSSVersion = sel.Version.Ptr()

		vuln.PublishedAt = parseNVDTimestamp(entry.CVE.Published)
		now := time.Now()
		vuln.UpdatedAt = &now

		vulns = append(vulns, vuln)
		entry.CVE.ID = canonical
		kept = append(kept, entry)
	}

	return vulns, kept
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

// ParseNVDTimestamp is parseNVDTimestamp for the other reader of the NVD feed,
// scheduler.CVESyncJob (M57). It parsed `published` / `lastModified` with
// time.RFC3339 alone — the bug M54 fixed here — so on NVD's real zoneless
// timestamps every record it fetched was undateable and its metadata refresh
// refused all of them. One parser for one wire format.
func ParseNVDTimestamp(v string) *time.Time {
	return parseNVDTimestamp(v)
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

// NVDUpstreamError is how SearchByCVEID reports that NVD did not give a usable
// answer, so the search route can say "upstream" instead of 500. Temporary is
// set when NVD said "not now" — 403 (NVD's documented answer to a client over
// the public rate limit), 429 or 503 — and RetryAfter then carries how long to
// wait: the upstream Retry-After when it sent one, clamped to
// [1s, nvdRetryAfterMax], otherwise nvdRetryAfterDefault (NVD's rate limit is
// a rolling 30-second window). Everything else — another status, a transport
// failure, an undecodable body — is not Temporary.
//
// Neither Error() nor any field carries the upstream body: the API's logs do
// not record upstream / error text (UPGRADE §16-§17), and the status says
// what the caller needs.
type NVDUpstreamError struct {
	Status     int // 0 for a transport / decode failure
	Temporary  bool
	RetryAfter time.Duration
	Err        error // transport / decode cause, if any
}

const (
	nvdRetryAfterDefault = 30 * time.Second
	nvdRetryAfterMax     = time.Hour
	nvdErrorBodyDrainMax = 256 << 10
)

func (e *NVDUpstreamError) Error() string {
	switch {
	case e.Err != nil:
		return e.Err.Error()
	case e.Temporary:
		return fmt.Sprintf("NVD API refused the request: %d (retry after %s)", e.Status, e.RetryAfter)
	default:
		return fmt.Sprintf("NVD API error: %d", e.Status)
	}
}

func (e *NVDUpstreamError) Unwrap() error { return e.Err }

func newNVDStatusError(resp *http.Response, now time.Time) *NVDUpstreamError {
	// Drain (a bounded amount of) the refusal so the keep-alive connection
	// can be reused: refusals arrive exactly while NVD is throttling us, and
	// a new TCP/TLS connection per refused lookup only adds to it. The body
	// itself is discarded, never logged or returned.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, nvdErrorBodyDrainMax))
	e := &NVDUpstreamError{Status: resp.StatusCode}
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		e.Temporary = true
		e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), now)
	}
	return e
}

// parseRetryAfter reads an RFC 9110 Retry-After (delta-seconds or HTTP-date)
// and clamps it to [1s, nvdRetryAfterMax]; absent or unparsable gives
// nvdRetryAfterDefault.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return nvdRetryAfterDefault
	}
	var d time.Duration
	if isASCIIDigits(v) {
		// delta-seconds: any all-digit value, however long, is a valid
		// (huge) delay — clamp it rather than treat it as unparsable.
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n > int64(nvdRetryAfterMax/time.Second) {
			return nvdRetryAfterMax
		}
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	} else {
		return nvdRetryAfterDefault
	}
	if d < time.Second {
		return time.Second
	}
	if d > nvdRetryAfterMax {
		return nvdRetryAfterMax
	}
	// Round UP: telling the caller to come back before the upstream deadline
	// would only earn another refusal.
	if r := d % time.Second; r != 0 {
		d += time.Second - r
	}
	return d
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
		return nil, &NVDUpstreamError{Err: fmt.Errorf("NVD API request failed: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, newNVDStatusError(resp, time.Now())
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
		return nil, &NVDUpstreamError{Err: fmt.Errorf("failed to decode NVD response: %w", err)}
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
		return nil, &NVDUpstreamError{Err: fmt.Errorf("SearchByCVEID: NVD returned a malformed CVE ID %q for %s",
			vulns[0].CVEID, want)}
	}
	if got != want {
		return nil, &NVDUpstreamError{Err: fmt.Errorf("SearchByCVEID: asked NVD for %s and it answered with %s; "+
			"refusing to serve one CVE under another's identity", want, got)}
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
