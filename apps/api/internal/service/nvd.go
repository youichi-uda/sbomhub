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
	ResultsPerPage  int            `json:"resultsPerPage"`
	StartIndex      int            `json:"startIndex"`
	TotalResults    int            `json:"totalResults"`
	Vulnerabilities []NVDVulnEntry `json:"vulnerabilities"`
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
	CvssMetricV2  []CvssMetric `json:"cvssMetricV2"`
}

type CvssMetric struct {
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
// not just the two items that collided. Meanwhile ScanComponents still returns
// nil, so "NVD scan completed" is logged in the same run as the error (the
// asymmetry M50 pinned).
//
// dbMu closes that window: it is taken for the entire per-item persistence
// section, so at most one goroutine is ever inside a statement on the shared
// tx. It costs nothing worth measuring. The concurrency this pool exists for
// is in the NVD HTTP round trip (hundreds of ms to seconds), which stays
// outside the lock; the database section is ~0.1ms per CVE against a local
// PostgreSQL, and the shared rate limiter caps the whole pool at one work item
// per rateLimitWithKey (700ms) regardless of how many workers there are.
//
// The mutex is per-call rather than a field on NVDService on purpose: one
// NVDService is shared process-wide, and two scans for different tenants run
// on different transactions with nothing to contend over.
//
// What this does NOT fix: a statement that fails on its own merits still
// aborts the shared transaction and discards every row the sweep wrote (M50).
// Serialising the workers removes the concurrency as a CAUSE of that abort; it
// does not change what an abort costs.
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
				s.persistWorkItem(ctx, &dbMu, vulns, work.componentIDs)
			}
		}()
	}

	wg.Wait()

	slog.Info("component scan completed",
		"processed", processedCount,
		"cache_hits", cacheHits,
		"api_calls", apiCalls,
	)

	return nil
}

// persistWorkItem upserts one work item's vulnerabilities and links them to
// every component instance that shares its (name, version).
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
// Per-CVE failures are logged and skipped rather than propagated, which is the
// behaviour this had before M54 and is left unchanged here — see the
// known-limitation note on SbomHandler.runScan for why a scan that lost rows
// still reports success.
func (s *NVDService) persistWorkItem(
	ctx context.Context,
	dbMu *sync.Mutex,
	vulns []model.Vulnerability,
	componentIDs []uuid.UUID,
) {
	dbMu.Lock()
	defer dbMu.Unlock()

	for i := range vulns {
		vuln := vulns[i]
		existing, err := s.vulnRepo.GetByCVE(ctx, vuln.CVEID)
		if err != nil {
			if err := s.vulnRepo.Create(ctx, &vuln); err != nil {
				slog.Warn("failed to create vulnerability", "cve", vuln.CVEID, "error", err)
				continue
			}
			existing = &vuln
		}

		for _, compID := range componentIDs {
			if err := s.vulnRepo.LinkComponent(ctx, compID, existing.ID); err != nil {
				slog.Debug("failed to link component", "component", compID, "vuln", existing.ID, "error", err)
			}
		}
	}
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

	return s.convertToVulnerabilities(nvdResp.Vulnerabilities), nil
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

		if t, err := time.Parse(time.RFC3339, entry.CVE.Published); err == nil {
			vuln.PublishedAt = &t
		}
		now := time.Now()
		vuln.UpdatedAt = &now

		vulns = append(vulns, vuln)
	}

	return vulns
}

// extractCvss returns the CVE's base score and severity. M46 B2: a CVE
// without any CVSS metrics (NVD "Awaiting Analysis") yields a nil score —
// NOT 0.0, which is a real "None" score — so un-scored CVEs are stored as
// NULL and rendered as unscored instead of "safe".
func extractCvss(metrics NVDMetrics) (*float64, string) {
	if len(metrics.CvssMetricV31) > 0 {
		m := metrics.CvssMetricV31[0].CvssData
		return &m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV30) > 0 {
		m := metrics.CvssMetricV30[0].CvssData
		return &m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV2) > 0 {
		m := metrics.CvssMetricV2[0].CvssData
		return &m.BaseScore, scoreToCvss2Severity(m.BaseScore)
	}
	return nil, "UNKNOWN"
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

	if len(nvdResp.Vulnerabilities) == 0 {
		return nil, nil // CVE not found
	}

	vulns := s.convertToVulnerabilities(nvdResp.Vulnerabilities)
	if len(vulns) == 0 {
		return nil, nil
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
