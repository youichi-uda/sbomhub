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
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	cveSyncAPIURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cveSyncRateLimitNoKey = 6 * time.Second        // ~5 requests per 30 seconds without API key
	cveSyncRateLimitKey   = 700 * time.Millisecond // ~50 requests per 30 seconds with API key
	cveSyncResultsPerPage = 2000
)

// CVESyncJob fetches new/updated CVEs from NVD and matches against components.
//
// codex-r4 P1 fix:
//   The `components` table is FORCE ROW LEVEL SECURITY (migration 023 /
//   027). The previous matching loop ran a single system-wide LIKE query
//   on `j.db` and silently matched zero rows under sbomhub_app. The fix
//   keeps vulnerability upsert on the non-RLS `vulnerabilities` table at
//   the system level (one row per CVE, shared across tenants) but moves
//   the component-match phase into a per-tenant tx so RLS policies see
//   the right tenant. `component_vulnerabilities` is not RLS-enabled, so
//   the link writes happen on the same tenant tx without further policy
//   plumbing.
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
	tenantIDs, terr := j.tenantRepo.ListAllIDs(ctx)
	if terr != nil {
		return fmt.Errorf("failed to list tenants for CVE match: %w", terr)
	}

	matchedCount := 0
	newVulnCount := 0
	for _, tid := range tenantIDs {
		tMatched, tNewVulns, err := j.matchTenant(ctx, tid, cves, vulnIndex)
		if err != nil {
			slog.Warn("failed to match CVEs for tenant", "tenant_id", tid, "error", err)
			continue
		}
		matchedCount += tMatched
		newVulnCount += tNewVulns
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

// matchTenant runs the component-match phase for one tenant inside a single
// RLS-pinned transaction. It returns:
//   - matched: number of CVEs that linked to at least one component in this tenant
//   - newVulns: number of NEW vulnerabilities (isNew && linked) for this tenant
//
// Holding one tx per tenant is much cheaper than one tx per (tenant, CVE)
// — the GUC is set once, then the loop can hammer through hundreds of
// CVEs against the same tenant's components.
func (j *CVESyncJob) matchTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	cves []CVEInfo,
	vulnIndex map[string]cveVulnEntry,
) (matched, newVulns int, err error) {
	err = runWithTenantTx(ctx, j.db, tenantID, func(txCtx context.Context, _ *sql.Tx) error {
		q := database.Querier(txCtx, j.db)
		for _, cve := range cves {
			entry, ok := vulnIndex[cve.ID]
			if !ok {
				continue
			}

			linked, lerr := j.linkCVEToTenantComponents(txCtx, q, cve, entry.id)
			if lerr != nil {
				slog.Warn("failed to link CVE for tenant",
					"tenant_id", tenantID,
					"cve_id", cve.ID,
					"error", lerr)
				continue
			}
			if linked > 0 {
				matched++
				if entry.isNew {
					newVulns++
				}
				slog.Debug("matched CVE to components",
					"tenant_id", tenantID,
					"cve_id", cve.ID,
					"components_linked", linked,
					"is_new", entry.isNew)
			}
		}
		return nil
	})
	return matched, newVulns, err
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

	rows, err := q.QueryContext(ctx, query, exactMatches, likePatterns)
	if err != nil {
		return 0, fmt.Errorf("query components: %w", err)
	}
	defer rows.Close()

	linkedCount := 0
	for rows.Next() {
		var componentID uuid.UUID
		if err := rows.Scan(&componentID); err != nil {
			continue
		}
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
