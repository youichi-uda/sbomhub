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
)

const (
	cveSyncAPIURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	cveSyncRateLimitNoKey = 6 * time.Second        // ~5 requests per 30 seconds without API key
	cveSyncRateLimitKey   = 700 * time.Millisecond // ~50 requests per 30 seconds with API key
	cveSyncResultsPerPage = 2000
)

// CVESyncJob fetches new/updated CVEs from NVD and matches against components
type CVESyncJob struct {
	db         *sql.DB
	httpClient *http.Client
	nvdAPIKey  string
	interval   time.Duration
}

// NewCVESyncJob creates a new CVE sync job
func NewCVESyncJob(db *sql.DB, nvdAPIKey string, interval time.Duration) *CVESyncJob {
	return &CVESyncJob{
		db:         db,
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

	// Match CVEs against components
	matchedCount := 0
	newVulnCount := 0
	for _, cve := range cves {
		matched, newVulns, err := j.matchCVEToComponents(ctx, cve)
		if err != nil {
			slog.Warn("failed to match CVE", "cve_id", cve.ID, "error", err)
			continue
		}
		if matched {
			matchedCount++
			newVulnCount += newVulns
		}
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

// matchCVEToComponents matches a CVE to components in the database
func (j *CVESyncJob) matchCVEToComponents(ctx context.Context, cve CVEInfo) (bool, int, error) {
	if len(cve.Keywords) == 0 {
		return false, 0, nil
	}

	// First, upsert the vulnerability record
	vulnID, isNew, err := j.upsertVulnerability(ctx, cve)
	if err != nil {
		return false, 0, fmt.Errorf("failed to upsert vulnerability: %w", err)
	}

	// Find matching components using keywords
	// This uses a LIKE query against component names
	query := `
		SELECT DISTINCT c.id
		FROM components c
		WHERE LOWER(c.name) = ANY($1)
		   OR LOWER(c.name) LIKE ANY($2)
	`

	// Create exact match array and LIKE patterns
	exactMatches := cve.Keywords
	likePatterns := make([]string, len(cve.Keywords))
	for i, kw := range cve.Keywords {
		likePatterns[i] = "%" + kw + "%"
	}

	rows, err := j.db.QueryContext(ctx, query, exactMatches, likePatterns)
	if err != nil {
		return false, 0, fmt.Errorf("failed to query components: %w", err)
	}
	defer rows.Close()

	linkedCount := 0
	for rows.Next() {
		var componentID uuid.UUID
		if err := rows.Scan(&componentID); err != nil {
			continue
		}

		// Link component to vulnerability
		_, err = j.db.ExecContext(ctx, `
			INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at)
			VALUES ($1, $2, NOW())
			ON CONFLICT (component_id, vulnerability_id) DO NOTHING
		`, componentID, vulnID)
		if err != nil {
			slog.Warn("failed to link component to vulnerability",
				"component_id", componentID,
				"vuln_id", vulnID,
				"error", err)
			continue
		}
		linkedCount++
	}

	newVulns := 0
	if isNew && linkedCount > 0 {
		newVulns = 1
	}

	if linkedCount > 0 {
		slog.Debug("matched CVE to components",
			"cve_id", cve.ID,
			"components_linked", linkedCount,
			"is_new", isNew)
	}

	return linkedCount > 0, newVulns, nil
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
