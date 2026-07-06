package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/validation"
)

const (
	epssAPIURL    = "https://api.first.org/data/v1/epss"
	epssBatchSize = 100
)

type EPSSService struct {
	client   *http.Client
	vulnRepo *repository.VulnerabilityRepository
	baseURL  string
	offline  bool
}

func NewEPSSService(vulnRepo *repository.VulnerabilityRepository, baseURL string, offline bool) *EPSSService {
	if baseURL == "" {
		baseURL = epssAPIURL
	}
	return &EPSSService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		vulnRepo: vulnRepo,
		baseURL:  baseURL,
		offline:  offline,
	}
}

// EPSSResponse represents the API response from FIRST EPSS
type EPSSResponse struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Data       []EPSSItem `json:"data"`
}

type EPSSItem struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// SyncScores fetches EPSS scores for all CVEs in the database
func (s *EPSSService) SyncScores(ctx context.Context) error {
	if s.offline {
		slog.Info("sync skipped: offline mode", "source", "epss")
		return nil
	}

	// Get all CVE IDs
	cveIDs, err := s.vulnRepo.GetAllCVEIDs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CVE IDs: %w", err)
	}

	if len(cveIDs) == 0 {
		slog.Info("No CVEs to sync EPSS scores for")
		return nil
	}

	slog.Info("Starting EPSS sync", "total_cves", len(cveIDs))

	// Process in batches
	for i := 0; i < len(cveIDs); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		scores, err := s.fetchEPSSScores(ctx, batch)
		if err != nil {
			slog.Error("Failed to fetch EPSS scores for batch", "error", err, "batch_start", i)
			continue
		}

		if len(scores) > 0 {
			if err := s.vulnRepo.UpdateEPSSScores(ctx, scores); err != nil {
				slog.Error("Failed to update EPSS scores", "error", err)
				continue
			}
		}

		slog.Info("Updated EPSS scores", "batch", i/epssBatchSize+1, "count", len(scores))

		// Rate limiting - be nice to the API
		time.Sleep(500 * time.Millisecond)
	}

	slog.Info("EPSS sync completed")
	return nil
}

func (s *EPSSService) fetchEPSSScores(ctx context.Context, cveIDs []string) (map[string]repository.EPSSData, error) {
	// Validate + normalize every CVE ID and DROP any malformed one before it
	// can reach the external FIRST EPSS URL. A single bad ID must not fail the
	// whole batch — it is filtered out and logged (M42 Wave 1). This is the
	// input-boundary guard for the request; the escaping below is defence in
	// depth.
	validIDs := make([]string, 0, len(cveIDs))
	for _, raw := range cveIDs {
		id, err := validation.ValidateCVEID(raw)
		if err != nil {
			slog.Warn("epss: dropping malformed CVE ID from batch", "cve_id", raw)
			continue
		}
		validIDs = append(validIDs, id)
	}
	if len(validIDs) == 0 {
		// Nothing valid to ask about — return an empty result rather than
		// hitting the API with an empty query.
		return map[string]repository.EPSSData{}, nil
	}

	// Build the request URL with net/url so the cve param is percent-encoded.
	// Each ID is escaped individually and joined with a LITERAL comma so the
	// FIRST EPSS documented comma-separated batch contract keeps working while
	// anything dangerous inside a value is still escaped. Validated IDs contain
	// only [A-Z0-9-] (nothing QueryEscape touches), so for real CVEs the
	// encoded form is identical to the input.
	escaped := make([]string, len(validIDs))
	for i, id := range validIDs {
		escaped[i] = url.QueryEscape(id)
	}
	reqURL := fmt.Sprintf("%s?cve=%s", s.baseURL, strings.Join(escaped, ","))

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return nil, fmt.Errorf("failed to decode EPSS response: %w", err)
	}

	scores := make(map[string]repository.EPSSData)
	for _, item := range epssResp.Data {
		var score, percentile float64
		fmt.Sscanf(item.EPSS, "%f", &score)
		fmt.Sscanf(item.Percentile, "%f", &percentile)
		scores[item.CVE] = repository.EPSSData{
			Score:      score,
			Percentile: percentile,
		}
	}

	return scores, nil
}

// GetScore fetches EPSS score for a single CVE (real-time). The CVE ID is
// validated first: a malformed ID returns validation.ErrInvalidCVEID WITHOUT
// making any external call (the handler maps that to 400).
func (s *EPSSService) GetScore(ctx context.Context, cveID string) (*repository.EPSSData, error) {
	normalized, err := validation.ValidateCVEID(cveID)
	if err != nil {
		return nil, err
	}

	if s.offline {
		return nil, nil
	}

	scores, err := s.fetchEPSSScores(ctx, []string{normalized})
	if err != nil {
		return nil, err
	}

	if data, ok := scores[normalized]; ok {
		return &data, nil
	}
	return nil, nil
}
