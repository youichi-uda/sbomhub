package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	epssAPIURL   = "https://api.first.org/data/v1/epss"
	epssBatchSize = 100
)

type EPSSService struct {
	client   *http.Client
	vulnRepo *repository.VulnerabilityRepository
}

func NewEPSSService(vulnRepo *repository.VulnerabilityRepository) *EPSSService {
	return &EPSSService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		vulnRepo: vulnRepo,
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
	// Build URL with CVE IDs
	url := fmt.Sprintf("%s?cve=%s", epssAPIURL, strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

// GetScore fetches EPSS score for a single CVE (real-time)
func (s *EPSSService) GetScore(ctx context.Context, cveID string) (*repository.EPSSData, error) {
	scores, err := s.fetchEPSSScores(ctx, []string{cveID})
	if err != nil {
		return nil, err
	}

	if data, ok := scores[cveID]; ok {
		return &data, nil
	}
	return nil, nil
}
