package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/validation"
)

// parseEPSSValue parses one FIRST-served decimal string as an EPSS
// probability. strconv.ParseFloat alone is NOT a sufficient validity check
// (M46 Codex final round, Medium #2): it accepts "NaN", "Inf"/"-Inf" and
// out-of-range decimals like "1.1" / "-0.1", which pre-fix flowed into the
// DB as real values — 110% probabilities in the UI, NaN breaking JSON
// marshalling of any response embedding the score (and NaN is a VALID
// Postgres numeric, so it round-trips), and |v| >= 10 aborting the
// DECIMAL(5,4) UPDATE mid-sync so stale values kept being served. EPSS
// scores and percentiles are probabilities: finite and within [0,1], or
// they are no data at all.
func parseEPSSValue(raw string) (float64, error) {
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("non-finite EPSS value %q", raw)
	}
	if v < 0 || v > 1 {
		return 0, fmt.Errorf("EPSS value %q outside [0,1]", raw)
	}
	return v, nil
}

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

	// The map that reaches UpdateEPSSScores is keyed ONLY by normalized CVE
	// ids that are members of THIS request's batch (M46 Codex final round,
	// Low #1). Pre-fix it was keyed by the raw response item.CVE with no
	// membership check — and because a tombstone entry CLEARS the global
	// vulnerabilities row's EPSS columns for every tenant, a FIRST 200
	// response carrying a malformed item for an unrequested CVE could reach
	// into rows this sync was never asked about. Unsolicited or unparseable
	// response ids are logged and dropped; requested ids answered in a
	// non-canonical case are normalized (ValidateCVEID upper-cases) so a
	// legitimate answer is never lost over casing.
	requested := make(map[string]struct{}, len(validIDs))
	for _, id := range validIDs {
		requested[id] = struct{}{}
	}

	scores := make(map[string]repository.EPSSData)
	for _, item := range epssResp.Data {
		cveID, err := validation.ValidateCVEID(item.CVE)
		if err != nil {
			slog.Warn("epss: dropping response item with malformed CVE id", "cve", item.CVE)
			continue
		}
		if _, ok := requested[cveID]; !ok {
			slog.Warn("epss: dropping unrequested CVE from FIRST response", "cve_id", cveID)
			continue
		}
		// FIRST serves scores as decimal strings. A malformed OR out-of-range
		// value must NOT be stored as a fabricated 0.0 (EPSS feeds SSVC
		// auto-assessment, so a silent zero downgrades real risk) — and it
		// must NOT be skipped either (M46 Codex round C, Medium): this sync
		// may be refreshing a CVE that already has a value in the DB, and a
		// skip leaves that previous, no-longer-authoritative value being
		// served as current with no freshness signal. Every answered CVE
		// therefore gets an explicit entry:
		//   - score OK, percentile invalid -> keep the score, clear only
		//     the percentile (a valid score must not be discarded);
		//   - score invalid -> clear BOTH columns to NULL ("no data", the
		//     state all readers already handle); a percentile without a
		//     score would read as fabricated "score 0 at high percentile"
		//     through the COALESCE readers.
		// "Invalid" covers both unparseable strings and parseable-but-
		// nonsensical probabilities (NaN / Inf / outside [0,1]) — see
		// parseEPSSValue (M46 Codex final round, Medium #2).
		score, sErr := parseEPSSValue(item.EPSS)
		percentile, pErr := parseEPSSValue(item.Percentile)
		switch {
		case sErr != nil:
			slog.Warn("epss: invalid score from FIRST API; clearing stored EPSS for CVE",
				"cve_id", cveID, "epss", item.EPSS, "percentile", item.Percentile,
				"score_err", sErr)
			scores[cveID] = repository.EPSSData{}
		case pErr != nil:
			slog.Warn("epss: invalid percentile from FIRST API; keeping score, clearing percentile",
				"cve_id", cveID, "epss", item.EPSS, "percentile", item.Percentile,
				"percentile_err", pErr)
			scores[cveID] = repository.EPSSData{Score: &score}
		default:
			scores[cveID] = repository.EPSSData{
				Score:      &score,
				Percentile: &percentile,
			}
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

	// A clear/tombstone entry (Score == nil) carries no presentable score:
	// answer "not found" exactly like a CVE FIRST did not return, so this
	// path can never leak a fabricated zero. Returned data always has
	// Score != nil; Percentile may still be nil (percentile-only parse
	// failure keeps the score).
	if data, ok := scores[normalized]; ok && data.Score != nil {
		return &data, nil
	}
	return nil, nil
}
