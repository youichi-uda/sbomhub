package service

import (
	"context"
	"encoding/json"
	"errors"
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

// ErrEPSSSyncIncomplete marks a sync that STARTED and applied some of its
// work but could not finish every batch. It is deliberately distinct from a
// hard failure (the CVE list could not be read, so nothing was attempted):
// the manual HTTP trigger answers 200 "partial" for this one, because the
// sweep is non-transactional and the batches that DID apply are already
// committed — a 500 would roll back only the request's own audit row while
// leaving those writes in place, reporting less truth, not more.
var ErrEPSSSyncIncomplete = errors.New("epss sync incomplete")

// epssStore is the slice of VulnerabilityRepository this service needs. It
// exists so the SyncScores WIRING — which per-batch call happens with which
// arguments — is testable without a live 10k-row DB sweep (M46 Codex final
// round follow-up). *repository.VulnerabilityRepository satisfies it, so
// production call sites are unchanged.
type epssStore interface {
	GetAllCVEIDs(ctx context.Context) ([]string, error)
	UpdateEPSSScores(ctx context.Context, scores map[string]repository.EPSSData) error
	MarkEPSSChecked(ctx context.Context, cveIDs []string) error
}

type EPSSService struct {
	client   *http.Client
	vulnRepo epssStore
	baseURL  string
	offline  bool
}

func NewEPSSService(vulnRepo epssStore, baseURL string, offline bool) *EPSSService {
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

// SyncScores fetches EPSS scores for all CVEs in the database.
//
// Failure handling (M46 Codex final round follow-up): a batch that fails is
// logged, counted and SKIPPED, but the sweep continues — one unreachable
// batch must not strand the remaining thousands of CVEs on stale values. At
// the end the counts are summarised into a returned error, because the
// pre-fix `continue` + `return nil` shape reported "sync completed" (and HTTP
// 200 from the manual trigger) after silently dropping arbitrarily many
// batches, which is the same class of quiet-failure this wave exists to
// remove. The score write and the checked-timestamp write are INDEPENDENT: a
// failed UpdateEPSSScores no longer suppresses MarkEPSSChecked, because the
// fetch attempt happened either way and that is all epss_checked_at claims.
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

	totalBatches := 0
	failedBatches := 0

	// Process in batches
	for i := 0; i < len(cveIDs); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]
		totalBatches++

		scores, unanswered, err := s.fetchEPSSScores(ctx, batch)
		if err != nil {
			slog.Error("Failed to fetch EPSS scores for batch", "error", err, "batch_start", i)
			failedBatches++
			continue
		}

		batchFailed := false
		// checkOnly starts as the CVEs FIRST omitted; a failed score write
		// adds the ANSWERED ones to it, because their fetch attempt happened
		// too and epss_checked_at claims nothing more than that. Without this
		// the "independent writes" contract would be false for exactly the
		// case it matters in (M46 Codex final round, round 3).
		checkOnly := unanswered
		if len(scores) > 0 {
			if err := s.vulnRepo.UpdateEPSSScores(ctx, scores); err != nil {
				slog.Error("Failed to update EPSS scores", "error", err, "batch_start", i)
				batchFailed = true
				for k := range scores {
					checkOnly = append(checkOnly, k)
				}
			}
		}

		// CVEs FIRST omitted from an otherwise-successful 200 still had a
		// fetch attempt made for them, and migration 059 defines
		// epss_checked_at as exactly that (M46 Codex final round, Medium #3).
		// Pre-fix only CVEs PRESENT in `data` moved any timestamp, so a CVE
		// FIRST does not cover never advanced checked_at and the column did
		// not mean what its DDL COMMENT said. See MarkEPSSChecked for why the
		// omission is NOT treated as an authoritative "no data" tombstone.
		//
		// This runs even when the score write above failed: the two record
		// different facts and the fetch attempt is not undone by a failed
		// UPDATE.
		if len(checkOnly) > 0 {
			if err := s.vulnRepo.MarkEPSSChecked(ctx, checkOnly); err != nil {
				slog.Error("Failed to record EPSS check timestamp",
					"error", err, "count", len(checkOnly), "batch_start", i)
				batchFailed = true
			}
		}
		// Report what was ATTEMPTED, and say so when part of it did not
		// land — "Updated EPSS scores count=100" after a failed write is the
		// same overstatement this wave is auditing for.
		if batchFailed {
			failedBatches++
			slog.Warn("EPSS batch partially applied", "batch", i/epssBatchSize+1,
				"answered", len(scores), "unanswered", len(unanswered))
		} else {
			slog.Info("Updated EPSS scores", "batch", i/epssBatchSize+1,
				"count", len(scores), "unanswered", len(unanswered))
		}

		// Rate limiting - be nice to the API
		time.Sleep(500 * time.Millisecond)
	}

	if failedBatches > 0 {
		slog.Error("EPSS sync completed with failures", "failed_batches", failedBatches, "total_batches", totalBatches)
		// Deliberately does NOT claim the failed batches were left untouched:
		// UpdateEPSSScores applies per CVE and reports an aggregate, so a
		// failed batch may be partially applied. All that is asserted is that
		// the sweep is incomplete and should be retried.
		return fmt.Errorf("%w: %d of %d batches did not fully apply; those CVEs may still hold values from an earlier sync",
			ErrEPSSSyncIncomplete, failedBatches, totalBatches)
	}

	slog.Info("EPSS sync completed", "batches", totalBatches)
	return nil
}

// fetchEPSSScores asks FIRST about one batch and returns
//
//	scores     — the authoritative values to persist, keyed by the VERBATIM
//	             cve_id string the caller passed in (i.e. the DB key);
//	unanswered — the caller's verbatim ids that FIRST's 200 did NOT mention.
//
// The keying is load-bearing (M46 Codex final round, Medium #2). The ids sent
// to FIRST are ValidateCVEID-canonicalized (trimmed, upper-cased) because that
// is the grammar the API speaks and because the response echoes CVEs in
// canonical case. Pre-fix the returned map was keyed by that CANONICAL form
// and handed straight to `UPDATE vulnerabilities ... WHERE cve_id = $3` — a
// case-sensitive comparison against a `character varying(50)` column with no
// CHECK constraint and no normalization on either ingestion path
// (VulnerabilityRepository.Create and scheduler/cve_sync.upsertVulnerability
// both store the upstream string verbatim). A row stored as `cve-2199-0001`
// would therefore be ASKED about correctly and then updated with
// `WHERE cve_id = 'CVE-2199-0001'`, matching zero rows: the sync reports
// success and the stale score keeps being served. Preserving the caller's
// exact key makes the write target the row the read came from, by
// construction, whatever the DB happens to contain.
//
// A canonical id can map back to MORE than one stored key (nothing stops
// `CVE-2199-0001` and `cve-2199-0001` both existing — the UNIQUE index is
// case-sensitive too), so the mapping is one-to-many and every alias receives
// the same answer.
func (s *EPSSService) fetchEPSSScores(ctx context.Context, cveIDs []string) (map[string]repository.EPSSData, []string, error) {
	// Validate + normalize every CVE ID and DROP any malformed one before it
	// can reach the external FIRST EPSS URL. A single bad ID must not fail the
	// whole batch — it is filtered out and logged (M42 Wave 1). This is the
	// input-boundary guard for the request; the escaping below is defence in
	// depth.
	//
	// requested maps canonical id -> the caller's verbatim key(s) it came
	// from; validIDs is the de-duplicated canonical list, in first-seen order,
	// that goes on the wire.
	requested := make(map[string][]string, len(cveIDs))
	validIDs := make([]string, 0, len(cveIDs))
	for _, raw := range cveIDs {
		id, err := validation.ValidateCVEID(raw)
		if err != nil {
			slog.Warn("epss: dropping malformed CVE ID from batch", "cve_id", raw)
			continue
		}
		if _, seen := requested[id]; !seen {
			validIDs = append(validIDs, id)
		}
		requested[id] = append(requested[id], raw)
	}
	if len(validIDs) == 0 {
		// Nothing valid to ask about — return an empty result rather than
		// hitting the API with an empty query. Malformed ids are NOT reported
		// as unanswered: no fetch was attempted for them, so there is nothing
		// to timestamp.
		return map[string]repository.EPSSData{}, nil, nil
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
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode EPSS response: %w", err)
	}

	// HTTP 200 is not on its own an answer (M46 Codex final round, round 3).
	// FIRST wraps every reply in an envelope whose `status` is "OK" on
	// success (measured against the live API 2026-07-27). A body that decodes
	// but does not say OK — an error envelope, an HTML error page that
	// happened to parse, a proxy's `{}` — would otherwise be read as "FIRST
	// answered and mentioned none of these CVEs", which now advances
	// epss_checked_at for the whole batch and reports the batch as a success.
	// Treat it as a fetch failure instead: nothing is written and the batch
	// is counted against the sync.
	if !strings.EqualFold(epssResp.Status, "OK") {
		return nil, nil, fmt.Errorf("EPSS API returned non-OK envelope status %q (status-code %d)",
			epssResp.Status, epssResp.StatusCode)
	}

	// FIRST paginates: `total` is the number of MATCHING records and `data`
	// is capped at `limit` (measured against the live API 2026-07-27:
	// `?cve=CVE-2021-44228,CVE-2022-27225&limit=1` answers total=2 with a
	// single data item). The default limit is 100 — exactly epssBatchSize —
	// so a full batch of covered CVEs sits ON the page boundary with no
	// margin. Under truncation the missing CVEs are indistinguishable from
	// CVEs FIRST simply does not cover, which is the concrete reason the
	// omitted set below is only TIMESTAMPED and never tombstoned. Say so
	// loudly when it happens.
	if epssResp.Total > len(epssResp.Data) {
		slog.Warn("epss: FIRST response is paginated; some requested CVEs were not returned in this page",
			"total", epssResp.Total, "returned", len(epssResp.Data),
			"limit", epssBatchSize, "requested", len(validIDs))
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
	answered := make(map[string]struct{}, len(validIDs))
	scores := make(map[string]repository.EPSSData, len(cveIDs))
	for _, item := range epssResp.Data {
		cveID, err := validation.ValidateCVEID(item.CVE)
		if err != nil {
			slog.Warn("epss: dropping response item with malformed CVE id", "cve", item.CVE)
			continue
		}
		dbKeys, ok := requested[cveID]
		if !ok {
			slog.Warn("epss: dropping unrequested CVE from FIRST response", "cve_id", cveID)
			continue
		}
		answered[cveID] = struct{}{}
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
		var data repository.EPSSData
		switch {
		case sErr != nil:
			slog.Warn("epss: invalid score from FIRST API; clearing stored EPSS for CVE",
				"cve_id", cveID, "epss", item.EPSS, "percentile", item.Percentile,
				"score_err", sErr)
			data = repository.EPSSData{}
		case pErr != nil:
			slog.Warn("epss: invalid percentile from FIRST API; keeping score, clearing percentile",
				"cve_id", cveID, "epss", item.EPSS, "percentile", item.Percentile,
				"percentile_err", pErr)
			data = repository.EPSSData{Score: &score}
		default:
			data = repository.EPSSData{
				Score:      &score,
				Percentile: &percentile,
			}
		}
		// One answer, replayed onto every stored key that canonicalizes to
		// this CVE (normally exactly one).
		for _, k := range dbKeys {
			scores[k] = data
		}
	}

	// Everything asked about that the 200 did not mention. FIRST represents
	// "no EPSS data for this CVE" by OMISSION, not by an error or a null
	// item (measured against the live API 2026-07-27: `?cve=CVE-2026-0001`
	// answers HTTP 200, status OK, total 0, data []), so an omission is a
	// normal outcome, not a fault. It is reported separately because the two
	// halves get different treatment — see MarkEPSSChecked.
	var unanswered []string
	for _, id := range validIDs {
		if _, ok := answered[id]; ok {
			continue
		}
		unanswered = append(unanswered, requested[id]...)
	}

	return scores, unanswered, nil
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

	// Read-only passthrough: unlike SyncScores this never persists anything,
	// so the unanswered set is discarded rather than timestamped (a CVE FIRST
	// does not cover simply answers "not found" to the caller).
	scores, _, err := s.fetchEPSSScores(ctx, []string{normalized})
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
