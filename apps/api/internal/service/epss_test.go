package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestEPSSService_FetchScores_InjectedURL proves that s.baseURL is actually
// used to build the request URL: we stand up an httptest server returning a
// canned FIRST EPSS API response and assert the scores are parsed from it.
func TestEPSSService_FetchScores_InjectedURL(t *testing.T) {
	const body = `{
		"status": "OK",
		"status-code": 200,
		"version": "1.0",
		"total": 2,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998", "date": "2024-01-15"},
			{"cve": "CVE-2021-45046", "epss": "0.12345", "percentile": "0.54321", "date": "2024-01-15"}
		]
	}`

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	// vulnRepo is not needed for fetchEPSSScores / GetScore paths.
	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228", "CVE-2021-45046"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if !hit {
		t.Fatal("expected the injected server URL to be hit, but it was not")
	}
	if len(scores) != 2 {
		t.Fatalf("expected 2 parsed scores, got %d", len(scores))
	}

	got, ok := scores["CVE-2021-44228"]
	if !ok {
		t.Fatalf("expected score for CVE-2021-44228 to be present")
	}
	if got.Score == nil || *got.Score != 0.97565 {
		t.Errorf("Score = %v, want 0.97565", got.Score)
	}
	if got.Percentile == nil || *got.Percentile != 0.99998 {
		t.Errorf("Percentile = %v, want 0.99998", got.Percentile)
	}

	// GetScore is the exported real-time lookup and must go through baseURL too.
	single, err := svc.GetScore(context.Background(), "CVE-2021-45046")
	if err != nil {
		t.Fatalf("GetScore returned error: %v", err)
	}
	if single == nil {
		t.Fatal("GetScore returned nil for a present CVE")
	}
	if single.Score == nil || *single.Score != 0.12345 {
		t.Errorf("GetScore Score = %v, want 0.12345", single.Score)
	}
}

// TestEPSSService_FiltersMalformedBeforeFetch proves the M42 Wave 1 boundary
// guard: a malformed CVE in a batch is DROPPED before the external URL is built,
// so it never reaches the FIRST EPSS API, while the valid IDs still go through
// as a comma-separated batch. The httptest handler inspects the actual query it
// received and fails the test if the malformed token leaked through.
func TestEPSSService_FiltersMalformedBeforeFetch(t *testing.T) {
	const body = `{"status":"OK","status-code":200,"version":"1.0","total":0,"data":[]}`

	var gotRawQuery, gotCVEParam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		gotCVEParam = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	// One valid ID, one hostile/malformed token, one more valid ID.
	batch := []string{"CVE-2021-44228", "not a cve! OR 1=1", "CVE-2021-45046"}
	if _, err := svc.fetchEPSSScores(context.Background(), batch); err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}

	// The malformed token must be entirely absent from the outbound request.
	if strings.Contains(gotRawQuery, "OR") || strings.Contains(gotRawQuery, "1=1") ||
		strings.Contains(gotCVEParam, "OR") || strings.Contains(gotCVEParam, "not") {
		t.Fatalf("malformed CVE leaked into the EPSS request: rawQuery=%q cve=%q", gotRawQuery, gotCVEParam)
	}

	// The two valid IDs must survive as a literal comma-separated batch (the
	// comma is a legitimate separator EPSS expects, not %2C-encoded).
	if gotCVEParam != "CVE-2021-44228,CVE-2021-45046" {
		t.Errorf("cve param = %q, want %q (comma-separated batch preserved)", gotCVEParam, "CVE-2021-44228,CVE-2021-45046")
	}
	if gotRawQuery != "cve=CVE-2021-44228,CVE-2021-45046" {
		t.Errorf("raw query = %q, want %q", gotRawQuery, "cve=CVE-2021-44228,CVE-2021-45046")
	}
}

// TestEPSSService_AllMalformed_NoFetch proves that a batch containing only
// malformed IDs never makes an HTTP call at all (the server handler fails the
// test if reached) and returns an empty, error-free result.
func TestEPSSService_AllMalformed_NoFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no HTTP call must be made when every CVE in the batch is malformed; got %q", r.URL.RawQuery)
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(), []string{"bogus", "CVE-xxxx", "'; DROP TABLE"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected empty scores for an all-malformed batch, got %d", len(scores))
	}
}

// TestEPSSService_GetScore_MalformedRejectedNoFetch proves the single real-time
// lookup validates its input first and returns validation.ErrInvalidCVEID
// WITHOUT any external call (the handler maps that to 400).
func TestEPSSService_GetScore_MalformedRejectedNoFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GetScore must not make an HTTP call for a malformed CVE; got %q", r.URL.RawQuery)
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	_, err := svc.GetScore(context.Background(), "definitely-not-a-cve")
	if err == nil {
		t.Fatal("GetScore(malformed) returned nil error, want validation error")
	}
}

// TestEPSSService_EscapeMechanism documents the defence-in-depth encoder used
// when building the cve param. Validated CVE IDs contain only [A-Z0-9-] (which
// QueryEscape leaves untouched, so real batches are unchanged), but the encoder
// still percent-encodes anything dangerous — this pins that contract.
func TestEPSSService_EscapeMechanism(t *testing.T) {
	// A valid CVE is passed through verbatim.
	if got := url.QueryEscape("CVE-2021-44228"); got != "CVE-2021-44228" {
		t.Errorf("QueryEscape(valid CVE) = %q, want it unchanged", got)
	}
	// A hostile value with a space + ampersand is neutralised (no raw
	// separators survive to break out of the cve param).
	got := url.QueryEscape("CVE-2021-4 &x")
	if strings.ContainsAny(got, " &") {
		t.Errorf("QueryEscape(hostile) = %q, want no raw space/ampersand", got)
	}
}

// TestEPSSService_MalformedValues_PartialKeepAndTombstone pins the M46 Codex
// round C (Medium) contract for malformed FIRST values. ca94806 correctly
// stopped fabricating 0.0 for unparseable strings but skipped the whole item
// (`continue`), which (a) left any previously-synced DB value in place being
// served as current — SSVC auto-assessment reads it with no freshness signal —
// and (b) threw away a perfectly good score when only the percentile was
// malformed. The required behaviour:
//
//   - score OK, percentile malformed -> entry present with the score KEPT and
//     the percentile explicitly absent (persisted as NULL);
//   - score malformed -> entry present as an explicit clear/tombstone (both
//     values absent -> both columns persisted as NULL), never a silent skip;
//   - fully well-formed items are unaffected.
func TestEPSSService_MalformedValues_PartialKeepAndTombstone(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 3,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998", "date": "2026-07-27"},
			{"cve": "CVE-2021-45046", "epss": "0.7", "percentile": "broken", "date": "2026-07-27"},
			{"cve": "CVE-2020-1938", "epss": "broken", "percentile": "0.95", "date": "2026-07-27"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(),
		[]string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2020-1938"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if len(scores) != 3 {
		t.Errorf("len(scores) = %d, want 3: every answered CVE needs an explicit entry (skipping leaves stale DB values being served as current)", len(scores))
	}

	// Fully well-formed item: both values set.
	if good, ok := scores["CVE-2021-44228"]; !ok {
		t.Error("well-formed item missing from scores")
	} else {
		if good.Score == nil || *good.Score != 0.97565 {
			t.Errorf("well-formed Score = %v, want 0.97565", good.Score)
		}
		if good.Percentile == nil || *good.Percentile != 0.99998 {
			t.Errorf("well-formed Percentile = %v, want 0.99998", good.Percentile)
		}
	}

	// Percentile-only failure: score kept, percentile explicitly absent.
	if part, ok := scores["CVE-2021-45046"]; !ok {
		t.Error("percentile-only parse failure must not discard the item (the valid score was being thrown away)")
	} else {
		if part.Score == nil || *part.Score != 0.7 {
			t.Errorf("partial Score = %v, want 0.7 (kept despite broken percentile)", part.Score)
		}
		if part.Percentile != nil {
			t.Errorf("partial Percentile = %v, want nil (persisted as NULL, not fabricated)", *part.Percentile)
		}
	}

	// Score failure: explicit tombstone — both values absent so the
	// repository clears both columns to NULL.
	if tombEntry, ok := scores["CVE-2020-1938"]; !ok {
		t.Error("score parse failure must yield an explicit clear entry, not a skip (skip keeps the previous sync's stale value)")
	} else {
		if tombEntry.Score != nil {
			t.Errorf("tombstone Score = %v, want nil", *tombEntry.Score)
		}
		if tombEntry.Percentile != nil {
			t.Errorf("tombstone Percentile = %v, want nil (percentile without score is fabricated junk)", *tombEntry.Percentile)
		}
	}

	// GetScore must surface the kept score for the percentile-broken CVE
	// (pre-fix it returned nil / handler 404 despite FIRST serving a score).
	partial, err := svc.GetScore(context.Background(), "CVE-2021-45046")
	if err != nil {
		t.Fatalf("GetScore returned error: %v", err)
	}
	if partial == nil {
		t.Error("GetScore(CVE-2021-45046) = nil, want the parsed score 0.7 (percentile failure must not hide the score)")
	} else if partial.Score == nil || *partial.Score != 0.7 {
		t.Errorf("GetScore(CVE-2021-45046).Score = %v, want 0.7", partial.Score)
	}

	// A tombstone has no presentable score: GetScore keeps answering nil
	// (handler 404) — same externally visible result as pre-fix, pinned so
	// the tombstone entry never leaks a fabricated zero through this path.
	tomb, err := svc.GetScore(context.Background(), "CVE-2020-1938")
	if err != nil {
		t.Fatalf("GetScore returned error: %v", err)
	}
	if tomb != nil {
		t.Errorf("GetScore(CVE-2020-1938) = %+v, want nil (malformed score has no presentable value)", tomb)
	}
}

// TestEPSSService_NonFiniteAndOutOfRangeValues pins the M46 Codex final round
// (Medium #2) contract: strconv.ParseFloat SUCCESS is not the same as a valid
// EPSS value. ParseFloat happily accepts "NaN", "Inf"/"-Inf" and out-of-range
// decimals like "1.1" / "-0.1" — pre-fix those flowed through as *real*
// scores: 110% probabilities in the UI, NaN breaking JSON marshalling of any
// response embedding the score, and values > 9.9999 aborting the DECIMAL(5,4)
// UPDATE mid-sync (leaving stale values served as current). An EPSS
// score/percentile is a probability: it must be finite AND within [0,1].
// Anything else is treated exactly like an unparseable string under the
// def6a46 contract — score invalid => tombstone both columns; percentile
// invalid => keep score, clear percentile.
func TestEPSSService_NonFiniteAndOutOfRangeValues(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 8,
		"data": [
			{"cve": "CVE-2021-0001", "epss": "1.1",  "percentile": "0.5", "date": "2026-07-27"},
			{"cve": "CVE-2021-0002", "epss": "-0.1", "percentile": "0.5", "date": "2026-07-27"},
			{"cve": "CVE-2021-0003", "epss": "NaN",  "percentile": "0.5", "date": "2026-07-27"},
			{"cve": "CVE-2021-0004", "epss": "Inf",  "percentile": "0.5", "date": "2026-07-27"},
			{"cve": "CVE-2021-0005", "epss": "0.4",  "percentile": "1.5", "date": "2026-07-27"},
			{"cve": "CVE-2021-0006", "epss": "0.4",  "percentile": "NaN", "date": "2026-07-27"},
			{"cve": "CVE-2021-0007", "epss": "0",    "percentile": "1",   "date": "2026-07-27"},
			{"cve": "CVE-2021-0008", "epss": "1",    "percentile": "0",   "date": "2026-07-27"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, err := svc.fetchEPSSScores(context.Background(), []string{
		"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004",
		"CVE-2021-0005", "CVE-2021-0006", "CVE-2021-0007", "CVE-2021-0008",
	})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if len(scores) != 8 {
		t.Errorf("len(scores) = %d, want 8 (every answered CVE gets an explicit entry)", len(scores))
	}

	// Invalid score (out-of-range or non-finite) => tombstone (both nil).
	for _, cve := range []string{"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004"} {
		entry, ok := scores[cve]
		if !ok {
			t.Errorf("%s: missing entry, want explicit tombstone", cve)
			continue
		}
		if entry.Score != nil {
			t.Errorf("%s: Score = %v, want nil (out-of-range/non-finite score must not be stored)", cve, *entry.Score)
		}
		if entry.Percentile != nil {
			t.Errorf("%s: Percentile = %v, want nil (no percentile without a score)", cve, *entry.Percentile)
		}
	}

	// Invalid percentile with valid score => score kept, percentile nil.
	for _, cve := range []string{"CVE-2021-0005", "CVE-2021-0006"} {
		entry, ok := scores[cve]
		if !ok {
			t.Errorf("%s: missing entry, want score-only entry", cve)
			continue
		}
		if entry.Score == nil || *entry.Score != 0.4 {
			t.Errorf("%s: Score = %v, want 0.4 (valid score survives an invalid percentile)", cve, entry.Score)
		}
		if entry.Percentile != nil {
			t.Errorf("%s: Percentile = %v, want nil", cve, *entry.Percentile)
		}
	}

	// The [0,1] boundaries themselves are legal values, not violations.
	if entry, ok := scores["CVE-2021-0007"]; !ok || entry.Score == nil || *entry.Score != 0 ||
		entry.Percentile == nil || *entry.Percentile != 1 {
		t.Errorf("CVE-2021-0007 = %+v, want Score=0 Percentile=1 (boundary values are valid)", entry)
	}
	if entry, ok := scores["CVE-2021-0008"]; !ok || entry.Score == nil || *entry.Score != 1 ||
		entry.Percentile == nil || *entry.Percentile != 0 {
		t.Errorf("CVE-2021-0008 = %+v, want Score=1 Percentile=0 (boundary values are valid)", entry)
	}
}

// TestEPSSService_UnrequestedOrMalformedResponseCVEs pins the M46 Codex final
// round (Low #1) contract: the persisted map is keyed ONLY by normalized CVE
// ids that were actually part of THIS request's batch. Pre-fix the map was
// keyed by the raw response `item.CVE` with no membership check, so a FIRST
// 200 response containing a malformed item for an UNREQUESTED CVE would
// tombstone that global vulnerabilities row's EPSS for every tenant — the
// upstream response body could reach into rows this sync was never asked
// about. A response id in non-canonical case for a REQUESTED CVE is still
// accepted (normalized), so legitimate answers cannot be dropped over casing.
func TestEPSSService_UnrequestedOrMalformedResponseCVEs(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 4,
		"data": [
			{"cve": "cve-2021-44228",   "epss": "0.9",    "percentile": "0.99", "date": "2026-07-27"},
			{"cve": "CVE-2020-7777777", "epss": "broken", "percentile": "0.5",  "date": "2026-07-27"},
			{"cve": "CVE-2020-8888888", "epss": "0.8",    "percentile": "0.5",  "date": "2026-07-27"},
			{"cve": "not-a-cve at all", "epss": "broken", "percentile": "0.5",  "date": "2026-07-27"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	// Only CVE-2021-44228 is requested. The response also carries: a
	// malformed item for unrequested CVE-2020-7777777 (would be a global
	// tombstone pre-fix), a well-formed item for unrequested
	// CVE-2020-8888888 (would be a write pre-fix), and a garbage id.
	scores, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}

	if len(scores) != 1 {
		t.Errorf("len(scores) = %d, want 1 (only the requested CVE may be persisted)", len(scores))
	}
	if _, ok := scores["CVE-2020-7777777"]; ok {
		t.Error("unrequested CVE-2020-7777777 present: its malformed item would tombstone a global row this sync never asked about")
	}
	if _, ok := scores["CVE-2020-8888888"]; ok {
		t.Error("unrequested CVE-2020-8888888 present: unsolicited response items must not be persisted")
	}
	for k := range scores {
		if k == "not-a-cve at all" || k == "cve-2021-44228" {
			t.Errorf("scores map carries raw/unnormalized key %q", k)
		}
	}

	// The requested CVE, answered in lowercase, must still land under its
	// normalized key with its values intact.
	entry, ok := scores["CVE-2021-44228"]
	if !ok {
		t.Fatal("requested CVE-2021-44228 missing: a case-variant answer for a requested id must be normalized and kept, not dropped")
	}
	if entry.Score == nil || *entry.Score != 0.9 {
		t.Errorf("Score = %v, want 0.9", entry.Score)
	}
	if entry.Percentile == nil || *entry.Percentile != 0.99 {
		t.Errorf("Percentile = %v, want 0.99", entry.Percentile)
	}
}

// TestEPSSService_Offline asserts that offline mode short-circuits BEFORE any
// HTTP call is made. The server handler fails the test if it is ever reached.
func TestEPSSService_Offline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not make HTTP calls")
	}))
	defer server.Close()

	// nil vulnRepo is safe: the offline guard returns before the repo is touched.
	svc := NewEPSSService(nil, server.URL, true)

	// SyncScores must return nil without hitting the network or the repo.
	if err := svc.SyncScores(context.Background()); err != nil {
		t.Errorf("SyncScores in offline mode returned error: %v", err)
	}

	// GetScore must return (nil, nil) in offline mode.
	data, err := svc.GetScore(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Errorf("GetScore in offline mode returned error: %v", err)
	}
	if data != nil {
		t.Errorf("GetScore in offline mode returned data %+v, want nil", data)
	}
}
