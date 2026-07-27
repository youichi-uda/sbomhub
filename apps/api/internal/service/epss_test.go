package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/repository"
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

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228", "CVE-2021-45046"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	assertNoUnanswered(t, unanswered)
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
	if _, _, err := svc.fetchEPSSScores(context.Background(), batch); err != nil {
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

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{"bogus", "CVE-xxxx", "'; DROP TABLE"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	assertNoUnanswered(t, unanswered)
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

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(),
		[]string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2020-1938"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	assertNoUnanswered(t, unanswered)
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

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{
		"CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003", "CVE-2021-0004",
		"CVE-2021-0005", "CVE-2021-0006", "CVE-2021-0007", "CVE-2021-0008",
	})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	assertNoUnanswered(t, unanswered)
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
	scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	assertNoUnanswered(t, unanswered)

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

// assertNoUnanswered is the default expectation for the fixtures above: every
// requested CVE appears in the canned response, so nothing is left for the
// "FIRST said nothing about this one" path (M46 Codex final round, Medium #3).
func assertNoUnanswered(t *testing.T, unanswered []string) {
	t.Helper()
	if len(unanswered) != 0 {
		t.Errorf("unanswered = %v, want empty (every requested CVE was answered)", unanswered)
	}
}

// TestEPSSService_OmittedCVEsAreReportedAsUnanswered pins the M46 Codex final
// round (Medium #3) contract. FIRST represents "no EPSS data for this CVE" by
// OMITTING it from `data` while still answering HTTP 200 / status OK
// (verified against the live API on 2026-07-27: `?cve=CVE-2026-0001` returns
// total 0, data []). Pre-fix such a CVE produced no map entry at all and
// therefore moved NO timestamp: epss_checked_at stayed exactly as stale as
// before even though a fetch had just been made for it, contradicting
// migration 059's definition of the column as the last fetch ATTEMPT.
// fetchEPSSScores now reports the omitted ids separately so the sync can
// timestamp them WITHOUT touching their scores.
func TestEPSSService_OmittedCVEsAreReportedAsUnanswered(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 1,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99", "date": "2026-07-27"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(),
		[]string{"CVE-2021-44228", "CVE-2026-0000001", "CVE-2026-0000002"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}

	if len(scores) != 1 {
		t.Errorf("len(scores) = %d, want 1 (only the answered CVE has an authoritative value)", len(scores))
	}
	if _, ok := scores["CVE-2026-0000001"]; ok {
		t.Error("an OMITTED CVE must not get a scores entry: UpdateEPSSScores would clear its stored score, and an omission is indistinguishable from a truncated page")
	}

	got := map[string]bool{}
	for _, id := range unanswered {
		got[id] = true
	}
	for _, want := range []string{"CVE-2026-0000001", "CVE-2026-0000002"} {
		if !got[want] {
			t.Errorf("unanswered = %v, want it to contain %q (FIRST omitted it, so only epss_checked_at may advance)", unanswered, want)
		}
	}
	if got["CVE-2021-44228"] {
		t.Errorf("unanswered = %v, must not contain the CVE FIRST actually answered", unanswered)
	}
}

// TestEPSSService_VerbatimDBKeysArePreserved pins the M46 Codex final round
// (Medium #2) contract. vulnerabilities.cve_id is `character varying(50)`
// with a case-sensitive UNIQUE index, no CHECK constraint and no
// normalization on either ingestion path, so the DB can hold a key that is
// not canonical. Pre-fix the returned map was keyed by the CANONICALIZED id,
// which is what `UPDATE ... WHERE cve_id = $3` then compared against — for a
// row stored as `cve-2199-0000001` the sync asked FIRST correctly and then
// updated ZERO rows, reporting success while the stale score kept being
// served. The map must be keyed by the caller's VERBATIM key while the wire
// request stays canonical.
func TestEPSSService_VerbatimDBKeysArePreserved(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 2,
		"data": [
			{"cve": "CVE-2199-0000001", "epss": "0.6", "percentile": "0.7", "date": "2026-07-27"},
			{"cve": "CVE-2199-0000003", "epss": "0.2", "percentile": "0.3", "date": "2026-07-27"}
		]
	}`

	var gotCVEParam string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCVEParam = r.URL.Query().Get("cve")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	// Three stored keys: a lowercase one, a whitespace-padded one, and a
	// canonical one that ALIASES the lowercase key (nothing prevents both
	// rows existing — the UNIQUE index is case-sensitive).
	scores, unanswered, err := svc.fetchEPSSScores(context.Background(),
		[]string{"cve-2199-0000001", " CVE-2199-0000003 ", "CVE-2199-0000001"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}

	// The wire request is canonical and de-duplicated: FIRST speaks the
	// canonical grammar, and asking twice for the same CVE wastes the batch.
	if gotCVEParam != "CVE-2199-0000001,CVE-2199-0000003" {
		t.Errorf("cve param = %q, want %q (canonicalized + de-duplicated on the wire)",
			gotCVEParam, "CVE-2199-0000001,CVE-2199-0000003")
	}

	// ...while every entry is keyed by the exact string the DB gave us, so
	// `WHERE cve_id = <key>` can round-trip.
	for _, key := range []string{"cve-2199-0000001", " CVE-2199-0000003 ", "CVE-2199-0000001"} {
		entry, ok := scores[key]
		if !ok {
			t.Errorf("scores is missing verbatim key %q: the UPDATE would target a canonicalized string that matches no row, leaving the stale score in place", key)
			continue
		}
		if entry.Score == nil {
			t.Errorf("scores[%q].Score = nil, want the value FIRST returned", key)
		}
	}
	if len(scores) != 3 {
		t.Errorf("len(scores) = %d, want 3 (one entry per stored key, aliases included)", len(scores))
	}
	assertNoUnanswered(t, unanswered)

	// The alias pair must carry the SAME answer.
	a, b := scores["cve-2199-0000001"], scores["CVE-2199-0000001"]
	if a.Score == nil || b.Score == nil || *a.Score != *b.Score {
		t.Errorf("alias keys disagree: %v vs %v", a.Score, b.Score)
	}
}

// TestEPSSService_UnansweredKeysAreVerbatimToo: the omitted-CVE path must
// preserve the stored key just like the answered path — a canonicalized entry
// in `unanswered` would make MarkEPSSChecked miss the row for exactly the
// same reason UpdateEPSSScores did.
func TestEPSSService_UnansweredKeysAreVerbatimToo(t *testing.T) {
	const body = `{"status":"OK","status-code":200,"version":"1.0","total":0,"data":[]}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	svc := NewEPSSService(nil, server.URL, false)

	scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{"cve-2199-0000009"})
	if err != nil {
		t.Fatalf("fetchEPSSScores returned error: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("len(scores) = %d, want 0", len(scores))
	}
	if len(unanswered) != 1 || unanswered[0] != "cve-2199-0000009" {
		t.Errorf("unanswered = %v, want [%q] (verbatim stored key)", unanswered, "cve-2199-0000009")
	}
}

// fakeEPSSStore records exactly which per-batch repository calls SyncScores
// makes. It exists because the SyncScores WIRING was untested: every other
// test in this file drives fetchEPSSScores directly, so deleting the
// MarkEPSSChecked call from SyncScores would have left them all green, and
// the integration test cannot substitute (SyncScores sweeps GetAllCVEIDs over
// the whole DB — 10,898 CVEs on the dev box).
type fakeEPSSStore struct {
	all     []string
	listErr error

	updated map[string]repository.EPSSData
	checked []string

	updateErr error
	checkErr  error
}

func (f *fakeEPSSStore) GetAllCVEIDs(context.Context) ([]string, error) { return f.all, f.listErr }

func (f *fakeEPSSStore) UpdateEPSSScores(_ context.Context, scores map[string]repository.EPSSData) error {
	if f.updated == nil {
		f.updated = map[string]repository.EPSSData{}
	}
	for k, v := range scores {
		f.updated[k] = v
	}
	return f.updateErr
}

func (f *fakeEPSSStore) MarkEPSSChecked(_ context.Context, cveIDs []string) error {
	f.checked = append(f.checked, cveIDs...)
	return f.checkErr
}

// TestEPSSService_SyncScores_MarksUnansweredAsChecked pins the wiring: a CVE
// FIRST omitted must reach MarkEPSSChecked (and must NOT reach
// UpdateEPSSScores, which would clear its stored score).
func TestEPSSService_SyncScores_MarksUnansweredAsChecked(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 1,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99", "date": "2026-07-27"}
		]
	}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	// The stored key is deliberately non-canonical so this also pins that
	// SyncScores hands the VERBATIM key to both repository calls.
	store := &fakeEPSSStore{all: []string{"CVE-2021-44228", "cve-2026-0000001"}}
	svc := NewEPSSService(store, server.URL, false)

	if err := svc.SyncScores(context.Background()); err != nil {
		t.Fatalf("SyncScores returned error: %v", err)
	}

	if _, ok := store.updated["CVE-2021-44228"]; !ok {
		t.Errorf("UpdateEPSSScores got %v, want the answered CVE", store.updated)
	}
	if _, ok := store.updated["cve-2026-0000001"]; ok {
		t.Error("the OMITTED CVE reached UpdateEPSSScores: that would clear its stored score on an omission")
	}
	if len(store.checked) != 1 || store.checked[0] != "cve-2026-0000001" {
		t.Errorf("MarkEPSSChecked got %v, want [%q] (migration 059 defines epss_checked_at as the last fetch ATTEMPT, and this CVE was fetched)",
			store.checked, "cve-2026-0000001")
	}
}

// TestEPSSService_SyncScores_ReportsFailuresAndStillTimestamps: a failing
// score write must neither be reported as success nor suppress the
// checked-timestamp write for the CVEs FIRST omitted (they are independent
// facts, and "sync completed" after dropped batches is the quiet-failure
// shape this wave removes).
func TestEPSSService_SyncScores_ReportsFailuresAndStillTimestamps(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 1,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99", "date": "2026-07-27"}
		]
	}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := &fakeEPSSStore{
		all:       []string{"CVE-2021-44228", "CVE-2026-0000001"},
		updateErr: errors.New("boom"),
	}
	svc := NewEPSSService(store, server.URL, false)

	err := svc.SyncScores(context.Background())
	if err == nil {
		t.Error("SyncScores returned nil after a failed batch: the manual trigger answers HTTP 200 'sync completed' on that, hiding an arbitrarily large gap")
	}
	var sawOmitted bool
	for _, id := range store.checked {
		if id == "CVE-2026-0000001" {
			sawOmitted = true
		}
	}
	if !sawOmitted {
		t.Errorf("MarkEPSSChecked got %v, want the omitted CVE recorded even though the score write failed (the fetch attempt still happened)", store.checked)
	}
}

// TestEPSSService_NonOKEnvelopeIsAFetchFailure pins the round-3 fix: HTTP 200
// is not on its own an answer. FIRST wraps every reply in an envelope whose
// `status` is "OK" on success; a body that decodes but does not say OK (an
// error envelope, a proxy's `{}`, an HTML page that happened to parse) would
// otherwise be read as "FIRST answered and mentioned none of these CVEs" —
// which advances epss_checked_at for the whole batch and counts the batch as
// a success.
func TestEPSSService_NonOKEnvelopeIsAFetchFailure(t *testing.T) {
	for name, body := range map[string]string{
		"error envelope": `{"status":"ERROR","status-code":500,"total":0,"data":[]}`,
		"empty object":   `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			svc := NewEPSSService(nil, server.URL, false)
			scores, unanswered, err := svc.fetchEPSSScores(context.Background(), []string{"CVE-2021-44228"})
			if err == nil {
				t.Fatalf("fetchEPSSScores returned nil error for a non-OK envelope; scores=%v unanswered=%v (the batch would be timestamped and counted as a success)", scores, unanswered)
			}
			if len(scores) != 0 || len(unanswered) != 0 {
				t.Errorf("scores=%v unanswered=%v, want both empty on a fetch failure", scores, unanswered)
			}
		})
	}
}

// TestEPSSService_SyncScores_FailedScoreWriteStillTimestampsAnswered pins the
// round-3 fix to the "independent writes" claim: when the score UPDATE fails,
// the ANSWERED CVEs still had their fetch attempt made, so they must reach
// MarkEPSSChecked too — otherwise epss_checked_at silently stops meaning
// "last fetch attempt" for exactly the CVEs whose write failed.
func TestEPSSService_SyncScores_FailedScoreWriteStillTimestampsAnswered(t *testing.T) {
	const body = `{
		"status": "OK", "status-code": 200, "version": "1.0", "total": 1,
		"data": [
			{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99", "date": "2026-07-27"}
		]
	}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := &fakeEPSSStore{
		all:       []string{"CVE-2021-44228", "CVE-2026-0000001"},
		updateErr: errors.New("boom"),
	}
	svc := NewEPSSService(store, server.URL, false)

	err := svc.SyncScores(context.Background())
	if !errors.Is(err, ErrEPSSSyncIncomplete) {
		t.Errorf("SyncScores error = %v, want it to wrap ErrEPSSSyncIncomplete (the manual trigger answers 200 'partial' on that sentinel and 500 otherwise)", err)
	}

	got := map[string]bool{}
	for _, id := range store.checked {
		got[id] = true
	}
	if !got["CVE-2026-0000001"] {
		t.Errorf("MarkEPSSChecked got %v, want the OMITTED CVE recorded", store.checked)
	}
	if !got["CVE-2021-44228"] {
		t.Errorf("MarkEPSSChecked got %v, want the ANSWERED CVE recorded too: its score write failed, but the fetch attempt still happened and that is all epss_checked_at claims", store.checked)
	}
}

// TestEPSSService_SyncScores_HardFailureIsNotIncomplete: a sync that could not
// even read the CVE list applied nothing, so it must NOT wrap
// ErrEPSSSyncIncomplete (the handler would answer 200 "partial" for a run
// that never started).
func TestEPSSService_SyncScores_HardFailureIsNotIncomplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no HTTP call must be made when the CVE list cannot be read")
	}))
	defer server.Close()

	store := &fakeEPSSStore{listErr: errors.New("db down")}
	svc := NewEPSSService(store, server.URL, false)

	err := svc.SyncScores(context.Background())
	if err == nil {
		t.Fatal("SyncScores returned nil when the CVE list could not be read")
	}
	if errors.Is(err, ErrEPSSSyncIncomplete) {
		t.Errorf("SyncScores error = %v, must NOT wrap ErrEPSSSyncIncomplete: nothing was attempted, so the manual trigger must answer 500, not 200 'partial'", err)
	}
}
