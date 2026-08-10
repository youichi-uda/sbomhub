package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// cannedNVDPager is a canned NVD CVE API 2.0 endpoint that honours
// resultsPerPage / startIndex the way the live service does.
//
// Its envelope behaviour is copied from MEASURED live responses
// (2026-08-11, services.nvd.nist.gov), not from the prose spec:
//
//	keywordSearch=openssl&resultsPerPage=200                -> resultsPerPage=200 startIndex=0   totalResults=563
//	keywordSearch=openssl&resultsPerPage=200&startIndex=200 -> resultsPerPage=200 startIndex=200 totalResults=563
//	keywordSearch=openssl&resultsPerPage=200&startIndex=400 -> resultsPerPage=163 startIndex=400 totalResults=563
//
// The third line is the one that matters for validate(): on the LAST page the
// API reports resultsPerPage as the number of records actually in that
// response (163), not the number that was requested (200), and it echoes the
// requested startIndex.
type cannedNVDPager struct {
	total int
	mu    sync.Mutex
	// queries records every request line, in order.
	queries []string
	// rewrite, when set, corrupts or perturbs the envelope just before it is
	// serialised. `page` is the 0-based index of this request within the walk.
	rewrite func(page int, resp *NVDResponse)
}

func (c *cannedNVDPager) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.queries))
	copy(out, c.queries)
	return out
}

func (c *cannedNVDPager) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.queries = append(c.queries, r.URL.RawQuery)
		page := len(c.queries) - 1
		c.mu.Unlock()

		rpp := 20
		if v := r.URL.Query().Get("resultsPerPage"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Errorf("resultsPerPage %q is not a number", v)
			}
			rpp = n
		}
		start := 0
		if v := r.URL.Query().Get("startIndex"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Errorf("startIndex %q is not a number", v)
			}
			start = n
		}

		n := rpp
		if start+n > c.total {
			n = c.total - start
		}
		if n < 0 {
			n = 0
		}
		entries := make([]NVDVulnEntry, 0, n)
		for i := 0; i < n; i++ {
			entries = append(entries, NVDVulnEntry{CVE: NVDCVE{
				ID:           m55CVEID(start + i),
				Published:    "2093-01-01T00:00:00.000",
				Descriptions: []NVDDesc{{Lang: "en", Value: "m55 paging probe"}},
			}})
		}
		resp := NVDResponse{
			ResultsPerPage:  nvdIntPtr(len(entries)),
			StartIndex:      nvdIntPtr(start),
			TotalResults:    nvdIntPtr(c.total),
			Vulnerabilities: nvdEntriesPtr(entries),
		}
		if c.rewrite != nil {
			c.rewrite(page, &resp)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode canned NVD page: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// m55CVEID gives every synthetic record a distinct, well-formed id in a year
// no real CVE uses, so validate()'s cve.id check is exercised rather than
// worked around.
func m55CVEID(i int) string { return fmt.Sprintf("CVE-2093-%07d", i) }

// TestM55SearchByKeyword_ReturnsEveryMatchWithinTheBudget is the reproduction.
//
// searchByKeyword asked for resultsPerPage=20, decoded ONE response and
// returned, never reading totalResults and never issuing the startIndex
// follow-ups the NVD API requires. Measured against the live API on 2026-08-11
// (one request per keyword at resultsPerPage=1, reading totalResults), with
// each keyword built exactly as searchByKeyword builds it:
//
//	jackson-databind 2.9.10   44 matches   -> 24 dropped, silently
//	curl (no version)        322 matches   -> 302 dropped
//	openssl (no version)     563 matches   -> 543 dropped
//	linux (no version)     21670 matches   -> 21650 dropped
//
// The first line is the one that makes this a Critical rather than a curiosity:
// it is an ordinary versioned Java component, of the kind every SBOM this
// product scans is full of.
//
// The request counts asserted below are the other half of the fix. Everything
// up to nvdPageSize costs ONE request — the same one the truncated
// implementation spent — so repairing the common case is free.
func TestM55SearchByKeyword_ReturnsEveryMatchWithinTheBudget(t *testing.T) {
	cases := []struct {
		total     int
		wantPages int
	}{
		{0, 1},
		{20, 1},
		{21, 1},   // the smallest set the old resultsPerPage=20 truncated
		{44, 1},   // measured: jackson-databind 2.9.10
		{200, 1},  // exactly one page
		{201, 2},  // one over
		{350, 2},  // measured shape: 2 pages, second one short
		{563, 3},  // measured: openssl
		{1000, 5}, // exactly the budget
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("total=%d", tc.total), func(t *testing.T) {
			pager := &cannedNVDPager{total: tc.total}
			srv := pager.start(t)

			svc := NewNVDService(nil, nil, "k", srv.URL, false)
			res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
			if err != nil {
				t.Fatalf("searchByKeyword: %v", err)
			}
			if len(res.vulns) != tc.total {
				t.Errorf("got %d of %d matches (%d dropped, requests=%v); a component's "+
					"omitted matches can hold the critical CVE that should have failed the build",
					len(res.vulns), tc.total, tc.total-len(res.vulns), pager.calls())
			}
			if res.truncated {
				t.Errorf("a result set of %d that was fully fetched must not be reported as "+
					"truncated", tc.total)
			}
			if got := len(pager.calls()); got != tc.wantPages {
				t.Errorf("issued %d NVD requests, want %d: %v", got, tc.wantPages, pager.calls())
			}
			// The first request must carry the page size and an explicit
			// startIndex, so that validate() has something to check the answer
			// against on the request that matters most.
			first := pager.calls()[0]
			for _, want := range []string{
				"resultsPerPage=" + strconv.Itoa(nvdPageSize),
				"startIndex=0",
			} {
				if !strings.Contains(first, want) {
					t.Errorf("first request %q does not contain %q", first, want)
				}
			}
		})
	}
}

// TestM55SearchByKeyword_StopsAtTheBudgetAndSaysSo pins the other half of the
// design: the walk is BOUNDED, and when the bound is what stopped it the result
// is reported as incomplete rather than returned as if it were the whole set.
//
// The measured case behind this is keywordSearch=linux: 21670 matches, which is
// 109 pages. Fetching them all would cost 76 s of rate limit for ONE component
// with an API key (11 minutes without one) and would then link 21670 CVEs to
// that component, none of which is evidence of anything. See searchByKeyword.
func TestM55SearchByKeyword_StopsAtTheBudgetAndSaysSo(t *testing.T) {
	const total = 21670 // measured: keywordSearch=linux, 2026-08-11
	pager := &cannedNVDPager{total: total}
	srv := pager.start(t)

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "linux", "", nil)
	if err != nil {
		t.Fatalf("searchByKeyword: %v", err)
	}

	wantFetched := nvdPageSize * nvdMaxPagesPerComponent
	if res.fetched != wantFetched {
		t.Errorf("fetched %d, want %d (%d pages x %d)",
			res.fetched, wantFetched, nvdMaxPagesPerComponent, nvdPageSize)
	}
	if got := len(pager.calls()); got != nvdMaxPagesPerComponent {
		t.Errorf("issued %d requests, want the budget %d", got, nvdMaxPagesPerComponent)
	}
	if !res.truncated {
		t.Fatalf("a walk that stopped at the budget with %d of %d matches reported itself "+
			"COMPLETE; that is the silent truncation this change exists to remove",
			res.fetched, total)
	}
	if res.total != total {
		t.Errorf("total = %d, want NVD's own totalResults %d", res.total, total)
	}
}

// TestM55SearchByKeyword_RefusesAPageThatIsNotTheOneAsked pins why the
// startIndex check had to become page-aware rather than be dropped.
//
// With paging, a server that answers every follow-up with page ZERO would let
// the walk collect the same records five times, count 1000 "fetched" against a
// totalResults of 1000, and declare the set complete. The M54 check (startIndex
// must be 0) would have accepted exactly that.
func TestM55SearchByKeyword_RefusesAPageThatIsNotTheOneAsked(t *testing.T) {
	pager := &cannedNVDPager{total: 350}
	pager.rewrite = func(page int, resp *NVDResponse) {
		if page == 1 {
			// The follow-up answers with page zero's coordinates.
			resp.StartIndex = nvdIntPtr(0)
		}
	}
	srv := pager.start(t)

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
	if err == nil {
		t.Fatalf("a follow-up page that is not the page requested was accepted "+
			"(fetched=%d truncated=%v); the walk would count the same records twice and "+
			"call the result complete", res.fetched, res.truncated)
	}
	if !strings.Contains(err.Error(), "startIndex") {
		t.Errorf("error does not name the mismatched page: %v", err)
	}
}

// TestM55SearchByKeyword_AShiftedResultSetIsNotProvablyComplete is the Codex
// M55 R1 (Critical) regression.
//
// Paging is by OFFSET. If a record is removed from the middle of the result set
// between two requests, every later record slides down one position and the
// record that occupied the next startIndex is returned by NO request. Counting
// records — or counting DE-DUPLICATED records — cannot see that: the missing
// record is simply absent, and the arithmetic still comes out even. The first
// cut of this walk reported such a lookup as complete, which is the same silent
// under-report the whole change exists to remove, reached by a different route.
//
// What IS observable is the disturbance: totalResults changing, or a record
// arriving twice (the mirror image, caused by an insertion). Either one means
// the offsets are no longer coherent and completeness cannot be claimed.
//
// The subtests below are the two symptoms, plus the control that must stay
// green so this does not degrade into "always report truncated".
func TestM55SearchByKeyword_AShiftedResultSetIsNotProvablyComplete(t *testing.T) {
	t.Run("totalResults changes mid-walk", func(t *testing.T) {
		pager := &cannedNVDPager{total: 350}
		pager.rewrite = func(page int, resp *NVDResponse) {
			if page >= 1 {
				// One record was removed between the two requests, so the
				// remaining set is 349 and every record after the removed one
				// has slid down a position.
				resp.TotalResults = nvdIntPtr(349)
			}
		}
		srv := pager.start(t)

		svc := NewNVDService(nil, nil, "k", srv.URL, false)
		res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
		if err != nil {
			t.Fatalf("a shifted result set must not fail the lookup: %v", err)
		}
		if !res.shifted {
			t.Error("totalResults changed between pages and the walk did not notice")
		}
		if !res.truncated {
			t.Errorf("fetched=%d total=%d and the walk called itself COMPLETE. Offsets moved "+
				"under it, so a record can have slid past the next startIndex and be missing "+
				"from every page — arithmetic that comes out even does not prove otherwise.",
				res.fetched, res.total)
		}
	})

	t.Run("a record arrives on two pages", func(t *testing.T) {
		pager := &cannedNVDPager{total: 350}
		pager.rewrite = func(page int, resp *NVDResponse) {
			if page == 1 {
				entries := *resp.Vulnerabilities
				entries[0].CVE.ID = m55CVEID(0) // already delivered on page 0
				resp.Vulnerabilities = &entries
			}
		}
		srv := pager.start(t)

		svc := NewNVDService(nil, nil, "k", srv.URL, false)
		res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
		if err != nil {
			t.Fatalf("searchByKeyword: %v", err)
		}
		// De-duplication still happens: the component must not be linked to
		// the same CVE twice, whatever the walk concludes about completeness.
		seen := make(map[string]int, len(res.vulns))
		for _, v := range res.vulns {
			seen[v.CVEID]++
		}
		for id, n := range seen {
			if n > 1 {
				t.Errorf("%s appears %d times in one component's result", id, n)
			}
		}
		if len(res.vulns) != 349 {
			t.Errorf("got %d unique matches, want 349", len(res.vulns))
		}
		if !res.truncated {
			t.Errorf("349 unique records were returned for a result set of %d and the walk "+
				"called itself complete; a duplicate means the window moved, and the record "+
				"it displaced is in no page at all", res.total)
		}
	})

	t.Run("a stable result set is still complete", func(t *testing.T) {
		pager := &cannedNVDPager{total: 350}
		srv := pager.start(t)

		svc := NewNVDService(nil, nil, "k", srv.URL, false)
		res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
		if err != nil {
			t.Fatalf("searchByKeyword: %v", err)
		}
		if res.shifted || res.truncated {
			t.Errorf("shifted=%v truncated=%v on an undisturbed 2-page walk; the shift "+
				"detection must not degrade into reporting every paged component",
				res.shifted, res.truncated)
		}
		if len(res.vulns) != 350 {
			t.Errorf("got %d matches, want 350", len(res.vulns))
		}
	})
}

// TestM55SearchByKeyword_DoesNotSpinOnAPageWithNoEntries pins the termination
// guard.
//
// A page that returns nothing does not advance startIndex, so without an
// explicit break the walk would re-request the same offset until the budget ran
// out. It is reachable: validate's `totalResults > startIndex` rule
// deliberately admits an empty answer past the end of a SHRUNKEN result set,
// which is exactly this shape.
func TestM55SearchByKeyword_DoesNotSpinOnAPageWithNoEntries(t *testing.T) {
	pager := &cannedNVDPager{total: 350}
	pager.rewrite = func(page int, resp *NVDResponse) {
		if page >= 1 {
			resp.TotalResults = nvdIntPtr(150)
			resp.ResultsPerPage = nvdIntPtr(0)
			resp.Vulnerabilities = nvdEntriesPtr([]NVDVulnEntry{})
		}
	}
	srv := pager.start(t)

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
	if err != nil {
		t.Fatalf("an empty page past the end of a shrunken result set must not fail the "+
			"lookup: %v", err)
	}
	if got := len(pager.calls()); got != 2 {
		t.Errorf("issued %d requests, want 2 — a page with no entries must end the walk, "+
			"not be re-requested until the budget runs out: %v", got, pager.calls())
	}
	if len(res.vulns) != 200 {
		t.Errorf("got %d matches, want the 200 the first page really carried", len(res.vulns))
	}
	// And it is still not claimed as complete: totalResults moved.
	if !res.truncated {
		t.Error("the result set shrank mid-walk, so completeness cannot be claimed")
	}
}

// TestM55SearchByKeyword_CountsTheRequestsAFailedWalkSpent pins the sweep's
// rate-limit accounting (Codex M55 R1, Low). A walk that dies on page 3 has
// still spent three requests against NVD's published rate, and the sweep
// summary has to say so.
func TestM55SearchByKeyword_CountsTheRequestsAFailedWalkSpent(t *testing.T) {
	pager := &cannedNVDPager{total: 1000}
	pager.rewrite = func(page int, resp *NVDResponse) {
		if page == 2 {
			// A page that fails validate: it claims records it does not carry.
			resp.ResultsPerPage = nvdIntPtr(200)
			resp.Vulnerabilities = nvdEntriesPtr([]NVDVulnEntry{})
		}
	}
	srv := pager.start(t)

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", nil)
	if err == nil {
		t.Fatal("a page that does not carry what it claims must fail the lookup")
	}
	if res.pages != 3 {
		t.Errorf("pages = %d, want 3 — the requests a failed walk already spent still count "+
			"against the rate limit", res.pages)
	}
	if len(res.vulns) != 0 {
		t.Errorf("a failed walk returned %d matches; a partial walk must not be handed back "+
			"as if it were an answer", len(res.vulns))
	}
}

// TestM55SearchByKeyword_PacesEveryPageAfterTheFirst pins the rate-limit
// invariant that makes paging safe to add at all.
//
// The worker pool takes one shared tick per WORK ITEM. That was one request
// until paging existed; a walk that issued its follow-ups without a tick would
// let the pool emit up to maxConcurrentWithKey * nvdMaxPagesPerComponent
// requests inside one tick — 25 with an API key — against a published rate of
// 50 per 30 seconds.
//
// The first page is deliberately NOT paced here: the work item's own tick has
// already paid for it, and pacing it again would halve the sweep's throughput.
func TestM55SearchByKeyword_PacesEveryPageAfterTheFirst(t *testing.T) {
	pager := &cannedNVDPager{total: 563} // measured: openssl -> 3 pages
	srv := pager.start(t)

	paced := 0
	pace := func(context.Context) error {
		paced++
		return nil
	}

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "openssl", "", pace)
	if err != nil {
		t.Fatalf("searchByKeyword: %v", err)
	}
	if res.pages != 3 {
		t.Fatalf("pages = %d, want 3", res.pages)
	}
	if paced != res.pages-1 {
		t.Errorf("paced %d times over %d pages, want %d: every page after the first must "+
			"take a rate-limiter tick, and the first must not",
			paced, res.pages, res.pages-1)
	}
}

// TestM55SearchByKeyword_AbortsWhenPacingIsCancelled pins that a cancelled
// sweep stops walking instead of spending the rest of its budget, and that a
// partial walk is reported as a FAILED lookup rather than as a short answer.
func TestM55SearchByKeyword_AbortsWhenPacingIsCancelled(t *testing.T) {
	pager := &cannedNVDPager{total: 1000}
	srv := pager.start(t)

	stop := errors.New("scan cancelled")
	pace := func(context.Context) error { return stop }

	svc := NewNVDService(nil, nil, "k", srv.URL, false)
	res, err := svc.searchByKeyword(context.Background(), "libfoo", "1.0", pace)
	if !errors.Is(err, stop) {
		t.Fatalf("err = %v, want the pacer's error", err)
	}
	if len(res.vulns) != 0 {
		t.Errorf("an aborted walk returned %d matches; a partial walk must not be handed "+
			"back as if it were an answer", len(res.vulns))
	}
	if got := len(pager.calls()); got != 1 {
		t.Errorf("issued %d requests after the pacer refused, want 1", got)
	}
}

// TestM55NVDResponse_ValidateIsPageAware pins the widened envelope rules.
//
// Case names say which rule each row is for; every row carries every field the
// EARLIER rules require, so a row cannot pass for the wrong reason (the trap
// Codex M54 R10 found in the M54 table).
func TestM55NVDResponse_ValidateIsPageAware(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantStart int
		wantErr   bool
	}{
		{
			"page 0 as before",
			`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`,
			0, false,
		},
		{
			"the requested later page is accepted",
			`{"resultsPerPage":1,"startIndex":200,"totalResults":201,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`,
			200, false,
		},
		{
			"a later page answered with page zero is refused",
			`{"resultsPerPage":1,"startIndex":0,"totalResults":201,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`,
			200, true,
		},
		{
			"page zero answered with a later page is still refused",
			`{"resultsPerPage":1,"startIndex":20,"totalResults":40,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}}]}`,
			0, true,
		},
		{
			// The live shape measured on 2026-08-11: asked for 200 from index
			// 400, answered with resultsPerPage=163.
			"the last page is short of the requested size",
			`{"resultsPerPage":2,"startIndex":400,"totalResults":402,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}},{"cve":{"id":"CVE-2021-45046"}}]}`,
			400, false,
		},
		{
			// Rule 5, unchanged on page zero.
			"page zero claims results and carries none",
			`{"resultsPerPage":0,"startIndex":0,"totalResults":5,"vulnerabilities":[]}`,
			0, true,
		},
		{
			// Rule 5 widened: past the end of a SHRUNKEN result set, an empty
			// page is the honest answer, not an inconsistency.
			"a shrunken result set answers past its end with nothing",
			`{"resultsPerPage":0,"startIndex":200,"totalResults":150,"vulnerabilities":[]}`,
			200, false,
		},
		{
			// Still inconsistent: the set says there is more AT this index.
			"a later page claims more results at this index and carries none",
			`{"resultsPerPage":0,"startIndex":200,"totalResults":500,"vulnerabilities":[]}`,
			200, true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var r NVDResponse
			if err := json.Unmarshal([]byte(tc.body), &r); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err := r.validate(tc.wantStart)
			if tc.wantErr && err == nil {
				t.Errorf("validate(%d) accepted %s", tc.wantStart, tc.body)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate(%d) rejected %s: %v", tc.wantStart, tc.body, err)
			}
		})
	}
}

// TestM55ScanReport_EscalationLadder pins exactly which sweeps are reported to
// the caller as failures and which are not.
//
// The ladder is what the whole product reads: a non-nil error here becomes
// ScanTracker "failed", `scan_state: failed` on the scan-status endpoint,
// `counts_final: false` in the MCP server, and exit 2 from `sbomhub scan`.
func TestM55ScanReport_EscalationLadder(t *testing.T) {
	cases := []struct {
		name    string
		report  NVDScanReport
		wantErr string // substring, or "" for nil
	}{
		{"nothing to do", NVDScanReport{}, ""},
		{"clean sweep", NVDScanReport{UniqueComponents: 3, Processed: 3}, ""},
		{
			"refused writes outrank everything",
			NVDScanReport{UniqueComponents: 3, Processed: 3, RefusedWrites: 2, TruncatedComponents: 1},
			"database refused",
		},
		{
			"total fetch failure",
			NVDScanReport{UniqueComponents: 3, Processed: 0, FetchFailures: 3},
			"no coverage",
		},
		{
			// The M55 addition. Without it, a scan that provably did not see
			// a component's match set reports completed and the CLI treats
			// the counts as final.
			"a truncated component fails the scan",
			NVDScanReport{UniqueComponents: 3, Processed: 3, TruncatedComponents: 1, DroppedMatches: 20670},
			"paging budget",
		},
		{
			// Deliberately NOT escalated: the threshold is a product decision
			// and this wave does not take it. The count must still be present
			// on the report — see the partial-failure observability test.
			"partial fetch failure stays a success",
			NVDScanReport{UniqueComponents: 10, Processed: 7, FetchFailures: 3},
			"",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.report.incompleteErr()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("incompleteErr() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("incompleteErr() = nil, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("incompleteErr() = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
