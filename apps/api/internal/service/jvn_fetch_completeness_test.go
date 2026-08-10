package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// A canned MyJVN getVulnOverviewList server.
//
// Everything it does is copied from a MEASURED live response (2026-08-11,
// https://jvndb.jvn.jp/myjvn), not from the prose spec, because three of the
// behaviours that matter here are only visible in the wire form:
//
//   - a zero-match answer is NOT an empty document. It carries totalRes="0"
//     totalResRet="0" firstRes="1" AND one <item> whose title is
//     "MyJVN　該当する脆弱性対策情報はありません。". A parser that checks
//     len(items) == totalResRet without knowing that rejects every empty
//     answer.
//   - retMax is the API's own 50-entry ceiling, NOT the maxCountItem that was
//     requested: asking for maxCountItem=3 still answers retMax="50".
//     totalResRet is the only attribute that says how many entries a page
//     actually holds.
//   - firstRes echoes the requested startItem when the page is non-empty, and
//     is 1 when it is empty.
//
// Element names are the namespaced ones the real feed uses (sec:identifier,
// sec:references, dcterms:issued), so the JVNItem tags are exercised the way
// production sees them rather than against a friendlier invention.
// ---------------------------------------------------------------------------

type cannedJVNAdvisory struct {
	ID        string
	CVE       string
	Published time.Time
}

type cannedMyJVN struct {
	mu sync.Mutex
	// corpus is ordered newest-first, as MyJVN orders its answers (measured:
	// startItem=1 for "openssl" returns 2026 entries, startItem=457 returns
	// 2002 entries).
	corpus []cannedJVNAdvisory
	// corpusFor, when set, overrides corpus per keyword.
	corpusFor func(keyword string) []cannedJVNAdvisory
	now       time.Time
	// requests records every query the service issued, in order.
	requests []url.Values
	// corrupt, when set, may rewrite the Status attributes and/or the item
	// window just before they are serialised. Used by the page-identity
	// tests to forge the responses a broken mirror would send.
	corrupt func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory)
	// fail, when set and returning a non-zero status, short-circuits the
	// request with that HTTP status.
	fail func(q url.Values) int
}

type cannedJVNStatus struct {
	RetCd       string
	TotalRes    int
	TotalResRet int
	FirstRes    int
	// omitTotalResRet models a mirror that drops the attribute entirely.
	omitTotalResRet bool
	// The request echo the live API sends back on every success.
	Method                  string
	Feed                    string
	Keyword                 string
	MaxCountItem            string
	StartItem               string
	RangeDatePublic         string
	RangeDatePublished      string
	RangeDateFirstPublished string
}

// echoOf builds the Status request echo for a query, the way MyJVN does.
func echoOf(q url.Values) cannedJVNStatus {
	def := func(name, fallback string) string {
		if v := q.Get(name); v != "" {
			return v
		}
		return fallback
	}
	return cannedJVNStatus{
		Method:                  def("method", "getVulnOverviewList"),
		Feed:                    def("feed", "hnd"),
		Keyword:                 q.Get("keyword"),
		MaxCountItem:            def("maxCountItem", "50"),
		StartItem:               def("startItem", "1"),
		RangeDatePublic:         def("rangeDatePublic", "w"),
		RangeDatePublished:      def("rangeDatePublished", "w"),
		RangeDateFirstPublished: def("rangeDateFirstPublished", "w"),
	}
}

// jvnTestPageReq is the request shape the hand-written fixtures answer.
func jvnTestPageReq(keyword string, startItem int) jvnPageRequest {
	return jvnPageRequest{keyword: keyword, startItem: startItem, maxCountItem: jvnMaxCountItem}
}

func (c *cannedMyJVN) calls() []url.Values {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]url.Values, len(c.requests))
	copy(out, c.requests)
	return out
}

func (c *cannedMyJVN) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		c.mu.Lock()
		c.requests = append(c.requests, q)
		c.mu.Unlock()

		if c.fail != nil {
			if code := c.fail(q); code != 0 {
				w.WriteHeader(code)
				return
			}
		}

		// MyJVN defaults all three date ranges to "w" == the past 7 days
		// INCLUDING today (spec: 「過去1週間」は当日を含む7日間). Absent
		// parameter and empty value both take the default.
		cutoff := time.Time{}
		for _, p := range []string{"rangeDatePublic", "rangeDatePublished", "rangeDateFirstPublished"} {
			v := q.Get(p)
			if v == "" {
				v = "w"
			}
			switch v {
			case "n":
			case "w":
				if t := c.now.AddDate(0, 0, -6); t.After(cutoff) {
					cutoff = t
				}
			case "m":
				if t := c.now.AddDate(0, -1, 0); t.After(cutoff) {
					cutoff = t
				}
			}
		}

		corpus := c.corpus
		if c.corpusFor != nil {
			corpus = c.corpusFor(q.Get("keyword"))
		}
		var filtered []cannedJVNAdvisory
		for _, a := range corpus {
			if cutoff.IsZero() || !a.Published.Before(cutoff) {
				filtered = append(filtered, a)
			}
		}

		maxCount := 50
		if v := q.Get("maxCountItem"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 50 {
				maxCount = n
			}
		}
		start := 1
		if v := q.Get("startItem"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 1 {
				start = n
			}
		}

		var window []cannedJVNAdvisory
		if start <= len(filtered) {
			end := start - 1 + maxCount
			if end > len(filtered) {
				end = len(filtered)
			}
			window = filtered[start-1 : end]
		}

		st := echoOf(q)
		st.RetCd = "0"
		st.TotalRes = len(filtered)
		st.TotalResRet = len(window)
		st.FirstRes = 1
		if len(window) > 0 {
			st.FirstRes = start
		}
		if c.corrupt != nil {
			c.corrupt(q, &st, &window)
		}

		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(renderCannedMyJVN(st, window, c.now)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func renderCannedMyJVN(st cannedJVNStatus, items []cannedJVNAdvisory, now time.Time) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" ?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
 xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/" xmlns:status="http://jvndb.jvn.jp/myjvn/Status" xml:lang="ja">
  <channel rdf:about="https://jvndb.jvn.jp/apis/myjvn">
    <title>JVNDB　脆弱性対策情報</title>
    <description/>
  </channel>
`)
	if len(items) == 0 {
		// The measured zero-match shape: one placeholder item with no
		// sec:identifier and no sec:references.
		b.WriteString(`  <item rdf:about="https://jvndb.jvn.jp/apis/myjvn">
    <title>MyJVN　該当する脆弱性対策情報はありません。</title>
    <link>https://jvndb.jvn.jp/apis/myjvn</link>
    <description>MyJVN　該当する脆弱性対策情報はありません。</description>
    <dc:date>` + now.Format(time.RFC3339) + `</dc:date>
    <dcterms:issued>` + now.Format(time.RFC3339) + `</dcterms:issued>
  </item>
`)
	}
	for _, a := range items {
		fmt.Fprintf(&b, `  <item rdf:about="https://jvndb.jvn.jp/ja/contents/%s.html">
    <title>%s における脆弱性</title>
    <link>https://jvndb.jvn.jp/ja/contents/%s.html</link>
    <description>test advisory</description>
    <sec:identifier>%s</sec:identifier>
    <sec:references source="CVE" id="%s">https://www.cve.org/CVERecord?id=%s</sec:references>
    <sec:cvss version="3.1" type="Base" severity="High" score="7.5" vector="CVSS:3.1/AV:N/AC:L"/>
    <dc:date>%s</dc:date>
    <dcterms:issued>%s</dcterms:issued>
    <dcterms:modified>%s</dcterms:modified>
  </item>
`, a.ID, a.ID, a.ID, a.ID, a.CVE, a.CVE,
			a.Published.Format(time.RFC3339), a.Published.Format(time.RFC3339), a.Published.Format(time.RFC3339))
	}
	trr := fmt.Sprintf(` totalResRet="%d"`, st.TotalResRet)
	if st.omitTotalResRet {
		trr = ""
	}
	fmt.Fprintf(&b, `  <status:Status version="3.3" method="%s" lang="ja" retCd="%s" retMax="50" errCd="" errMsg="" totalRes="%d"%s firstRes="%d" feed="%s" keyword="%s" maxCountItem="%s" startItem="%s" rangeDatePublic="%s" rangeDatePublished="%s" rangeDateFirstPublished="%s"/>
</rdf:RDF>`, st.Method, st.RetCd, st.TotalRes, trr, st.FirstRes, st.Feed,
		st.Keyword, st.MaxCountItem, st.StartItem,
		st.RangeDatePublic, st.RangeDatePublished, st.RangeDateFirstPublished)
	return b.String()
}

// cannedCorpus builds `total` advisories, the newest `recent` of which fall
// inside MyJVN's default past-week window and the rest of which are years old.
func cannedCorpus(now time.Time, total, recent int) []cannedJVNAdvisory {
	out := make([]cannedJVNAdvisory, 0, total)
	for i := 0; i < total; i++ {
		// Recent entries are spaced by the hour so that more than
		// maxCountItem of them fit inside MyJVN's 7-day default window.
		published := now.Add(-time.Duration(i) * time.Hour)
		if i >= recent {
			published = now.AddDate(-3, 0, -i) // comfortably outside the week
		}
		out = append(out, cannedJVNAdvisory{
			ID:        fmt.Sprintf("JVNDB-2020-%06d", 900000-i),
			CVE:       fmt.Sprintf("CVE-2020-%05d", 10000+i),
			Published: published,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Observation / regression
// ---------------------------------------------------------------------------

// TestM55JVN_FetchCoverage measures how much of a keyword's match set the
// scanner actually retrieves.
//
// BEFORE this change (measured against this same server): 1 request carrying
// maxCountItem=10 and no date range at all, so MyJVN applied its documented
// past-week default and answered 3 of 137 — the scanner then kept those 3 and
// reported the component successfully checked.
func TestM55JVN_FetchCoverage(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: cannedCorpus(now, 137, 3), now: now}
	ts := srv.start(t)

	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}

	calls := srv.calls()
	t.Logf("requests=%d totalRes=%d retrieved=%d vulns=%d truncated=%v",
		len(calls), res.TotalRes, res.Retrieved, len(res.Vulns), res.Truncated)
	for i, q := range calls {
		t.Logf("  req[%d] maxCountItem=%q startItem=%q rangeDatePublic=%q rangeDatePublished=%q rangeDateFirstPublished=%q",
			i, q.Get("maxCountItem"), q.Get("startItem"),
			q.Get("rangeDatePublic"), q.Get("rangeDatePublished"), q.Get("rangeDateFirstPublished"))
	}

	if res.TotalRes != 137 {
		t.Errorf("TotalRes = %d, want 137 — the date range is still filtering the corpus", res.TotalRes)
	}
	if len(res.Vulns) != 137 {
		t.Errorf("retrieved %d advisories, want 137 — %d were dropped and the scan still reported success",
			len(res.Vulns), 137-len(res.Vulns))
	}
	if res.Truncated {
		t.Error("a fully-retrieved match set must not be reported as truncated")
	}
	if got := len(calls); got != 3 {
		t.Errorf("issued %d requests, want 3 (ceil(137/50)) — maxCountItem must be the API's 50-entry maximum", got)
	}
	for i, q := range calls {
		for _, p := range []string{"rangeDatePublic", "rangeDatePublished", "rangeDateFirstPublished"} {
			if q.Get(p) != "n" {
				t.Errorf("req[%d] %s = %q, want \"n\" — MyJVN defaults it to the past week", i, p, q.Get(p))
			}
		}
		if q.Get("maxCountItem") != "50" {
			t.Errorf("req[%d] maxCountItem = %q, want \"50\"", i, q.Get("maxCountItem"))
		}
	}
	if len(calls) >= 2 && calls[1].Get("startItem") != "51" {
		t.Errorf("second request startItem = %q, want \"51\"", calls[1].Get("startItem"))
	}
}

// TestM55JVN_TruncationIsDeclared pins that a match set larger than the fetch
// budget is REPORTED as incomplete rather than silently cut.
func TestM55JVN_TruncationIsDeclared(t *testing.T) {
	now := time.Now()
	total := jvnMaxCountItem*jvnMaxPagesPerComponent + 1
	srv := &cannedMyJVN{corpus: cannedCorpus(now, total, total), now: now}
	ts := srv.start(t)

	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "linux", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("retrieved %d of %d advisories but Truncated = false — the scan would claim complete coverage",
			res.Retrieved, res.TotalRes)
	}
	if res.Retrieved != jvnMaxCountItem*jvnMaxPagesPerComponent {
		t.Errorf("Retrieved = %d, want the full per-component budget %d",
			res.Retrieved, jvnMaxCountItem*jvnMaxPagesPerComponent)
	}
	if n := len(srv.calls()); n != jvnMaxPagesPerComponent {
		t.Errorf("issued %d requests, want the per-component cap %d", n, jvnMaxPagesPerComponent)
	}

	// And the scan-level report must turn that into a caller-visible error,
	// because the only channel JVNService owns to ScanTracker is its error
	// return.
	rep := JVNScanReport{Components: 1, Scanned: 1, TruncatedComponents: 1,
		EntriesRetrieved: res.Retrieved, EntriesAvailable: res.TotalRes}
	if err := rep.Err(); err == nil {
		t.Fatal("a truncated sweep returned no error; ScanTracker would record it as completed")
	} else if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("truncation error %q does not say the results are incomplete", err)
	}
}

// TestM55JVN_SharedPageBudget pins that the extra-page pool is shared across
// the sweep, and that its exhaustion is declared rather than swallowed.
//
// The first page of every component is always fetched (so a large SBOM never
// loses component coverage to a component that matched thousands); only pages
// 2..N draw on the pool.
func TestM55JVN_SharedPageBudget(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: cannedCorpus(now, 500, 500), now: now}
	ts := srv.start(t)

	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	budget := 2
	res, err := svc.searchKeyword(context.Background(), "openssl", &budget)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if n := len(srv.calls()); n != 3 {
		t.Errorf("issued %d requests, want 3 (1 mandatory + 2 from the pool)", n)
	}
	if budget != 0 {
		t.Errorf("shared budget = %d, want 0 (fully drawn down)", budget)
	}
	if !res.Truncated {
		t.Error("budget exhaustion left 350 advisories unseen but Truncated = false")
	}
	if !res.BudgetExhausted {
		t.Error("BudgetExhausted = false; the caller cannot tell the pool ran out")
	}

	// A second component still gets its mandatory first page with an empty
	// pool — component coverage is never traded for depth.
	before := len(srv.calls())
	if _, err := svc.searchKeyword(context.Background(), "curl", &budget); err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if got := len(srv.calls()) - before; got != 1 {
		t.Errorf("with an exhausted pool the next component issued %d requests, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// Page identity — the correctness half (Codex M54 R10, Critical)
// ---------------------------------------------------------------------------

func TestM55JVN_PageIdentityIsChecked(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name    string
		corrupt func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory)
		wantErr string
	}{
		{
			// A mirror that ignores startItem and keeps answering page 1.
			// Accepting it means the paging loop re-reads the same 50
			// entries and calls the rest "seen".
			name: "firstRes does not match the requested startItem",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				if q.Get("startItem") != "1" {
					st.FirstRes = 1
				}
			},
			wantErr: "firstRes",
		},
		{
			// The page says it holds 50 entries and carries 3. The
			// missing 47 are silently lost today.
			name: "page is shorter than its own totalResRet",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				if len(*items) > 3 {
					*items = (*items)[:3]
				}
			},
			wantErr: "totalResRet",
		},
		{
			// More entries than were asked for: the answer is not to the
			// question we posed.
			name: "page is longer than maxCountItem",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.TotalResRet = 51
			},
			wantErr: "totalResRet",
		},
		{
			// Without totalResRet nothing identifies how long the page
			// should be, so a short page cannot be detected at all.
			name: "totalResRet attribute is absent",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.omitTotalResRet = true
			},
			wantErr: "totalResRet",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &cannedMyJVN{corpus: cannedCorpus(now, 137, 137), now: now, corrupt: tc.corrupt}
			ts := srv.start(t)
			svc := NewJVNService(nil, nil, ts.URL, false)
			svc.requestDelay = 0

			_, err := svc.searchKeyword(context.Background(), "libfoo", nil)
			if err == nil {
				t.Fatalf("a response that cannot be identified as the requested page was accepted as an answer")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestM55JVN_ResponseMustEchoTheRequest pins that a page is only accepted when
// the Status element echoes the query that produced it (Codex M55 R1,
// Critical). Without it, a cache or proxy could answer with a well-formed page
// belonging to another component, or one taken under the old one-week window,
// and nothing about its shape would give it away.
func TestM55JVN_ResponseMustEchoTheRequest(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name    string
		corrupt func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory)
		wantErr string
	}{
		{
			name: "answer is about a different component",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.Keyword = "some-other-component"
			},
			wantErr: "keyword",
		},
		{
			// The whole point of the change: proving the seven-day
			// default is gone, not merely no longer requested.
			name: "answer still covers MyJVN's one-week default window",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.RangeDatePublic = "w"
			},
			wantErr: "rangeDatePublic",
		},
		{
			name: "answer was built for a different startItem",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.StartItem = "999"
			},
			wantErr: "startItem",
		},
		{
			name: "answer was built for a different page size",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.MaxCountItem = "10"
			},
			wantErr: "maxCountItem",
		},
		{
			name: "answer is to a different method",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.Method = "getAlertList"
			},
			wantErr: "method",
		},
		{
			name: "answer is in a different feed format",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.Feed = "itm"
			},
			wantErr: "feed",
		},
		{
			name: "echo is absent entirely",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.Keyword, st.StartItem, st.MaxCountItem = "", "", ""
				st.RangeDatePublic, st.RangeDatePublished, st.RangeDateFirstPublished = "", "", ""
			},
			wantErr: "rangeDatePublic",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &cannedMyJVN{corpus: cannedCorpus(now, 5, 5), now: now, corrupt: tc.corrupt}
			ts := srv.start(t)
			svc := NewJVNService(nil, nil, ts.URL, false)
			svc.requestDelay = 0

			_, err := svc.searchKeyword(context.Background(), "libfoo", nil)
			if err == nil {
				t.Fatal("a response that does not echo the request was accepted as its answer")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestM55JVN_NonASCIIKeywordEchoIsAccepted is the other half of the echo check:
// it must not reject legitimate answers.
//
// Measured on the live API: MyJVN returns the keyword exactly as it appeared in
// the query string, so a non-ASCII component name comes back percent-encoded.
// A literal comparison would fail every such component — turning a guard into
// an outage for exactly the Japanese-market components this product exists for.
func TestM55JVN_NonASCIIKeywordEchoIsAccepted(t *testing.T) {
	for _, keyword := range []string{"日本語 テスト", "golang.org/x/crypto", "OpenSSL-Test_1.0"} {
		t.Run(keyword, func(t *testing.T) {
			if !jvnKeywordEchoMatches(url.QueryEscape(keyword), keyword) {
				t.Errorf("percent-encoded echo of %q was rejected", keyword)
			}
			if !jvnKeywordEchoMatches(keyword, keyword) {
				t.Errorf("literal echo of %q was rejected", keyword)
			}
			if jvnKeywordEchoMatches("something-else", keyword) {
				t.Errorf("echo of a different keyword was accepted for %q", keyword)
			}
		})
	}
}

// TestM55JVN_ShrinkingTotalResStillCountsAsTruncated pins that a total which
// drops between pages cannot erase the entries it previously advertised
// (Codex M55 R1, Critical).
//
// Page 1 says totalRes=137 and hands over 50. Page 2 comes back empty and says
// totalRes=50. Taking the last total made Retrieved == TotalRes, so 87 unseen
// advisories were reported as a complete answer.
func TestM55JVN_ShrinkingTotalResStillCountsAsTruncated(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: cannedCorpus(now, 137, 137), now: now,
		corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
			if q.Get("startItem") != "1" {
				*items = nil
				st.TotalRes = 50
				st.TotalResRet = 0
				st.FirstRes = 1
			}
		}}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if !res.Truncated {
		t.Fatalf("Retrieved=%d TotalRes=%d Truncated=false — 87 advertised advisories vanished "+
			"and the component was reported complete", res.Retrieved, res.TotalRes)
	}
	if res.TotalRes != 137 {
		t.Errorf("TotalRes = %d, want the largest total any page claimed (137)", res.TotalRes)
	}
}

// TestM55JVN_RepeatedEntriesAreNotCountedTwice pins that Retrieved counts
// DISTINCT advisories (Codex M55 R1, Critical).
//
// A mirror that re-serves page 1's entries as page 2, with a correct firstRes,
// made 50 distinct advisories count as 100 against a totalRes of 137 — and the
// second half of the match set was never fetched. It also covers the honest
// version of the same event: MyJVN orders newest-first, so an advisory
// published mid-scan shifts the window and one entry really does repeat.
func TestM55JVN_RepeatedEntriesAreNotCountedTwice(t *testing.T) {
	now := time.Now()
	corpus := cannedCorpus(now, 137, 137)
	srv := &cannedMyJVN{corpus: corpus, now: now,
		corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
			// Always hand back the first 50, whatever was asked for,
			// while claiming the page identity that was requested.
			if len(*items) > 0 {
				*items = corpus[:50]
				st.TotalResRet = 50
			}
		}}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if res.Retrieved != 50 {
		t.Errorf("Retrieved = %d, want 50 distinct advisories (the wire returned %d entries)",
			res.Retrieved, res.Entries)
	}
	if !res.Truncated {
		t.Error("50 distinct advisories out of 137 were reported as a complete answer")
	}
	if len(res.Vulns) != 50 {
		t.Errorf("returned %d vulnerabilities, want 50 — duplicates were not collapsed", len(res.Vulns))
	}
}

// TestM55JVN_UnidentifiableEntryIsAShortfall pins that an entry MyJVN returned
// but this scanner cannot record does not count as retrieved (Codex M55 R1,
// Critical). Counting the wire entry made a page of unusable items read as a
// complete answer that contributed nothing.
func TestM55JVN_UnidentifiableEntryIsAShortfall(t *testing.T) {
	now := time.Now()
	corpus := cannedCorpus(now, 5, 5)
	corpus[2].ID = ""  // no sec:identifier
	corpus[2].CVE = "" // and no CVE reference
	srv := &cannedMyJVN{corpus: corpus, now: now}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if res.Retrieved != 4 {
		t.Errorf("Retrieved = %d, want 4 — the unusable entry was counted as an advisory we hold",
			res.Retrieved)
	}
	if res.Entries != 5 {
		t.Errorf("Entries = %d, want 5 wire entries", res.Entries)
	}
	if !res.Truncated {
		t.Error("an advisory MyJVN returned and this scan could not record was reported as covered")
	}
}

// TestM55JVN_ZeroMatchSentinelIsNotAProtocolError pins the measured shape of a
// zero-match answer: totalRes="0" totalResRet="0" firstRes="1" plus ONE
// placeholder <item>. It is a legitimate empty answer, not a short page.
func TestM55JVN_ZeroMatchSentinelIsNotAProtocolError(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: nil, now: now}
	ts := srv.start(t)

	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "zzqqxxnotarealpackage9999", nil)
	if err != nil {
		t.Fatalf("the documented zero-match answer must not be an error: %v", err)
	}
	if len(res.Vulns) != 0 {
		t.Errorf("zero-match answer produced %d vulnerabilities — the placeholder item was stored",
			len(res.Vulns))
	}
	if res.Truncated {
		t.Error("a zero-match answer is not truncated")
	}
	if n := len(srv.calls()); n != 1 {
		t.Errorf("issued %d requests for an empty match set, want 1", n)
	}
}

// TestM55JVN_EmptyKeywordIsNotQueried guards a consequence of removing the
// date default. A component with no name used to send keyword="" against a
// one-week window; against full history the same request matches the ENTIRE
// JVN corpus and would spend the whole page budget on it.
func TestM55JVN_EmptyKeywordIsNotQueried(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: cannedCorpus(now, 137, 137), now: now}
	ts := srv.start(t)

	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "   ", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if len(res.Vulns) != 0 || res.Requests != 0 {
		t.Errorf("a blank keyword issued %d request(s) and produced %d vulnerabilities; want 0/0",
			res.Requests, len(res.Vulns))
	}
	if n := len(srv.calls()); n != 0 {
		t.Errorf("server saw %d requests for a blank keyword, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Partial fetch failure observability
// ---------------------------------------------------------------------------

// TestM55JVN_ReportCountsAreCallerVisible pins that the counts a caller needs
// to judge a partial failure are RETURN VALUES, not log lines.
//
// Whether N failures out of M components should fail a scan stays a product
// decision (unchanged here); being able to count them is not.
func TestM55JVN_ReportCountsAreCallerVisible(t *testing.T) {
	rep := JVNScanReport{Components: 10, Scanned: 7, Failed: 3, EntriesRetrieved: 42, EntriesAvailable: 42}
	if rep.Failed != 3 {
		t.Fatalf("Failed = %d, want 3", rep.Failed)
	}
	if err := rep.Err(); err != nil {
		t.Errorf("partial failure must stay a success (product policy unchanged), got %v", err)
	}
	if !strings.Contains(rep.Summary(), "failed=3") {
		t.Errorf("Summary() = %q, want it to carry the failure count", rep.Summary())
	}

	// Total failure still escalates (M54 R8).
	total := JVNScanReport{Components: 10, Scanned: 0, Failed: 10}
	if err := total.Err(); err == nil {
		t.Error("a sweep where every lookup failed must not report success")
	}

	// A refused write still escalates (M54 R10).
	refused := JVNScanReport{Components: 1, Scanned: 1, RefusedWrites: 2}
	if err := refused.Err(); err == nil {
		t.Error("a refused write must not report success")
	}
}

// TestM55JVN_FetchFailureSurfacesAsAnError pins that a MyJVN 500 is an ERROR
// rather than zero matches, which is what makes it countable one level up.
//
// The aggregation itself (rep.Failed) needs a component list and therefore a
// database; it is pinned in TestM55JVNScanReport_PartialFetchFailureIsCounted.
// This test deliberately does not claim to cover it (Codex M55 R1, Low: it
// used to be named as though it did).
func TestM55JVN_FetchFailureSurfacesAsAnError(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{
		corpus: cannedCorpus(now, 5, 5),
		now:    now,
		fail: func(q url.Values) int {
			if q.Get("keyword") == "boom" {
				return http.StatusInternalServerError
			}
			return 0
		},
	}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	if _, err := svc.searchKeyword(context.Background(), "boom", nil); err == nil {
		t.Fatal("a 500 from MyJVN must surface as an error, not as zero matches")
	}
	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if len(res.Vulns) != 5 {
		t.Errorf("got %d vulnerabilities, want 5", len(res.Vulns))
	}
}

// ---------------------------------------------------------------------------
// getVulnDetailInfo is a different document type
// ---------------------------------------------------------------------------

// TestM55JVN_DetailInfoIsNotAnRSSFeed records why GetVulnerabilitiesByJVNID
// was removed rather than kept.
//
// Measured (2026-08-11, live getVulnDetailInfo for JVNDB-2021-012182): the
// response root is <VULDEF-Document>, whose children are <Vulinfo>, not the
// <rdf:RDF> + <item> feed getVulnOverviewList returns. The overview parser is
// bound to the RDF root, so the detail entry point could never have returned a
// vulnerability against the real API — it could only ever return the unmarshal
// error below. This test keeps that fact executable so a future detail lookup
// is written against the VULDEF schema instead of reviving the old path.
func TestM55JVN_DetailInfoIsNotAnRSSFeed(t *testing.T) {
	const vuldef = `<?xml version="1.0" encoding="UTF-8" ?>
<VULDEF-Document version="3.2" xmlns="http://jvn.jp/vuldef/" xmlns:vuldef="http://jvn.jp/vuldef/"
 xmlns:status="http://jvndb.jvn.jp/myjvn/Status" xml:lang="ja">
  <Vulinfo>
    <VulinfoID>JVNDB-2021-012182</VulinfoID>
  </Vulinfo>
  <status:Status version="3.3" method="getVulnDetailInfo" lang="ja" retCd="0" retMax="10" errCd="" errMsg="" totalRes="1" totalResRet="1" firstRes="1" feed="hnd"/>
</VULDEF-Document>`

	svc := NewJVNService(nil, nil, "", false)
	if _, err := svc.parseJVNPage([]byte(vuldef), jvnTestPageReq("libfoo", 1)); err == nil {
		t.Fatal("a VULDEF detail document parsed as an overview feed without error")
	}
}

// TestM55JVN_RealResponseParses runs the parser over a VERBATIM live MyJVN
// answer (testdata/myjvn_getVulnOverviewList_openssl.xml, captured 2026-08-11:
// keyword=openssl, maxCountItem=3, startItem=1, all three date ranges "n").
//
// The fixture is MyJVN API output, retained under the MyJVN terms of use
// (https://jvndb.jvn.jp/apis/termsofuse.html); the vulnerability information it
// contains is provided by IPA / JPCERT-CC through JVN iPedia.
//
// Every other test in this package feeds the parser a fixture written by the
// same person who wrote the parser. This one does not, and it is the only
// thing here that can catch the parse structs being bound to element names
// MyJVN does not use — the real feed namespaces them (sec:identifier,
// sec:references, dcterms:issued) and puts an <items>/<rdf:Seq> index inside
// <channel> that must not be mistaken for entries.
func TestM55JVN_RealResponseParses(t *testing.T) {
	body, err := os.ReadFile("testdata/myjvn_getVulnOverviewList_openssl.xml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	svc := NewJVNService(nil, nil, "", false)

	page, err := svc.parseJVNPage(body, jvnPageRequest{keyword: "openssl", startItem: 1, maxCountItem: 3})
	if err != nil {
		t.Fatalf("a live MyJVN response did not parse: %v", err)
	}
	if page.totalRes != 459 || page.totalResRet != 3 || page.firstRes != 1 {
		t.Errorf("totalRes/totalResRet/firstRes = %d/%d/%d, want 459/3/1",
			page.totalRes, page.totalResRet, page.firstRes)
	}
	if len(page.vulns) != 3 {
		t.Fatalf("parsed %d advisories from a 3-entry page — the <item> tags are not being matched",
			len(page.vulns))
	}
	if page.vulns[0].CVEID != "CVE-2026-54876" {
		t.Errorf("first CVE = %q, want CVE-2026-54876 (from sec:references/@id)", page.vulns[0].CVEID)
	}
	if page.vulns[0].PublishedAt == nil {
		t.Error("PublishedAt is nil; dcterms:issued is not reaching the model")
	}

	// The same body is not page 2, and the parser must say so.
	if _, err := svc.parseJVNPage(body, jvnPageRequest{keyword: "openssl", startItem: 51, maxCountItem: 3}); err == nil {
		t.Error("a live page 1 was accepted as the answer to startItem=51")
	}
}

// TestM55JVN_TrailingContentAfterTheFeedIsRejected is the JVN twin of the NVD
// trailing-content check: a mirror must not be able to prefix a valid empty
// envelope to arbitrary content and have it read as an authoritative answer.
func TestM55JVN_TrailingContentAfterTheFeedIsRejected(t *testing.T) {
	st := echoOf(url.Values{"keyword": {"libfoo"}, "startItem": {"1"}, "maxCountItem": {"50"},
		"rangeDatePublic": {"n"}, "rangeDatePublished": {"n"}, "rangeDateFirstPublished": {"n"}})
	st.RetCd = "0"
	st.FirstRes = 1
	body := renderCannedMyJVN(st, nil, time.Now()) + `<rdf:RDF/>`
	svc := NewJVNService(nil, nil, "", false)
	if _, err := svc.parseJVNPage([]byte(body), jvnTestPageReq("libfoo", 1)); err == nil {
		t.Fatal("a body with a second document after the feed was accepted")
	}
}
