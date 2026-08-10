package service

import (
	"context"
	"encoding/xml"
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

	"github.com/sbomhub/sbomhub/internal/model"
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
	ID string
	// CVE is the advisory's single CVE; CVEs overrides it when an advisory
	// covers several, the way real JVNDB advisories do.
	CVE       string
	CVEs      []string
	Published time.Time
	// CVSS, when set, replaces the default single 3.1/High/7.5 element.
	CVSS []cannedJVNCVSS
}

type cannedJVNCVSS struct {
	Version  string
	Severity string
	Score    string
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
	Lang                    string
	Keyword                 string
	MaxCountItem            string
	StartItem               string
	RangeDatePublic         string
	RangeDatePublished      string
	RangeDateFirstPublished string
}

// rawQueryParam returns a parameter's value as it literally appears in the
// query string, undecoded.
func rawQueryParam(rawQuery, name string) string {
	for _, kv := range strings.Split(rawQuery, "&") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
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
		Lang:                    def("lang", "ja"),
		Keyword:                 q.Get("keyword"),
		MaxCountItem:            def("maxCountItem", "50"),
		StartItem:               def("startItem", "1"),
		RangeDatePublic:         def("rangeDatePublic", "w"),
		RangeDatePublished:      def("rangeDatePublished", "w"),
		RangeDateFirstPublished: def("rangeDateFirstPublished", "w"),
	}
}

// jvnTestCVSS builds a <sec:cvss> element the way the wire carries it —
// unprefixed attributes — now that JVNCVSS reads them namespace-aware.
func jvnTestCVSS(version, severity, score string) JVNCVSS {
	return JVNCVSS{Attrs: []xml.Attr{
		{Name: xml.Name{Local: "version"}, Value: version},
		{Name: xml.Name{Local: "type"}, Value: "Base"},
		{Name: xml.Name{Local: "severity"}, Value: severity},
		{Name: xml.Name{Local: "score"}, Value: score},
	}}
}

// jvnTestRef builds a <sec:references> element with unprefixed attributes.
func jvnTestRef(source, id string) JVNRef {
	return JVNRef{Attrs: []xml.Attr{
		{Name: xml.Name{Local: "source"}, Value: source},
		{Name: xml.Name{Local: "id"}, Value: id},
	}}
}

// jvnTestPageReq is the request shape the hand-written fixtures answer: they
// all echo keyword="libfoo", startItem=1, at the full page size.
func jvnTestPageReq() jvnPageRequest {
	return jvnPageRequest{keyword: "libfoo", startItem: 1, maxCountItem: jvnMaxCountItem}
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
		// MEASURED: MyJVN echoes each parameter exactly as it appeared in
		// the query string, WITHOUT decoding it — a Japanese component name
		// comes back percent-encoded. Echoing r.URL.Query()'s decoded value
		// would have made the fixture kinder than the real API and left the
		// wire-form branch of the keyword check unexercised.
		rawKeyword := rawQueryParam(r.URL.RawQuery, "keyword")

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
		st.Keyword = rawKeyword
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
%s%s    <dc:date>%s</dc:date>
    <dcterms:issued>%s</dcterms:issued>
    <dcterms:modified>%s</dcterms:modified>
  </item>
`, a.ID, a.ID, a.ID, a.ID, renderCannedRefs(a), renderCannedCVSS(a.CVSS),
			a.Published.Format(time.RFC3339), a.Published.Format(time.RFC3339), a.Published.Format(time.RFC3339))
	}
	trr := fmt.Sprintf(` totalResRet="%d"`, st.TotalResRet)
	if st.omitTotalResRet {
		trr = ""
	}
	fmt.Fprintf(&b, `  <status:Status version="3.3" method="%s" lang="%s" retCd="%s" retMax="50" errCd="" errMsg="" totalRes="%d"%s firstRes="%d" feed="%s" keyword="%s" maxCountItem="%s" startItem="%s" rangeDatePublic="%s" rangeDatePublished="%s" rangeDateFirstPublished="%s"/>
</rdf:RDF>`, st.Method, st.Lang, st.RetCd, st.TotalRes, trr, st.FirstRes, st.Feed,
		st.Keyword, st.MaxCountItem, st.StartItem,
		st.RangeDatePublic, st.RangeDatePublished, st.RangeDateFirstPublished)
	return b.String()
}

func renderCannedRefs(a cannedJVNAdvisory) string {
	cves := a.CVEs
	if cves == nil {
		cves = []string{a.CVE}
	}
	var b strings.Builder
	for _, cve := range cves {
		fmt.Fprintf(&b, "    <sec:references source=\"CVE\" id=%q>https://www.cve.org/CVERecord?id=%s</sec:references>\n",
			cve, cve)
	}
	return b.String()
}

func renderCannedCVSS(entries []cannedJVNCVSS) string {
	if entries == nil {
		entries = []cannedJVNCVSS{{Version: "3.1", Severity: "High", Score: "7.5"}}
	}
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "    <sec:cvss version=%q type=\"Base\" severity=%q score=%q vector=\"CVSS:3.1/AV:N/AC:L\"/>\n",
			e.Version, e.Severity, e.Score)
	}
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
			// default is gone, not merely no longer requested. All
			// THREE are covered separately — with only rangeDatePublic
			// exercised, either of the other two checks could be
			// deleted and the suite would stay green (Codex M55 R3,
			// Medium).
			name: "answer still covers the one-week default (rangeDatePublic)",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.RangeDatePublic = "w"
			},
			wantErr: "rangeDatePublic",
		},
		{
			name: "answer still covers the one-week default (rangeDatePublished)",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.RangeDatePublished = "w"
			},
			wantErr: "rangeDatePublished",
		},
		{
			name: "answer still covers the one-week default (rangeDateFirstPublished)",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.RangeDateFirstPublished = "m"
			},
			wantErr: "rangeDateFirstPublished",
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
			// Measured: lang selects the corpus, it does not translate
			// one. keyword=openssl answers totalRes=459 under lang=ja
			// and totalRes=4 under lang=en.
			name: "answer is from the English corpus",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				st.Lang = "en"
			},
			wantErr: "lang",
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
	// Query encoding is not injective against the RAW name (Codex M55 R4,
	// High): "foo bar" goes on the wire as "foo+bar", which is exactly the
	// literal name of a DIFFERENT component. A cached answer for one was
	// accepted as the answer for the other.
	if jvnKeywordEchoMatches("foo+bar", "foo+bar") {
		t.Error(`the echo "foo+bar" — which is the wire form of the component "foo bar" — ` +
			`was accepted as the answer for the component "foo+bar"`)
	}
	if !jvnKeywordEchoMatches("foo+bar", "foo bar") {
		t.Error(`the genuine echo for the component "foo bar" was rejected`)
	}
	if !jvnKeywordEchoMatches("foo%2Bbar", "foo+bar") {
		t.Error(`the genuine echo for the component "foo+bar" was rejected`)
	}

	// And the same rule has to hold through the REAL fetch path, not just
	// in the helper (Codex M55 R5, Low): the canned server echoes the raw
	// wire form, so a component whose name is not plain ASCII exercises the
	// branch that production depends on.
	t.Run("through the fetch path", func(t *testing.T) {
		now := time.Now()
		srv := &cannedMyJVN{corpus: cannedCorpus(now, 3, 3), now: now}
		ts := srv.start(t)
		svc := NewJVNService(nil, nil, ts.URL, false)
		svc.requestDelay = 0

		for _, keyword := range []string{"日本語 テスト", "golang.org/x/crypto", "foo+bar", "foo bar"} {
			res, err := svc.searchKeyword(context.Background(), keyword, nil)
			if err != nil {
				t.Errorf("a legitimate answer for %q was rejected: %v", keyword, err)
				continue
			}
			if len(res.Vulns) != 3 {
				t.Errorf("keyword %q returned %d vulnerabilities, want 3", keyword, len(res.Vulns))
			}
		}
	})

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
// made 50 distinct advisories count as 100 against the real total — and the
// rest of the match set was never fetched. It also covers the honest
// version of the same event: MyJVN orders newest-first, so an advisory
// published mid-scan shifts the window and one entry really does repeat.
func TestM55JVN_RepeatedEntriesAreNotCountedTwice(t *testing.T) {
	now := time.Now()
	corpus := cannedCorpus(now, 500, 500)
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
		t.Error("50 distinct advisories out of 500 were reported as a complete answer")
	}
	if len(res.Vulns) != 50 {
		t.Errorf("returned %d vulnerabilities, want 50 — duplicates were not collapsed", len(res.Vulns))
	}
}

// TestM55JVN_NamespacesAreBound pins that the parse structs match on the MyJVN
// namespaces and not merely on local names (Codex M55 R3, High).
//
// encoding/xml matches an untagged field name against the local part alone, so
// the document below — which uses the words RDF, Status and item in a namespace
// that has nothing to do with MyJVN, and carries a plausible request echo with
// zero counts — parsed as a MyJVN feed and was accepted as an authoritative
// "this component has no advisories".
func TestM55JVN_NamespacesAreBound(t *testing.T) {
	const impostor = `<?xml version="1.0" encoding="UTF-8"?>
<x:RDF xmlns="http://purl.org/rss/1.0/" xmlns:x="http://attacker.example/not-rdf" xmlns:y="http://attacker.example/not-status">
  <channel><title>JVNDB</title><description/></channel>
  <y:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd="" errMsg="" totalRes="0" totalResRet="0" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
</x:RDF>`

	svc := NewJVNService(nil, nil, "", false)
	if _, err := svc.parseJVNPage([]byte(impostor), jvnTestPageReq()); err == nil {
		t.Fatal("a document using the MyJVN local names in foreign namespaces was accepted " +
			"as an authoritative empty answer")
	}

	// The same body in the RIGHT namespaces is a legitimate empty answer —
	// the check must discriminate, not just reject.
	genuine := strings.NewReplacer(
		"http://attacker.example/not-rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
		"http://attacker.example/not-status", "http://jvndb.jvn.jp/myjvn/Status",
	).Replace(impostor)
	if _, err := svc.parseJVNPage([]byte(genuine), jvnTestPageReq()); err != nil {
		t.Fatalf("a correctly-namespaced empty answer was rejected: %v", err)
	}
}

// TestM55JVN_StatusAttributeNamespaces pins that the Status attributes are read
// from the EMPTY namespace only (Codex M55 R4, High).
//
// encoding/xml matches an attribute tag on its local name in any namespace, so
// a correctly-namespaced <status:Status> carrying evil:retCd / evil:keyword /
// evil:totalRes and friends from an attacker namespace populated every field
// and walked a forged zero-result envelope through the entire validator.
// Measured with a scratch program: with tag `xml:"retCd,attr"`,
// `<s:S xmlns:evil="http://evil/" evil:retCd="0"/>` yields RetCd="0" — and so
// does the ` retCd,attr` empty-namespace form, which is why the attributes are
// read by hand instead.
func TestM55JVN_StatusAttributeNamespaces(t *testing.T) {
	const tmpl = `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:status="http://jvndb.jvn.jp/myjvn/Status" xmlns:evil="http://attacker.example/">
  <channel rdf:about="https://jvndb.jvn.jp/apis/myjvn">
    <title>JVNDB　脆弱性対策情報</title>
    <description/>
  </channel>
  <status:Status %sversion="3.3" %smethod="getVulnOverviewList" %slang="ja" %sretCd="0" retMax="50" errCd="" errMsg="" %stotalRes="0" %stotalResRet="0" %sfirstRes="1" %sfeed="hnd" %skeyword="libfoo" %smaxCountItem="50" %sstartItem="1" %srangeDatePublic="n" %srangeDatePublished="n" %srangeDateFirstPublished="n"/>
</rdf:RDF>`
	fill := func(prefix string) string {
		args := make([]any, 14)
		for i := range args {
			args[i] = prefix
		}
		return fmt.Sprintf(tmpl, args...)
	}

	svc := NewJVNService(nil, nil, "", false)

	if _, err := svc.parseJVNPage([]byte(fill("evil:")), jvnTestPageReq()); err == nil {
		t.Fatal("a Status whose every attribute came from an attacker namespace was accepted " +
			"as an authoritative empty answer")
	}
	// The same body with unprefixed attributes is a legitimate empty answer.
	if _, err := svc.parseJVNPage([]byte(fill("")), jvnTestPageReq()); err != nil {
		t.Fatalf("a genuine unprefixed Status was rejected: %v", err)
	}
}

// TestM55JVN_StatusOnlyBodyIsNotAFeed pins that a body carrying nothing but a
// well-formed zero-count Status is refused (Codex M55 R5, High).
//
// A getVulnOverviewList success is JVNRSS + Status, and JVNRSS always carries a
// <channel>. Accepting a Status-only document meant a body with no feed content
// whatsoever could assert "this component has no advisories" — Retrieved=0,
// TotalRes=0, Truncated=false — and be indistinguishable from a real empty
// answer. The earlier fixtures for this package were themselves Status-only,
// which is what certified the acceptance.
func TestM55JVN_StatusOnlyBodyIsNotAFeed(t *testing.T) {
	const statusOnly = `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
  <status:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd="" errMsg="" totalRes="0" totalResRet="0" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
</rdf:RDF>`

	svc := NewJVNService(nil, nil, "", false)
	if _, err := svc.parseJVNPage([]byte(statusOnly), jvnTestPageReq()); err == nil {
		t.Fatal("a body with a status and no feed at all was accepted as an authoritative " +
			"empty answer")
	}
}

// TestM55JVN_MultiCVEAdvisoryYieldsEveryCVE pins that an advisory covering
// several CVEs contributes all of them (Codex M55 R5, High).
//
// Measured on the live API (2026-08-11): JVNDB-2026-000019 carries four CVE
// references — CVE-2026-20704 / -22550 / -24449 / -24465. Keeping only the
// first dropped three real vulnerabilities per such advisory while the advisory
// still counted as retrieved, so the component was reported complete.
func TestM55JVN_MultiCVEAdvisoryYieldsEveryCVE(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	got := svc.convertJVNItemToVulnerabilities(JVNItem{
		Identifier: "JVNDB-2026-000019",
		References: []JVNRef{
			jvnTestRef("CVE", "CVE-2026-20704"),
			jvnTestRef("CVE", "CVE-2026-22550"),
			jvnTestRef("JVN", "JVNVU#92139835"),
			jvnTestRef("CVE", "cve-2026-24449"),
			jvnTestRef("CVE", "CVE-2026-24465"),
			jvnTestRef("CVE", "CVE-2026-20704"), // repeated
		},
		CVSS: []JVNCVSS{jvnTestCVSS("3.1", "Critical", "9.8")},
	})

	var ids []string
	for _, v := range got {
		ids = append(ids, v.CVEID)
		if v.Severity != "CRITICAL" {
			t.Errorf("%s stored as %s, want the advisory's CRITICAL assessment", v.CVEID, v.Severity)
		}
	}
	want := []string{"CVE-2026-20704", "CVE-2026-22550", "CVE-2026-24449", "CVE-2026-24465"}
	if len(ids) != len(want) {
		t.Fatalf("got %v, want all four CVEs %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("CVE[%d] = %q, want %q (canonicalised, de-duplicated, order preserved)",
				i, ids[i], want[i])
		}
	}

	// An advisory naming no CVE is still keyed by its JVNDB id.
	got = svc.convertJVNItemToVulnerabilities(JVNItem{Identifier: "JVNDB-2024-000123"})
	if len(got) != 1 || got[0].CVEID != "JVNDB-2024-000123" {
		t.Errorf("advisory with no CVE gave %v, want one row keyed by its JVNDB id", got)
	}

	// No identity at all is still dropped.
	if got = svc.convertJVNItemToVulnerabilities(JVNItem{Title: "nothing"}); len(got) != 0 {
		t.Errorf("an item with no identity produced %v, want nothing", got)
	}
}

// TestM55JVN_MultiCVEReachesTheFetchPath drives the multi-CVE rule through the
// REAL paging path (Codex M55 R6, Medium: the helper-level test stayed green
// when the parser was reverted to the singular conversion).
func TestM55JVN_MultiCVEReachesTheFetchPath(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{now: now, corpus: []cannedJVNAdvisory{{
		ID:        "JVNDB-2026-000019",
		CVEs:      []string{"CVE-2026-20704", "CVE-2026-22550", "CVE-2026-24449", "CVE-2026-24465"},
		Published: now,
	}}}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if len(res.Vulns) != 4 {
		t.Fatalf("got %d vulnerabilities from a four-CVE advisory, want 4", len(res.Vulns))
	}
	// One ADVISORY was retrieved, and the total counts advisories, so this
	// is complete rather than truncated.
	if res.Retrieved != 1 || res.TotalRes != 1 || res.Truncated {
		t.Errorf("Retrieved=%d TotalRes=%d Truncated=%v; a four-CVE advisory is one advisory",
			res.Retrieved, res.TotalRes, res.Truncated)
	}
}

// TestM55JVN_CompetingCVSSEntriesRankBySeverity pins that a stated CRITICAL is
// not outranked by a higher-scored HIGH within one advisory (Codex M55 R6,
// High).
func TestM55JVN_CompetingCVSSEntriesRankBySeverity(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	got := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000010",
		CVSS: []JVNCVSS{
			jvnTestCVSS("3.1", "Critical", "8.0"),
			jvnTestCVSS("3.1", "High", "8.5"),
		},
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.Severity != "CRITICAL" || got.CVSSScore == nil || *got.CVSSScore != 8.0 {
		t.Errorf("stored %s/%v, want CRITICAL/8.0 — the higher raw score demoted a stated CRITICAL",
			got.Severity, got.CVSSScore)
	}
}

// TestM55JVN_EmptyPageMustIdentifyItself pins that a zero-count answer still
// says where it is (Codex M55 R6, High). firstRes was checked only on non-empty
// pages, so values identifying no position at all passed unexamined.
func TestM55JVN_EmptyPageMustIdentifyItself(t *testing.T) {
	now := time.Now()
	for _, firstRes := range []int{0, 999} {
		t.Run(fmt.Sprintf("firstRes=%d", firstRes), func(t *testing.T) {
			srv := &cannedMyJVN{corpus: nil, now: now,
				corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
					st.FirstRes = firstRes
				}}
			ts := srv.start(t)
			svc := NewJVNService(nil, nil, ts.URL, false)
			svc.requestDelay = 0
			if _, err := svc.searchKeyword(context.Background(), "libfoo", nil); err == nil {
				t.Fatal("an empty page reporting an impossible firstRes was accepted")
			}
		})
	}
}

// TestM55JVN_ImpossibleCVSSValuesAreRefused pins the score sanity checks
// (Codex M55 R5, High).
func TestM55JVN_ImpossibleCVSSValuesAreRefused(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	// NaN parses, and every later comparison against it is false — one NaN
	// entry would otherwise pin the result and keep a Critical from winning.
	got := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000001",
		CVSS: []JVNCVSS{
			jvnTestCVSS("3.1", "Critical", "NaN"),
			jvnTestCVSS("3.1", "Critical", "9.8"),
		},
	})
	if got == nil || got.CVSSScore == nil || *got.CVSSScore != 9.8 {
		t.Errorf("stored %v, want 9.8 — a NaN score blocked the real one", got)
	}

	// Out of range is not a CVSS base score: it must not be stored. The
	// severity that element states is still honoured (see R7 above), so the
	// stated CRITICAL wins and the bad number is simply absent.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000002",
		CVSS: []JVNCVSS{
			jvnTestCVSS("3.1", "Critical", "1000"),
			jvnTestCVSS("3.1", "High", "7.5"),
		},
	})
	if got == nil || got.CVSSScore != nil {
		t.Errorf("stored %v, want no score — an out-of-range score was accepted", got)
	}
	if got != nil && got.Severity != "CRITICAL" {
		t.Errorf("stored severity %s, want CRITICAL", got.Severity)
	}

	// A label that contradicts its own score is read at the harsher of the
	// two: severity="Low" score="9.8" must not be stored as LOW.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000003",
		CVSS:       []JVNCVSS{jvnTestCVSS("3.1", "Low", "9.8")},
	})
	if got == nil || got.Severity != "CRITICAL" {
		t.Errorf("stored %v, want CRITICAL — a LOW label on a 9.8 score was taken at face value", got)
	}

	// A v2 score does not gain a CRITICAL band that the v2 scale lacks...
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000004",
		CVSS:       []JVNCVSS{jvnTestCVSS("2.0", "High", "10.0")},
	})
	if got == nil || got.Severity != "HIGH" {
		t.Errorf("stored %v, want HIGH — a v2 score was given a v3 CRITICAL band", got)
	}

	// ...but a v2 element still has to agree with the v2 band table
	// (Codex M55 R7, High). severity="Low" score="10.0" is HIGH on the v2
	// scale, and skipping v2 reconciliation entirely stored it as LOW.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000006",
		CVSS:       []JVNCVSS{jvnTestCVSS("2.0", "Low", "10.0")},
	})
	if got == nil || got.Severity != "HIGH" {
		t.Errorf("stored %v, want HIGH — a v2 LOW label on a 10.0 score was taken at face value", got)
	}

	// A severity label with stray whitespace must still be recognised
	// (Codex M55 R7, Medium): untrimmed it fell through to UNKNOWN and the
	// score band then supplied HIGH, silently demoting a stated CRITICAL.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000007",
		CVSS:       []JVNCVSS{jvnTestCVSS("3.1", "Critical ", "8.0")},
	})
	if got == nil || got.Severity != "CRITICAL" {
		t.Errorf("stored %v, want CRITICAL — a padded label was not recognised", got)
	}
}

// TestM55JVN_RefAndCVSSAttributeNamespaces pins that an advisory's identity and
// its severity are read from unprefixed attributes only (Codex M55 R5, High).
//
// This is the same encoding/xml trap already closed on Status, one element
// deeper: `xml:"id,attr"` on <sec:references> and `xml:"score,attr"` on
// <sec:cvss> matched a forged evil:id / evil:score, so an attacker-chosen CVE
// and a lowered assessment were stored while the advisory still counted as
// retrieved.
func TestM55JVN_RefAndCVSSAttributeNamespaces(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	ns := func(space, local, value string) xml.Attr {
		return xml.Attr{Name: xml.Name{Space: space, Local: local}, Value: value}
	}

	// A reference whose id lives in a foreign namespace names no CVE, so the
	// advisory falls back to its JVNDB id rather than adopting the forgery.
	got := svc.convertJVNItemToVulnerabilities(JVNItem{
		Identifier: "JVNDB-2024-000001",
		References: []JVNRef{{Attrs: []xml.Attr{
			ns("", "source", "CVE"),
			ns("http://attacker.example/", "id", "CVE-1999-0001"),
		}}},
	})
	if len(got) != 1 || got[0].CVEID != "JVNDB-2024-000001" {
		t.Errorf("got %v, want the advisory keyed by its own JVNDB id — a namespaced evil:id "+
			"supplied the CVE this advisory is filed under", got)
	}

	// A CVSS element whose score and severity live in a foreign namespace
	// carries no assessment at all, so the advisory stays unrated instead of
	// being lowered to the forged one.
	one := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000002",
		CVSS: []JVNCVSS{{Attrs: []xml.Attr{
			ns("", "version", "3.1"),
			ns("http://attacker.example/", "severity", "Low"),
			ns("http://attacker.example/", "score", "0.1"),
		}}},
	})
	if one == nil {
		t.Fatal("item was dropped")
	}
	if one.CVSSScore != nil || one.Severity != "UNKNOWN" {
		t.Errorf("stored %s/%v, want UNKNOWN/nil — namespaced evil:score decided the severity",
			one.Severity, one.CVSSScore)
	}
}

// TestM55JVN_ExactlyOneStatusElement pins that a response carries exactly one
// answer (Codex M55 R7, High).
//
// The Status field used to be a scalar, so a body holding BOTH a success
// envelope and a retCd!=0 error envelope resolved to whichever one the decoder
// kept, and the reported failure was never seen.
func TestM55JVN_ExactlyOneStatusElement(t *testing.T) {
	const two = `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
 xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
  <channel><title>JVNDB</title><description/></channel>
  <status:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd="" errMsg="" totalRes="0" totalResRet="0" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
  <status:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="1" retMax="50" errCd="MYJVN-ERR-101" errMsg="service trouble" totalRes="0" totalResRet="0" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
</rdf:RDF>`

	svc := NewJVNService(nil, nil, "", false)
	if _, err := svc.parseJVNPage([]byte(two), jvnTestPageReq()); err == nil {
		t.Fatal("a body carrying both a success and a failure status was accepted as a success")
	}
}

// TestM55JVN_R8Regressions pins the four defects Codex found in the machinery
// added by the previous rounds' own fixes (M55 R8). Each is a way for a scan to
// under-report while reporting success.
func TestM55JVN_R8Regressions(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	t.Run("an unusable v3 entry does not suppress a valid v2 one", func(t *testing.T) {
		got := svc.convertJVNItemToVulnerability(JVNItem{
			Identifier: "JVNDB-2024-000001",
			CVSS: []JVNCVSS{
				jvnTestCVSS("3.1", "", "n/a"), // yields nothing usable
				jvnTestCVSS("2.0", "High", "10.0"),
			},
		})
		if got == nil {
			t.Fatal("item was dropped")
		}
		if got.Severity != "HIGH" || got.CVSSScore == nil || *got.CVSSScore != 10.0 {
			t.Errorf("stored %s/%v, want HIGH/10 — an empty v3 pass hid a valid v2 assessment",
				got.Severity, got.CVSSScore)
		}
	})

	t.Run("an unknown version cannot suppress a valid v2 entry", func(t *testing.T) {
		// M55 R9, High: every non-v2 version used to enter a PREFERRED
		// pass, so an unrecognised version reporting Low/0.1 was returned
		// before the v2 HIGH beside it was ever considered.
		got := svc.convertJVNItemToVulnerability(JVNItem{
			Identifier: "JVNDB-2024-000010",
			CVSS: []JVNCVSS{
				jvnTestCVSS("9.9", "Low", "0.1"),
				jvnTestCVSS("2.0", "High", "10.0"),
			},
		})
		if got == nil {
			t.Fatal("item was dropped")
		}
		if got.Severity != "HIGH" || got.CVSSScore == nil || *got.CVSSScore != 10.0 {
			t.Errorf("stored %s/%v, want HIGH/10 — an unknown version outranked a valid v2 entry",
				got.Severity, got.CVSSScore)
		}
	})

	t.Run("a v3 CRITICAL still beats a higher-scored v2 HIGH", func(t *testing.T) {
		// The property the removed version-preference stage existed for.
		// It survives because the comparison leads with the rating.
		got := svc.convertJVNItemToVulnerability(JVNItem{
			Identifier: "JVNDB-2024-000011",
			CVSS: []JVNCVSS{
				jvnTestCVSS("2.0", "High", "10.0"),
				jvnTestCVSS("3.1", "Critical", "9.8"),
			},
		})
		if got == nil || got.Severity != "CRITICAL" || got.CVSSScore == nil || *got.CVSSScore != 9.8 {
			t.Errorf("stored %v, want CRITICAL/9.8", got)
		}
	})

	t.Run("a reference declaring source=CVE is CVE-intended", func(t *testing.T) {
		// M55 R9, Medium: the id alone was tested, so a mangled id under
		// source="CVE" was skipped in silence and left no shortfall.
		ids, complete := jvnItemCVEIDs(JVNItem{
			Identifier: "JVNDB-2024-000012",
			References: []JVNRef{
				jvnTestRef("CVE", "CVE-2026-20704"),
				jvnTestRef("CVE", "2026-22550"),
			},
		})
		if len(ids) != 1 || ids[0] != "CVE-2026-20704" {
			t.Errorf("ids = %v, want the one parseable CVE", ids)
		}
		if complete {
			t.Error("complete = true although a reference declaring source=CVE could not be recorded")
		}
	})

	t.Run("CVSS v4 is banded on the five-band scale", func(t *testing.T) {
		got := svc.convertJVNItemToVulnerability(JVNItem{
			Identifier: "JVNDB-2024-000002",
			CVSS:       []JVNCVSS{jvnTestCVSS("4.0", "Low", "9.8")},
		})
		if got == nil || got.Severity != "CRITICAL" {
			t.Errorf("stored %v, want CRITICAL — v4 was banded with the v2 table", got)
		}
		// An unrecognised version fails towards the harsher rating too.
		got = svc.convertJVNItemToVulnerability(JVNItem{
			Identifier: "JVNDB-2024-000003",
			CVSS:       []JVNCVSS{jvnTestCVSS("9.9", "Low", "9.8")},
		})
		if got == nil || got.Severity != "CRITICAL" {
			t.Errorf("stored %v, want CRITICAL for an unknown CVSS version", got)
		}
	})

	t.Run("a malformed CVE reference makes the advisory incomplete", func(t *testing.T) {
		ids, complete := jvnItemCVEIDs(JVNItem{
			Identifier: "JVNDB-2024-000004",
			References: []JVNRef{
				jvnTestRef("CVE", "CVE-2026-20704"),
				jvnTestRef("CVE", "CVE-2026-BOGUS"),
			},
		})
		if len(ids) != 1 || ids[0] != "CVE-2026-20704" {
			t.Errorf("ids = %v, want the one parseable CVE", ids)
		}
		if complete {
			t.Error("complete = true although a CVE that was on the wire could not be recorded")
		}
	})

	t.Run("advisory identity is case-canonical", func(t *testing.T) {
		upper := jvnAdvisoryKey(JVNItem{Identifier: "JVNDB-2026-027713"}, "")
		lower := jvnAdvisoryKey(JVNItem{Identifier: "jvndb-2026-027713"}, "")
		if upper != lower {
			t.Errorf("%q and %q are the same advisory but key differently; a mirror could "+
				"re-serve a page in another case and have it counted as new entries", upper, lower)
		}
	})
}

// TestM55JVN_CaseVariantRepeatIsNotNewCoverage drives the case-canonical
// identity through the REAL paging path.
func TestM55JVN_CaseVariantRepeatIsNotNewCoverage(t *testing.T) {
	now := time.Now()
	corpus := cannedCorpus(now, 100, 100)
	srv := &cannedMyJVN{corpus: corpus, now: now,
		corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
			if q.Get("startItem") == "51" {
				// Page 1 again, lower-cased: distinct bytes, same advisories.
				repeat := make([]cannedJVNAdvisory, 50)
				for i, a := range corpus[:50] {
					a.ID = strings.ToLower(a.ID)
					repeat[i] = a
				}
				*items = repeat
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
		t.Errorf("Retrieved = %d, want 50 distinct advisories (the wire returned %d)",
			res.Retrieved, res.Entries)
	}
	if !res.Truncated {
		t.Error("a re-served page in another case was counted as new coverage")
	}
}

// TestM55JVN_PageCountsMustBeSelfConsistent pins the arithmetic bounds a page
// has to satisfy against its own totalRes (Codex M55 R3, High).
//
// Both shapes below are impossible for a real answer and both used to be
// accepted. The first is the one that mattered: totalRes=1 with totalResRet=2,
// one usable entry and one without an identity, landed on Retrieved == TotalRes
// and reported a complete answer while dropping half of what it returned.
func TestM55JVN_PageCountsMustBeSelfConsistent(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name    string
		corrupt func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory)
		wantErr string
	}{
		{
			name: "page holds more entries than the match set has",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				*items = (*items)[:2]
				(*items)[1].ID, (*items)[1].CVE = "", ""
				st.TotalRes = 1
				st.TotalResRet = 2
			},
			wantErr: "contradicts the total",
		},
		{
			// firstRes=3 with 3 entries claims [3,5] out of a 4-entry
			// match set: each count is individually plausible, only
			// their sum is not.
			name: "page runs past the end of the match set",
			corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
				*items = (*items)[:3]
				st.TotalRes = 4
				st.TotalResRet = 3
				st.FirstRes = 3
				st.StartItem = "3"
			},
			wantErr: "runs past the end",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &cannedMyJVN{corpus: cannedCorpus(now, 5, 5), now: now, corrupt: tc.corrupt}
			ts := srv.start(t)
			svc := NewJVNService(nil, nil, ts.URL, false)
			svc.requestDelay = 0

			_, err := svc.fetchPage(context.Background(), "libfoo", startItemFor(tc.name))
			if err == nil {
				t.Fatal("a page whose counts contradict each other was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// startItemFor picks the startItem the forged page in each case claims.
func startItemFor(name string) int {
	if strings.Contains(name, "runs past") {
		return 3
	}
	return 1
}

// TestM55JVN_ZeroCountPageMayNotSmuggleEntries pins that a totalResRet=0 answer
// is the documented one-item placeholder and nothing else (Codex M55 R3, High).
//
// Allowing any number of identity-less items left a body that could carry
// arbitrary entries, have all of them discarded, and still be accepted as an
// authoritative "this component has no advisories" — Retrieved=0, TotalRes=0,
// Truncated=false, with nothing downstream able to tell.
func TestM55JVN_ZeroCountPageMayNotSmuggleEntries(t *testing.T) {
	now := time.Now()
	srv := &cannedMyJVN{corpus: nil, now: now,
		corrupt: func(q url.Values, st *cannedJVNStatus, items *[]cannedJVNAdvisory) {
			// Two entries, neither identifiable, under a zero count.
			*items = []cannedJVNAdvisory{{Published: now}, {Published: now}}
			st.TotalRes = 0
			st.TotalResRet = 0
		}}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	if _, err := svc.searchKeyword(context.Background(), "libfoo", nil); err == nil {
		t.Fatal("a zero-count page carrying multiple entries was accepted as an empty answer")
	}
}

// TestM55JVN_DuplicateCVEKeepsTheMoreSevere pins that when two JVNDB advisories
// cite the same CVE, the assessment that survives is the more severe one
// (Codex M55 R3, High).
//
// Only one catalogue row can exist per CVE. Keeping whichever advisory happened
// to arrive first meant a critical score could be discarded in favour of a low
// one that came earlier in the feed, and a severity-gated CI check would pass on
// the milder of the two.
func TestM55JVN_DuplicateCVEKeepsTheMoreSevere(t *testing.T) {
	low := 3.1
	high := 9.8
	mk := func(score *float64, sev string) model.Vulnerability {
		return model.Vulnerability{CVEID: "CVE-2021-44228", CVSSScore: score, Severity: sev}
	}

	if !jvnMoreSevere(mk(&high, "CRITICAL"), mk(&low, "LOW")) {
		t.Error("a critical assessment did not displace a low one")
	}
	if jvnMoreSevere(mk(&low, "LOW"), mk(&high, "CRITICAL")) {
		t.Error("a low assessment displaced a critical one")
	}
	if !jvnMoreSevere(mk(&low, "LOW"), mk(nil, "UNKNOWN")) {
		t.Error("a scored advisory did not displace an unscored one")
	}
	// The severity LABEL outranks the raw score, because CVSS v2 and v3
	// numbers are not comparable (Codex M55 R4, High): a v2 HIGH of 10.0
	// must not displace a v3.1 CRITICAL of 9.8.
	v2high := 10.0
	v3crit := 9.8
	if jvnMoreSevere(mk(&v2high, "HIGH"), mk(&v3crit, "CRITICAL")) {
		t.Error("a HIGH/10.0 displaced a CRITICAL/9.8; raw scores were compared across versions")
	}
	if !jvnMoreSevere(mk(&v3crit, "CRITICAL"), mk(&v2high, "HIGH")) {
		t.Error("a CRITICAL/9.8 did not displace a HIGH/10.0")
	}
	if jvnMoreSevere(mk(nil, "UNKNOWN"), mk(&low, "LOW")) {
		t.Error("an unscored advisory displaced a scored one")
	}
	if !jvnMoreSevere(mk(nil, "HIGH"), mk(nil, "MEDIUM")) {
		t.Error("with no scores, the severity label did not decide")
	}
	if jvnMoreSevere(mk(&high, "CRITICAL"), mk(&high, "CRITICAL")) {
		t.Error("an equal assessment displaced the incumbent; arrival order must not matter")
	}
}

// TestM55JVN_WorstCVSSIsStored pins that an advisory carrying several CVSS
// elements is stored at its most severe assessment (Codex M55 R4, High).
//
// Taking the first v3 element and breaking meant a v3.0 LOW listed before a
// v3.1 CRITICAL was stored as LOW, and a malformed first score was stored as
// 0.0 — in both cases while the same item explicitly stated a critical
// assessment, so a critical-only CI gate would pass.
func TestM55JVN_WorstCVSSIsStored(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	got := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000001",
		CVSS: []JVNCVSS{
			jvnTestCVSS("3.0", "Low", "3.1"),
			jvnTestCVSS("3.1", "Critical", "9.8"),
		},
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.Severity != "CRITICAL" || got.CVSSScore == nil || *got.CVSSScore != 9.8 {
		t.Errorf("stored %s/%v, want CRITICAL/9.8 — the milder of two stated assessments was kept",
			got.Severity, got.CVSSScore)
	}

	// A malformed score must be skipped, but the severity the same element
	// STATES must not go with it (Codex M55 R7, High). An earlier cut
	// dropped the whole element, so an advisory reading
	// severity="Critical" score="n/a" was stored as UNKNOWN and a
	// critical-only gate passed on an advisory that says Critical in words.
	// The stated CRITICAL outranks the High sibling; the unusable score
	// stays absent rather than becoming a number.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000002",
		CVSS: []JVNCVSS{
			jvnTestCVSS("3.1", "Critical", "n/a"),
			jvnTestCVSS("3.1", "High", "7.5"),
		},
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("stored severity %s, want CRITICAL — a stated Critical was discarded with its "+
			"unparseable score", got.Severity)
	}
	if got.CVSSScore != nil {
		t.Errorf("stored score %v, want nil — an unparseable score became a real one", *got.CVSSScore)
	}

	// A sole element with an unusable score still carries its severity.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000005",
		CVSS:       []JVNCVSS{jvnTestCVSS("3.1", "Critical", "n/a")},
	})
	if got == nil || got.Severity != "CRITICAL" || got.CVSSScore != nil {
		t.Errorf("stored %v, want CRITICAL with no score", got)
	}

	// CVSS v3 wins over v2 outright: the scales are not comparable.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000003",
		CVSS: []JVNCVSS{
			jvnTestCVSS("2.0", "High", "10.0"),
			jvnTestCVSS("3.1", "Critical", "9.8"),
		},
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.Severity != "CRITICAL" || got.CVSSScore == nil || *got.CVSSScore != 9.8 {
		t.Errorf("stored %s/%v, want CRITICAL/9.8 — a v2 10.0 outranked a v3.1 CRITICAL",
			got.Severity, got.CVSSScore)
	}

	// No CVSS at all stays NULL, not 0.0 (M46 B2).
	got = svc.convertJVNItemToVulnerability(JVNItem{Identifier: "JVNDB-2024-000004"})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.CVSSScore != nil || got.Severity != "UNKNOWN" {
		t.Errorf("stored %s/%v, want UNKNOWN/nil", got.Severity, got.CVSSScore)
	}
}

// TestM55JVN_DuplicateCVEAcrossPagesKeepsTheMoreSevere drives the same rule
// through the REAL paging path (Codex M55 R4, High: the unit test called
// jvnMoreSevere directly, so reverting the searchKeyword wiring to
// first-entry-wins left it green).
func TestM55JVN_DuplicateCVEAcrossPagesKeepsTheMoreSevere(t *testing.T) {
	now := time.Now()
	// Two DISTINCT JVNDB advisories citing one CVE; the milder one is
	// listed first, exactly the order that used to win.
	corpus := []cannedJVNAdvisory{
		{ID: "JVNDB-2021-000001", CVE: "CVE-2021-44228", Published: now,
			CVSS: []cannedJVNCVSS{{Version: "3.1", Severity: "Low", Score: "3.1"}}},
		{ID: "JVNDB-2021-000002", CVE: "CVE-2021-44228", Published: now,
			CVSS: []cannedJVNCVSS{{Version: "3.1", Severity: "Critical", Score: "9.8"}}},
	}
	srv := &cannedMyJVN{corpus: corpus, now: now}
	ts := srv.start(t)
	svc := NewJVNService(nil, nil, ts.URL, false)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "log4j", nil)
	if err != nil {
		t.Fatalf("searchKeyword: %v", err)
	}
	if res.Retrieved != 2 {
		t.Errorf("Retrieved = %d, want 2 distinct advisories", res.Retrieved)
	}
	if res.Truncated {
		t.Error("both advisories were retrieved; this is not truncated")
	}
	if len(res.Vulns) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1 (both advisories name one CVE)", len(res.Vulns))
	}
	if res.Vulns[0].Severity != "CRITICAL" || res.Vulns[0].CVSSScore == nil || *res.Vulns[0].CVSSScore != 9.8 {
		t.Errorf("kept %s/%v, want CRITICAL/9.8 — the advisory that arrived first won on order alone",
			res.Vulns[0].Severity, res.Vulns[0].CVSSScore)
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
	if _, err := svc.parseJVNPage([]byte(vuldef), jvnTestPageReq()); err == nil {
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
	if _, err := svc.parseJVNPage([]byte(body), jvnTestPageReq()); err == nil {
		t.Fatal("a body with a second document after the feed was accepted")
	}
}
