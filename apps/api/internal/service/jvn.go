package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/validation"
)

const (
	jvnAPIBaseURL = "https://jvndb.jvn.jp/myjvn"

	// jvnMaxCountItem is MyJVN's OWN per-request ceiling, not a choice:
	// getVulnOverviewList documents maxCountItem as 1..50 with 50 as the
	// upper bound, and the FAQ states 「一度のアクセスで51件以上の取得はできません」.
	// The scanner used to send 10, which threw away four fifths of every
	// request's allowance for nothing.
	//   https://jvndb.jvn.jp/apis/getVulnOverviewList_api_hnd.html
	//   https://jvndb.jvn.jp/apis/myjvnapi_faq.html  (Q2-2)
	jvnMaxCountItem = 50

	// jvnMaxPagesPerComponent caps how deep one component's match set is
	// followed: 10 pages == 500 advisories.
	//
	// Measured against the live API on 2026-08-11 with all three date
	// ranges set to "n" (totalRes for one keyword):
	//
	//	lodash 11 | log4j 21 | jackson-databind 77 | nginx 233
	//	curl 243  | openssl 459 | express 482 | linux 17622
	//
	// 500 covers every one of those outright except "linux", whose 17,622
	// matches would cost 353 requests — roughly three minutes of MyJVN
	// traffic for a SINGLE component, inside the transaction the upload
	// scan holds open. Exhaustive paging is therefore not on the table;
	// what is on the table is following the match set to a stated budget
	// and SAYING SO when the budget binds, which is what jvnKeywordResult
	// .Truncated and JVNScanReport.Err carry.
	jvnMaxPagesPerComponent = 10

	// jvnExtraPageBudgetPerScan is a pool shared by every component in one
	// sweep, drawn on only by pages 2..N.
	//
	// The FIRST page of every component is always fetched and never draws
	// on the pool. That is what keeps this change strictly better than
	// what it replaces: a 2,000-component SBOM still issues its 2,000
	// lookups, so no component loses coverage to a component that happened
	// to match thousands of advisories. The pool bounds the ADDED traffic
	// at a constant that does not grow with the SBOM — worst case ~500
	// extra requests, ~7 minutes at the pacing below — instead of at
	// components x 10.
	jvnExtraPageBudgetPerScan = 500

	// jvnRequestDelay paces MyJVN requests. The FAQ asks for roughly 2-3
	// requests per second for short collections and gentler pacing for
	// long ones (「短時間（数分）での収集であれば秒間あたり、2～3アクセス程度」),
	// and warns that excessive traffic can get the source address blocked.
	// 500ms == 2/s, the rate this scanner already used between components;
	// page requests are paced identically rather than bursting.
	jvnRequestDelay = 500 * time.Millisecond

	// The request values the Status echo is checked against.
	jvnMethodOverviewList = "getVulnOverviewList"
	jvnFeedHND            = "hnd"
	jvnDateRangeAll       = "n"
)

// JVNService handles JVN (Japan Vulnerability Notes) API integration
type JVNService struct {
	vulnRepo      *repository.VulnerabilityRepository
	componentRepo *repository.ComponentRepository
	httpClient    *http.Client
	// baseURL is the MyJVN API base endpoint. It defaults to jvnAPIBaseURL but
	// is overridable (M40 Wave B) for air-gapped mirrors / httptest servers.
	baseURL string
	// offline short-circuits every HTTP fetch entry point when true (M40 Wave B
	// air-gapped degrade mode).
	offline bool
	// requestDelay paces outbound MyJVN requests (jvnRequestDelay by
	// default). Tests set it to zero; nothing else writes it.
	requestDelay time.Duration
}

// NewJVNService creates a new JVN service.
//
// baseURL and offline (M40 Wave B) are appended last: baseURL overrides the
// jvnAPIBaseURL default (empty => jvnAPIBaseURL); offline enables air-gapped
// degrade mode where scans short-circuit to empty results.
func NewJVNService(vulnRepo *repository.VulnerabilityRepository, componentRepo *repository.ComponentRepository, baseURL string, offline bool) *JVNService {
	if baseURL == "" {
		baseURL = jvnAPIBaseURL
	}
	return &JVNService{
		vulnRepo:      vulnRepo,
		componentRepo: componentRepo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:      baseURL,
		offline:      offline,
		requestDelay: jvnRequestDelay,
	}
}

// JVNRSS XML structures
type JVNRSSFeed struct {
	XMLName xml.Name   `xml:"RDF"`
	Channel JVNChannel `xml:"channel"`
	Items   []JVNItem  `xml:"item"`
	// Status is MyJVN's application-level result, and it was not modelled at
	// all until M54 (Codex R9, Critical). MyJVN reports failures — bad
	// parameters, service trouble — through retCd on this element, commonly
	// WITH HTTP 200. An unmodelled Status meant such a response unmarshalled
	// happily into zero items, scanComponent returned nil, the component was
	// counted as successfully checked, and even a total application-level
	// outage finished as "JVN scan completed" with no findings.
	Status JVNStatus `xml:"Status"`
}

// JVNStatus is the MyJVN <status:Status> element. retCd "0" is success;
// anything else is an application-level error carrying errCd / errMsg.
//
// The three paging attributes mean different things and only one of them says
// how long the page is (measured against the live API, 2026-08-11):
//
//   - totalRes    "応答エントリ総数" — how many entries match the FILTER, across
//     all pages. openssl with no date range answers 459.
//   - totalResRet "応答エントリ数" — how many entries THIS response holds.
//   - firstRes    "応答エントリ開始位置" — which entry this page starts at. It
//     echoes the requested startItem when the page is non-empty (measured:
//     startItem=457 answers firstRes="457") and is 1 when it is empty.
//
// retMax is NOT the page length: it is the API's own 50-entry ceiling and
// answers "50" even when maxCountItem=3 was requested (measured). Using it to
// validate a page would validate nothing.
//
// The element also ECHOES every request parameter (「各リクエストパラメタ」 in the
// response template). That echo is what makes it possible to tell "the answer
// to the query I sent" from "an answer" — a cache or proxy holding a reply for
// a different component, or one taken before the date range was widened, is
// otherwise indistinguishable from a genuine one. Measured echo behaviour: the
// value is returned exactly as it appeared in the query string, so a non-ASCII
// keyword comes back percent-encoded (keyword=日本語 echoes
// "%E6%97%A5%E6%9C%AC%E8%AA%9E") — the comparison has to allow for that.
type JVNStatus struct {
	Version     string `xml:"version,attr"`
	Method      string `xml:"method,attr"`
	RetCd       string `xml:"retCd,attr"`
	RetMax      string `xml:"retMax,attr"`
	ErrCd       string `xml:"errCd,attr"`
	ErrMsg      string `xml:"errMsg,attr"`
	TotalRes    string `xml:"totalRes,attr"`
	TotalResRet string `xml:"totalResRet,attr"`
	FirstRes    string `xml:"firstRes,attr"`
	Feed        string `xml:"feed,attr"`

	// Echoed request parameters.
	Keyword                 string `xml:"keyword,attr"`
	MaxCountItem            string `xml:"maxCountItem,attr"`
	StartItem               string `xml:"startItem,attr"`
	RangeDatePublic         string `xml:"rangeDatePublic,attr"`
	RangeDatePublished      string `xml:"rangeDatePublished,attr"`
	RangeDateFirstPublished string `xml:"rangeDateFirstPublished,attr"`
}

type JVNChannel struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
}

type JVNItem struct {
	Title       string    `xml:"title"`
	Link        string    `xml:"link"`
	Description string    `xml:"description"`
	Identifier  string    `xml:"identifier"`
	References  []JVNRef  `xml:"references"`
	CPE         []JVNCPE  `xml:"cpe"`
	CVSS        []JVNCVSS `xml:"cvss"`
	Published   string    `xml:"issued"`
	Modified    string    `xml:"modified"`
}

type JVNRef struct {
	ID     string `xml:"id,attr"`
	Source string `xml:"source,attr"`
	Title  string `xml:",chardata"`
}

type JVNCPE struct {
	Version string `xml:"version,attr"`
	Vendor  string `xml:"vendor,attr"`
	Product string `xml:"product,attr"`
	Value   string `xml:",chardata"`
}

type JVNCVSS struct {
	Version  string `xml:"version,attr"`
	Type     string `xml:"type,attr"`
	Severity string `xml:"severity,attr"`
	Score    string `xml:"score,attr"`
	Vector   string `xml:"vector,attr"`
}

// JVNScanReport is what one ScanComponents sweep did, as counts.
//
// It exists because the counts have to be REACHABLE BY THE CALLER, not just
// logged (M55). Before this, `failed` was incremented, written to a slog line
// and discarded; a caller holding the `error` return could distinguish "every
// lookup failed" from "fine" and nothing else, so a sweep in which 9 of 10
// components could not be reached was indistinguishable from a clean one.
//
// Whether a partial failure should FAIL a scan is still a product decision and
// is deliberately not taken here — Err() keeps the existing policy. Counting
// it is not a policy decision, and is what this type fixes.
type JVNScanReport struct {
	// Components is how many components the SBOM held.
	Components int
	// Scanned is how many were looked up without error.
	Scanned int
	// Failed is how many lookups returned an error — the partial-fetch
	// failure count that used to exist only in a log line.
	Failed int
	// SkippedNoName is how many components carried no usable name and were
	// therefore not queried at all.
	SkippedNoName int
	// Unscanned is how many components were never reached because the
	// sweep was cancelled part-way.
	Unscanned int
	// Cancelled records that the sweep ended early because its context
	// did. It is separate from Unscanned because cancellation ON THE LAST
	// component leaves nothing behind it — Unscanned would be 0 and, with
	// one earlier success, the killed sweep would report success (Codex
	// M55 R1, Critical).
	Cancelled bool
	// RefusedWrites is how many matches the database declined to record.
	RefusedWrites int
	// TruncatedComponents is how many components matched more advisories
	// in MyJVN than the fetch budget retrieved.
	TruncatedComponents int
	// Requests is how many MyJVN requests the sweep issued.
	Requests int
	// EntriesRetrieved / EntriesAvailable are the advisory counts behind
	// TruncatedComponents: DISTINCT advisories actually obtained, versus
	// what MyJVN said existed. EntriesReturned is what the API put on the
	// wire; it exceeds EntriesRetrieved exactly when entries were repeated
	// across pages or carried no identity.
	EntriesRetrieved int
	EntriesAvailable int
	EntriesReturned  int
	// BudgetExhausted records that the shared extra-page pool ran out, so
	// truncation here is our own budget rather than MyJVN's size.
	BudgetExhausted bool
}

// Summary renders the report as a single log/diagnostic string.
func (r JVNScanReport) Summary() string {
	return fmt.Sprintf(
		"components=%d scanned=%d failed=%d skipped_no_name=%d unscanned=%d cancelled=%t "+
			"refused_writes=%d truncated_components=%d advisories=%d/%d wire_entries=%d "+
			"requests=%d budget_exhausted=%t",
		r.Components, r.Scanned, r.Failed, r.SkippedNoName, r.Unscanned, r.Cancelled,
		r.RefusedWrites, r.TruncatedComponents, r.EntriesRetrieved, r.EntriesAvailable,
		r.EntriesReturned, r.Requests, r.BudgetExhausted)
}

// Err maps the report onto the single channel JVNService owns to the caller.
//
// The caller is SbomHandler.runScan, which turns a non-nil error into
// ScanTracker.MarkFailed — documented as "the upload succeeded, but scan
// results are incomplete". Every condition below is exactly that, so they all
// escalate through it:
//
//   - a refused WRITE (M54 R10) — a match was obtained and not recorded;
//   - EVERY lookup failing (M54 R8) — the sweep has no coverage at all;
//   - the sweep being cancelled part-way — components were never looked up;
//   - TRUNCATION (M55) — MyJVN holds more advisories for a component than the
//     budget retrieved.
//
// Two conditions are counted and NOT escalated:
//
//   - a PARTIAL fetch failure, unchanged: picking the threshold at which N of M
//     unreachable components invalidates a scan is a product decision. Failed
//     carries the number either way.
//   - a component with no name (SkippedNoName). There is nothing to look up, so
//     this is a defect in the uploaded SBOM rather than in the scan; the
//     component is not claimed as checked, it is claimed as skipped.
//
// It follows that a sweep of an SBOM whose components are ALL nameless returns
// nil — the same "nothing was looked up, and that is not an error" outcome an
// empty SBOM and offline mode already produce (see SbomHandler.runScan on what
// `completed` is worth).
func (r JVNScanReport) Err() error {
	if r.RefusedWrites > 0 {
		return fmt.Errorf("jvn: database refused %d vulnerability write(s); scan results are incomplete",
			r.RefusedWrites)
	}
	if r.Scanned == 0 && r.Failed > 0 {
		return fmt.Errorf("jvn: all %d component lookup(s) failed; the scan has no coverage", r.Failed)
	}
	if r.Cancelled {
		return fmt.Errorf("jvn: the scan was cancelled with %d of %d component(s) never looked up; "+
			"scan results are incomplete", r.Unscanned, r.Components)
	}
	if r.TruncatedComponents > 0 {
		return fmt.Errorf("jvn: %d of %d component(s) match more advisories than the fetch budget "+
			"retrieves (%d of %d entries pulled, budget_exhausted=%t); scan results are incomplete",
			r.TruncatedComponents, r.Components, r.EntriesRetrieved, r.EntriesAvailable, r.BudgetExhausted)
	}
	return nil
}

// ScanComponents scans components for JVN vulnerabilities.
//
// It is the compatibility shell over ScanComponentsReport for callers that
// only want the pass/fail verdict. Callers that need the counts — how many
// component lookups failed, how many match sets were truncated — must use
// ScanComponentsReport; those numbers cannot be recovered from this error.
func (s *JVNService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	_, err := s.ScanComponentsReport(ctx, sbomID)
	return err
}

// ScanComponentsReport scans every component of the SBOM against MyJVN and
// returns both the counts and the verdict. The report is populated even when
// the error is non-nil, except when the component list itself could not be
// read.
func (s *JVNService) ScanComponentsReport(ctx context.Context, sbomID uuid.UUID) (JVNScanReport, error) {
	var rep JVNScanReport

	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "jvn")
		return rep, nil
	}

	components, err := s.componentRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return rep, fmt.Errorf("failed to get components: %w", err)
	}
	rep.Components = len(components)

	// The pool is per-SWEEP, so one pathological component cannot spend the
	// whole scan's allowance and every component still gets its first page.
	extraPages := jvnExtraPageBudgetPerScan

	for i := range components {
		comp := &components[i]

		if strings.TrimSpace(comp.Name) == "" {
			// Not merely useless: with the date default removed a blank
			// keyword matches the ENTIRE JVN corpus, so querying it would
			// burn the page budget on an answer that means nothing.
			slog.Warn("skipping JVN lookup for a component with no name", "component_id", comp.ID)
			rep.SkippedNoName++
			continue
		}

		out, err := s.scanComponent(ctx, comp, &extraPages)
		rep.RefusedWrites += out.RefusedWrites
		rep.Requests += out.Fetch.Requests
		rep.EntriesRetrieved += out.Fetch.Retrieved
		rep.EntriesAvailable += out.Fetch.TotalRes
		rep.EntriesReturned += out.Fetch.Entries
		if out.Fetch.Truncated {
			rep.TruncatedComponents++
			slog.Warn("JVN match set truncated",
				"component", comp.Name,
				"retrieved", out.Fetch.Retrieved,
				"available", out.Fetch.TotalRes,
				"wire_entries", out.Fetch.Entries,
				"requests", out.Fetch.Requests,
				"budget_exhausted", out.Fetch.BudgetExhausted)
		}
		if out.Fetch.BudgetExhausted {
			rep.BudgetExhausted = true
		}
		if err != nil {
			slog.Error("Failed to scan component for JVN vulnerabilities",
				"component", comp.Name,
				"error", err)
			rep.Failed++
			if ctx.Err() != nil {
				// A cancelled context makes every remaining lookup fail
				// for a reason that has nothing to do with the component.
				// Counting those as "checked and clean" is how a killed
				// scan used to finish as a successful one.
				rep.Cancelled = true
				rep.Unscanned = len(components) - i - 1
				break
			}
			continue
		}
		rep.Scanned++

		if err := s.pause(ctx); err != nil {
			rep.Cancelled = true
			rep.Unscanned = len(components) - i - 1
			break
		}
	}

	slog.Info("JVN component scan completed", "report", rep.Summary())
	return rep, rep.Err()
}

// pause applies the inter-request delay, abandoning it if the context ends.
func (s *JVNService) pause(ctx context.Context) error {
	if s.requestDelay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(s.requestDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// scanComponent looks one component up in JVN and records what it finds.
//
// It returns the number of statements the DATABASE REFUSED alongside any fetch
// error, so ScanComponents can escalate (M54, Codex R10 Critical — the JVN twin
// of the R1 NVD defect). Before this, every write failure was logged and
// swallowed and scanComponent always returned nil, so a component whose matches
// could not be recorded was counted as successfully scanned and "JVN scan
// completed" was emitted for a sweep that persisted nothing.
func (s *JVNService) scanComponent(ctx context.Context, comp *model.Component, extraPages *int) (jvnComponentOutcome, error) {
	// Search JVN by product name
	res, err := s.searchKeyword(ctx, comp.Name, extraPages)
	out := jvnComponentOutcome{Fetch: res}
	if err != nil {
		return out, err
	}
	vulns := res.Vulns

	refused := 0
	for _, vuln := range vulns {
		// Check if vulnerability already exists
		existing, _ := s.vulnRepo.GetByCVEID(ctx, vuln.CVEID)
		if existing != nil {
			// Link existing vulnerability to component if not already linked.
			// A failed link means the component silently loses this match, so
			// log it (same treatment as the new-vulnerability path below).
			if err := s.vulnRepo.LinkToComponent(ctx, existing.ID, comp.ID); err != nil {
				slog.Error("Failed to link existing vulnerability to component",
					"cve_id", vuln.CVEID, "component", comp.Name, "error", err)
				refused++
			}
			continue
		}

		// Create new vulnerability
		vuln.ID = uuid.New()
		if err := s.vulnRepo.Create(ctx, &vuln); err != nil {
			slog.Error("Failed to create JVN vulnerability", "cve_id", vuln.CVEID, "error", err)
			refused++
			continue
		}

		// Link to component
		if err := s.vulnRepo.LinkToComponent(ctx, vuln.ID, comp.ID); err != nil {
			slog.Error("Failed to link vulnerability to component", "error", err)
			refused++
		}
	}

	out.RefusedWrites = refused
	return out, nil
}

// jvnComponentOutcome is what one component's scan did: what was fetched, and
// how much of it the database refused.
type jvnComponentOutcome struct {
	Fetch         jvnKeywordResult
	RefusedWrites int
}

// jvnKeywordResult is one component's keyword lookup: what came back, and how
// much of what MyJVN holds it represents.
//
// Retrieved counts DISTINCT ADVISORIES ACTUALLY OBTAINED — advisories whose
// JVNDB / CVE identity this scan now holds — and is deliberately not the sum of
// the pages' totalResRet (Codex M55 R1, Critical, two ways):
//
//   - an entry MyJVN returned that carries no identity is not an advisory this
//     scan holds. Counting the wire entry made a page of 50 unusable items read
//     as 50 retrieved, so Retrieved == TotalRes and the component was reported
//     complete while contributing nothing.
//   - a mirror that re-serves the same entries on page 2 (with a correct
//     firstRes) made 50 distinct advisories count as 100. Distinct counting
//     turns that into Retrieved=50 < TotalRes=100, i.e. truncated, which is the
//     truth. It also handles the legitimate version of the same event: MyJVN
//     orders newest-first, so an advisory published mid-scan shifts the window
//     and one entry genuinely appears twice while another is missed.
//
// TotalRes is the LARGEST total any page claimed, not the last. A total that
// shrinks between pages would otherwise erase the gap: page 1 saying
// totalRes=100 and page 2 saying totalRes=50 after 50 entries would compute
// Retrieved == TotalRes and report a complete answer with 50 advisories unseen.
type jvnKeywordResult struct {
	Vulns    []model.Vulnerability
	TotalRes int
	// Retrieved is distinct advisories obtained; Entries is what the API
	// returned on the wire. They differ exactly when something was dropped
	// or repeated, which is why both are kept.
	Retrieved int
	Entries   int
	Requests  int
	// Truncated is Retrieved < TotalRes: MyJVN holds advisories for this
	// keyword that this scan did not look at. It must reach the caller —
	// silently keeping the first N is what M55 exists to stop.
	Truncated bool
	// BudgetExhausted distinguishes "our shared page pool ran out" from
	// "this component alone exceeded the per-component cap".
	BudgetExhausted bool
}

// searchKeyword asks MyJVN for the advisories matching a component name and
// follows the result set to a stated budget.
//
// # What this sends, and why (M55; primary source, not recall)
//
// Every parameter below was checked against the getVulnOverviewList
// specification and against live responses on 2026-08-11:
//
//		https://jvndb.jvn.jp/apis/getVulnOverviewList_api_hnd.html
//		https://jvndb.jvn.jp/apis/myjvnapi_faq.html
//
//	  - rangeDatePublic / rangeDatePublished / rangeDateFirstPublished = "n".
//	    All three DEFAULT TO "w" — the past seven days including today. Omitting
//	    them, which is what this code did, meant the scanner could only ever see
//	    advisories published or updated in the last week: measured against a
//	    canned corpus modelled on the live totalRes figures, a component whose
//	    keyword matches 459 advisories (openssl) contributed 1, and one matching
//	    17,622 (linux) contributed 2. "n" is the value the MyJVN FAQ itself uses
//	    for an unrestricted query.
//	  - maxCountItem = 50, the documented maximum ("1～50", and 「一度のアクセスで
//	    51件以上の取得はできません」). The previous value of 10 discarded four
//	    fifths of each request's allowance for no saving.
//	  - startItem, 1-based, advanced by the number of entries each page actually
//	    returned rather than by the page size we asked for.
//
// # What it does NOT do
//
// It does not page exhaustively. jvnMaxPagesPerComponent and the shared
// jvnExtraPageBudgetPerScan pool bound the traffic; when either binds, or when
// MyJVN simply holds more than the cap, Truncated is set and the sweep reports
// the scan incomplete. The alternative — following every match set — costs 353
// requests for a single "linux" component (measured), inside the transaction
// the upload scan holds open.
func (s *JVNService) searchKeyword(ctx context.Context, keyword string, extraPages *int) (jvnKeywordResult, error) {
	var res jvnKeywordResult

	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "jvn")
		return res, nil
	}
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		// Against the previous one-week window a blank keyword was merely
		// wasteful. Against full history it matches the whole corpus.
		return res, nil
	}

	seenAdvisories := make(map[string]struct{})
	seenCVEs := make(map[string]struct{})
	startItem := 1
	for page := 0; page < jvnMaxPagesPerComponent; page++ {
		if page > 0 {
			if extraPages != nil {
				if *extraPages <= 0 {
					res.BudgetExhausted = true
					break
				}
				*extraPages--
			}
			if err := s.pause(ctx); err != nil {
				return res, err
			}
		}

		p, err := s.fetchPage(ctx, keyword, startItem)
		if err != nil {
			// A page we cannot trust makes the whole component's answer
			// untrustworthy: the entries we already hold are a prefix of
			// an answer whose length we can no longer establish.
			res.Requests++
			return res, err
		}
		res.Requests++
		if p.totalRes > res.TotalRes {
			res.TotalRes = p.totalRes
		}
		res.Entries += p.totalResRet
		for _, id := range p.advisoryIDs {
			if _, dup := seenAdvisories[id]; dup {
				continue
			}
			seenAdvisories[id] = struct{}{}
			res.Retrieved++
		}
		for _, v := range p.vulns {
			if _, dup := seenCVEs[v.CVEID]; dup {
				continue
			}
			seenCVEs[v.CVEID] = struct{}{}
			res.Vulns = append(res.Vulns, v)
		}

		if p.totalResRet == 0 {
			break
		}
		startItem += p.totalResRet
		if startItem > p.totalRes {
			break
		}
	}

	res.Truncated = res.Retrieved < res.TotalRes
	return res, nil
}

// fetchPage issues one getVulnOverviewList request and validates that the
// answer is the page that was asked for.
func (s *JVNService) fetchPage(ctx context.Context, keyword string, startItem int) (*jvnPage, error) {
	params := url.Values{}
	params.Set("method", jvnMethodOverviewList)
	params.Set("feed", jvnFeedHND)
	params.Set("keyword", keyword)
	params.Set("maxCountItem", strconv.Itoa(jvnMaxCountItem))
	params.Set("startItem", strconv.Itoa(startItem))
	// See searchKeyword: all three default to the past week.
	params.Set("rangeDatePublic", jvnDateRangeAll)
	params.Set("rangeDatePublished", jvnDateRangeAll)
	params.Set("rangeDateFirstPublished", jvnDateRangeAll)
	params.Set("lang", "ja")

	reqURL := fmt.Sprintf("%s?%s", s.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JVN API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return s.parseJVNPage(body, jvnPageRequest{
		keyword:      keyword,
		startItem:    startItem,
		maxCountItem: jvnMaxCountItem,
	})
}

// jvnPageRequest is the question a response has to be the answer to.
type jvnPageRequest struct {
	keyword      string
	startItem    int
	maxCountItem int
}

// jvnPage is one validated getVulnOverviewList response.
type jvnPage struct {
	vulns    []model.Vulnerability
	totalRes int
	// advisoryIDs are the identities of the entries this page carried, one
	// per identifiable entry. An entry with no identity contributes
	// nothing, which is how it shows up as a shortfall against totalRes.
	advisoryIDs []string
	totalResRet int
	firstRes    int
}

// parseJVNPage decodes one getVulnOverviewList response and refuses anything
// that cannot be identified as the page that was requested.
//
// # Page identity (M55; the JVN twin of NVDResponse.validate)
//
// Neither firstRes nor totalResRet was read before, so two different broken
// answers were accepted as complete ones (measured against a canned mirror:
// a response carrying firstRes=999 while claiming totalResRet=10 and holding 2
// items returned err=nil and 2 advisories):
//
//   - a mirror that ignores startItem and re-serves page 1 turns the paging
//     loop into a loop over the same 50 entries while the rest are recorded as
//     "seen";
//   - a page that is short of its own totalResRet loses the missing entries
//     with no trace.
//
// firstRes is only meaningful when the page is non-empty: MyJVN answers
// firstRes="1" for a zero-match response regardless of the startItem asked for
// (measured), so the equality check is conditioned on totalResRet > 0.
//
// # The zero-match answer is not an empty document
//
// Measured: a keyword with no matches answers totalRes="0" totalResRet="0"
// firstRes="1" AND one <item> titled 「MyJVN　該当する脆弱性対策情報はありません。」.
// A naive len(items) == totalResRet check would reject every empty answer, so
// totalResRet == 0 is handled explicitly — and is still required to hold no
// IDENTIFIABLE advisory, so a mirror cannot hide entries behind a zero count.
// # The response has to answer the question that was asked
//
// The Status element echoes every request parameter, and all of them are
// checked (Codex M55 R1, Critical). Without that, a cache or proxy could hand
// back a well-formed answer belonging to a DIFFERENT component — attributing
// one component's advisories to another — or one taken while the date range was
// still MyJVN's one-week default, and neither is distinguishable from a genuine
// reply by its shape alone. The date-range echo in particular is the only thing
// that proves the seven-day window is really gone rather than merely no longer
// requested.
func (s *JVNService) parseJVNPage(data []byte, req jvnPageRequest) (*jvnPage, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var feed JVNRSSFeed
	if err := dec.Decode(&feed); err != nil {
		return nil, fmt.Errorf("failed to parse JVN response: %w", err)
	}
	// Nothing may follow the feed. Same reasoning as decodeNVDResponse:
	// xml.Unmarshal decodes the first element and stops, so a proxy could
	// prefix a valid empty envelope to anything at all and have the scan
	// accept it as an authoritative "this component has no advisories".
	if err := jvnRequireCleanEOF(dec); err != nil {
		return nil, err
	}

	// MyJVN signals application-level failure through retCd, usually with HTTP
	// 200 (M54, Codex R9 Critical). retCd is part of BOTH the success and the
	// error envelope, so its ABSENCE means the body is not a MyJVN response at
	// all — the R9 cut tolerated that, which made a bare `<rdf:RDF/>` read as
	// an authoritative "no vulnerabilities" (R10, Critical). Same reasoning as
	// NVDResponse.validate: what distinguishes "no matches" from "not an
	// answer" is the presence of the envelope, not its value.
	rc := strings.TrimSpace(feed.Status.RetCd)
	if rc == "" {
		return nil, fmt.Errorf("JVN response has no status element; the endpoint returned 200 " +
			"but the body is not a MyJVN getVulnOverviewList response")
	}
	if rc != "0" {
		return nil, fmt.Errorf("JVN API reported failure: retCd=%s errCd=%s errMsg=%s",
			rc, feed.Status.ErrCd, feed.Status.ErrMsg)
	}

	if err := jvnCheckEcho(feed.Status, req); err != nil {
		return nil, err
	}

	totalRes, err := jvnCount(feed.Status.TotalRes, "totalRes")
	if err != nil {
		return nil, err
	}
	totalResRet, err := jvnCount(feed.Status.TotalResRet, "totalResRet")
	if err != nil {
		return nil, err
	}
	firstRes, err := jvnCount(feed.Status.FirstRes, "firstRes")
	if err != nil {
		return nil, err
	}

	if totalResRet > req.maxCountItem {
		return nil, fmt.Errorf("JVN response totalResRet=%d exceeds the requested maxCountItem=%d; "+
			"the answer is not to the question that was asked", totalResRet, req.maxCountItem)
	}

	page := &jvnPage{totalRes: totalRes, totalResRet: totalResRet, firstRes: firstRes}

	if totalResRet == 0 {
		for _, item := range feed.Items {
			if jvnItemIdentity(item) != "" {
				return nil, fmt.Errorf("JVN response declares totalResRet=0 but carries advisory %q; "+
					"the page contradicts its own entry count", jvnItemIdentity(item))
			}
		}
		return page, nil
	}

	// firstRes is only meaningful on a non-empty page; the echoed startItem
	// above covers the empty case.
	if firstRes != req.startItem {
		return nil, fmt.Errorf("JVN response firstRes=%d but startItem=%d was requested; "+
			"this is not the page that was asked for", firstRes, req.startItem)
	}
	if len(feed.Items) != totalResRet {
		return nil, fmt.Errorf("JVN response declares totalResRet=%d but carries %d entries; "+
			"the page is incomplete", totalResRet, len(feed.Items))
	}

	for _, item := range feed.Items {
		// An entry with no identity is one this scan cannot record. It is
		// NOT counted as retrieved (see jvnKeywordResult.Retrieved), so it
		// surfaces as a shortfall against totalRes rather than vanishing.
		if id := jvnItemIdentity(item); id != "" {
			page.advisoryIDs = append(page.advisoryIDs, jvnAdvisoryKey(item, id))
		}
		vuln := s.convertJVNItemToVulnerability(item)
		if vuln != nil {
			page.vulns = append(page.vulns, *vuln)
		}
	}

	return page, nil
}

// jvnAdvisoryKey is the identity used to tell entries apart ACROSS pages.
//
// It is the JVNDB advisory id where there is one, not the CVE id: totalRes
// counts advisories, and two JVNDB advisories may cite the same CVE. Keying on
// the CVE would collapse them, make Retrieved fall short of totalRes, and
// report a truncation that did not happen.
func jvnAdvisoryKey(item JVNItem, fallback string) string {
	if id := strings.TrimSpace(item.Identifier); id != "" {
		return id
	}
	return fallback
}

// jvnCheckEcho verifies that the Status element echoes the request that was
// sent. Every attribute it inspects is present in the live success envelope
// (measured); an absent one is a refusal, because "the parameter I cannot see"
// and "the parameter that was ignored" have to be treated the same way.
func jvnCheckEcho(st JVNStatus, req jvnPageRequest) error {
	if got := strings.TrimSpace(st.Method); got != jvnMethodOverviewList {
		return fmt.Errorf("JVN response is for method %q, not %q", got, jvnMethodOverviewList)
	}
	if got := strings.TrimSpace(st.Feed); got != jvnFeedHND {
		return fmt.Errorf("JVN response is for feed %q, not %q", got, jvnFeedHND)
	}
	for _, rng := range []struct{ name, got string }{
		{"rangeDatePublic", st.RangeDatePublic},
		{"rangeDatePublished", st.RangeDatePublished},
		{"rangeDateFirstPublished", st.RangeDateFirstPublished},
	} {
		if got := strings.TrimSpace(rng.got); got != jvnDateRangeAll {
			return fmt.Errorf("JVN response echoes %s=%q, not %q; the answer covers a narrower "+
				"date window than was asked for", rng.name, got, jvnDateRangeAll)
		}
	}
	if got, err := jvnCount(st.StartItem, "startItem echo"); err != nil {
		return err
	} else if got != req.startItem {
		return fmt.Errorf("JVN response echoes startItem=%d, not the requested %d", got, req.startItem)
	}
	if got, err := jvnCount(st.MaxCountItem, "maxCountItem echo"); err != nil {
		return err
	} else if got != req.maxCountItem {
		return fmt.Errorf("JVN response echoes maxCountItem=%d, not the requested %d", got, req.maxCountItem)
	}
	if !jvnKeywordEchoMatches(st.Keyword, req.keyword) {
		return fmt.Errorf("JVN response echoes keyword %q, not the requested %q; "+
			"this answer is about a different component", st.Keyword, req.keyword)
	}
	return nil
}

// jvnKeywordEchoMatches compares the echoed keyword with the one that was
// sent.
//
// MyJVN returns the value exactly as it appeared in the query string rather
// than decoding it, so a non-ASCII component name comes back percent-encoded
// (measured: keyword=日本語 テスト echoes
// "%E6%97%A5%E6%9C%AC%E8%AA%9E%20%E3%83%86%E3%82%B9%E3%83%88"). Both forms are
// accepted; requiring the literal form would reject every component whose name
// is not plain ASCII, turning this check from a guard into an outage.
func jvnKeywordEchoMatches(echo, want string) bool {
	echo = strings.TrimSpace(echo)
	if echo == want {
		return true
	}
	if decoded, err := url.QueryUnescape(echo); err == nil && decoded == want {
		return true
	}
	return false
}

// jvnRequireCleanEOF consumes what is left after the root element and rejects
// anything that is not insignificant markup.
func jvnRequireCleanEOF(dec *xml.Decoder) error {
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("JVN response body did not end cleanly: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return errJVNTrailingContent
			}
		case xml.Comment, xml.ProcInst, xml.Directive:
			// Insignificant.
		default:
			return errJVNTrailingContent
		}
	}
}

var errJVNTrailingContent = errors.New("JVN response has trailing content after the feed; " +
	"the endpoint returned 200 but the body is not a single MyJVN getVulnOverviewList response")

// jvnCount parses a MyJVN Status count attribute. An ABSENT attribute is an
// error, not a zero: totalResRet in particular is the only thing that says how
// long a page should be, so treating its absence as 0 would silently restore
// the short-page hole this check exists to close.
func jvnCount(raw, name string) (int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return 0, fmt.Errorf("JVN response has no %s attribute; the page cannot be identified", name)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("JVN response has a malformed %s attribute %q", name, raw)
	}
	return n, nil
}

func (s *JVNService) convertJVNItemToVulnerability(item JVNItem) *model.Vulnerability {
	// Extract CVE ID from references or identifier.
	//
	// M54 (Codex R9, Critical): the fallback to item.Identifier used to be
	// unconditional, so an item carrying NEITHER a CVE reference NOR an
	// identifier produced CVEID "". `vulnerabilities.cve_id` is VARCHAR NOT
	// NULL and accepts the empty string, so that row was created, the
	// component was linked to it, and the scan reported success — and because
	// cve_id is the ON CONFLICT key, every such item across every component
	// collapsed onto one nameless catalogue row. MyJVN's zero-match responses
	// are the ordinary way to reach that, which makes it a live defect rather
	// than a hostile-input one.
	//
	// CVE ids are canonicalised for the same reason NVD's are (M54 R8, High):
	// cve_id is UNIQUE and compared exactly, so "cve-..." and "CVE-..." would
	// otherwise become two rows for one vulnerability.
	cveID := jvnItemIdentity(item)
	if cveID == "" {
		slog.Warn("dropping JVN item with no CVE reference and no identifier",
			"title", item.Title, "link", item.Link)
		return nil
	}

	// M54 (Codex R10, Medium): JVNItem.Published was decoded and then never
	// used, so every JVN row stored published_at = NULL and consumers could
	// not display, sort or age those findings. JVN issues RFC3339 timestamps
	// with an offset; the zoneless NVD shapes are accepted too rather than
	// maintaining a second, subtly different parser.
	publishedAt := parseNVDTimestamp(item.Published)

	// Get CVSS score and severity. M46 B2: an item without any CVSS
	// entry yields a nil score (NOT 0.0, a real "None" score) so
	// un-scored JVN advisories are stored as NULL.
	var cvssScore *float64
	var severity string
	for _, cvss := range item.CVSS {
		if cvss.Version == "3.0" || cvss.Version == "3.1" {
			score, _ := strconv.ParseFloat(cvss.Score, 64)
			cvssScore = &score
			severity = s.mapCVSSSeverity(cvss.Severity)
			break
		}
	}
	// Fallback to CVSS v2
	if severity == "" && len(item.CVSS) > 0 {
		score, _ := strconv.ParseFloat(item.CVSS[0].Score, 64)
		cvssScore = &score
		severity = s.mapCVSSSeverity(item.CVSS[0].Severity)
	}

	if severity == "" {
		severity = "UNKNOWN"
	}

	now := time.Now()
	return &model.Vulnerability{
		CVEID:       cveID,
		Description: item.Description,
		Severity:    severity,
		CVSSScore:   cvssScore,
		PublishedAt: publishedAt,
		Source:      "JVN",
		UpdatedAt:   &now,
	}
}

// jvnItemIdentity returns the id an advisory would be catalogued under, or ""
// when it carries none.
//
// It is shared by convertJVNItemToVulnerability and by parseJVNPage's
// zero-entry check so that "does this item name an advisory?" has ONE answer.
// The MyJVN placeholder that a zero-match response carries — an <item> titled
// 「該当する脆弱性対策情報はありません。」 with no sec:identifier and no
// sec:references — is exactly an item with no identity, which is why the empty
// answer needs no special case beyond its entry count.
func jvnItemIdentity(item JVNItem) string {
	if canonical, err := validation.ValidateCVEID(extractJVNCVEID(item)); err == nil {
		return canonical
	}
	// JVN advisories that carry no CVE are keyed by their JVNDB id.
	return strings.TrimSpace(item.Identifier)
}

// extractJVNCVEID finds the CVE this advisory is about, if it names one.
//
// The prefix test is case-INSENSITIVE (M54). It was `HasPrefix(ref.ID, "CVE-")`
// before, so a reference written "cve-2021-44228" was not recognised as a CVE
// at all and the advisory fell through to being keyed by its JVNDB id —
// producing a SECOND catalogue row for a vulnerability the NVD scanner already
// stores under its CVE id. That is the same identity split the canonicalisation
// in convertJVNItemToVulnerability exists to prevent, one step earlier.
//
// Callers must still validate: this returns the RAW matched string, which is
// only a candidate.
func extractJVNCVEID(item JVNItem) string {
	for _, ref := range item.References {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ref.ID)), "CVE-") {
			return ref.ID
		}
	}
	// Check in identifier
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(item.Identifier)), "CVE-") {
		return item.Identifier
	}
	return ""
}

func (s *JVNService) mapCVSSSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "c":
		return "CRITICAL"
	case "high", "h":
		return "HIGH"
	case "medium", "m":
		return "MEDIUM"
	case "low", "l":
		return "LOW"
	case "none", "n":
		return "NONE"
	default:
		return "UNKNOWN"
	}
}

// GetVulnerabilitiesByJVNID was REMOVED in M55.
//
// It called getVulnDetailInfo and handed the body to the getVulnOverviewList
// parser. Those are different document types, which is not a subtlety —
// measured against the live API on 2026-08-11 (vulnId=JVNDB-2021-012182), the
// detail response root element is <VULDEF-Document> with <Vulinfo> children,
// while the overview parser is bound to the <rdf:RDF> feed root. Unmarshalling
// one as the other cannot succeed, so this entry point could never have
// returned a vulnerability against MyJVN; every call would have failed at the
// first line of parsing.
//
// It had no production callers (checked across apps/api, apps/web, packages
// and the CLI: the only references were its own definition and one offline
// test), so nothing regressed by deleting it, and nothing depended on the
// behaviour it did not have.
//
// Deleting beat both alternatives. Keeping it documented would leave a public
// method that reads as a working JVNDB detail lookup and is not one — the next
// caller to reach for it inherits the bug. Fixing it would mean writing and
// maintaining a VULDEF 3.2 parser, with its own page-identity handling, for a
// feature nothing asks for. If a detail lookup is wanted later it should be
// written against https://jvndb.jvn.jp/schema/vuldef_3.2.xsd from scratch, not
// revived from here. TestM55JVN_DetailInfoIsNotAnRSSFeed keeps the measured
// incompatibility executable so that decision is made with the fact in hand.
