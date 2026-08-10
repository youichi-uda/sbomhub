package service

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	jvnLang               = "ja"
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
	// extraPageBudget is the per-sweep pool of pages 2..N
	// (jvnExtraPageBudgetPerScan by default). It is a field only so a test
	// can shrink it: at the real value a test would need 500 pages of
	// fixtures to observe the pool being shared, which is why the sharing
	// went unpinned (Codex M55 R7, Low). Nothing but tests writes it.
	extraPageBudget int
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
		baseURL:         baseURL,
		offline:         offline,
		requestDelay:    jvnRequestDelay,
		extraPageBudget: jvnExtraPageBudgetPerScan,
	}
}

// JVNRSS XML structures.
//
// Every element is bound to the NAMESPACE MyJVN publishes it in, not just to
// its local name (Codex M55 R3, High). encoding/xml matches an untagged name
// against the local part alone, so before this an unrelated document that
// merely used the local names RDF / Status / item — in any namespace at all,
// or none — parsed as a MyJVN feed. With plausible echo attributes and zero
// counts it was then accepted as an authoritative "this component has no
// advisories". The URIs are the ones in the schemaLocation the live feed
// declares (jvnrss_3.2, mod_sec_3.0, status_3.3).
type JVNRSSFeed struct {
	XMLName xml.Name `xml:"http://www.w3.org/1999/02/22-rdf-syntax-ns# RDF"`
	// Channel is a POINTER so its absence is detectable. A body carrying
	// only a Status element is not a JVNRSS feed, and accepting one meant a
	// document with no feed content at all could assert "this component has
	// no advisories" (Codex M55 R5, High).
	Channel *JVNChannel `xml:"http://purl.org/rss/1.0/ channel"`
	Items   []JVNItem   `xml:"http://purl.org/rss/1.0/ item"`
	// Status is MyJVN's application-level result, and it was not modelled at
	// all until M54 (Codex R9, Critical). MyJVN reports failures — bad
	// parameters, service trouble — through retCd on this element, commonly
	// WITH HTTP 200. An unmodelled Status meant such a response unmarshalled
	// happily into zero items, scanComponent returned nil, the component was
	// counted as successfully checked, and even a total application-level
	// outage finished as "JVN scan completed" with no findings.
	// Statuses is a SLICE so that "how many status elements are there?" is
	// answerable (Codex M55 R7, High). A scalar field silently keeps one of
	// them, so a body carrying a success envelope alongside a retCd!=0
	// error envelope resolved to whichever the decoder happened to keep and
	// the failure was never seen.
	Statuses []JVNStatus `xml:"http://jvndb.jvn.jp/myjvn/Status Status"`
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
	// Attrs holds the element's attributes with their namespaces intact.
	//
	// Named `xml:"retCd,attr"` fields would be simpler and are WRONG here
	// (Codex M55 R4, High): encoding/xml matches an attribute tag on its
	// local name in ANY namespace, so a correctly-namespaced <status:Status>
	// carrying evil:retCd / evil:keyword / evil:totalRes from an attacker
	// namespace populated every field and let a forged zero-result envelope
	// through the whole validator. Measured: with tag `xml:"retCd,attr"`,
	// `<s:S xmlns:evil="http://evil/" evil:retCd="0"/>` yields RetCd="0";
	// the ` retCd,attr` (empty-namespace) form does NOT fix it — it matches
	// just the same. Reading the attributes ourselves and requiring an empty
	// namespace is the only form that discriminates.
	Attrs []xml.Attr `xml:",any,attr"`
}

// attr returns the value of an UNPREFIXED attribute, or "" when it is absent.
// A namespaced attribute of the same local name is not this attribute.
func (st JVNStatus) attr(name string) string { return jvnAttr(st.Attrs, name) }

// jvnAttr is the empty-namespace attribute lookup every MyJVN element needs.
// See the note on JVNStatus for why encoding/xml's own attribute tags cannot
// express this.
func jvnAttr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

type JVNChannel struct {
	Title       string `xml:"http://purl.org/rss/1.0/ title"`
	Description string `xml:"http://purl.org/rss/1.0/ description"`
}

type JVNItem struct {
	Title       string    `xml:"http://purl.org/rss/1.0/ title"`
	Link        string    `xml:"http://purl.org/rss/1.0/ link"`
	Description string    `xml:"http://purl.org/rss/1.0/ description"`
	Identifier  string    `xml:"http://jvn.jp/rss/mod_sec/3.0/ identifier"`
	References  []JVNRef  `xml:"http://jvn.jp/rss/mod_sec/3.0/ references"`
	CPE         []JVNCPE  `xml:"http://jvn.jp/rss/mod_sec/3.0/ cpe"`
	CVSS        []JVNCVSS `xml:"http://jvn.jp/rss/mod_sec/3.0/ cvss"`
	Published   string    `xml:"http://purl.org/dc/terms/ issued"`
	Modified    string    `xml:"http://purl.org/dc/terms/ modified"`
}

// JVNRef is a <sec:references> element. Its attributes are read through
// jvnAttr for the same reason JVNStatus's are (Codex M55 R5, High): a plain
// `xml:"id,attr"` tag matches the local name in ANY namespace, so a forged
// evil:id would have supplied the CVE this advisory is filed under.
type JVNRef struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Title string     `xml:",chardata"`
}

func (r JVNRef) ID() string     { return jvnAttr(r.Attrs, "id") }
func (r JVNRef) Source() string { return jvnAttr(r.Attrs, "source") }

// JVNCPE is decoded and not read by anything. Its attributes are left with
// plain tags deliberately: nothing downstream consumes them, so there is no
// decision for a forged one to influence. If a caller ever starts reading them,
// they need jvnAttr like the rest.
type JVNCPE struct {
	Version string `xml:"version,attr"`
	Vendor  string `xml:"vendor,attr"`
	Product string `xml:"product,attr"`
	Value   string `xml:",chardata"`
}

// JVNCVSS is a <sec:cvss> element. Namespace-aware for the same reason as
// JVNRef: a forged evil:severity / evil:score would otherwise decide what a
// severity-gated CI check sees.
type JVNCVSS struct {
	Attrs []xml.Attr `xml:",any,attr"`
}

func (c JVNCVSS) Version() string  { return jvnAttr(c.Attrs, "version") }
func (c JVNCVSS) Severity() string { return jvnAttr(c.Attrs, "severity") }
func (c JVNCVSS) Score() string    { return jvnAttr(c.Attrs, "score") }

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
	extraPages := s.extraPageBudget

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

		// No pause after the LAST component: there is nothing left to
		// pace, and a context that expired during that dead wait turned a
		// sweep which had in fact finished everything into a cancelled one
		// (Codex M55 R8, Low).
		if i == len(components)-1 {
			continue
		}
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
// # The keyword is the component NAME, with no version — deliberately
//
// NVDService.searchByKeyword sends "<name> <version>" because the NVD keyword
// search ANDs its terms, so the version narrows the match set. MyJVN does the
// OPPOSITE: it takes the UNION. Measured on the live API, 2026-08-11, totalRes
// with all three ranges "n":
//
//	keyword                   bare   +version   version alone
//	glibc / 2.31               158        198              40   <- 158+40 exactly
//	tomcat / 9.0.30            299        299               0
//	openssl / 1.1.1k           459        459               -
//	libxml2 / 2.9.10           135        139               -
//	jackson-databind / 2.9.10   77         79               -
//	lodash / 4.17.20            11         11               -
//
// glibc is the clean case: |glibc ∪ 2.31| = |glibc| + |2.31|. Appending a
// version can therefore only WIDEN a JVN query, never narrow it, and versions
// that appear nowhere in JVN's text (9.0.30) simply add nothing. Copying the
// NVD strategy here would cost requests and precision and buy neither.
//
// The consequence has to be stated plainly, because it is the price of this
// change: JVN matching is by name against advisory text, with no version and no
// CPE constraint, so a component named "tomcat" now gets ~299 advisories linked
// to it and "openssl" ~459 — most of them about other versions or other
// products that merely mention the word. Widening the fetch does not make the
// matching more precise, it makes the imprecision visible. Matching on the
// cpeName parameter instead is the real answer and is a separate change.
//
// It also settles the budget question: every component measured except a
// bare-OS-name class keyword fits inside jvnMaxPagesPerComponent (openssl 459
// and express 482 are the largest, both under 500). The cap binds on "linux"
// (17,622) and its relatives, not on ordinary library components.
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
	seenCVEs := make(map[string]int)
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
			// Two JVNDB advisories can cite the SAME CVE. Both are
			// retrieved, but only one row can be written, and taking
			// whichever arrived first meant a critical assessment could
			// be discarded in favour of a low one that happened to come
			// earlier in the feed (Codex M55 R3, High) — a severity-gated
			// CI check would then pass on the milder of the two. Keep the
			// more severe.
			if at, dup := seenCVEs[v.CVEID]; dup {
				if jvnMoreSevere(v, res.Vulns[at]) {
					res.Vulns[at] = v
				}
				continue
			}
			seenCVEs[v.CVEID] = len(res.Vulns)
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
	params.Set("lang", jvnLang)

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
// # What these checks do NOT establish
//
// They establish CONSISTENCY, not AUTHENTICITY (Codex M55 R6). A mirror that
// controls the connection can return a fully self-consistent empty feed — right
// namespaces, right channel, right echoes, right placeholder — and nothing here
// can tell it from a real "no advisories". Detecting that needs something this
// layer does not have: a signed feed, pinned transport, or corroboration
// against a second source. Transport security is the only thing standing behind
// the answer today, and a completed JVN scan should be read that way.
//
// The CVSS `vector` attribute is likewise not parsed, so an element whose
// vector encodes critical metrics while its severity says "Low" is stored as
// Low. Recomputing a base score from the vector is a CVSS calculator, i.e. its
// own component with its own tests, and is not attempted here.
//
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
	if len(feed.Statuses) != 1 {
		if len(feed.Statuses) == 0 {
			return nil, fmt.Errorf("JVN response has no status element; the endpoint returned 200 " +
				"but the body is not a MyJVN getVulnOverviewList response")
		}
		return nil, fmt.Errorf("JVN response carries %d status elements; exactly one answer is "+
			"expected and which of them is the answer is not decidable", len(feed.Statuses))
	}
	status := feed.Statuses[0]

	rc := strings.TrimSpace(status.attr("retCd"))
	if rc == "" {
		return nil, fmt.Errorf("JVN response has no status element; the endpoint returned 200 " +
			"but the body is not a MyJVN getVulnOverviewList response")
	}
	if rc != "0" {
		return nil, fmt.Errorf("JVN API reported failure: retCd=%s errCd=%s errMsg=%s",
			rc, status.attr("errCd"), status.attr("errMsg"))
	}

	if err := jvnCheckEcho(status, req); err != nil {
		return nil, err
	}

	// A success response is JVNRSS + Status, and JVNRSS always carries a
	// <channel> (Codex M55 R5, High). Without this, a body holding nothing
	// but a well-formed zero-count Status — no channel, no entries, no feed
	// at all — was accepted as an authoritative "this component has no
	// advisories", with Retrieved=0 / Truncated=false and nothing downstream
	// able to tell it apart from a real empty answer.
	if feed.Channel == nil {
		return nil, fmt.Errorf("JVN response has no channel element; the body carries a status " +
			"but is not a JVNRSS feed")
	}

	totalRes, err := jvnCount(status.attr("totalRes"), "totalRes")
	if err != nil {
		return nil, err
	}
	totalResRet, err := jvnCount(status.attr("totalResRet"), "totalResRet")
	if err != nil {
		return nil, err
	}
	firstRes, err := jvnCount(status.attr("firstRes"), "firstRes")
	if err != nil {
		return nil, err
	}

	if totalResRet > req.maxCountItem {
		return nil, fmt.Errorf("JVN response totalResRet=%d exceeds the requested maxCountItem=%d; "+
			"the answer is not to the question that was asked", totalResRet, req.maxCountItem)
	}
	// A page cannot hold more entries than the whole match set has, and it
	// cannot run past the end of it (Codex M55 R3, High). Without these, a
	// response could claim totalRes=1 / totalResRet=2, hand over two entries
	// one of which is unusable, and land on Retrieved == TotalRes — i.e.
	// report a complete answer while dropping one of the two entries it
	// actually returned.
	if totalResRet > totalRes {
		return nil, fmt.Errorf("JVN response holds totalResRet=%d entries out of a totalRes=%d "+
			"match set; the page contradicts the total it reports", totalResRet, totalRes)
	}
	if totalResRet > 0 && firstRes+totalResRet-1 > totalRes {
		return nil, fmt.Errorf("JVN response page [%d,%d] runs past the end of its own totalRes=%d "+
			"match set", firstRes, firstRes+totalResRet-1, totalRes)
	}

	page := &jvnPage{totalRes: totalRes, totalResRet: totalResRet, firstRes: firstRes}

	if totalResRet == 0 {
		// An empty page still has to say WHERE it is (Codex M55 R6, High).
		// firstRes is not compared with startItem here because MyJVN
		// answers firstRes="1" for a zero-match response (measured), but
		// values such as 0 or 999 identify no position at all and used to
		// pass unexamined.
		if firstRes != 1 && firstRes != req.startItem {
			return nil, fmt.Errorf("JVN response is empty and reports firstRes=%d, which is "+
				"neither 1 nor the requested startItem=%d", firstRes, req.startItem)
		}
		// The measured zero-match body carries exactly ONE placeholder
		// <item> and nothing else. Allowing any number of identity-less
		// items (Codex M55 R3, High) left a shape in which a body could
		// carry arbitrary entries, have every one of them discarded, and
		// still be accepted as an authoritative "no advisories" — with
		// Retrieved=0, TotalRes=0 and Truncated=false, so nothing
		// downstream could tell.
		if len(feed.Items) > 1 {
			return nil, fmt.Errorf("JVN response declares totalResRet=0 but carries %d entries; "+
				"a zero-match answer holds at most the one placeholder item", len(feed.Items))
		}
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
		// An entry this scan cannot record IN FULL is not counted as
		// retrieved (see jvnKeywordResult.Retrieved), so it surfaces as a
		// shortfall against totalRes rather than vanishing. That covers an
		// entry with no identity at all AND one carrying a CVE reference
		// that could not be parsed.
		_, complete := jvnItemCVEIDs(item)
		if id := jvnItemIdentity(item); id != "" && complete {
			page.advisoryIDs = append(page.advisoryIDs, jvnAdvisoryKey(item, id))
		}
		page.vulns = append(page.vulns, s.convertJVNItemToVulnerabilities(item)...)
	}

	return page, nil
}

// jvnSeverityRank orders the severity labels this scanner stores, most severe
// first. Anything unrecognised ranks lowest so it can never displace a rated
// advisory.
var jvnSeverityRank = map[string]int{
	"CRITICAL": 5,
	"HIGH":     4,
	"MEDIUM":   3,
	"LOW":      2,
	"NONE":     1,
}

// jvnMoreSevere reports whether a should replace b as the record kept for a CVE
// that two advisories both describe.
//
// The SEVERITY LABEL is compared first and the raw score only breaks ties
// (Codex M55 R4, High). Comparing scores first is wrong across CVSS versions,
// which JVN mixes: a v2 HIGH of 10.0 would otherwise displace a v3.1 CRITICAL
// of 9.8, demoting the record a critical-only CI gate is looking for. A rated
// advisory beats an unrated one, and a scored one beats an unscored one at
// equal rating. Equality keeps the incumbent, so arrival order can only ever
// raise the stored assessment, never lower it.
func jvnMoreSevere(a, b model.Vulnerability) bool {
	ra := jvnSeverityRank[strings.ToUpper(strings.TrimSpace(a.Severity))]
	rb := jvnSeverityRank[strings.ToUpper(strings.TrimSpace(b.Severity))]
	if ra != rb {
		return ra > rb
	}
	switch {
	case a.CVSSScore != nil && b.CVSSScore != nil:
		return *a.CVSSScore > *b.CVSSScore
	case a.CVSSScore != nil:
		return true
	default:
		return false
	}
}

// jvnAdvisoryKey is the identity used to tell entries apart ACROSS pages.
//
// It is the JVNDB advisory id where there is one, not the CVE id: totalRes
// counts advisories, and two JVNDB advisories may cite the same CVE. Keying on
// the CVE would collapse them, make Retrieved fall short of totalRes, and
// report a truncation that did not happen.
func jvnAdvisoryKey(item JVNItem, fallback string) string {
	// Upper-cased as well as trimmed (Codex M55 R8, High). JVNDB ids are
	// upper-case, and comparing them byte-for-byte let a mirror re-serve
	// page 1 with lower-cased identifiers: the entries looked distinct, so
	// Retrieved reached TotalRes and the scan claimed complete coverage
	// while half the match set had never been fetched.
	if id := strings.TrimSpace(item.Identifier); id != "" {
		return strings.ToUpper(id)
	}
	return strings.ToUpper(strings.TrimSpace(fallback))
}

// jvnCheckEcho verifies that the Status element echoes the request that was
// sent. Every attribute it inspects is present in the live success envelope
// (measured); an absent one is a refusal, because "the parameter I cannot see"
// and "the parameter that was ignored" have to be treated the same way.
func jvnCheckEcho(st JVNStatus, req jvnPageRequest) error {
	if got := strings.TrimSpace(st.attr("method")); got != jvnMethodOverviewList {
		return fmt.Errorf("JVN response is for method %q, not %q", got, jvnMethodOverviewList)
	}
	if got := strings.TrimSpace(st.attr("feed")); got != jvnFeedHND {
		return fmt.Errorf("JVN response is for feed %q, not %q", got, jvnFeedHND)
	}
	// lang is not cosmetic: it selects which corpus is searched. Measured on
	// the live API, keyword=openssl with the same date range answers
	// totalRes=459 under lang=ja and totalRes=4 under lang=en. A proxy that
	// served the English corpus would therefore under-report by two orders of
	// magnitude while looking entirely well-formed.
	if got := strings.TrimSpace(st.attr("lang")); got != jvnLang {
		return fmt.Errorf("JVN response is in lang %q, not %q; that is a different corpus, "+
			"not a translation of the same one", got, jvnLang)
	}
	for _, rng := range []struct{ name, got string }{
		{"rangeDatePublic", st.attr("rangeDatePublic")},
		{"rangeDatePublished", st.attr("rangeDatePublished")},
		{"rangeDateFirstPublished", st.attr("rangeDateFirstPublished")},
	} {
		if got := strings.TrimSpace(rng.got); got != jvnDateRangeAll {
			return fmt.Errorf("JVN response echoes %s=%q, not %q; the answer covers a narrower "+
				"date window than was asked for", rng.name, got, jvnDateRangeAll)
		}
	}
	if got, err := jvnCount(st.attr("startItem"), "startItem echo"); err != nil {
		return err
	} else if got != req.startItem {
		return fmt.Errorf("JVN response echoes startItem=%d, not the requested %d", got, req.startItem)
	}
	if got, err := jvnCount(st.attr("maxCountItem"), "maxCountItem echo"); err != nil {
		return err
	} else if got != req.maxCountItem {
		return fmt.Errorf("JVN response echoes maxCountItem=%d, not the requested %d", got, req.maxCountItem)
	}
	if !jvnKeywordEchoMatches(st.attr("keyword"), req.keyword) {
		return fmt.Errorf("JVN response echoes keyword %q, not the requested %q; "+
			"this answer is about a different component", st.attr("keyword"), req.keyword)
	}
	return nil
}

// jvnKeywordEchoMatches compares the echoed keyword with the one that was
// sent.
//
// MyJVN returns the value exactly as it appeared in the query string rather
// than decoding it, so a non-ASCII component name comes back percent-encoded
// (measured: keyword=日本語 テスト echoes
// "%E6%97%A5%E6%9C%AC%E8%AA%9E%20%E3%83%86%E3%82%B9%E3%83%88"). Requiring the
// literal name would therefore reject every component whose name is not plain
// ASCII — turning this check from a guard into an outage.
//
// What it must NOT do is compare the echo against the RAW name (Codex M55 R4,
// High). Query encoding is not injective on that comparison: a component named
// "foo+bar" goes on the wire as "foo%2Bbar", while a component named "foo bar"
// goes on the wire as "foo+bar" — so a cached answer for "foo bar" echoes
// exactly the string "foo+bar" and a raw comparison accepted it as the answer
// for "foo+bar". The two forms compared here are the two the wire can actually
// carry: what WE sent, and what the echo decodes back to.
func jvnKeywordEchoMatches(echo, want string) bool {
	echo = strings.TrimSpace(echo)
	if echo == url.QueryEscape(want) {
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

// convertJVNItemToVulnerabilities turns one advisory into one row PER CVE it
// names. See jvnItemCVEIDs.
func (s *JVNService) convertJVNItemToVulnerabilities(item JVNItem) []model.Vulnerability {
	ids, _ := jvnItemCVEIDs(item)
	if len(ids) == 0 {
		slog.Warn("dropping JVN item with no CVE reference and no identifier",
			"title", item.Title, "link", item.Link)
		return nil
	}
	base := s.convertJVNItemToVulnerability(item)
	if base == nil {
		return nil
	}
	out := make([]model.Vulnerability, 0, len(ids))
	for _, id := range ids {
		v := *base
		v.CVEID = id
		out = append(out, v)
	}
	return out
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
	//
	// M55 (Codex R4, High): this used to take the FIRST v3 element and
	// break, and to discard ParseFloat's error. An advisory carrying a v3.0
	// LOW before a v3.1 CRITICAL was therefore stored as LOW, and one whose
	// first score was malformed was stored as 0.0 — in both cases while the
	// same item explicitly stated a critical assessment. Take the most
	// severe entry instead, and skip entries whose score will not parse.
	cvssScore, severity := jvnWorstCVSS(item.CVSS)
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

// jvnWorstCVSS picks the assessment to store from an advisory's CVSS elements.
//
// CVSS v3 is preferred over v2 outright rather than by comparing their numbers:
// the two scales are not comparable, and a v2 HIGH of 10.0 is a LOWER
// assessment than a v3.1 CRITICAL of 9.8 (Codex M55 R4, High). Within a
// version family the highest score wins. Entries whose score does not parse are
// skipped rather than silently becoming 0.0.
func jvnWorstCVSS(entries []JVNCVSS) (*float64, string) {
	pick := func(want func(version string) bool) (*float64, string) {
		var best *float64
		var severity string
		seen := false
		for _, e := range entries {
			if !want(strings.TrimSpace(e.Version())) {
				continue
			}

			var candidateScore *float64
			candidate := mapCVSSSeverity(e.Severity())
			score, err := strconv.ParseFloat(strings.TrimSpace(e.Score()), 64)
			switch {
			case err != nil || !jvnScoreIsSane(score):
				// The SCORE is unusable; the stated SEVERITY is not
				// (Codex M55 R7, High). Dropping the whole element meant
				// an advisory whose only assessment read
				// severity="Critical" score="n/a" was stored as UNKNOWN
				// with no score at all, and a critical-only gate passed on
				// an advisory that says Critical in words.
				//
				// NaN is the reason the score cannot simply be kept:
				// ParseFloat accepts it and every later comparison against
				// it is false, so one NaN would pin the result and keep a
				// real Critical from ever winning (M55 R5).
				slog.Warn("ignoring JVN CVSS score but keeping its stated severity",
					"version", e.Version(), "score", e.Score(), "severity", e.Severity())
			default:
				// Reconcile FIRST, then rank on the reconciled severity
				// with the score as the tiebreak (M55 R6): ranking on the
				// raw score meant severity="Critical" score="8.0" lost to
				// severity="High" score="8.5".
				candidate = jvnReconcileSeverity(e.Version(), e.Severity(), score)
				s := score
				candidateScore = &s
			}

			if !seen || jvnMoreSevere(
				model.Vulnerability{Severity: candidate, CVSSScore: candidateScore},
				model.Vulnerability{Severity: severity, CVSSScore: best},
			) {
				seen = true
				best = candidateScore
				severity = candidate
			}
		}
		if !seen {
			return nil, ""
		}
		return best, severity
	}

	// The modern-scale pass only wins when it actually yielded an
	// assessment. Treating any non-empty severity as a win meant a v3 entry
	// that produced nothing usable — no score AND no recognisable label, so
	// UNKNOWN — suppressed a perfectly good v2 HIGH sitting next to it
	// (Codex M55 R8, High).
	usable := func(score *float64, severity string) bool {
		return score != nil || (severity != "" && severity != "UNKNOWN")
	}
	if score, severity := pick(jvnIsModernCVSS); usable(score, severity) {
		return score, severity
	}
	if score, severity := pick(func(v string) bool { return !jvnIsModernCVSS(v) }); usable(score, severity) {
		return score, severity
	}
	return nil, ""
}

// jvnItemCVEIDs returns EVERY CVE this advisory is filed under, canonicalised
// and de-duplicated, or the JVNDB id when it names none.
//
// M55 (Codex R5, High): a JVN advisory routinely covers several CVEs, and only
// the first was kept. Measured against the live API on 2026-08-11,
// JVNDB-2026-000019 carries four — CVE-2026-20704 / -22550 / -24449 / -24465 —
// so three of the four vulnerabilities it reports were dropped, while the
// advisory still counted as retrieved and the component was reported complete.
//
// Every CVE of the advisory inherits the advisory's CVSS. That is the shape of
// the data, not a shortcut: the MyJVN FAQ (Q2-3) states that an advisory
// covering several CVEs publishes the assessment of the MOST severe of them, so
// the shared score can overstate a milder sibling. Overstating severity is the
// safe direction for a security gate; dropping the CVE entirely, which is what
// happened before, is not.
func jvnItemCVEIDs(item JVNItem) (ids []string, complete bool) {
	out := []string{}
	complete = true
	seen := make(map[string]struct{})
	for _, ref := range item.References {
		id := strings.TrimSpace(ref.ID())
		if !strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			continue
		}
		canonical, err := validation.ValidateCVEID(id)
		if err != nil {
			// A CVE that was ON THE WIRE and could not be recorded is a
			// gap, not a log line (Codex M55 R8, Medium). The advisory
			// still has its JVNDB id, so without this it went on counting
			// as fully retrieved and the missing CVE left no trace.
			slog.Warn("dropping malformed CVE reference on a JVN advisory",
				"advisory", item.Identifier, "reference", id)
			complete = false
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	if len(out) > 0 {
		return out, complete
	}
	// An advisory with a CVE-shaped identifier, or none at all, keeps the
	// single-identity behaviour.
	if id := jvnItemIdentity(item); id != "" {
		return []string{id}, complete
	}
	return nil, complete
}

// jvnScoreIsSane rejects the values a CVSS base score cannot take. NaN and the
// infinities parse happily and then poison every comparison they take part in;
// a score outside 0..10 is not a CVSS base score at all.
func jvnScoreIsSane(score float64) bool {
	return !math.IsNaN(score) && !math.IsInf(score, 0) && score >= 0 && score <= 10
}

// jvnReconcileSeverity returns the MORE severe of the label an advisory states
// and the band its own score falls in (Codex M55 R5, High).
//
// `severity="Low" score="9.8"` is internally impossible, and taking the label
// stored it as LOW — letting a critical-only gate pass on an entry that says
// 9.8. Taking the harsher reading is the safe direction when a response
// contradicts itself.
//
// Each CVSS version is reconciled against ITS OWN band table (Codex M55 R7,
// High). An earlier cut skipped v2 entirely to avoid inventing a CRITICAL the
// v2 scale does not have — but that also let `version="2.0" severity="Low"
// score="10.0"` through as LOW, when 10.0 is HIGH on the v2 scale. Using the v2
// table gives the correction without inventing the missing band.
func jvnReconcileSeverity(version, label string, score float64) string {
	stated := mapCVSSSeverity(label)
	banded := jvnScoreBand(version, score)
	if jvnSeverityRank[banded] > jvnSeverityRank[stated] {
		return banded
	}
	return stated
}

// jvnIsModernCVSS reports whether a version uses the five-band qualitative
// scale (v3 and v4) rather than CVSS v2's three bands.
//
// The test is "not v2" rather than "is v3" (Codex M55 R8, High): keying on the
// "3." prefix put CVSS v4 — and every future or unrecognised version — into the
// v2 table, so a v4 score of 9.8 was banded HIGH instead of CRITICAL. An
// unknown version is treated as modern so that the failure direction is the
// harsher rating, not the milder one.
func jvnIsModernCVSS(version string) bool {
	return !strings.HasPrefix(strings.TrimSpace(version), "2.")
}

// jvnScoreBand is the qualitative rating a score implies, per CVSS version.
// v3 and v4 define five bands; v2 defines three and has no CRITICAL.
func jvnScoreBand(version string, score float64) string {
	if jvnIsModernCVSS(version) {
		switch {
		case score >= 9.0:
			return "CRITICAL"
		case score >= 7.0:
			return "HIGH"
		case score >= 4.0:
			return "MEDIUM"
		case score > 0:
			return "LOW"
		default:
			return "NONE"
		}
	}
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
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
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ref.ID())), "CVE-") {
			return ref.ID()
		}
	}
	// Check in identifier
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(item.Identifier)), "CVE-") {
		return item.Identifier
	}
	return ""
}

// mapCVSSSeverity normalises a CVSS qualitative rating. The label is TRIMMED
// (Codex M55 R7, Medium): `severity="Critical "` otherwise fell through to
// UNKNOWN, and with the score band supplying the answer instead, a stated
// CRITICAL was silently read as HIGH.
func mapCVSSSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
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
