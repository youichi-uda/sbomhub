package service

import (
	"context"
	"encoding/xml"
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
		baseURL: baseURL,
		offline: offline,
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
type JVNStatus struct {
	Version  string `xml:"version,attr"`
	Method   string `xml:"method,attr"`
	RetCd    string `xml:"retCd,attr"`
	RetMax   string `xml:"retMax,attr"`
	ErrCd    string `xml:"errCd,attr"`
	ErrMsg   string `xml:"errMsg,attr"`
	TotalRes string `xml:"totalRes,attr"`
	FirstRes string `xml:"firstRes,attr"`
	Feed     string `xml:"feed,attr"`
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

// ScanComponents scans components for JVN vulnerabilities
func (s *JVNService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "jvn")
		return nil
	}

	components, err := s.componentRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("failed to get components: %w", err)
	}

	scanned, failed, refusedWrites := 0, 0, 0
	for _, comp := range components {
		refused, err := s.scanComponent(ctx, &comp)
		refusedWrites += refused
		if err != nil {
			slog.Error("Failed to scan component for JVN vulnerabilities",
				"component", comp.Name,
				"error", err)
			failed++
			continue
		}
		scanned++
		// Rate limiting - JVN API is more lenient but still be polite
		time.Sleep(500 * time.Millisecond)
	}

	// TOTAL failure has zero coverage and must not report success (M54, Codex
	// R8 Critical). This mirrors NVDService.processComponentsParallel: with
	// `?sources=jvn`, every request could return 500 and the caller still
	// logged "JVN scan completed" — and on the upload path that is what
	// ScanTracker records, so the CLI reads "0 vulnerabilities" off an outage
	// and `sbomhub scan --fail-on critical` exits 0.
	//
	// PARTIAL failure stays success here for the same reason it does in the
	// NVD scanner: choosing how many components may fail before a scan is
	// worthless is a product-policy decision, not a bug fix. See the note on
	// SbomHandler.runScan.
	// A refused WRITE means the database declined to record a match we had
	// already obtained — the same escalation NVDService makes, for the same
	// reason (M54, Codex R10 Critical).
	if refusedWrites > 0 {
		return fmt.Errorf("jvn: database refused %d vulnerability write(s); scan results are incomplete",
			refusedWrites)
	}

	if scanned == 0 && failed > 0 {
		return fmt.Errorf("jvn: all %d component lookup(s) failed; the scan has no coverage", failed)
	}

	slog.Info("JVN component scan completed",
		"scanned", scanned, "failed", failed, "refused_writes", refusedWrites)
	return nil
}

// scanComponent looks one component up in JVN and records what it finds.
//
// It returns the number of statements the DATABASE REFUSED alongside any fetch
// error, so ScanComponents can escalate (M54, Codex R10 Critical — the JVN twin
// of the R1 NVD defect). Before this, every write failure was logged and
// swallowed and scanComponent always returned nil, so a component whose matches
// could not be recorded was counted as successfully scanned and "JVN scan
// completed" was emitted for a sweep that persisted nothing.
func (s *JVNService) scanComponent(ctx context.Context, comp *model.Component) (int, error) {
	// Search JVN by product name
	vulns, err := s.searchByKeyword(ctx, comp.Name)
	if err != nil {
		return 0, err
	}

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

	return refused, nil
}

// searchByKeyword asks MyJVN for advisories matching a component name.
//
// # Two known completeness defects, NOT fixed in M54
//
// Both are the JVN twins of the NVD resultsPerPage truncation documented on
// NVDService.searchByKeyword, and both are deferred for the same reason: the
// repair is a fetch-policy decision, not a loop, and getting it wrong makes
// every scan of a common library unusably slow against a rate-limited API.
// Raised by Codex in M54 R9 (both Critical) and reported upward rather than
// left undocumented.
//
//  1. NO DATE RANGE IS SENT. MyJVN defaults rangeDatePublic /
//     rangeDatePublished / rangeDateFirstPublished to the past WEEK when they
//     are absent, so this only ever sees advisories from the last seven days.
//     Anything older is invisible to the scan, which still reports success.
//     Sending `n` (no range) is one line — but it turns every component lookup
//     into a full-history query, which interacts directly with defect 2.
//  2. THE RESULT SET IS TRUNCATED AT TEN. maxCountItem=10 is requested,
//     startItem is never sent, and the response's totalRes is ignored. An
//     eleventh match is dropped silently, and with defect 1 repaired there
//     would routinely be thousands.
//
// Fixing 1 without 2 makes under-reporting worse, not better: a full-history
// query returns far more matches, all but the first ten of which are then
// discarded. They have to be decided together, with a paging and rate-limit
// budget, which is why neither is taken here.
//
//  3. THE PAGE IS NOT IDENTIFIED. MyJVN sends firstRes (which page this is)
//     and totalResRet (how many entries it holds); neither is checked, so a
//     later page is accepted with the first one missing, and a page that is
//     short of its own totalResRet is accepted as complete (Codex M54 R10,
//     Critical). This is the JVN twin of the NVD startIndex / resultsPerPage
//     checks in NVDResponse.validate and is the one of the three that is NOT a
//     policy question — it is deferred only because it belongs with the paging
//     work above, whose response handling it would otherwise be written twice.
//
// Until then, a completed JVN scan means "some page of the first ten matches
// from the last seven days, per component" — not "every advisory affecting
// this component".
func (s *JVNService) searchByKeyword(ctx context.Context, keyword string) ([]model.Vulnerability, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "jvn")
		return nil, nil
	}

	params := url.Values{}
	params.Set("method", "getVulnOverviewList")
	params.Set("feed", "hnd")
	params.Set("keyword", keyword)
	params.Set("maxCountItem", "10")
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

	return s.parseJVNResponse(body)
}

func (s *JVNService) parseJVNResponse(data []byte) ([]model.Vulnerability, error) {
	var feed JVNRSSFeed
	if err := xml.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("failed to parse JVN response: %w", err)
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

	var vulns []model.Vulnerability
	for _, item := range feed.Items {
		vuln := s.convertJVNItemToVulnerability(item)
		if vuln != nil {
			vulns = append(vulns, *vuln)
		}
	}

	return vulns, nil
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
	cveID := ""
	if canonical, err := validation.ValidateCVEID(s.extractCVEID(item)); err == nil {
		cveID = canonical
	} else if id := strings.TrimSpace(item.Identifier); id != "" {
		// JVN advisories that carry no CVE are keyed by their JVNDB id.
		cveID = id
	}
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

// extractCVEID finds the CVE this advisory is about, if it names one.
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
func (s *JVNService) extractCVEID(item JVNItem) string {
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

// GetVulnerabilitiesByJVNID fetches detailed info for a specific JVNDB ID
func (s *JVNService) GetVulnerabilitiesByJVNID(ctx context.Context, jvnID string) (*model.Vulnerability, error) {
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "jvn")
		return nil, nil
	}

	params := url.Values{}
	params.Set("method", "getVulnDetailInfo")
	params.Set("feed", "hnd")
	params.Set("vulnId", jvnID)
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

	vulns, err := s.parseJVNResponse(body)
	if err != nil {
		return nil, err
	}

	if len(vulns) == 0 {
		return nil, fmt.Errorf("vulnerability not found: %s", jvnID)
	}

	return &vulns[0], nil
}
