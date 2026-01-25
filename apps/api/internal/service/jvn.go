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
)

const (
	jvnAPIBaseURL = "https://jvndb.jvn.jp/myjvn"
)

// JVNService handles JVN (Japan Vulnerability Notes) API integration
type JVNService struct {
	vulnRepo      *repository.VulnerabilityRepository
	componentRepo *repository.ComponentRepository
	httpClient    *http.Client
}

// NewJVNService creates a new JVN service
func NewJVNService(vulnRepo *repository.VulnerabilityRepository, componentRepo *repository.ComponentRepository) *JVNService {
	return &JVNService{
		vulnRepo:      vulnRepo,
		componentRepo: componentRepo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// JVNRSS XML structures
type JVNRSSFeed struct {
	XMLName xml.Name   `xml:"RDF"`
	Channel JVNChannel `xml:"channel"`
	Items   []JVNItem  `xml:"item"`
}

type JVNChannel struct {
	Title       string `xml:"title"`
	Description string `xml:"description"`
}

type JVNItem struct {
	Title       string       `xml:"title"`
	Link        string       `xml:"link"`
	Description string       `xml:"description"`
	Identifier  string       `xml:"identifier"`
	References  []JVNRef     `xml:"references"`
	CPE         []JVNCPE     `xml:"cpe"`
	CVSS        []JVNCVSS    `xml:"cvss"`
	Published   string       `xml:"issued"`
	Modified    string       `xml:"modified"`
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
	components, err := s.componentRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("failed to get components: %w", err)
	}

	for _, comp := range components {
		if err := s.scanComponent(ctx, &comp); err != nil {
			slog.Error("Failed to scan component for JVN vulnerabilities",
				"component", comp.Name,
				"error", err)
			continue
		}
		// Rate limiting - JVN API is more lenient but still be polite
		time.Sleep(500 * time.Millisecond)
	}

	return nil
}

func (s *JVNService) scanComponent(ctx context.Context, comp *model.Component) error {
	// Search JVN by product name
	vulns, err := s.searchByKeyword(ctx, comp.Name)
	if err != nil {
		return err
	}

	for _, vuln := range vulns {
		// Check if vulnerability already exists
		existing, _ := s.vulnRepo.GetByCVEID(ctx, vuln.CVEID)
		if existing != nil {
			// Link existing vulnerability to component if not already linked
			s.vulnRepo.LinkToComponent(ctx, existing.ID, comp.ID)
			continue
		}

		// Create new vulnerability
		vuln.ID = uuid.New()
		if err := s.vulnRepo.Create(ctx, &vuln); err != nil {
			slog.Error("Failed to create JVN vulnerability", "cve_id", vuln.CVEID, "error", err)
			continue
		}

		// Link to component
		if err := s.vulnRepo.LinkToComponent(ctx, vuln.ID, comp.ID); err != nil {
			slog.Error("Failed to link vulnerability to component", "error", err)
		}
	}

	return nil
}

func (s *JVNService) searchByKeyword(ctx context.Context, keyword string) ([]model.Vulnerability, error) {
	params := url.Values{}
	params.Set("method", "getVulnOverviewList")
	params.Set("feed", "hnd")
	params.Set("keyword", keyword)
	params.Set("maxCountItem", "10")
	params.Set("lang", "ja")

	reqURL := fmt.Sprintf("%s?%s", jvnAPIBaseURL, params.Encode())

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
	// Extract CVE ID from references or identifier
	cveID := s.extractCVEID(item)
	if cveID == "" {
		// Use JVN ID if no CVE
		cveID = item.Identifier
	}

	// Get CVSS score and severity
	var cvssScore float64
	var severity string
	for _, cvss := range item.CVSS {
		if cvss.Version == "3.0" || cvss.Version == "3.1" {
			score, _ := strconv.ParseFloat(cvss.Score, 64)
			cvssScore = score
			severity = s.mapCVSSSeverity(cvss.Severity)
			break
		}
	}
	// Fallback to CVSS v2
	if severity == "" && len(item.CVSS) > 0 {
		score, _ := strconv.ParseFloat(item.CVSS[0].Score, 64)
		cvssScore = score
		severity = s.mapCVSSSeverity(item.CVSS[0].Severity)
	}

	if severity == "" {
		severity = "UNKNOWN"
	}

	return &model.Vulnerability{
		CVEID:       cveID,
		Description: item.Description,
		Severity:    severity,
		CVSSScore:   cvssScore,
		Source:      "JVN",
		UpdatedAt:   time.Now(),
	}
}

func (s *JVNService) extractCVEID(item JVNItem) string {
	for _, ref := range item.References {
		if strings.HasPrefix(ref.ID, "CVE-") {
			return ref.ID
		}
	}
	// Check in identifier
	if strings.HasPrefix(item.Identifier, "CVE-") {
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
	params := url.Values{}
	params.Set("method", "getVulnDetailInfo")
	params.Set("feed", "hnd")
	params.Set("vulnId", jvnID)
	params.Set("lang", "ja")

	reqURL := fmt.Sprintf("%s?%s", jvnAPIBaseURL, params.Encode())

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
