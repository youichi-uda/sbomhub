package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	nvdAPIBase = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	rateLimit  = 6 * time.Second
)

type NVDService struct {
	httpClient *http.Client
	vulnRepo   *repository.VulnerabilityRepository
	compRepo   *repository.ComponentRepository
	apiKey     string
}

func NewNVDService(vr *repository.VulnerabilityRepository, cr *repository.ComponentRepository, apiKey string) *NVDService {
	return &NVDService{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		vulnRepo:   vr,
		compRepo:   cr,
		apiKey:     apiKey,
	}
}

type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []NVDVulnEntry  `json:"vulnerabilities"`
}

type NVDVulnEntry struct {
	CVE NVDCVE `json:"cve"`
}

type NVDCVE struct {
	ID          string        `json:"id"`
	Published   string        `json:"published"`
	LastModified string       `json:"lastModified"`
	Descriptions []NVDDesc    `json:"descriptions"`
	Metrics     NVDMetrics    `json:"metrics"`
}

type NVDDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDMetrics struct {
	CvssMetricV31 []CvssMetric `json:"cvssMetricV31"`
	CvssMetricV30 []CvssMetric `json:"cvssMetricV30"`
	CvssMetricV2  []CvssMetric `json:"cvssMetricV2"`
}

type CvssMetric struct {
	CvssData CvssData `json:"cvssData"`
}

type CvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

func (s *NVDService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	components, err := s.compRepo.ListBySbom(ctx, sbomID)
	if err != nil {
		return fmt.Errorf("failed to get components: %w", err)
	}

	for _, comp := range components {
		if comp.Name == "" {
			continue
		}

		vulns, err := s.searchByKeyword(ctx, comp.Name, comp.Version)
		if err != nil {
			slog.Warn("Failed to search NVD", "component", comp.Name, "error", err)
			continue
		}

		for _, v := range vulns {
			existing, err := s.vulnRepo.GetByCVE(ctx, v.CVEID)
			if err != nil {
				if err := s.vulnRepo.Create(ctx, &v); err != nil {
					slog.Warn("Failed to create vulnerability", "cve", v.CVEID, "error", err)
					continue
				}
				existing = &v
			}

			if err := s.vulnRepo.LinkComponent(ctx, comp.ID, existing.ID); err != nil {
				slog.Warn("Failed to link component", "component", comp.ID, "vuln", existing.ID, "error", err)
			}
		}

		time.Sleep(rateLimit)
	}

	return nil
}

func (s *NVDService) searchByKeyword(ctx context.Context, name, version string) ([]model.Vulnerability, error) {
	keyword := name
	if version != "" {
		keyword = fmt.Sprintf("%s %s", name, version)
	}

	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "20")

	req, err := http.NewRequestWithContext(ctx, "GET", nvdAPIBase+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	if s.apiKey != "" {
		req.Header.Set("apiKey", s.apiKey)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API error: %d - %s", resp.StatusCode, string(body))
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	return s.convertToVulnerabilities(nvdResp.Vulnerabilities), nil
}

func (s *NVDService) convertToVulnerabilities(entries []NVDVulnEntry) []model.Vulnerability {
	var vulns []model.Vulnerability

	for _, entry := range entries {
		vuln := model.Vulnerability{
			ID:     uuid.New(),
			CVEID:  entry.CVE.ID,
			Source: "NVD",
		}

		for _, desc := range entry.CVE.Descriptions {
			if desc.Lang == "en" {
				vuln.Description = desc.Value
				break
			}
		}

		score, severity := extractCvss(entry.CVE.Metrics)
		vuln.CVSSScore = score
		vuln.Severity = severity

		if t, err := time.Parse(time.RFC3339, entry.CVE.Published); err == nil {
			vuln.PublishedAt = t
		}
		vuln.UpdatedAt = time.Now()

		vulns = append(vulns, vuln)
	}

	return vulns
}

func extractCvss(metrics NVDMetrics) (float64, string) {
	if len(metrics.CvssMetricV31) > 0 {
		m := metrics.CvssMetricV31[0].CvssData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV30) > 0 {
		m := metrics.CvssMetricV30[0].CvssData
		return m.BaseScore, strings.ToUpper(m.BaseSeverity)
	}
	if len(metrics.CvssMetricV2) > 0 {
		m := metrics.CvssMetricV2[0].CvssData
		return m.BaseScore, scoreToCvss2Severity(m.BaseScore)
	}
	return 0, "UNKNOWN"
}

func scoreToCvss2Severity(score float64) string {
	switch {
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
