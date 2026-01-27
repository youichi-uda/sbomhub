package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const osvAPIURL = "https://api.osv.dev/v1"

// OSVClient is a client for the OSV (Open Source Vulnerabilities) API
type OSVClient struct {
	httpClient *http.Client
}

// NewOSVClient creates a new OSV API client
func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// OSVVulnerability represents an OSV vulnerability response
type OSVVulnerability struct {
	ID        string       `json:"id"`
	Summary   string       `json:"summary"`
	Details   string       `json:"details"`
	Aliases   []string     `json:"aliases"`
	Modified  string       `json:"modified"`
	Published string       `json:"published"`
	Affected  []OSVAffected `json:"affected"`
	Severity  []OSVSeverity `json:"severity"`
}

// OSVAffected represents affected package information
type OSVAffected struct {
	Package         OSVPackage        `json:"package"`
	Ranges          []OSVRange        `json:"ranges"`
	Versions        []string          `json:"versions"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]interface{} `json:"database_specific"`
}

// OSVPackage represents package information
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
}

// OSVRange represents version range information
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent represents a version event (introduced/fixed)
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// OSVSeverity represents severity information
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVQueryRequest represents a query request to OSV API
type OSVQueryRequest struct {
	Package *OSVPackage `json:"package,omitempty"`
	Version string      `json:"version,omitempty"`
}

// OSVQueryResponse represents the response from OSV API
type OSVQueryResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

// GetVulnerability fetches a specific vulnerability by ID (CVE, GHSA, etc.)
func (c *OSVClient) GetVulnerability(ctx context.Context, vulnID string) (*OSVVulnerability, error) {
	url := fmt.Sprintf("%s/vulns/%s", osvAPIURL, vulnID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var vuln OSVVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	return &vuln, nil
}

// GetRemediation extracts remediation information from OSV vulnerability
func (c *OSVClient) GetRemediation(vuln *OSVVulnerability, packageName, ecosystem string) *RemediationInfo {
	if vuln == nil {
		return nil
	}

	remediation := &RemediationInfo{
		VulnID:       vuln.ID,
		Summary:      vuln.Summary,
		Workarounds:  []string{},
	}

	// Find the affected entry for this package
	for _, affected := range vuln.Affected {
		if !matchesPackage(affected.Package, packageName, ecosystem) {
			continue
		}

		// Extract fixed version from ranges
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					remediation.FixedVersion = event.Fixed
					break
				}
			}
			if remediation.FixedVersion != "" {
				break
			}
		}

		// Get affected versions
		remediation.AffectedVersions = affected.Versions
	}

	return remediation
}

// RemediationInfo contains remediation information for a vulnerability
type RemediationInfo struct {
	VulnID           string   `json:"vuln_id"`
	Summary          string   `json:"summary"`
	FixedVersion     string   `json:"fixed_version"`
	AffectedVersions []string `json:"affected_versions"`
	Workarounds      []string `json:"workarounds"`
}

func matchesPackage(pkg OSVPackage, name, ecosystem string) bool {
	// Normalize ecosystem names
	normalizedEcosystem := strings.ToLower(ecosystem)
	osvEcosystem := strings.ToLower(pkg.Ecosystem)

	ecosystemMatch := osvEcosystem == normalizedEcosystem ||
		(normalizedEcosystem == "maven" && osvEcosystem == "maven") ||
		(normalizedEcosystem == "npm" && osvEcosystem == "npm") ||
		(normalizedEcosystem == "pypi" && osvEcosystem == "pypi") ||
		(normalizedEcosystem == "go" && osvEcosystem == "go")

	nameMatch := strings.EqualFold(pkg.Name, name)

	return ecosystemMatch && nameMatch
}
