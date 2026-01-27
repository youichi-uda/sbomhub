package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// RemediationService provides remediation guidance for vulnerabilities
type RemediationService struct {
	vulnRepo      *repository.VulnerabilityRepository
	componentRepo *repository.ComponentRepository
	osvClient     *client.OSVClient
}

// NewRemediationService creates a new remediation service
func NewRemediationService(
	vulnRepo *repository.VulnerabilityRepository,
	componentRepo *repository.ComponentRepository,
) *RemediationService {
	return &RemediationService{
		vulnRepo:      vulnRepo,
		componentRepo: componentRepo,
		osvClient:     client.NewOSVClient(),
	}
}

// RemediationResponse contains full remediation information
type RemediationResponse struct {
	CVEID             string                `json:"cve_id"`
	Summary           string                `json:"summary"`
	Severity          string                `json:"severity"`
	AffectedComponent AffectedComponent     `json:"affected_component"`
	Remediation       RemediationDetails    `json:"remediation"`
	Workarounds       []Workaround          `json:"workarounds"`
}

// AffectedComponent describes the affected component
type AffectedComponent struct {
	Name             string   `json:"name"`
	Ecosystem        string   `json:"ecosystem"`
	CurrentVersion   string   `json:"current_version"`
	AffectedVersions string   `json:"affected_versions"`
}

// RemediationDetails contains upgrade information
type RemediationDetails struct {
	Type          string            `json:"type"`
	TargetVersion string            `json:"target_version"`
	Commands      map[string]string `json:"commands"`
}

// Workaround describes an alternative fix
type Workaround struct {
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// GetRemediation fetches remediation guidance for a vulnerability
func (s *RemediationService) GetRemediation(ctx context.Context, vulnID uuid.UUID) (*RemediationResponse, error) {
	// Get vulnerability from database
	vuln, err := s.vulnRepo.GetByID(ctx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("vulnerability not found: %w", err)
	}

	// Fetch from OSV API
	osvVuln, err := s.osvClient.GetVulnerability(ctx, vuln.CVEID)
	if err != nil {
		// If OSV fails, return basic info from our database
		return &RemediationResponse{
			CVEID:    vuln.CVEID,
			Summary:  vuln.Description,
			Severity: vuln.Severity,
			Remediation: RemediationDetails{
				Type:     "manual",
				Commands: map[string]string{},
			},
			Workarounds: getKnownWorkarounds(vuln.CVEID),
		}, nil
	}

	response := &RemediationResponse{
		CVEID:    vuln.CVEID,
		Summary:  vuln.Description,
		Severity: vuln.Severity,
	}

	// Get remediation info from OSV - try to find any affected package
	if osvVuln != nil && len(osvVuln.Affected) > 0 {
		affected := osvVuln.Affected[0]
		remediationInfo := s.osvClient.GetRemediation(osvVuln, affected.Package.Name, affected.Package.Ecosystem)

		response.AffectedComponent = AffectedComponent{
			Name:      affected.Package.Name,
			Ecosystem: affected.Package.Ecosystem,
		}

		if remediationInfo != nil && remediationInfo.FixedVersion != "" {
			response.Remediation = RemediationDetails{
				Type:          "upgrade",
				TargetVersion: remediationInfo.FixedVersion,
				Commands:      generateUpgradeCommands(affected.Package.Name, remediationInfo.FixedVersion, affected.Package.Ecosystem),
			}
			if len(remediationInfo.AffectedVersions) > 0 {
				response.AffectedComponent.AffectedVersions = strings.Join(remediationInfo.AffectedVersions[:min(5, len(remediationInfo.AffectedVersions))], ", ")
			}
		}
	}

	// Add known workarounds for specific CVEs
	response.Workarounds = getKnownWorkarounds(vuln.CVEID)

	return response, nil
}


// GetRemediationByCVE fetches remediation by CVE ID
func (s *RemediationService) GetRemediationByCVE(ctx context.Context, cveID string, componentName, componentVersion string) (*RemediationResponse, error) {
	// Fetch from OSV API
	osvVuln, err := s.osvClient.GetVulnerability(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from OSV: %w", err)
	}
	if osvVuln == nil {
		return nil, fmt.Errorf("vulnerability not found in OSV: %s", cveID)
	}

	// Try to find the ecosystem from the affected packages
	ecosystem := ""
	for _, affected := range osvVuln.Affected {
		if strings.EqualFold(affected.Package.Name, componentName) {
			ecosystem = affected.Package.Ecosystem
			break
		}
	}

	remediationInfo := s.osvClient.GetRemediation(osvVuln, componentName, ecosystem)

	response := &RemediationResponse{
		CVEID:    cveID,
		Summary:  osvVuln.Summary,
		Severity: extractSeverity(osvVuln.Severity),
		AffectedComponent: AffectedComponent{
			Name:           componentName,
			Ecosystem:      ecosystem,
			CurrentVersion: componentVersion,
		},
	}

	if remediationInfo != nil && remediationInfo.FixedVersion != "" {
		response.Remediation = RemediationDetails{
			Type:          "upgrade",
			TargetVersion: remediationInfo.FixedVersion,
			Commands:      generateUpgradeCommands(componentName, remediationInfo.FixedVersion, ecosystem),
		}
	}

	response.Workarounds = getKnownWorkarounds(cveID)

	return response, nil
}

func (s *RemediationService) buildBasicResponse(vuln *model.Vulnerability, component *model.Component) *RemediationResponse {
	ecosystem := detectEcosystem(component.Purl, component.Type)
	return &RemediationResponse{
		CVEID:    vuln.CVEID,
		Summary:  vuln.Description,
		Severity: vuln.Severity,
		AffectedComponent: AffectedComponent{
			Name:           component.Name,
			Ecosystem:      ecosystem,
			CurrentVersion: component.Version,
		},
		Remediation: RemediationDetails{
			Type:     "manual",
			Commands: map[string]string{},
		},
		Workarounds: getKnownWorkarounds(vuln.CVEID),
	}
}

func detectEcosystem(purl, componentType string) string {
	if purl != "" {
		if strings.HasPrefix(purl, "pkg:maven/") {
			return "Maven"
		}
		if strings.HasPrefix(purl, "pkg:npm/") {
			return "npm"
		}
		if strings.HasPrefix(purl, "pkg:pypi/") {
			return "PyPI"
		}
		if strings.HasPrefix(purl, "pkg:golang/") {
			return "Go"
		}
		if strings.HasPrefix(purl, "pkg:nuget/") {
			return "NuGet"
		}
		if strings.HasPrefix(purl, "pkg:cargo/") {
			return "crates.io"
		}
		if strings.HasPrefix(purl, "pkg:gem/") {
			return "RubyGems"
		}
	}
	return componentType
}

func generateUpgradeCommands(name, version, ecosystem string) map[string]string {
	commands := make(map[string]string)

	switch strings.ToLower(ecosystem) {
	case "maven":
		commands["maven"] = fmt.Sprintf("<version>%s</version>", version)
		commands["gradle"] = fmt.Sprintf("implementation '%s:%s'", name, version)
	case "npm":
		commands["npm"] = fmt.Sprintf("npm install %s@%s", name, version)
		commands["yarn"] = fmt.Sprintf("yarn add %s@%s", name, version)
		commands["pnpm"] = fmt.Sprintf("pnpm add %s@%s", name, version)
	case "pypi":
		commands["pip"] = fmt.Sprintf("pip install %s==%s", name, version)
		commands["poetry"] = fmt.Sprintf("poetry add %s@%s", name, version)
	case "go":
		commands["go"] = fmt.Sprintf("go get %s@v%s", name, version)
	case "nuget":
		commands["dotnet"] = fmt.Sprintf("dotnet add package %s --version %s", name, version)
		commands["nuget"] = fmt.Sprintf("Install-Package %s -Version %s", name, version)
	case "crates.io", "cargo":
		commands["cargo"] = fmt.Sprintf("%s = \"%s\"", name, version)
	case "rubygems", "gem":
		commands["bundler"] = fmt.Sprintf("gem '%s', '%s'", name, version)
		commands["gem"] = fmt.Sprintf("gem install %s -v %s", name, version)
	}

	return commands
}

func extractSeverity(severities []client.OSVSeverity) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			// Parse CVSS score to severity
			return s.Score
		}
	}
	return "UNKNOWN"
}

func getKnownWorkarounds(cveID string) []Workaround {
	// Known workarounds for famous vulnerabilities
	workarounds := map[string][]Workaround{
		"CVE-2021-44228": { // Log4Shell
			{
				Description: "JndiLookup クラスを削除",
				Command:     "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
			},
			{
				Description: "システムプロパティで無効化",
				Command:     "-Dlog4j2.formatMsgNoLookups=true",
			},
			{
				Description: "環境変数で無効化",
				Command:     "LOG4J_FORMAT_MSG_NO_LOOKUPS=true",
			},
		},
		"CVE-2021-45046": { // Log4j 2.15.0 bypass
			{
				Description: "log4j2.noFormatMsgLookup を設定",
				Command:     "-Dlog4j2.noFormatMsgLookup=true",
			},
		},
		"CVE-2022-22965": { // Spring4Shell
			{
				Description: "disallowedFields を設定",
				Command:     "WebDataBinder.setDisallowedFields(\"class.*\", \"Class.*\", \"*.class.*\", \"*.Class.*\")",
			},
		},
	}

	if ws, ok := workarounds[cveID]; ok {
		return ws
	}
	return []Workaround{}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
