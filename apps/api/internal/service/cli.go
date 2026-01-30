package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// CLIService handles CLI-specific operations.
type CLIService struct {
	projectRepo   *repository.ProjectRepository
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
	httpClient    *http.Client
}

// NewCLIService creates a new CLIService.
func NewCLIService(
	pr *repository.ProjectRepository,
	sr *repository.SbomRepository,
	cr *repository.ComponentRepository,
) *CLIService {
	return &CLIService{
		projectRepo:   pr,
		sbomRepo:      sr,
		componentRepo: cr,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetOrCreateProject finds a project by name within a tenant, or creates it if not found.
func (s *CLIService) GetOrCreateProject(ctx context.Context, tenantID uuid.UUID, name, description string) (*model.Project, bool, error) {
	// Try to find existing project
	existing, err := s.projectRepo.GetByName(ctx, tenantID, name)
	if err != nil {
		return nil, false, fmt.Errorf("failed to search project: %w", err)
	}
	if existing != nil {
		return existing, false, nil // false = not created
	}

	// Create new project
	project := &model.Project{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.projectRepo.CreateWithTenant(ctx, tenantID, project); err != nil {
		return nil, false, fmt.Errorf("failed to create project: %w", err)
	}

	return project, true, nil // true = created
}

// UploadSBOM imports an SBOM for a project via CLI.
func (s *CLIService) UploadSBOM(ctx context.Context, projectID uuid.UUID, data []byte) (*model.Sbom, int, error) {
	format, err := detectFormat(data)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	sbom := &model.Sbom{
		ID:        uuid.New(),
		ProjectID: projectID,
		Format:    string(format),
		RawData:   data,
		CreatedAt: time.Now(),
	}

	if err := s.sbomRepo.Create(ctx, sbom); err != nil {
		return nil, 0, fmt.Errorf("failed to save SBOM: %w", err)
	}

	components, err := parseComponents(data, format)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse components: %w", err)
	}

	for _, comp := range components {
		comp.SbomID = sbom.ID
		if err := s.componentRepo.Create(ctx, &comp); err != nil {
			return nil, 0, fmt.Errorf("failed to save component: %w", err)
		}
	}

	return sbom, len(components), nil
}

// CLIVulnerabilityResult represents the result of a vulnerability check for CLI output.
type CLIVulnerabilityResult struct {
	TotalComponents int                     `json:"total_components"`
	TotalVulns      int                     `json:"total_vulnerabilities"`
	BySeverity      map[string]int          `json:"by_severity"`
	Vulnerabilities []CLIVulnerabilityEntry `json:"vulnerabilities"`
}

// CLIVulnerabilityEntry represents a single vulnerability entry for CLI output.
type CLIVulnerabilityEntry struct {
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	Purl        string   `json:"purl,omitempty"`
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary,omitempty"`
	FixedIn     string   `json:"fixed_in,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
	References  []string `json:"references,omitempty"`
}

// OSV API types
type osvQuery struct {
	Queries []osvQueryItem `json:"queries"`
}

type osvQueryItem struct {
	Package osvPackage `json:"package,omitempty"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl,omitempty"`
}

type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns,omitempty"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Summary    string         `json:"summary"`
	Severity   []osvSeverity  `json:"severity,omitempty"`
	Affected   []osvAffected  `json:"affected,omitempty"`
	Aliases    []string       `json:"aliases,omitempty"`
	References []osvReference `json:"references,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvPackage  `json:"package"`
	Ranges  []osvRange  `json:"ranges,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events,omitempty"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CheckVulnerabilitiesRequest represents the request body for vulnerability check.
type CheckVulnerabilitiesRequest struct {
	Components []CLIComponentInput `json:"components"`
}

// CLIComponentInput represents a component input for vulnerability check.
type CLIComponentInput struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// CheckVulnerabilities checks vulnerabilities using OSV API.
func (s *CLIService) CheckVulnerabilities(ctx context.Context, components []CLIComponentInput) (*CLIVulnerabilityResult, error) {
	if len(components) == 0 {
		return &CLIVulnerabilityResult{
			TotalComponents: 0,
			TotalVulns:      0,
			BySeverity:      map[string]int{},
			Vulnerabilities: []CLIVulnerabilityEntry{},
		}, nil
	}

	// Build OSV batch query
	queries := make([]osvQueryItem, 0, len(components))
	componentMap := make(map[int]CLIComponentInput)

	for i, comp := range components {
		componentMap[i] = comp

		query := osvQueryItem{}
		if comp.Purl != "" {
			query.Package = osvPackage{Purl: comp.Purl}
			query.Version = comp.Version
		} else if comp.Ecosystem != "" {
			query.Package = osvPackage{
				Name:      comp.Name,
				Ecosystem: comp.Ecosystem,
			}
			query.Version = comp.Version
		} else {
			// Skip components without ecosystem or purl
			continue
		}
		queries = append(queries, query)
	}

	if len(queries) == 0 {
		return &CLIVulnerabilityResult{
			TotalComponents: len(components),
			TotalVulns:      0,
			BySeverity:      map[string]int{},
			Vulnerabilities: []CLIVulnerabilityEntry{},
		}, nil
	}

	// Call OSV API
	reqBody := osvQuery{Queries: queries}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSV request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/querybatch", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create OSV request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(body))
	}

	var osvResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode OSV response: %w", err)
	}

	// Process results
	result := &CLIVulnerabilityResult{
		TotalComponents: len(components),
		BySeverity: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"UNKNOWN":  0,
		},
		Vulnerabilities: []CLIVulnerabilityEntry{},
	}

	seenVulns := make(map[string]bool)

	for i, r := range osvResp.Results {
		if i >= len(components) {
			break
		}
		comp := components[i]

		for _, v := range r.Vulns {
			// Deduplicate by vuln ID + package
			key := fmt.Sprintf("%s:%s:%s", v.ID, comp.Name, comp.Version)
			if seenVulns[key] {
				continue
			}
			seenVulns[key] = true

			severity := cliExtractSeverity(v)
			fixedIn := cliExtractFixedVersion(v, comp.Name)
			refs := cliExtractReferences(v)

			entry := CLIVulnerabilityEntry{
				Package:    comp.Name,
				Version:    comp.Version,
				Purl:       comp.Purl,
				ID:         v.ID,
				Severity:   severity,
				Summary:    v.Summary,
				FixedIn:    fixedIn,
				Aliases:    v.Aliases,
				References: refs,
			}

			result.Vulnerabilities = append(result.Vulnerabilities, entry)
			result.BySeverity[severity]++
		}
	}

	result.TotalVulns = len(result.Vulnerabilities)

	return result, nil
}

func cliExtractSeverity(v osvVuln) string {
	for _, sev := range v.Severity {
		if sev.Type == "CVSS_V3" {
			score := cliParseCVSSScore(sev.Score)
			if score >= 9.0 {
				return "CRITICAL"
			} else if score >= 7.0 {
				return "HIGH"
			} else if score >= 4.0 {
				return "MEDIUM"
			} else if score > 0 {
				return "LOW"
			}
		}
	}
	return "UNKNOWN"
}

func cliParseCVSSScore(score string) float64 {
	var f float64
	fmt.Sscanf(score, "%f", &f)
	return f
}

func cliExtractFixedVersion(v osvVuln, pkgName string) string {
	for _, affected := range v.Affected {
		if affected.Package.Name == pkgName || affected.Package.Purl != "" {
			for _, r := range affected.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	return ""
}

func cliExtractReferences(v osvVuln) []string {
	refs := make([]string, 0, len(v.References))
	for _, r := range v.References {
		refs = append(refs, r.URL)
	}
	return refs
}

// ListProjects lists projects for a tenant.
func (s *CLIService) ListProjects(ctx context.Context, tenantID uuid.UUID) ([]model.Project, error) {
	return s.projectRepo.ListByTenant(ctx, tenantID)
}

// GetProject gets a project by ID, verifying it belongs to the tenant.
func (s *CLIService) GetProject(ctx context.Context, tenantID uuid.UUID, projectID uuid.UUID) (*model.Project, error) {
	// Get project
	project, err := s.projectRepo.Get(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// Verify tenant ownership
	projectTenantID, err := s.projectRepo.GetTenantID(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if projectTenantID != tenantID {
		return nil, fmt.Errorf("project not found")
	}

	return project, nil
}
