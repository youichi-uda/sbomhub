package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/sbomhub/sbomhub/internal/model"
)

// Sentinel errors returned by SearchByCVE so the handler can map them to
// the right HTTP status with errors.Is, instead of matching on error
// strings or leaking the raw (possibly DB-internal) message to the client.
var (
	// ErrInvalidCVEID is returned when the query is not a well-formed CVE
	// ID. The handler maps it to 400.
	ErrInvalidCVEID = errors.New("search: invalid cve id")
	// ErrCVENotFound is returned when the CVE is not in the local DB and no
	// NVD fallback resolves it. The handler maps it to 404.
	ErrCVENotFound = errors.New("search: cve not found")
)

// searchRepoAPI is the subset of *repository.SearchRepository that
// SearchService uses. Declared as an interface so search_test.go can
// substitute a fake that returns a canned result / a local miss without a
// real DB. The concrete *repository.SearchRepository satisfies it, so the
// cmd/server/main.go wiring is unchanged.
type searchRepoAPI interface {
	SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error)
	SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error)
}

// nvdLookupAPI is the subset of *NVDService that SearchService uses for the
// NVD fallback. An interface so tests can inject an operational error or a
// successful-but-empty result. The concrete *NVDService satisfies it.
type nvdLookupAPI interface {
	SearchByCVEID(ctx context.Context, cveID string) (*model.Vulnerability, error)
	SaveVulnerability(ctx context.Context, vuln *model.Vulnerability) error
}

type SearchService struct {
	searchRepo searchRepoAPI
	nvdService nvdLookupAPI
}

func NewSearchService(searchRepo searchRepoAPI) *SearchService {
	return &SearchService{searchRepo: searchRepo}
}

// NewSearchServiceWithNVD creates a SearchService with NVD fallback support
func NewSearchServiceWithNVD(searchRepo searchRepoAPI, nvdService nvdLookupAPI) *SearchService {
	return &SearchService{
		searchRepo: searchRepo,
		nvdService: nvdService,
	}
}

// SearchByCVE searches for all projects affected by a specific CVE
// Uses hybrid approach: local DB first, then NVD API fallback
func (s *SearchService) SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error) {
	// Normalize CVE ID
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCVEID, cveID)
	}

	// Try local database first
	result, err := s.searchRepo.SearchByCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVE: %w", err)
	}
	if result != nil {
		return result, nil
	}

	// Fallback to NVD API if available
	if s.nvdService != nil {
		slog.Info("CVE not in local DB, fetching from NVD", "cve_id", cveID)
		vuln, err := s.nvdService.SearchByCVEID(ctx, cveID)
		if err != nil {
			slog.Warn("NVD API search failed", "cve_id", cveID, "error", err)
			// An NVD operational failure (timeout / rate-limit / 5xx /
			// decode error) is NOT evidence the CVE is absent. Return a
			// non-sentinel error so the handler's default path yields a
			// generic 500 instead of falsely claiming 404 "CVE not found".
			return nil, fmt.Errorf("nvd lookup failed for %s: %w", cveID, err)
		}
		if vuln == nil {
			return nil, fmt.Errorf("%w: %s", ErrCVENotFound, cveID)
		}

		// Save to local DB for future queries
		if err := s.nvdService.SaveVulnerability(ctx, vuln); err != nil {
			slog.Warn("failed to cache CVE in local DB", "cve_id", cveID, "error", err)
		}

		// Return CVE info (no affected projects since we just fetched it)
		return &model.CVESearchResult{
			CVEID:              vuln.CVEID,
			Description:        vuln.Description,
			Severity:           vuln.Severity,
			CVSSScore:          vuln.CVSSScore,
			EPSSScore:          0,
			AffectedProjects:   []model.AffectedProject{},
			UnaffectedProjects: []model.UnaffectedProject{},
		}, nil
	}

	// Genuine not-found (no NVD fallback wired and the CVE is not in the
	// local DB). Wrap the sentinel like the other not-found sites so the
	// handler maps it to 404 rather than a generic 500.
	return nil, fmt.Errorf("%w: %s", ErrCVENotFound, cveID)
}

// SearchByComponent searches for components by name and optional version constraint
func (s *SearchService) SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("component name is required")
	}

	result, err := s.searchRepo.SearchByComponent(ctx, name, versionConstraint)
	if err != nil {
		return nil, fmt.Errorf("failed to search component: %w", err)
	}

	return result, nil
}
