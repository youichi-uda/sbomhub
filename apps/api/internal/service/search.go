package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type SearchService struct {
	searchRepo *repository.SearchRepository
}

func NewSearchService(searchRepo *repository.SearchRepository) *SearchService {
	return &SearchService{searchRepo: searchRepo}
}

// SearchByCVE searches for all projects affected by a specific CVE
func (s *SearchService) SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error) {
	// Normalize CVE ID
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if !strings.HasPrefix(cveID, "CVE-") {
		return nil, fmt.Errorf("invalid CVE ID format: %s", cveID)
	}

	result, err := s.searchRepo.SearchByCVE(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to search CVE: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("CVE not found: %s", cveID)
	}

	return result, nil
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
