package service

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type SbomDiffService struct {
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
}

func NewSbomDiffService(sr *repository.SbomRepository, cr *repository.ComponentRepository) *SbomDiffService {
	return &SbomDiffService{
		sbomRepo:      sr,
		componentRepo: cr,
	}
}

type SbomDiffRequest struct {
	BaseSbomID   uuid.UUID
	TargetSbomID uuid.UUID
}

func (s *SbomDiffService) Diff(ctx context.Context, req SbomDiffRequest) (*model.SbomDiffResponse, error) {
	baseSbom, err := s.sbomRepo.GetByID(ctx, req.BaseSbomID)
	if err != nil {
		return nil, fmt.Errorf("base sbom not found: %w", err)
	}
	targetSbom, err := s.sbomRepo.GetByID(ctx, req.TargetSbomID)
	if err != nil {
		return nil, fmt.Errorf("target sbom not found: %w", err)
	}
	if baseSbom.ProjectID != targetSbom.ProjectID {
		return nil, fmt.Errorf("sbom project mismatch")
	}

	baseComponents, err := s.componentRepo.ListBySbom(ctx, baseSbom.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load base components: %w", err)
	}
	targetComponents, err := s.componentRepo.ListBySbom(ctx, targetSbom.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load target components: %w", err)
	}

	baseMap := map[string]model.Component{}
	targetMap := map[string]model.Component{}
	baseByName := map[string]model.Component{}
	targetByName := map[string]model.Component{}

	for _, c := range baseComponents {
		key := componentKey(c)
		baseMap[key] = c
		baseByName[componentNameKey(c.Name)] = c
	}
	for _, c := range targetComponents {
		key := componentKey(c)
		targetMap[key] = c
		targetByName[componentNameKey(c.Name)] = c
	}

	added := make([]model.SbomDiffComponent, 0)
	removed := make([]model.SbomDiffComponent, 0)
	updated := make([]model.SbomDiffUpdated, 0)

	for key, c := range targetMap {
		if _, ok := baseMap[key]; ok {
			continue
		}
		added = append(added, diffComponent(c))
	}

	for key, c := range baseMap {
		if _, ok := targetMap[key]; ok {
			continue
		}
		removed = append(removed, diffComponent(c))
	}

	for nameKey, baseComp := range baseByName {
		targetComp, ok := targetByName[nameKey]
		if !ok {
			continue
		}
		if strings.TrimSpace(baseComp.Version) == strings.TrimSpace(targetComp.Version) {
			continue
		}
		updated = append(updated, model.SbomDiffUpdated{
			Name:       baseComp.Name,
			OldVersion: baseComp.Version,
			NewVersion: targetComp.Version,
		})
	}

	newVulns, err := s.diffNewVulnerabilities(ctx, baseSbom.ID, targetSbom.ID)
	if err != nil {
		return nil, err
	}
	if newVulns == nil {
		newVulns = make([]model.SbomDiffVulnerability, 0)
	}

	resp := &model.SbomDiffResponse{
		Summary: model.SbomDiffSummary{
			AddedCount:              len(added),
			RemovedCount:            len(removed),
			UpdatedCount:            len(updated),
			NewVulnerabilitiesCount: len(newVulns),
		},
		Added:             added,
		Removed:           removed,
		Updated:           updated,
		NewVulnerabilities: newVulns,
	}

	return resp, nil
}

func (s *SbomDiffService) diffNewVulnerabilities(ctx context.Context, baseSbomID, targetSbomID uuid.UUID) ([]model.SbomDiffVulnerability, error) {
	baseVulns, err := s.componentRepo.ListComponentVulnerabilitiesBySbom(ctx, baseSbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to load base vulnerabilities: %w", err)
	}
	targetVulns, err := s.componentRepo.ListComponentVulnerabilitiesBySbom(ctx, targetSbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to load target vulnerabilities: %w", err)
	}

	baseSet := map[string]struct{}{}
	for _, v := range baseVulns {
		baseSet[strings.ToUpper(v.CVEID)] = struct{}{}
	}

	seen := map[string]struct{}{}
	var newVulns []model.SbomDiffVulnerability
	for _, v := range targetVulns {
		cveKey := strings.ToUpper(v.CVEID)
		if _, ok := baseSet[cveKey]; ok {
			continue
		}
		dedupeKey := cveKey + ":" + componentNameKey(v.ComponentName) + ":" + strings.TrimSpace(v.ComponentVersion)
		if _, ok := seen[dedupeKey]; ok {
			continue
		}
		seen[dedupeKey] = struct{}{}
		newVulns = append(newVulns, model.SbomDiffVulnerability{
			CVEID:     v.CVEID,
			Severity:  v.Severity,
			Component: v.ComponentName,
			Version:   v.ComponentVersion,
		})
	}
	return newVulns, nil
}

func diffComponent(c model.Component) model.SbomDiffComponent {
	return model.SbomDiffComponent{
		Name:    c.Name,
		Version: c.Version,
		License: c.License,
	}
}

func componentKey(c model.Component) string {
	if strings.TrimSpace(c.Purl) != "" {
		return normalizePurl(c.Purl)
	}
	return componentNameKey(c.Name) + ":" + strings.TrimSpace(c.Version)
}

var spaceRegex = regexp.MustCompile(`[^a-z0-9]+`)

func componentNameKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = spaceRegex.ReplaceAllString(name, " ")
	return strings.TrimSpace(name)
}

func normalizePurl(purl string) string {
	purl = strings.TrimSpace(strings.ToLower(purl))
	if purl == "" {
		return purl
	}
	if at := strings.Index(purl, "@"); at > 0 {
		return purl[:at]
	}
	return purl
}
