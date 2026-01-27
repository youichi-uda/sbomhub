package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type SbomService struct {
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
}

func NewSbomService(sr *repository.SbomRepository, cr *repository.ComponentRepository) *SbomService {
	return &SbomService{sbomRepo: sr, componentRepo: cr}
}

func (s *SbomService) Import(ctx context.Context, projectID uuid.UUID, data []byte) (*model.Sbom, error) {
	format, err := detectFormat(data)
	if err != nil {
		return nil, fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	sbom := &model.Sbom{
		ID:        uuid.New(),
		ProjectID: projectID,
		Format:    string(format),
		RawData:   data,
		CreatedAt: time.Now(),
	}

	if err := s.sbomRepo.Create(ctx, sbom); err != nil {
		return nil, fmt.Errorf("failed to save SBOM: %w", err)
	}

	components, err := parseComponents(data, format)
	if err != nil {
		return nil, fmt.Errorf("failed to parse components: %w", err)
	}

	for _, comp := range components {
		comp.SbomID = sbom.ID
		if err := s.componentRepo.Create(ctx, &comp); err != nil {
			return nil, fmt.Errorf("failed to save component: %w", err)
		}
	}

	return sbom, nil
}

func (s *SbomService) GetLatest(ctx context.Context, projectID uuid.UUID) (*model.Sbom, error) {
	return s.sbomRepo.GetLatest(ctx, projectID)
}

func (s *SbomService) ListByProject(ctx context.Context, projectID uuid.UUID) ([]model.Sbom, error) {
	return s.sbomRepo.ListByProject(ctx, projectID)
}

func (s *SbomService) GetComponents(ctx context.Context, projectID uuid.UUID) ([]model.Component, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Component{}, nil
		}
		return nil, err
	}
	return s.componentRepo.ListBySbom(ctx, sbom.ID)
}

func (s *SbomService) GetVulnerabilities(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	sbom, err := s.sbomRepo.GetLatest(ctx, projectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []model.Vulnerability{}, nil
		}
		return nil, err
	}
	return s.componentRepo.GetVulnerabilities(ctx, sbom.ID)
}

func detectFormat(data []byte) (model.SbomFormat, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	if _, ok := raw["bomFormat"]; ok {
		return model.FormatCycloneDX, nil
	}
	if _, ok := raw["spdxVersion"]; ok {
		return model.FormatSPDX, nil
	}

	return "", fmt.Errorf("unknown SBOM format")
}

func parseComponents(data []byte, format model.SbomFormat) ([]model.Component, error) {
	switch format {
	case model.FormatCycloneDX:
		return parseCycloneDX(data)
	case model.FormatSPDX:
		return parseSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func parseCycloneDX(data []byte) ([]model.Component, error) {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	var components []model.Component
	if bom.Components != nil {
		for _, c := range *bom.Components {
			comp := model.Component{
				ID:        uuid.New(),
				Name:      c.Name,
				Version:   c.Version,
				Type:      string(c.Type),
				CreatedAt: time.Now(),
			}
			if c.PackageURL != "" {
				comp.Purl = c.PackageURL
			}
			if c.Licenses != nil && len(*c.Licenses) > 0 {
				for _, lic := range *c.Licenses {
					if lic.License != nil && lic.License.ID != "" {
						comp.License = lic.License.ID
						break
					}
				}
			}
			components = append(components, comp)
		}
	}

	return components, nil
}

func parseSPDX(data []byte) ([]model.Component, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	var components []model.Component
	if packages, ok := raw["packages"].([]interface{}); ok {
		for _, pkg := range packages {
			if p, ok := pkg.(map[string]interface{}); ok {
				comp := model.Component{
					ID:        uuid.New(),
					Name:      getString(p, "name"),
					Version:   getString(p, "versionInfo"),
					Type:      "library",
					CreatedAt: time.Now(),
				}
				if purl := getString(p, "externalRefs"); purl != "" {
					comp.Purl = purl
				}
				components = append(components, comp)
			}
		}
	}

	return components, nil
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
