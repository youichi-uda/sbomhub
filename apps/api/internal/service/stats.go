package service

import (
	"context"

	"github.com/sbomhub/sbomhub/internal/repository"
)

type Stats struct {
	Projects        int `json:"projects"`
	Components      int `json:"components"`
	Vulnerabilities int `json:"vulnerabilities"`
}

type StatsService struct {
	statsRepo *repository.StatsRepository
}

func NewStatsService(sr *repository.StatsRepository) *StatsService {
	return &StatsService{statsRepo: sr}
}

func (s *StatsService) GetStats(ctx context.Context) (*Stats, error) {
	projects, err := s.statsRepo.CountProjects(ctx)
	if err != nil {
		return nil, err
	}

	components, err := s.statsRepo.CountComponents(ctx)
	if err != nil {
		return nil, err
	}

	vulnerabilities, err := s.statsRepo.CountVulnerabilities(ctx)
	if err != nil {
		return nil, err
	}

	return &Stats{
		Projects:        projects,
		Components:      components,
		Vulnerabilities: vulnerabilities,
	}, nil
}
