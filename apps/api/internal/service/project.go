package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type ProjectService struct {
	repo *repository.ProjectRepository
}

func NewProjectService(repo *repository.ProjectRepository) *ProjectService {
	return &ProjectService{repo: repo}
}

func (s *ProjectService) Create(ctx context.Context, req model.CreateProjectRequest) (*model.Project, error) {
	project := &model.Project{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.Create(ctx, project); err != nil {
		return nil, err
	}

	return project, nil
}

func (s *ProjectService) List(ctx context.Context) ([]model.Project, error) {
	return s.repo.List(ctx)
}

func (s *ProjectService) Get(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	return s.repo.Get(ctx, id)
}

func (s *ProjectService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}
