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

// Create creates a project with tenant isolation
func (s *ProjectService) Create(ctx context.Context, tenantID uuid.UUID, req model.CreateProjectRequest) (*model.Project, error) {
	project := &model.Project{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.repo.CreateWithTenant(ctx, tenantID, project); err != nil {
		return nil, err
	}

	return project, nil
}

// List lists projects for a specific tenant
func (s *ProjectService) List(ctx context.Context, tenantID uuid.UUID) ([]model.Project, error) {
	return s.repo.ListByTenant(ctx, tenantID)
}

// Get gets a project by ID with tenant verification
func (s *ProjectService) Get(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	return s.repo.GetByTenant(ctx, tenantID, projectID)
}

// Delete deletes a project with tenant verification
func (s *ProjectService) Delete(ctx context.Context, tenantID, projectID uuid.UUID) error {
	return s.repo.DeleteByTenant(ctx, tenantID, projectID)
}
