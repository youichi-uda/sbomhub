package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// ListForKeyProject lists the projects a project-scoped API key may enumerate:
// its own project, and only that one. See listProjectsForKeyProject.
func (s *ProjectService) ListForKeyProject(ctx context.Context, tenantID, keyProjectID uuid.UUID) ([]model.Project, error) {
	return listProjectsForKeyProject(ctx, s.repo, tenantID, keyProjectID)
}

// listProjectsForKeyProject is the M50 W3 narrowed answer shared by
// ProjectService.ListForKeyProject and CLIService.ListForKeyProject, so the two
// project-list routes cannot drift apart in what a project-scoped key sees.
//
// Guarantees, and only these:
//
//   - It reads through repository.ProjectRepository.GetByTenant. That is a
//     DIFFERENT statement from ListByTenant — different WHERE clause, no ORDER
//     BY — with an IDENTICAL projection, five columns and not tenant_id, so a
//     row reaches the wire with the same JSON fields either way. The claim is
//     about the projection only, and it is checked as behaviour rather than
//     trusted: TestM50W3NarrowedRowIsTheSameRowAsTheTenantWideOne marshals the
//     same project from both paths against a live database and requires the
//     bytes to be equal. (The earlier wording here said "the SAME query … plus
//     an id predicate", which was not true — Codex R1.)
//
//   - `tenantID` is the tenant the REQUEST authenticated as, never a tenant
//     derived from keyProjectID. A key whose project_id names another tenant's
//     project (possible for rows minted before M47 W1) matches nothing and gets
//     an empty list, not that project.
//
//   - Not-found is an empty list and a nil error, because "no projects" is then
//     the true answer. Every OTHER error is returned, so a database fault is a
//     500 rather than a silent "you have no projects".
//
//     Which production state reaches that branch is narrower than it looks.
//     DELETING the project does not: `api_keys_project_id_fkey` is
//     `REFERENCES projects(id) ON DELETE CASCADE` (migration 005, still the
//     live definition — read off pg_constraint on 2026-07-30), so deleting a
//     project deletes its project-scoped keys and the key is answered 401 by
//     ValidateKey before any of this runs (observed against a live server:
//     `{"error":"invalid API key"}`, and `sbomhub doctor` correctly reports
//     `認証失敗 (401) — api_key が無効・失効しています`). What DOES reach it is
//     the M50 W2 residual: a row whose project_id names a project of ANOTHER
//     tenant, mintable before M47 W1 added the ownership check, because the
//     foreign key is on `projects(id)` alone and not on (tenant_id, id).
//
//   - The empty result is a non-nil zero-length slice, so it serialises as `[]`
//     rather than `null` (TestM50W3EmptyNarrowedListIsAnArrayNotNull). The
//     tenant-wide path is left alone and still answers `null` when a tenant has
//     no projects; that shape predates this wave and is shared with the
//     Clerk-facing GET /api/v1/projects.
//
// It does NOT verify that the key's project_id was ever LEGITIMATE — that
// api_keys.project_id names a project of api_keys.tenant_id — nor that the
// caller may read the project's contents.
//
// Nothing at request time does verify legitimacy. ValidateKey checks that the
// key exists and has not expired, and the route table
// (middleware.apiKeyRouteScope) compares the key's project against the one the
// REQUEST names — which is a real boundary, and the one scopeProjectPathParam
// enforces — but neither asks whether the key's own project_id was ever a
// project of the key's own tenant. That check exists only on the MINT route
// (M47 W1), which is why rows minted before it can still name another tenant's
// project. What this function guarantees for such a row is only that it
// resolves to nothing, which the tenant predicate above gives for free.
func listProjectsForKeyProject(
	ctx context.Context, repo *repository.ProjectRepository, tenantID, keyProjectID uuid.UUID,
) ([]model.Project, error) {
	project, err := repo.GetByTenant(ctx, tenantID, keyProjectID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return []model.Project{}, nil
	case err != nil:
		return nil, fmt.Errorf("failed to load the api key's project: %w", err)
	}
	return []model.Project{*project}, nil
}

// Get gets a project by ID with tenant verification
func (s *ProjectService) Get(ctx context.Context, tenantID, projectID uuid.UUID) (*model.Project, error) {
	return s.repo.GetByTenant(ctx, tenantID, projectID)
}

// Delete deletes a project with tenant verification
func (s *ProjectService) Delete(ctx context.Context, tenantID, projectID uuid.UUID) error {
	return s.repo.DeleteByTenant(ctx, tenantID, projectID)
}
