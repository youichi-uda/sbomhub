package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type PublicLinkService struct {
	linkRepo      *repository.PublicLinkRepository
	projectRepo   *repository.ProjectRepository
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
}

func NewPublicLinkService(
	linkRepo *repository.PublicLinkRepository,
	projectRepo *repository.ProjectRepository,
	sbomRepo *repository.SbomRepository,
	componentRepo *repository.ComponentRepository,
) *PublicLinkService {
	return &PublicLinkService{
		linkRepo:      linkRepo,
		projectRepo:   projectRepo,
		sbomRepo:      sbomRepo,
		componentRepo: componentRepo,
	}
}

type CreatePublicLinkInput struct {
	TenantID         uuid.UUID
	ProjectID        uuid.UUID
	Name             string
	SbomID           *uuid.UUID
	ExpiresAt        time.Time
	IsActive         bool
	AllowedDownloads *int
	Password         string
}

type UpdatePublicLinkInput struct {
	Name             string
	SbomID           *uuid.UUID
	ExpiresAt        time.Time
	IsActive         bool
	AllowedDownloads *int
	Password         *string
}

func (s *PublicLinkService) Create(ctx context.Context, input CreatePublicLinkInput) (*model.PublicLink, error) {
	if input.Name == "" {
		return nil, errors.New("name is required")
	}
	token, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	var passwordHash *string
	if input.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		hashStr := string(hash)
		passwordHash = &hashStr
	}

	now := time.Now()
	link := &model.PublicLink{
		ID:               uuid.New(),
		TenantID:         input.TenantID,
		ProjectID:        input.ProjectID,
		SbomID:           input.SbomID,
		Token:            token,
		Name:             input.Name,
		ExpiresAt:        input.ExpiresAt,
		IsActive:         input.IsActive,
		AllowedDownloads: input.AllowedDownloads,
		PasswordHash:     passwordHash,
		ViewCount:        0,
		DownloadCount:    0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.linkRepo.Create(ctx, link); err != nil {
		return nil, err
	}
	return link, nil
}

// ListByProject is the dashboard list view. tenantID MUST come from the
// authenticated session middleware — see PublicLinkRepository.ListByProject
// for the load-bearing tenant filter rationale.
func (s *PublicLinkService) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.PublicLink, error) {
	return s.linkRepo.ListByProject(ctx, tenantID, projectID)
}

// Update applies dashboard-side edits to a public link. tenantID MUST come
// from the authenticated session middleware.
func (s *PublicLinkService) Update(ctx context.Context, tenantID, id uuid.UUID, input UpdatePublicLinkInput) (*model.PublicLink, error) {
	link, err := s.linkRepo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return nil, errors.New("public link not found")
	}

	link.Name = input.Name
	link.SbomID = input.SbomID
	link.ExpiresAt = input.ExpiresAt
	link.IsActive = input.IsActive
	link.AllowedDownloads = input.AllowedDownloads

	if input.Password != nil {
		if *input.Password == "" {
			link.PasswordHash = nil
		} else {
			hash, err := bcrypt.GenerateFromPassword([]byte(*input.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			hashStr := string(hash)
			link.PasswordHash = &hashStr
		}
	}

	link.UpdatedAt = time.Now()
	if err := s.linkRepo.Update(ctx, tenantID, link); err != nil {
		return nil, err
	}
	return link, nil
}

// Delete removes a public link restricted to the authenticated tenant.
func (s *PublicLinkService) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.linkRepo.Delete(ctx, tenantID, id)
}

func (s *PublicLinkService) GetPublicView(ctx context.Context, token string, password string) (*model.PublicSbomView, *model.PublicLink, error) {
	link, err := s.linkRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if link == nil {
		return nil, nil, errors.New("link not found")
	}
	if !link.IsActive {
		return nil, nil, errors.New("link inactive")
	}
	if time.Now().After(link.ExpiresAt) {
		return nil, nil, errors.New("link expired")
	}
	if link.PasswordHash != nil {
		if password == "" {
			return nil, nil, errors.New("password required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*link.PasswordHash), []byte(password)); err != nil {
			return nil, nil, errors.New("invalid password")
		}
	}

	project, err := s.projectRepo.Get(ctx, link.ProjectID)
	if err != nil {
		return nil, nil, err
	}

	var sbom *model.Sbom
	if link.SbomID != nil {
		sbom, err = s.sbomRepo.GetByID(ctx, *link.SbomID)
	} else {
		sbom, err = s.sbomRepo.GetLatest(ctx, link.ProjectID)
	}
	if err != nil {
		return nil, nil, err
	}

	components, err := s.componentRepo.ListBySbom(ctx, sbom.ID)
	if err != nil {
		return nil, nil, err
	}

	view := &model.PublicSbomView{
		ProjectName: project.Name,
		Sbom:        *sbom,
		Components:  components,
		Link: model.PublicLinkMeta{
			Name:          link.Name,
			ExpiresAt:     link.ExpiresAt,
			ViewCount:     link.ViewCount,
			DownloadCount: link.DownloadCount,
		},
	}

	return view, link, nil
}

func (s *PublicLinkService) GetPublicSbomRaw(ctx context.Context, token string, password string) ([]byte, *model.PublicLink, error) {
	link, err := s.linkRepo.GetByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if link == nil {
		return nil, nil, errors.New("link not found")
	}
	if !link.IsActive {
		return nil, nil, errors.New("link inactive")
	}
	if time.Now().After(link.ExpiresAt) {
		return nil, nil, errors.New("link expired")
	}
	if link.PasswordHash != nil {
		if password == "" {
			return nil, nil, errors.New("password required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*link.PasswordHash), []byte(password)); err != nil {
			return nil, nil, errors.New("invalid password")
		}
	}

	var sbom *model.Sbom
	if link.SbomID != nil {
		sbom, err = s.sbomRepo.GetByID(ctx, *link.SbomID)
	} else {
		sbom, err = s.sbomRepo.GetLatest(ctx, link.ProjectID)
	}
	if err != nil {
		return nil, nil, err
	}

	return sbom.RawData, link, nil
}

func (s *PublicLinkService) LogAccess(ctx context.Context, linkID uuid.UUID, action, ip, userAgent string) error {
	log := &model.PublicLinkAccessLog{
		ID:           uuid.New(),
		PublicLinkID: linkID,
		Action:       action,
		IPAddress:    ip,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
	}
	return s.linkRepo.CreateAccessLog(ctx, log)
}

// IsDownloadLimitReached is invoked from the anonymous public-download
// flow; the caller passes the tenant id derived from the link returned by
// GetByToken, so the repository-level tenant filter is satisfied without
// requiring tenant middleware on the route.
func (s *PublicLinkService) IsDownloadLimitReached(ctx context.Context, tenantID, linkID uuid.UUID) (bool, error) {
	return s.linkRepo.IsDownloadLimitReached(ctx, tenantID, linkID)
}

// IncrementView / IncrementDownload run after a successful token lookup.
// The link's own TenantID is what the caller passes here — see
// handler.PublicLinkHandler.PublicGet / PublicDownload.
func (s *PublicLinkService) IncrementView(ctx context.Context, tenantID, linkID uuid.UUID) error {
	return s.linkRepo.IncrementView(ctx, tenantID, linkID)
}

func (s *PublicLinkService) IncrementDownload(ctx context.Context, tenantID, linkID uuid.UUID) error {
	return s.linkRepo.IncrementDownload(ctx, tenantID, linkID)
}

func generateToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
