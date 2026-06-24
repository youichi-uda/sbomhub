package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type PublicLinkService struct {
	linkRepo      *repository.PublicLinkRepository
	projectRepo   *repository.ProjectRepository
	sbomRepo      *repository.SbomRepository
	componentRepo *repository.ComponentRepository
	// db is the raw *sql.DB used to open tenant-scoped transactions for the
	// anonymous public-link content flow (PublicGet / PublicDownload).
	//
	// Why this exists (codex-r7 P1):
	//   public_links itself had RLS removed in migration 030 (codex-r5-5a) so
	//   the anonymous /public/:token route can resolve a token without
	//   tenant middleware. But the *content* the link points at —
	//   projects / sboms / components — is still RLS-enabled. Without
	//   pinning app.current_tenant_id to the tenant carried by the resolved
	//   link, the follow-up reads inside GetPublicView /
	//   GetPublicSbomRaw match zero rows and the share link returns an
	//   empty view (or download fails). We open our own tx here, set the
	//   GUC with `is_local=true`, and run the content reads inside it.
	db *sql.DB
}

func NewPublicLinkService(
	db *sql.DB,
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
		db:            db,
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

// GetPublicView resolves the share token anonymously, then loads the
// project / sbom / components inside a tenant-scoped tx so the RLS on
// those tables sees the right tenant. The token lookup itself runs
// outside the tx — public_links has RLS removed (migration 030) so the
// anonymous /public/:token route can find the row without tenant context.
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

	var view *model.PublicSbomView
	if err := s.runWithTenantTx(ctx, link.TenantID, func(txCtx context.Context) error {
		project, err := s.projectRepo.Get(txCtx, link.ProjectID)
		if err != nil {
			return err
		}

		var sbom *model.Sbom
		if link.SbomID != nil {
			sbom, err = s.sbomRepo.GetByID(txCtx, *link.SbomID)
		} else {
			sbom, err = s.sbomRepo.GetLatest(txCtx, link.ProjectID)
		}
		if err != nil {
			return err
		}

		components, err := s.componentRepo.ListBySbom(txCtx, sbom.ID)
		if err != nil {
			return err
		}

		view = &model.PublicSbomView{
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
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return view, link, nil
}

// GetPublicSbomRaw mirrors GetPublicView for the download flow: token
// lookup outside the tx, sbom read inside a tenant-scoped tx so RLS on
// the sboms table sees the right tenant id.
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

	var raw []byte
	if err := s.runWithTenantTx(ctx, link.TenantID, func(txCtx context.Context) error {
		var sbom *model.Sbom
		var ferr error
		if link.SbomID != nil {
			sbom, ferr = s.sbomRepo.GetByID(txCtx, *link.SbomID)
		} else {
			sbom, ferr = s.sbomRepo.GetLatest(txCtx, link.ProjectID)
		}
		if ferr != nil {
			return ferr
		}
		raw = sbom.RawData
		return nil
	}); err != nil {
		return nil, nil, err
	}

	return raw, link, nil
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

// runWithTenantTx opens a fresh transaction on s.db, pins
// `app.current_tenant_id` to tenantID for the duration of that tx, and
// runs fn with a ctx that carries the tx via database.WithTx.
//
// This mirrors ReportService.runWithTenantTx — the two could be unified
// later, but keeping a private copy here keeps the codex-r7 fix
// scope-local and avoids churning files in the "DO NOT touch" set.
//
// `is_local=true` scopes the GUC to the transaction only, so once the tx
// commits or rolls back the pooled connection returns with no tenant
// residue.
func (s *PublicLinkService) runWithTenantTx(ctx context.Context, tenantID uuid.UUID, fn func(txCtx context.Context) error) error {
	if s.db == nil {
		return fmt.Errorf("public link service: db handle is nil; cannot open tenant-scoped tx")
	}
	return database.WithTxFunc(ctx, s.db, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(
			txCtx,
			`SELECT set_config('app.current_tenant_id', $1, true)`,
			tenantID.String(),
		); err != nil {
			return fmt.Errorf("set tenant context for %s: %w", tenantID, err)
		}
		return fn(txCtx)
	})
}

func generateToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
