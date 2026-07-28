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

// ErrPublicLinkSbomNotInProject is returned by Create / Update when the
// caller-supplied `sbom_id` does not name an SBOM of the link's own
// (tenant, project) — M47 W1.
//
// Why this is a real hole and not a formality: `public_links.sbom_id` is a
// bare single-column FK to `sboms(id)` and `public_links` itself has NO row
// level security (migration 030 removed it so the anonymous /public/:token
// route can resolve a token without tenant middleware). Nothing anywhere
// bound the pinned SBOM to the project the link claims to publish. A member
// of the tenant could therefore create — or silently repoint, via
// PUT /public-links/:id — a share link whose header names project Y while the
// bytes it serves anonymously (and the component inventory it renders) come
// from project X. GetPublicView/GetPublicSbomRaw re-open the tx as
// link.TenantID, so RLS on `sboms` stopped the CROSS-TENANT variant from
// rendering, but (a) it never stopped the row from being written and (b) it
// does nothing at all for the cross-project-within-tenant variant, which is
// the one that actually leaks an unrelated project's SBOM to the public
// internet.
//
// Unknown / foreign / other-project sbom ids all collapse into this ONE
// sentinel, which the handler maps to 404 — the one-sentinel discipline, so a
// share-link form cannot be used to probe for SBOM UUIDs.
var ErrPublicLinkSbomNotInProject = errors.New("sbom does not belong to this project")

// ErrPublicLinkNotFound is returned by Update when the link id does not
// resolve inside the caller's tenant (M47 W1, Codex round 1 Medium). It used
// to be an untyped errors.New that the handler could not tell apart from a
// bcrypt or repository failure, so every one of them came back as 400 —
// which both hid genuine faults and left this route outside the wave's
// one-sentinel/404 contract.
var ErrPublicLinkNotFound = errors.New("public link not found")

// ErrPublicLinkScopeCheckFailed wraps an infrastructure failure of the M47
// W1 sbom-ownership query (Codex round 1, Medium). It exists so the handler
// can tell "the DB is unwell" (500) apart from "that sbom is not yours"
// (404) and from the service's own caller-facing validation (400). Without
// it every one of the three came back as a 400.
var ErrPublicLinkScopeCheckFailed = errors.New("failed to verify sbom ownership")

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
	// M47 W1: typed so the handler can keep this — the ONLY caller-fixable
	// error on this route — as a 400 while everything else (token gen,
	// bcrypt, repository) becomes a 500. Previously all of them shared one
	// 400 bucket, which told a caller "your request was bad" during an
	// outage.
	if input.Name == "" {
		return nil, ValidationErrorf("name is required")
	}
	// M47 W1: bind BOTH the project and the pinned SBOM to the caller's
	// tenant BEFORE anything is persisted. The checks live here rather than
	// in the handler so every future caller of Create inherits them.
	//
	// Codex round 2 (Low): the project check used to be skipped, on the
	// grounds that `public_links` carries the composite
	// (tenant_id, project_id) -> projects(tenant_id, id) FK (migration 044)
	// and a hard constraint beats an application predicate. That reasoning
	// holds for INTEGRITY but not for the WIRE CONTRACT: the FK rejects a
	// foreign project as an opaque INSERT error, which this route renders as
	// a generic 400 — a status a prober can tell apart from the 404 every
	// other out-of-scope target returns. And with `sbom_id` omitted (the
	// legitimate "always latest" form) no scope query ran at all. Checking
	// explicitly makes the answer the same 404 in every case.
	if err := s.requireProjectInTenant(ctx, input.TenantID, input.ProjectID); err != nil {
		return nil, err
	}
	if err := s.requireSbomInProject(ctx, input.TenantID, input.ProjectID, input.SbomID); err != nil {
		return nil, err
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
		// Codex round 2 (Low): a driver failure here used to escape raw and
		// land in the handler's generic bucket. It is an infrastructure
		// fault, not a caller error — wrap it so the handler renders 500.
		return nil, fmt.Errorf("%w: link %s: %v", ErrPublicLinkScopeCheckFailed, id, err)
	}
	if link == nil {
		return nil, ErrPublicLinkNotFound
	}

	// M47 W1: the update path can REPOINT an existing link at another
	// SBOM, so it needs the same binding as Create. The project is the
	// link's own (the route has no :project_id), read back from the
	// tenant-scoped GetByID above — never from the request body.
	if err := s.requireSbomInProject(ctx, tenantID, link.ProjectID, input.SbomID); err != nil {
		return nil, err
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
		// The GetByID above already established the link is in scope, so a
		// 0-row UPDATE here means it was deleted in between. Same answer as
		// "it was never there" — see Delete.
		if errors.Is(err, repository.ErrPublicLinkRowNotFound) {
			return nil, ErrPublicLinkNotFound
		}
		return nil, err
	}
	return link, nil
}

// Delete removes a public link restricted to the authenticated tenant.
//
// M47R (Codex cross-wave review, Low): the repository's 0-row sentinel is
// translated to the service-level ErrPublicLinkNotFound that Update already
// returns, so the handler has ONE thing to test for on both verbs. Everything
// else stays a raw error and the handler renders it as 500.
//
// The 404 this produces is not an existence oracle: the DELETE's predicate is
// `id = $1 AND tenant_id = $2`, so an unknown link and another tenant's link
// are indistinguishable in the answer — the same sentinel Update collapses
// them into (M47 W1).
func (s *PublicLinkService) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	if err := s.linkRepo.Delete(ctx, tenantID, id); err != nil {
		if errors.Is(err, repository.ErrPublicLinkRowNotFound) {
			return ErrPublicLinkNotFound
		}
		return err
	}
	return nil
}

// assertSbomServesLink is the M47 W1 read-side half of the share-link
// binding: the SBOM the anonymous route is about to publish must belong to
// the project the link names.
//
// The write-side guard (requireSbomInProject) stops NEW mis-pinned links.
// This one refuses to serve rows that were written before it existed, which
// is what makes the fix retroactive rather than merely forward-looking — no
// data migration, no operator action. The refusal is a plain error: both
// anonymous handlers already collapse every failure into one generic 403
// ("invalid password or the share link is unavailable"), so a probe learns
// nothing from it either way.
func assertSbomServesLink(sbom *model.Sbom, link *model.PublicLink) error {
	if sbom == nil {
		return errors.New("share link resolves to no SBOM")
	}
	if sbom.ProjectID != link.ProjectID {
		return fmt.Errorf("share link %s is pinned to an SBOM of a different project", link.ID)
	}
	return nil
}

// requireProjectInTenant is the M47 W1 project half of Create's binding
// (Codex round 2, Low). `projects` is FORCE RLS, so under the request's
// TenantTx a foreign project is invisible and this reads as "not in tenant";
// the explicit tenant_id predicate inside the query is the belt that still
// holds if RLS is ever disabled. Out-of-scope collapses into the SAME
// sentinel the sbom check uses, so both render as one 404.
func (s *PublicLinkService) requireProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) error {
	if s.linkRepo == nil {
		return fmt.Errorf("%w: public link repository is not wired", ErrPublicLinkScopeCheckFailed)
	}
	inTenant, err := s.linkRepo.ProjectInTenant(ctx, tenantID, projectID)
	if err != nil {
		return fmt.Errorf("%w: project %s: %v", ErrPublicLinkScopeCheckFailed, projectID, err)
	}
	if !inTenant {
		return ErrPublicLinkSbomNotInProject
	}
	return nil
}

// requireSbomInProject is the shared M47 W1 guard for Create / Update.
//
// A nil sbomID is legitimate and means "always publish the project's latest
// SBOM" (GetPublicView falls back to GetLatest), so it is accepted without a
// lookup — the latest SBOM of the link's own project is in scope by
// construction. A non-nil id must resolve inside (tenant, project) or the
// whole request is rejected with the single ErrPublicLinkSbomNotInProject
// sentinel.
func (s *PublicLinkService) requireSbomInProject(ctx context.Context, tenantID, projectID uuid.UUID, sbomID *uuid.UUID) error {
	if sbomID == nil {
		return nil
	}
	if s.sbomRepo == nil {
		// Fail closed on a misconfigured wiring rather than dereference nil
		// (and rather than silently accept an unverified sbom_id).
		return fmt.Errorf("%w: sbom repository is not wired", ErrPublicLinkScopeCheckFailed)
	}
	ok, err := s.sbomRepo.SbomInProject(ctx, tenantID, projectID, *sbomID)
	if err != nil {
		return fmt.Errorf("%w: sbom %s in project %s: %v",
			ErrPublicLinkScopeCheckFailed, *sbomID, projectID, err)
	}
	if !ok {
		return ErrPublicLinkSbomNotInProject
	}
	return nil
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
		// M47 W1 read-side guard. Create / Update now refuse a cross-project
		// sbom_id, but that only protects rows written from here on: a
		// deployment that already carries a mis-pinned link would keep
		// serving another project's SBOM anonymously forever. Re-checking the
		// resolved row's own project_id neutralises those legacy rows without
		// a data migration, and costs nothing (project_id is already on the
		// row we just read).
		if err := assertSbomServesLink(sbom, link); err != nil {
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
		// M47 W1 read-side guard — see GetPublicView. This is the path that
		// hands over the raw SBOM bytes, so it needs the check at least as
		// much as the view does.
		if err := assertSbomServesLink(sbom, link); err != nil {
			return err
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

// IsDownloadLimitReached reports whether the per-link download cap is
// exhausted WITHOUT consuming anything. The anonymous download route must
// NOT use it to gate a download — see TryConsumeDownload — because the
// check and the increment would be two statements and concurrent
// requests can all pass the check before any of them increments (M46 B-1
// High-2 TOCTOU). It remains for read-only reporting.
func (s *PublicLinkService) IsDownloadLimitReached(ctx context.Context, tenantID, linkID uuid.UUID) (bool, error) {
	return s.linkRepo.IsDownloadLimitReached(ctx, tenantID, linkID)
}

// TryConsumeDownload is the final gate for the anonymous public-download
// flow: in ONE conditional UPDATE it re-checks that the link is still
// active and unexpired and that the cap is not exhausted, and consumes
// one download. It returns false when any of those fail — the caller must
// then withhold the SBOM bytes it has already loaded. The caller passes
// the tenant id derived from the link returned by GetByToken, so the
// repository-level tenant filter is satisfied without requiring tenant
// middleware on the route.
func (s *PublicLinkService) TryConsumeDownload(ctx context.Context, tenantID, linkID uuid.UUID) (bool, error) {
	return s.linkRepo.TryConsumeDownload(ctx, tenantID, linkID)
}

// TryRegisterView is the final gate for the anonymous view flow: it
// re-checks active + not-expired at send time and bumps view_count.
// Returns false when the link was revoked or expired while the view was
// being assembled, in which case the caller must withhold the view.
func (s *PublicLinkService) TryRegisterView(ctx context.Context, tenantID, linkID uuid.UUID) (bool, error) {
	return s.linkRepo.TryRegisterView(ctx, tenantID, linkID)
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
