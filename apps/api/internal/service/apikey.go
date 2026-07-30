package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// ErrInvalidPermissions is returned by CreateKey / CreateProjectKey when
// the caller supplies a permissions string that is not in the documented
// allowlist (read / write / admin / owner). M1 Codex review #F17 fix:
// previously CreateKey accepted any value verbatim and the MultiAuth
// validation step silently promoted unknown values to write-capable. The
// sentinel allows handlers to map this error to 400 rather than 500
// without string-matching against the wrapped error message.
//
// The error message is intentionally generic — it lists the recognised
// values rather than echoing back the rejected input — so callers
// receive a fix-it-yourself hint without confirming whether a probe
// string was rejected for being outside the allowlist or for some other
// validation failure further down. The 400 body emitted by the handler
// wraps this with `{"error":"invalid permissions"}`.
var ErrInvalidPermissions = fmt.Errorf(
	"permissions must be one of: read, write, admin",
)

// ErrAPIKeyProjectNotInTenant is returned by CreateProjectKey when the
// route's :id does not name a project of the caller's tenant (M47 W1).
//
// POST /projects/:id/apikeys parsed :id straight into the INSERT payload and
// checked nothing. `api_keys` is the ONE child table with neither RLS
// (migration 028 removed the policy so the pre-TenantTx authn lookup can run
// under sbomhub_app) nor a composite (tenant_id, project_id) FK, so its
// single-column FK to projects(id) accepted any project UUID in the database.
// Two consequences, both real:
//
//   - cross-tenant pollution: an admin of tenant A minted a key row whose
//     project_id points into tenant B's project graph. It authenticates as A
//     (tenant_id is A), but it is now CASCADE-coupled to B's project — B
//     deleting that project silently revokes A's key — and it shows up in
//     nothing that A's own project listing can reach.
//   - an existence oracle: a real project UUID answered 201 while a
//     non-existent one answered 400 (FK violation), letting any admin
//     enumerate project UUIDs across the whole installation.
//
// The handler maps this to 404, the same answer as an unknown project.
var ErrAPIKeyProjectNotInTenant = errors.New("project not found in this tenant")

// ErrAPIKeyScopeCheckFailed wraps an infrastructure failure of the M47 W1
// ownership queries (Codex round 1, Low). It lets the handler separate "the
// DB is unwell" (500) from "that project/key is not yours" (404) — without
// it, mapCreateKeyError rendered a repository outage as a client 400 and
// Delete rendered it as a 404.
var ErrAPIKeyScopeCheckFailed = errors.New("failed to verify api key scope")

type APIKeyService struct {
	keyRepo *repository.APIKeyRepository
}

func NewAPIKeyService(keyRepo *repository.APIKeyRepository) *APIKeyService {
	return &APIKeyService{keyRepo: keyRepo}
}

// CreateAPIKeyInput is used for creating tenant-level API keys (new)
type CreateAPIKeyInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	Name        string     `json:"name"`
	Permissions string     `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateProjectAPIKeyInput is used for project-scoped API keys — keys limited
// to one project (M50 W2 made api_keys.project_id load-bearing; see
// middleware/project_scope.go for what the limit covers).
type CreateProjectAPIKeyInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	ProjectID   uuid.UUID  `json:"project_id"`
	Name        string     `json:"name"`
	Permissions string     `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateKey creates a new tenant-level API key (recommended).
//
// M1 Codex review #F17: permissions are validated against the allowlist
// (read / write / admin / owner) before persistence. Empty input is
// substituted with the documented default "write" first so callers that
// rely on the historical "omit permissions for a default write key"
// shorthand keep working. Anything not in the allowlist returns
// ErrInvalidPermissions; the handler maps that to 400. The reason for
// validating at this layer rather than relying on the middleware's
// fail-closed default is that an unknown value silently downgraded to
// RoleViewer at validation time looks like a write key in the API
// response (the persisted permissions column echoes the caller's input)
// but functions as a read key in practice — a confusing UX that the
// allowlist eliminates by rejecting the input up front.
func (s *APIKeyService) CreateKey(ctx context.Context, input CreateAPIKeyInput) (*model.APIKeyWithSecret, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.Permissions == "" {
		input.Permissions = "write" // Default permission
	}
	// F17: normalise + validate against the MultiAuth allowlist BEFORE
	// persistence so unknown values cannot land in the column at all.
	input.Permissions = strings.ToLower(strings.TrimSpace(input.Permissions))
	if !model.IsKnownAPIKeyPermission(input.Permissions) {
		return nil, ErrInvalidPermissions
	}

	// Generate a random key: sbh_<32 random hex chars>
	rawKey, err := generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Hash the key for storage
	keyHash := hashKey(rawKey)

	// Get prefix for identification (e.g., "sbh_abc1")
	keyPrefix := rawKey[:12]

	now := time.Now()
	apiKey := &model.APIKey{
		ID:          uuid.New(),
		TenantID:    input.TenantID,
		ProjectID:   nil, // Tenant-level key has no project
		Name:        input.Name,
		KeyHash:     keyHash,
		KeyPrefix:   keyPrefix,
		Permissions: input.Permissions,
		ExpiresAt:   input.ExpiresAt,
		CreatedAt:   now,
	}

	if err := s.keyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &model.APIKeyWithSecret{
		APIKey: *apiKey,
		Key:    rawKey,
	}, nil
}

// CreateProjectKey creates a project-scoped API key: one limited to the project
// named by the route.
//
// M50 W2: this is no longer a backwards-compatibility path. Until M50 W2 the
// project_id it writes was read by no authentication path, so the key it minted
// was indistinguishable from a tenant-level one at request time; it is now
// enforced by middleware.apiKeyProjectScopeAllowed and by CLIHandler's
// body-resolved routes. What the limit does and does not cover is enumerated in
// middleware/project_scope.go and docs/UPGRADE.md §2d.
//
// The same F17 permissions validation as CreateKey applies — this path is not
// exempt because, after the F14 MultiAuth integration, both tenant- and
// project-scoped keys land on the same TenantContext role allowlist via
// roleFromAPIKeyPermissions. Scope and role are independent: a project-scoped
// key still needs permissions=write to drive a write route.
func (s *APIKeyService) CreateProjectKey(ctx context.Context, input CreateProjectAPIKeyInput) (*model.APIKeyWithSecret, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.Permissions == "" {
		input.Permissions = "write" // Default permission
	}
	// F17: see CreateKey for the rationale — same allowlist, same
	// rejection contract. This stays FIRST (ahead of the M47 scope check
	// below) because it inspects caller input only: it issues no SQL, so a
	// malformed request costs nothing, and its answer reveals nothing about
	// whether the project exists. F17's own test pins "no SQL must run for
	// rejected permissions".
	input.Permissions = strings.ToLower(strings.TrimSpace(input.Permissions))
	if !model.IsKnownAPIKeyPermission(input.Permissions) {
		return nil, ErrInvalidPermissions
	}

	// M47 W1: the project MUST belong to the caller's tenant. See
	// ErrAPIKeyProjectNotInTenant — for this table the predicate is the only
	// defence there is. Checked before the key material is generated so a
	// rejected request never burns entropy or leaves a hash in memory.
	inTenant, err := s.keyRepo.ProjectInTenant(ctx, input.TenantID, input.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("%w: project %s: %v", ErrAPIKeyScopeCheckFailed, input.ProjectID, err)
	}
	if !inTenant {
		return nil, ErrAPIKeyProjectNotInTenant
	}

	// Generate a random key: sbh_<32 random hex chars>
	rawKey, err := generateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Hash the key for storage
	keyHash := hashKey(rawKey)

	// Get prefix for identification (e.g., "sbh_abc1")
	keyPrefix := rawKey[:12]

	now := time.Now()
	apiKey := &model.APIKey{
		ID:          uuid.New(),
		TenantID:    input.TenantID,
		ProjectID:   &input.ProjectID,
		Name:        input.Name,
		KeyHash:     keyHash,
		KeyPrefix:   keyPrefix,
		Permissions: input.Permissions,
		ExpiresAt:   input.ExpiresAt,
		CreatedAt:   now,
	}

	if err := s.keyRepo.Create(ctx, apiKey); err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}

	return &model.APIKeyWithSecret{
		APIKey: *apiKey,
		Key:    rawKey,
	}, nil
}

// GetKey looks up an API key restricted to the caller's tenant. tenantID
// MUST be derived from the authenticated session (e.g. middleware.ContextKeyTenantID),
// never from a request body — see APIKeyRepository.GetByID for the rationale.
func (s *APIKeyService) GetKey(ctx context.Context, tenantID, id uuid.UUID) (*model.APIKey, error) {
	return s.keyRepo.GetByID(ctx, tenantID, id)
}

// ListByTenant returns all API keys for a tenant (new tenant-level method)
func (s *APIKeyService) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.APIKey, error) {
	return s.keyRepo.ListByTenant(ctx, tenantID)
}

// ListByProject returns the project-scoped API keys of one project.
// tenantID restricts the query to the caller's own tenant; without it a
// caller could enumerate API keys on another tenant's project by guessing
// the project UUID (RLS no longer enforces this — see migration 028).
func (s *APIKeyService) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.APIKey, error) {
	return s.keyRepo.ListByProject(ctx, tenantID, projectID)
}

// DeleteKey removes a PROJECT-level API key, restricted to the caller's
// tenant AND to the project named in the route.
//
// M47 W1: projectID is a new parameter. The repository DELETE filters on
// (id, tenant_id) only, so DELETE /projects/A/apikeys/<B's key> destroyed
// B's key and answered 204. `api_keys` has no RLS (migration 028) and no
// composite FK, so the predicate added here is the only thing that binds the
// key to the project. Returns ErrAPIKeyProjectNotInTenant — the same
// sentinel, and therefore the same 404, as a project the caller does not own.
func (s *APIKeyService) DeleteKey(ctx context.Context, tenantID, projectID, id uuid.UUID) error {
	// Codex round 2 (Low): one conditional DELETE — see
	// VEXService.DeleteStatement for the rationale.
	err := s.keyRepo.DeleteKeyInProject(ctx, tenantID, projectID, id)
	if errors.Is(err, repository.ErrScopedDeleteNoRows) {
		return ErrAPIKeyProjectNotInTenant
	}
	if err != nil {
		return fmt.Errorf("%w: key %s in project %s: %v", ErrAPIKeyScopeCheckFailed, id, projectID, err)
	}
	return nil
}

// DeleteKeyByTenant deletes an API key ensuring it belongs to the specified tenant
func (s *APIKeyService) DeleteKeyByTenant(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	return s.keyRepo.DeleteByTenant(ctx, id, tenantID)
}

// ValidateKey validates an API key and returns the key info if valid.
//
// GetByKeyHash is the sole tenant-unscoped read on api_keys: it is itself
// the call that decides which tenant the caller belongs to. Once we have
// the row, every subsequent api_keys access (here: UpdateLastUsed) is
// re-scoped to key.TenantID.
func (s *APIKeyService) ValidateKey(ctx context.Context, rawKey string) (*model.APIKey, error) {
	keyHash := hashKey(rawKey)

	key, err := s.keyRepo.GetByKeyHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup key: %w", err)
	}
	if key == nil {
		return nil, fmt.Errorf("invalid API key")
	}

	// Check expiration
	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("API key has expired")
	}

	// Update last used (best-effort; scoped to the key's own tenant).
	_ = s.keyRepo.UpdateLastUsed(ctx, key.TenantID, key.ID)

	return key, nil
}

// generateAPIKey creates a random API key with format: sbh_<32 hex chars>
func generateAPIKey() (string, error) {
	bytes := make([]byte, 24) // 24 bytes = 48 hex chars, we'll use 32
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "sbh_" + hex.EncodeToString(bytes)[:32], nil
}

// hashKey creates a SHA256 hash of the key
func hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}
