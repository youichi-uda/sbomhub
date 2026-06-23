package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

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

// CreateProjectAPIKeyInput is used for legacy project-level API keys (deprecated)
type CreateProjectAPIKeyInput struct {
	TenantID    uuid.UUID  `json:"tenant_id"`
	ProjectID   uuid.UUID  `json:"project_id"`
	Name        string     `json:"name"`
	Permissions string     `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// CreateKey creates a new tenant-level API key (recommended)
func (s *APIKeyService) CreateKey(ctx context.Context, input CreateAPIKeyInput) (*model.APIKeyWithSecret, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.Permissions == "" {
		input.Permissions = "write" // Default permission
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

// CreateProjectKey creates a legacy project-level API key (deprecated, for backwards compatibility)
func (s *APIKeyService) CreateProjectKey(ctx context.Context, input CreateProjectAPIKeyInput) (*model.APIKeyWithSecret, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.Permissions == "" {
		input.Permissions = "write" // Default permission
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

// ListByProject returns API keys for a specific project (legacy, deprecated).
// tenantID restricts the query to the caller's own tenant; without it a
// caller could enumerate API keys on another tenant's project by guessing
// the project UUID (RLS no longer enforces this — see migration 028).
func (s *APIKeyService) ListByProject(ctx context.Context, tenantID, projectID uuid.UUID) ([]model.APIKey, error) {
	return s.keyRepo.ListByProject(ctx, tenantID, projectID)
}

// DeleteKey removes an API key restricted to the caller's tenant.
func (s *APIKeyService) DeleteKey(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.keyRepo.Delete(ctx, tenantID, id)
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
