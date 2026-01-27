package model

import (
	"time"

	"github.com/google/uuid"
)

type PublicLink struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	TenantID         uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ProjectID        uuid.UUID  `json:"project_id" db:"project_id"`
	SbomID           *uuid.UUID `json:"sbom_id,omitempty" db:"sbom_id"`
	Token            string     `json:"token" db:"token"`
	Name             string     `json:"name" db:"name"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	IsActive         bool       `json:"is_active" db:"is_active"`
	AllowedDownloads *int       `json:"allowed_downloads,omitempty" db:"allowed_downloads"`
	PasswordHash     *string    `json:"-" db:"password_hash"`
	ViewCount        int        `json:"view_count" db:"view_count"`
	DownloadCount    int        `json:"download_count" db:"download_count"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`
}

type PublicLinkAccessLog struct {
	ID           uuid.UUID `json:"id" db:"id"`
	PublicLinkID uuid.UUID `json:"public_link_id" db:"public_link_id"`
	Action       string    `json:"action" db:"action"`
	IPAddress    string    `json:"ip_address" db:"ip_address"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

type PublicSbomView struct {
	ProjectName string        `json:"project_name"`
	Sbom        Sbom          `json:"sbom"`
	Components  []Component   `json:"components"`
	Link        PublicLinkMeta `json:"link"`
}

type PublicLinkMeta struct {
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	ViewCount int       `json:"view_count"`
	DownloadCount int   `json:"download_count"`
}
