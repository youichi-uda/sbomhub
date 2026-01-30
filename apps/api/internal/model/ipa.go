package model

import (
	"time"

	"github.com/google/uuid"
)

// IPAAnnouncement represents an IPA security announcement
type IPAAnnouncement struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	IPAID       string     `json:"ipa_id" db:"ipa_id"`
	Title       string     `json:"title" db:"title"`
	TitleJa     string     `json:"title_ja,omitempty" db:"title_ja"`
	Description string     `json:"description,omitempty" db:"description"`
	Category    string     `json:"category" db:"category"`
	Severity    string     `json:"severity,omitempty" db:"severity"`
	SourceURL   string     `json:"source_url" db:"source_url"`
	RelatedCVEs []string   `json:"related_cves,omitempty" db:"related_cves"`
	PublishedAt time.Time  `json:"published_at" db:"published_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// IPASyncSettings represents IPA sync settings for a tenant
type IPASyncSettings struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	TenantID       uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	Enabled        bool       `json:"enabled" db:"enabled"`
	NotifyOnNew    bool       `json:"notify_on_new" db:"notify_on_new"`
	NotifySeverity []string   `json:"notify_severity" db:"notify_severity"`
	LastSyncAt     *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// IPAVulnerabilityMapping maps IPA announcements to CVEs
type IPAVulnerabilityMapping struct {
	ID               uuid.UUID `json:"id" db:"id"`
	IPAAnnouncementID uuid.UUID `json:"ipa_announcement_id" db:"ipa_announcement_id"`
	CVEID            string    `json:"cve_id" db:"cve_id"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// IPA category constants
const (
	IPACategorySecurityAlert   = "security_alert"
	IPACategoryVulnerabilityNote = "vulnerability_note"
	IPACategoryTechnicalWatch  = "technical_watch"
)

// IPAAnnouncementWithVulnerability combines IPA info with vulnerability details
type IPAAnnouncementWithVulnerability struct {
	IPAAnnouncement
	VulnerabilityCount int `json:"vulnerability_count"`
}
