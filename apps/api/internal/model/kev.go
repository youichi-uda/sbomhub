package model

import (
	"time"

	"github.com/google/uuid"
)

// KEVEntry represents an entry in the CISA Known Exploited Vulnerabilities catalog
type KEVEntry struct {
	ID                uuid.UUID `json:"id" db:"id"`
	CVEID             string    `json:"cve_id" db:"cve_id"`
	VendorProject     string    `json:"vendor_project" db:"vendor_project"`
	Product           string    `json:"product" db:"product"`
	VulnerabilityName string    `json:"vulnerability_name" db:"vulnerability_name"`
	ShortDescription  string    `json:"short_description,omitempty" db:"short_description"`
	RequiredAction    string    `json:"required_action,omitempty" db:"required_action"`
	DateAdded         time.Time `json:"date_added" db:"date_added"`
	DueDate           time.Time `json:"due_date" db:"due_date"`
	KnownRansomwareUse bool     `json:"known_ransomware_use" db:"known_ransomware_use"`
	Notes             string    `json:"notes,omitempty" db:"notes"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// KEVSyncSettings represents global KEV sync configuration
type KEVSyncSettings struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	Enabled            bool       `json:"enabled" db:"enabled"`
	SyncIntervalHours  int        `json:"sync_interval_hours" db:"sync_interval_hours"`
	LastSyncAt         *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	LastCatalogVersion string     `json:"last_catalog_version,omitempty" db:"last_catalog_version"`
	TotalEntries       int        `json:"total_entries" db:"total_entries"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// KEVSyncLog represents a sync operation log entry
type KEVSyncLog struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	StartedAt      time.Time  `json:"started_at" db:"started_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	Status         string     `json:"status" db:"status"` // running, success, failed
	NewEntries     int        `json:"new_entries" db:"new_entries"`
	UpdatedEntries int        `json:"updated_entries" db:"updated_entries"`
	TotalProcessed int        `json:"total_processed" db:"total_processed"`
	ErrorMessage   string     `json:"error_message,omitempty" db:"error_message"`
	CatalogVersion string     `json:"catalog_version,omitempty" db:"catalog_version"`
}

// KEVSyncStatus represents sync status constants
type KEVSyncStatus string

const (
	KEVSyncStatusRunning KEVSyncStatus = "running"
	KEVSyncStatusSuccess KEVSyncStatus = "success"
	KEVSyncStatusFailed  KEVSyncStatus = "failed"
)

// KEVSyncResult represents the result of a sync operation
type KEVSyncResult struct {
	NewEntries     int    `json:"new_entries"`
	UpdatedEntries int    `json:"updated_entries"`
	TotalProcessed int    `json:"total_processed"`
	CatalogVersion string `json:"catalog_version"`
}
