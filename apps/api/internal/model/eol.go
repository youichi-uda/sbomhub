package model

import (
	"time"

	"github.com/google/uuid"
)

// EOLStatus represents the End of Life status of a component
type EOLStatus string

const (
	EOLStatusActive   EOLStatus = "active"   // Component is actively supported
	EOLStatusEOL      EOLStatus = "eol"      // End of Life reached (no more updates)
	EOLStatusEOS      EOLStatus = "eos"      // End of Support (security updates ended)
	EOLStatusUnknown  EOLStatus = "unknown"  // EOL status cannot be determined
)

// EOLProduct represents a product tracked in endoflife.date
type EOLProduct struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`                 // API identifier (e.g., "python", "nodejs")
	Title       string    `json:"title" db:"title"`               // Human-readable name
	Category    string    `json:"category,omitempty" db:"category"`
	Link        string    `json:"link,omitempty" db:"link"`
	TotalCycles int       `json:"total_cycles" db:"total_cycles"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// EOLProductCycle represents a version cycle for a product
type EOLProductCycle struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ProductID      uuid.UUID  `json:"product_id" db:"product_id"`
	Cycle          string     `json:"cycle" db:"cycle"`                       // Version cycle (e.g., "3.11", "18")
	ReleaseDate    *time.Time `json:"release_date,omitempty" db:"release_date"`
	EOLDate        *time.Time `json:"eol_date,omitempty" db:"eol_date"`       // End of Life date
	EOSDate        *time.Time `json:"eos_date,omitempty" db:"eos_date"`       // End of Support date
	LatestVersion  string     `json:"latest_version,omitempty" db:"latest_version"`
	IsLTS          bool       `json:"is_lts" db:"is_lts"`
	IsEOL          bool       `json:"is_eol" db:"is_eol"`
	Discontinued   bool       `json:"discontinued" db:"discontinued"`
	Link           string     `json:"link,omitempty" db:"link"`
	SupportEndDate *time.Time `json:"support_end_date,omitempty" db:"support_end_date"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// EOLComponentMapping maps component names/patterns to EOL products
type EOLComponentMapping struct {
	ID               uuid.UUID `json:"id" db:"id"`
	ProductID        uuid.UUID `json:"product_id" db:"product_id"`
	ComponentPattern string    `json:"component_pattern" db:"component_pattern"`
	ComponentType    string    `json:"component_type,omitempty" db:"component_type"`
	PurlType         string    `json:"purl_type,omitempty" db:"purl_type"`
	Priority         int       `json:"priority" db:"priority"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}

// EOLSyncSettings represents global EOL sync configuration
type EOLSyncSettings struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	Enabled           bool       `json:"enabled" db:"enabled"`
	SyncIntervalHours int        `json:"sync_interval_hours" db:"sync_interval_hours"`
	LastSyncAt        *time.Time `json:"last_sync_at,omitempty" db:"last_sync_at"`
	TotalProducts     int        `json:"total_products" db:"total_products"`
	TotalCycles       int        `json:"total_cycles" db:"total_cycles"`
	CreatedAt         time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at" db:"updated_at"`
}

// EOLSyncLog represents a sync operation log entry
type EOLSyncLog struct {
	ID                uuid.UUID  `json:"id" db:"id"`
	StartedAt         time.Time  `json:"started_at" db:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty" db:"completed_at"`
	Status            string     `json:"status" db:"status"` // running, success, failed
	ProductsSynced    int        `json:"products_synced" db:"products_synced"`
	CyclesSynced      int        `json:"cycles_synced" db:"cycles_synced"`
	ComponentsUpdated int        `json:"components_updated" db:"components_updated"`
	ErrorMessage      string     `json:"error_message,omitempty" db:"error_message"`
}

// EOLSyncStatus represents sync status constants
type EOLSyncStatus string

const (
	EOLSyncStatusRunning EOLSyncStatus = "running"
	EOLSyncStatusSuccess EOLSyncStatus = "success"
	EOLSyncStatusFailed  EOLSyncStatus = "failed"
)

// EOLSyncResult represents the result of a sync operation
type EOLSyncResult struct {
	ProductsSynced    int `json:"products_synced"`
	CyclesSynced      int `json:"cycles_synced"`
	ComponentsUpdated int `json:"components_updated"`
}

// ComponentEOLInfo contains EOL information for a component
type ComponentEOLInfo struct {
	Status          EOLStatus  `json:"status"`
	ProductID       *uuid.UUID `json:"product_id,omitempty"`
	ProductName     string     `json:"product_name,omitempty"`
	CycleID         *uuid.UUID `json:"cycle_id,omitempty"`
	CycleVersion    string     `json:"cycle_version,omitempty"`
	EOLDate         *time.Time `json:"eol_date,omitempty"`
	EOSDate         *time.Time `json:"eos_date,omitempty"`
	LatestVersion   string     `json:"latest_version,omitempty"`
	IsLTS           bool       `json:"is_lts"`
	ReleaseDate     *time.Time `json:"release_date,omitempty"`
	SupportEndDate  *time.Time `json:"support_end_date,omitempty"`
}

// EOLSummary represents EOL statistics for a project
type EOLSummary struct {
	ProjectID       uuid.UUID `json:"project_id"`
	TotalComponents int       `json:"total_components"`
	Active          int       `json:"active"`
	EOL             int       `json:"eol"`
	EOS             int       `json:"eos"`
	Unknown         int       `json:"unknown"`
}

// EOLStats represents overall EOL catalog statistics
type EOLStats struct {
	TotalProducts    int                `json:"total_products"`
	TotalCycles      int                `json:"total_cycles"`
	LastSyncAt       *time.Time         `json:"last_sync_at,omitempty"`
	LatestSyncStatus *EOLSyncLog        `json:"latest_sync_status,omitempty"`
}
