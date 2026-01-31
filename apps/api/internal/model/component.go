package model

import (
	"time"

	"github.com/google/uuid"
)

type Component struct {
	ID        uuid.UUID `json:"id" db:"id"`
	SbomID    uuid.UUID `json:"sbom_id" db:"sbom_id"`
	Name      string    `json:"name" db:"name"`
	Version   string    `json:"version" db:"version"`
	Type      string    `json:"type" db:"type"`
	Purl      string    `json:"purl" db:"purl"`
	License   string    `json:"license" db:"license"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// EOL (End of Life) fields
	EOLStatus       string     `json:"eol_status,omitempty" db:"eol_status"`
	EOLProductID    *uuid.UUID `json:"eol_product_id,omitempty" db:"eol_product_id"`
	EOLCycleID      *uuid.UUID `json:"eol_cycle_id,omitempty" db:"eol_cycle_id"`
	EOLDate         *time.Time `json:"eol_date,omitempty" db:"eol_date"`
	EOSDate         *time.Time `json:"eos_date,omitempty" db:"eos_date"`
	EOLProductName  string     `json:"eol_product_name,omitempty" db:"-"`
	EOLCycleVersion string     `json:"eol_cycle_version,omitempty" db:"-"`
}

type ComponentVulnerability struct {
	ComponentID      uuid.UUID `json:"component_id" db:"component_id"`
	ComponentName    string    `json:"component_name" db:"component_name"`
	ComponentVersion string    `json:"component_version" db:"component_version"`
	ComponentPurl    string    `json:"component_purl" db:"component_purl"`
	ComponentLicense string    `json:"component_license" db:"component_license"`
	CVEID            string    `json:"cve_id" db:"cve_id"`
	Severity         string    `json:"severity" db:"severity"`
}
