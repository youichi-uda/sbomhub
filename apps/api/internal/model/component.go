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
