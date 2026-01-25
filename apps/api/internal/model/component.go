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
