package model

import (
	"time"

	"github.com/google/uuid"
)

type Sbom struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ProjectID uuid.UUID `json:"project_id" db:"project_id"`
	Format    string    `json:"format" db:"format"`
	Version   string    `json:"version" db:"version"`
	RawData   []byte    `json:"-" db:"raw_data"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type SbomFormat string

const (
	FormatCycloneDX SbomFormat = "cyclonedx"
	FormatSPDX      SbomFormat = "spdx"
)
