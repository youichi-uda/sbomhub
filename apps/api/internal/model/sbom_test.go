package model

import (
	"testing"

	"github.com/google/uuid"
)

func TestSbomFormat_Constants(t *testing.T) {
	if FormatCycloneDX != "cyclonedx" {
		t.Errorf("FormatCycloneDX should be 'cyclonedx', got %s", FormatCycloneDX)
	}
	if FormatSPDX != "spdx" {
		t.Errorf("FormatSPDX should be 'spdx', got %s", FormatSPDX)
	}
}

func TestSbom_Fields(t *testing.T) {
	id := uuid.New()
	projectID := uuid.New()
	rawData := []byte(`{"bomFormat":"CycloneDX"}`)

	sbom := Sbom{
		ID:        id,
		ProjectID: projectID,
		Format:    string(FormatCycloneDX),
		Version:   "1.4",
		RawData:   rawData,
	}

	if sbom.ID != id {
		t.Error("ID mismatch")
	}
	if sbom.ProjectID != projectID {
		t.Error("ProjectID mismatch")
	}
	if sbom.Format != "cyclonedx" {
		t.Errorf("Format mismatch: got %s", sbom.Format)
	}
	if sbom.Version != "1.4" {
		t.Error("Version mismatch")
	}
	if len(sbom.RawData) == 0 {
		t.Error("RawData should not be empty")
	}
}

func TestSbomFormat_String(t *testing.T) {
	var format SbomFormat = "cyclonedx"
	if string(format) != "cyclonedx" {
		t.Errorf("SbomFormat string conversion failed")
	}
}
