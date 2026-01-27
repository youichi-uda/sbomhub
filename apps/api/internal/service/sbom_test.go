package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestDetectFormat_CycloneDX(t *testing.T) {
	cycloneDXData := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"components": []
	}`)

	format, err := detectFormat(cycloneDXData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if format != model.FormatCycloneDX {
		t.Errorf("expected CycloneDX, got %s", format)
	}
}

func TestDetectFormat_SPDX(t *testing.T) {
	spdxData := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test"
	}`)

	format, err := detectFormat(spdxData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if format != model.FormatSPDX {
		t.Errorf("expected SPDX, got %s", format)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	unknownData := []byte(`{
		"someField": "value"
	}`)

	_, err := detectFormat(unknownData)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestDetectFormat_InvalidJSON(t *testing.T) {
	invalidData := []byte(`not valid json`)

	_, err := detectFormat(invalidData)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseCycloneDX(t *testing.T) {
	cycloneDXData := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"components": [
			{
				"type": "library",
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21",
				"licenses": [{"license": {"id": "MIT"}}]
			},
			{
				"type": "library",
				"name": "express",
				"version": "4.18.2"
			}
		]
	}`)

	components, err := parseCycloneDX(cycloneDXData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	// Check first component
	c1 := components[0]
	if c1.Name != "lodash" {
		t.Errorf("expected name 'lodash', got '%s'", c1.Name)
	}
	if c1.Version != "4.17.21" {
		t.Errorf("expected version '4.17.21', got '%s'", c1.Version)
	}
	if c1.Type != "library" {
		t.Errorf("expected type 'library', got '%s'", c1.Type)
	}
	if c1.Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected purl 'pkg:npm/lodash@4.17.21', got '%s'", c1.Purl)
	}
	if c1.License != "MIT" {
		t.Errorf("expected license 'MIT', got '%s'", c1.License)
	}

	// Check second component has no purl/license
	c2 := components[1]
	if c2.Name != "express" {
		t.Errorf("expected name 'express', got '%s'", c2.Name)
	}
	if c2.Purl != "" {
		t.Errorf("expected empty purl, got '%s'", c2.Purl)
	}
}

func TestParseCycloneDX_EmptyComponents(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1
	}`)

	components, err := parseCycloneDX(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

func TestParseSPDX(t *testing.T) {
	spdxData := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-project",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-1",
				"name": "axios",
				"versionInfo": "1.4.0",
				"downloadLocation": "https://registry.npmjs.org/axios"
			},
			{
				"SPDXID": "SPDXRef-Package-2",
				"name": "react",
				"versionInfo": "18.2.0"
			}
		]
	}`)

	components, err := parseSPDX(spdxData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	c1 := components[0]
	if c1.Name != "axios" {
		t.Errorf("expected name 'axios', got '%s'", c1.Name)
	}
	if c1.Version != "1.4.0" {
		t.Errorf("expected version '1.4.0', got '%s'", c1.Version)
	}
	if c1.Type != "library" {
		t.Errorf("expected type 'library', got '%s'", c1.Type)
	}
}

func TestParseSPDX_NoPackages(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "empty-project"
	}`)

	components, err := parseSPDX(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

func TestParseComponents_UnsupportedFormat(t *testing.T) {
	data := []byte(`{}`)
	
	_, err := parseComponents(data, "unknown")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"name":    "test",
		"version": "1.0.0",
		"count":   123,
	}

	if getString(m, "name") != "test" {
		t.Error("failed to get string value")
	}
	if getString(m, "version") != "1.0.0" {
		t.Error("failed to get version string")
	}
	if getString(m, "count") != "" {
		t.Error("expected empty string for non-string value")
	}
	if getString(m, "missing") != "" {
		t.Error("expected empty string for missing key")
	}
}
