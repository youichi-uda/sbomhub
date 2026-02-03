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

func TestDetectFormatAndVersion_CycloneDX14(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"version": 1,
		"components": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatCycloneDX {
		t.Errorf("expected CycloneDX, got %s", info.Format)
	}
	if info.Version != "1.4" {
		t.Errorf("expected version 1.4, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_CycloneDX15(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"components": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatCycloneDX {
		t.Errorf("expected CycloneDX, got %s", info.Format)
	}
	if info.Version != "1.5" {
		t.Errorf("expected version 1.5, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_CycloneDX16(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"components": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatCycloneDX {
		t.Errorf("expected CycloneDX, got %s", info.Format)
	}
	if info.Version != "1.6" {
		t.Errorf("expected version 1.6, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_CycloneDX17(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.7",
		"version": 1,
		"components": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatCycloneDX {
		t.Errorf("expected CycloneDX, got %s", info.Format)
	}
	if info.Version != "1.7" {
		t.Errorf("expected version 1.7, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_SPDX22(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.2",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test"
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatSPDX {
		t.Errorf("expected SPDX, got %s", info.Format)
	}
	if info.Version != "2.2" {
		t.Errorf("expected version 2.2, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_SPDX23(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test"
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatSPDX {
		t.Errorf("expected SPDX, got %s", info.Format)
	}
	if info.Version != "2.3" {
		t.Errorf("expected version 2.3, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_SPDX30(t *testing.T) {
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0/terms/Core",
		"@graph": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatSPDX {
		t.Errorf("expected SPDX, got %s", info.Format)
	}
	if info.Version != "3.0" {
		t.Errorf("expected version 3.0, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_SPDX301(t *testing.T) {
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0.1/terms/Core",
		"@graph": []
	}`)

	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Format != model.FormatSPDX {
		t.Errorf("expected SPDX, got %s", info.Format)
	}
	if info.Version != "3.0.1" {
		t.Errorf("expected version 3.0.1, got %s", info.Version)
	}
}

func TestDetectFormatAndVersion_Unknown(t *testing.T) {
	data := []byte(`{
		"someField": "value"
	}`)

	_, err := detectFormatAndVersion(data)
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestDetectFormatAndVersion_InvalidJSON(t *testing.T) {
	data := []byte(`not valid json`)

	_, err := detectFormatAndVersion(data)
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

func TestParseSPDX3(t *testing.T) {
	spdx3Data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0/terms/Core",
		"@graph": [
			{
				"spdxId": "https://example.com/Document1",
				"type": "SpdxDocument",
				"name": "test-document"
			},
			{
				"spdxId": "https://example.com/Package1",
				"type": "software_Package",
				"name": "lodash",
				"packageVersion": "4.17.21",
				"externalIdentifier": [
					{
						"externalIdentifierType": "packageUrl",
						"identifier": "pkg:npm/lodash@4.17.21"
					}
				],
				"declaredLicense": "MIT"
			},
			{
				"spdxId": "https://example.com/Package2",
				"type": "software_Package",
				"name": "express",
				"packageVersion": "4.18.2"
			}
		]
	}`)

	components, err := parseSPDX3(spdx3Data)
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
	if c1.Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected purl 'pkg:npm/lodash@4.17.21', got '%s'", c1.Purl)
	}
	if c1.License != "MIT" {
		t.Errorf("expected license 'MIT', got '%s'", c1.License)
	}

	// Check second component
	c2 := components[1]
	if c2.Name != "express" {
		t.Errorf("expected name 'express', got '%s'", c2.Name)
	}
	if c2.Version != "4.18.2" {
		t.Errorf("expected version '4.18.2', got '%s'", c2.Version)
	}
}

func TestParseSPDX3_EmptyGraph(t *testing.T) {
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0/terms/Core",
		"@graph": []
	}`)

	components, err := parseSPDX3(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

func TestParseSPDX3_OnlyDocument(t *testing.T) {
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0/terms/Core",
		"@graph": [
			{
				"spdxId": "https://example.com/Document1",
				"type": "SpdxDocument",
				"name": "test-document"
			}
		]
	}`)

	components, err := parseSPDX3(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components (only document), got %d", len(components))
	}
}

func TestParseComponents_UnsupportedFormat(t *testing.T) {
	data := []byte(`{}`)

	_, err := parseComponents(data, "unknown", "")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestParseComponents_SPDX2(t *testing.T) {
	spdxData := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-project",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-1",
				"name": "test-package",
				"versionInfo": "1.0.0"
			}
		]
	}`)

	components, err := parseComponents(spdxData, model.FormatSPDX, "2.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Name != "test-package" {
		t.Errorf("expected name 'test-package', got '%s'", components[0].Name)
	}
}

func TestParseComponents_SPDX3(t *testing.T) {
	spdx3Data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0/terms/Core",
		"@graph": [
			{
				"spdxId": "https://example.com/Package1",
				"type": "software_Package",
				"name": "test-package-3",
				"packageVersion": "3.0.0"
			}
		]
	}`)

	components, err := parseComponents(spdx3Data, model.FormatSPDX, "3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(components))
	}
	if components[0].Name != "test-package-3" {
		t.Errorf("expected name 'test-package-3', got '%s'", components[0].Name)
	}
	if components[0].Version != "3.0.0" {
		t.Errorf("expected version '3.0.0', got '%s'", components[0].Version)
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

func TestExtractSPDX3Version(t *testing.T) {
	tests := []struct {
		ctx      string
		expected string
	}{
		{"https://spdx.org/rdf/3.0/terms/Core", "3.0"},
		{"https://spdx.org/rdf/3.0.1/terms/Core", "3.0.1"},
		{"https://spdx.org/rdf/3.0.1/terms/Software", "3.0.1"},
		{"https://spdx.org/rdf/3.0/spdx-json-ld-context.jsonld", "3.0"},
		{"unknown", "3.0"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.ctx, func(t *testing.T) {
			result := extractSPDX3Version(tt.ctx)
			if result != tt.expected {
				t.Errorf("extractSPDX3Version(%q) = %q, expected %q", tt.ctx, result, tt.expected)
			}
		})
	}
}
