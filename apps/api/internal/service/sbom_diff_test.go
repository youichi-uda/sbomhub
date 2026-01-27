package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestComponentKey_WithPurl(t *testing.T) {
	comp := model.Component{
		Name:    "lodash",
		Version: "4.17.21",
		Purl:    "pkg:npm/lodash@4.17.21",
	}

	key := componentKey(comp)
	expected := "pkg:npm/lodash" // version stripped by normalizePurl
	if key != expected {
		t.Errorf("componentKey() = %s, want %s", key, expected)
	}
}

func TestComponentKey_WithoutPurl(t *testing.T) {
	comp := model.Component{
		Name:    "My Component",
		Version: "1.0.0",
	}

	key := componentKey(comp)
	// name is normalized: lowercase, special chars replaced with space
	expected := "my component:1.0.0"
	if key != expected {
		t.Errorf("componentKey() = %s, want %s", key, expected)
	}
}

func TestComponentNameKey(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"simple", "simple"},
		{"My Component", "my component"},
		{"lodash-es", "lodash es"},
		{"@angular/core", "angular core"},
		{"  spaces  ", "spaces"},
		{"MixedCase123", "mixedcase123"},
		{"special!@#$chars", "special chars"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := componentNameKey(tt.name)
			if result != tt.expected {
				t.Errorf("componentNameKey(%q) = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestNormalizePurl(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0", "pkg:maven/org.apache.logging.log4j/log4j-core"},
		{"pkg:pypi/requests@2.28.0", "pkg:pypi/requests"},
		{"pkg:npm/express", "pkg:npm/express"}, // no version
		{"", ""},
		{"  ", ""},
		{"PKG:NPM/LODASH@1.0.0", "pkg:npm/lodash"}, // uppercase normalized
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			result := normalizePurl(tt.purl)
			if result != tt.expected {
				t.Errorf("normalizePurl(%q) = %q, want %q", tt.purl, result, tt.expected)
			}
		})
	}
}

func TestDiffComponent(t *testing.T) {
	comp := model.Component{
		Name:    "test-component",
		Version: "1.2.3",
		License: "MIT",
		Type:    "library",
		Purl:    "pkg:npm/test-component@1.2.3",
	}

	diff := diffComponent(comp)

	if diff.Name != comp.Name {
		t.Errorf("Name mismatch: got %s, want %s", diff.Name, comp.Name)
	}
	if diff.Version != comp.Version {
		t.Errorf("Version mismatch: got %s, want %s", diff.Version, comp.Version)
	}
	if diff.License != comp.License {
		t.Errorf("License mismatch: got %s, want %s", diff.License, comp.License)
	}
}
