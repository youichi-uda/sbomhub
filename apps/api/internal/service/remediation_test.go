package service

import (
	"testing"
)

func TestDetectEcosystem(t *testing.T) {
	tests := []struct {
		name          string
		purl          string
		componentType string
		expected      string
	}{
		// PURL-based detection
		{"maven purl", "pkg:maven/org.apache/commons", "library", "Maven"},
		{"npm purl", "pkg:npm/lodash@4.17.21", "library", "npm"},
		{"pypi purl", "pkg:pypi/requests", "library", "PyPI"},
		{"golang purl", "pkg:golang/github.com/gin-gonic/gin", "library", "Go"},
		{"nuget purl", "pkg:nuget/Newtonsoft.Json", "library", "NuGet"},
		{"cargo purl", "pkg:cargo/serde", "library", "crates.io"},
		{"gem purl", "pkg:gem/rails", "library", "RubyGems"},

		// Fallback to component type
		{"empty purl", "", "library", "library"},
		{"no purl with type", "", "framework", "framework"},

		// Unknown purl prefix
		{"unknown purl", "pkg:unknown/something", "library", "library"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectEcosystem(tt.purl, tt.componentType)
			if result != tt.expected {
				t.Errorf("detectEcosystem(%q, %q) = %q, want %q", tt.purl, tt.componentType, result, tt.expected)
			}
		})
	}
}

func TestGenerateUpgradeCommands(t *testing.T) {
	tests := []struct {
		name      string
		pkgName   string
		version   string
		ecosystem string
		wantKeys  []string
	}{
		{
			name:      "npm package",
			pkgName:   "lodash",
			version:   "4.17.21",
			ecosystem: "npm",
			wantKeys:  []string{"npm", "yarn", "pnpm"},
		},
		{
			name:      "maven package",
			pkgName:   "org.apache.logging.log4j:log4j-core",
			version:   "2.17.0",
			ecosystem: "Maven",
			wantKeys:  []string{"maven", "gradle"},
		},
		{
			name:      "pypi package",
			pkgName:   "requests",
			version:   "2.28.0",
			ecosystem: "PyPI",
			wantKeys:  []string{"pip", "poetry"},
		},
		{
			name:      "go module",
			pkgName:   "github.com/gin-gonic/gin",
			version:   "1.9.0",
			ecosystem: "Go",
			wantKeys:  []string{"go"},
		},
		{
			name:      "nuget package",
			pkgName:   "Newtonsoft.Json",
			version:   "13.0.3",
			ecosystem: "NuGet",
			wantKeys:  []string{"dotnet", "nuget"},
		},
		{
			name:      "cargo package",
			pkgName:   "serde",
			version:   "1.0.188",
			ecosystem: "crates.io",
			wantKeys:  []string{"cargo"},
		},
		{
			name:      "rubygems package",
			pkgName:   "rails",
			version:   "7.1.0",
			ecosystem: "RubyGems",
			wantKeys:  []string{"bundler", "gem"},
		},
		{
			name:      "unknown ecosystem",
			pkgName:   "unknown-pkg",
			version:   "1.0.0",
			ecosystem: "Unknown",
			wantKeys:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateUpgradeCommands(tt.pkgName, tt.version, tt.ecosystem)

			// Check that expected keys are present
			for _, key := range tt.wantKeys {
				if _, ok := result[key]; !ok {
					t.Errorf("generateUpgradeCommands() missing key %q", key)
				}
			}

			// Check key count matches
			if len(result) != len(tt.wantKeys) {
				t.Errorf("generateUpgradeCommands() returned %d keys, want %d", len(result), len(tt.wantKeys))
			}
		})
	}
}

func TestGenerateUpgradeCommands_CommandFormat(t *testing.T) {
	// Test specific command formats
	tests := []struct {
		name      string
		pkgName   string
		version   string
		ecosystem string
		cmdKey    string
		wantCmd   string
	}{
		{
			name:      "npm install command",
			pkgName:   "lodash",
			version:   "4.17.21",
			ecosystem: "npm",
			cmdKey:    "npm",
			wantCmd:   "npm install lodash@4.17.21",
		},
		{
			name:      "yarn add command",
			pkgName:   "express",
			version:   "4.18.2",
			ecosystem: "npm",
			cmdKey:    "yarn",
			wantCmd:   "yarn add express@4.18.2",
		},
		{
			name:      "pip install command",
			pkgName:   "requests",
			version:   "2.28.0",
			ecosystem: "PyPI",
			cmdKey:    "pip",
			wantCmd:   "pip install requests==2.28.0",
		},
		{
			name:      "go get command",
			pkgName:   "github.com/gin-gonic/gin",
			version:   "1.9.0",
			ecosystem: "Go",
			cmdKey:    "go",
			wantCmd:   "go get github.com/gin-gonic/gin@v1.9.0",
		},
		{
			name:      "dotnet command",
			pkgName:   "Newtonsoft.Json",
			version:   "13.0.3",
			ecosystem: "NuGet",
			cmdKey:    "dotnet",
			wantCmd:   "dotnet add package Newtonsoft.Json --version 13.0.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateUpgradeCommands(tt.pkgName, tt.version, tt.ecosystem)
			if result[tt.cmdKey] != tt.wantCmd {
				t.Errorf("generateUpgradeCommands()[%q] = %q, want %q", tt.cmdKey, result[tt.cmdKey], tt.wantCmd)
			}
		})
	}
}

func TestGetKnownWorkarounds(t *testing.T) {
	tests := []struct {
		cveID     string
		wantCount int
		wantFirst string
	}{
		// Log4Shell - has 3 workarounds
		{"CVE-2021-44228", 3, "JndiLookup クラスを削除"},
		// Log4j bypass
		{"CVE-2021-45046", 1, "log4j2.noFormatMsgLookup を設定"},
		// Spring4Shell
		{"CVE-2022-22965", 1, "disallowedFields を設定"},
		// Unknown CVE - empty
		{"CVE-9999-99999", 0, ""},
		// Empty CVE
		{"", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.cveID, func(t *testing.T) {
			result := getKnownWorkarounds(tt.cveID)

			if len(result) != tt.wantCount {
				t.Errorf("getKnownWorkarounds(%q) returned %d workarounds, want %d", tt.cveID, len(result), tt.wantCount)
			}

			if tt.wantCount > 0 && result[0].Description != tt.wantFirst {
				t.Errorf("getKnownWorkarounds(%q)[0].Description = %q, want %q", tt.cveID, result[0].Description, tt.wantFirst)
			}
		})
	}
}

func TestGetKnownWorkarounds_Log4Shell(t *testing.T) {
	workarounds := getKnownWorkarounds("CVE-2021-44228")

	// Verify all Log4Shell workarounds have commands
	for i, w := range workarounds {
		if w.Command == "" {
			t.Errorf("workaround[%d] has empty command", i)
		}
		if w.Description == "" {
			t.Errorf("workaround[%d] has empty description", i)
		}
	}

	// Check specific workarounds exist
	foundEnvVar := false
	for _, w := range workarounds {
		if w.Command == "LOG4J_FORMAT_MSG_NO_LOOKUPS=true" {
			foundEnvVar = true
		}
	}
	if !foundEnvVar {
		t.Error("expected to find LOG4J_FORMAT_MSG_NO_LOOKUPS workaround")
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{5, 5, 5},
		{0, 10, 0},
		{-1, 1, -1},
		{-5, -3, -5},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.want {
			t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.want)
		}
	}
}
