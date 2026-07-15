package service

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureServiceSlog redirects the process-global default slog logger into a
// buffer for one test (restored via t.Cleanup) so Warn-line contracts can be
// asserted. Tests using it must not run in parallel.
func captureServiceSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// osvLinkedRemediationFixture is a well-formed OSV record whose own ID IS the
// requested CVE (linked) and which carries a fixed version — the positive
// control for the M45 Wave 1 C2 linkage guard.
const osvLinkedRemediationFixture = `{
	"id": "CVE-2025-7777",
	"summary": "linked test vuln",
	"severity": [{"type": "CVSS_V3", "score": "7.5"}],
	"affected": [
		{
			"package": {"name": "libfoo", "ecosystem": "npm"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
			"versions": ["1.0.0", "1.1.0"]
		}
	]
}`

// osvUnlinkedRemediationFixture is a mis-routed / canned record: its ID is an
// unrelated GO- advisory and its aliases do NOT name the requested CVE, yet it
// carries a (foreign) fixed version 9.9.9 that must NOT be surfaced as upgrade
// guidance for the requested CVE (M45 Wave 1 C2).
const osvUnlinkedRemediationFixture = `{
	"id": "GO-2025-0001",
	"summary": "canned unrelated record",
	"aliases": ["CVE-9999-0000"],
	"affected": [
		{
			"package": {"name": "libfoo", "ecosystem": "npm"},
			"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]
		}
	]
}`

// TestGetRemediationByCVE_404ReturnsNotFound pins the M45 Wave 1 C1 trap fix:
// a definitive OSV 404 must map to the "not found in OSV" message (which the
// handler renders as 404), NOT the "failed to fetch" (500-class) message it
// would have become once the client started returning a typed sentinel.
func TestGetRemediationByCVE_404ReturnsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	svc := NewRemediationService(nil, nil, server.URL, false)
	resp, err := svc.GetRemediationByCVE(context.Background(), "CVE-2025-0404", "libfoo", "1.0.0")
	if err == nil {
		t.Fatalf("GetRemediationByCVE on 404 err = nil (resp=%+v), want a not-found error", resp)
	}
	if !strings.Contains(err.Error(), "not found in OSV") {
		t.Errorf("GetRemediationByCVE on 404 err = %q, want it to contain %q (not the failed-to-fetch message)", err.Error(), "not found in OSV")
	}
	if strings.Contains(err.Error(), "failed to fetch") {
		t.Errorf("GetRemediationByCVE on 404 err = %q, must NOT be the transient failed-to-fetch message", err.Error())
	}
}

// TestGetRemediationByCVE_TransientErrorSurfacesFetchFailure guards the other
// side: a 5xx is transient and must surface as "failed to fetch from OSV",
// distinct from the definitive not-found path.
func TestGetRemediationByCVE_TransientErrorSurfacesFetchFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewRemediationService(nil, nil, server.URL, false)
	_, err := svc.GetRemediationByCVE(context.Background(), "CVE-2025-0500", "libfoo", "1.0.0")
	if err == nil {
		t.Fatal("GetRemediationByCVE on 500 err = nil, want a fetch-failure error")
	}
	if !strings.Contains(err.Error(), "failed to fetch") {
		t.Errorf("GetRemediationByCVE on 500 err = %q, want it to contain %q", err.Error(), "failed to fetch")
	}
	if strings.Contains(err.Error(), "not found in OSV") {
		t.Errorf("GetRemediationByCVE on 500 err = %q, must NOT be the definitive not-found message", err.Error())
	}
}

// TestGetRemediationByCVE_UnlinkedBodyDowngradedToNotFound pins the M45 Wave 1
// C2 linkage降格: a retrieved body that does not vouch for the requested CVE
// (mis-routed / canned mirror) is treated as not-found — its foreign fixed
// version is never surfaced as upgrade guidance — and emits one operator Warn.
func TestGetRemediationByCVE_UnlinkedBodyDowngradedToNotFound(t *testing.T) {
	logs := captureServiceSlog(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvUnlinkedRemediationFixture))
	}))
	defer server.Close()

	svc := NewRemediationService(nil, nil, server.URL, false)
	resp, err := svc.GetRemediationByCVE(context.Background(), "CVE-2025-7777", "libfoo", "1.0.0")
	if err == nil {
		t.Fatalf("GetRemediationByCVE on an unlinked body err = nil (resp=%+v), want a not-found error", resp)
	}
	if !strings.Contains(err.Error(), "not found in OSV") {
		t.Errorf("unlinked-body err = %q, want the not-found message", err.Error())
	}
	if !strings.Contains(logs.String(), "does not vouch for the requested CVE") {
		t.Errorf("expected an unlinked-record Warn in logs, got: %s", logs.String())
	}
}

// TestGetRemediationByCVE_LinkedBodyUpgrades is the positive control: a linked
// body (ID == requested CVE) with a fixed version passes the linkage guard and
// yields an upgrade remediation.
func TestGetRemediationByCVE_LinkedBodyUpgrades(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(osvLinkedRemediationFixture))
	}))
	defer server.Close()

	svc := NewRemediationService(nil, nil, server.URL, false)
	resp, err := svc.GetRemediationByCVE(context.Background(), "CVE-2025-7777", "libfoo", "1.0.0")
	if err != nil {
		t.Fatalf("GetRemediationByCVE on a linked body returned error: %v", err)
	}
	if resp.Remediation.Type != "upgrade" {
		t.Errorf("Remediation.Type = %q, want upgrade", resp.Remediation.Type)
	}
	if resp.Remediation.TargetVersion != "1.2.3" {
		t.Errorf("Remediation.TargetVersion = %q, want 1.2.3", resp.Remediation.TargetVersion)
	}
}

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
