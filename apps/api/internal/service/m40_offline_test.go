package service

import (
	"context"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// TestRemediationByCVE_Offline verifies the M40 Phase D fix: in offline mode
// GetRemediationByCVE degrades to a graceful non-error response (known
// workarounds + manual) instead of the misleading "not found" error, and never
// touches the OSV client or the DB (nil deps are safe here).
func TestRemediationByCVE_Offline(t *testing.T) {
	svc := NewRemediationService(nil, nil, "", true /* offline */)

	resp, err := svc.GetRemediationByCVE(context.Background(), "CVE-2021-44228", "log4j-core", "2.14.1")
	if err != nil {
		t.Fatalf("offline GetRemediationByCVE returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("offline GetRemediationByCVE returned nil response; want graceful degrade")
	}
	if resp.CVEID != "CVE-2021-44228" {
		t.Errorf("CVEID = %q, want CVE-2021-44228", resp.CVEID)
	}
	if resp.Remediation.Type != "manual" {
		t.Errorf("Remediation.Type = %q, want manual", resp.Remediation.Type)
	}
	if resp.Remediation.Commands == nil {
		t.Error("Remediation.Commands should be a non-nil (empty) map")
	}
}

// TestCLIService_WithOSVBaseURL_TrimsTrailingSlash locks the M40 Phase D fix so
// the CLI OSV batch path cannot post to ".../v1//querybatch" when an operator
// sets SBOMHUB_OSV_URL with a trailing slash — matching client.OSVClient.
func TestCLIService_WithOSVBaseURL_TrimsTrailingSlash(t *testing.T) {
	// default (no override) keeps the shared default base
	def := NewCLIService(nil, nil, nil)
	if def.osvBaseURL != client.DefaultOSVBaseURL {
		t.Errorf("default osvBaseURL = %q, want %q", def.osvBaseURL, client.DefaultOSVBaseURL)
	}

	s := NewCLIService(nil, nil, nil).WithOSVBaseURL("https://mirror.internal/v1/")
	if s.osvBaseURL != "https://mirror.internal/v1" {
		t.Errorf("osvBaseURL = %q, want trailing slash trimmed", s.osvBaseURL)
	}

	// empty override is ignored (keeps default)
	s2 := NewCLIService(nil, nil, nil).WithOSVBaseURL("")
	if s2.osvBaseURL != client.DefaultOSVBaseURL {
		t.Errorf("empty override should keep default, got %q", s2.osvBaseURL)
	}
}
