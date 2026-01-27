package model

import (
	"testing"

	"github.com/google/uuid"
)

func TestLicensePolicyType_Constants(t *testing.T) {
	if LicensePolicyAllowed != "allowed" {
		t.Errorf("LicensePolicyAllowed should be 'allowed', got %s", LicensePolicyAllowed)
	}
	if LicensePolicyDenied != "denied" {
		t.Errorf("LicensePolicyDenied should be 'denied', got %s", LicensePolicyDenied)
	}
	if LicensePolicyReview != "review" {
		t.Errorf("LicensePolicyReview should be 'review', got %s", LicensePolicyReview)
	}
}

func TestCommonLicenses_Contains(t *testing.T) {
	expectedLicenses := []string{
		"MIT", "Apache-2.0", "GPL-2.0-only", "GPL-3.0-only",
		"BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0",
		"CC0-1.0", "Unlicense", "AGPL-3.0-only",
	}

	for _, license := range expectedLicenses {
		if _, ok := CommonLicenses[license]; !ok {
			t.Errorf("CommonLicenses should contain %s", license)
		}
	}
}

func TestCommonLicenses_Names(t *testing.T) {
	tests := []struct {
		id   string
		name string
	}{
		{"MIT", "MIT License"},
		{"Apache-2.0", "Apache License 2.0"},
		{"GPL-3.0-only", "GNU General Public License v3.0 only"},
		{"BSD-3-Clause", "BSD 3-Clause \"New\" or \"Revised\" License"},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			name, ok := CommonLicenses[tt.id]
			if !ok {
				t.Fatalf("license %s not found", tt.id)
			}
			if name != tt.name {
				t.Errorf("CommonLicenses[%s] = %s, want %s", tt.id, name, tt.name)
			}
		})
	}
}

func TestLicenseViolation(t *testing.T) {
	compID := uuid.New()
	violation := LicenseViolation{
		ComponentID:   compID,
		ComponentName: "test-lib",
		Version:       "1.0.0",
		License:       "GPL-3.0-only",
		PolicyType:    LicensePolicyDenied,
		Reason:        "Copyleft license not allowed",
	}

	if violation.ComponentID != compID {
		t.Error("ComponentID mismatch")
	}
	if violation.License != "GPL-3.0-only" {
		t.Error("License mismatch")
	}
	if violation.PolicyType != LicensePolicyDenied {
		t.Error("PolicyType mismatch")
	}
}
