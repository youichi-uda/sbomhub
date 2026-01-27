package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestIsValidPolicyType(t *testing.T) {
	tests := []struct {
		name       string
		policyType model.LicensePolicyType
		valid      bool
	}{
		{"allowed is valid", model.LicensePolicyAllowed, true},
		{"denied is valid", model.LicensePolicyDenied, true},
		{"review is valid", model.LicensePolicyReview, true},
		{"empty is invalid", model.LicensePolicyType(""), false},
		{"unknown is invalid", model.LicensePolicyType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPolicyType(tt.policyType)
			if result != tt.valid {
				t.Errorf("isValidPolicyType(%s) = %v, want %v", tt.policyType, result, tt.valid)
			}
		})
	}
}

func TestNormalizeLicenseID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Standard SPDX IDs should remain unchanged
		{"MIT", "MIT"},
		{"Apache-2.0", "Apache-2.0"},
		{"GPL-3.0-only", "GPL-3.0-only"},
		{"BSD-3-Clause", "BSD-3-Clause"},
		
		// Common variations should be normalized
		{"MIT License", "MIT"},
		{"Apache 2.0", "Apache-2.0"},
		{"Apache 2", "Apache-2.0"},
		{"Apache-2", "Apache-2.0"},
		
		// GPL variations
		{"GPL-2.0", "GPL-2.0-only"},
		{"GPL-3.0", "GPL-3.0-only"},
		{"LGPL-2.1", "LGPL-2.1-only"},
		{"LGPL-3.0", "LGPL-3.0-only"},
		
		// BSD variations
		{"BSD 2-Clause", "BSD-2-Clause"},
		{"BSD 3-Clause", "BSD-3-Clause"},
		{"BSD-2", "BSD-2-Clause"},
		{"BSD-3", "BSD-3-Clause"},
		
		// CC0 variations
		{"CC0", "CC0-1.0"},
		{"Creative Commons Zero", "CC0-1.0"},
		
		// Whitespace handling
		{"  MIT  ", "MIT"},
		{" Apache-2.0 ", "Apache-2.0"},
		
		// Unknown licenses pass through
		{"Custom-License", "Custom-License"},
		{"Proprietary", "Proprietary"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeLicenseID(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeLicenseID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
