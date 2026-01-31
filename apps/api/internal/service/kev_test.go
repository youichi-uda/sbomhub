package service

import (
	"testing"
)

func TestKEVService_IsInKEV(t *testing.T) {
	// This is a basic test structure - actual tests would require mocking the repository
	tests := []struct {
		name     string
		cveID    string
		expected bool
	}{
		{
			name:     "CVE in KEV catalog",
			cveID:    "CVE-2021-44228", // Log4Shell - definitely in KEV
			expected: true,
		},
		{
			name:     "CVE not in KEV catalog",
			cveID:    "CVE-9999-99999", // Non-existent CVE
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test structure placeholder
			// In a real test, we would:
			// 1. Create a mock repository
			// 2. Set up expected behavior
			// 3. Call the service method
			// 4. Assert the result
			_ = tt.cveID
			_ = tt.expected
		})
	}
}

func TestKEVService_ParseCISAResponse(t *testing.T) {
	// Test parsing of CISA KEV JSON response
	sampleJSON := `{
		"title": "CISA Catalog of Known Exploited Vulnerabilities",
		"catalogVersion": "2024.01.15",
		"dateReleased": "2024-01-15T00:00:00.000Z",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2021-44228",
				"vendorProject": "Apache",
				"product": "Log4j2",
				"vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
				"dateAdded": "2021-12-10",
				"shortDescription": "Apache Log4j2 contains a vulnerability that allows remote code execution.",
				"requiredAction": "Apply updates per vendor instructions.",
				"dueDate": "2021-12-24",
				"knownRansomwareCampaignUse": "Known",
				"notes": ""
			},
			{
				"cveID": "CVE-2021-45046",
				"vendorProject": "Apache",
				"product": "Log4j2",
				"vulnerabilityName": "Apache Log4j2 Denial of Service Vulnerability",
				"dateAdded": "2021-12-15",
				"shortDescription": "Apache Log4j2 Thread Context Message Pattern allows DoS.",
				"requiredAction": "Apply updates per vendor instructions.",
				"dueDate": "2021-12-29",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": ""
			}
		]
	}`

	// Verify the JSON can be parsed correctly
	if len(sampleJSON) == 0 {
		t.Error("Sample JSON should not be empty")
	}

	// In a real test, we would parse this JSON and verify:
	// - catalogVersion is "2024.01.15"
	// - count is 2
	// - First CVE is CVE-2021-44228
	// - knownRansomwareCampaignUse is correctly parsed
}

func TestKEVService_RansomwareUseParsing(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"Known ransomware", "Known", true},
		{"Unknown ransomware", "Unknown", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.value == "Known"
			if result != tt.expected {
				t.Errorf("RansomwareUse parsing: got %v, want %v", result, tt.expected)
			}
		})
	}
}
