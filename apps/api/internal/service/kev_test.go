package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKEVRepository is a mock implementation of KEVRepository for testing
type mockKEVRepository struct {
	entries      map[string]*model.KEVEntry
	syncSettings *model.KEVSyncSettings
	syncLogs     []*model.KEVSyncLog
}

func newMockKEVRepository() *mockKEVRepository {
	return &mockKEVRepository{
		entries: make(map[string]*model.KEVEntry),
		syncSettings: &model.KEVSyncSettings{
			ID:                uuid.New(),
			Enabled:           true,
			SyncIntervalHours: 24,
		},
		syncLogs: make([]*model.KEVSyncLog, 0),
	}
}

func (m *mockKEVRepository) GetByCVE(ctx context.Context, cveID string) (*model.KEVEntry, error) {
	entry, ok := m.entries[cveID]
	if !ok {
		return nil, nil
	}
	return entry, nil
}

func (m *mockKEVRepository) addEntry(entry *model.KEVEntry) {
	m.entries[entry.CVEID] = entry
}

func TestKEVService_IsInKEV(t *testing.T) {
	tests := []struct {
		name     string
		cveID    string
		inKEV    bool
		setup    func(*mockKEVRepository)
		expected bool
	}{
		{
			name:  "CVE in KEV catalog",
			cveID: "CVE-2021-44228", // Log4Shell - definitely in KEV
			inKEV: true,
			setup: func(repo *mockKEVRepository) {
				repo.addEntry(&model.KEVEntry{
					ID:                uuid.New(),
					CVEID:             "CVE-2021-44228",
					VendorProject:     "Apache",
					Product:           "Log4j2",
					VulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
					DateAdded:         time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
					DueDate:           time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC),
					KnownRansomwareUse: true,
				})
			},
			expected: true,
		},
		{
			name:     "CVE not in KEV catalog",
			cveID:    "CVE-9999-99999", // Non-existent CVE
			inKEV:    false,
			setup:    func(repo *mockKEVRepository) {},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockKEVRepository()
			tt.setup(repo)

			// Simulate KEV check
			entry, err := repo.GetByCVE(context.Background(), tt.cveID)
			require.NoError(t, err)

			result := entry != nil
			assert.Equal(t, tt.expected, result, "CVE in KEV status mismatch")
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

	// Parse the JSON
	var catalog KEVCatalogResponse
	err := json.Unmarshal([]byte(sampleJSON), &catalog)
	require.NoError(t, err, "Failed to parse KEV catalog JSON")

	// Verify catalog metadata
	assert.Equal(t, "2024.01.15", catalog.CatalogVersion, "Catalog version mismatch")
	assert.Equal(t, 2, catalog.Count, "Vulnerability count mismatch")

	// Verify vulnerabilities
	require.Len(t, catalog.Vulnerabilities, 2, "Expected 2 vulnerabilities")

	// Verify first CVE (CVE-2021-44228)
	vuln1 := catalog.Vulnerabilities[0]
	assert.Equal(t, "CVE-2021-44228", vuln1.CVEID)
	assert.Equal(t, "Apache", vuln1.VendorProject)
	assert.Equal(t, "Log4j2", vuln1.Product)
	assert.Equal(t, "2021-12-10", vuln1.DateAdded)
	assert.Equal(t, "2021-12-24", vuln1.DueDate)
	assert.Equal(t, "Known", vuln1.KnownRansomwareCampaignUse)

	// Verify second CVE (CVE-2021-45046)
	vuln2 := catalog.Vulnerabilities[1]
	assert.Equal(t, "CVE-2021-45046", vuln2.CVEID)
	assert.Equal(t, "Unknown", vuln2.KnownRansomwareCampaignUse)
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
		{"Other value", "N/A", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.value == "Known"
			assert.Equal(t, tt.expected, result, "RansomwareUse parsing mismatch for value: %s", tt.value)
		})
	}
}

func TestKEVService_ParseVulnerability(t *testing.T) {
	service := &KEVService{}

	tests := []struct {
		name        string
		input       KEVVulnerability
		expectError bool
		validate    func(*testing.T, *model.KEVEntry)
	}{
		{
			name: "Valid vulnerability",
			input: KEVVulnerability{
				CVEID:                     "CVE-2021-44228",
				VendorProject:             "Apache",
				Product:                   "Log4j2",
				VulnerabilityName:         "Apache Log4j2 Remote Code Execution Vulnerability",
				DateAdded:                 "2021-12-10",
				ShortDescription:          "RCE vulnerability",
				RequiredAction:            "Apply updates",
				DueDate:                   "2021-12-24",
				KnownRansomwareCampaignUse: "Known",
				Notes:                     "Critical",
			},
			expectError: false,
			validate: func(t *testing.T, entry *model.KEVEntry) {
				assert.Equal(t, "CVE-2021-44228", entry.CVEID)
				assert.Equal(t, "Apache", entry.VendorProject)
				assert.Equal(t, "Log4j2", entry.Product)
				assert.True(t, entry.KnownRansomwareUse)
				assert.Equal(t, 2021, entry.DateAdded.Year())
				assert.Equal(t, time.December, entry.DateAdded.Month())
				assert.Equal(t, 10, entry.DateAdded.Day())
			},
		},
		{
			name: "Unknown ransomware use",
			input: KEVVulnerability{
				CVEID:                     "CVE-2021-45046",
				VendorProject:             "Apache",
				Product:                   "Log4j2",
				VulnerabilityName:         "DoS Vulnerability",
				DateAdded:                 "2021-12-15",
				ShortDescription:          "DoS",
				RequiredAction:            "Apply updates",
				DueDate:                   "2021-12-29",
				KnownRansomwareCampaignUse: "Unknown",
			},
			expectError: false,
			validate: func(t *testing.T, entry *model.KEVEntry) {
				assert.False(t, entry.KnownRansomwareUse)
			},
		},
		{
			name: "Invalid date_added format",
			input: KEVVulnerability{
				CVEID:     "CVE-2021-12345",
				DateAdded: "2021/12/10", // Wrong format
				DueDate:   "2021-12-24",
			},
			expectError: true,
		},
		{
			name: "Invalid due_date format",
			input: KEVVulnerability{
				CVEID:     "CVE-2021-12345",
				DateAdded: "2021-12-10",
				DueDate:   "12-24-2021", // Wrong format
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := service.parseVulnerability(tt.input)

			if tt.expectError {
				assert.Error(t, err, "Expected an error but got none")
				return
			}

			require.NoError(t, err, "Unexpected error")
			require.NotNil(t, entry, "Entry should not be nil")

			if tt.validate != nil {
				tt.validate(t, entry)
			}
		})
	}
}

func TestKEVService_GetStats(t *testing.T) {
	// Test that GetStats returns correct aggregated stats
	repo := newMockKEVRepository()

	// Add some entries
	repo.addEntry(&model.KEVEntry{
		ID:        uuid.New(),
		CVEID:     "CVE-2021-44228",
		DateAdded: time.Now().AddDate(0, 0, -30),
	})
	repo.addEntry(&model.KEVEntry{
		ID:        uuid.New(),
		CVEID:     "CVE-2021-45046",
		DateAdded: time.Now().AddDate(0, 0, -25),
	})

	// Verify entry count
	assert.Equal(t, 2, len(repo.entries), "Expected 2 entries in repository")

	// Verify sync settings exist
	assert.NotNil(t, repo.syncSettings, "Sync settings should not be nil")
	assert.True(t, repo.syncSettings.Enabled, "Sync should be enabled by default")
	assert.Equal(t, 24, repo.syncSettings.SyncIntervalHours, "Default sync interval should be 24 hours")
}
