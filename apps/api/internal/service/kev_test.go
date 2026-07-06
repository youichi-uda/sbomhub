package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKEVRepository implements KEVRepositoryInterface for testing
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

// Implement KEVRepositoryInterface
func (m *mockKEVRepository) GetByCVE(ctx context.Context, cveID string) (*model.KEVEntry, error) {
	entry, ok := m.entries[cveID]
	if !ok {
		return nil, nil
	}
	return entry, nil
}

func (m *mockKEVRepository) UpsertEntry(ctx context.Context, entry *model.KEVEntry) error {
	m.entries[entry.CVEID] = entry
	return nil
}

func (m *mockKEVRepository) GetAllCVEIDs(ctx context.Context) ([]string, error) {
	ids := make([]string, 0, len(m.entries))
	for id := range m.entries {
		ids = append(ids, id)
	}
	return ids, nil
}

func (m *mockKEVRepository) SyncVulnerabilitiesKEVStatus(ctx context.Context) (int, error) {
	return len(m.entries), nil
}

func (m *mockKEVRepository) GetSyncSettings(ctx context.Context) (*model.KEVSyncSettings, error) {
	return m.syncSettings, nil
}

func (m *mockKEVRepository) UpdateSyncSettings(ctx context.Context, settings *model.KEVSyncSettings) error {
	m.syncSettings = settings
	return nil
}

func (m *mockKEVRepository) CreateSyncLog(ctx context.Context) (*model.KEVSyncLog, error) {
	log := &model.KEVSyncLog{
		ID:        uuid.New(),
		StartedAt: time.Now(),
		Status:    "in_progress",
	}
	m.syncLogs = append(m.syncLogs, log)
	return log, nil
}

func (m *mockKEVRepository) UpdateSyncLog(ctx context.Context, log *model.KEVSyncLog) error {
	for i, l := range m.syncLogs {
		if l.ID == log.ID {
			m.syncLogs[i] = log
			return nil
		}
	}
	return nil
}

func (m *mockKEVRepository) GetLatestSyncLog(ctx context.Context) (*model.KEVSyncLog, error) {
	if len(m.syncLogs) == 0 {
		return nil, nil
	}
	return m.syncLogs[len(m.syncLogs)-1], nil
}

func (m *mockKEVRepository) List(ctx context.Context, limit, offset int) ([]model.KEVEntry, int, error) {
	entries := make([]model.KEVEntry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, *e)
	}
	// Simple pagination
	total := len(entries)
	if offset >= len(entries) {
		return []model.KEVEntry{}, total, nil
	}
	end := offset + limit
	if end > len(entries) {
		end = len(entries)
	}
	return entries[offset:end], total, nil
}

func (m *mockKEVRepository) GetKEVVulnerabilities(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	// Return empty list for testing
	return []model.Vulnerability{}, nil
}

func (m *mockKEVRepository) Count(ctx context.Context) (int, error) {
	return len(m.entries), nil
}

// Helper to add entries to mock
func (m *mockKEVRepository) addEntry(entry *model.KEVEntry) {
	m.entries[entry.CVEID] = entry
}

func TestKEVService_CheckCVEInKEV(t *testing.T) {
	tests := []struct {
		name     string
		cveID    string
		setup    func(*mockKEVRepository)
		expected bool
	}{
		{
			name:  "CVE in KEV catalog",
			cveID: "CVE-2021-44228", // Log4Shell - definitely in KEV
			setup: func(repo *mockKEVRepository) {
				repo.addEntry(&model.KEVEntry{
					ID:                 uuid.New(),
					CVEID:              "CVE-2021-44228",
					VendorProject:      "Apache",
					Product:            "Log4j2",
					VulnerabilityName:  "Apache Log4j2 Remote Code Execution Vulnerability",
					DateAdded:          time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
					DueDate:            time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC),
					KnownRansomwareUse: true,
				})
			},
			expected: true,
		},
		{
			name:     "CVE not in KEV catalog",
			cveID:    "CVE-9999-99999", // Non-existent CVE
			setup:    func(repo *mockKEVRepository) {},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockKEVRepository()
			tt.setup(repo)

			// Create service with mock repository
			service := NewKEVServiceWithRepo(repo, "", false)

			// Call actual service method
			result, err := service.CheckCVEInKEV(context.Background(), tt.cveID)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, result, "CVE in KEV status mismatch")
		})
	}
}

func TestKEVService_GetByCVE(t *testing.T) {
	tests := []struct {
		name      string
		cveID     string
		setup     func(*mockKEVRepository)
		expectNil bool
		validate  func(*testing.T, *model.KEVEntry)
	}{
		{
			name:  "CVE exists in KEV",
			cveID: "CVE-2021-44228",
			setup: func(repo *mockKEVRepository) {
				repo.addEntry(&model.KEVEntry{
					ID:                 uuid.New(),
					CVEID:              "CVE-2021-44228",
					VendorProject:      "Apache",
					Product:            "Log4j2",
					VulnerabilityName:  "Apache Log4j2 Remote Code Execution Vulnerability",
					KnownRansomwareUse: true,
				})
			},
			expectNil: false,
			validate: func(t *testing.T, entry *model.KEVEntry) {
				assert.Equal(t, "CVE-2021-44228", entry.CVEID)
				assert.Equal(t, "Apache", entry.VendorProject)
				assert.Equal(t, "Log4j2", entry.Product)
				assert.True(t, entry.KnownRansomwareUse)
			},
		},
		{
			name:      "CVE does not exist",
			cveID:     "CVE-0000-00000",
			setup:     func(repo *mockKEVRepository) {},
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockKEVRepository()
			tt.setup(repo)

			service := NewKEVServiceWithRepo(repo, "", false)
			entry, err := service.GetByCVE(context.Background(), tt.cveID)
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, entry)
			} else {
				require.NotNil(t, entry)
				if tt.validate != nil {
					tt.validate(t, entry)
				}
			}
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
				CVEID:                      "CVE-2021-44228",
				VendorProject:              "Apache",
				Product:                    "Log4j2",
				VulnerabilityName:          "Apache Log4j2 Remote Code Execution Vulnerability",
				DateAdded:                  "2021-12-10",
				ShortDescription:           "RCE vulnerability",
				RequiredAction:             "Apply updates",
				DueDate:                    "2021-12-24",
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "Critical",
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
				CVEID:                      "CVE-2021-45046",
				VendorProject:              "Apache",
				Product:                    "Log4j2",
				VulnerabilityName:          "DoS Vulnerability",
				DateAdded:                  "2021-12-15",
				ShortDescription:           "DoS",
				RequiredAction:             "Apply updates",
				DueDate:                    "2021-12-29",
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

func TestKEVService_GetSyncSettings(t *testing.T) {
	repo := newMockKEVRepository()
	service := NewKEVServiceWithRepo(repo, "", false)

	settings, err := service.GetSyncSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, settings)

	assert.True(t, settings.Enabled)
	assert.Equal(t, 24, settings.SyncIntervalHours)
}

func TestKEVService_GetCatalog(t *testing.T) {
	repo := newMockKEVRepository()

	// Add test entries
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

	service := NewKEVServiceWithRepo(repo, "", false)

	entries, total, err := service.GetCatalog(context.Background(), 10, 0)
	require.NoError(t, err)

	assert.Equal(t, 2, total)
	assert.Len(t, entries, 2)
}

// TestKEVService_SyncCatalog_InjectedURL proves that s.baseURL is actually used
// to fetch the catalog: an httptest server returns a canned CISA KEV catalog
// and we assert SyncCatalog parsed and persisted it.
func TestKEVService_SyncCatalog_InjectedURL(t *testing.T) {
	const body = `{
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
				"shortDescription": "RCE",
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
				"shortDescription": "DoS",
				"requiredAction": "Apply updates per vendor instructions.",
				"dueDate": "2021-12-29",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": ""
			}
		]
	}`

	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	repo := newMockKEVRepository()
	service := NewKEVServiceWithRepo(repo, server.URL, false)

	result, err := service.SyncCatalog(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, hit, "expected the injected server URL to be hit")
	assert.Equal(t, "2024.01.15", result.CatalogVersion)
	assert.Equal(t, 2, result.TotalProcessed)
	assert.Equal(t, 2, result.NewEntries)

	// Verify the parsed data landed in the repo.
	entry, err := repo.GetByCVE(context.Background(), "CVE-2021-44228")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "Apache", entry.VendorProject)
	assert.True(t, entry.KnownRansomwareUse)
}

// TestKEVService_Offline asserts that offline mode short-circuits SyncCatalog
// before any HTTP call. The server handler fails the test if it is reached.
func TestKEVService_Offline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("offline mode must not make HTTP calls")
	}))
	defer server.Close()

	repo := newMockKEVRepository()
	service := NewKEVServiceWithRepo(repo, server.URL, true)

	result, err := service.SyncCatalog(context.Background())
	require.NoError(t, err)
	assert.Nil(t, result, "SyncCatalog in offline mode should return nil result")

	// The guard returns before creating a sync log, so none should exist.
	latest, err := repo.GetLatestSyncLog(context.Background())
	require.NoError(t, err)
	assert.Nil(t, latest, "offline mode should not create a sync log")
}
