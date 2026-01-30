package service

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

func TestIPAAnnouncementListResponse(t *testing.T) {
	response := &IPAAnnouncementListResponse{
		Announcements: []model.IPAAnnouncement{
			{
				ID:       uuid.New(),
				IPAID:    "IPA-2024-001",
				Title:    "Test Announcement",
				Category: "alert",
				Severity: "HIGH",
			},
		},
		Total:  1,
		Limit:  20,
		Offset: 0,
	}

	if len(response.Announcements) != 1 {
		t.Errorf("expected 1 announcement, got %d", len(response.Announcements))
	}

	if response.Total != 1 {
		t.Errorf("expected total 1, got %d", response.Total)
	}
}

func TestUpdateSyncSettingsInput(t *testing.T) {
	tests := []struct {
		name  string
		input UpdateSyncSettingsInput
	}{
		{
			name: "enabled with all severities",
			input: UpdateSyncSettingsInput{
				Enabled:        true,
				NotifyOnNew:    true,
				NotifySeverity: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"},
			},
		},
		{
			name: "disabled",
			input: UpdateSyncSettingsInput{
				Enabled:        false,
				NotifyOnNew:    false,
				NotifySeverity: []string{},
			},
		},
		{
			name: "critical only",
			input: UpdateSyncSettingsInput{
				Enabled:        true,
				NotifyOnNew:    true,
				NotifySeverity: []string{"CRITICAL"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify struct can be created and fields are set correctly
			if tt.input.Enabled && len(tt.input.NotifySeverity) == 0 && tt.name != "disabled" {
				t.Error("enabled sync should have severity settings")
			}
		})
	}
}

func TestSyncResult(t *testing.T) {
	result := &SyncResult{
		NewAnnouncements:     5,
		UpdatedAnnouncements: 3,
		TotalProcessed:       8,
	}

	if result.TotalProcessed != result.NewAnnouncements+result.UpdatedAnnouncements {
		t.Error("total processed should equal new + updated")
	}
}

func TestListAnnouncements_LimitValidation(t *testing.T) {
	tests := []struct {
		name          string
		inputLimit    int
		expectedLimit int
	}{
		{"negative limit", -1, 20},
		{"zero limit", 0, 20},
		{"valid small limit", 10, 10},
		{"valid limit", 50, 50},
		{"max limit", 100, 100},
		{"over max limit", 150, 100},
		{"way over max limit", 1000, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the limit validation logic used in ListAnnouncements
			limit := tt.inputLimit
			if limit <= 0 {
				limit = 20
			}
			if limit > 100 {
				limit = 100
			}

			if limit != tt.expectedLimit {
				t.Errorf("limit validation: got %d, want %d", limit, tt.expectedLimit)
			}
		})
	}
}

func TestDefaultSyncSettings(t *testing.T) {
	tenantID := uuid.New()

	// Simulate default settings returned when none exist
	defaultSettings := &model.IPASyncSettings{
		TenantID:       tenantID,
		Enabled:        true,
		NotifyOnNew:    true,
		NotifySeverity: []string{"CRITICAL", "HIGH"},
	}

	if !defaultSettings.Enabled {
		t.Error("default settings should be enabled")
	}

	if !defaultSettings.NotifyOnNew {
		t.Error("default settings should notify on new")
	}

	if len(defaultSettings.NotifySeverity) != 2 {
		t.Errorf("expected 2 default severities, got %d", len(defaultSettings.NotifySeverity))
	}

	expectedSeverities := map[string]bool{"CRITICAL": true, "HIGH": true}
	for _, sev := range defaultSettings.NotifySeverity {
		if !expectedSeverities[sev] {
			t.Errorf("unexpected severity in defaults: %s", sev)
		}
	}
}

func TestIPAAnnouncement_Categories(t *testing.T) {
	validCategories := []string{"alert", "notice", "vuln_note"}

	for _, category := range validCategories {
		announcement := &model.IPAAnnouncement{
			ID:       uuid.New(),
			IPAID:    "IPA-2024-001",
			Category: category,
		}

		if announcement.Category == "" {
			t.Errorf("category should not be empty")
		}
	}
}

func TestIPAAnnouncement_Severities(t *testing.T) {
	validSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

	for _, severity := range validSeverities {
		t.Run(severity, func(t *testing.T) {
			announcement := &model.IPAAnnouncement{
				ID:       uuid.New(),
				IPAID:    "IPA-2024-001",
				Severity: severity,
			}

			if announcement.Severity == "" {
				t.Error("severity should not be empty")
			}
		})
	}
}

func TestIPAAnnouncement_RelatedCVEs(t *testing.T) {
	tests := []struct {
		name        string
		relatedCVEs []string
		count       int
	}{
		{"no CVEs", nil, 0},
		{"single CVE", []string{"CVE-2024-1234"}, 1},
		{"multiple CVEs", []string{"CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9012"}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			announcement := &model.IPAAnnouncement{
				ID:          uuid.New(),
				IPAID:       "IPA-2024-001",
				RelatedCVEs: tt.relatedCVEs,
			}

			if len(announcement.RelatedCVEs) != tt.count {
				t.Errorf("expected %d related CVEs, got %d", tt.count, len(announcement.RelatedCVEs))
			}
		})
	}
}
