package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// IPAService handles IPA integration business logic
type IPAService struct {
	ipaRepo   *repository.IPARepository
	ipaClient *client.IPAClient
}

// NewIPAService creates a new IPAService
func NewIPAService(ipaRepo *repository.IPARepository) *IPAService {
	return &IPAService{
		ipaRepo:   ipaRepo,
		ipaClient: client.NewIPAClient(),
	}
}

// IPAAnnouncementListResponse represents paginated IPA announcements
type IPAAnnouncementListResponse struct {
	Announcements []model.IPAAnnouncement `json:"announcements"`
	Total         int                     `json:"total"`
	Limit         int                     `json:"limit"`
	Offset        int                     `json:"offset"`
}

// ListAnnouncements lists IPA announcements with pagination
func (s *IPAService) ListAnnouncements(ctx context.Context, category string, limit, offset int) (*IPAAnnouncementListResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	announcements, total, err := s.ipaRepo.ListAnnouncements(ctx, category, limit, offset)
	if err != nil {
		return nil, err
	}

	return &IPAAnnouncementListResponse{
		Announcements: announcements,
		Total:         total,
		Limit:         limit,
		Offset:        offset,
	}, nil
}

// GetAnnouncementsByCVE gets IPA announcements related to a CVE
func (s *IPAService) GetAnnouncementsByCVE(ctx context.Context, cveID string) ([]model.IPAAnnouncement, error) {
	return s.ipaRepo.GetAnnouncementsByCVE(ctx, cveID)
}

// GetSyncSettings gets IPA sync settings for a tenant
func (s *IPAService) GetSyncSettings(ctx context.Context, tenantID uuid.UUID) (*model.IPASyncSettings, error) {
	settings, err := s.ipaRepo.GetSyncSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Return default settings if none exist
	if settings == nil {
		return &model.IPASyncSettings{
			TenantID:       tenantID,
			Enabled:        true,
			NotifyOnNew:    true,
			NotifySeverity: []string{"CRITICAL", "HIGH"},
		}, nil
	}

	return settings, nil
}

// UpdateSyncSettingsInput represents input for updating sync settings
type UpdateSyncSettingsInput struct {
	Enabled        bool     `json:"enabled"`
	NotifyOnNew    bool     `json:"notify_on_new"`
	NotifySeverity []string `json:"notify_severity"`
}

// UpdateSyncSettings updates IPA sync settings for a tenant
func (s *IPAService) UpdateSyncSettings(ctx context.Context, tenantID uuid.UUID, input UpdateSyncSettingsInput) (*model.IPASyncSettings, error) {
	// Get existing settings
	existing, err := s.ipaRepo.GetSyncSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var settings *model.IPASyncSettings
	if existing == nil {
		settings = &model.IPASyncSettings{
			ID:       uuid.New(),
			TenantID: tenantID,
		}
	} else {
		settings = existing
	}

	settings.Enabled = input.Enabled
	settings.NotifyOnNew = input.NotifyOnNew
	settings.NotifySeverity = input.NotifySeverity

	if err := s.ipaRepo.UpsertSyncSettings(ctx, settings); err != nil {
		return nil, err
	}

	return settings, nil
}

// SyncResult represents the result of a sync operation
type SyncResult struct {
	NewAnnouncements     int `json:"new_announcements"`
	UpdatedAnnouncements int `json:"updated_announcements"`
	TotalProcessed       int `json:"total_processed"`
}

// SyncAnnouncements fetches and stores IPA announcements
func (s *IPAService) SyncAnnouncements(ctx context.Context) (*SyncResult, error) {
	result := &SyncResult{}

	// Fetch security alerts
	alerts, err := s.ipaClient.FetchSecurityAlerts(ctx)
	if err != nil {
		// Log error but continue with vulnerability notes
		// In production, use proper logging
	} else {
		for _, item := range alerts {
			processed, isNew, err := s.processAnnouncement(ctx, item)
			if err != nil {
				continue
			}
			if processed {
				result.TotalProcessed++
				if isNew {
					result.NewAnnouncements++
				} else {
					result.UpdatedAnnouncements++
				}
			}
		}
	}

	// Fetch vulnerability notes
	notes, err := s.ipaClient.FetchVulnerabilityNotes(ctx)
	if err != nil {
		// Log error but continue
	} else {
		for _, item := range notes {
			processed, isNew, err := s.processAnnouncement(ctx, item)
			if err != nil {
				continue
			}
			if processed {
				result.TotalProcessed++
				if isNew {
					result.NewAnnouncements++
				} else {
					result.UpdatedAnnouncements++
				}
			}
		}
	}

	return result, nil
}

// processAnnouncement processes a single announcement
func (s *IPAService) processAnnouncement(ctx context.Context, item client.IPAFeedItem) (processed bool, isNew bool, err error) {
	// Check if already exists
	existing, err := s.ipaRepo.GetAnnouncementByIPAID(ctx, item.IPAID)
	if err != nil {
		return false, false, err
	}

	announcement := &model.IPAAnnouncement{
		IPAID:       item.IPAID,
		Title:       item.Title,
		TitleJa:     item.Title, // RSS typically returns Japanese title
		Description: item.Description,
		Category:    item.Category,
		Severity:    item.Severity,
		SourceURL:   item.Link,
		RelatedCVEs: item.RelatedCVEs,
		PublishedAt: item.PublishedAt,
	}

	if existing == nil {
		announcement.ID = uuid.New()
		isNew = true
	} else {
		announcement.ID = existing.ID
		isNew = false
	}

	if err := s.ipaRepo.CreateAnnouncement(ctx, announcement); err != nil {
		return false, false, err
	}

	return true, isNew, nil
}

// GetRecentAnnouncements gets announcements published after a given time
func (s *IPAService) GetRecentAnnouncements(ctx context.Context, since time.Time) ([]model.IPAAnnouncement, error) {
	return s.ipaRepo.GetRecentAnnouncements(ctx, since)
}

// SyncForTenant syncs announcements and updates tenant's last sync time
func (s *IPAService) SyncForTenant(ctx context.Context, tenantID uuid.UUID) (*SyncResult, error) {
	// First sync all announcements
	result, err := s.SyncAnnouncements(ctx)
	if err != nil {
		return nil, err
	}

	// Update tenant's last sync time
	if err := s.ipaRepo.UpdateLastSyncAt(ctx, tenantID); err != nil {
		// Log but don't fail
	}

	return result, nil
}
