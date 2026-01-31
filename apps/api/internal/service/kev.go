package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	kevCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// KEVService handles KEV catalog synchronization
type KEVService struct {
	client  *http.Client
	kevRepo *repository.KEVRepository
}

// NewKEVService creates a new KEVService
func NewKEVService(kevRepo *repository.KEVRepository) *KEVService {
	return &KEVService{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		kevRepo: kevRepo,
	}
}

// KEVCatalogResponse represents the CISA KEV catalog JSON response
type KEVCatalogResponse struct {
	CatalogVersion string                `json:"catalogVersion"`
	DateReleased   string                `json:"dateReleased"`
	Count          int                   `json:"count"`
	Vulnerabilities []KEVVulnerability   `json:"vulnerabilities"`
}

// KEVVulnerability represents a single vulnerability in the KEV catalog
type KEVVulnerability struct {
	CVEID                     string `json:"cveID"`
	VendorProject             string `json:"vendorProject"`
	Product                   string `json:"product"`
	VulnerabilityName         string `json:"vulnerabilityName"`
	DateAdded                 string `json:"dateAdded"`
	ShortDescription          string `json:"shortDescription"`
	RequiredAction            string `json:"requiredAction"`
	DueDate                   string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                     string `json:"notes"`
}

// SyncCatalog fetches and synchronizes the KEV catalog
func (s *KEVService) SyncCatalog(ctx context.Context) (*model.KEVSyncResult, error) {
	// Create sync log
	syncLog, err := s.kevRepo.CreateSyncLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create sync log: %w", err)
	}

	// Fetch catalog
	catalog, err := s.fetchCatalog(ctx)
	if err != nil {
		s.finishSyncLog(ctx, syncLog, model.KEVSyncStatusFailed, err.Error(), nil)
		return nil, fmt.Errorf("failed to fetch KEV catalog: %w", err)
	}

	slog.Info("Fetched KEV catalog", "version", catalog.CatalogVersion, "count", catalog.Count)

	// Get existing CVE IDs for comparison
	existingCVEs, err := s.kevRepo.GetAllCVEIDs(ctx)
	if err != nil {
		s.finishSyncLog(ctx, syncLog, model.KEVSyncStatusFailed, err.Error(), nil)
		return nil, fmt.Errorf("failed to get existing CVE IDs: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, cve := range existingCVEs {
		existingSet[cve] = true
	}

	// Process vulnerabilities
	result := &model.KEVSyncResult{
		CatalogVersion: catalog.CatalogVersion,
	}

	for _, v := range catalog.Vulnerabilities {
		entry, err := s.parseVulnerability(v)
		if err != nil {
			slog.Warn("Failed to parse KEV entry", "cve", v.CVEID, "error", err)
			continue
		}

		if err := s.kevRepo.UpsertEntry(ctx, entry); err != nil {
			slog.Error("Failed to upsert KEV entry", "cve", v.CVEID, "error", err)
			continue
		}

		if existingSet[v.CVEID] {
			result.UpdatedEntries++
		} else {
			result.NewEntries++
		}
		result.TotalProcessed++
	}

	// Sync vulnerability table KEV status
	affected, err := s.kevRepo.SyncVulnerabilitiesKEVStatus(ctx)
	if err != nil {
		slog.Error("Failed to sync vulnerabilities KEV status", "error", err)
	} else {
		slog.Info("Synced vulnerabilities KEV status", "affected", affected)
	}

	// Update sync settings
	settings, err := s.kevRepo.GetSyncSettings(ctx)
	if err == nil && settings != nil {
		now := time.Now()
		settings.LastSyncAt = &now
		settings.LastCatalogVersion = catalog.CatalogVersion
		settings.TotalEntries = catalog.Count
		if err := s.kevRepo.UpdateSyncSettings(ctx, settings); err != nil {
			slog.Error("Failed to update sync settings", "error", err)
		}
	}

	// Complete sync log
	s.finishSyncLog(ctx, syncLog, model.KEVSyncStatusSuccess, "", result)

	slog.Info("KEV sync completed",
		"new", result.NewEntries,
		"updated", result.UpdatedEntries,
		"total", result.TotalProcessed,
		"version", result.CatalogVersion,
	)

	return result, nil
}

func (s *KEVService) fetchCatalog(ctx context.Context) (*KEVCatalogResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", kevCatalogURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SBOMHub/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV API returned status %d", resp.StatusCode)
	}

	var catalog KEVCatalogResponse
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("failed to decode KEV response: %w", err)
	}

	return &catalog, nil
}

func (s *KEVService) parseVulnerability(v KEVVulnerability) (*model.KEVEntry, error) {
	dateAdded, err := time.Parse("2006-01-02", v.DateAdded)
	if err != nil {
		return nil, fmt.Errorf("invalid date_added format: %w", err)
	}

	dueDate, err := time.Parse("2006-01-02", v.DueDate)
	if err != nil {
		return nil, fmt.Errorf("invalid due_date format: %w", err)
	}

	ransomwareUse := v.KnownRansomwareCampaignUse == "Known"

	return &model.KEVEntry{
		ID:                 uuid.New(),
		CVEID:              v.CVEID,
		VendorProject:      v.VendorProject,
		Product:            v.Product,
		VulnerabilityName:  v.VulnerabilityName,
		ShortDescription:   v.ShortDescription,
		RequiredAction:     v.RequiredAction,
		DateAdded:          dateAdded,
		DueDate:            dueDate,
		KnownRansomwareUse: ransomwareUse,
		Notes:              v.Notes,
	}, nil
}

func (s *KEVService) finishSyncLog(ctx context.Context, log *model.KEVSyncLog, status model.KEVSyncStatus, errMsg string, result *model.KEVSyncResult) {
	now := time.Now()
	log.CompletedAt = &now
	log.Status = string(status)
	log.ErrorMessage = errMsg

	if result != nil {
		log.NewEntries = result.NewEntries
		log.UpdatedEntries = result.UpdatedEntries
		log.TotalProcessed = result.TotalProcessed
		log.CatalogVersion = result.CatalogVersion
	}

	if err := s.kevRepo.UpdateSyncLog(ctx, log); err != nil {
		slog.Error("Failed to update sync log", "error", err)
	}
}

// GetSyncSettings gets the current sync settings
func (s *KEVService) GetSyncSettings(ctx context.Context) (*model.KEVSyncSettings, error) {
	return s.kevRepo.GetSyncSettings(ctx)
}

// GetLatestSyncLog gets the most recent sync log
func (s *KEVService) GetLatestSyncLog(ctx context.Context) (*model.KEVSyncLog, error) {
	return s.kevRepo.GetLatestSyncLog(ctx)
}

// GetCatalog lists KEV entries with pagination
func (s *KEVService) GetCatalog(ctx context.Context, limit, offset int) ([]model.KEVEntry, int, error) {
	return s.kevRepo.List(ctx, limit, offset)
}

// GetByCVE gets a KEV entry by CVE ID
func (s *KEVService) GetByCVE(ctx context.Context, cveID string) (*model.KEVEntry, error) {
	return s.kevRepo.GetByCVE(ctx, cveID)
}

// CheckCVEInKEV checks if a CVE is in the KEV catalog
func (s *KEVService) CheckCVEInKEV(ctx context.Context, cveID string) (bool, error) {
	entry, err := s.kevRepo.GetByCVE(ctx, cveID)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// GetKEVVulnerabilities gets all KEV vulnerabilities for a project
func (s *KEVService) GetKEVVulnerabilities(ctx context.Context, projectID uuid.UUID) ([]model.Vulnerability, error) {
	return s.kevRepo.GetKEVVulnerabilities(ctx, projectID)
}

// GetStats returns KEV catalog statistics
func (s *KEVService) GetStats(ctx context.Context) (*KEVStats, error) {
	count, err := s.kevRepo.Count(ctx)
	if err != nil {
		return nil, err
	}

	settings, err := s.kevRepo.GetSyncSettings(ctx)
	if err != nil {
		return nil, err
	}

	latestLog, err := s.kevRepo.GetLatestSyncLog(ctx)
	if err != nil {
		return nil, err
	}

	return &KEVStats{
		TotalEntries:      count,
		LastSyncAt:        settings.LastSyncAt,
		CatalogVersion:    settings.LastCatalogVersion,
		LatestSyncStatus:  latestLog,
	}, nil
}

// KEVStats represents KEV catalog statistics
type KEVStats struct {
	TotalEntries     int               `json:"total_entries"`
	LastSyncAt       *time.Time        `json:"last_sync_at,omitempty"`
	CatalogVersion   string            `json:"catalog_version,omitempty"`
	LatestSyncStatus *model.KEVSyncLog `json:"latest_sync_status,omitempty"`
}
