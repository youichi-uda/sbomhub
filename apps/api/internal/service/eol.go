package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	endoflifeAPIBaseURL = "https://endoflife.date/api"
)

// EOLService handles EOL catalog synchronization
type EOLService struct {
	client  *http.Client
	eolRepo *repository.EOLRepository
}

// NewEOLService creates a new EOLService
func NewEOLService(eolRepo *repository.EOLRepository) *EOLService {
	return &EOLService{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		eolRepo: eolRepo,
	}
}

// EOLAllProductsResponse represents the list of all products from endoflife.date
type EOLAllProductsResponse []string

// EOLCycleResponse represents a single cycle from endoflife.date API
// Note: eol, lts, support can be bool or date string
type EOLCycleResponse struct {
	Cycle           interface{} `json:"cycle"`
	ReleaseDate     string      `json:"releaseDate,omitempty"`
	EOL             interface{} `json:"eol,omitempty"`       // Can be bool or date string
	Latest          string      `json:"latest,omitempty"`
	LatestReleaseDate string    `json:"latestReleaseDate,omitempty"`
	LTS             interface{} `json:"lts,omitempty"`       // Can be bool or date string
	Support         interface{} `json:"support,omitempty"`   // Can be bool or date string
	Discontinued    interface{} `json:"discontinued,omitempty"`
	Link            string      `json:"link,omitempty"`
}

// SyncCatalog synchronizes the EOL catalog from endoflife.date
func (s *EOLService) SyncCatalog(ctx context.Context) (*model.EOLSyncResult, error) {
	// Create sync log
	syncLog, err := s.eolRepo.CreateSyncLog(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create sync log: %w", err)
	}

	result := &model.EOLSyncResult{}

	// Get all products we want to sync (from our pre-seeded list)
	existingProducts, err := s.eolRepo.GetAllProductNames(ctx)
	if err != nil {
		s.finishSyncLog(ctx, syncLog, model.EOLSyncStatusFailed, err.Error(), nil)
		return nil, fmt.Errorf("failed to get existing products: %w", err)
	}

	slog.Info("Starting EOL sync", "products_to_sync", len(existingProducts))

	// Sync each product
	for _, productName := range existingProducts {
		productResult, err := s.SyncProduct(ctx, productName)
		if err != nil {
			slog.Warn("Failed to sync EOL product", "product", productName, "error", err)
			continue
		}
		if productResult != nil {
			result.ProductsSynced++
			result.CyclesSynced += productResult.CyclesSynced
		}
	}

	// Update sync settings
	settings, err := s.eolRepo.GetSyncSettings(ctx)
	if err == nil && settings != nil {
		now := time.Now()
		settings.LastSyncAt = &now
		productCount, _ := s.eolRepo.CountProducts(ctx)
		cycleCount, _ := s.eolRepo.CountCycles(ctx)
		settings.TotalProducts = productCount
		settings.TotalCycles = cycleCount
		if err := s.eolRepo.UpdateSyncSettings(ctx, settings); err != nil {
			slog.Error("Failed to update sync settings", "error", err)
		}
	}

	// Complete sync log
	s.finishSyncLog(ctx, syncLog, model.EOLSyncStatusSuccess, "", result)

	slog.Info("EOL sync completed",
		"products_synced", result.ProductsSynced,
		"cycles_synced", result.CyclesSynced,
	)

	return result, nil
}

// SyncProduct syncs a single product from endoflife.date
func (s *EOLService) SyncProduct(ctx context.Context, productName string) (*model.EOLSyncResult, error) {
	// Fetch cycles from API
	cycles, err := s.fetchProductCycles(ctx, productName)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch cycles for %s: %w", productName, err)
	}

	// Get or create product
	product, err := s.eolRepo.GetProductByName(ctx, productName)
	if err != nil {
		return nil, err
	}
	if product == nil {
		return nil, fmt.Errorf("product not found: %s", productName)
	}

	result := &model.EOLSyncResult{}

	// Process cycles
	for _, cycleResp := range cycles {
		cycle, err := s.parseCycle(product.ID, cycleResp)
		if err != nil {
			slog.Warn("Failed to parse EOL cycle", "product", productName, "error", err)
			continue
		}

		if err := s.eolRepo.UpsertCycle(ctx, cycle); err != nil {
			slog.Error("Failed to upsert EOL cycle", "product", productName, "cycle", cycle.Cycle, "error", err)
			continue
		}
		result.CyclesSynced++
	}

	// Update product total cycles
	product.TotalCycles = len(cycles)
	if err := s.eolRepo.UpsertProduct(ctx, product); err != nil {
		slog.Error("Failed to update product", "product", productName, "error", err)
	}

	result.ProductsSynced = 1
	return result, nil
}

func (s *EOLService) fetchProductCycles(ctx context.Context, productName string) ([]EOLCycleResponse, error) {
	url := fmt.Sprintf("%s/%s.json", endoflifeAPIBaseURL, productName)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("product not found in endoflife.date: %s", productName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife.date API returned status %d", resp.StatusCode)
	}

	var cycles []EOLCycleResponse
	if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return cycles, nil
}

func (s *EOLService) parseCycle(productID uuid.UUID, resp EOLCycleResponse) (*model.EOLProductCycle, error) {
	cycle := &model.EOLProductCycle{
		ID:        uuid.New(),
		ProductID: productID,
	}

	// Parse cycle (can be string or number)
	switch v := resp.Cycle.(type) {
	case string:
		cycle.Cycle = v
	case float64:
		cycle.Cycle = fmt.Sprintf("%g", v)
	default:
		return nil, fmt.Errorf("invalid cycle type: %T", resp.Cycle)
	}

	// Parse release date
	if resp.ReleaseDate != "" {
		t, err := time.Parse("2006-01-02", resp.ReleaseDate)
		if err == nil {
			cycle.ReleaseDate = &t
		}
	}

	// Parse EOL (can be bool or date string)
	cycle.EOLDate, cycle.IsEOL = s.parseDateOrBool(resp.EOL)

	// Parse support end date
	cycle.SupportEndDate, _ = s.parseDateOrBool(resp.Support)

	// For EOS, use support end date if available, otherwise use EOL date
	if cycle.SupportEndDate != nil {
		cycle.EOSDate = cycle.SupportEndDate
	} else {
		cycle.EOSDate = cycle.EOLDate
	}

	// Parse LTS
	_, cycle.IsLTS = s.parseDateOrBool(resp.LTS)
	if !cycle.IsLTS {
		// If LTS is a date, it means it's LTS
		if resp.LTS != nil {
			switch v := resp.LTS.(type) {
			case string:
				if v != "" && v != "false" {
					cycle.IsLTS = true
				}
			case bool:
				cycle.IsLTS = v
			}
		}
	}

	// Parse discontinued
	if resp.Discontinued != nil {
		switch v := resp.Discontinued.(type) {
		case bool:
			cycle.Discontinued = v
		case string:
			cycle.Discontinued = v == "true"
		}
	}

	cycle.LatestVersion = resp.Latest
	cycle.Link = resp.Link

	return cycle, nil
}

// parseDateOrBool parses a value that can be either a date string or a boolean
func (s *EOLService) parseDateOrBool(val interface{}) (*time.Time, bool) {
	if val == nil {
		return nil, false
	}

	switch v := val.(type) {
	case bool:
		// If EOL is true but no date, set to a very old date to indicate EOL
		if v {
			// Return nil date but true for isEOL
			return nil, true
		}
		return nil, false
	case string:
		if v == "" || v == "false" {
			return nil, false
		}
		if v == "true" {
			return nil, true
		}
		// Try to parse as date
		t, err := time.Parse("2006-01-02", v)
		if err == nil {
			isEOL := t.Before(time.Now())
			return &t, isEOL
		}
	}

	return nil, false
}

func (s *EOLService) finishSyncLog(ctx context.Context, log *model.EOLSyncLog, status model.EOLSyncStatus, errMsg string, result *model.EOLSyncResult) {
	now := time.Now()
	log.CompletedAt = &now
	log.Status = string(status)
	log.ErrorMessage = errMsg

	if result != nil {
		log.ProductsSynced = result.ProductsSynced
		log.CyclesSynced = result.CyclesSynced
		log.ComponentsUpdated = result.ComponentsUpdated
	}

	if err := s.eolRepo.UpdateSyncLog(ctx, log); err != nil {
		slog.Error("Failed to update sync log", "error", err)
	}
}

// MatchComponentToEOL attempts to match a component to an EOL product and determine its status
func (s *EOLService) MatchComponentToEOL(ctx context.Context, name, version, purl string) (*model.ComponentEOLInfo, error) {
	info := &model.ComponentEOLInfo{
		Status: model.EOLStatusUnknown,
	}

	// Get mappings
	mappings, err := s.eolRepo.GetMappings(ctx)
	if err != nil {
		return info, err
	}

	// Try to find a matching mapping
	var matchedMapping *model.EOLComponentMapping
	nameLower := strings.ToLower(name)

	for _, m := range mappings {
		pattern := strings.ToLower(m.ComponentPattern)

		// Check for exact match or pattern match
		if nameLower == pattern || strings.Contains(nameLower, pattern) {
			// Check PURL type if specified
			if m.PurlType != "" && purl != "" {
				if !strings.Contains(strings.ToLower(purl), m.PurlType) {
					continue
				}
			}
			matchedMapping = &m
			break
		}

		// Try regex match
		if strings.Contains(pattern, "*") || strings.Contains(pattern, "^") {
			re, err := regexp.Compile(pattern)
			if err == nil && re.MatchString(nameLower) {
				matchedMapping = &m
				break
			}
		}
	}

	if matchedMapping == nil {
		return info, nil
	}

	// Get product
	product, err := s.eolRepo.GetProductByID(ctx, matchedMapping.ProductID)
	if err != nil || product == nil {
		return info, err
	}

	info.ProductID = &product.ID
	info.ProductName = product.Title

	// Find matching cycle
	cycle, err := s.eolRepo.FindMatchingCycle(ctx, product.ID, version)
	if err != nil {
		return info, err
	}

	if cycle == nil {
		// No matching cycle found, but we know the product
		return info, nil
	}

	info.CycleID = &cycle.ID
	info.CycleVersion = cycle.Cycle
	info.EOLDate = cycle.EOLDate
	info.EOSDate = cycle.EOSDate
	info.LatestVersion = cycle.LatestVersion
	info.IsLTS = cycle.IsLTS
	info.ReleaseDate = cycle.ReleaseDate
	info.SupportEndDate = cycle.SupportEndDate

	// Determine status
	now := time.Now()

	if cycle.Discontinued {
		info.Status = model.EOLStatusEOL
	} else if cycle.IsEOL || (cycle.EOLDate != nil && cycle.EOLDate.Before(now)) {
		info.Status = model.EOLStatusEOL
	} else if cycle.EOSDate != nil && cycle.EOSDate.Before(now) {
		info.Status = model.EOLStatusEOS
	} else if cycle.SupportEndDate != nil && cycle.SupportEndDate.Before(now) {
		info.Status = model.EOLStatusEOS
	} else {
		info.Status = model.EOLStatusActive
	}

	return info, nil
}

// UpdateProjectComponentsEOL updates EOL status for all components in a project
func (s *EOLService) UpdateProjectComponentsEOL(ctx context.Context, projectID uuid.UUID) (int, error) {
	// Get components that need checking
	components, err := s.eolRepo.GetComponentsForEOLCheck(ctx, projectID, 1000)
	if err != nil {
		return 0, err
	}

	updated := 0
	for _, comp := range components {
		info, err := s.MatchComponentToEOL(ctx, comp.Name, comp.Version, comp.Purl)
		if err != nil {
			slog.Warn("Failed to match component to EOL", "component", comp.Name, "error", err)
			continue
		}

		if err := s.eolRepo.UpdateComponentEOLStatus(ctx, comp.ID, info); err != nil {
			slog.Error("Failed to update component EOL status", "component", comp.Name, "error", err)
			continue
		}
		updated++
	}

	return updated, nil
}

// GetEOLSummary gets EOL summary for a project
func (s *EOLService) GetEOLSummary(ctx context.Context, projectID uuid.UUID) (*model.EOLSummary, error) {
	return s.eolRepo.GetEOLSummary(ctx, projectID)
}

// GetSyncSettings gets the current sync settings
func (s *EOLService) GetSyncSettings(ctx context.Context) (*model.EOLSyncSettings, error) {
	return s.eolRepo.GetSyncSettings(ctx)
}

// GetLatestSyncLog gets the most recent sync log
func (s *EOLService) GetLatestSyncLog(ctx context.Context) (*model.EOLSyncLog, error) {
	return s.eolRepo.GetLatestSyncLog(ctx)
}

// GetProducts lists EOL products with pagination
func (s *EOLService) GetProducts(ctx context.Context, limit, offset int) ([]model.EOLProduct, int, error) {
	return s.eolRepo.ListProducts(ctx, limit, offset)
}

// GetProductByName gets a product by name with its cycles
func (s *EOLService) GetProductByName(ctx context.Context, name string) (*model.EOLProduct, []model.EOLProductCycle, error) {
	product, err := s.eolRepo.GetProductByName(ctx, name)
	if err != nil || product == nil {
		return nil, nil, err
	}

	cycles, err := s.eolRepo.GetCyclesByProduct(ctx, product.ID)
	if err != nil {
		return product, nil, err
	}

	return product, cycles, nil
}

// GetStats returns EOL catalog statistics
func (s *EOLService) GetStats(ctx context.Context) (*model.EOLStats, error) {
	productCount, err := s.eolRepo.CountProducts(ctx)
	if err != nil {
		return nil, err
	}

	cycleCount, err := s.eolRepo.CountCycles(ctx)
	if err != nil {
		return nil, err
	}

	settings, err := s.eolRepo.GetSyncSettings(ctx)
	if err != nil {
		return nil, err
	}

	latestLog, err := s.eolRepo.GetLatestSyncLog(ctx)
	if err != nil {
		return nil, err
	}

	return &model.EOLStats{
		TotalProducts:    productCount,
		TotalCycles:      cycleCount,
		LastSyncAt:       settings.LastSyncAt,
		LatestSyncStatus: latestLog,
	}, nil
}
