package service

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// AuditService provides audit log operations
type AuditService struct {
	auditRepo *repository.AuditRepository
	userRepo  *repository.UserRepository
}

// NewAuditService creates a new AuditService
func NewAuditService(auditRepo *repository.AuditRepository, userRepo *repository.UserRepository) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
		userRepo:  userRepo,
	}
}

// AuditListResponse represents a paginated list of audit logs
type AuditListResponse struct {
	Logs       []AuditLogWithUser `json:"logs"`
	Total      int                `json:"total"`
	Page       int                `json:"page"`
	Limit      int                `json:"limit"`
	TotalPages int                `json:"total_pages"`
}

// AuditLogWithUser extends AuditLog with user information
type AuditLogWithUser struct {
	model.AuditLog
	UserEmail string `json:"user_email,omitempty"`
	UserName  string `json:"user_name,omitempty"`
}

// AuditFilter defines filter options for listing audit logs
type AuditFilter struct {
	Action       string     `json:"action,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	UserID       *uuid.UUID `json:"user_id,omitempty"`
	StartDate    *time.Time `json:"start_date,omitempty"`
	EndDate      *time.Time `json:"end_date,omitempty"`
	Page         int        `json:"page"`
	Limit        int        `json:"limit"`
}

// List returns a paginated list of audit logs with filtering
func (s *AuditService) List(ctx context.Context, tenantID uuid.UUID, filter AuditFilter) (*AuditListResponse, error) {
	// Set defaults
	if filter.Limit <= 0 {
		filter.Limit = 50
	}
	if filter.Limit > 100 {
		filter.Limit = 100
	}
	if filter.Page <= 0 {
		filter.Page = 1
	}

	offset := (filter.Page - 1) * filter.Limit

	// Convert to repository filter
	repoFilter := repository.AuditFilter{
		Action:       filter.Action,
		ResourceType: filter.ResourceType,
		UserID:       filter.UserID,
		StartDate:    filter.StartDate,
		EndDate:      filter.EndDate,
		Limit:        filter.Limit,
		Offset:       offset,
	}

	logs, total, err := s.auditRepo.ListWithFilter(ctx, tenantID, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	// Collect unique user IDs for enrichment
	userIDs := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.UserID != nil {
			userIDs[*log.UserID] = true
		}
	}

	// Fetch user information
	userMap := make(map[uuid.UUID]*model.User)
	for userID := range userIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err == nil && user != nil {
			userMap[userID] = user
		}
	}

	// Enrich logs with user information
	enrichedLogs := make([]AuditLogWithUser, len(logs))
	for i, log := range logs {
		enrichedLogs[i] = AuditLogWithUser{
			AuditLog: log,
		}
		if log.UserID != nil {
			if user, ok := userMap[*log.UserID]; ok {
				enrichedLogs[i].UserEmail = user.Email
				enrichedLogs[i].UserName = user.Name
			}
		}
	}

	totalPages := total / filter.Limit
	if total%filter.Limit > 0 {
		totalPages++
	}

	return &AuditListResponse{
		Logs:       enrichedLogs,
		Total:      total,
		Page:       filter.Page,
		Limit:      filter.Limit,
		TotalPages: totalPages,
	}, nil
}

// ExportCSV exports audit logs as CSV
func (s *AuditService) ExportCSV(ctx context.Context, tenantID uuid.UUID, filter AuditFilter) ([]byte, error) {
	// For export, get all matching logs (up to 10000)
	filter.Limit = 10000
	filter.Page = 1

	offset := 0
	repoFilter := repository.AuditFilter{
		Action:       filter.Action,
		ResourceType: filter.ResourceType,
		UserID:       filter.UserID,
		StartDate:    filter.StartDate,
		EndDate:      filter.EndDate,
		Limit:        filter.Limit,
		Offset:       offset,
	}

	logs, _, err := s.auditRepo.ListWithFilter(ctx, tenantID, repoFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	// Collect unique user IDs for enrichment
	userIDs := make(map[uuid.UUID]bool)
	for _, log := range logs {
		if log.UserID != nil {
			userIDs[*log.UserID] = true
		}
	}

	// Fetch user information
	userMap := make(map[uuid.UUID]*model.User)
	for userID := range userIDs {
		user, err := s.userRepo.GetByID(ctx, userID)
		if err == nil && user != nil {
			userMap[userID] = user
		}
	}

	// Generate CSV
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write BOM for Excel compatibility
	buf.Write([]byte{0xEF, 0xBB, 0xBF})

	// Write header
	header := []string{
		"ID",
		"Timestamp",
		"Action",
		"Resource Type",
		"Resource ID",
		"User ID",
		"User Email",
		"User Name",
		"IP Address",
		"User Agent",
	}
	if err := writer.Write(header); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows
	for _, log := range logs {
		userEmail := ""
		userName := ""
		if log.UserID != nil {
			if user, ok := userMap[*log.UserID]; ok {
				userEmail = user.Email
				userName = user.Name
			}
		}

		resourceID := ""
		if log.ResourceID != nil {
			resourceID = log.ResourceID.String()
		}

		userID := ""
		if log.UserID != nil {
			userID = log.UserID.String()
		}

		ipAddress := ""
		if log.IPAddress != nil {
			ipAddress = log.IPAddress.String()
		}

		row := []string{
			log.ID.String(),
			log.CreatedAt.Format(time.RFC3339),
			log.Action,
			log.ResourceType,
			resourceID,
			userID,
			userEmail,
			userName,
			ipAddress,
			log.UserAgent,
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to flush CSV: %w", err)
	}

	return buf.Bytes(), nil
}

// GetStatistics returns audit log statistics
func (s *AuditService) GetStatistics(ctx context.Context, tenantID uuid.UUID, days int) (*AuditStatistics, error) {
	if days <= 0 {
		days = 30
	}

	now := time.Now()
	start := now.AddDate(0, 0, -days)

	actionCounts, err := s.auditRepo.GetActionCounts(ctx, tenantID, start, now)
	if err != nil {
		return nil, fmt.Errorf("failed to get action counts: %w", err)
	}

	dailyCounts, err := s.auditRepo.GetDailyActionCounts(ctx, tenantID, days)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily counts: %w", err)
	}

	return &AuditStatistics{
		Period:       days,
		ActionCounts: actionCounts,
		DailyCounts:  dailyCounts,
	}, nil
}

// AuditStatistics represents audit log statistics
type AuditStatistics struct {
	Period       int                      `json:"period"`
	ActionCounts []repository.ActionCount `json:"action_counts"`
	DailyCounts  []map[string]interface{} `json:"daily_counts"`
}

// GetAvailableActions returns list of available action types for filtering
func (s *AuditService) GetAvailableActions() []ActionInfo {
	return []ActionInfo{
		// User actions
		{Action: model.ActionUserSignIn, Label: "User Sign In", Category: "user"},
		{Action: model.ActionUserSignOut, Label: "User Sign Out", Category: "user"},
		{Action: model.ActionUserCreated, Label: "User Created", Category: "user"},
		{Action: model.ActionUserUpdated, Label: "User Updated", Category: "user"},
		{Action: model.ActionUserDeleted, Label: "User Deleted", Category: "user"},
		{Action: model.ActionUserInvited, Label: "User Invited", Category: "user"},
		{Action: model.ActionUserRoleChanged, Label: "User Role Changed", Category: "user"},

		// Project actions
		{Action: model.ActionProjectCreated, Label: "Project Created", Category: "project"},
		{Action: model.ActionProjectUpdated, Label: "Project Updated", Category: "project"},
		{Action: model.ActionProjectDeleted, Label: "Project Deleted", Category: "project"},
		{Action: "project.viewed", Label: "Project Viewed", Category: "project"},

		// SBOM actions
		{Action: model.ActionSBOMUploaded, Label: "SBOM Uploaded", Category: "sbom"},
		{Action: model.ActionSBOMDeleted, Label: "SBOM Deleted", Category: "sbom"},
		{Action: model.ActionSBOMScanned, Label: "SBOM Scanned", Category: "sbom"},
		{Action: "sbom.viewed", Label: "SBOM Viewed", Category: "sbom"},

		// VEX actions
		{Action: model.ActionVEXCreated, Label: "VEX Created", Category: "vex"},
		{Action: model.ActionVEXUpdated, Label: "VEX Updated", Category: "vex"},
		{Action: model.ActionVEXDeleted, Label: "VEX Deleted", Category: "vex"},

		// API Key actions
		{Action: model.ActionAPIKeyCreated, Label: "API Key Created", Category: "apikey"},
		{Action: model.ActionAPIKeyDeleted, Label: "API Key Deleted", Category: "apikey"},
		{Action: model.ActionAPIKeyUsed, Label: "API Key Used", Category: "apikey"},

		// Settings actions
		{Action: model.ActionSettingsUpdated, Label: "Settings Updated", Category: "settings"},
	}
}

// ActionInfo represents information about an audit action
type ActionInfo struct {
	Action   string `json:"action"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

// GetAvailableResourceTypes returns list of available resource types for filtering
func (s *AuditService) GetAvailableResourceTypes() []ResourceTypeInfo {
	return []ResourceTypeInfo{
		{Type: model.ResourceUser, Label: "User"},
		{Type: model.ResourceTenant, Label: "Tenant"},
		{Type: model.ResourceProject, Label: "Project"},
		{Type: model.ResourceSBOM, Label: "SBOM"},
		{Type: model.ResourceVEX, Label: "VEX"},
		{Type: model.ResourceAPIKey, Label: "API Key"},
		{Type: model.ResourceSubscription, Label: "Subscription"},
		{Type: model.ResourceSettings, Label: "Settings"},
		{Type: "report", Label: "Report"},
		{Type: "compliance", Label: "Compliance"},
		{Type: "analytics", Label: "Analytics"},
		{Type: "integration", Label: "Integration"},
	}
}

// ResourceTypeInfo represents information about a resource type
type ResourceTypeInfo struct {
	Type  string `json:"type"`
	Label string `json:"label"`
}
