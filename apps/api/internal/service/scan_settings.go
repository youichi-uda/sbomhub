package service

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ScanSettingsService manages scan settings
type ScanSettingsService struct {
	db *sql.DB
}

// NewScanSettingsService creates a new scan settings service
func NewScanSettingsService(db *sql.DB) *ScanSettingsService {
	return &ScanSettingsService{db: db}
}

// ScanSettings represents scan configuration
type ScanSettings struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Enabled        bool       `json:"enabled"`
	ScheduleType   string     `json:"schedule_type"`
	ScheduleHour   int        `json:"schedule_hour"`
	ScheduleDay    *int       `json:"schedule_day"`
	NotifyCritical bool       `json:"notify_critical"`
	NotifyHigh     bool       `json:"notify_high"`
	NotifyMedium   bool       `json:"notify_medium"`
	NotifyLow      bool       `json:"notify_low"`
	LastScanAt     *time.Time `json:"last_scan_at"`
	NextScanAt     *time.Time `json:"next_scan_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// ScanLog represents a scan execution log
type ScanLog struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	StartedAt          time.Time  `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at"`
	Status             string     `json:"status"`
	ProjectsScanned    int        `json:"projects_scanned"`
	NewVulnerabilities int        `json:"new_vulnerabilities"`
	ErrorMessage       *string    `json:"error_message"`
	CreatedAt          time.Time  `json:"created_at"`
}

// Get retrieves scan settings for a tenant
func (s *ScanSettingsService) Get(ctx context.Context, tenantID uuid.UUID) (*ScanSettings, error) {
	var settings ScanSettings
	var scheduleDay sql.NullInt64
	var lastScanAt, nextScanAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, enabled, schedule_type, schedule_hour, schedule_day,
		       notify_critical, notify_high, notify_medium, notify_low,
		       last_scan_at, next_scan_at, created_at, updated_at
		FROM scan_settings
		WHERE tenant_id = $1
	`, tenantID).Scan(
		&settings.ID, &settings.TenantID, &settings.Enabled,
		&settings.ScheduleType, &settings.ScheduleHour, &scheduleDay,
		&settings.NotifyCritical, &settings.NotifyHigh, &settings.NotifyMedium, &settings.NotifyLow,
		&lastScanAt, &nextScanAt, &settings.CreatedAt, &settings.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Return defaults
		return &ScanSettings{
			TenantID:       tenantID,
			Enabled:        false,
			ScheduleType:   "daily",
			ScheduleHour:   6,
			NotifyCritical: true,
			NotifyHigh:     true,
			NotifyMedium:   false,
			NotifyLow:      false,
		}, nil
	}
	if err != nil {
		return nil, err
	}

	if scheduleDay.Valid {
		day := int(scheduleDay.Int64)
		settings.ScheduleDay = &day
	}
	if lastScanAt.Valid {
		settings.LastScanAt = &lastScanAt.Time
	}
	if nextScanAt.Valid {
		settings.NextScanAt = &nextScanAt.Time
	}

	return &settings, nil
}

// UpdateInput represents update request
type UpdateScanSettingsInput struct {
	Enabled        *bool   `json:"enabled"`
	ScheduleType   *string `json:"schedule_type"`
	ScheduleHour   *int    `json:"schedule_hour"`
	ScheduleDay    *int    `json:"schedule_day"`
	NotifyCritical *bool   `json:"notify_critical"`
	NotifyHigh     *bool   `json:"notify_high"`
	NotifyMedium   *bool   `json:"notify_medium"`
	NotifyLow      *bool   `json:"notify_low"`
}

// Update updates or creates scan settings
func (s *ScanSettingsService) Update(ctx context.Context, tenantID uuid.UUID, input UpdateScanSettingsInput) (*ScanSettings, error) {
	// Get existing or create new
	existing, err := s.Get(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if input.Enabled != nil {
		existing.Enabled = *input.Enabled
	}
	if input.ScheduleType != nil {
		if !isValidScheduleType(*input.ScheduleType) {
			return nil, fmt.Errorf("invalid schedule type: %s", *input.ScheduleType)
		}
		existing.ScheduleType = *input.ScheduleType
	}
	if input.ScheduleHour != nil {
		if *input.ScheduleHour < 0 || *input.ScheduleHour > 23 {
			return nil, fmt.Errorf("invalid schedule hour: %d", *input.ScheduleHour)
		}
		existing.ScheduleHour = *input.ScheduleHour
	}
	if input.ScheduleDay != nil {
		if *input.ScheduleDay < 0 || *input.ScheduleDay > 6 {
			return nil, fmt.Errorf("invalid schedule day: %d", *input.ScheduleDay)
		}
		existing.ScheduleDay = input.ScheduleDay
	}
	if input.NotifyCritical != nil {
		existing.NotifyCritical = *input.NotifyCritical
	}
	if input.NotifyHigh != nil {
		existing.NotifyHigh = *input.NotifyHigh
	}
	if input.NotifyMedium != nil {
		existing.NotifyMedium = *input.NotifyMedium
	}
	if input.NotifyLow != nil {
		existing.NotifyLow = *input.NotifyLow
	}

	// Calculate next scan time
	nextScan := calculateNextScan(existing.ScheduleType, existing.ScheduleHour, existing.ScheduleDay)

	// Upsert
	if existing.ID == uuid.Nil {
		existing.ID = uuid.New()
		_, err = s.db.ExecContext(ctx, `
			INSERT INTO scan_settings (id, tenant_id, enabled, schedule_type, schedule_hour, schedule_day,
			                           notify_critical, notify_high, notify_medium, notify_low, next_scan_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, existing.ID, tenantID, existing.Enabled, existing.ScheduleType, existing.ScheduleHour,
			existing.ScheduleDay, existing.NotifyCritical, existing.NotifyHigh, existing.NotifyMedium,
			existing.NotifyLow, nextScan)
	} else {
		_, err = s.db.ExecContext(ctx, `
			UPDATE scan_settings 
			SET enabled = $1, schedule_type = $2, schedule_hour = $3, schedule_day = $4,
			    notify_critical = $5, notify_high = $6, notify_medium = $7, notify_low = $8,
			    next_scan_at = $9, updated_at = NOW()
			WHERE tenant_id = $10
		`, existing.Enabled, existing.ScheduleType, existing.ScheduleHour, existing.ScheduleDay,
			existing.NotifyCritical, existing.NotifyHigh, existing.NotifyMedium, existing.NotifyLow,
			nextScan, tenantID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to save scan settings: %w", err)
	}

	existing.NextScanAt = &nextScan
	return existing, nil
}

// GetLogs retrieves scan logs for a tenant
func (s *ScanSettingsService) GetLogs(ctx context.Context, tenantID uuid.UUID, limit int) ([]ScanLog, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, started_at, completed_at, status, 
		       projects_scanned, new_vulnerabilities, error_message, created_at
		FROM scan_logs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ScanLog
	for rows.Next() {
		var log ScanLog
		var completedAt sql.NullTime
		var errorMsg sql.NullString

		if err := rows.Scan(&log.ID, &log.TenantID, &log.StartedAt, &completedAt,
			&log.Status, &log.ProjectsScanned, &log.NewVulnerabilities,
			&errorMsg, &log.CreatedAt); err != nil {
			continue
		}

		if completedAt.Valid {
			log.CompletedAt = &completedAt.Time
		}
		if errorMsg.Valid {
			log.ErrorMessage = &errorMsg.String
		}

		logs = append(logs, log)
	}

	return logs, nil
}

func isValidScheduleType(t string) bool {
	switch t {
	case "hourly", "daily", "weekly":
		return true
	}
	return false
}

func calculateNextScan(scheduleType string, hour int, day *int) time.Time {
	now := time.Now()

	switch scheduleType {
	case "hourly":
		return now.Add(1 * time.Hour).Truncate(time.Hour)
	case "daily":
		next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
		if next.Before(now) {
			next = next.Add(24 * time.Hour)
		}
		return next
	case "weekly":
		targetDay := 1 // Monday by default
		if day != nil {
			targetDay = *day
		}
		daysUntil := (7 + targetDay - int(now.Weekday())) % 7
		if daysUntil == 0 && now.Hour() >= hour {
			daysUntil = 7
		}
		return time.Date(now.Year(), now.Month(), now.Day()+daysUntil, hour, 0, 0, 0, now.Location())
	}

	return now.Add(24 * time.Hour)
}
