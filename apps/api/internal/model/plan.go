package model

import (
	"time"

	"github.com/google/uuid"
)

// PlanLimits represents the limits for a subscription plan
type PlanLimits struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Plan               string                 `json:"plan" db:"plan"`
	MaxUsers           int                    `json:"max_users" db:"max_users"`
	MaxProjects        int                    `json:"max_projects" db:"max_projects"`
	MaxSBOMsPerProject int                    `json:"max_sboms_per_project" db:"max_sboms_per_project"`
	MaxAPIKeys         int                    `json:"max_api_keys" db:"max_api_keys"`
	APIRateLimit       int                    `json:"api_rate_limit" db:"api_rate_limit"`
	Features           map[string]interface{} `json:"features" db:"features"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
}

// Plan name constants
const (
	PlanFree       = "free"
	PlanStarter    = "starter"
	PlanPro        = "pro"
	PlanTeam       = "team"
	PlanEnterprise = "enterprise"
)

// DefaultPlanLimits returns the default limits for each plan
// Used when database lookup is not available
func DefaultPlanLimits(plan string) PlanLimits {
	switch plan {
	case PlanFree:
		return PlanLimits{
			Plan:               PlanFree,
			MaxUsers:           1,
			MaxProjects:        2,
			MaxSBOMsPerProject: 5,
			MaxAPIKeys:         2,
			APIRateLimit:       60,
			Features: map[string]interface{}{
				"vulnerability_alerts": true,
				"vex_support":          false,
				"license_policies":     false,
				"slack_integration":    false,
				"discord_integration":  false,
				"api_access":           false,
				"audit_logs":           false,
			},
		}
	case PlanStarter:
		return PlanLimits{
			Plan:               PlanStarter,
			MaxUsers:           3,
			MaxProjects:        10,
			MaxSBOMsPerProject: 50,
			MaxAPIKeys:         10,
			APIRateLimit:       300,
			Features: map[string]interface{}{
				"vulnerability_alerts": true,
				"vex_support":          true,
				"license_policies":     true,
				"slack_integration":    true,
				"discord_integration":  true,
				"api_access":           true,
				"audit_logs":           false,
			},
		}
	case PlanPro:
		return PlanLimits{
			Plan:               PlanPro,
			MaxUsers:           10,
			MaxProjects:        -1, // unlimited
			MaxSBOMsPerProject: 200,
			MaxAPIKeys:         50,
			APIRateLimit:       1000,
			Features: map[string]interface{}{
				"vulnerability_alerts": true,
				"vex_support":          true,
				"license_policies":     true,
				"slack_integration":    true,
				"discord_integration":  true,
				"api_access":           true,
				"audit_logs":           true,
			},
		}
	case PlanTeam:
		return PlanLimits{
			Plan:               PlanTeam,
			MaxUsers:           30,
			MaxProjects:        -1, // unlimited
			MaxSBOMsPerProject: -1, // unlimited
			MaxAPIKeys:         -1, // unlimited
			APIRateLimit:       3000,
			Features: map[string]interface{}{
				"vulnerability_alerts": true,
				"vex_support":          true,
				"license_policies":     true,
				"slack_integration":    true,
				"discord_integration":  true,
				"api_access":           true,
				"audit_logs":           true,
				"sso":                  false,
			},
		}
	case PlanEnterprise:
		return PlanLimits{
			Plan:               PlanEnterprise,
			MaxUsers:           -1, // unlimited
			MaxProjects:        -1, // unlimited
			MaxSBOMsPerProject: -1, // unlimited
			MaxAPIKeys:         -1, // unlimited
			APIRateLimit:       -1, // unlimited
			Features: map[string]interface{}{
				"vulnerability_alerts":  true,
				"vex_support":           true,
				"license_policies":      true,
				"slack_integration":     true,
				"discord_integration":   true,
				"api_access":            true,
				"audit_logs":            true,
				"sso":                   true,
				"custom_integrations":   true,
			},
		}
	default:
		return DefaultPlanLimits(PlanFree)
	}
}

// IsUnlimited returns true if the value represents unlimited (-1)
func IsUnlimited(value int) bool {
	return value == -1
}

// CheckLimit returns true if the current count is within the limit
func CheckLimit(current, limit int) bool {
	if IsUnlimited(limit) {
		return true
	}
	return current < limit
}

// HasFeature checks if the plan has a specific feature enabled
func (pl *PlanLimits) HasFeature(feature string) bool {
	if pl.Features == nil {
		return false
	}
	if val, ok := pl.Features[feature]; ok {
		if boolVal, ok := val.(bool); ok {
			return boolVal
		}
	}
	return false
}
