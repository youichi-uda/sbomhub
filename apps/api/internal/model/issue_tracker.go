package model

import (
	"time"

	"github.com/google/uuid"
)

// TrackerType represents the type of issue tracker
type TrackerType string

const (
	TrackerTypeJira    TrackerType = "jira"
	TrackerTypeBacklog TrackerType = "backlog"
)

// AuthType represents the authentication type
type AuthType string

const (
	AuthTypeAPIToken AuthType = "api_token"
	AuthTypeOAuth    AuthType = "oauth"
)

// TicketStatus represents the local ticket status
type TicketStatus string

const (
	TicketStatusOpen       TicketStatus = "open"
	TicketStatusInProgress TicketStatus = "in_progress"
	TicketStatusResolved   TicketStatus = "resolved"
	TicketStatusClosed     TicketStatus = "closed"
)

// IssueTrackerConnection represents a connection to an issue tracker
type IssueTrackerConnection struct {
	ID                 uuid.UUID   `json:"id" db:"id"`
	TenantID           uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	TrackerType        TrackerType `json:"tracker_type" db:"tracker_type"`
	Name               string      `json:"name" db:"name"`
	BaseURL            string      `json:"base_url" db:"base_url"`
	AuthType           AuthType    `json:"auth_type" db:"auth_type"`
	AuthEmail          string      `json:"auth_email,omitempty" db:"auth_email"`
	AuthTokenEncrypted string      `json:"-" db:"auth_token_encrypted"`
	DefaultProjectKey  string      `json:"default_project_key,omitempty" db:"default_project_key"`
	DefaultIssueType   string      `json:"default_issue_type,omitempty" db:"default_issue_type"`
	IsActive           bool        `json:"is_active" db:"is_active"`
	LastSyncAt         *time.Time  `json:"last_sync_at,omitempty" db:"last_sync_at"`
	CreatedAt          time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time   `json:"updated_at" db:"updated_at"`
}

// VulnerabilityTicket represents a ticket created for a vulnerability
type VulnerabilityTicket struct {
	ID                uuid.UUID    `json:"id" db:"id"`
	TenantID          uuid.UUID    `json:"tenant_id" db:"tenant_id"`
	VulnerabilityID   uuid.UUID    `json:"vulnerability_id" db:"vulnerability_id"`
	ProjectID         uuid.UUID    `json:"project_id" db:"project_id"`
	ConnectionID      uuid.UUID    `json:"connection_id" db:"connection_id"`
	ExternalTicketID  string       `json:"external_ticket_id" db:"external_ticket_id"`
	ExternalTicketKey string       `json:"external_ticket_key,omitempty" db:"external_ticket_key"`
	ExternalTicketURL string       `json:"external_ticket_url" db:"external_ticket_url"`
	LocalStatus       TicketStatus `json:"local_status" db:"local_status"`
	ExternalStatus    string       `json:"external_status,omitempty" db:"external_status"`
	Priority          string       `json:"priority,omitempty" db:"priority"`
	Assignee          string       `json:"assignee,omitempty" db:"assignee"`
	Summary           string       `json:"summary,omitempty" db:"summary"`
	LastSyncedAt      *time.Time   `json:"last_synced_at,omitempty" db:"last_synced_at"`
	CreatedAt         time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at" db:"updated_at"`
}

// VulnerabilityTicketWithDetails includes related information
type VulnerabilityTicketWithDetails struct {
	VulnerabilityTicket
	CVEID         string `json:"cve_id"`
	Severity      string `json:"severity"`
	TrackerType   string `json:"tracker_type"`
	TrackerName   string `json:"tracker_name"`
	ProjectName   string `json:"project_name"`
	ComponentName string `json:"component_name,omitempty"`
}

// CreateTicketInput represents the input for creating a ticket
type CreateTicketInput struct {
	VulnerabilityID uuid.UUID
	ProjectID       uuid.UUID
	ConnectionID    uuid.UUID
	ProjectKey      string
	IssueType       string
	Priority        string
	Summary         string
	Description     string
	Labels          []string
}

// ExternalTicket represents ticket data from the external system
type ExternalTicket struct {
	ID       string
	Key      string
	URL      string
	Status   string
	Priority string
	Assignee string
	Summary  string
}
