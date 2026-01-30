package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// IssueTrackerService handles issue tracker business logic
type IssueTrackerService struct {
	issueTrackerRepo *repository.IssueTrackerRepository
	vulnRepo         *repository.VulnerabilityRepository
	encryptionKey    []byte
}

// NewIssueTrackerService creates a new IssueTrackerService
func NewIssueTrackerService(
	issueTrackerRepo *repository.IssueTrackerRepository,
	vulnRepo *repository.VulnerabilityRepository,
	encryptionKey string,
) *IssueTrackerService {
	// Use a 32-byte key for AES-256
	key := make([]byte, 32)
	copy(key, []byte(encryptionKey))

	return &IssueTrackerService{
		issueTrackerRepo: issueTrackerRepo,
		vulnRepo:         vulnRepo,
		encryptionKey:    key,
	}
}

// CreateConnectionInput represents input for creating a connection
type CreateConnectionInput struct {
	TrackerType       model.TrackerType
	Name              string
	BaseURL           string
	AuthEmail         string // For Jira
	APIToken          string
	DefaultProjectKey string
	DefaultIssueType  string
}

// CreateConnection creates a new issue tracker connection
func (s *IssueTrackerService) CreateConnection(ctx context.Context, tenantID uuid.UUID, input CreateConnectionInput) (*model.IssueTrackerConnection, error) {
	// Encrypt the API token
	encryptedToken, err := s.encrypt(input.APIToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt token: %w", err)
	}

	conn := &model.IssueTrackerConnection{
		ID:                 uuid.New(),
		TenantID:           tenantID,
		TrackerType:        input.TrackerType,
		Name:               input.Name,
		BaseURL:            input.BaseURL,
		AuthType:           model.AuthTypeAPIToken,
		AuthEmail:          input.AuthEmail,
		AuthTokenEncrypted: encryptedToken,
		DefaultProjectKey:  input.DefaultProjectKey,
		DefaultIssueType:   input.DefaultIssueType,
		IsActive:           true,
	}

	// Test connection before saving
	if err := s.testConnection(ctx, conn, input.APIToken); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	if err := s.issueTrackerRepo.CreateConnection(ctx, conn); err != nil {
		return nil, err
	}

	return conn, nil
}

// testConnection tests the connection to the issue tracker
func (s *IssueTrackerService) testConnection(ctx context.Context, conn *model.IssueTrackerConnection, apiToken string) error {
	switch conn.TrackerType {
	case model.TrackerTypeJira:
		jiraClient := client.NewJiraClient(conn.BaseURL, conn.AuthEmail, apiToken)
		return jiraClient.TestConnection(ctx)
	case model.TrackerTypeBacklog:
		backlogClient := client.NewBacklogClient(conn.BaseURL, apiToken)
		return backlogClient.TestConnection(ctx)
	default:
		return fmt.Errorf("unsupported tracker type: %s", conn.TrackerType)
	}
}

// GetConnection gets a connection by ID
func (s *IssueTrackerService) GetConnection(ctx context.Context, id uuid.UUID) (*model.IssueTrackerConnection, error) {
	return s.issueTrackerRepo.GetConnection(ctx, id)
}

// ListConnections lists all connections for a tenant
func (s *IssueTrackerService) ListConnections(ctx context.Context, tenantID uuid.UUID) ([]model.IssueTrackerConnection, error) {
	return s.issueTrackerRepo.ListConnections(ctx, tenantID)
}

// DeleteConnection deletes a connection
func (s *IssueTrackerService) DeleteConnection(ctx context.Context, id uuid.UUID) error {
	return s.issueTrackerRepo.DeleteConnection(ctx, id)
}

// CreateTicketInput represents input for creating a ticket
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

// CreateTicket creates a new ticket for a vulnerability
func (s *IssueTrackerService) CreateTicket(ctx context.Context, tenantID uuid.UUID, input CreateTicketInput) (*model.VulnerabilityTicket, error) {
	// Get connection
	conn, err := s.issueTrackerRepo.GetConnection(ctx, input.ConnectionID)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("connection not found")
	}

	// Check if ticket already exists
	existing, err := s.issueTrackerRepo.GetTicketByVulnerability(ctx, input.VulnerabilityID, input.ConnectionID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("ticket already exists for this vulnerability")
	}

	// Decrypt API token
	apiToken, err := s.decrypt(conn.AuthTokenEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Use defaults if not provided
	projectKey := input.ProjectKey
	if projectKey == "" {
		projectKey = conn.DefaultProjectKey
	}
	issueType := input.IssueType
	if issueType == "" {
		issueType = conn.DefaultIssueType
	}
	if issueType == "" {
		issueType = "Bug" // Default issue type
	}

	// Create ticket in external system
	var externalTicket *model.ExternalTicket
	switch conn.TrackerType {
	case model.TrackerTypeJira:
		externalTicket, err = s.createJiraTicket(ctx, conn, apiToken, projectKey, issueType, input)
	case model.TrackerTypeBacklog:
		externalTicket, err = s.createBacklogTicket(ctx, conn, apiToken, projectKey, input)
	default:
		return nil, fmt.Errorf("unsupported tracker type: %s", conn.TrackerType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create external ticket: %w", err)
	}

	now := time.Now()
	ticket := &model.VulnerabilityTicket{
		ID:                uuid.New(),
		TenantID:          tenantID,
		VulnerabilityID:   input.VulnerabilityID,
		ProjectID:         input.ProjectID,
		ConnectionID:      input.ConnectionID,
		ExternalTicketID:  externalTicket.ID,
		ExternalTicketKey: externalTicket.Key,
		ExternalTicketURL: externalTicket.URL,
		LocalStatus:       model.TicketStatusOpen,
		ExternalStatus:    externalTicket.Status,
		Priority:          externalTicket.Priority,
		Assignee:          externalTicket.Assignee,
		Summary:           externalTicket.Summary,
		LastSyncedAt:      &now,
	}

	if err := s.issueTrackerRepo.CreateTicket(ctx, ticket); err != nil {
		return nil, err
	}

	return ticket, nil
}

func (s *IssueTrackerService) createJiraTicket(ctx context.Context, conn *model.IssueTrackerConnection, apiToken, projectKey, issueType string, input CreateTicketInput) (*model.ExternalTicket, error) {
	jiraClient := client.NewJiraClient(conn.BaseURL, conn.AuthEmail, apiToken)

	jiraInput := client.CreateIssueInput{
		ProjectKey:  projectKey,
		IssueType:   issueType,
		Summary:     input.Summary,
		Description: input.Description,
		Priority:    input.Priority,
		Labels:      input.Labels,
	}

	issue, err := jiraClient.CreateIssue(ctx, jiraInput)
	if err != nil {
		return nil, err
	}

	return &model.ExternalTicket{
		ID:       issue.ID,
		Key:      issue.Key,
		URL:      fmt.Sprintf("%s/browse/%s", conn.BaseURL, issue.Key),
		Status:   issue.Fields.Status.Name,
		Priority: issue.Fields.Priority.Name,
		Summary:  issue.Fields.Summary,
	}, nil
}

func (s *IssueTrackerService) createBacklogTicket(ctx context.Context, conn *model.IssueTrackerConnection, apiToken, projectKey string, input CreateTicketInput) (*model.ExternalTicket, error) {
	backlogClient := client.NewBacklogClient(conn.BaseURL, apiToken)

	// Get project ID from project key
	projects, err := backlogClient.GetProjects(ctx)
	if err != nil {
		return nil, err
	}

	var projectID int
	for _, p := range projects {
		if p.ProjectKey == projectKey {
			projectID = p.ID
			break
		}
	}
	if projectID == 0 {
		return nil, fmt.Errorf("project not found: %s", projectKey)
	}

	// Get issue types
	issueTypes, err := backlogClient.GetIssueTypes(ctx, projectKey)
	if err != nil {
		return nil, err
	}
	if len(issueTypes) == 0 {
		return nil, fmt.Errorf("no issue types found for project")
	}
	issueTypeID := issueTypes[0].ID // Use first issue type as default

	// Get priorities
	priorities, err := backlogClient.GetPriorities(ctx)
	if err != nil {
		return nil, err
	}
	priorityID := 3 // Default to "Normal"
	for _, p := range priorities {
		if p.Name == input.Priority {
			priorityID = p.ID
			break
		}
	}

	backlogInput := client.CreateBacklogIssueInput{
		ProjectID:   projectID,
		IssueTypeID: issueTypeID,
		PriorityID:  priorityID,
		Summary:     input.Summary,
		Description: input.Description,
	}

	issue, err := backlogClient.CreateIssue(ctx, backlogInput)
	if err != nil {
		return nil, err
	}

	return &model.ExternalTicket{
		ID:       fmt.Sprintf("%d", issue.ID),
		Key:      issue.IssueKey,
		URL:      backlogClient.GetIssueURL(issue.IssueKey),
		Status:   issue.Status.Name,
		Priority: issue.Priority.Name,
		Summary:  issue.Summary,
	}, nil
}

// GetTicketByVulnerability gets a ticket for a vulnerability
func (s *IssueTrackerService) GetTicketByVulnerability(ctx context.Context, vulnID uuid.UUID) ([]model.VulnerabilityTicketWithDetails, error) {
	return s.issueTrackerRepo.ListTicketsByVulnerability(ctx, vulnID)
}

// ListTickets lists tickets for a tenant
func (s *IssueTrackerService) ListTickets(ctx context.Context, tenantID uuid.UUID, status string, limit, offset int) ([]model.VulnerabilityTicketWithDetails, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	return s.issueTrackerRepo.ListTickets(ctx, tenantID, status, limit, offset)
}

// SyncTicket syncs a ticket with the external system
func (s *IssueTrackerService) SyncTicket(ctx context.Context, ticketID uuid.UUID) error {
	ticket, err := s.issueTrackerRepo.GetTicket(ctx, ticketID)
	if err != nil {
		return err
	}
	if ticket == nil {
		return fmt.Errorf("ticket not found")
	}

	conn, err := s.issueTrackerRepo.GetConnection(ctx, ticket.ConnectionID)
	if err != nil {
		return err
	}
	if conn == nil {
		return fmt.Errorf("connection not found")
	}

	apiToken, err := s.decrypt(conn.AuthTokenEncrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt token: %w", err)
	}

	var externalStatus, priority, assignee string

	switch conn.TrackerType {
	case model.TrackerTypeJira:
		jiraClient := client.NewJiraClient(conn.BaseURL, conn.AuthEmail, apiToken)
		issue, err := jiraClient.GetIssue(ctx, ticket.ExternalTicketKey)
		if err != nil {
			return err
		}
		if issue.Fields.Status != nil {
			externalStatus = issue.Fields.Status.Name
		}
		if issue.Fields.Priority != nil {
			priority = issue.Fields.Priority.Name
		}
		if issue.Fields.Assignee != nil {
			assignee = issue.Fields.Assignee.DisplayName
		}

	case model.TrackerTypeBacklog:
		backlogClient := client.NewBacklogClient(conn.BaseURL, apiToken)
		issue, err := backlogClient.GetIssue(ctx, ticket.ExternalTicketKey)
		if err != nil {
			return err
		}
		externalStatus = issue.Status.Name
		priority = issue.Priority.Name
		if issue.Assignee != nil {
			assignee = issue.Assignee.Name
		}
	}

	// Update ticket
	ticket.ExternalStatus = externalStatus
	ticket.Priority = priority
	ticket.Assignee = assignee
	now := time.Now()
	ticket.LastSyncedAt = &now

	// Map external status to local status
	ticket.LocalStatus = s.mapExternalStatus(externalStatus)

	return s.issueTrackerRepo.UpdateTicket(ctx, ticket)
}

// mapExternalStatus maps external status to local status
func (s *IssueTrackerService) mapExternalStatus(externalStatus string) model.TicketStatus {
	switch externalStatus {
	case "Done", "Closed", "完了", "クローズ":
		return model.TicketStatusClosed
	case "Resolved", "解決済み":
		return model.TicketStatusResolved
	case "In Progress", "処理中", "対応中":
		return model.TicketStatusInProgress
	default:
		return model.TicketStatusOpen
	}
}

// Encryption helpers
func (s *IssueTrackerService) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *IssueTrackerService) decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
