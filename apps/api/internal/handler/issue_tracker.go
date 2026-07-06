package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// IssueTrackerServiceAPI captures the service surface the handler depends
// on (F370). Narrowing the dependency to an interface follows the meti.go /
// cra_reports.go / sbom.go handler precedent: it lets handler tests pin full
// request→response flows (e.g. the 201 + github base_url default below)
// with a recording stub, where the concrete service would require a live
// DB, an external tracker endpoint, and an SSRF-validated public base URL.
// *service.IssueTrackerService satisfies it unchanged (see the compile-time
// assertion below NewIssueTrackerHandler).
type IssueTrackerServiceAPI interface {
	CreateConnection(ctx context.Context, tenantID uuid.UUID, input service.CreateConnectionInput) (*model.IssueTrackerConnection, error)
	ListConnections(ctx context.Context, tenantID uuid.UUID) ([]model.IssueTrackerConnection, error)
	GetConnection(ctx context.Context, id uuid.UUID) (*model.IssueTrackerConnection, error)
	DeleteConnection(ctx context.Context, id uuid.UUID) error
	CreateTicket(ctx context.Context, tenantID uuid.UUID, input service.CreateTicketInput) (*model.VulnerabilityTicket, error)
	GetTicketByVulnerability(ctx context.Context, vulnID uuid.UUID) ([]model.VulnerabilityTicketWithDetails, error)
	ListTickets(ctx context.Context, tenantID uuid.UUID, status string, limit, offset int) ([]model.VulnerabilityTicketWithDetails, int, error)
	SyncTicket(ctx context.Context, ticketID uuid.UUID) error
}

// githubDefaultBaseURL is substituted when a GitHub connection request
// omits base_url (F370): github.com's API root is a fixed constant — only
// GitHub Enterprise Server self-hosts differ — unlike Jira/Backlog whose
// base URL embeds the customer subdomain and therefore stays required.
// Mirrors the client-side default (client.NewGitHubIssuesClient falls back
// to the same root for an empty baseURL), but the substitution happens here
// so the persisted connection row and the API response carry the resolved
// URL explicitly.
const githubDefaultBaseURL = "https://api.github.com"

// IssueTrackerHandler handles issue tracker API requests
type IssueTrackerHandler struct {
	issueTrackerService IssueTrackerServiceAPI
}

// NewIssueTrackerHandler creates a new IssueTrackerHandler
func NewIssueTrackerHandler(issueTrackerService IssueTrackerServiceAPI) *IssueTrackerHandler {
	return &IssueTrackerHandler{
		issueTrackerService: issueTrackerService,
	}
}

// The production service must keep satisfying the handler's dependency
// surface — a signature drift fails compilation here, not at wiring time
// in cmd/server.
var _ IssueTrackerServiceAPI = (*service.IssueTrackerService)(nil)

// CreateConnectionRequest represents the request body for creating a connection
type CreateConnectionRequest struct {
	TrackerType       string `json:"tracker_type"`
	Name              string `json:"name"`
	BaseURL           string `json:"base_url"`
	Email             string `json:"email,omitempty"` // For Jira
	APIToken          string `json:"api_token"`
	DefaultProjectKey string `json:"default_project_key,omitempty"`
	DefaultIssueType  string `json:"default_issue_type,omitempty"`
}

// CreateConnection handles POST /api/v1/integrations
func (h *IssueTrackerHandler) CreateConnection(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant context required")
	}

	var req CreateConnectionRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	// F370: an omitted base_url on a github request defaults to the public
	// API root BEFORE the all-tracker required-field check below, so the
	// check keeps rejecting an empty base_url for every other tracker
	// (their contract is unchanged) while GitHub operators no longer have
	// to know/type the api.github.com constant. GHES operators still pass
	// their own API root explicitly and it wins over the default.
	if req.TrackerType == "github" && req.BaseURL == "" {
		req.BaseURL = githubDefaultBaseURL
	}

	if req.TrackerType == "" || req.Name == "" || req.BaseURL == "" || req.APIToken == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "tracker_type, name, base_url, and api_token are required")
	}

	var trackerType model.TrackerType
	switch req.TrackerType {
	case "jira":
		trackerType = model.TrackerTypeJira
		if req.Email == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "email is required for Jira")
		}
	case "backlog":
		trackerType = model.TrackerTypeBacklog
	case "github":
		trackerType = model.TrackerTypeGitHub
		// GitHub's connection test is repository-scoped (GET /repos/{owner}/
		// {repo}), so the "owner/repo" project key is required at creation —
		// the handler-level check mirrors Jira's email requirement above and
		// gives operators a field-specific 400 instead of the service's
		// connection-test failure.
		if req.DefaultProjectKey == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "default_project_key (owner/repo) is required for GitHub")
		}
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid tracker_type. Must be 'jira', 'backlog', or 'github'")
	}

	input := service.CreateConnectionInput{
		TrackerType:       trackerType,
		Name:              req.Name,
		BaseURL:           req.BaseURL,
		AuthEmail:         req.Email,
		APIToken:          req.APIToken,
		DefaultProjectKey: req.DefaultProjectKey,
		DefaultIssueType:  req.DefaultIssueType,
	}

	conn, err := h.issueTrackerService.CreateConnection(ctx, tenantID, input)
	if err != nil {
		// F44x: split the former blanket 400 (which echoed the raw service
		// error). CreateConnection mixes self-authored validation feedback
		// (invalid base URL — safe to echo) with %w-wrapped internal errors
		// (crypto, external connection-test HTTP detail, DB). Only validation
		// is echoed at 400; everything else is a generic 500 with the raw error
		// kept in the server log (and further genericized by the global 5xx
		// handler — defense in depth).
		if errors.Is(err, service.ErrValidation) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		slog.Warn("issue tracker: create connection failed", "tenant_id", tenantID, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create connection")
	}

	// F208 / M14-1: publish the newly-minted integration UUID so the
	// audit middleware records audit_logs.resource_id = conn.ID. POST
	// /integrations is a tenant-scoped create with no UUID path param,
	// so without this Set the row would drop to NULL and break the
	// forensic join audit_logs ⨝ issue_tracker_connections for every
	// integration.created row.
	if conn != nil {
		middleware.SetAuditResourceID(c, conn.ID)
	}

	return c.JSON(http.StatusCreated, conn)
}

// ListConnections handles GET /api/v1/integrations
func (h *IssueTrackerHandler) ListConnections(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant context required")
	}

	connections, err := h.issueTrackerService.ListConnections(ctx, tenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list connections")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"connections": connections,
	})
}

// GetConnection handles GET /api/v1/integrations/:id
func (h *IssueTrackerHandler) GetConnection(c echo.Context) error {
	ctx := c.Request().Context()

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid connection ID")
	}

	conn, err := h.issueTrackerService.GetConnection(ctx, id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get connection")
	}
	if conn == nil {
		return echo.NewHTTPError(http.StatusNotFound, "Connection not found")
	}

	return c.JSON(http.StatusOK, conn)
}

// DeleteConnection handles DELETE /api/v1/integrations/:id
func (h *IssueTrackerHandler) DeleteConnection(c echo.Context) error {
	ctx := c.Request().Context()

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid connection ID")
	}

	if err := h.issueTrackerService.DeleteConnection(ctx, id); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete connection")
	}

	return c.NoContent(http.StatusNoContent)
}

// CreateTicketRequest represents the request body for creating a ticket
type CreateTicketRequest struct {
	VulnerabilityID string   `json:"vulnerability_id"`
	ProjectID       string   `json:"project_id"`
	ConnectionID    string   `json:"connection_id"`
	ProjectKey      string   `json:"project_key,omitempty"`
	IssueType       string   `json:"issue_type,omitempty"`
	Priority        string   `json:"priority,omitempty"`
	Summary         string   `json:"summary,omitempty"`
	Description     string   `json:"description,omitempty"`
	Labels          []string `json:"labels,omitempty"`
}

// CreateTicket handles POST /api/v1/vulnerabilities/:vuln_id/ticket
func (h *IssueTrackerHandler) CreateTicket(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant context required")
	}

	vulnID, err := uuid.Parse(c.Param("vuln_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid vulnerability ID")
	}

	var req CreateTicketRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
	}

	connectionID, err := uuid.Parse(req.ConnectionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid connection_id")
	}

	projectID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid project_id")
	}

	input := service.CreateTicketInput{
		VulnerabilityID: vulnID,
		ProjectID:       projectID,
		ConnectionID:    connectionID,
		ProjectKey:      req.ProjectKey,
		IssueType:       req.IssueType,
		Priority:        req.Priority,
		Summary:         req.Summary,
		Description:     req.Description,
		Labels:          req.Labels,
	}

	ticket, err := h.issueTrackerService.CreateTicket(ctx, tenantID, input)
	if err != nil {
		// F44x: split the former blanket 400 (see CreateConnection).
		// CreateTicket mixes validation feedback (connection not found,
		// duplicate ticket — safe to echo) with %w-wrapped internal errors
		// (crypto, external ticket-creation HTTP detail, DB). Only validation
		// is echoed at 400; everything else is a generic 500 with the raw error
		// logged server-side.
		if errors.Is(err, service.ErrValidation) {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		slog.Warn("issue tracker: create ticket failed", "tenant_id", tenantID, "vuln_id", vulnID, "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create ticket")
	}

	// F208 / M14-1: publish the newly-minted ticket UUID so the audit
	// middleware records audit_logs.resource_id = ticket.ID instead of
	// the parent :vuln_id (which would point at the vulnerability, not
	// the just-created ticket). POST /vulnerabilities/:vuln_id/ticket
	// has :vuln_id bound, so without this override the priority-list
	// would pick up :vuln_id and forensic joins to tickets would
	// silently drop.
	if ticket != nil {
		middleware.SetAuditResourceID(c, ticket.ID)
	}

	return c.JSON(http.StatusCreated, ticket)
}

// GetTicketsByVulnerability handles GET /api/v1/vulnerabilities/:vuln_id/tickets
func (h *IssueTrackerHandler) GetTicketsByVulnerability(c echo.Context) error {
	ctx := c.Request().Context()

	vulnID, err := uuid.Parse(c.Param("vuln_id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid vulnerability ID")
	}

	tickets, err := h.issueTrackerService.GetTicketByVulnerability(ctx, vulnID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get tickets")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"tickets": tickets,
	})
}

// ListTickets handles GET /api/v1/tickets
func (h *IssueTrackerHandler) ListTickets(c echo.Context) error {
	ctx := c.Request().Context()

	tenantID, ok := c.Get(middleware.ContextKeyTenantID).(uuid.UUID)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "tenant context required")
	}

	status := c.QueryParam("status")
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	offset, _ := strconv.Atoi(c.QueryParam("offset"))

	if limit <= 0 {
		limit = 20
	}

	tickets, total, err := h.issueTrackerService.ListTickets(ctx, tenantID, status, limit, offset)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to list tickets")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"tickets": tickets,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// SyncTicket handles POST /api/v1/tickets/:id/sync
func (h *IssueTrackerHandler) SyncTicket(c echo.Context) error {
	ctx := c.Request().Context()

	ticketID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid ticket ID")
	}

	if err := h.issueTrackerService.SyncTicket(ctx, ticketID); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status": "synced",
	})
}
