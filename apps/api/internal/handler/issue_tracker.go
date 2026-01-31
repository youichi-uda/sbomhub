package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/service"
)

// IssueTrackerHandler handles issue tracker API requests
type IssueTrackerHandler struct {
	issueTrackerService *service.IssueTrackerService
}

// NewIssueTrackerHandler creates a new IssueTrackerHandler
func NewIssueTrackerHandler(issueTrackerService *service.IssueTrackerService) *IssueTrackerHandler {
	return &IssueTrackerHandler{
		issueTrackerService: issueTrackerService,
	}
}

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
	default:
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid tracker_type. Must be 'jira' or 'backlog'")
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
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
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
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
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
