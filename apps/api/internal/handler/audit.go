package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/service"
)

// AuditHandler handles audit log related requests
type AuditHandler struct {
	auditService *service.AuditService
}

// NewAuditHandler creates a new AuditHandler
func NewAuditHandler(as *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: as}
}

// List returns a paginated list of audit logs
// GET /api/v1/audit-logs
func (h *AuditHandler) List(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Parse query parameters
	filter := service.AuditFilter{}

	// Action filter
	if action := c.QueryParam("action"); action != "" {
		filter.Action = action
	}

	// Resource type filter
	if resourceType := c.QueryParam("resource_type"); resourceType != "" {
		filter.ResourceType = resourceType
	}

	// User ID filter
	if userIDStr := c.QueryParam("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filter.UserID = &userID
		}
	}

	// Date range filters
	if startDateStr := c.QueryParam("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filter.StartDate = &startDate
		} else if startDate, err := time.Parse("2006-01-02", startDateStr); err == nil {
			filter.StartDate = &startDate
		}
	}

	if endDateStr := c.QueryParam("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filter.EndDate = &endDate
		} else if endDate, err := time.Parse("2006-01-02", endDateStr); err == nil {
			// Add 1 day to include the end date
			endDate = endDate.Add(24*time.Hour - time.Second)
			filter.EndDate = &endDate
		}
	}

	// Pagination
	if page, err := strconv.Atoi(c.QueryParam("page")); err == nil && page > 0 {
		filter.Page = page
	} else {
		filter.Page = 1
	}

	if limit, err := strconv.Atoi(c.QueryParam("limit")); err == nil && limit > 0 {
		filter.Limit = limit
	} else {
		filter.Limit = 50
	}

	result, err := h.auditService.List(c.Request().Context(), tenantID, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

// Export exports audit logs as CSV
// GET /api/v1/audit-logs/export
func (h *AuditHandler) Export(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	// Check admin permission
	if !tc.CanAdmin() {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "admin permission required"})
	}

	// Parse query parameters
	filter := service.AuditFilter{}

	// Action filter
	if action := c.QueryParam("action"); action != "" {
		filter.Action = action
	}

	// Resource type filter
	if resourceType := c.QueryParam("resource_type"); resourceType != "" {
		filter.ResourceType = resourceType
	}

	// User ID filter
	if userIDStr := c.QueryParam("user_id"); userIDStr != "" {
		if userID, err := uuid.Parse(userIDStr); err == nil {
			filter.UserID = &userID
		}
	}

	// Date range filters
	if startDateStr := c.QueryParam("start_date"); startDateStr != "" {
		if startDate, err := time.Parse(time.RFC3339, startDateStr); err == nil {
			filter.StartDate = &startDate
		} else if startDate, err := time.Parse("2006-01-02", startDateStr); err == nil {
			filter.StartDate = &startDate
		}
	}

	if endDateStr := c.QueryParam("end_date"); endDateStr != "" {
		if endDate, err := time.Parse(time.RFC3339, endDateStr); err == nil {
			filter.EndDate = &endDate
		} else if endDate, err := time.Parse("2006-01-02", endDateStr); err == nil {
			// Add 1 day to include the end date
			endDate = endDate.Add(24*time.Hour - time.Second)
			filter.EndDate = &endDate
		}
	}

	csvData, err := h.auditService.ExportCSV(c.Request().Context(), tenantID, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Generate filename with timestamp
	filename := fmt.Sprintf("audit-logs-%s.csv", time.Now().Format("2006-01-02-150405"))

	c.Response().Header().Set("Content-Type", "text/csv; charset=utf-8")
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Response().Header().Set("Content-Length", strconv.Itoa(len(csvData)))

	return c.Blob(http.StatusOK, "text/csv", csvData)
}

// GetStatistics returns audit log statistics
// GET /api/v1/audit-logs/statistics
func (h *AuditHandler) GetStatistics(c echo.Context) error {
	tc := middleware.NewTenantContext(c)
	tenantID := tc.TenantID()

	if tenantID == uuid.Nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	days := 30
	if daysStr := c.QueryParam("days"); daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 365 {
			days = d
		}
	}

	stats, err := h.auditService.GetStatistics(c.Request().Context(), tenantID, days)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, stats)
}

// GetActions returns available actions for filtering
// GET /api/v1/audit-logs/actions
func (h *AuditHandler) GetActions(c echo.Context) error {
	actions := h.auditService.GetAvailableActions()
	return c.JSON(http.StatusOK, actions)
}

// GetResourceTypes returns available resource types for filtering
// GET /api/v1/audit-logs/resource-types
func (h *AuditHandler) GetResourceTypes(c echo.Context) error {
	resourceTypes := h.auditService.GetAvailableResourceTypes()
	return c.JSON(http.StatusOK, resourceTypes)
}
