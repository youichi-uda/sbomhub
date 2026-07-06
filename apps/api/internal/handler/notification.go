package handler

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

type NotificationHandler struct {
	notificationService *service.NotificationService
}

func NewNotificationHandler(ns *service.NotificationService) *NotificationHandler {
	return &NotificationHandler{notificationService: ns}
}

// GetSettings gets notification settings for a project
func (h *NotificationHandler) GetSettings(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	settings, err := h.notificationService.GetSettings(c.Request().Context(), projectID)
	if err != nil {
		slog.Warn("notification: get settings failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get notification settings"})
	}

	return c.JSON(http.StatusOK, settings)
}

// UpdateSettings updates notification settings for a project
func (h *NotificationHandler) UpdateSettings(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	var input service.UpdateNotificationSettingsInput
	if err := c.Bind(&input); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	settings, err := h.notificationService.UpdateSettings(c.Request().Context(), projectID, input)
	if err != nil {
		slog.Warn("notification: update settings failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update notification settings"})
	}

	return c.JSON(http.StatusOK, settings)
}

// TestNotification sends a test notification
func (h *NotificationHandler) TestNotification(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	if err := h.notificationService.SendTestNotification(c.Request().Context(), projectID); err != nil {
		slog.Warn("notification: send test notification failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send test notification"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "test notification sent"})
}

// GetLogs gets notification logs for a project
func (h *NotificationHandler) GetLogs(c echo.Context) error {
	projectID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid project id"})
	}

	logs, err := h.notificationService.GetLogs(c.Request().Context(), projectID, 50)
	if err != nil {
		slog.Warn("notification: get logs failed", "project_id", projectID, "error", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get notification logs"})
	}

	return c.JSON(http.StatusOK, logs)
}
