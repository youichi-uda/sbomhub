package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/egress"
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
		// M50: the webhook URL is now checked against the deployment's egress
		// policy before the row is written. That is caller-fixable input, and
		// the message is self-authored by internal/egress (host, address and a
		// reason from its own tables — no remote content), so it is safe to
		// echo at 400. Without this split the admin gets a bare 500 and no way
		// to learn that the URL was the problem.
		if errors.Is(err, service.ErrValidation) {
			// Safe to echo: the service builds this with ValidationErrorf from
			// an *egress.DestinationError, which carries the field name, the
			// normalised host/address and a reason from egress's own tables —
			// never the URL path or query. (The whole-URL exposure Codex round 5
			// flagged comes from *url.Error on the DELIVERY path, which does not
			// reach here.)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
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
		// M50: a destination the egress policy refuses is a configuration
		// problem the admin can fix, and this endpoint exists precisely so they
		// can find out. Returning the bare 500 below would leave "test
		// notification failed" as the only signal for the single most likely
		// post-upgrade breakage (a webhook pointing inside the network).
		//
		// Only the *egress.DestinationError is echoed, extracted with errors.As
		// — NOT err.Error(). Codex round 5 (Low): this error arrives from
		// http.Client.Do wrapped in a *url.Error, whose message contains the
		// whole request URL. For a Slack or Discord webhook that URL IS the
		// credential, so echoing the chain would have put the tenant's webhook
		// secret in an HTTP response body.
		var dest *egress.DestinationError
		if errors.As(err, &dest) {
			slog.Warn("notification: test notification refused by egress policy",
				"project_id", projectID, "error", err)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": dest.Error()})
		}
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
