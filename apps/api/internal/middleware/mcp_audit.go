package middleware

import (
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

func MCPAudit(auditRepo *repository.AuditRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)

			key, _ := c.Get(ContextKeyAPI).(*model.APIKey)
			tenantID, _ := c.Get(ContextKeyTenantID).(uuid.UUID)

			details := map[string]interface{}{
				"path":       c.Path(),
				"method":     c.Request().Method,
				"status":     c.Response().Status,
				"latency_ms": time.Since(start).Milliseconds(),
			}

			_ = auditRepo.Log(c.Request().Context(), &model.CreateAuditLogInput{
				TenantID:     &tenantID,
				UserID:       nil,
				Action:       model.ActionAPIKeyUsed,
				ResourceType: model.ResourceAPIKey,
				ResourceID:   resourceID(key),
				Details:      details,
				IPAddress:    c.RealIP(),
				UserAgent:    c.Request().UserAgent(),
			})

			return err
		}
	}
}

func resourceID(key *model.APIKey) *uuid.UUID {
	if key == nil {
		return nil
	}
	return &key.ID
}
