package middleware

import (
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// MCPAudit emits one audit row per authenticated MCP request. Like its
// sibling Audit() in audit.go, this is a middleware-level best-effort
// path — see the Audit() head comment for the full dual-path rationale
// (middleware-level swallow vs F168 handler-level audit_pair). Same
// 500-storm blast-radius reasoning applies: failing the MCP request on
// an audit-log INSERT failure would mean every MCP read 500s during any
// audit_logs table outage, which is worse than dropping the audit row.
// F229 (M14 Phase D round 3) adds this symmetric docstring so a future
// reviewer inspecting mcp_audit.go in isolation has the same signal
// audit.go now carries — the inline swallow below is intentional, not
// an F168 audit-or-nothing violation. F230 (M14 Phase D round 4)
// rewrote the line-number reference to a position-relative phrase so
// the docstring does not bit-rot under future line drift, matching
// the F227 docstring's line-number-free style on audit.go.
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

			// F229 (M14 Phase D round 3) — intentional swallow, same
			// rationale as Audit() in audit.go. See that head comment
			// for the middleware-level vs F168 handler-level audit_pair
			// (audit-or-nothing) distinction. Handler-level audit_pair
			// example: handler/sbom.go::writeAutoFiredAudit /
			// runDiffWebhookAutoTrigger.
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
