package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/service"
)

const (
	APIKeyHeader  = "X-API-Key"
	BearerPrefix  = "Bearer "
	ContextKeyAPI = "api_key"
)

// APIKeyAuth returns a middleware that validates API keys
func APIKeyAuth(keyService *service.APIKeyService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get API key from header
			apiKey := c.Request().Header.Get(APIKeyHeader)

			// Also check Authorization header
			if apiKey == "" {
				auth := c.Request().Header.Get("Authorization")
				if strings.HasPrefix(auth, BearerPrefix) {
					apiKey = strings.TrimPrefix(auth, BearerPrefix)
				}
			}

			if apiKey == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "API key required. Use X-API-Key header or Authorization: Bearer <key>",
				})
			}

			// Validate the key
			key, err := keyService.ValidateKey(c.Request().Context(), apiKey)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": err.Error(),
				})
			}

			// Store key info in context for handlers to use
			c.Set(ContextKeyAPI, key)

			return next(c)
		}
	}
}

// OptionalAPIKeyAuth returns a middleware that validates API keys if present
// but doesn't require them (for mixed auth scenarios)
func OptionalAPIKeyAuth(keyService *service.APIKeyService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get API key from header
			apiKey := c.Request().Header.Get(APIKeyHeader)

			// Also check Authorization header
			if apiKey == "" {
				auth := c.Request().Header.Get("Authorization")
				if strings.HasPrefix(auth, BearerPrefix) {
					apiKey = strings.TrimPrefix(auth, BearerPrefix)
				}
			}

			if apiKey != "" {
				// Validate the key if present
				key, err := keyService.ValidateKey(c.Request().Context(), apiKey)
				if err != nil {
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": err.Error(),
					})
				}
				c.Set(ContextKeyAPI, key)
			}

			return next(c)
		}
	}
}
