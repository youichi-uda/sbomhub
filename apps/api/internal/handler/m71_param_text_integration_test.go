//go:build integration

// Package handler — M71: NUL / invalid UTF-8 in the query string or a path
// parameter must be a 400, not a PostgreSQL 22021 surfacing as a 500.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M71' ./internal/handler
//
// The chain is the production one in miniature: TextGuardParams via e.Use,
// then a group carrying the tenant, TenantTx and the Audit middleware, then
// the real SearchHandler / EOLHandler over the app role (RLS on).
package handler

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

func m71Server(appDB *sql.DB, tenantID uuid.UUID, guarded bool) *echo.Echo {
	e := echo.New()
	e.JSONSerializer = NewTextGuardJSONSerializer()
	e.Binder = NewTextGuardBinder()
	if guarded {
		e.Use(middleware.TextGuardParams())
	}
	setTenant := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(middleware.ContextKeyTenantID, tenantID)
			return next(c)
		}
	}
	g := e.Group("/api/v1", setTenant, middleware.TenantTx(appDB),
		middleware.Audit(repository.NewAuditRepository(appDB)))
	search := NewSearchHandler(service.NewSearchService(repository.NewSearchRepository(appDB)))
	g.GET("/search/component", search.SearchByComponent)
	eol := NewEOLHandler(service.NewEOLService(repository.NewEOLRepository(appDB), "", true))
	g.GET("/eol/products/:name", eol.GetProduct)
	return e
}

func TestM71ParamText_NULAndInvalidUTF8Are400NotPostgres500(t *testing.T) {
	appURL, migURL := craReanalyseEnv(t)
	migDB := craReanalyseOpen(t, migURL)
	appDB := craReanalyseOpen(t, appURL)
	tenantID := craReanalyseSeedTenant(t, migDB, "m71")

	targets := []string{
		"/api/v1/search/component?name=a%00b",
		"/api/v1/search/component?name=%FF",
		"/api/v1/search/component?name=log4j&x=%00", // an unused parameter: the audit row's jsonb
		"/api/v1/eol/products/a%00b",
		"/api/v1/eol/products/%FF",
	}

	// Reproduction: without the guard every one of these reached PostgreSQL
	// and answered 500 (measured 2026-11-13 on PostgreSQL 15: 22021
	// "invalid byte sequence for encoding UTF8", or a failed audit insert
	// aborting the tenant transaction so its commit failed).
	unguarded := m71Server(appDB, tenantID, false)
	for _, target := range targets {
		rec := httptest.NewRecorder()
		unguarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code < 500 {
			t.Logf("note: unguarded %s answered %d (reproduction no longer 5xx)", target, rec.Code)
		}
	}

	guarded := m71Server(appDB, tenantID, true)
	for _, target := range targets {
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("%s: status %d body %s, want 400 {\"error\": ...}", target, rec.Code, rec.Body.String())
		}
	}

	// Ordinary text still reaches the database and is answered.
	for _, target := range []string{
		"/api/v1/search/component?name=log4j&version=2.14.1",
		"/api/v1/search/component?name=%E6%97%A5%E6%9C%AC",
	} {
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d body %s, want 200", target, rec.Code, rec.Body.String())
		}
	}
}
