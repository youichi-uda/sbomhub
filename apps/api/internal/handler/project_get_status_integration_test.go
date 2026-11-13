//go:build integration

// GET /api/v1/projects/:id under the RLS-enforced app role (M66 residual):
// real database errors became 500, but "not found" must stay 404 — including
// another tenant's project, which RLS hides and the tenant filter excludes.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'ProjectGetStatus' ./internal/handler
package handler

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func projectGetCall(t *testing.T, appDB *sql.DB, tenantID, projectID uuid.UUID) (int, string) {
	t.Helper()
	h := m50w3ProjectHandler(appDB)
	return m50w2Call(t, appDB, m50w2Req{
		method:   http.MethodGet,
		target:   "/api/v1/projects/" + projectID.String(),
		tenantID: tenantID,
	}, func(c echo.Context) error {
		c.SetParamNames("id")
		c.SetParamValues(projectID.String())
		return h.Get(c)
	})
}

func TestProjectGetStatus_Integration(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	a := m50w2SeedTenant(t, migDB, "getstatus-a")
	b := m50w2SeedTenant(t, migDB, "getstatus-b")

	code, body := projectGetCall(t, appDB, a.tenantID, a.project1ID)
	if code != http.StatusOK || !strings.Contains(body, a.project1ID.String()) {
		t.Fatalf("own project: status %d body %s, want 200 with the project", code, body)
	}

	// Another tenant's project: invisible under RLS, so not found — not 500,
	// and not its existence disclosed.
	code, body = projectGetCall(t, appDB, a.tenantID, b.project1ID)
	if code != http.StatusNotFound {
		t.Fatalf("other tenant's project: status %d body %s, want 404", code, body)
	}
	if strings.Contains(body, b.project1) {
		t.Fatalf("other tenant's project leaked: %s", body)
	}

	// A project id nobody owns answers the same 404 body as the other tenant's.
	code, unknownBody := projectGetCall(t, appDB, a.tenantID, uuid.New())
	if code != http.StatusNotFound || unknownBody != body {
		t.Fatalf("unknown project: status %d body %s, want the same 404 as another tenant's (%s)",
			code, unknownBody, body)
	}
}
