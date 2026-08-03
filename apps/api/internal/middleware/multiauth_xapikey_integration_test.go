//go:build integration

// Package middleware — MultiAuth and the `X-API-Key` header.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'MultiAuthXAPIKey' ./internal/middleware
//
// # The defect this file reproduces
//
// APIKeyAuth (apikey.go, the /api/v1/{cli,mcp}/* groups) reads the credential
// from EITHER `X-API-Key` or `Authorization: Bearer`. MultiAuth (the canonical
// /api/v1/projects/:id/... routes) read only `Authorization`. A client sending
// `X-API-Key` alone therefore presented a perfectly valid credential that the
// canonical routes did not look at — and, because the unread header left
// `Authorization` empty, the request did not stop there either: it fell through
// to Auth(), whose self-hosted branch provisions the DEFAULT tenant's Owner.
//
// Measured on a throwaway stack (2026-08-04, self-host `anonymous` mode,
// postgres 15 / redis 7, api built from 6aebd54):
//
//	X-API-Key: <project-scoped key>   GET /projects/<SIBLING>/sbom   200   ← reached a project the key is scoped away from
//	Authorization: Bearer <same key>  GET /projects/<SIBLING>/sbom   403
//	X-API-Key: <invalid key>          GET /projects/<SIBLING>/sbom   200   ← an invalid credential admitted
//
// Two shipped clients send exactly that header to exactly those routes:
// packages/mcp-server (src/client/api.ts) and .github/workflows/sbom-upload.yml
// (POST /api/v1/projects/:id/sbom).
//
// The shape is M48's fail-open one — a credential that cannot be used is
// silently replaced by a default identity instead of being refused — so the
// tests below assert BOTH halves: the key is honoured (and its project scope
// with it), and a key that does not validate is refused rather than downgraded.
//
// # What is deliberately NOT claimed
//
// In `anonymous` mode nothing here is a privilege ESCALATION: a caller sending
// no header at all already reaches the same routes as the default tenant's
// Owner, which is that mode's acknowledged posture (docs/UPGRADE.md). What the
// silent fall-through destroyed is the project-scope PROMISE for a caller who
// did present a scoped key. The `no header` case below is pinned precisely so
// the fix cannot be mistaken for a change to that posture.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// multiAuthHeaderResult is what one request through the real MultiAuth
// produced. `sawAPIKey` distinguishes the two ways a request can reach a
// handler with 200: through handleAPIKeyAuth (an API key was honoured) or
// through the Clerk / self-hosted fall-through (it was not). Status alone
// cannot tell them apart, and that indistinguishability IS the defect.
type multiAuthHeaderResult struct {
	status       int
	body         string
	handlerRan   bool
	sawAPIKey    bool
	sawScoped    bool
	sawProjectID uuid.UUID
	sawTenantID  uuid.UUID
	sawClerkUser string
}

// selfHostedConfig builds the config MultiAuth sees in `anonymous` self-host,
// which is the mode that matters here: it is the one whose fall-through
// provisions a DEFAULT identity, so a silently-ignored credential produces a
// 200 rather than the 401 a Clerk deployment would answer. Going through
// config.Load() rather than &config.Config{} is load-bearing — `mode` is
// unexported and a zero value resolves to SaaS, which would make every case
// below 401 for a reason that has nothing to do with the header.
func selfHostedConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "")
	cfg := config.Load()
	if !cfg.IsSelfHosted() {
		t.Fatalf("expected a self-hosted config, got mode %q", cfg.Mode())
	}
	return cfg
}

// driveMultiAuthWithHeaders mounts the REAL MultiAuth over a recording handler
// and issues one request carrying `headers`.
func driveMultiAuthWithHeaders(
	t *testing.T, method, routePath, requestURL string, headers map[string]string,
) multiAuthHeaderResult {
	t.Helper()

	appURL, _ := m50w3Env(t)
	appDB := m50w3Open(t, appURL)

	cfg := selfHostedConfig(t)
	mw := MultiAuth(
		cfg,
		repository.NewTenantRepository(appDB),
		repository.NewUserRepository(appDB),
		service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB)),
	)
	e := echo.New()
	var out multiAuthHeaderResult
	handler := func(c echo.Context) error {
		out.handlerRan = true
		out.sawProjectID, out.sawScoped = APIKeyProjectID(c)
		_, out.sawAPIKey = c.Get(ContextKeyAPI).(*model.APIKey)
		out.sawTenantID, _ = c.Get(ContextKeyTenantID).(uuid.UUID)
		out.sawClerkUser, _ = c.Get(ContextKeyClerkUserID).(string)
		return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
	}
	e.Add(method, routePath, handler, mw)

	req := httptest.NewRequest(method, requestURL, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	out.status, out.body = rec.Code, rec.Body.String()
	return out
}

const multiAuthScanStatusRoute = "/api/v1/projects/:id/sboms/:sbom_id/scan-status"

// TestMultiAuthXAPIKeyIsHonoured: the header apikey.go accepts must authenticate
// on the canonical routes too, and must arrive carrying the key's own project
// scope. Without the scope on the context, admission alone would be worthless —
// the project-scope comparison is what the "Project-scoped" label promises.
func TestMultiAuthXAPIKeyIsHonoured(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	_ = appURL
	seed := m50w3SeedAuth(t, migDB)

	for _, routePath := range []string{
		"/api/v1/projects/:id/sbom",
		multiAuthScanStatusRoute,
	} {
		t.Run(routePath, func(t *testing.T) {
			url := "/api/v1/projects/" + seed.projectID.String() + "/sbom"
			if routePath == multiAuthScanStatusRoute {
				url = "/api/v1/projects/" + seed.projectID.String() +
					"/sboms/" + uuid.New().String() + "/scan-status"
			}
			r := driveMultiAuthWithHeaders(t, http.MethodGet, routePath, url,
				map[string]string{APIKeyHeader: seed.scopedKey})

			if !r.handlerRan || r.status != http.StatusOK {
				t.Fatalf("%s: a valid key in %s was refused (status %d, body %s)",
					routePath, APIKeyHeader, r.status, r.body)
			}
			if !r.sawAPIKey {
				t.Fatalf("%s: the handler ran WITHOUT an API key on the context — the request "+
					"authenticated through the Clerk/self-hosted fall-through, so the key was "+
					"silently ignored and every project-scope check was skipped", routePath)
			}
			if !r.sawScoped || r.sawProjectID != seed.projectID {
				t.Errorf("%s: handler saw scope (%s, scoped=%v), want the key's %s",
					routePath, r.sawProjectID, r.sawScoped, seed.projectID)
			}
			if r.sawTenantID != seed.tenantID {
				t.Errorf("%s: handler saw tenant %s, want the key's %s",
					routePath, r.sawTenantID, seed.tenantID)
			}
		})
	}
}

// TestMultiAuthXAPIKeyEnforcesProjectScope is the half that fails loudest
// against 6aebd54: the sibling project was answered 200 for a key scoped to
// another project, because the scope comparison never ran.
func TestMultiAuthXAPIKeyEnforcesProjectScope(t *testing.T) {
	_, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	seed := m50w3SeedAuth(t, migDB)

	const routePath = "/api/v1/projects/:id/sbom"
	r := driveMultiAuthWithHeaders(t, http.MethodGet, routePath,
		"/api/v1/projects/"+seed.siblingID.String()+"/sbom",
		map[string]string{APIKeyHeader: seed.scopedKey})

	if r.handlerRan {
		t.Errorf("a project-scoped key sent in %s reached a SIBLING project's handler "+
			"(status %d, body %s). Authorization: Bearer with the same key answers 403; the "+
			"two headers must not disagree about who the caller is.",
			APIKeyHeader, r.status, r.body)
	}
	if r.status != http.StatusForbidden {
		t.Errorf("status %d body %s, want 403 (the status every project-scope refusal uses)",
			r.status, r.body)
	}
}

// TestMultiAuthUnusableXAPIKeyIsRefused is the fail-closed half. An
// unauthenticatable value in the API-key header must end the request, not be
// replaced by the self-hosted default identity. Anything else is the M48 shape:
// refusal degrading into a default.
func TestMultiAuthUnusableXAPIKeyIsRefused(t *testing.T) {
	_, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	seed := m50w3SeedAuth(t, migDB)

	for _, tc := range []struct{ name, value string }{
		{"never issued", "sbh_" + uuid.New().String()},
		{"not even key-shaped", "definitely-not-a-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := driveMultiAuthWithHeaders(t, http.MethodGet,
				"/api/v1/projects/:id/sbom",
				"/api/v1/projects/"+seed.projectID.String()+"/sbom",
				map[string]string{APIKeyHeader: tc.value})

			if r.handlerRan {
				t.Errorf("a %s value in %s reached the handler (status %d, body %s). "+
					"The credential was presented and could not be used, so the request must be "+
					"refused — falling back to the self-hosted default identity turns a rejected "+
					"credential into an accepted one.", tc.name, APIKeyHeader, r.status, r.body)
			}
			if r.status != http.StatusUnauthorized {
				t.Errorf("status %d body %s, want 401", r.status, r.body)
			}
		})
	}
}

// TestMultiAuthNoHeaderStillReachesTheSelfHostedDefault pins the promise the
// fix must NOT break. `anonymous` self-host is documented as "a local curl with
// no header still works"; the fix distinguishes NO credential from an UNUSABLE
// one, and only the second is refused. Without this test, tightening the
// unusable case could silently take the documented case with it.
func TestMultiAuthNoHeaderStillReachesTheSelfHostedDefault(t *testing.T) {
	_, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	seed := m50w3SeedAuth(t, migDB)

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"no header at all", nil},
		// An empty header value is how a shell that expands an unset variable
		// into `-H "X-API-Key: $KEY"` presents itself. apikey.go treats "" as
		// absent; MultiAuth must agree, or the two middlewares disagree about
		// what "no credential" means.
		{"empty " + APIKeyHeader, map[string]string{APIKeyHeader: ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := driveMultiAuthWithHeaders(t, http.MethodGet,
				"/api/v1/projects/:id/sbom",
				"/api/v1/projects/"+seed.projectID.String()+"/sbom",
				tc.headers)

			if !r.handlerRan || r.status != http.StatusOK {
				t.Fatalf("%s: self-hosted anonymous access was refused (status %d, body %s); "+
					"the fix for an UNUSABLE credential must not change the NO-credential case",
					tc.name, r.status, r.body)
			}
			if r.sawAPIKey {
				t.Errorf("%s: the handler saw an API key on the context although none was sent",
					tc.name)
			}
			// Codex R1 (Low): "not the seeded tenant" is satisfied by uuid.Nil
			// and by any unrelated tenant, so it does not actually show the
			// self-hosted branch ran. handleSelfHostedAuth is the only thing
			// that stamps ContextKeyClerkUserID with this literal
			// (auth.go: c.Set(ContextKeyClerkUserID, "self-hosted")), and
			// GetAuthContext().IsSelfHosted keys off the same value.
			if r.sawClerkUser != "self-hosted" {
				t.Errorf("%s: handler saw clerk_user_id %q, want \"self-hosted\" — the request did "+
					"not go through Auth()'s self-hosted branch, so the default tenant/user was "+
					"never provisioned", tc.name, r.sawClerkUser)
			}
			if r.sawTenantID == uuid.Nil {
				t.Errorf("%s: handler saw no tenant at all; the self-hosted branch must bind the "+
					"default tenant before calling next", tc.name)
			}
			if r.sawTenantID == seed.tenantID {
				t.Errorf("%s: the anonymous fall-through resolved to the SEEDED tenant %s; it "+
					"must provision the default tenant instead", tc.name, seed.tenantID)
			}
		})
	}
}

// TestTheTwoAuthenticatorsResolveTheSamePrincipal — Codex R3 (Low).
//
// TestPresentedAPIKeyMatchesMultiAuth (multiauth_test.go) compares the two
// RESOLVERS, apiKeyCredential and presentedAPIKey. That is not the property
// worth having: reverting APIKeyAuth to `Header.Get` while leaving
// presentedAPIKey in place would keep it green and reinstate exactly the
// cross-route divergence it is named after.
//
// So this drives the two MIDDLEWARES, over one request that separates them.
// The request carries
//
//	X-API-Key:                       (empty — the value a first-value-only read stops at)
//	X-API-Key: <the SCOPED key>
//	Authorization: Bearer <the TENANT-LEVEL key>
//
// A middleware reading only the first X-API-Key value sees nothing there, falls
// back to Authorization, and authenticates the TENANT-LEVEL key — which carries
// no project scope at all. So "which key won" is observable as
// APIKeyProjectID(c), not merely as a status: both middlewares must reach their
// handler carrying the SCOPED key's project.
//
// It needs a live database because the divergence is only visible once both
// keys actually validate; the helper-level test is what covers the same ground
// in the default (untagged) gate.
func TestTheTwoAuthenticatorsResolveTheSamePrincipal(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	appDB := m50w3Open(t, appURL)
	migDB := m50w3Open(t, migURL)
	seed := m50w3SeedAuth(t, migDB)

	setHeaders := func(h http.Header) {
		h.Add(APIKeyHeader, "")
		h.Add(APIKeyHeader, seed.scopedKey)
		h.Set("Authorization", BearerPrefix+seed.tenantKey)
	}

	// One route per authenticator, both classified scopeProjectPathParam and
	// both addressed at the scoped key's OWN project, so the scope filter
	// admits whichever key it ends up with — the difference shows up in what
	// the handler SEES, not in the status.
	for _, tc := range []struct {
		name       string
		routePath  string
		requestURL string
		mw         echo.MiddlewareFunc
	}{
		{
			name:       "APIKeyAuth (/api/v1/mcp/*)",
			routePath:  "/api/v1/mcp/projects/:id/sboms",
			requestURL: "/api/v1/mcp/projects/" + seed.projectID.String() + "/sboms",
			mw:         APIKeyAuth(service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB))),
		},
		{
			name:       "MultiAuth (canonical routes)",
			routePath:  "/api/v1/projects/:id/sbom",
			requestURL: "/api/v1/projects/" + seed.projectID.String() + "/sbom",
			mw: MultiAuth(
				selfHostedConfig(t),
				repository.NewTenantRepository(appDB),
				repository.NewUserRepository(appDB),
				service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB)),
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			var out multiAuthHeaderResult
			e.GET(tc.routePath, func(c echo.Context) error {
				out.handlerRan = true
				out.sawProjectID, out.sawScoped = APIKeyProjectID(c)
				_, out.sawAPIKey = c.Get(ContextKeyAPI).(*model.APIKey)
				return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
			}, tc.mw)

			req := httptest.NewRequest(http.MethodGet, tc.requestURL, nil)
			setHeaders(req.Header)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			out.status, out.body = rec.Code, rec.Body.String()

			if !out.handlerRan || out.status != http.StatusOK {
				t.Fatalf("%s: request refused (status %d, body %s)", tc.name, out.status, out.body)
			}
			if !out.sawAPIKey {
				t.Fatalf("%s: no API key on the context", tc.name)
			}
			if !out.sawScoped || out.sawProjectID != seed.projectID {
				t.Errorf("%s: the handler saw scope (%s, scoped=%v); it authenticated the "+
					"TENANT-LEVEL key from Authorization instead of the project-scoped key sitting "+
					"in the second %s value. The other authenticator resolves the scoped key, so "+
					"one request is two principals depending on which route family it reaches.",
					tc.name, out.sawProjectID, out.sawScoped, APIKeyHeader)
			}
		})
	}
}

// TestMultiAuthXAPIKeyWinsOverAuthorization pins the precedence, which apikey.go
// already fixes for its own routes (it reads X-API-Key first and only falls back
// to Authorization). Two credentials naming different identities must not be
// resolved differently by the two middlewares, or the same request would be one
// principal on /api/v1/mcp/* and another on /api/v1/projects/*.
func TestMultiAuthXAPIKeyWinsOverAuthorization(t *testing.T) {
	_, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	seed := m50w3SeedAuth(t, migDB)

	r := driveMultiAuthWithHeaders(t, http.MethodGet,
		"/api/v1/projects/:id/sbom",
		"/api/v1/projects/"+seed.siblingID.String()+"/sbom",
		map[string]string{
			APIKeyHeader:    seed.scopedKey,
			"Authorization": "Bearer " + seed.tenantKey,
		})

	if r.status != http.StatusForbidden || r.handlerRan {
		t.Errorf("with a project-scoped key in %s and a tenant-level key in Authorization, "+
			"the request reached a sibling project (status %d, handlerRan=%v, body %s). "+
			"apikey.go resolves %s first; MultiAuth must resolve the same principal.",
			APIKeyHeader, r.status, r.handlerRan, r.body, APIKeyHeader)
	}
}
