//go:build integration

// Package middleware — M50 W3: drive the REAL APIKeyAuth middleware with a REAL
// `sbh_...` string against a REAL api_keys row, and observe what reaches the
// handler.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50W3APIKeyAuth' ./internal/middleware
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # Why this file exists (Codex R2, Medium)
//
// Before it, the claim "a project-scoped key is refused on a tenant-wide route"
// rested on two tests that together do not reach the production middleware:
//
//   - TestM50W2ScopeCheckCoversEveryValidateKeyCallSite is an AST test. It
//     checks that every function calling APIKeyService.ValidateKey also mentions
//     the identifier apiKeyProjectScopeAllowed. It cannot see the ORDER of the
//     two, and it cannot see what the function does with the boolean.
//   - TestM50W2ScopeDenialShortCircuitsBeforeNext builds its own middleware that
//     calls apiKeyProjectScopeAllowed the way APIKeyAuth is supposed to. It
//     asserts on that reimplementation, not on APIKeyAuth.
//
// So `if ok, err := apiKeyProjectScopeAllowed(c, key); !ok { return err }` in
// apikey.go could have been written as `_, _ = apiKeyProjectScopeAllowed(c, key)`
// and both tests would still have passed while every refused route became
// reachable. This file removes that gap for the routes M50 W3 touches by
// constructing service.NewAPIKeyService over a live database and mounting the
// real APIKeyAuth on the real registered paths.
//
// # What it does NOT cover
//
// OptionalAPIKeyAuth, which is registered nowhere
// (TestM50W2OptionalAPIKeyAuthIsUnwired), still rests on the two tests above.
// The other two authenticators are covered: APIKeyAuth (the /api/v1/{mcp,cli}/*
// groups, where both narrowed list routes live) and MultiAuth's
// handleAPIKeyAuth (the canonical /api/v1/projects/:id/... routes) — the latter
// added in Codex R4, which pointed out that the same "calls the guard but drops
// the answer" regression was ungated there.
package middleware

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// m50w3Env returns the app-role and migrator-role DSNs, skipping when the
// compose stack is not up. Mirrors the handler package's m46b1HandlerEnv; it is
// duplicated rather than shared because the two live in different packages.
func m50w3Env(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL = os.Getenv("DATABASE_URL")
	migURL = os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" {
		t.Skip("DATABASE_URL unset — this test asserts against a live database")
	}
	if migURL == "" {
		migURL = appURL
	}
	return appURL, migURL
}

func m50w3Open(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("open %s: %v", url, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("ping: %v — this test asserts against a live database", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m50w3HashKey mirrors service.hashKey, which is unexported. If the two ever
// diverge every test here fails at the 401 assertion rather than silently
// passing, because the seeded row would stop matching the raw key.
func m50w3HashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type m50w3AuthSeed struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
	siblingID uuid.UUID
	scopedKey string // raw sbh_... whose api_keys.project_id = projectID
	tenantKey string // raw sbh_... whose api_keys.project_id IS NULL
}

func m50w3SeedAuth(t *testing.T, migDB *sql.DB) m50w3AuthSeed {
	t.Helper()

	s := m50w3AuthSeed{
		tenantID:  uuid.New(),
		projectID: uuid.New(),
		siblingID: uuid.New(),
		scopedKey: "sbh_" + hex.EncodeToString(uuid.New().NodeID()) + uuid.New().String(),
		tenantKey: "sbh_" + hex.EncodeToString(uuid.New().NodeID()) + uuid.New().String(),
	}

	org := "m50w3-auth-" + s.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		s.tenantID, org, "m50w3 auth", org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := s.tenantID
	t.Cleanup(func() {
		// api_keys.tenant_id and .project_id are both ON DELETE CASCADE, so
		// this one statement removes the projects and the keys with it.
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, s.tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3), ($4, $2, $5)`,
		s.projectID, s.tenantID, "m50w3-auth-own", s.siblingID, "m50w3-auth-sibling"); err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO api_keys (id, tenant_id, project_id, name, key_hash, key_prefix, permissions)
		 VALUES ($1, $2, $3, 'm50w3-scoped', $4, 'sbh_test', 'write'),
		        ($5, $2, NULL, 'm50w3-tenant', $6, 'sbh_test', 'write')`,
		uuid.New(), s.tenantID, s.projectID, m50w3HashKey(s.scopedKey),
		uuid.New(), m50w3HashKey(s.tenantKey)); err != nil {
		t.Fatalf("seed api keys: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed: %v", err)
	}
	return s
}

// m50w3AuthResult is what one request through the real middleware produced.
//
// It carries what APIKeyProjectID(c) reported inside the handler, not just
// whether the handler ran, because that is what the narrowing downstream
// actually consults: APIKeyAuth could admit the request correctly and still put
// a key on the context whose ProjectID is nil, and the list handler would then
// take the tenant-wide branch and return siblings (Codex R3, Medium).
type m50w3AuthResult struct {
	status       int
	body         string
	handlerRan   bool
	sawScoped    bool
	sawProjectID uuid.UUID
}

// m50w3DriveAPIKeyAuth mounts the REAL APIKeyAuth over a recording handler and
// issues one request bearing rawKey.
//
// The route is registered at `routePath` so that c.Path() inside the middleware
// is the registered path the scope table is keyed on — the same property
// TestM50W2EchoPathIsTheRegisteredRouteInMiddleware pins.
func m50w3DriveAPIKeyAuth(
	t *testing.T, appDB *sql.DB, method, routePath, requestURL, rawKey string,
) m50w3AuthResult {
	t.Helper()

	keyService := service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB))
	e := echo.New()
	var out m50w3AuthResult
	handler := func(c echo.Context) error {
		out.handlerRan = true
		out.sawProjectID, out.sawScoped = APIKeyProjectID(c)
		return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
	}
	e.Add(method, routePath, handler, APIKeyAuth(keyService))

	req := httptest.NewRequest(method, requestURL, nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	out.status, out.body = rec.Code, rec.Body.String()
	return out
}

// TestM50W3APIKeyAuthAdmitsTheNarrowedListRoutes: the two routes this wave
// reclassified must REACH their handler, because the narrowing lives there. A
// middleware refusal would pre-empt it and reinstate the 403 that broke
// `sbomhub doctor`.
func TestM50W3APIKeyAuthAdmitsTheNarrowedListRoutes(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	appDB := m50w3Open(t, appURL)
	seed := m50w3SeedAuth(t, migDB)

	for _, routePath := range []string{"/api/v1/cli/projects", "/api/v1/mcp/projects"} {
		t.Run(routePath, func(t *testing.T) {
			r := m50w3DriveAPIKeyAuth(
				t, appDB, http.MethodGet, routePath, routePath, seed.scopedKey)
			if !r.handlerRan {
				t.Fatalf("%s: the handler never ran for a project-scoped key (status %d, body %s); "+
					"the middleware refused a route whose narrowing is the handler's job",
					routePath, r.status, r.body)
			}
			if r.status != http.StatusOK {
				t.Errorf("%s: status %d body %s, want 200", routePath, r.status, r.body)
			}
			// Admission alone is not enough: the handler narrows by reading
			// APIKeyProjectID off the context, so the context must carry the
			// key's project. If it did not, the handler would see an apparent
			// tenant-level key and list the whole tenant.
			if !r.sawScoped {
				t.Errorf("%s: the handler sees NO project scope on the context, so it would "+
					"take the tenant-wide branch and return every project of the tenant to a "+
					"project-scoped key", routePath)
			} else if r.sawProjectID != seed.projectID {
				t.Errorf("%s: the handler sees project scope %s, want the key's %s",
					routePath, r.sawProjectID, seed.projectID)
			}
		})
	}
}

// TestM50W3APIKeyAuthStillRefusesWhatItRefusedBefore is the other half, and the
// one that fails if apikey.go stops propagating the scope decision. Each case
// must produce 403 AND must not run the handler.
func TestM50W3APIKeyAuthStillRefusesWhatItRefusedBefore(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	appDB := m50w3Open(t, appURL)
	seed := m50w3SeedAuth(t, migDB)

	for _, tc := range []struct{ name, method, routePath, requestURL string }{
		{"tenant aggregate", http.MethodGet,
			"/api/v1/mcp/dashboard/summary", "/api/v1/mcp/dashboard/summary"},
		{"cross-project CVE search", http.MethodGet,
			"/api/v1/mcp/search/cve", "/api/v1/mcp/search/cve?cve=CVE-2021-44228"},
		{"cross-project component search", http.MethodGet,
			"/api/v1/mcp/search/component", "/api/v1/mcp/search/component?name=log4j"},
		{"a sibling project named in the path", http.MethodGet,
			"/api/v1/cli/projects/:id", "/api/v1/cli/projects/" + uuid.New().String()},
		{"an unclassified route under an API-key prefix", http.MethodGet,
			"/api/v1/mcp/not-a-real-route", "/api/v1/mcp/not-a-real-route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := m50w3DriveAPIKeyAuth(
				t, appDB, tc.method, tc.routePath, tc.requestURL, seed.scopedKey)
			if r.handlerRan {
				t.Errorf("%s (%s): the handler RAN for a project-scoped key. APIKeyAuth "+
					"must return the refusal from apiKeyProjectScopeAllowed instead of "+
					"calling next.", tc.name, tc.routePath)
			}
			if r.status != http.StatusForbidden {
				t.Errorf("%s (%s): status %d body %s, want 403", tc.name, tc.routePath, r.status, r.body)
			}
		})
	}
}

// TestM50W3APIKeyAuthLeavesTenantLevelKeysAlone is the regression fence at the
// middleware level for keys with `project_id IS NULL`. Nothing in the code
// guarantees how common those are; what is measured is that the development
// database this wave was built against held 96 such keys and 0 project-scoped
// ones on 2026-07-30 (docs/UPGRADE.md §2d). A deployment's own mix is its own.
func TestM50W3APIKeyAuthLeavesTenantLevelKeysAlone(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	appDB := m50w3Open(t, appURL)
	seed := m50w3SeedAuth(t, migDB)

	for _, tc := range []struct{ routePath, requestURL string }{
		{"/api/v1/cli/projects", "/api/v1/cli/projects"},
		{"/api/v1/mcp/projects", "/api/v1/mcp/projects"},
		{"/api/v1/mcp/dashboard/summary", "/api/v1/mcp/dashboard/summary"},
		{"/api/v1/cli/projects/:id", "/api/v1/cli/projects/" + uuid.New().String()},
	} {
		t.Run(tc.routePath, func(t *testing.T) {
			r := m50w3DriveAPIKeyAuth(
				t, appDB, http.MethodGet, tc.routePath, tc.requestURL, seed.tenantKey)
			if !r.handlerRan || r.status != http.StatusOK {
				t.Errorf("%s: tenant-level key was refused (status %d, handlerRan=%v, body %s)",
					tc.routePath, r.status, r.handlerRan, r.body)
			}
			// And it must reach the handler as UNSCOPED, or the list handlers
			// would narrow for a key that is entitled to the whole tenant.
			if r.sawScoped {
				t.Errorf("%s: a tenant-level key (project_id IS NULL) reached the handler "+
					"carrying project scope %s", tc.routePath, r.sawProjectID)
			}
		})
	}
}

// m50w3DriveMultiAuth is the same drive against MultiAuth, the authenticator of
// the canonical routes registered directly on the Echo instance.
//
// MultiAuth needs a config and the tenant/user repositories because it falls
// through to Clerk when the Authorization header is not an `sbh_...` key. Every
// request here carries one, so only handleAPIKeyAuth is exercised; the Clerk
// branch is Auth()'s own tests' business.
func m50w3DriveMultiAuth(
	t *testing.T, appDB *sql.DB, method, routePath, requestURL, rawKey string,
) m50w3AuthResult {
	t.Helper()

	cfg := &config.Config{}
	mw := MultiAuth(
		cfg,
		repository.NewTenantRepository(appDB),
		repository.NewUserRepository(appDB),
		service.NewAPIKeyService(repository.NewAPIKeyRepository(appDB)),
	)
	e := echo.New()
	var out m50w3AuthResult
	handler := func(c echo.Context) error {
		out.handlerRan = true
		out.sawProjectID, out.sawScoped = APIKeyProjectID(c)
		return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
	}
	e.Add(method, routePath, handler, mw)

	req := httptest.NewRequest(method, requestURL, nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	out.status, out.body = rec.Code, rec.Body.String()
	return out
}

// TestM50W3MultiAuthEnforcesProjectScope closes the same gap on the second
// authenticator (Codex R4, Medium).
//
// MultiAuth fronts the canonical per-project routes. Nothing behavioural drove
// its handleAPIKeyAuth branch: TestM50W2ScopeCheckCoversEveryValidateKeyCallSite
// only checks that the identifier `apiKeyProjectScopeAllowed` appears in the same
// function as ValidateKey, so `_, _ = apiKeyProjectScopeAllowed(c, key)` would
// have kept it green while a project-scoped key reached a SIBLING project's SBOM
// — same tenant, so no downstream check separates them.
func TestM50W3MultiAuthEnforcesProjectScope(t *testing.T) {
	appURL, migURL := m50w3Env(t)
	migDB := m50w3Open(t, migURL)
	appDB := m50w3Open(t, appURL)
	seed := m50w3SeedAuth(t, migDB)

	const routePath = "/api/v1/projects/:id/sbom"

	t.Run("the key's own project is admitted, carrying its scope", func(t *testing.T) {
		r := m50w3DriveMultiAuth(t, appDB, http.MethodGet, routePath,
			"/api/v1/projects/"+seed.projectID.String()+"/sbom", seed.scopedKey)
		if !r.handlerRan || r.status != http.StatusOK {
			t.Fatalf("own project refused: status %d handlerRan=%v body %s",
				r.status, r.handlerRan, r.body)
		}
		if !r.sawScoped || r.sawProjectID != seed.projectID {
			t.Errorf("handler saw scope (%s, scoped=%v), want the key's %s",
				r.sawProjectID, r.sawScoped, seed.projectID)
		}
	})

	t.Run("a sibling project of the same tenant is refused", func(t *testing.T) {
		r := m50w3DriveMultiAuth(t, appDB, http.MethodGet, routePath,
			"/api/v1/projects/"+seed.siblingID.String()+"/sbom", seed.scopedKey)
		if r.handlerRan {
			t.Errorf("the handler RAN for a sibling project. MultiAuth must return the "+
				"refusal from apiKeyProjectScopeAllowed instead of calling next; the sibling "+
				"belongs to the same tenant, so nothing downstream separates them. "+
				"(status %d, body %s)", r.status, r.body)
		}
		if r.status != http.StatusForbidden {
			t.Errorf("status %d body %s, want 403", r.status, r.body)
		}
	})

	t.Run("a tenant-level key still reaches any project of its tenant", func(t *testing.T) {
		r := m50w3DriveMultiAuth(t, appDB, http.MethodGet, routePath,
			"/api/v1/projects/"+seed.siblingID.String()+"/sbom", seed.tenantKey)
		if !r.handlerRan || r.status != http.StatusOK {
			t.Errorf("tenant-level key refused on a project of its own tenant: status %d "+
				"handlerRan=%v body %s", r.status, r.handlerRan, r.body)
		}
		if r.sawScoped {
			t.Errorf("a tenant-level key reached the handler carrying project scope %s",
				r.sawProjectID)
		}
	})
}

// TestM50W3APIKeyAuthRejectsAnUnknownKey is the sanity check on the fixture: it
// shows that a key which is in no api_keys row is answered 401, so the seeded
// rows in the tests above are doing real work rather than every request failing
// authentication.
//
// The refusal assertions above do not actually depend on it — they require
// exactly 403, which a broken fixture producing 401 would fail (an earlier
// version of this comment claimed otherwise; Codex R3, Low). The admission
// tests do: they require 200, which only a matching row can produce.
func TestM50W3APIKeyAuthRejectsAnUnknownKey(t *testing.T) {
	appURL, _ := m50w3Env(t)
	appDB := m50w3Open(t, appURL)

	r := m50w3DriveAPIKeyAuth(t, appDB, http.MethodGet,
		"/api/v1/cli/projects", "/api/v1/cli/projects", "sbh_"+uuid.New().String())
	if r.handlerRan {
		t.Error("the handler ran for a key that is in no api_keys row")
	}
	if r.status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", r.status)
	}
}
