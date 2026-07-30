//go:build integration

// Package handler — M50 W3: the two project-LIST routes answer a project-scoped
// API key with that key's own project instead of refusing.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M50W3' ./internal/handler
//
// -count=1 is load-bearing (F344): live DB state is not an input to go's test
// cache.
//
// # What this file is for
//
// M50 W2 classified both project lists scopeTenantWide and refused them, on the
// general principle that narrowing a tenant-wide answer silently changes what
// its fields mean. That principle holds for /mcp/dashboard/summary (counters
// computed over a population the body does not name) and for /mcp/search/cve
// (a miss reads as "absent from the tenant"). It does not hold for a project
// list, whose body IS the population: every element is a project the credential
// can in fact address, and no field is computed over a wider set than the one
// shown.
//
// The cost of refusing was measured on a live server (see the observation notes
// on each test): `sbomhub doctor` reported FAIL because it probes
// GET /api/v1/cli/projects as its auth check, and `sbomhub projects list` was
// refused outright.
//
// # Why both routes are in one file
//
// GET /api/v1/cli/projects is served by CLIHandler.ListProjects and
// GET /api/v1/mcp/projects by ProjectHandler.List — two handlers, two services,
// one contract. The M50 W2 note that "narrowing only the CLI copy would leave
// two structurally identical routes disagreeing" is exactly the failure this
// file is built to catch, so every scoped-key case below is asserted against
// BOTH handlers and TestM50W3TheTwoProjectListRoutesAgree compares their
// answers directly.
//
// # The regression this file also fences
//
// ProjectHandler.List is registered TWICE in cmd/server/main.go: on the
// MCP group (API key), and at `auth.GET("/projects", ...)` behind the Clerk /
// self-hosted chain, which no API key can reach (appmw.Auth verifies a JWT or,
// in anonymous mode, ignores the Authorization header — pinned by
// TestM50W2APIKeyReachableRoutesAreAllClassified, which does not classify
// GET /api/v1/projects because it is not API-key-reachable). Narrowing the
// handler unconditionally would blank the web UI's project list. The narrowing
// therefore keys off middleware.APIKeyProjectID, and
// TestM50W3NoAPIKeyCredentialSeesTheWholeTenant drives the handler in exactly
// the context state that chain produces.
package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/middleware"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func m50w3ProjectHandler(appDB *sql.DB) *ProjectHandler {
	return NewProjectHandler(service.NewProjectService(repository.NewProjectRepository(appDB)))
}

// m50w3Lister is one of the two project-list routes: a label for failure
// messages, the handler to drive, the route it is mounted at, and a decoder for
// its response shape.
//
// The two shapes differ and always have: /cli/projects answers
// `{"projects":[...],"total":N}` (handler.ProjectsListResponse) and
// /mcp/projects answers a bare `[...]`. This wave does not unify them — that
// would be a breaking change for existing tenant-level consumers of either
// route — so the decoder is per-route.
type m50w3Lister struct {
	label  string
	target string
	call   func(t *testing.T, appDB *sql.DB, r m50w2Req) (int, string)
	decode func(t *testing.T, body string) []model.Project
	// wantEmptyBody validates the EXACT wire form of an empty result for this
	// route, returning "" when it is correct. Per-route rather than shared:
	// a shared "is it an array anywhere?" check accepted a bare `[]` from the
	// CLI route, a `{"projects":[]}` with `total` missing, and a
	// `{"projects":[],"total":999}` (Codex R3, Low).
	wantEmptyBody func(body string) string
}

// TestM50W3EveryNarrowedRouteHasAHandlerUnderTest closes the fail-open shape of
// the scopeProjectListNarrowed classification (Codex R2, Medium).
//
// The middleware ADMITS every route it classifies scopeProjectListNarrowed and
// relies on that route's handler to narrow. Nothing in the middleware can check
// that, so a route added to the class whose handler still calls ListByTenant
// would serve the whole tenant to a project-scoped key. The middleware package's
// own pin (TestM50W3NarrowedListRoutesAreExactlyTheKnownTwo) does not catch it:
// its expected set is a literal, so adding the route to both the table and the
// literal keeps it green.
//
// This test makes the obligation land HERE, where the handlers are: the set of
// routes the table promises to narrow must equal the set of routes the tests
// below actually drive through a real handler against a live database.
func TestM50W3EveryNarrowedRouteHasAHandlerUnderTest(t *testing.T) {
	promised := middleware.APIKeyProjectListNarrowedRoutes()
	if len(promised) == 0 {
		t.Fatal("middleware classifies no route scopeProjectListNarrowed — either the " +
			"classification was removed (in which case delete this file) or the accessor is blind")
	}

	// The listers are all GET; the method is part of the key the middleware
	// table uses, so it is spelled out rather than assumed.
	covered := map[string]bool{}
	for _, l := range m50w3Listers(nil) {
		covered[http.MethodGet+" "+l.target] = true
	}

	for _, key := range promised {
		if !covered[key] {
			t.Errorf("middleware.apiKeyRouteScope promises to NARROW %q, but no lister in "+
				"m50w3Listers drives it, so no test in this file proves its handler narrows "+
				"anything. Add a lister (handler + response decoder) before classifying a "+
				"route scopeProjectListNarrowed — the middleware admits it unconditionally.", key)
		}
		delete(covered, key)
	}
	for key := range covered {
		t.Errorf("m50w3Listers drives %q as a narrowed project list, but the middleware does "+
			"not classify it scopeProjectListNarrowed. Either the classification was changed "+
			"(and this file's expectations with it) or the lister is testing the wrong route.", key)
	}
}

func m50w3Listers(appDB *sql.DB) []m50w3Lister {
	cli := m50w2CLIHandler(appDB)
	prj := m50w3ProjectHandler(appDB)
	return []m50w3Lister{
		{
			label:  "GET /api/v1/cli/projects (CLIHandler.ListProjects)",
			target: "/api/v1/cli/projects",
			call: func(t *testing.T, db *sql.DB, r m50w2Req) (int, string) {
				return m50w2Call(t, db, r, cli.ListProjects)
			},
			decode: func(t *testing.T, body string) []model.Project {
				t.Helper()
				var out ProjectsListResponse
				if err := json.Unmarshal([]byte(body), &out); err != nil {
					t.Fatalf("decode /cli/projects body %q: %v", body, err)
				}
				if out.Total != len(out.Projects) {
					t.Errorf("total=%d but %d projects were returned; `total` is the "+
						"length of the list, not a tenant-wide count",
						out.Total, len(out.Projects))
				}
				return out.Projects
			},
			wantEmptyBody: func(body string) string {
				var decoded any
				if err := json.Unmarshal([]byte(body), &decoded); err != nil {
					return fmt.Sprintf("body is not valid JSON (%v)", err)
				}
				obj, ok := decoded.(map[string]any)
				if !ok {
					return fmt.Sprintf("body is a JSON %T; this route answers "+
						`{"projects":[...],"total":N}`, decoded)
				}
				raw, ok := obj["projects"]
				if !ok {
					return `object has no "projects" key`
				}
				arr, ok := raw.([]any)
				if !ok {
					return fmt.Sprintf(`"projects" is %T, not a JSON array`, raw)
				}
				if len(arr) != 0 {
					return fmt.Sprintf(`"projects" has %d elements, want 0`, len(arr))
				}
				total, ok := obj["total"]
				if !ok {
					return `object has no "total" key; the CLI contract carries it always`
				}
				if n, ok := total.(float64); !ok || n != 0 {
					return fmt.Sprintf(`"total" is %v, want 0 alongside an empty list`, total)
				}
				// Exactly these two keys. Extra fields are what an added
				// disclosure would look like — `{"projects":[],"total":0,
				// "all_projects":[...]}` satisfied every check above, and the
				// typed decoder ignores unknown fields too (Codex R4, Low).
				for k := range obj {
					if k != "projects" && k != "total" {
						return fmt.Sprintf("object carries an unexpected field %q; this "+
							"route's contract is exactly {projects,total}", k)
					}
				}
				return ""
			},
		},
		{
			label:  "GET /api/v1/mcp/projects (ProjectHandler.List)",
			target: "/api/v1/mcp/projects",
			call: func(t *testing.T, db *sql.DB, r m50w2Req) (int, string) {
				return m50w2Call(t, db, r, prj.List)
			},
			decode: func(t *testing.T, body string) []model.Project {
				t.Helper()
				var out []model.Project
				if err := json.Unmarshal([]byte(body), &out); err != nil {
					t.Fatalf("decode /mcp/projects body %q: %v", body, err)
				}
				return out
			},
			wantEmptyBody: func(body string) string {
				var decoded any
				if err := json.Unmarshal([]byte(body), &decoded); err != nil {
					return fmt.Sprintf("body is not valid JSON (%v)", err)
				}
				arr, ok := decoded.([]any)
				if !ok {
					return fmt.Sprintf("body is a JSON %T; this route answers a bare array", decoded)
				}
				if len(arr) != 0 {
					return fmt.Sprintf("array has %d elements, want 0", len(arr))
				}
				return ""
			},
		},
	}
}

// m50w3List drives one lister and returns the decoded projects, failing the test
// unless the status is 200.
func m50w3List(t *testing.T, appDB *sql.DB, l m50w3Lister, r m50w2Req) []model.Project {
	t.Helper()
	r.method = http.MethodGet
	r.target = l.target
	code, body := l.call(t, appDB, r)
	if code != http.StatusOK {
		t.Fatalf("%s: status %d body %s, want 200", l.label, code, body)
	}
	return l.decode(t, body)
}

func m50w3IDs(projects []model.Project) map[uuid.UUID]model.Project {
	out := make(map[uuid.UUID]model.Project, len(projects))
	for _, p := range projects {
		out[p.ID] = p
	}
	return out
}

// ---------------------------------------------------------------------------
// 1. A project-scoped key sees exactly its own project — on both routes.
// ---------------------------------------------------------------------------

// TestM50W3ScopedKeySeesOnlyItsOwnProject is the core case.
//
// Observed before this change (2026-07-30, `go run ./cmd/server` on :8099
// against the dev database, an api_keys row with project_id set to p1):
//
//	GET /api/v1/cli/projects -> 403 {"error":"forbidden"}
//	GET /api/v1/mcp/projects -> 403 {"error":"forbidden"}
//
// and with a tenant-level key both answered 200 with BOTH projects, which is
// the authority the scoped key must not have.
func TestM50W3ScopedKeySeesOnlyItsOwnProject(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "listscope")

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			got := m50w3List(t, appDB, l, m50w2Req{
				tenantID: seed.tenantID,
				key:      m50w2ProjectKey(seed.tenantID, seed.project1ID),
			})
			if len(got) != 1 {
				t.Fatalf("%s: returned %d projects, want exactly the key's own one: %+v",
					l.label, len(got), got)
			}
			if got[0].ID != seed.project1ID {
				t.Errorf("%s: returned project %s (%q), want the key's project %s",
					l.label, got[0].ID, got[0].Name, seed.project1ID)
			}
			if got[0].Name != seed.project1 {
				t.Errorf("%s: name = %q, want %q", l.label, got[0].Name, seed.project1)
			}
			// The sibling is the project RLS cannot separate from the key's:
			// same tenant, same table. Only api_keys.project_id can.
			if _, leaked := m50w3IDs(got)[seed.project2ID]; leaked {
				t.Errorf("%s: the sibling project %s is in the list", l.label, seed.project2ID)
			}
		})
	}
}

// TestM50W3TheTwoProjectListRoutesAgree is the reason both routes were changed
// in one wave rather than the CLI one alone. The two are served by different
// handlers over different services; the contract is that a given credential
// gets the same project SET from either.
func TestM50W3TheTwoProjectListRoutesAgree(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "twins")
	listers := m50w3Listers(appDB)

	for _, tc := range []struct {
		name string
		req  m50w2Req
	}{
		{"project-scoped key", m50w2Req{tenantID: seed.tenantID, key: m50w2ProjectKey(seed.tenantID, seed.project1ID)}},
		{"tenant-level key", m50w2Req{tenantID: seed.tenantID, key: m50w2TenantKey(seed.tenantID)}},
		{"no API-key credential", m50w2Req{tenantID: seed.tenantID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := m50w3IDs(m50w3List(t, appDB, listers[0], tc.req))
			b := m50w3IDs(m50w3List(t, appDB, listers[1], tc.req))
			// Non-vacuity: two empty lists agree, and would agree just as well
			// if both routes were broken in the same direction. Every case in
			// this table seeds two projects and uses a credential entitled to
			// at least one of them, so an empty answer is a failure, not an
			// agreement.
			if len(a) == 0 || len(b) == 0 {
				t.Fatalf("%s: %s returned %d projects and %s returned %d; both must be "+
					"non-empty for the comparison below to mean anything",
					tc.name, listers[0].label, len(a), listers[1].label, len(b))
			}
			for id := range a {
				if _, ok := b[id]; !ok {
					t.Errorf("%s has project %s, %s does not — the two project-list "+
						"routes disagree about what this credential sees",
						listers[0].label, id, listers[1].label)
				}
			}
			for id := range b {
				if _, ok := a[id]; !ok {
					t.Errorf("%s has project %s, %s does not — the two project-list "+
						"routes disagree about what this credential sees",
						listers[1].label, id, listers[0].label)
				}
			}
		})
	}
}

// TestM50W3NarrowedRowIsTheSameRowAsTheTenantWideOne pins that narrowing changes
// the LENGTH of the list and nothing else. If the scoped path fetched the
// project through a different query it could quietly return a different field
// set (repository.ProjectRepository.Get, for instance, selects tenant_id, which
// ListByTenant does not), and the response would then tell a project-scoped
// caller something a tenant-level caller is not told.
func TestM50W3NarrowedRowIsTheSameRowAsTheTenantWideOne(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "samerow")

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			// Two-value lookup: `m[missing]` yields a zero model.Project, and
			// comparing that against a zero-valued narrowed row would pass
			// while proving nothing (Codex R2, Low).
			wide, ok := m50w3IDs(m50w3List(t, appDB, l, m50w2Req{
				tenantID: seed.tenantID,
				key:      m50w2TenantKey(seed.tenantID),
			}))[seed.project1ID]
			if !ok {
				t.Fatalf("%s: the tenant-wide list does not contain project %s, so there is "+
					"nothing to compare the narrowed row against", l.label, seed.project1ID)
			}
			if wide.ID != seed.project1ID || wide.Name != seed.project1 {
				t.Fatalf("%s: the tenant-wide row for %s came back as %+v; the comparison "+
					"below would be against a row that is already wrong",
					l.label, seed.project1ID, wide)
			}
			narrow := m50w3List(t, appDB, l, m50w2Req{
				tenantID: seed.tenantID,
				key:      m50w2ProjectKey(seed.tenantID, seed.project1ID),
			})
			if len(narrow) != 1 {
				t.Fatalf("%s: narrowed list has %d entries, want 1", l.label, len(narrow))
			}
			wideJSON, err := json.Marshal(wide)
			if err != nil {
				t.Fatalf("marshal tenant-wide row: %v", err)
			}
			narrowJSON, err := json.Marshal(narrow[0])
			if err != nil {
				t.Fatalf("marshal narrowed row: %v", err)
			}
			if string(wideJSON) != string(narrowJSON) {
				t.Errorf("%s: the same project serialises differently depending on the "+
					"credential.\n tenant-level: %s\n project-scoped: %s",
					l.label, wideJSON, narrowJSON)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. Non-regression: every credential that is NOT a project-scoped key is
//    unchanged.
// ---------------------------------------------------------------------------

// TestM50W3TenantLevelKeySeesTheWholeTenant is the fence around every api_keys
// row that exists today (`project_id IS NULL`).
func TestM50W3TenantLevelKeySeesTheWholeTenant(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "tenantkey")

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			got := m50w3IDs(m50w3List(t, appDB, l, m50w2Req{
				tenantID: seed.tenantID,
				key:      m50w2TenantKey(seed.tenantID),
			}))
			for _, want := range []uuid.UUID{seed.project1ID, seed.project2ID} {
				if _, ok := got[want]; !ok {
					t.Errorf("%s: tenant-level key no longer sees project %s", l.label, want)
				}
			}
		})
	}
}

// TestM50W3NoAPIKeyCredentialSeesTheWholeTenant is the web-UI regression fence,
// and the reason the narrowing is conditional rather than unconditional.
//
// ProjectHandler.List also serves `auth.GET("/api/v1/projects")`, whose chain is
// appmw.Auth: a Clerk JWT, or in self-hosted mode (SBOMHUB_AUTH_MODE=anonymous)
// no credential at all. Neither sets middleware.ContextKeyAPI — the only three
// places that set it are APIKeyAuth, OptionalAPIKeyAuth (unwired) and MultiAuth's
// handleAPIKeyAuth, all in internal/middleware, enumerated by grepping the whole
// non-test source for `Set(ContextKeyAPI` on 2026-07-30. This case drives both
// handlers with ContextKeyAPI unset, which is exactly that state, and requires
// the full tenant list back.
func TestM50W3NoAPIKeyCredentialSeesTheWholeTenant(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "clerk")

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			got := m50w3IDs(m50w3List(t, appDB, l, m50w2Req{tenantID: seed.tenantID}))
			for _, want := range []uuid.UUID{seed.project1ID, seed.project2ID} {
				if _, ok := got[want]; !ok {
					t.Errorf("%s: a request with no API-key credential (Clerk session / "+
						"self-hosted default — the web UI's project list) no longer sees "+
						"project %s. The narrowing must key off the API key, not the route.",
						l.label, want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Edge cases of the narrowed answer.
// ---------------------------------------------------------------------------

// TestM50W3UnresolvableKeyProjectYieldsAnEmptyListNot500 drives the branch where
// the key's project cannot be resolved under the key's own tenant.
//
// What that state is NOT, checked rather than assumed: it is not "the project
// was deleted". `api_keys_project_id_fkey` is
// `REFERENCES projects(id) ON DELETE CASCADE` (pg_constraint, 2026-07-30), so
// deleting a project deletes its project-scoped keys with it — observed against
// a live server, where such a key is answered
// `401 {"error":"invalid API key"}` by ValidateKey and never reaches a handler.
// The production state that DOES reach here is the M50 W2 residual: a key whose
// project_id names another tenant's project, mintable before M47 W1 added the
// ownership check because the foreign key is on `projects(id)` and not on
// (tenant_id, id). TestM50W3KeyPointingAtAnotherTenantsProjectSeesNothing drives
// that one with two real tenants; this test drives the same handler branch with
// an unallocated UUID, so the branch stays covered independently of whether such
// a row can still be created.
//
// The answer must be 200 with an empty list, for two reasons. It is TRUE — the
// set of projects that credential can address is empty. And `sbomhub doctor`
// branches on the STATUS only (doctor.go step 5: 200 -> OK, 401 -> FAIL,
// 403 -> FAIL, anything else -> WARN), so an empty list is reported as
// `[OK] 認証 OK` and not mistaken for an authentication failure — which is
// correct here, because authentication did succeed and re-running
// `sbomhub login` would not help.
func TestM50W3UnresolvableKeyProjectYieldsAnEmptyListNot500(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "unresolvable")
	gone := uuid.New()

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			got := m50w3List(t, appDB, l, m50w2Req{
				tenantID: seed.tenantID,
				key:      m50w2ProjectKey(seed.tenantID, gone),
			})
			if len(got) != 0 {
				t.Errorf("%s: returned %d projects for a key whose project does not exist: %+v",
					l.label, len(got), got)
			}
		})
	}
}

// TestM50W3EmptyNarrowedListIsAnArrayNotNull pins the JSON shape of the empty
// case, which the decoders above cannot see (encoding/json accepts `null` into
// a slice).
//
// It applies to the NARROWED path only. The tenant-wide path still answers
// `null` / `"projects":null` for a tenant with no projects, because
// repository.ProjectRepository.ListByTenant returns a nil slice and that has
// been the response shape of `auth.GET("/api/v1/projects")` since before this
// wave. Changing it would be a contract change on the web route this wave is
// supposed to leave alone.
func TestM50W3EmptyNarrowedListIsAnArrayNotNull(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	seed := m50w2SeedTenant(t, migDB, "emptyshape")
	gone := uuid.New()

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			code, body := l.call(t, appDB, m50w2Req{
				method:   http.MethodGet,
				target:   l.target,
				tenantID: seed.tenantID,
				key:      m50w2ProjectKey(seed.tenantID, gone),
			})
			if code != http.StatusOK {
				t.Fatalf("%s: status %d body %s, want 200", l.label, code, body)
			}
			if why := l.wantEmptyBody(body); why != "" {
				t.Errorf("%s: %s (body: %s). A JSON consumer that maps over the result — "+
					"the MCP server does — throws on null and iterates zero times on [].",
					l.label, why, body)
			}
		})
	}
}

// TestM50W3KeyPointingAtAnotherTenantsProjectSeesNothing keeps the M50 W2
// residual true for the narrowed routes.
//
// `api_keys` has no RLS and no composite foreign key, so before M47 W1 added an
// ownership check to the mint route a row could name a project of a different
// tenant. Such a key still authenticates as its OWN tenant, so the narrowed
// lookup runs under that tenant and must find nothing — narrowing must not
// become a way to read across tenants.
func TestM50W3KeyPointingAtAnotherTenantsProjectSeesNothing(t *testing.T) {
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)

	mine := m50w2SeedTenant(t, migDB, "xtenant-a")
	theirs := m50w2SeedTenant(t, migDB, "xtenant-b")

	for _, l := range m50w3Listers(appDB) {
		t.Run(l.label, func(t *testing.T) {
			got := m50w3List(t, appDB, l, m50w2Req{
				tenantID: mine.tenantID,
				key:      m50w2ProjectKey(mine.tenantID, theirs.project1ID),
			})
			if len(got) != 0 {
				t.Errorf("%s: a key whose project_id names another tenant's project got "+
					"%d rows back: %+v", l.label, len(got), got)
			}
		})
	}
}
