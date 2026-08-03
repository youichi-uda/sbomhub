package middleware

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

// TestAPIKeyCredential pins the credential lookup MultiAuth performs, without a
// database. The behavioural consequences — the key is honoured, its project
// scope applies, an unusable one is refused instead of downgraded — are driven
// against a live stack in multiauth_xapikey_integration_test.go; this is the
// part that runs in the default `go test ./...` gate, where the integration
// tags are off.
//
// The two properties worth stating separately:
//
//   - `presented` is what makes the middleware fail-closed. It must be true for
//     any non-empty X-API-Key, INCLUDING values that are not `sbh_`-shaped:
//     the caller meant to authenticate, so the value has to validate rather
//     than be dropped in favour of the self-hosted default identity.
//   - it must be FALSE when no credential is offered (no header, empty header,
//     a bare Clerk JWT), because that is the self-host "curl with no header
//     still works" path, and the fix must not take it with it.
func TestAPIKeyCredential(t *testing.T) {
	const key = "sbh_0123456789abcdef0123456789abcdef"

	cases := []struct {
		name          string
		headers       map[string]string
		wantRaw       string
		wantPresented bool
	}{
		{"no headers at all", nil, "", false},
		{"empty X-API-Key is absent, as in apikey.go",
			map[string]string{APIKeyHeader: ""}, "", false},
		{"X-API-Key carries the key",
			map[string]string{APIKeyHeader: key}, key, true},
		// Fail-closed: a value that cannot possibly validate is still an
		// attempt. Returning presented=false here would restore exactly the
		// silent fall-through this lookup exists to remove.
		{"X-API-Key that is not key-shaped is still an attempt",
			map[string]string{APIKeyHeader: "definitely-not-a-key"},
			"definitely-not-a-key", true},
		{"X-API-Key of whitespace is an attempt, not an absence",
			map[string]string{APIKeyHeader: " "}, " ", true},
		{"Authorization: Bearer sbh_ carries the key",
			map[string]string{"Authorization": BearerPrefix + key}, key, true},
		// Authorization is shared with Clerk, so only the sbh_ prefix marks a
		// Bearer value as an API key. Widening this would route every web UI
		// session token into the API-key table.
		{"a Clerk JWT in Authorization is not an API key",
			map[string]string{"Authorization": BearerPrefix + "eyJhbGciOiJSUzI1NiJ9.e30.x"},
			"", false},
		{"a non-Bearer Authorization is not an API key",
			map[string]string{"Authorization": "Basic " + key}, "", false},
		// Precedence, matching APIKeyAuth: X-API-Key is read first. Without
		// this the same request would resolve to different principals on
		// /api/v1/mcp/* and /api/v1/projects/*.
		{"X-API-Key wins over Authorization",
			map[string]string{
				APIKeyHeader:    key,
				"Authorization": BearerPrefix + "sbh_ffffffffffffffffffffffffffffffff",
			}, key, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/x/sbom", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			raw, presented := apiKeyCredential(req)
			if presented != tc.wantPresented {
				t.Fatalf("presented = %v, want %v (headers %v)", presented, tc.wantPresented, tc.headers)
			}
			if raw != tc.wantRaw {
				t.Errorf("raw = %q, want %q", raw, tc.wantRaw)
			}
		})
	}
}

// TestAPIKeyCredentialDuplicateHeaders — Codex R1 (Medium).
//
// HTTP lets a field name repeat and Go keeps every value, but `Header.Get`
// returns only the FIRST. Reading the credential with Get therefore made
//
//	X-API-Key:
//	X-API-Key: sbh_<a real key>
//
// look like no credential at all, and the request fell through to the Clerk /
// self-hosted path — the same silent discard the whole change removes, reachable
// by prepending one empty header.
//
// Set() cannot express this; Add() is what the cases below use.
func TestAPIKeyCredentialDuplicateHeaders(t *testing.T) {
	const keyA = "sbh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const keyB = "sbh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cases := []struct {
		name          string
		values        []string
		authorization string
		wantRaw       string
		wantPresented bool
	}{
		{
			name:          "an empty value before a real one does not hide it",
			values:        []string{"", keyA},
			wantRaw:       keyA,
			wantPresented: true,
		},
		{
			// The dangerous variant: with Authorization ALSO set to something
			// the Clerk path would accept, a first-value-only read hands the
			// request to Clerk while an API key was sitting in the same header.
			name:          "an empty value cannot divert the request to the Clerk path",
			values:        []string{"", keyA},
			authorization: BearerPrefix + "eyJhbGciOiJSUzI1NiJ9.e30.x",
			wantRaw:       keyA,
			wantPresented: true,
		},
		{
			name:          "the same key repeated is one credential, not a conflict",
			values:        []string{keyA, keyA},
			wantRaw:       keyA,
			wantPresented: true,
		},
		{
			// Two different credentials. Answering with either is a guess about
			// which the caller meant, and "take the first" is precisely the rule
			// that produced the defect above. presented=true with no value is
			// how the middleware is told to refuse.
			name:          "two different keys are presented but unresolvable",
			values:        []string{keyA, keyB},
			wantRaw:       "",
			wantPresented: true,
		},
		{
			name:          "only empty values is still no credential",
			values:        []string{"", ""},
			wantRaw:       "",
			wantPresented: false,
		},
		{
			// ...and in that case Authorization is still consulted, so the
			// empty-means-absent rule does not swallow the other channel.
			name:          "only empty values falls through to Authorization",
			values:        []string{"", ""},
			authorization: BearerPrefix + keyB,
			wantRaw:       keyB,
			wantPresented: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/x/sbom", nil)
			for _, v := range tc.values {
				req.Header.Add(APIKeyHeader, v)
			}
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}
			raw, presented := apiKeyCredential(req)
			if presented != tc.wantPresented {
				t.Fatalf("presented = %v, want %v (values %q)", presented, tc.wantPresented, tc.values)
			}
			if raw != tc.wantRaw {
				t.Errorf("raw = %q, want %q (values %q)", raw, tc.wantRaw, tc.values)
			}
		})
	}
}

// TestMultiAuthReadsTheAPIKeyHeader — Codex R1 (Low).
//
// Every other proof that MultiAuth reads X-API-Key lives behind the
// `integration` build tag and skips itself when DATABASE_URL is unset, so
// `go test ./...` could go green with none of it exercised. TestAPIKeyCredential
// above does run there, but it calls the helper directly: it would pass
// unchanged if the helper existed and MultiAuth were still wired to the old
// Authorization-only lookup.
//
// This closes that gap without a database, by asking a question whose answer
// does not depend on one. The API-key service is built over a *sql.DB that
// cannot connect, so:
//
//   - X-API-Key present  → ValidateKey fails → 401, and the handler must not run.
//     Pre-fix the header was ignored, the request went to the self-hosted
//     branch, and that branch's own DB call failed with 500 — a different status
//     from a different code path, which is what makes this discriminating.
//   - no header          → still the self-hosted branch, so NOT 401.
//
// The unreachable database is the point, not a limitation: it makes the two
// paths answer differently without either of them succeeding.
func TestMultiAuthReadsTheAPIKeyHeader(t *testing.T) {
	t.Setenv("CLERK_SECRET_KEY", "")
	cfg := config.Load()
	if !cfg.IsSelfHosted() {
		t.Fatalf("expected a self-hosted config, got mode %q", cfg.Mode())
	}

	// A DSN that parses but cannot connect. sql.Open is lazy, so this never
	// touches the network until a query runs, and then it fails.
	db, err := sql.Open("postgres",
		"postgres://nobody:nobody@127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	mw := MultiAuth(
		cfg,
		repository.NewTenantRepository(db),
		repository.NewUserRepository(db),
		service.NewAPIKeyService(repository.NewAPIKeyRepository(db)),
	)

	drive := func(t *testing.T, set func(h http.Header)) (int, bool) {
		t.Helper()
		e := echo.New()
		handlerRan := false
		e.GET("/api/v1/projects/:id/sbom", func(c echo.Context) error {
			handlerRan = true
			return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
		}, mw)

		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/projects/3f1d6f6e-1b6a-4a7e-9f0b-2a5c8d4e1b90/sbom", nil)
		set(req.Header)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code, handlerRan
	}

	t.Run("a value in X-API-Key is validated as a credential", func(t *testing.T) {
		code, ran := drive(t, func(h http.Header) {
			h.Set(APIKeyHeader, "sbh_0123456789abcdef0123456789abcdef")
		})
		if ran {
			t.Fatalf("the handler ran for an unvalidatable credential (status %d)", code)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401. MultiAuth is not reading %s: the request took the "+
				"Clerk/self-hosted branch, whose own failure here is 500.", code, APIKeyHeader)
		}
	})

	t.Run("two conflicting X-API-Key values are refused, not guessed", func(t *testing.T) {
		code, ran := drive(t, func(h http.Header) {
			h.Add(APIKeyHeader, "sbh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
			h.Add(APIKeyHeader, "sbh_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		})
		if ran || code != http.StatusUnauthorized {
			t.Errorf("status %d handlerRan=%v, want 401 and no handler", code, ran)
		}
	})

	t.Run("no header still takes the self-hosted branch", func(t *testing.T) {
		code, ran := drive(t, func(http.Header) {})
		if ran {
			t.Fatalf("the handler ran although the self-hosted branch's DB is unreachable")
		}
		if code == http.StatusUnauthorized {
			t.Errorf("a credential-less request was answered 401; in self-hosted mode it must "+
				"reach Auth()'s default-tenant branch (which fails 500 here because the "+
				"database is unreachable, not because it refused). status %d", code)
		}
	})
}

// TestRoleFromAPIKeyPermissions_F14 pins the F14 contract (Codex M1
// round 6): api_keys.permissions must map onto the TenantContext role
// allowlist so handlers gated on CanWrite() / CanAdmin() accept API-key
// requests.
//
// M1 Codex review #F17 update (round 7): the default branch flipped
// from RoleMember (fail-open) to RoleViewer (fail-closed). The legacy
// rationale was "APIKeyService.CreateKey fills empty input with 'write',
// so empty here is just legacy keys" — but that argument collapsed
// the moment any non-default unrecognised value (typo, "readonly",
// "none") could reach the persisted column. Treating those as RoleMember
// silently promoted them to write-capable on every MultiAuth-fronted
// endpoint. The fix is "anything not in the allowlist is RoleViewer";
// creation-time validation in apikey.go::CreateKey now refuses such
// values up front so the persisted column stays clean going forward.
func TestRoleFromAPIKeyPermissions_F14(t *testing.T) {
	cases := []struct {
		perm string
		want string
	}{
		// Documented happy-path values.
		{"read", model.RoleViewer},
		{"write", model.RoleMember},
		{"admin", model.RoleAdmin},
		{"owner", model.RoleAdmin},

		// Case-insensitivity and trimming.
		{"WRITE", model.RoleMember},
		{"Admin", model.RoleAdmin},
		{"  read  ", model.RoleViewer},

		// F17 fail-closed: every value below previously mapped to
		// RoleMember and therefore satisfied CanWrite() on every
		// MultiAuth-fronted endpoint. They must now map to RoleViewer
		// so a row that escaped CreateKey's allowlist (direct INSERT,
		// schema downgrade, etc.) cannot be used to drive writes.
		{"", model.RoleViewer},
		{"   ", model.RoleViewer},
		{"garbage", model.RoleViewer},
		{"readonly", model.RoleViewer}, // documented F17 typo example
		{"none", model.RoleViewer},     // documented F17 typo example
	}

	for _, tc := range cases {
		t.Run(tc.perm, func(t *testing.T) {
			got := roleFromAPIKeyPermissions(tc.perm)
			if got != tc.want {
				t.Errorf("roleFromAPIKeyPermissions(%q) = %q, want %q",
					tc.perm, got, tc.want)
			}
		})
	}
}

// TestRoleFromAPIKeyPermissions_UnknownDefaults_ToViewer is the
// regression test for M1 Codex review #F17 specifically. The previous
// implementation returned RoleMember in the default case, which made
// any unrecognised permission string (typos, "readonly", "none",
// "garbage", direct-INSERT empties) silently write-capable. That is the
// definition of a fail-open default in a security product. The fix
// flips the default to RoleViewer so the worst case for an unknown
// value is "read but not write" rather than "full member-tier write".
//
// Companion: TestIsKnownAPIKeyPermission below pins the creation-time
// allowlist so unknown values are also rejected up front (the two-layer
// contract: validate at write, fail-closed at read).
func TestRoleFromAPIKeyPermissions_UnknownDefaults_ToViewer(t *testing.T) {
	for _, perm := range []string{
		"", "   ", "garbage", "readonly", "none",
		"WRITEONLY", "write_only", "rw", "*", "delete",
	} {
		t.Run(perm, func(t *testing.T) {
			got := roleFromAPIKeyPermissions(perm)
			if got != model.RoleViewer {
				t.Errorf("F17: unknown permission %q must map to RoleViewer, got %q (fail-open)",
					perm, got)
			}
		})
	}
}

// TestIsKnownAPIKeyPermission pins the F17 creation-time allowlist.
// APIKeyService.CreateKey consults this helper to refuse unknown values
// with 400 rather than silently persisting them. Recognised values are
// the four the wire contract documents: read / write / admin / owner.
// Everything else (typos, empty, arbitrary strings) is rejected.
func TestIsKnownAPIKeyPermission(t *testing.T) {
	for _, perm := range []string{"read", "write", "admin", "owner", "WRITE", "Admin", "  read  "} {
		t.Run("known/"+perm, func(t *testing.T) {
			if !IsKnownAPIKeyPermission(perm) {
				t.Errorf("F17: %q must be a known permission", perm)
			}
		})
	}
	for _, perm := range []string{"", "   ", "readonly", "none", "garbage", "rw", "*", "delete"} {
		t.Run("unknown/"+perm, func(t *testing.T) {
			if IsKnownAPIKeyPermission(perm) {
				t.Errorf("F17: %q must NOT be a known permission (fail-closed)", perm)
			}
		})
	}
}

// TestRoleFromAPIKeyPermissions_F14_CanWrite verifies the mapping
// composes correctly with TenantContext.CanWrite(): every
// permission tier except explicit "read" must satisfy CanWrite() so
// triage/run, /vex-drafts/:id/decision, and /vex-drafts/:id/reanalyse
// are reachable.
//
// We construct a TenantContext directly with the mapped role rather than
// going through a real Echo request — the role mapping is the only piece
// being exercised, and the indirect coupling to TenantContext is the
// regression vector (Codex pointed out that wiring MultiAuth without
// setting Role would silently fail CanWrite even with a correct
// Permissions field).
func TestRoleFromAPIKeyPermissions_F14_CanWrite(t *testing.T) {
	cases := []struct {
		perm         string
		wantCanWrite bool
		wantCanAdmin bool
	}{
		{"read", false, false},
		{"write", true, false},
		{"admin", true, true},
		// F17: empty / unknown is now fail-closed (RoleViewer) — no
		// CanWrite, no CanAdmin. Pre-F17 this row would have been
		// {true, false} because the legacy default was RoleMember.
		{"", false, false},
		{"garbage", false, false},
	}

	for _, tc := range cases {
		t.Run(tc.perm, func(t *testing.T) {
			role := roleFromAPIKeyPermissions(tc.perm)

			// Reproduce TenantContext.CanWrite() / CanAdmin() inline so
			// this test does not need to spin up an echo.Context just to
			// read back a single string. Keep the allowlists in sync with
			// internal/middleware/tenant.go.
			canWrite := role == model.RoleOwner ||
				role == model.RoleAdmin ||
				role == model.RoleMember
			canAdmin := role == model.RoleOwner ||
				role == model.RoleAdmin

			if canWrite != tc.wantCanWrite {
				t.Errorf("perm=%q role=%q CanWrite=%v, want %v",
					tc.perm, role, canWrite, tc.wantCanWrite)
			}
			if canAdmin != tc.wantCanAdmin {
				t.Errorf("perm=%q role=%q CanAdmin=%v, want %v",
					tc.perm, role, canAdmin, tc.wantCanAdmin)
			}
		})
	}
}
