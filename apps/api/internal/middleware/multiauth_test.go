package middleware

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

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
