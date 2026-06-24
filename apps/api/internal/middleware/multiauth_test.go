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
// Empty / unrecognised values default to RoleMember because
// APIKeyService.CreateKey defaults the permissions column to "write"
// when callers omit it (see internal/service/apikey.go:48). Without this
// default, legacy keys created before #F14 (when the column was unused
// for routing) would suddenly fail every CanWrite() check.
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

		// Defaults / robustness — these must NOT silently downgrade a
		// write-capable key into a viewer; that would have been the
		// regression mode if F14 mapped unknown values to RoleViewer.
		{"", model.RoleMember},
		{"   ", model.RoleMember},
		{"WRITE", model.RoleMember},  // case-insensitive
		{"Admin", model.RoleAdmin},   // case-insensitive
		{"garbage", model.RoleMember}, // unknown defaults to member, NOT viewer
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
		{"", true, false},
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
