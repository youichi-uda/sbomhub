package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/pkgversion"
)

// Codex M70 R44 Medium-2: "debian-N" must name the entry's release; a
// release whose codename is not known here gets no target.
func TestM70R44_UnknownReleases(t *testing.T) {
	if err := r32Query(t, "Debian:16", "pkg:deb/debian/p?distro=debian-17"); err == nil {
		t.Error("debian-17 accepted for Debian:16")
	}
	if err := r32Query(t, "Debian:16", "pkg:deb/debian/p?distro=debian-16"); err != nil {
		t.Errorf("debian-16 refused: %v", err)
	}
	for _, p := range []string{
		"pkg:deb/debian/p@1.0-1?distro=debian-16",
		"pkg:deb/ubuntu/p@1.0-1?distro=ubuntu-28.04",
	} {
		if _, why := distroTargetFor(p, "1.0-1", nil); why != "unknown_release" {
			t.Errorf("%s: %q, want unknown_release", p, why)
		}
	}
	if _, why := distroTargetFor("pkg:deb/ubuntu/p@1.0-1?distro=ubuntu-22.04", "1.0-1", nil); why != "" {
		t.Errorf("22.04: %q", why)
	}
}

// Codex M70 R44 Low-3: the rpm epoch never passes through int.
func TestM70R44_RPMEpochUint(t *testing.T) {
	c, err := pkgversion.CompareRPMEVR("1:1.0-1", "4294967295:1.0-1")
	if err != nil || c >= 0 {
		t.Errorf("compare = %d, %v", c, err)
	}
}
