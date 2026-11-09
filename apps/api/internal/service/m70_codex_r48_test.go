package service

import "testing"

// Codex M70 R48 High-1: a repository-scoped package is not the
// distribution's; an affected entry scoped to a repository is refused.
func TestM70R48_RepositoryScoped(t *testing.T) {
	for _, p := range []string{
		"pkg:rpm/almalinux/openssl@3.0.7-27.el9?distro=almalinux-9&repository_url=https%3A%2F%2Fvendor.example%2Frpm",
		"pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&repository_url=https%3A%2F%2Fvendor.example%2Fdeb",
	} {
		if _, why := distroTargetFor(p, "", nil); why != "repository_scoped" {
			t.Errorf("%s: %q, want repository_scoped", p, why)
		}
	}
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?repository_url=https%3A%2F%2Fvendor.example%2Frpm"); err == nil {
		t.Error("repository-scoped affected entry accepted")
	}
}

// Codex M70 R49 Medium-2: the rpm distro suffix is a canonical release.
func TestM70R49_RPMDistroSuffix(t *testing.T) {
	for _, d := range []string{"el9.garbage", "almalinux-9.", "almalinux-09", "el9.1.2"} {
		if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?distro="+d); err == nil {
			t.Errorf("distro=%s accepted", d)
		}
	}
	for _, d := range []string{"el9", "almalinux-9.4"} {
		if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?distro="+d); err != nil {
			t.Errorf("distro=%s refused: %v", d, err)
		}
	}
}

// Codex M70 R50 High-1: an epoch-qualified rpm affected entry is refused.
func TestM70R50_RPMEpochQualifier(t *testing.T) {
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?epoch=1"); err == nil {
		t.Error("epoch-qualified rpm entry accepted")
	}
}

// Codex M70 R51 High-1: a versioned rpm affected purl (which may carry an
// epoch) is refused; Ubuntu's versioned deb purls stay accepted.
func TestM70R51_VersionedRPMPurl(t *testing.T) {
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p@1%3A3.0.1-1?distro=almalinux-9"); err == nil {
		t.Error("versioned rpm entry accepted")
	}
	if err := r32Query(t, "Ubuntu:22.04:LTS", "pkg:deb/ubuntu/p@3.0.2-0ubuntu1.10?arch=source&distro=jammy"); err != nil {
		t.Errorf("Ubuntu versioned purl refused: %v", err)
	}
}
