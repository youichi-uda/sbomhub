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
