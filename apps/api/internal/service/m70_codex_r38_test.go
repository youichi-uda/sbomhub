package service

import "testing"

// Codex M70 R38 Low-3: a raw "?" after "#" is a misplaced delimiter.
func TestM70R38_QuestionMarkInSubpath(t *testing.T) {
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p#src?arch=x86_64"); err == nil {
		t.Error("affected purl with '?' in the subpath accepted")
	}
	if _, ok := parsePurl("pkg:deb/debian/openssl@1.1.1k-1#src?distro=debian-11"); ok {
		t.Error("component purl with '?' in the subpath accepted")
	}
}
