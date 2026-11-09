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

// Codex M70 R39 Medium-2: a named source keeps its identity across endpoint
// credential changes; unnamed sources are told apart by the full URL.
func TestM70R39_NamedSourceIdentity(t *testing.T) {
	a := NewDistroServiceWithSourceID(nil, "https://m.example/v1?key=old", "corp-osv", nil, true)
	b := NewDistroServiceWithSourceID(nil, "https://m.example/v1?key=new", "corp-osv", nil, true)
	if a.sourceID != b.sourceID {
		t.Error("a named source changed identity with its credential")
	}
	c := NewDistroService(nil, "https://m.example/v1?key=old", nil, true)
	d := NewDistroService(nil, "https://m.example/v1?key=new", nil, true)
	if c.sourceID == d.sourceID || c.sourceID == a.sourceID {
		t.Error("unnamed sources not told apart")
	}
}
