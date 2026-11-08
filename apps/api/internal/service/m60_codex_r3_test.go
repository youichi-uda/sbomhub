package service

import (
	"testing"
)

// Codex M60 R3 Low: when no CPE candidate survives, the lookup is the plain
// keyword search whatever the purl says, so distro-ness must not split the
// work item (two identical keyword walks on a cold cache).
func TestM60R3_DistroDoesNotSplitKeywordOnlyWork(t *testing.T) {
	a := nvdWorkKey("openssl", "1.1.1k", nil, "pkg:deb/debian/openssl@1.1.1k")
	b := nvdWorkKey("openssl", "1.1.1k", nil, "pkg:generic/openssl@1.1.1k")
	if a != b {
		t.Errorf("keyword-only items split by distro-ness: %+v vs %+v", a, b)
	}
	cpe := []string{"cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}
	if nvdWorkKey("openssl", "1.1.1k", cpe, "pkg:deb/debian/openssl@1.1.1k") ==
		nvdWorkKey("openssl", "1.1.1k", cpe, "pkg:generic/openssl@1.1.1k") {
		t.Errorf("CPE items with different labels (distro vs not) share a key")
	}
}
