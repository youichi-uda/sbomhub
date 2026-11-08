package service

import "testing"

// Codex M60 R12 High: an NA candidate ("2.0:-", final release only) and an
// ANY candidate ("2.0:*") verify differently (R11), so they must not share a
// cache entry or a work item. The query sent to NVD is the same for both.
func TestM60R12_UpdateNAAndAnyHaveDistinctIdentities(t *testing.T) {
	anyC := cpeCandidates([]string{"cpe:2.3:a:v:widget:2.0:*:*:*:*:*:*:*"}, "", "")[0]
	naC := cpeCandidates([]string{"cpe:2.3:a:v:widget:2.0:-:*:*:*:*:*:*"}, "", "")[0]
	if anyC.query() != naC.query() {
		t.Errorf("queries differ (%q / %q); NA is a local distinction only", anyC.query(), naC.query())
	}
	if nvdCPECacheName(anyC) == nvdCPECacheName(naC) {
		t.Errorf("ANY and NA candidates share a cache key")
	}
	k1 := nvdWorkKey("widget", "2.0", []string{"cpe:2.3:a:v:widget:2.0:*:*:*:*:*:*:*"}, "")
	k2 := nvdWorkKey("widget", "2.0", []string{"cpe:2.3:a:v:widget:2.0:-:*:*:*:*:*:*"}, "")
	if k1 == k2 {
		t.Errorf("ANY and NA components share a work item")
	}
}

// Codex M60 R12 Medium-2: empty segments and leading/trailing separators
// ("1..0", ".1", "1.0.") are not collapsed into a decided comparison.
func TestM60R12_EmptySegmentsAreUndecidable(t *testing.T) {
	for _, tc := range []struct{ a, b string }{{"1..0", "1.0"}, {".1", "1"}, {"1.0.", "1.0"}, {"1.0--rc1", "1.0-rc1"}} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
	if c, ok := compareVersions("1.0+build..x", "1.0"); !ok || c != 0 {
		t.Errorf("build metadata is ignored whatever it contains: %d,%v", c, ok)
	}
}
