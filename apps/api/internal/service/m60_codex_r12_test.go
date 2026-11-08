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
