package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// Codex M60 R2 Medium-1: a CVE KEPT although it could not be verified
// (undecidable) must not carry the "verified" label. It is labelled
// nvd_cpe_unverified (low confidence), and a lookup holding one is not cached
// (the cache stores no per-CVE provenance).
func TestM60R2_UndecidableCVEsAreLabelledUnverified(t *testing.T) {
	// Serve the recorded log4j answer with one CVE's configurations removed:
	// that CVE cannot be verified.
	fx := m60NVDFixture(t, "p01_cpename_log4j")
	for i := range *fx.Vulnerabilities {
		if (*fx.Vulnerabilities)[i].CVE.ID == "CVE-2021-45046" {
			(*fx.Vulnerabilities)[i].CVE.Configurations = nil
		}
	}
	body, err := json.Marshal(fx)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	svc := NewNVDService(nil, nil, "", srv.URL, false)
	item := nvdWorkItem{
		key:        nvdComponentKey{Name: "log4j-core", Version: "2.14.1"},
		candidates: []cpeCandidate{{part: "a", vendor: "apache", product: "log4j", version: "2.14.1", raw: "2.14.1"}},
	}
	l, err := svc.lookupComponent(context.Background(), item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.vulns) != 10 || len(l.methods) != len(l.vulns) {
		t.Fatalf("vulns=%d methods=%d", len(l.vulns), len(l.methods))
	}
	for i, v := range l.vulns {
		want := model.MatchNVDCPE
		if v.CVEID == "CVE-2021-45046" {
			want = model.MatchNVDCPEUnverified
		}
		if l.methods[i] != want {
			t.Errorf("%s labelled %q, want %q", v.CVEID, l.methods[i], want)
		}
	}
	if !l.uncacheable {
		t.Errorf("a lookup holding an unverified CVE was marked cacheable")
	}
	if model.MatchNVDCPEUnverified.Confidence() != model.MatchConfidenceLow {
		t.Errorf("nvd_cpe_unverified confidence = %q, want low", model.MatchNVDCPEUnverified.Confidence())
	}
}

// Codex M60 R2 Medium-2: SPDX 2.2's CPE locator pattern is case-insensitive
// in its scheme and part ("cPE:/A:openssl:openssl:1.1.1k").
func TestM60R2_MixedCaseCPEPrefixIsAccepted(t *testing.T) {
	in := []string{"cPE:/A:openssl:openssl:1.1.1k", "CPE:2.3:A:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
	if got := normaliseSBOMCPEs(in, "1.0", ""); len(got) != 2 {
		t.Fatalf("normaliseSBOMCPEs dropped mixed-case CPEs: %q", got)
	}
	cs := cpeCandidates(in, "", "")
	if len(cs) != 2 || cs[0].String() != "a:openssl:openssl@1.1.1k" || cs[1].String() != "a:apache:log4j@2.14.1" {
		t.Errorf("candidates = %v", cs)
	}
}

// Codex M60 R2 Low-1: two components that would issue exactly the same
// lookups are one work item, even if their stored CPE lists differ only in
// entries past the candidate cap.
func TestM60R2_DedupKeyIsTheCandidatesUsed(t *testing.T) {
	base := []string{
		"cpe:2.3:a:a:a:1:*:*:*:*:*:*:*", "cpe:2.3:a:b:b:1:*:*:*:*:*:*:*", "cpe:2.3:a:c:c:1:*:*:*:*:*:*:*",
	}
	k1 := nvdWorkKey("x", "1", append(append([]string{}, base...), "cpe:2.3:a:d:d:1:*:*:*:*:*:*:*"), "")
	k2 := nvdWorkKey("x", "1", append(append([]string{}, base...), "cpe:2.3:a:e:e:1:*:*:*:*:*:*:*"), "")
	if k1 != k2 {
		t.Errorf("keys differ although the lookups are identical:\n%+v\n%+v", k1, k2)
	}
	if nvdWorkKey("x", "1", base[:1], "") == nvdWorkKey("x", "1", base[1:2], "") {
		t.Errorf("different candidates share a key")
	}
}
