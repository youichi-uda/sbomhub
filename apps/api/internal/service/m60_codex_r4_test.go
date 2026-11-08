package service

import (
	"strings"
	"testing"
)

// Codex M60 R4 High: the product identity used for the global "NVD knows no
// such product" cache entry and for candidate dedupe joined UNESCAPED fields
// with ':'. A quoted colon is valid CPE syntax and NVD has such products
// (mailcow:mailcow:_dockerized in CVE-2025-53909's configurations), so two
// different products shared one identity: one tenant scanning the unknown one
// could cache "no such product" for the other, globally, for 24h.
func TestM60R4_ProductIdentityIsInjective(t *testing.T) {
	a := cpeCandidates([]string{`cpe:2.3:a:mailcow\:mailcow:_dockerized:1:*:*:*:*:*:*:*`}, "", "")
	b := cpeCandidates([]string{`cpe:2.3:a:mailcow:mailcow\:_dockerized:1:*:*:*:*:*:*:*`}, "", "")
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("candidates: %v / %v", a, b)
	}
	if a[0].vendor != "mailcow:mailcow" || b[0].product != "mailcow:_dockerized" {
		t.Fatalf("parse: %+v / %+v", a[0], b[0])
	}
	if nvdNoCPECacheName(a[0]) == nvdNoCPECacheName(b[0]) {
		t.Errorf("two different products share the negative-cache key")
	}
	if a[0].productKey() == b[0].productKey() {
		t.Errorf("two different products share a product identity: %q", a[0].productKey())
	}
	both := cpeCandidates([]string{
		`cpe:2.3:a:mailcow\:mailcow:_dockerized:1:*:*:*:*:*:*:*`,
		`cpe:2.3:a:mailcow:mailcow\:_dockerized:1:*:*:*:*:*:*:*`,
	}, "", "")
	if len(both) != 2 {
		t.Errorf("candidate dedupe collapsed two different products: %v", both)
	}
}

// Codex M60 R4 Medium: CPE matching is case-insensitive, so case variants of
// one CPE are one CPE; they must not use up the storage cap and push a real
// candidate out.
func TestM60R4_StoredCPEDedupeIsCaseInsensitiveBeforeTheCap(t *testing.T) {
	var in []string
	base := "cpe:2.3:a:unknown:thing:1:*:*:*:*:*:*:*"
	for i := 0; i < maxStoredCPEsPerComponent; i++ {
		var b strings.Builder
		for j, r := range base {
			if j < 16 && (i>>(j%4))&1 == 1 && r >= 'a' && r <= 'z' {
				r -= 'a' - 'A'
			}
			b.WriteRune(r)
		}
		in = append(in, b.String())
	}
	in = append(in, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	got := normaliseSBOMCPEs(in)
	if got[len(got)-1] != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("the real candidate was pushed out by case variants: %q", got)
	}
}
