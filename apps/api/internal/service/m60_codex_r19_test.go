package service

import (
	"strings"
	"testing"
)

// Codex M60 R19 Medium: "the version as the SBOM stated it" includes its
// whitespace — "2.0 " is not plain, so it may not exclude anything.
func TestM60R19_WhitespaceInComponentVersionIsNotPlain(t *testing.T) {
	cs := cpeCandidates([]string{"cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}, "2.0 ", "")
	if len(cs) != 1 {
		t.Fatalf("candidates = %v", cs)
	}
	if cs[0].plain() {
		t.Errorf("candidate from version %q counted as plain", "2.0 ")
	}
	if cs[0].version != "2.0" {
		t.Errorf("query version = %q, want the trimmed 2.0", cs[0].version)
	}
}

// Codex M60 R19 Low: a QUOTED lone "*" or "-" is a literal value, not the
// logical ANY / NA, and it round-trips into the query quoted.
func TestM60R19_QuotedLogicalCharactersAreLiterals(t *testing.T) {
	n, ok := parseCPE(`cpe:2.3:a:acme:\*:1.0:*:*:*:*:*:*:*`)
	if !ok {
		t.Fatalf("a quoted * product was rejected")
	}
	if !cpeConcrete(n.Product) {
		t.Errorf("quoted * product read as ANY")
	}
	cs := cpeCandidates([]string{`cpe:2.3:a:acme:\*:1.0:*:*:*:*:*:*:*`}, "", "")
	if len(cs) != 1 || !strings.Contains(cs[0].query(), `:acme:\*:1.0:`) {
		t.Errorf("candidates = %v, want product literal * queried as \\*", cs)
	}
	// It is not equal to a bare-ANY product, and equal to itself.
	other, _ := parseCPE(`cpe:2.3:a:acme:-:1.0:*:*:*:*:*:*:*`)
	if other.Product == n.Product {
		t.Errorf("NA product and literal * product compare equal")
	}
	if _, ok := parseCPE(`cpe:2.3:a:acme:*:1.0:*:*:*:*:*:*:*`); ok {
		t.Errorf("bare * product (ANY) accepted as a concrete product")
	}
	lit, ok := parseCPE(`cpe:2.3:a:acme:widget:\-:*:*:*:*:*:*:*`)
	if !ok || !cpeConcrete(lit.Version) || lit.Version == "-" {
		t.Errorf("quoted - version read as NA: %+v %v", lit, ok)
	}
}
