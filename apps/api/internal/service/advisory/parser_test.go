package advisory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// loadFixture reads a testdata file or fails the test.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("testdata", "advisories", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture %s: %v", p, err)
	}
	return b
}

func TestParsedAdvisory_Normalize(t *testing.T) {
	p := &ParsedAdvisory{
		CVEID:          "  CVE-2024-99999  ",
		Source:         SourceNVD,
		VulnFuncs:      []string{"pkg.Foo", "pkg.Foo", "  ", "pkg.Bar"},
		AffectedPaths:  []string{"a/b.go", "", "a/b.go"},
		RequiredConfig: nil,
		RequiredEnv:    []string{"DEBUG"},
		RawExcerpt:     "  hello world\n  ",
	}
	got := p.Normalize()
	if got.CVEID != "CVE-2024-99999" {
		t.Fatalf("CVEID not trimmed: %q", got.CVEID)
	}
	if len(got.VulnFuncs) != 2 || got.VulnFuncs[0] != "pkg.Foo" || got.VulnFuncs[1] != "pkg.Bar" {
		t.Fatalf("VulnFuncs not deduped/trimmed: %v", got.VulnFuncs)
	}
	if len(got.AffectedPaths) != 1 || got.AffectedPaths[0] != "a/b.go" {
		t.Fatalf("AffectedPaths not deduped: %v", got.AffectedPaths)
	}
	if got.FetchedAt.IsZero() {
		t.Fatal("FetchedAt should be set to now()")
	}
	if got.IsEmpty() {
		t.Fatal("not empty: has VulnFuncs")
	}
	empty := &ParsedAdvisory{RawExcerpt: "x"}
	if !empty.IsEmpty() {
		t.Fatal("expected IsEmpty true when only RawExcerpt is set")
	}
}

func TestSource_IsValid(t *testing.T) {
	for _, s := range []Source{SourceNVD, SourceGHSA, SourceJVN} {
		if !s.IsValid() {
			t.Fatalf("expected %q to be valid", s)
		}
	}
	if Source("other").IsValid() {
		t.Fatal("expected unknown source to be invalid")
	}
}

func TestNVDParser_ParseSingle(t *testing.T) {
	parser := NewNVDParser()
	raw := loadFixture(t, "nvd_cve-2024-24786.json")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.CVEID != "CVE-2024-24786" {
		t.Fatalf("CVEID = %q want CVE-2024-24786", got.CVEID)
	}
	if got.Source != SourceNVD {
		t.Fatalf("Source = %q want %q", got.Source, SourceNVD)
	}
	if !containsString(got.VulnFuncs, "protojson.Unmarshal") {
		t.Fatalf("expected VulnFuncs to contain protojson.Unmarshal, got %v", got.VulnFuncs)
	}
	if !containsString(got.AffectedPaths, "encoding/protojson/decode.go") {
		t.Fatalf("expected AffectedPaths to contain encoding/protojson/decode.go, got %v", got.AffectedPaths)
	}
	if got.RawExcerpt == "" {
		t.Fatal("RawExcerpt should be populated")
	}
}

func TestNVDParser_ParseEnvelopeWithEnv(t *testing.T) {
	parser := NewNVDParser()
	raw := loadFixture(t, "nvd_envelope_cve-2023-44487.json")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.CVEID != "CVE-2023-44487" {
		t.Fatalf("CVEID = %q want CVE-2023-44487", got.CVEID)
	}
	if !containsString(got.VulnFuncs, "http2.Server.serveConn") {
		t.Fatalf("expected VulnFuncs to contain http2.Server.serveConn, got %v", got.VulnFuncs)
	}
	if !containsString(got.RequiredEnv, "GODEBUG") {
		t.Fatalf("expected RequiredEnv to contain GODEBUG, got %v", got.RequiredEnv)
	}
}

func TestNVDParser_ParseUnsupportedType(t *testing.T) {
	parser := NewNVDParser()
	_, err := parser.Parse(context.Background(), 42)
	if err == nil {
		t.Fatal("expected error for unsupported payload type")
	}
}

func TestNVDParser_ParseNil(t *testing.T) {
	parser := NewNVDParser()
	got, err := parser.Parse(context.Background(), nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for nil payload, got %+v", got)
	}
}

func TestGHSAParser_ParseExplicitVulnFunctions(t *testing.T) {
	parser := NewGHSAParser()
	raw := loadFixture(t, "ghsa_ghsa-9763-4f94-gfch.json")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.CVEID != "CVE-2024-24786" {
		t.Fatalf("CVEID = %q want CVE-2024-24786", got.CVEID)
	}
	if got.Source != SourceGHSA {
		t.Fatalf("Source = %q want %q", got.Source, SourceGHSA)
	}
	// The fixture lists explicit vulnerable_functions on the per-vuln record.
	if !containsString(got.VulnFuncs, "encoding/protojson.Unmarshal") {
		t.Fatalf("expected encoding/protojson.Unmarshal in VulnFuncs, got %v", got.VulnFuncs)
	}
	if !containsString(got.VulnFuncs, "encoding/protojson.UnmarshalOptions.Unmarshal") {
		t.Fatalf("expected encoding/protojson.UnmarshalOptions.Unmarshal in VulnFuncs, got %v", got.VulnFuncs)
	}
	if !containsString(got.AffectedPaths, "encoding/protojson/decode.go") {
		t.Fatalf("expected encoding/protojson/decode.go in AffectedPaths, got %v", got.AffectedPaths)
	}
	if !containsString(got.RequiredEnv, "GODEBUG") {
		t.Fatalf("expected GODEBUG in RequiredEnv, got %v", got.RequiredEnv)
	}
}

func TestGHSAParser_ParseArray(t *testing.T) {
	parser := NewGHSAParser()
	raw := loadFixture(t, "ghsa_array_minimal.json")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	// CVE field is empty in the fixture; parser must fall back to GHSA id so
	// the excerpt is never keyed on an empty string.
	if got.CVEID != "GHSA-xxxx-yyyy-zzzz" {
		t.Fatalf("CVEID = %q want GHSA-xxxx-yyyy-zzzz (fallback)", got.CVEID)
	}
	if !got.IsEmpty() {
		t.Fatalf("expected IsEmpty=true (no extractable hints), got %+v", got)
	}
	if got.RawExcerpt == "" {
		t.Fatal("RawExcerpt should still be set for LLM fallback")
	}
}

func TestGHSAParser_ParseEmpty(t *testing.T) {
	parser := NewGHSAParser()
	got, err := parser.Parse(context.Background(), []byte(""))
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty payload, got %+v", got)
	}
}

func TestJVNParser_ParseRSS(t *testing.T) {
	parser := NewJVNParser()
	raw := loadFixture(t, "jvn_rss_jvndb-2024-000001.xml")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.Source != SourceJVN {
		t.Fatalf("Source = %q want %q", got.Source, SourceJVN)
	}
	// CVE alias should win over the JVNDB id.
	if got.CVEID != "CVE-2024-99999" {
		t.Fatalf("CVEID = %q want CVE-2024-99999", got.CVEID)
	}
	if !containsString(got.VulnFuncs, "filepath.Clean") {
		t.Fatalf("expected filepath.Clean in VulnFuncs, got %v", got.VulnFuncs)
	}
	if !containsString(got.AffectedPaths, "path/filepath/path.go") {
		t.Fatalf("expected path/filepath/path.go in AffectedPaths, got %v", got.AffectedPaths)
	}
	if !containsString(got.RequiredEnv, "GO_FILEPATH_RELAXED") {
		t.Fatalf("expected GO_FILEPATH_RELAXED in RequiredEnv, got %v", got.RequiredEnv)
	}
}

func TestJVNParser_ParseDetail(t *testing.T) {
	parser := NewJVNParser()
	raw := loadFixture(t, "jvn_detail_jvndb-2023-001234.xml")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.CVEID != "CVE-2023-12345" {
		t.Fatalf("CVEID = %q want CVE-2023-12345", got.CVEID)
	}
	if !containsString(got.VulnFuncs, "cms.handleUpload") {
		t.Fatalf("expected cms.handleUpload in VulnFuncs, got %v", got.VulnFuncs)
	}
	if !containsString(got.AffectedPaths, "cms/upload.go") {
		t.Fatalf("expected cms/upload.go in AffectedPaths, got %v", got.AffectedPaths)
	}
	if !containsString(got.RequiredEnv, "DEBUG") {
		t.Fatalf("expected DEBUG in RequiredEnv, got %v", got.RequiredEnv)
	}
}

func TestJVNParser_ParseIpediaJSON(t *testing.T) {
	parser := NewJVNParser()
	raw := loadFixture(t, "jvn_ipedia_jvndb-2025-000010.json")

	got, err := parser.Parse(context.Background(), raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("got nil parsed advisory")
	}
	if got.CVEID != "CVE-2025-00010" {
		t.Fatalf("CVEID = %q want CVE-2025-00010", got.CVEID)
	}
	if !got.IsEmpty() {
		t.Fatalf("expected IsEmpty=true (no extractable hints), got %+v", got)
	}
	if got.RawExcerpt == "" {
		t.Fatal("RawExcerpt should still be set")
	}
}

func TestJVNParser_ParseInvalidBytes(t *testing.T) {
	parser := NewJVNParser()
	_, err := parser.Parse(context.Background(), []byte("not xml or json"))
	if err == nil {
		t.Fatal("expected error for invalid payload")
	}
}

// containsString reports whether haystack contains needle (exact match).
func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
