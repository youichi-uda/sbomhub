package service

import (
	"encoding/json"
	"fmt"
	"testing"
)

// cdx10k builds a CycloneDX 1.5 document with n components shaped like Syft
// output (name, version, purl, licenses, a description with escapes and
// non-ASCII text), so the text check is measured on a realistic byte mix.
func cdx10k(tb testing.TB, n int) []byte {
	tb.Helper()
	comps := make([]map[string]any, n)
	for i := range comps {
		comps[i] = map[string]any{
			"type":        "library",
			"bom-ref":     fmt.Sprintf("pkg:npm/%%40scope/lib-%d@1.%d.0", i, i%50),
			"name":        fmt.Sprintf("lib-%d", i),
			"version":     fmt.Sprintf("1.%d.0", i%50),
			"purl":        fmt.Sprintf("pkg:npm/%%40scope/lib-%d@1.%d.0", i, i%50),
			"description": "A \"quoted\" library\twith tabs, a path C:\\\\tmp and 日本語の説明 🚀",
			"licenses":    []map[string]any{{"license": map[string]string{"id": "MIT"}}},
		}
	}
	b, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": comps,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func TestCDX10kFixtureIsAcceptedAndParses(t *testing.T) {
	data := cdx10k(t, 10000)
	if err := checkSBOMText(data); err != nil {
		t.Fatal(err)
	}
	info, err := detectFormatAndVersion(data)
	if err != nil {
		t.Fatal(err)
	}
	comps, err := parseComponents(data, info.Format, info.Version)
	if err != nil || len(comps) != 10000 {
		t.Fatalf("parsed %d components, err %v", len(comps), err)
	}
	t.Logf("fixture: %d bytes", len(data))
}

// go test -run '^$' -bench 'SBOM10k' -benchmem ./internal/service
func BenchmarkSBOM10k_TextCheck(b *testing.B) {
	data := cdx10k(b, 10000)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if err := checkSBOMText(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSBOM10k_DetectAndParse(b *testing.B) {
	data := cdx10k(b, 10000)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		info, err := detectFormatAndVersion(data)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := parseComponents(data, info.Format, info.Version); err != nil {
			b.Fatal(err)
		}
	}
}

// asciiEscaped rewrites every non-ASCII character as \uXXXX (surrogate pairs
// above the BMP), as Python's json.dumps(ensure_ascii=True) does by default:
// the worst case for the escape walk in checkSBOMText.
func asciiEscaped(b []byte) []byte {
	out := make([]byte, 0, len(b)*2)
	for _, r := range string(b) {
		switch {
		case r < 0x80:
			out = append(out, byte(r))
		case r > 0xFFFF:
			r -= 0x10000
			out = fmt.Appendf(out, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		default:
			out = fmt.Appendf(out, `\u%04x`, r)
		}
	}
	return out
}

func BenchmarkSBOM10k_TextCheck_ASCIIEscaped(b *testing.B) {
	data := asciiEscaped(cdx10k(b, 10000))
	if err := checkSBOMText(data); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if err := checkSBOMText(data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSBOM10k_DetectAndParse_ASCIIEscaped(b *testing.B) {
	data := asciiEscaped(cdx10k(b, 10000))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		info, err := detectFormatAndVersion(data)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := parseComponents(data, info.Format, info.Version); err != nil {
			b.Fatal(err)
		}
	}
}
