package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// The spec version of an upload decides how it is parsed. Before this,
// detection read CycloneDX's specVersion without checking it and SPDX's
// spdxVersion by stripping a prefix, so:
//
//   - an unknown CycloneDX version ("1.8") passed detection, the SBOM row was
//     written, and only then did cyclonedx-go reject it;
//   - a CycloneDX document WITHOUT specVersion (or with a number) was stored
//     with an empty version and parsed as whatever the library guessed;
//   - `"spdxVersion": "SPDX-3.0"` (not a real SPDX 3 document — those are
//     JSON-LD) was routed to the SPDX 3 parser and silently produced zero
//     components;
//   - an SPDX 3 @context of a later 3.0.x was labelled "3.0".
//
// Now every version is checked at detection, before anything is written, and
// an unsupported one is a validation error (400) that names the versions this
// server accepts.

func cdxDoc(specVersion string) []byte {
	return []byte(`{"bomFormat":"CycloneDX",` + specVersion + `"version":1,"components":[]}`)
}

func TestDetectFormatAndVersion_CycloneDXSupportedVersions(t *testing.T) {
	for _, v := range []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"} {
		info, err := detectFormatAndVersion(cdxDoc(`"specVersion":"` + v + `",`))
		if err != nil {
			t.Fatalf("specVersion %s: unexpected error %v", v, err)
		}
		if info.Format != model.FormatCycloneDX || info.Version != v {
			t.Fatalf("specVersion %s: got %+v", v, info)
		}
	}
}

func TestDetectFormatAndVersion_CycloneDXUnsupportedVersions(t *testing.T) {
	cases := map[string]string{
		"future 1.8":     `"specVersion":"1.8",`,
		"2.0":            `"specVersion":"2.0",`,
		"empty":          `"specVersion":"",`,
		"missing":        ``,
		"number":         `"specVersion":1.5,`,
		"null":           `"specVersion":null,`,
		"padded":         `"specVersion":" 1.5",`,
		"patch spelling": `"specVersion":"1.5.0",`,
	}
	for name, field := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := detectFormatAndVersion(cdxDoc(field))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrUnsupportedSpecVersion) {
				t.Fatalf("error %v is not ErrUnsupportedSpecVersion", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "CycloneDX") || !strings.Contains(msg, "1.7") || !strings.Contains(msg, "1.0") {
				t.Fatalf("message must name the format and the supported range, got %q", msg)
			}
		})
	}
}

func TestDetectFormatAndVersion_SPDX2Versions(t *testing.T) {
	for _, v := range []string{"2.0", "2.1", "2.2", "2.3"} {
		info, err := detectFormatAndVersion([]byte(`{"spdxVersion":"SPDX-` + v + `","packages":[]}`))
		if err != nil {
			t.Fatalf("SPDX-%s: unexpected error %v", v, err)
		}
		if info.Format != model.FormatSPDX || info.Version != v {
			t.Fatalf("SPDX-%s: got %+v", v, info)
		}
	}
	for _, bad := range []string{`"SPDX-3.0"`, `"SPDX-2.4"`, `"SPDX-1.2"`, `"2.3"`, `"SPDX-"`, `""`, `2.3`, `null`} {
		_, err := detectFormatAndVersion([]byte(`{"spdxVersion":` + bad + `,"packages":[]}`))
		if !errors.Is(err, ErrUnsupportedSpecVersion) {
			t.Fatalf("spdxVersion %s: want ErrUnsupportedSpecVersion, got %v", bad, err)
		}
		if !strings.Contains(err.Error(), "SPDX-2.3") {
			t.Fatalf("spdxVersion %s: message must name the supported versions, got %q", bad, err)
		}
	}
}

func TestDetectFormatAndVersion_SPDX3Versions(t *testing.T) {
	ok := map[string]string{
		"https://spdx.org/rdf/3.0/terms/Core":                  "3.0",
		"https://spdx.org/rdf/3.0.1/terms/Core":                "3.0.1",
		"https://spdx.org/rdf/3.0.1/spdx-context.jsonld":       "3.0.1",
		"https://spdx.org/rdf/3.0/spdx-json-ld-context.jsonld": "3.0",
	}
	for ctx, want := range ok {
		info, err := detectFormatAndVersion([]byte(`{"@context":"` + ctx + `","@graph":[]}`))
		if err != nil {
			t.Fatalf("%s: unexpected error %v", ctx, err)
		}
		if info.Format != model.FormatSPDX || info.Version != want {
			t.Fatalf("%s: got %+v, want version %s", ctx, info, want)
		}
	}
	for _, ctx := range []string{
		"https://spdx.org/rdf/3.0.2/terms/Core",
		"https://spdx.org/rdf/3.1/terms/Core",
		"https://spdx.org/rdf/3.0.10/terms/Core",
	} {
		_, err := detectFormatAndVersion([]byte(`{"@context":"` + ctx + `","@graph":[]}`))
		if !errors.Is(err, ErrUnsupportedSpecVersion) {
			t.Fatalf("%s: want ErrUnsupportedSpecVersion, got %v", ctx, err)
		}
	}
}

// Codex R1 Medium: the CycloneDX discriminator itself was not checked, so
// {"bomFormat":"SPDX",...} was stored as CycloneDX and a numeric bomFormat
// passed detection.
func TestDetectFormatAndVersion_BomFormatMustBeCycloneDX(t *testing.T) {
	for _, bf := range []string{`"SPDX"`, `"cyclonedx"`, `""`, `1`, `null`, `{}`} {
		_, err := detectFormatAndVersion([]byte(`{"bomFormat":` + bf + `,"specVersion":"1.5","version":1}`))
		if err == nil {
			t.Fatalf("bomFormat %s accepted", bf)
		}
	}
}

func TestDetectFormatAndVersion_SPDX3ContextMustBeSPDXOrigin(t *testing.T) {
	for _, ctx := range []string{
		"https://evil.example/spdx.org/rdf/3.0.1/terms/Core",
		"https://notspdx.org/rdf/3.0.1/terms/Core",
	} {
		info, err := detectFormatAndVersion([]byte(`{"@context":"` + ctx + `","@graph":[]}`))
		if err == nil {
			t.Fatalf("%s accepted as %+v", ctx, info)
		}
	}
}
