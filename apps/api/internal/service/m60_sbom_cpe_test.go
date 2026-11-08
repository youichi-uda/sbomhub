package service

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// M60: components must keep the CPE candidates (and the purl) the SBOM
// carries, because the NVD scanner matches on them.
//
// The fixtures under testdata/m60 are REAL Syft 1.46.0 output (generated
// 2026-11-08 from a synthetic tree: a Debian dpkg status file, a pom.xml, a
// package-lock.json and a go.mod), with only the scratch directory path
// rewritten to /fixture. Syft writes the FIRST CPE candidate to the
// CycloneDX `cpe` field and the rest to `syft:cpe23` properties; in SPDX 2 it
// writes every candidate as a `cpe23Type` externalRef. The candidates' ORDER
// matters and is pinned: for log4j-core the NVD product (apache:log4j) is the
// THIRD candidate, not the first.

func m60Fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "m60", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func m60Find(t *testing.T, comps []model.Component, name string) model.Component {
	t.Helper()
	for _, c := range comps {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("component %q not found among %d parsed components", name, len(comps))
	return model.Component{}
}

var m60Log4jCPEs = []string{
	"cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
	"cpe:2.3:a:apache:log4j_core:2.14.1:*:*:*:*:*:*:*",
	"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
}

func TestM60ParseCycloneDX_KeepsSyftCPECandidatesInOrder(t *testing.T) {
	comps, err := parseCycloneDX(m60Fixture(t, "syft.cdx.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	log4j := m60Find(t, comps, "log4j-core")
	if !reflect.DeepEqual(log4j.CPEs, m60Log4jCPEs) {
		t.Errorf("log4j-core CPEs = %q, want %q", log4j.CPEs, m60Log4jCPEs)
	}
	if log4j.Purl != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("log4j-core purl = %q", log4j.Purl)
	}
	lodash := m60Find(t, comps, "lodash")
	if want := []string{"cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"}; !reflect.DeepEqual(lodash.CPEs, want) {
		t.Errorf("lodash CPEs = %q, want %q", lodash.CPEs, want)
	}
}

// Before M60 parseSPDX read `externalRefs` with getString, but externalRefs is
// an ARRAY in SPDX 2.x JSON, so the purl of every SPDX 2 package was silently
// dropped (the field was always ""). That fed every purl consumer — VEX purl
// matching, the reachability ecosystem — an empty value.
func TestM60ParseSPDX2_ReadsPurlAndCPEsFromExternalRefs(t *testing.T) {
	comps, err := parseSPDX(m60Fixture(t, "syft.spdx.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	log4j := m60Find(t, comps, "log4j-core")
	if log4j.Purl != "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" {
		t.Errorf("log4j-core purl = %q, want the purl externalRef", log4j.Purl)
	}
	if !reflect.DeepEqual(log4j.CPEs, m60Log4jCPEs) {
		t.Errorf("log4j-core CPEs = %q, want %q", log4j.CPEs, m60Log4jCPEs)
	}
	openssl := m60Find(t, comps, "openssl")
	if !strings.HasPrefix(openssl.Purl, "pkg:deb/debian/openssl@1.1.1k-1") {
		t.Errorf("openssl purl = %q", openssl.Purl)
	}
}

func TestM60ParseSPDX3_ReadsCPEExternalIdentifiers(t *testing.T) {
	data := []byte(`{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"spdxId": "p1", "type": "software_Package", "name": "log4j-core", "packageVersion": "2.14.1",
			 "externalIdentifier": [
				{"externalIdentifierType": "cpe23", "identifier": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
				{"externalIdentifierType": "cpe22", "identifier": "cpe:/a:apache:log4j:2.14.1"},
				{"externalIdentifierType": "packageUrl", "identifier": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
			 ]}
		]
	}`)
	comps, err := parseSPDX3(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components", len(comps))
	}
	want := []string{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpe:/a:apache:log4j:2.14.1"}
	if !reflect.DeepEqual(comps[0].CPEs, want) {
		t.Errorf("CPEs = %q, want %q", comps[0].CPEs, want)
	}
}

// The stored list is bounded and filtered: it is uploaded data, and only
// strings that are CPEs are worth a column (and later an NVD request).
func TestM60NormaliseSBOMCPEs(t *testing.T) {
	in := []string{
		"  cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*  ",
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", // duplicate after trim
		"not-a-cpe",
		"",
		"cpe:/a:openssl:openssl:1.1.1k",
		"cpe:2.3:a:" + strings.Repeat("x", 600) + ":p:1:*:*:*:*:*:*:*", // oversize
	}
	got := normaliseSBOMCPEs(in)
	want := []string{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpe:/a:openssl:openssl:1.1.1k"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normaliseSBOMCPEs = %q, want %q", got, want)
	}

	many := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		many = append(many, "cpe:2.3:a:v:p"+strings.Repeat("x", i)+":1:*:*:*:*:*:*:*")
	}
	if n := len(normaliseSBOMCPEs(many)); n != maxStoredCPEsPerComponent {
		t.Errorf("kept %d CPEs, want the cap %d", n, maxStoredCPEsPerComponent)
	}
	if normaliseSBOMCPEs(nil) != nil {
		t.Errorf("no CPEs must stay nil (stored as NULL), not an empty array")
	}
}
