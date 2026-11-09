package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// Codex M70 R19 High-2: record identities are canonical at the network
// boundary (a CVE-like id, alias or upstream entry that is not exactly
// canonical fails the whole query), and reduction matches exactly.
func TestM70R19_RecordIdentitiesAreCanonical(t *testing.T) {
	for _, rec := range []string{
		`{"id":" DEBIAN-CVE-2026-1234","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"debian-cve-2026-1234","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-2","upstream":["cve-2026-1234"],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-2","aliases":["CVE-2026-1234 "],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
		`{"id":"DSA-2","upstream":["CVE-26-1"],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`,
	} {
		if err := r15Query(t, `{"vulns":[`+r15OK+`,`+rec+`]}`); err == nil {
			t.Errorf("accepted %s", rec)
		}
	}
	// Non-CVE upstream ids (GHSA, DEBIAN-CVE-...) remain fine when canonical.
	ok := `{"id":"DSA-3","upstream":["CVE-2026-1234","DEBIAN-CVE-2026-1234","GHSA-xxxx-yyyy-zzzz"],"modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"p","ecosystem":"Debian:11"}}]}`
	if err := r15Query(t, `{"vulns":[`+ok+`]}`); err != nil {
		t.Errorf("canonical upstream refused: %v", err)
	}
	if got := (&distroRecord{ID: "Debian-CVE-2026-1234"}).recordCVE(); got != "" {
		t.Errorf("recordCVE folded case: %q", got)
	}
}

// Codex M70 R19 Medium-3: the SBOM's operating-system component is used only
// when its fields are canonical; nothing is trimmed or case-folded.
func TestM70R19_OSComponentIsCanonical(t *testing.T) {
	for _, c := range []model.Component{
		{Type: " operating-system ", Name: "debian", Version: "11"},
		{Type: "operating-system", Name: " Debian ", Version: "11"},
		{Type: "operating-system", Name: "debian", Version: " 11 "},
		{Type: "Operating-System", Name: "debian", Version: "11"},
	} {
		if os := sbomOperatingSystem([]model.Component{c}); os != nil {
			t.Errorf("%+v accepted as %+v", c, os)
		}
	}
	if os := sbomOperatingSystem([]model.Component{{Type: "operating-system", Name: "debian", Version: "11"}}); os == nil || os.id != "debian" {
		t.Errorf("canonical OS refused: %+v", os)
	}
}
