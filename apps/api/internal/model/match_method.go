package model

// MatchMethod records HOW a component -> vulnerability link was made
// (component_vulnerabilities.match_method, migration 067, M60).
//
// The vocabulary is enforced twice: by the CHECK constraint in migration 067
// and by IsValid here. The two lists must move together.
type MatchMethod string

const (
	// MatchNVDCPE: an NVD CPE query for one of the component's CPE names, with
	// the CVE then verified locally against its NVD configurations — a
	// vulnerable=true criterion for the same part:vendor:product whose version
	// (or version range) contains the component's version.
	MatchNVDCPE MatchMethod = "nvd_cpe"
	// MatchNVDCPEDistro: as MatchNVDCPE, for a distro package (purl type
	// deb / rpm / apk / alpm). The match uses the UPSTREAM version (distro
	// revision and epoch stripped), so a fix the distro backported without
	// changing the upstream version is NOT taken into account.
	MatchNVDCPEDistro MatchMethod = "nvd_cpe_distro"
	// MatchNVDKeyword: NVD keywordSearch on "<name> <version>"; used when the
	// component has no CPE whose product NVD knows.
	MatchNVDKeyword MatchMethod = "nvd_keyword"
	// MatchJVNKeyword: MyJVN keyword search on the component name. MyJVN ORs
	// keyword terms and its overview carries no version ranges, so this is a
	// product-name-level match at best.
	MatchJVNKeyword MatchMethod = "jvn_keyword"
	// MatchCVESyncKeyword: the daily CVE-sync linker, which matches product
	// names taken from a CVE's CPE criteria against component NAMES (no
	// version check).
	MatchCVESyncKeyword MatchMethod = "cve_sync_keyword"
)

// Match confidence labels exposed through the API.
const (
	MatchConfidenceHigh    = "high"
	MatchConfidenceMedium  = "medium"
	MatchConfidenceLow     = "low"
	MatchConfidenceUnknown = "unknown"
)

// IsValid reports whether m is one of the methods migration 067 accepts.
func (m MatchMethod) IsValid() bool {
	switch m {
	case MatchNVDCPE, MatchNVDCPEDistro, MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword:
		return true
	}
	return false
}

// Rank orders methods by how much evidence they carry; a link is relabelled
// only to a strictly higher rank. "" (a pre-M60 link, NULL in the database)
// ranks below everything.
func (m MatchMethod) Rank() int {
	switch m {
	case MatchNVDCPE:
		return 3
	case MatchNVDCPEDistro:
		return 2
	case MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword:
		return 1
	}
	return 0
}

// Confidence maps a method to the label the API shows. "" is a link made
// before M60, whose method was never recorded: "unknown", not "low" — we do
// not know that it was a keyword match.
func (m MatchMethod) Confidence() string {
	switch m.Rank() {
	case 3:
		return MatchConfidenceHigh
	case 2:
		return MatchConfidenceMedium
	case 1:
		return MatchConfidenceLow
	}
	return MatchConfidenceUnknown
}

// WeakerMatchMethods lists the valid methods ranked strictly below m — the
// stored values a link written with m is allowed to replace.
func WeakerMatchMethods(m MatchMethod) []string {
	var out []string
	for _, w := range []MatchMethod{MatchNVDCPE, MatchNVDCPEDistro, MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword} {
		if w.Rank() < m.Rank() {
			out = append(out, string(w))
		}
	}
	return out
}
