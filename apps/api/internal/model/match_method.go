package model

// MatchMethod records HOW a component -> vulnerability link was made
// (component_vulnerabilities.match_method, migration 067, M60).
//
// The vocabulary is enforced twice: by the CHECK constraint (migration 067,
// widened by 070 for the distro labels of M70) and by IsValid here. The two
// lists must move together.
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
	// MatchNVDCPEUnverified: NVD returned the CVE for the component's CPE,
	// but its configurations could not be checked against the version
	// (absent, never naming the product, or a version comparison that cannot
	// be decided). Kept so a comparator limit is not a silent false
	// negative, but NOT claimed as verified: low confidence.
	MatchNVDCPEUnverified MatchMethod = "nvd_cpe_unverified"
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

	// M70 — the distro's own fixed-version data (OSV's distro ecosystems),
	// compared with the distro's own version ordering (dpkg / rpm), relabels
	// the links of a distro package. Each carries its evidence in
	// component_vulnerabilities.match_evidence (DistroEvidence).

	// MatchDistroAffected: the distro has released a fix for this CVE in the
	// installed release, and the installed version is BELOW it. High
	// confidence; the evidence names the fixed version to upgrade to.
	MatchDistroAffected MatchMethod = "distro_affected"
	// MatchDistroUnfixed: the distro lists the installed release as affected
	// with no fix released. High confidence.
	MatchDistroUnfixed MatchMethod = "distro_unfixed"
	// MatchDistroFixed: the distro's data says the installed version
	// already contains the fix (installed >= fixed). The link is KEPT, not
	// deleted, and nothing is marked not_affected: a human reviews the
	// evidence (SBOMHub drafts, humans approve). It ranks BELOW every other
	// method when the API picks one label per CVE, so another component's
	// possible finding is never hidden behind it.
	MatchDistroFixed MatchMethod = "distro_fixed"
)

// allMatchMethods lists every valid method, in no particular order.
var allMatchMethods = []MatchMethod{
	MatchNVDCPE, MatchNVDCPEDistro, MatchNVDCPEUnverified, MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword,
	MatchDistroAffected, MatchDistroUnfixed, MatchDistroFixed,
}

// Match confidence labels exposed through the API.
const (
	MatchConfidenceHigh    = "high"
	MatchConfidenceMedium  = "medium"
	MatchConfidenceLow     = "low"
	MatchConfidenceUnknown = "unknown"
	// MatchConfidenceDistroFixed (M70) is not a confidence that the CVE
	// applies: it says the distro's data shows the installed package already
	// fixed. The finding is kept for a human to review.
	MatchConfidenceDistroFixed = "distro_fixed"
)

// IsValid reports whether m is one of the methods migrations 067 / 070 accept.
func (m MatchMethod) IsValid() bool {
	for _, v := range allMatchMethods {
		if m == v {
			return true
		}
	}
	return false
}

// Rank orders methods by how much evidence they carry about ONE link; a link
// is relabelled only to a strictly higher rank. "" (a pre-M60 link, NULL in
// the database) ranks below everything.
//
// The distro labels (M70) outrank the NVD ones: they are the distro's own
// statement about the installed package, which an upstream-version match
// cannot see (backports). Among them, the labels that say "affected" outrank
// distro_fixed, so a correction in the distro's data can move a link from
// fixed to affected on a rescan but never the other way: once a scan found
// the installed version affected, only a human (triage) clears it. Likewise
// unfixed -> affected (a fix was released since) is allowed, the reverse not.
// The NVD / JVN / CVE-sync writers can never downgrade a distro label, since
// they only ever relabel upward.
func (m MatchMethod) Rank() int {
	switch m {
	case MatchDistroAffected:
		return 6
	case MatchDistroUnfixed:
		return 5
	case MatchDistroFixed:
		return 4
	case MatchNVDCPE:
		return 3
	case MatchNVDCPEDistro:
		return 2
	case MatchNVDCPEUnverified, MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword:
		return 1
	}
	return 0
}

// IsDistro reports whether m is one of the M70 distro labels, the only
// methods that carry match_evidence.
func (m MatchMethod) IsDistro() bool {
	return m == MatchDistroAffected || m == MatchDistroUnfixed || m == MatchDistroFixed
}

// FindingRank orders methods for the ONE label the vulnerability list shows
// per CVE, chosen among an SBOM's links to it: how strongly the links say the
// CVE applies. It differs from Rank only for distro_fixed, which ranks below
// everything, a pre-M60 NULL link included: when one component's link is
// "fixed by the distro" and another's is anything else, the CVE must show the
// other one. repository.bestMatchMethodJoin mirrors this CASE.
func (m MatchMethod) FindingRank() int {
	if m == MatchDistroFixed {
		return -1
	}
	return m.Rank()
}

// Confidence maps a method to the label the API shows. "" is a link made
// before M60, whose method was never recorded: "unknown", not "low" — we do
// not know that it was a keyword match.
func (m MatchMethod) Confidence() string {
	switch m {
	case MatchDistroAffected, MatchDistroUnfixed, MatchNVDCPE:
		return MatchConfidenceHigh
	case MatchDistroFixed:
		return MatchConfidenceDistroFixed
	case MatchNVDCPEDistro:
		return MatchConfidenceMedium
	case MatchNVDCPEUnverified, MatchNVDKeyword, MatchJVNKeyword, MatchCVESyncKeyword:
		return MatchConfidenceLow
	}
	return MatchConfidenceUnknown
}

// WeakerMatchMethods lists the valid methods ranked strictly below m — the
// stored values a link written with m is allowed to replace.
func WeakerMatchMethods(m MatchMethod) []string {
	var out []string
	for _, w := range allMatchMethods {
		if w.Rank() < m.Rank() {
			out = append(out, string(w))
		}
	}
	return out
}
