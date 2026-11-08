package service

// CPE-based NVD matching (M60).
//
// # Why
//
// Before M60 both scanners matched by keyword. Measured against the live NVD
// API on 2026-11-08 for a Syft SBOM of realistic components, NVD's
// keywordSearch on "<name> <version>" (which ANDs the terms) returned 0
// records for log4j-core 2.14.1 (Log4Shell missed), tomcat-embed-core 9.0.30,
// golang.org/x/net v0.7.0, gin v1.7.0, openssl 1.1.1k-1 (Debian) and the
// kernel: the version string has to appear in the CVE DESCRIPTION, and it
// rarely does. A CPE query asks NVD's affected-configuration data instead.
//
// # How a component is matched
//
//  1. Up to nvdMaxCPECandidates distinct part:vendor:product candidates are
//     taken from the CPE names the SBOM declared, in SBOM order. Syft's
//     FIRST candidate is often not NVD's product (measured: log4j-core ->
//     apache:log4j-core, NVD uses apache:log4j, Syft's third candidate).
//  2. For a candidate, NVD is asked `cpeName=<part:vendor:product:version:*...>`
//     (exact name, NVD evaluates the version ranges server-side) and the walk
//     pages exactly like the keyword walk (same budget, same truncation and
//     page-identity checks).
//  3. Every returned CVE is VERIFIED locally against its configurations
//     (verifyCPEMatch). Measured: cpeName for openssl 1.1.1k returned 47
//     CVEs, 5 of them only because openssl appears as a vulnerable=false
//     PLATFORM in an AND configuration (Mutt CVE-2009-1390 etc., httpd
//     CVE-2019-0190). Those are not openssl vulnerabilities.
//  4. A cpeName answer of ZERO is ambiguous: NVD answers 0, with no error, for
//     a product it has never heard of (measured: apache:log4j-core) exactly
//     as it does for a known product whose version is unaffected. A second,
//     one-record request (`virtualMatchString=cpe:2.3:part:vendor:product`)
//     tells them apart. Known product -> the verified answer is "none" and it
//     is final. Unknown product -> try the next candidate.
//  5. No candidate names a product NVD knows -> fall back to the keyword
//     search, and the links are labelled nvd_keyword (low confidence). A wrong
//     CPE therefore never turns into a silent "clean".

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/model"
)

// nvdMaxCPECandidates bounds how many distinct part:vendor:product
// candidates of ONE component are tried. Each unknown candidate costs two
// requests (the cpeName query and the product probe). Measured on Syft 1.46.0
// output (2026-11-08): maven / go packages carry 1-3 candidates and the NVD
// product was within the first 3 in every case; Debian packages carry up to
// 18, all generated from the package name (linux-image-5.10.0-8-amd64), none
// of them an NVD product — trying all 18 would be 36 wasted requests.
const nvdMaxCPECandidates = 3

// cpeName is the parsed, UNESCAPED form of a CPE name's leading attributes.
type cpeName struct {
	Part    string
	Vendor  string
	Product string
	Version string
	Update  string
}

// parseCPE parses a CPE 2.3 formatted string (`cpe:2.3:a:vendor:product:...`,
// backslash-escaped) or a CPE 2.2 URI (`cpe:/a:vendor:product:...`,
// percent-encoded). Attribute values are returned unescaped and lower-cased.
func parseCPE(s string) (cpeName, bool) {
	s = strings.TrimSpace(s)
	var fields []string
	// The scheme is case-insensitive (SPDX 2.2's CPE 2.2 locator pattern
	// accepts "cPE:/A:..."; Codex M60 R2 Medium-2). Attribute values are
	// lower-cased below anyway.
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "cpe:2.3:"):
		fields = splitCPE23(s[len("cpe:2.3:"):])
	case strings.HasPrefix(lower, "cpe:/"):
		for _, f := range strings.Split(s[len("cpe:/"):], ":") {
			u, err := url.PathUnescape(f)
			if err != nil {
				return cpeName{}, false
			}
			fields = append(fields, u)
		}
	default:
		return cpeName{}, false
	}
	get := func(i int) string {
		if i < len(fields) {
			return strings.ToLower(fields[i])
		}
		return ""
	}
	n := cpeName{Part: get(0), Vendor: get(1), Product: get(2), Version: get(3), Update: get(4)}
	if n.Part != "a" && n.Part != "o" && n.Part != "h" {
		return cpeName{}, false
	}
	if !cpeConcrete(n.Vendor) || !cpeConcrete(n.Product) {
		return cpeName{}, false
	}
	return n, true
}

// splitCPE23 splits a CPE 2.3 formatted string body on unescaped colons and
// removes the backslash escapes.
func splitCPE23(s string) []string {
	var out []string
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\':
			esc = true
		case r == ':':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	return append(out, b.String())
}

// cpeConcrete is false for the logical values ANY ("*") and NA ("-") and for
// an empty attribute.
func cpeConcrete(v string) bool {
	return v != "" && v != "*" && v != "-"
}

// escapeCPE23 re-escapes an attribute value for a CPE 2.3 formatted string:
// everything other than letters, digits, '_', '-' and '.' is backslash-quoted.
func escapeCPE23(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('\\')
		b.WriteRune(r)
	}
	return b.String()
}

// cpeCandidate is one part:vendor:product to try for a component, with the
// version the component will be matched at.
type cpeCandidate struct {
	part, vendor, product string
	version               string
	// update is the CPE `update` attribute when the SBOM's CPE pinned one
	// ("beta9" in log4j:2.0:beta9), else "". It is part of the release the
	// CPE names (Codex M60 R1 High-1).
	update string
}

// effectiveVersion is the release the candidate names, in the single-string
// form SBOM versions use: "2.0-beta9" for version 2.0 + update beta9.
func (c cpeCandidate) effectiveVersion() string {
	if c.update != "" {
		return c.version + "-" + c.update
	}
	return c.version
}

// query is the exact CPE name sent as cpeName. Every attribute after the
// version is ANY: measured on 2026-11-08, cpeName for lodash 4.17.20 with
// target_sw=node.js and with target_sw=* both returned the same 5 CVEs, and
// a wildcard cannot exclude a criterion the SBOM's guess got wrong.
func (c cpeCandidate) query() string {
	update := "*"
	if c.update != "" {
		update = escapeCPE23(c.update)
	}
	return "cpe:2.3:" + c.part + ":" + escapeCPE23(c.vendor) + ":" + escapeCPE23(c.product) + ":" +
		escapeCPE23(c.version) + ":" + update + ":*:*:*:*:*:*"
}

// productQuery is the version-less virtualMatchString used to ask whether NVD
// knows the product at all.
func (c cpeCandidate) productQuery() string {
	return "cpe:2.3:" + c.part + ":" + escapeCPE23(c.vendor) + ":" + escapeCPE23(c.product)
}

// productKey is the candidate's product identity for dedupe and for the
// negative cache. It is the ESCAPED form (productQuery), not the unescaped
// fields joined with ':' — a quoted colon is valid CPE syntax and NVD has
// such products, so the joined form let `mailcow\:mailcow` + `_dockerized`
// and `mailcow` + `mailcow\:_dockerized` share one identity, and one tenant
// could cache "unknown product" for another's (Codex M60 R4 High).
func (c cpeCandidate) productKey() string { return c.productQuery() }

// distroPurlTypes are purl types whose versions carry a distro revision (and
// possibly an epoch) on top of the upstream version.
var distroPurlTypes = map[string]bool{"deb": true, "rpm": true, "apk": true, "alpm": true}

// purlType returns the purl's type ("maven", "deb", ...) or "".
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "/@?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

// isDistroComponent reports whether the component is a distro package.
func isDistroComponent(purl string) bool { return distroPurlTypes[purlType(purl)] }

// normaliseCPEVersion turns an SBOM version into the version NVD's
// configurations are written in.
//
//   - A leading "v" before a digit is dropped (Go modules). Measured: cpeName
//     golang:networking:v0.7.0 -> 0 CVEs, :0.7.0 -> 2.
//   - For a distro package the epoch ("1:") and the distro revision (after the
//     LAST "-": Debian "1.1.1k-1+deb11u2", RPM "2.17-326.el7", Alpine
//     "1.1.1k-r0") are dropped, leaving the upstream version. This is what
//     makes a distro package matchable at all, and it is also why such links
//     are labelled nvd_cpe_distro: a backported fix does not change the
//     upstream version.
func normaliseCPEVersion(v string, distro bool) string {
	v = strings.TrimSpace(v)
	if distro {
		if i := strings.Index(v, ":"); i > 0 && isDigits(v[:i]) {
			v = v[i+1:]
		}
		if i := strings.LastIndex(v, "-"); i > 0 {
			v = v[:i]
		}
	}
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// cpeCandidates derives the candidates for one component. The version is the
// CPE's own version attribute when it is concrete (that is what the SBOM
// author asserted), otherwise the component version; either way normalised.
// A candidate without any version is dropped — a version-less cpeName would
// match every version of the product.
func cpeCandidates(cpes []string, compVersion, purl string) []cpeCandidate {
	distro := isDistroComponent(purl)
	var out []cpeCandidate
	seen := make(map[string]struct{})
	for _, raw := range cpes {
		n, ok := parseCPE(raw)
		if !ok {
			continue
		}
		if n.Version == "-" {
			// NA: the SBOM asserts a version-less thing. Substituting the
			// component version would invent a CPE it did not assert
			// (Codex M60 R6 Medium).
			continue
		}
		v, update := compVersion, ""
		if cpeConcrete(n.Version) {
			v = n.Version
			if cpeConcrete(n.Update) {
				update = n.Update
			}
		}
		v = normaliseCPEVersion(v, distro)
		if !cpeConcrete(v) {
			continue
		}
		c := cpeCandidate{part: n.Part, vendor: n.Vendor, product: n.Product, version: strings.ToLower(v), update: update}
		if _, dup := seen[c.productKey()]; dup {
			continue
		}
		seen[c.productKey()] = struct{}{}
		out = append(out, c)
		if len(out) == nvdMaxCPECandidates {
			break
		}
	}
	return out
}

// NVD configuration structures (CVE API 2.0 `configurations`).
type NVDConfiguration struct {
	Operator string          `json:"operator"`
	Negate   bool            `json:"negate"`
	Nodes    []NVDConfigNode `json:"nodes"`
}

type NVDConfigNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CpeMatch []NVDCPEMatch `json:"cpeMatch"`
}

type NVDCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// cpeVerdict is the outcome of checking one CVE against one candidate.
type cpeVerdict int

const (
	// cpeRejected: NVD's configurations hold no vulnerable criterion for this
	// product whose version spec contains the component version.
	cpeRejected cpeVerdict = iota
	// cpeMatched: at least one vulnerable criterion for this product contains
	// the version.
	cpeMatched
	// cpeUndecidable: a vulnerable criterion for this product exists but the
	// version comparison could not be decided locally (unparseable or
	// incomparable versions). NVD's own server-side evaluation returned the
	// CVE, so it is KEPT — dropping it would turn our comparator's limits
	// into silent false negatives.
	cpeUndecidable
)

// verifyCPEMatch checks a CVE NVD returned for a cpeName query against the
// CVE's own configurations.
//
// Only vulnerable=true criteria count: a vulnerable=false criterion is a
// platform the vulnerable thing runs ON (measured: 5 of 47 openssl 1.1.1k
// answers). AND configurations ("X running on Y") count when the component is
// the vulnerable X — the platform half cannot be known from an SBOM, so
// requiring it would drop real findings. Negated nodes/configurations are
// never used as positive evidence.
//
// Rejection requires POSITIVE evidence (Codex M60 R1 High-2): a criterion for
// this product that is not vulnerable, or whose version spec excludes the
// component. A CVE whose configurations are absent, or never mention the
// product, cannot be verified either way — NVD's own cpeName evaluation
// selected it, so it is kept as undecidable rather than silently dropped (and
// then cached as a clean answer).
func verifyCPEMatch(cve NVDCVE, c cpeCandidate) cpeVerdict {
	undecidable := false
	sawProduct := false
	for _, cfg := range cve.Configurations {
		if cfg.Negate {
			continue
		}
		for _, node := range cfg.Nodes {
			if node.Negate {
				continue
			}
			for _, m := range node.CpeMatch {
				crit, ok := parseCPE(m.Criteria)
				if !ok || crit.Part != c.part || crit.Vendor != c.vendor || crit.Product != c.product {
					continue
				}
				sawProduct = true
				if !m.Vulnerable {
					continue
				}
				switch v := criterionContains(crit, m, c); v {
				case cpeMatched:
					return cpeMatched
				case cpeUndecidable:
					undecidable = true
				}
			}
		}
	}
	if undecidable || !sawProduct {
		return cpeUndecidable
	}
	return cpeRejected
}

// criterionContains decides whether one vulnerable criterion covers the
// candidate.
func criterionContains(crit cpeName, m NVDCPEMatch, c cpeCandidate) cpeVerdict {
	version := c.effectiveVersion()
	if crit.Version == "-" {
		// NA: the criterion applies to a version-less thing; a versioned
		// component is not it.
		return cpeRejected
	}
	if cpeConcrete(crit.Version) {
		// A criterion can pin a qualifier in the CPE `update` attribute
		// (NVD writes log4j 2.0-beta9 as `log4j:2.0:beta9`), so the release
		// it names is version+update, and an SBOM writes that as one
		// version string ("2.0-beta9"). `update` = "-" (NA) names the final
		// release itself.
		//
		// The criterion's update decides what is compared (Codex M60 R6
		// High-1): ANY accepts every update of its version, so only the base
		// versions are compared; NA names the final release, so a candidate
		// with an update is a different release; a concrete update names
		// one release.
		target, mine := crit.Version, version
		switch {
		case crit.Update == "" || crit.Update == "*":
			mine = c.version
		case crit.Update == "-":
			if c.update != "" {
				return cpeRejected
			}
		default:
			target += "-" + crit.Update
		}
		cmp, ok := compareVersions(mine, target)
		if !ok {
			return cpeUndecidable
		}
		if cmp != 0 {
			return cpeRejected
		}
		return cpeMatched
	}
	// version "*": a range, or every version when no bound is given.
	bounds := []struct {
		v    string
		pass func(int) bool
	}{
		{m.VersionStartIncluding, func(c int) bool { return c >= 0 }},
		{m.VersionStartExcluding, func(c int) bool { return c > 0 }},
		{m.VersionEndIncluding, func(c int) bool { return c <= 0 }},
		{m.VersionEndExcluding, func(c int) bool { return c < 0 }},
	}
	for _, b := range bounds {
		if b.v == "" {
			continue
		}
		cmp, ok := compareVersions(version, strings.ToLower(b.v))
		if !ok {
			return cpeUndecidable
		}
		if !b.pass(cmp) {
			return cpeRejected
		}
	}
	return cpeMatched
}

// Version ordering for NVD ranges.
//
// A version is tokenised into runs of digits and runs of letters. Letter runs
// are classified, because the same letters mean opposite things in different
// schemes (Codex M60 R2 High / R3 High):
//
//   - PRE-RELEASE: a known qualifier word ("alpha", "beta", "rc", "dev", ...)
//     or a shorthand letter immediately followed by a number ("1.0a1",
//     "1.0b2", Tomcat's "9.0.0.M1"). Sorts BEFORE the release it qualifies,
//     in Maven order: dev < alpha < beta < milestone < preview < rc < snapshot.
//   - POST-RELEASE: one or two bare letters with no number after them —
//     OpenSSL's patch releases ("1.1.1k" > "1.1.1", "1.1.1za" > "1.1.1z").
//     OpenSSL 1.1.1m is a patch release, not a milestone.
//   - RELEASE MARKER: "final", "ga", "release" (Maven's "4.1.100.Final") mean
//     the release itself and are dropped.
//   - anything else ("post1", "dfsg", "final2", ...) is UNKNOWN: a comparison
//     that depends on it is undecidable, never guessed. The caller keeps such
//     a CVE as nvd_cpe_unverified and does not cache the answer.
//
// Separators matter in two places (Codex M60 R5 High):
//
//   - everything from "+" on is SemVer build metadata and is ignored
//     ("1.0.0+1" == "1.0.0", "1.2.3+dfsg" == "1.2.3");
//   - a NUMBER directly after "-" is a pre-release in SemVer ("1.0.0-1" <
//     "1.0.0") but a revision in other schemes. Such a token compares only
//     against another dash-number; any order that depends on it otherwise is
//     undecidable.
//
// Numeric zero padding is skipped wherever a number faces a qualifier, so
// "1.0" == "1.0.0" and "1.0.0-rc1" < "1.0" < "1.0.0a" all hold together.
// The orderings are pinned by transitivity tests over mixed sets.

type versionToken struct {
	num   bool
	value string
	// dashNum: a number whose preceding separator was "-" (see above).
	dashNum bool
}

var releaseMarkers = map[string]bool{"final": true, "ga": true, "release": true}

// preReleaseRank orders the qualifier words; shorthand letters map onto them.
var preReleaseRank = map[string]int{
	"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3,
	"pre": 4, "preview": 4, "rc": 5, "cr": 5, "snapshot": 6,
}

// shorthandPreRelease are qualifiers that are pre-releases ONLY when a number
// follows them. Bare, "m" is an OpenSSL patch letter (1.1.1m), while a bare
// "a"/"b" is an alpha/beta in PEP 440 ("1.0a" < "1.0") but a patch letter in
// OpenSSL ("1.1.1a" > "1.1.1"), so it is UNKNOWN (Codex M60 R6 High-2).
var shorthandPreRelease = map[string]bool{"a": true, "b": true, "m": true}

type tokenKind int

const (
	kindNum tokenKind = iota
	kindPre
	kindPost
	kindUnknown
)

func tokenKindAt(toks []versionToken, i int) tokenKind {
	t := toks[i]
	if t.num {
		return kindNum
	}
	numberFollows := i+1 < len(toks) && toks[i+1].num
	if shorthandPreRelease[t.value] {
		switch {
		case numberFollows:
			return kindPre
		case t.value == "m":
			return kindPost
		}
		return kindUnknown
	}
	if _, ok := preReleaseRank[t.value]; ok {
		return kindPre
	}
	if len(t.value) <= 2 && !numberFollows {
		return kindPost
	}
	return kindUnknown
}

func tokeniseVersion(v string) []versionToken {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // SemVer build metadata takes no part in ordering
	}
	var out []versionToken
	var cur strings.Builder
	curNum := false
	var sep rune // separator seen since the last token
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, versionToken{num: curNum, value: cur.String(), dashNum: curNum && sep == '-'})
			cur.Reset()
			sep = 0
		}
	}
	for _, r := range strings.ToLower(v) {
		isNum := r >= '0' && r <= '9'
		isAlpha := r >= 'a' && r <= 'z'
		if !isNum && !isAlpha {
			flush()
			sep = r
			continue
		}
		if cur.Len() > 0 && isNum != curNum {
			flush()
		}
		curNum = isNum
		cur.WriteRune(r)
	}
	flush()
	// Drop release markers, but only bare ones: "final2" is not "final".
	kept := out[:0]
	for i, t := range out {
		numberFollows := i+1 < len(out) && out[i+1].num
		if !t.num && releaseMarkers[t.value] && !numberFollows {
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// isZero is a zero that can be read as padding — never a dash-number.
func isZero(t versionToken) bool {
	return t.num && !t.dashNum && strings.TrimLeft(t.value, "0") == ""
}

// compareVersions compares two versions the way NVD's configuration ranges
// are written. ok is false when they cannot be ordered with confidence;
// callers must treat that as "unknown", never as "outside".
func compareVersions(a, b string) (int, bool) {
	ta, tb := tokeniseVersion(a), tokeniseVersion(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0, false
	}
	return compareTokens(ta, tb)
}

func compareTokens(ta, tb []versionToken) (int, bool) {
	for i := 0; i < len(ta) && i < len(tb); i++ {
		x, y := ta[i], tb[i]
		switch {
		case x.num && y.num:
			if x.dashNum != y.dashNum {
				// "1.0.0-1" vs "1.0.0.1": pre-release or revision?
				return 0, false
			}
			if c := compareNumeric(x.value, y.value); c != 0 {
				return c, true
			}
		case !x.num && !y.num:
			kx, ky := tokenKindAt(ta, i), tokenKindAt(tb, i)
			if kx == kindUnknown || ky == kindUnknown {
				if x.value == y.value {
					continue
				}
				return 0, false
			}
			if kx != ky { // pre-release before post-release
				if kx == kindPre {
					return -1, true
				}
				return 1, true
			}
			if kx == kindPre {
				if c := preReleaseRank[x.value] - preReleaseRank[y.value]; c != 0 {
					if c < 0 {
						return -1, true
					}
					return 1, true
				}
				continue
			}
			if c := strings.Compare(x.value, y.value); c != 0 {
				return c, true
			}
		case x.num: // number vs qualifier
			return compareNumVsQualifier(ta[i:], tb[i:], 1)
		default: // qualifier vs number
			return compareNumVsQualifier(tb[i:], ta[i:], -1)
		}
	}
	if len(ta) == len(tb) {
		return 0, true
	}
	longer, sign := ta, 1
	if len(tb) > len(ta) {
		longer, sign = tb, -1
	}
	c, ok := compareRest(longer[min(len(ta), len(tb)):])
	return sign * c, ok
}

// compareNumVsQualifier handles a number (head of nums) facing a qualifier
// (head of quals). sign orients the result: +1 when nums is the left operand.
func compareNumVsQualifier(nums, quals []versionToken, sign int) (int, bool) {
	if nums[0].dashNum {
		return 0, false // SemVer and Maven order "1.0-1" vs "1.0-rc1" differently
	}
	if isZero(nums[0]) {
		// Zero padding: "1.0.0" vs "1.0a" compares like "1.0" vs "1.0a".
		j := 0
		for j < len(nums) && isZero(nums[j]) {
			j++
		}
		c, ok := compareTokens(nums[j:], quals)
		if len(nums[j:]) == 0 {
			c, ok = compareRest(quals)
			c = -c
		}
		return sign * c, ok
	}
	if tokenKindAt(quals, 0) == kindPre {
		return sign, true // "2.0-beta9" < "2.0.1"
	}
	return 0, false
}

// compareRest orders the tail a longer version has beyond a shorter one that
// is its prefix: positive when the tail makes it newer.
func compareRest(rest []versionToken) (int, bool) {
	for len(rest) > 0 && isZero(rest[0]) {
		rest = rest[1:]
	}
	if len(rest) == 0 {
		return 0, true
	}
	if rest[0].dashNum {
		return 0, false // "1.0.0-1" vs "1.0.0": pre-release or revision?
	}
	switch tokenKindAt(rest, 0) {
	case kindNum, kindPost:
		return 1, true
	case kindPre:
		return -1, true
	}
	return 0, false
}

// nvdCPECacheName / nvdNoCPECacheName are the cache identities of the CPE
// path. Both hash a length-prefixed input like nvdCacheName (same injectivity
// argument), and their schema prefixes ("m60c." / "m60n.") share no prefix
// with each other or with the keyword path's "m55.", so the three key spaces
// are disjoint within this build. Older builds compose every key as
// `NVDCachePrefix + nvdCacheName(...)` = "nvdv2:m55.<hex>" (M55..M59) or use
// the legacy "nvd:vuln:" prefix (pre-M55), so neither can write a key here.
const (
	nvdCPECacheSchema   = "m60c."
	nvdNoCPECacheSchema = "m60n."
)

// nvdCPECacheName keys a VERIFIED answer for one candidate at one version.
// The entry holds only CVEs that passed verifyCPEMatch; an EMPTY entry means
// "NVD knows this product and none of its CVEs covers this version".
func nvdCPECacheName(c cpeCandidate) string {
	q := c.query()
	sum := sha256.Sum256([]byte(strconv.Itoa(len(q)) + ":" + q))
	return nvdCPECacheSchema + hex.EncodeToString(sum[:])
}

// nvdNoCPECacheName keys the negative fact "NVD's configurations name no
// CVE for this part:vendor:product". Its only effect is to skip the
// candidate, which ends in the keyword fallback — a poisoned or stale entry
// lowers a component's match CONFIDENCE, it cannot make it read as clean.
func nvdNoCPECacheName(c cpeCandidate) string {
	k := c.productKey()
	sum := sha256.Sum256([]byte(strconv.Itoa(len(k)) + ":" + k))
	return nvdNoCPECacheSchema + hex.EncodeToString(sum[:])
}

// nvdWorkKey is the deduplication key of one component: everything its lookup
// depends on — the name and version (keyword fallback), the CPE candidates
// ACTUALLY tried, in order, and whether it is a distro package. Built from the
// candidates rather than the stored CPE list, so components that differ only
// in CPEs past the candidate cap share one lookup (Codex M60 R2 Low-1).
func nvdWorkKey(name, version string, cpes []string, purl string) nvdComponentKey {
	var b strings.Builder
	for _, c := range cpeCandidates(cpes, version, purl) {
		q := c.query()
		b.WriteString(strconv.Itoa(len(q)))
		b.WriteByte(':')
		b.WriteString(q)
	}
	// Distro-ness only changes the lookup when there are candidates (it
	// selects the version normalisation and the nvd_cpe_distro label); a
	// keyword-only item is the same walk either way (Codex M60 R3 Low).
	return nvdComponentKey{Name: name, Version: version, CPEKey: b.String(), Distro: b.Len() > 0 && isDistroComponent(purl)}
}

// matchMethodFor is the label a CPE-path link gets.
func matchMethodFor(distro bool) model.MatchMethod {
	if distro {
		return model.MatchNVDCPEDistro
	}
	return model.MatchNVDCPE
}

// String is for logs.
func (c cpeCandidate) String() string {
	return fmt.Sprintf("%s:%s:%s@%s", c.part, c.vendor, c.product, c.effectiveVersion())
}

// lookupComponent resolves one work item: the CPE path first, the keyword
// fallback when no candidate names a product NVD knows.
//
// The worker loop has already paid ONE pacer tick for this item, which covers
// exactly its first request; every later request (another candidate, the
// product probe, the keyword fallback) pays its own. That keeps the pool's
// invariant from M55: at most one NVD request per tick, whatever the mix.
func (s *NVDService) lookupComponent(ctx context.Context, item nvdWorkItem, pace nvdPacer) (nvdLookup, error) {
	spent := 0
	for _, c := range item.candidates {
		l, decided, err := s.lookupCPECandidate(ctx, c, item.distro, pace, spent > 0)
		spent += l.requests
		if err != nil {
			return nvdLookup{requests: spent}, err
		}
		if decided {
			l.requests = spent
			// An answer that cost requests is not a cache hit, even if
			// its last step was (Codex M60 R4 Low): CacheHits promises
			// "no HTTP request".
			l.fromCache = l.fromCache && spent == 0
			return l, nil
		}
	}
	l, err := s.keywordLookup(ctx, item.key.Name, item.key.Version, pace, spent > 0)
	l.requests += spent
	l.fromCache = l.fromCache && spent == 0
	l.method = model.MatchNVDKeyword
	l.keywordFallback = len(item.candidates) > 0
	return l, err
}

// lookupCPECandidate asks NVD about one candidate. decided=false means "NVD
// has no CVE configured for this part:vendor:product; try the next candidate"
// and is the ONLY outcome that moves on — a fetch error is returned as an
// error, never treated as "unknown product", so a network failure cannot be
// laundered into a keyword-only (or clean) result.
func (s *NVDService) lookupCPECandidate(ctx context.Context, c cpeCandidate, distro bool, pace nvdPacer, paceFirst bool) (nvdLookup, bool, error) {
	method := matchMethodFor(distro)

	if s.cache != nil {
		if entry, err := s.cache.Get(ctx, nvdCPECacheName(c), ""); err != nil {
			slog.Debug("cache get error", "cpe", c.String(), "error", err)
		} else if entry != nil {
			if vulns, usable := cachedNVDVulns(entry, c.productKey(), c.version); usable {
				return nvdLookup{vulns: vulns, fromCache: true, method: method}, true, nil
			}
		}
		if entry, err := s.cache.Get(ctx, nvdNoCPECacheName(c), ""); err == nil && entry != nil {
			return nvdLookup{}, false, nil
		}
	}

	q := url.Values{}
	q.Set("cpeName", c.query())
	res, err := s.walkNVD(ctx, q, pace, paceFirst)
	if err != nil {
		return nvdLookup{requests: res.pages}, false, err
	}
	out := nvdLookup{
		requests:  res.pages,
		truncated: res.truncated,
		shifted:   res.shifted,
		total:     res.total,
		fetched:   res.fetched,
		method:    method,
	}

	if res.total == 0 && len(res.entries) == 0 {
		// Ambiguous zero: unknown product, or known product with no CVE at
		// this version. One record of the version-less product query decides.
		if pace != nil {
			if err := pace(ctx); err != nil {
				return out, false, err
			}
		}
		pq := url.Values{}
		pq.Set("virtualMatchString", c.productQuery())
		page, err := s.fetchPage(ctx, pq, 0, 1)
		out.requests++
		if err != nil {
			return out, false, err
		}
		if *page.TotalResults == 0 {
			s.cacheVulns(ctx, nvdNoCPECacheName(c), c.String(), nil)
			return nvdLookup{requests: out.requests}, false, nil
		}
		// "Known product" ends the candidate walk with a final, cached
		// "no CVE at this version", so the probe's answer must be ABOUT the
		// product (Codex M60 R6 High-3): a mirror that ignored
		// virtualMatchString and returned some unrelated record would
		// otherwise make an unknown product known. Neither known nor
		// unknown can be concluded then, so the lookup fails.
		if !recordNamesProduct(page.entries(), c) {
			return out, false, fmt.Errorf("nvd: product probe for %s answered with a record that does not name the product; "+
				"cannot tell whether NVD knows it", c.productQuery())
		}
		s.cacheVulns(ctx, nvdCPECacheName(c), c.String(), nil)
		return out, true, nil
	}

	for i, e := range res.entries {
		switch verifyCPEMatch(e.CVE, c) {
		case cpeMatched:
			out.vulns = append(out.vulns, res.vulns[i])
			out.methods = append(out.methods, method)
		case cpeUndecidable:
			// Kept (NVD selected it for this CPE), but NOT labelled as
			// verified (Codex M60 R2 Medium-1).
			out.vulns = append(out.vulns, res.vulns[i])
			out.methods = append(out.methods, model.MatchNVDCPEUnverified)
			out.cpeUndecidable++
		case cpeRejected:
			out.cpeRejected++
		}
	}
	// Same rule as the keyword path: a truncated answer is never cached, or
	// the truncation would be reported once and then laundered for a TTL.
	// Nor is an answer holding an unverified CVE: the cache carries no
	// per-CVE provenance, so a hit would relabel it as verified.
	out.uncacheable = res.truncated || out.cpeUndecidable > 0
	if !out.uncacheable {
		s.cacheVulns(ctx, nvdCPECacheName(c), c.String(), out.vulns)
	}
	return out, true, nil
}

// recordNamesProduct reports whether any configuration criterion of the
// given records names the candidate's part:vendor:product.
func recordNamesProduct(entries []NVDVulnEntry, c cpeCandidate) bool {
	for _, e := range entries {
		for _, cfg := range e.CVE.Configurations {
			for _, n := range cfg.Nodes {
				for _, m := range n.CpeMatch {
					if crit, ok := parseCPE(m.Criteria); ok &&
						crit.Part == c.part && crit.Vendor == c.vendor && crit.Product == c.product {
						return true
					}
				}
			}
		}
	}
	return false
}

// cacheVulns writes one cache record (best effort, like the keyword path).
func (s *NVDService) cacheVulns(ctx context.Context, cacheName, label string, vulns []model.Vulnerability) {
	if s.cache == nil {
		return
	}
	cachedVulns := make([]cache.CachedVuln, len(vulns))
	for i, v := range vulns {
		cachedVulns[i] = cache.CachedVuln{
			CVEID:       v.CVEID,
			Description: v.Description,
			Severity:    v.Severity,
			CVSSScore:   v.CVSSScore,
			PublishedAt: v.PublishedAt,
		}
	}
	if err := s.cache.Set(ctx, cacheName, "", cachedVulns); err != nil {
		slog.Debug("cache set error", "key", label, "error", err)
	}
}
