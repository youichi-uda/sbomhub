package service

// Distro-aware matching (M70): which distro release a component belongs to,
// and what the distro's own fixed-version data says about one of its CVEs.
//
// # The invariant (M60's, kept)
//
// A gap in comparison or in data costs a LABEL, never a finding. Concretely:
//
//   - The distro step only RELABELS links the NVD / JVN sweeps already made;
//     it never deletes one and never adds one.
//   - A component whose distro or release cannot be identified exactly
//     (distroTargetFor), a version either side cannot parse, an epoch only
//     one side states, a range shape this code does not evaluate, or no
//     record for the CVE: no verdict, the M60 label stays.
//   - A distro-data FETCH failure is reported (scan reason
//     distro_data_failed), and the links of that package keep their labels;
//     it is never read as "no fix".
//
// # What the data is (measured 2026-11-09, live api.osv.dev)
//
// OSV's distro ecosystems normalise each distro's own data into one schema:
// Debian (DSA/DLA advisories plus DEBIAN-CVE records generated from the
// Debian security tracker), Ubuntu (UBUNTU-CVE / USN), AlmaLinux (ALSA),
// Rocky Linux (RLSA). A record lists, per release ecosystem ("Debian:11") and
// package, ECOSYSTEM ranges of introduced / fixed events in the distro's own
// version syntax.
//
// Two measured gaps shape the rules below:
//
//   - Debian 11 (bullseye) reached the end of LTS in 2026-08: the DEBIAN-CVE
//     records and the Debian tracker's own JSON no longer list it (openssl:
//     291 DEBIAN-CVE records, entries only for Debian:12/13/14; the tracker
//     lists bookworm / trixie / forky / sid). Only the 11 DSA/DLA advisories
//     issued while it was supported still name Debian:11. See
//     laterReleaseVerdict for what can still be said soundly.
//   - OSV omits a Debian release the tracker marks not-affected (tracker
//     fixed_version "0"): 29 of openssl's 320 tracker CVEs have no OSV record
//     at all. No record is no verdict, never "not affected".

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/pkgversion"
)

// distroScheme is a distro's version ordering.
type distroScheme int

const (
	schemeDpkg distroScheme = iota + 1
	schemeRPM
)

// distroTarget is everything the distro step needs to ask about one
// component: which data to read and which version to compare.
type distroTarget struct {
	// family is the distro ("debian", "ubuntu", "almalinux", "rocky").
	family string
	// query is the OSV ecosystem queried: "Debian" (every Debian release, so
	// that later releases can be read for an end-of-life one), or the
	// release itself for the other distros.
	query string
	// release is the OSV ecosystem of the installed release.
	release string
	// releaseMajor is the Debian major release number (laterReleaseVerdict).
	releaseMajor int
	// pkg is the OSV package name: the SOURCE package for Debian/Ubuntu,
	// the binary package for the rpm distros.
	pkg string
	// binary is the installed (binary) package name, the purl's name.
	binary string
	// version is the installed version, in the distro's syntax.
	version string
	scheme  distroScheme
}

// fetchKey identifies the OSV query (and its cache entry) a target needs.
func (t distroTarget) fetchKey() distroFetchKey {
	return distroFetchKey{ecosystem: t.query, pkg: t.pkg}
}

type distroFetchKey struct{ ecosystem, pkg string }

// distroOS is the operating system the SBOM itself declares (Syft's
// operating-system component, e.g. name "debian", version "11"). It is used
// only when a package's purl carries no distro qualifier.
type distroOS struct {
	id, version string
}

// parsedPurl is the part of a package URL the distro step reads.
type parsedPurl struct {
	typ, namespace, name, version string
	qualifiers                    url.Values
}

// parsePurl parses "pkg:type/namespace/name@version?qualifiers#subpath"
// (package-url spec): type and namespace are lower-cased for deb/rpm/apk,
// every component is percent-decoded. ok is false for anything that does not
// have that shape.
func parsePurl(s string) (parsedPurl, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return parsedPurl{}, false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	var p parsedPurl
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		q, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return parsedPurl{}, false
		}
		p.qualifiers = q
		rest = rest[:i]
	}
	rest = strings.Trim(rest, "/")
	slash := strings.LastIndexByte(rest, '/')
	if at := strings.LastIndexByte(rest, '@'); at > slash {
		v, err := url.PathUnescape(rest[at+1:])
		if err != nil {
			return parsedPurl{}, false
		}
		p.version = v
		rest = rest[:at]
	}
	segs := strings.Split(rest, "/")
	if len(segs) < 2 {
		return parsedPurl{}, false
	}
	p.typ = strings.ToLower(segs[0])
	for i := range segs[1:] {
		u, err := url.PathUnescape(segs[1+i])
		if err != nil || u == "" {
			return parsedPurl{}, false
		}
		segs[1+i] = u
	}
	p.name = segs[len(segs)-1]
	p.namespace = strings.ToLower(strings.Join(segs[1:len(segs)-1], "/"))
	return p, true
}

// qualifier returns a single-valued qualifier. A qualifier given twice is
// ambiguous and reads as absent-but-conflicting (ok=false).
func (p parsedPurl) qualifier(k string) (string, bool) {
	vs := p.qualifiers[k]
	switch len(vs) {
	case 0:
		return "", true
	case 1:
		return vs[0], true
	}
	return "", false
}

// distroTargetFor identifies the distro release, the package and the version
// of one component, or says why it cannot (the reason is for logs and the
// report only). It never guesses: the release comes from the purl's distro
// qualifier, or else from the SBOM's own single operating-system component of
// the SAME distro; a qualifier that names another distro than the purl's
// namespace, an unknown distro, or a version in the wrong syntax is no target.
func distroTargetFor(purl, compVersion string, os *distroOS) (distroTarget, string) {
	p, ok := parsePurl(purl)
	if !ok {
		return distroTarget{}, "no_purl"
	}
	switch p.typ {
	case "deb", "rpm":
	case "apk", "alpm":
		return distroTarget{}, "no_comparator"
	default:
		return distroTarget{}, "not_distro"
	}
	distroQ, ok := p.qualifier("distro")
	if !ok {
		return distroTarget{}, "ambiguous_qualifier"
	}
	id, rel := "", ""
	if distroQ != "" {
		i := strings.LastIndexByte(distroQ, '-')
		if i <= 0 {
			return distroTarget{}, "unknown_release"
		}
		id, rel = strings.ToLower(distroQ[:i]), distroQ[i+1:]
	} else if os != nil {
		id, rel = strings.ToLower(os.id), os.version
	} else {
		return distroTarget{}, "unknown_release"
	}
	if id != p.namespace && purlNamespaceAlias[p.namespace] != id {
		return distroTarget{}, "distro_mismatch"
	}
	compVersion = strings.TrimSpace(compVersion)
	version := p.version
	if version == "" {
		version = compVersion
	}
	if version == "" {
		return distroTarget{}, "no_version"
	}
	// The NVD link was made on the component's version: a purl stating a
	// different one is no target (Codex M70 R3 High-1). Checked per scheme
	// below, before any source-package override.
	mismatch := func(cmp func(a, b string) (int, error), a, b string) bool {
		if b == "" {
			return false
		}
		c, err := cmp(a, b)
		return err != nil || c != 0
	}

	t := distroTarget{family: id}
	switch p.typ {
	case "deb":
		t.scheme = schemeDpkg
		if mismatch(pkgversion.CompareDpkg, version, compVersion) {
			return distroTarget{}, "version_mismatch"
		}
		// Without an `upstream` qualifier the source package is taken to be
		// the binary's own name: dpkg omits the Source field exactly when
		// the two are equal, and Syft derives `upstream` from that field.
		// (Codex M70 R4 High-2, declined for Debian — its data names no
		// binaries to check against; for Ubuntu every entry is checked
		// against its own binaries list, see decide.)
		t.pkg, t.binary, t.version = p.name, p.name, version
		up, ok := p.qualifier("upstream")
		if !ok {
			return distroTarget{}, "ambiguous_qualifier"
		}
		if up != "" {
			// Syft: "upstream=glibc" (same version as the binary) or
			// "upstream=linux-signed-amd64@5.10.46+4" (source name@version).
			name, ver, hasVer := strings.Cut(up, "@")
			if name == "" || (hasVer && ver == "") {
				return distroTarget{}, "bad_upstream"
			}
			t.pkg = name
			if hasVer {
				t.version = ver
			}
		}
		if _, err := pkgversion.ParseDpkg(t.version); err != nil {
			return distroTarget{}, "bad_version"
		}
		switch id {
		case "debian":
			major, ok := releaseMajor(rel)
			if !ok || major < debianFirstNumbered {
				// OSV names Debian 3.0 .. 6.0 "Debian:3.0", "Debian:3.1",
				// ...: a major number cannot identify them (Codex M70 R2
				// High-2), and they ended long before this data existed.
				return distroTarget{}, "unknown_release"
			}
			t.releaseMajor = major
			t.release = "Debian:" + strconv.Itoa(major)
			t.query = "Debian"
		case "ubuntu":
			eco, ok := ubuntuEcosystem(rel)
			if !ok {
				return distroTarget{}, "unknown_release"
			}
			if ubuntuProBuild(t.version) || ubuntuProBuild(version) {
				// Both the source version compared and the binary's own
				// (an upstream qualifier may state a standard source
				// version for an ESM binary, Codex M70 R7 High-2).
				// An Ubuntu Pro / FIPS / ESM build belongs to another stream
				// (Ubuntu:Pro:..., Ubuntu:Pro:FIPS:...) with the same binary
				// names; the SBOM does not say which one. Comparing it with
				// the standard stream's fixes is wrong (Codex M70 R5 High-1).
				return distroTarget{}, "ubuntu_pro_stream"
			}
			t.release, t.query = eco, eco
		default:
			return distroTarget{}, "unsupported_distro"
		}
	case "rpm":
		t.scheme = schemeRPM
		t.pkg, t.binary = p.name, p.name
		epoch, ok := p.qualifier("epoch")
		if !ok {
			return distroTarget{}, "ambiguous_qualifier"
		}
		if epoch != "" {
			if strings.Contains(version, ":") {
				// Both the version and the qualifier state an epoch.
				ev, _, _ := strings.Cut(version, ":")
				if ev != epoch {
					return distroTarget{}, "bad_version"
				}
			} else {
				version = epoch + ":" + version
			}
		}
		if _, err := pkgversion.ParseRPMEVR(version); err != nil {
			return distroTarget{}, "bad_version"
		}
		cv := compVersion
		if cv != "" && epoch != "" && !strings.Contains(cv, ":") {
			cv = epoch + ":" + cv // Syft's component version omits the epoch
		}
		if mismatch(pkgversion.CompareRPMEVR, version, cv) {
			return distroTarget{}, "version_mismatch"
		}
		t.version = version
		major, ok := numericReleaseMajor(rel) // no codenames (Codex M70 R3 High-2)
		if !ok {
			return distroTarget{}, "unknown_release"
		}
		switch id {
		case "almalinux":
			t.release = "AlmaLinux:" + strconv.Itoa(major)
		case "rocky":
			t.release = "Rocky Linux:" + strconv.Itoa(major)
		default:
			// rhel / centos / fedora / amzn / ol / sles: OSV either has no
			// such ecosystem or keys it by repository (Red Hat), which the
			// SBOM does not state. No guess.
			return distroTarget{}, "unsupported_distro"
		}
		t.query = t.release
	}
	return t, ""
}

// purlNamespaceAlias maps a purl namespace to the os-release ID Syft writes in
// the distro qualifier when the two differ (pkg:rpm/redhat/...?distro=rhel-9.4).
var purlNamespaceAlias = map[string]string{"redhat": "rhel"}

// releaseMajor reads "11", "11.7" or "9.4" as its major number. Debian
// codenames are accepted too (Syft writes VERSION_ID, but other tools write
// the codename).
func releaseMajor(rel string) (int, bool) {
	rel = strings.ToLower(strings.TrimSpace(rel))
	if n, ok := debianCodenames[rel]; ok {
		return n, true
	}
	return numericReleaseMajor(rel)
}

// numericReleaseMajor reads "11", "11.7" or "9.4" as its major number.
func numericReleaseMajor(rel string) (int, bool) {
	rel = strings.TrimSpace(rel)
	// Digits, optionally one numeric point release ("11", "11.7", "9.4").
	// Anything else ("12.sid", "11.7.1", "9.garbage") is not a release
	// this code can name an ecosystem for (Codex M70 R1 Medium).
	major, point, hasPoint := strings.Cut(rel, ".")
	canonical := func(s string) bool { return isDigits(s) && len(s) <= 3 && (s == "0" || s[0] != '0') }
	if !canonical(major) || (hasPoint && !canonical(point)) {
		// "011", "11.07": not canonical (Codex M70 R7 Medium-4).
		return 0, false
	}
	n, err := strconv.Atoi(major)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

var debianCodenames = map[string]int{
	"buzz": 1, "rex": 1, "bo": 1, "hamm": 2, "slink": 2, "potato": 2, "woody": 3, "sarge": 3, "etch": 4,
	"lenny": 5, "squeeze": 6, "wheezy": 7, "jessie": 8, "stretch": 9, "buster": 10, "bullseye": 11,
	"bookworm": 12, "trixie": 13, "forky": 14, "duke": 15,
}

// noncanonicalFor reports an ecosystem spelling that could denote the
// target's distro but is not canonical: empty, a case variant of the
// installed release, or (Debian) any "debian..." form debianEcosystemMajor
// does not accept.
func noncanonicalFor(t distroTarget, eco string) bool {
	if strings.TrimSpace(eco) == "" || eco != strings.TrimSpace(eco) {
		return true
	}
	if eco != t.release && strings.EqualFold(eco, t.release) {
		return true
	}
	lower := strings.ToLower(eco)
	switch t.family {
	case "debian":
		if strings.HasPrefix(lower, "debian") {
			_, ok := debianEcosystemMajor(eco)
			return !ok
		}
	case "ubuntu":
		if strings.HasPrefix(lower, "ubuntu") {
			return !canonicalUbuntuEcosystem(eco)
		}
	case "almalinux":
		if strings.HasPrefix(lower, "almalinux") {
			return !canonicalNumbered(eco, "AlmaLinux:")
		}
	case "rocky":
		if strings.HasPrefix(lower, "rocky") {
			return !canonicalNumbered(eco, "Rocky Linux:")
		}
	}
	return false
}

// canonicalUbuntuEcosystem: "Ubuntu:YY.MM" for an interim release,
// "Ubuntu:YY.MM:LTS" for an LTS one (as ubuntuEcosystem spells them), or an
// Ubuntu Pro stream "Ubuntu:Pro:[<stream>:]YY.MM:LTS" (Codex M70 R9 High-1).
func canonicalUbuntuEcosystem(eco string) bool {
	if rest, ok := strings.CutPrefix(eco, "Ubuntu:Pro:"); ok {
		parts := strings.Split(rest, ":")
		switch len(parts) {
		case 2:
		case 3:
			if parts[0] == "" || !isStreamName(parts[0]) {
				return false
			}
			parts = parts[1:]
		default:
			return false
		}
		want, ok := ubuntuEcosystem(parts[0])
		return ok && parts[1] == "LTS" && want == "Ubuntu:"+parts[0]+":LTS"
	}
	rest, ok := strings.CutPrefix(eco, "Ubuntu:")
	if !ok {
		return false
	}
	yymm, _, _ := strings.Cut(rest, ":")
	want, ok := ubuntuEcosystem(yymm)
	return ok && want == eco
}

func isStreamName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		if !letter && c != '-' {
			return false
		}
	}
	return s != ""
}

// canonicalNumbered: prefix + a canonical major number ("AlmaLinux:9").
func canonicalNumbered(eco, prefix string) bool {
	rest, ok := strings.CutPrefix(eco, prefix)
	return ok && isDigits(rest) && rest[0] != '0' && len(rest) <= 3
}

// purlNameAgrees: the component's name is the purl's package name (the
// binary the NVD link was made for). Codex M70 R8 High-3.
func purlNameAgrees(purl, compName string) bool {
	p, ok := parsePurl(purl)
	name := strings.TrimSpace(compName)
	return ok && name != "" && p.name == name
}

// cpeVersionsAgree reports whether every concrete version the component's
// CPE names state equals the component's version. M60 matches NVD on a CPE's
// own version when it states one (cpeCandidates), so a CPE that states
// another version than the component made the link about THAT version; a
// distro verdict on the component's version would then be about something
// else (Codex M70 R7 High-1). CPEs that do not parse, or state ANY / NA, are
// never matched on a version of their own.
func cpeVersionsAgree(cpes []string, compVersion string) bool {
	want := strings.ToLower(strings.TrimSpace(compVersion))
	for _, raw := range cpes {
		n, ok := parseCPE(raw)
		if !ok {
			continue
		}
		if cpeConcrete(n.Update) {
			// A pinned update names the release version-update, which M60
			// queried; not the component's version (Codex M70 R8 High-2).
			return false
		}
		if !cpeConcrete(n.Version) {
			continue
		}
		if strings.TrimPrefix(n.Version, cpeLiteralMark) != want {
			return false
		}
	}
	return true
}

// ubuntuProBuild reports a version built for an Ubuntu Pro stream:
// "...ubuntu2.fips.7.1", "...+esm1", "...~esm1".
func ubuntuProBuild(v string) bool {
	v = strings.ToLower(v)
	return strings.Contains(v, "fips") || strings.Contains(v, "esm")
}

// ubuntuEcosystem maps "22.04" to OSV's "Ubuntu:22.04:LTS" and "23.10" to
// "Ubuntu:23.10". Ubuntu's LTS releases are the April releases of even years
// (14.04, 16.04, ..., 24.04). Anything not shaped YY.MM is no release.
func ubuntuEcosystem(rel string) (string, bool) {
	yy, mm, ok := strings.Cut(strings.TrimSpace(rel), ".")
	if !ok || len(yy) != 2 || len(mm) != 2 || !isDigits(yy) || !isDigits(mm) {
		return "", false
	}
	y, _ := strconv.Atoi(yy)
	if mm == "04" && y%2 == 0 {
		return "Ubuntu:" + yy + "." + mm + ":LTS", true
	}
	return "Ubuntu:" + yy + "." + mm, true
}

// distroRecord is the reduced, cacheable form of one OSV record: the CVEs it
// speaks about and its entries for the queried package only.
type distroRecord struct {
	ID      string        `json:"id"`
	CVEs    []string      `json:"cves"`
	Entries []distroEntry `json:"entries"`
	// Releases / Packages are how many distinct release ecosystems and
	// package names the ORIGINAL record had, all packages included: the CVE
	// list is about all of them, so filtering to one package must not make
	// an advisory look single-entry (Codex M70 R2 High-1).
	Releases int `json:"releases"`
	Packages int `json:"packages"`
	// Modified is the record's OSV `modified`, normalised (normaliseModified).
	Modified string `json:"modified,omitempty"`
}

// normaliseModified renders an OSV timestamp as fixed-width UTC RFC 3339 with
// nanoseconds, so that revisions compare as text; "" if it does not parse.
func normaliseModified(s string) string {
	ts, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return ts.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

type distroEntry struct {
	Ecosystem string            `json:"ecosystem"`
	Ranges    []client.OSVRange `json:"ranges,omitempty"`
	Versions  []string          `json:"versions,omitempty"`
	// Binaries are the binary packages the entry applies to, when the data
	// says (Ubuntu: ecosystem_specific.binaries); BinariesListed tells an
	// empty list from an absent one.
	Binaries       []string `json:"binaries,omitempty"`
	BinariesListed bool     `json:"binaries_listed,omitempty"`
}

// entryBinaries reads Ubuntu's ecosystem_specific.binaries[].binary_name.
// ok is false when the field is absent or not of that shape.
func entryBinaries(es map[string]interface{}) ([]string, bool) {
	raw, present := es["binaries"]
	if !present {
		return nil, false
	}
	list, isList := raw.([]interface{})
	if !isList {
		return nil, false
	}
	var out []string
	for _, item := range list {
		m, isMap := item.(map[string]interface{})
		if !isMap {
			return nil, false
		}
		name, isStr := m["binary_name"].(string)
		if !isStr || name == "" {
			return nil, false
		}
		out = append(out, name)
	}
	return out, true
}

func (e distroEntry) namesBinary(b string) bool {
	if !e.BinariesListed {
		return false
	}
	for _, x := range e.Binaries {
		if x == b {
			return true
		}
	}
	return false
}

// reduceOSVRecords keeps, of each non-withdrawn record, the CVE ids it is
// about and its affected entries for pkg (exact name; OSV package names are
// case-sensitive). The CVE ids are the record's own id when it is a CVE, its
// aliases and its `upstream` list, and the CVE a DEBIAN-/UBUNTU-CVE id is
// generated from. `related` is not read: it links records that are merely
// connected.
func reduceOSVRecords(recs []client.OSVPackageRecord, pkg string) []distroRecord {
	var out []distroRecord
	for _, r := range recs {
		if strings.TrimSpace(r.Withdrawn) != "" {
			continue
		}
		cves := map[string]bool{}
		add := func(id string) {
			id = strings.ToUpper(strings.TrimSpace(id))
			if isCVEID(id) {
				cves[id] = true
			}
		}
		add(r.ID)
		for _, pfx := range []string{"DEBIAN-", "UBUNTU-"} {
			if rest, ok := strings.CutPrefix(strings.ToUpper(r.ID), pfx); ok {
				add(rest)
			}
		}
		for _, a := range r.Aliases {
			add(a)
		}
		for _, u := range r.Upstream {
			add(u)
		}
		if len(cves) == 0 {
			continue
		}
		var entries []distroEntry
		releases, packages := map[string]bool{}, map[string]bool{}
		for _, a := range r.Affected {
			releases[a.Package.Ecosystem] = true
			packages[a.Package.Name] = true
			if a.Package.Name != pkg {
				continue
			}
			// An entry with an empty ecosystem is kept: decide treats it as
			// a blocker, never as nothing (Codex M70 R8 High-1).
			bins, listed := entryBinaries(a.EcosystemSpecific)
			entries = append(entries, distroEntry{Ecosystem: a.Package.Ecosystem, Ranges: a.Ranges, Versions: a.Versions,
				Binaries: bins, BinariesListed: listed})
		}
		if len(entries) == 0 {
			continue
		}
		d := distroRecord{ID: r.ID, Entries: entries, Releases: len(releases), Packages: len(packages),
			Modified: normaliseModified(r.Modified)}
		for c := range cves {
			d.CVEs = append(d.CVEs, c)
		}
		sort.Strings(d.CVEs)
		out = append(out, d)
	}
	return out
}

// rawRevision is the newest `modified` (or `withdrawn`) of EVERY record a
// query returned, withdrawn and unrelated ones included, normalised: the
// data's snapshot revision. Counting dropped records keeps a withdrawal from
// lowering it (Codex M70 R9 High-2).
func rawRevision(recs []client.OSVPackageRecord) string {
	rev := ""
	for _, r := range recs {
		for _, ts := range []string{r.Modified, r.Withdrawn} {
			if m := normaliseModified(ts); m > rev {
				rev = m
			}
		}
	}
	return rev
}

// isCVEID: "CVE-<4 digits>-<4+ digits>".
func isCVEID(s string) bool {
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return false
	}
	y, n, ok := strings.Cut(rest, "-")
	return ok && len(y) == 4 && isDigits(y) && len(n) >= 4 && isDigits(n)
}

// distroData indexes one package's reduced records by CVE.
type distroData struct {
	byCVE map[string][]*distroRecord
	// revision is the newest record `modified` of the package (normalised):
	// the data snapshot the decisions rest on.
	revision string
	// source is the endpoint the data came from (evidence source_url).
	source string
	// cveRecordReleases are the release ecosystems named by at least one
	// CVE-specific record (DEBIAN-CVE-* / UBUNTU-CVE-*) of the package:
	// the releases the CVE-level data still covers. A Debian release absent
	// from all of them has been dropped from the data (end of life).
	cveRecordReleases map[string]bool
}

func indexDistroRecords(recs []distroRecord) distroData {
	d := distroData{byCVE: map[string][]*distroRecord{}, cveRecordReleases: map[string]bool{}}
	for i := range recs {
		r := &recs[i]
		if m := normaliseModified(r.Modified); m > d.revision {
			d.revision = m
		}
		for _, c := range r.CVEs {
			d.byCVE[c] = append(d.byCVE[c], r)
		}
		if r.isCVERecord() {
			for _, e := range r.Entries {
				d.cveRecordReleases[e.Ecosystem] = true
			}
		}
	}
	return d
}

// recordCVE returns the CVE a per-CVE record (DEBIAN-CVE-<id>,
// UBUNTU-CVE-<id>, or an id that is itself a CVE) is generated for, or "".
// The suffix must be a canonical CVE id (Codex M70 R9 High-3).
func (r *distroRecord) recordCVE() string {
	// Exactly one of three forms (Codex M70 R12 High-3): "CVE-…",
	// "DEBIAN-CVE-…", "UBUNTU-CVE-…".
	id := strings.ToUpper(strings.TrimSpace(r.ID))
	if isCVEID(id) {
		return id
	}
	for _, pfx := range []string{"DEBIAN-", "UBUNTU-"} {
		if rest, ok := strings.CutPrefix(id, pfx); ok && isCVEID(rest) {
			return rest
		}
	}
	return ""
}

// isCVERecord: the record is generated per CVE.
func (r *distroRecord) isCVERecord() bool { return r.recordCVE() != "" }

// isCVERecordFor: the record is THE per-CVE record of cve; its entries are
// statements about cve (and only cve).
func (r *distroRecord) isCVERecordFor(cve string) bool { return r.recordCVE() == cve }

// speaksFor reports whether the record's entries can be read as a statement
// about cve in EVERY release they name (Codex M70 R1 High-1). An advisory
// (DSA / DLA / USN / ALSA) lists the CVEs it fixes and a fixed version per
// release, but not which CVE applies to which release: USN-5402-1 lists
// CVE-2022-1343 with 18.04 / 20.04 fixes, and UBUNTU-CVE-2022-1343 shows only
// 22.04 is affected. So an advisory speaks for each of its CVEs only when it
// names ONE CVE, or ONE release and ONE package in the whole record (an LTS
// advisory for one source package: every listed CVE was fixed there). An
// AlmaLinux / Rocky Linux erratum that lists several CVEs for several binary
// rpms (openssl, openssl-libs, ...) does not say which CVE concerns which rpm
// either (Codex M70 R3 High-4), so it decides only single-CVE cases.
func (r *distroRecord) speaksFor(cve string) bool {
	return r.isCVERecordFor(cve) || len(r.CVEs) == 1 || (r.Releases == 1 && r.Packages == 1)
}

// debianFirstNumbered is the first Debian release OSV names by its major
// number alone ("Debian:7"); older ones are "Debian:6.0", "Debian:3.1", ...
const debianFirstNumbered = 7

// debianLastEndOfLife is the newest Debian major release that is past its
// LTS period (bullseye, 11: LTS ended 2026-08-31). laterReleaseVerdict
// applies only at or below it. Raise it when a release leaves LTS (bookworm,
// 12: June 2028); until then, the cost is only a missing label.
const debianLastEndOfLife = 11

// distroVerdict is what the data says about one (component, CVE).
type distroVerdict int

const (
	verdictNone distroVerdict = iota
	verdictAffected
	verdictUnfixed
	verdictFixed
)

func (v distroVerdict) method() model.MatchMethod {
	switch v {
	case verdictAffected:
		return model.MatchDistroAffected
	case verdictUnfixed:
		return model.MatchDistroUnfixed
	case verdictFixed:
		return model.MatchDistroFixed
	}
	return ""
}

// distroDecision is a verdict with its evidence.
type distroDecision struct {
	verdict  distroVerdict
	evidence model.DistroEvidence
	// reason says why there is no verdict (logs / tests).
	reason string
}

// entryState is one entry's statement about the installed version.
type entryState int

const (
	entryUndecidable entryState = iota
	entryAffected
	entryFixed
)

// entryResult is the evaluation of one affected entry (or one range).
type entryResult struct {
	state entryState
	// fix is, for entryAffected, the version that ends the affected range
	// above the installed one; for entryFixed, the fixed version that closed
	// the range at or below the installed one.
	fix string
	// noFix (entryAffected): the affected range has no fixed event — the
	// distro has released no fix.
	noFix bool
	// fixUnknown (entryAffected): affected for certain, but which version
	// fixes it cannot be stated (incomparable fixes, or affected only by the
	// `versions` list).
	fixUnknown bool
}

// decide applies the distro's data to one CVE of one component.
//
// Entries for the installed release decide, taken from the records that
// speak for the CVE in that release (speaksFor): for Ubuntu only the
// CVE-specific record when there is one; for Debian the CVE-specific record
// when it names the release, else advisories that speak for the CVE. An
// advisory that does not is never used, in either direction.
func (d distroData) decide(t distroTarget, cveID string) distroDecision {
	cve := strings.ToUpper(strings.TrimSpace(cveID))
	recs := d.byCVE[cve]
	if len(recs) == 0 {
		return distroDecision{reason: "no_record"}
	}
	cmp := t.comparator()

	// Any entry spelled non-canonically (or with no ecosystem) could be a
	// statement about the installed release this code would not see: no
	// verdict (Codex M70 R8 High-1).
	for _, r := range recs {
		for _, e := range r.Entries {
			if noncanonicalFor(t, e.Ecosystem) {
				return distroDecision{reason: "noncanonical_ecosystem"}
			}
		}
	}

	var cveRecs []*distroRecord
	cveRecordNamesRelease := false
	for _, r := range recs {
		if r.isCVERecordFor(cve) {
			cveRecs = append(cveRecs, r)
			for _, e := range r.Entries {
				if e.Ecosystem == t.release {
					cveRecordNamesRelease = true
				}
			}
		}
	}

	var exact []entryResult
	var usable []distroEntry
	var exactIDs []string
	sawExact, excluded := false, false
	for _, r := range recs {
		for _, e := range r.Entries {
			if e.Ecosystem != t.release {
				continue
			}
			sawExact = true
			if t.family == "ubuntu" && !e.namesBinary(t.binary) {
				// Ubuntu lists the binaries each entry applies to; another
				// binary of the same source is not vouched for (Codex M70 R4
				// High-3), nor is any binary when the list is absent.
				excluded = true
				continue
			}
			switch {
			case r.isCVERecordFor(cve):
			case t.family == "ubuntu" && len(cveRecs) > 0:
				// UBUNTU-CVE lists every affected release; the USNs add only
				// ambiguity.
				excluded = true
				continue
			case t.family == "debian" && cveRecordNamesRelease:
				excluded = true
				continue
			case !r.speaksFor(cve):
				// No verdict from it, in either direction: other releases'
				// records do not prove which of its CVEs concerned this one —
				// Debian's "introduced 0" is lossy (a 3.0-only CVE reads the
				// same), Codex M70 R3 High-5.
				excluded = true
				continue
			}
			exact = append(exact, evalEntry(t.version, e, cmp))
			usable = append(usable, e)
			exactIDs = appendUnique(exactIDs, r.ID)
		}
	}
	ev := model.DistroEvidence{
		Source:       model.DistroSourceOSV,
		Basis:        model.DistroBasisRelease,
		Release:      t.release,
		Package:      t.pkg,
		Installed:    t.version,
		DataModified: d.revision,
		SourceURL:    d.source,
	}
	if len(exact) > 0 {
		dec := combineExact(exact, exactIDs, ev, cmp)
		if dec.verdict == verdictFixed && excluded {
			// An entry for the release was set aside: "fixed" would rest on
			// part of the data.
			return distroDecision{reason: "undecidable"}
		}
		if dec.verdict == verdictAffected && dec.evidence.Fixed != "" {
			// The advertised upgrade target must itself be outside every
			// entry that decided, and no entry may have been set aside
			// (Codex M70 R5 Medium-3).
			ok := !excluded
			for _, e := range usable {
				if evalEntry(dec.evidence.Fixed, e, cmp).state != entryFixed {
					ok = false
				}
			}
			if !ok {
				dec.evidence.Fixed = ""
			}
		}
		if dec.verdict == verdictFixed && dec.evidence.Fixed != "" {
			// Same for the version a "fixed" verdict names (Codex M70 R8
			// Medium-5).
			for _, e := range usable {
				if !outsideAffectedSet(dec.evidence.Fixed, e, cmp) {
					dec.evidence.Fixed = ""
					break
				}
			}
		}
		return dec
	}
	if sawExact {
		return distroDecision{reason: "undecidable"}
	}
	if t.family == "debian" {
		if t.releaseMajor > debianLastEndOfLife || d.cveRecordReleases[t.release] {
			// A supported release, or one the CVE-level data still covers:
			// its absence from this CVE's record is "not affected" or "not
			// tracked", never "fixed" (Codex M70 R1 High-2).
			return distroDecision{reason: "release_not_listed"}
		}
		return laterReleaseVerdict(t, cveRecs, ev, cmp)
	}
	return distroDecision{reason: "release_not_listed"}
}

// combineExact combines the entries that name the installed release.
//
//   - Any entry with the installed version inside an affected range wins: the
//     CVE applies. If any such range has no fix, it is distro_unfixed;
//     otherwise distro_affected with the HIGHEST of their next fixed versions
//     (an advisory and its regression update, DLA-3942-1 / -2, both name the
//     same CVEs: the later fix is the one that leaves no affected range), or
//     with no fixed version when they cannot be ordered.
//   - Otherwise, if any entry could not be evaluated: no verdict.
//   - Otherwise every entry closed a range at or below the installed version:
//     distro_fixed, with the highest such fixed version as evidence.
func combineExact(rs []entryResult, ids []string, ev model.DistroEvidence, cmp versionCmp) distroDecision {
	affected, noFix, fixUnknown, undecidable := false, false, false, false
	fix := ""
	for _, r := range rs {
		switch r.state {
		case entryAffected:
			affected = true
			switch {
			case r.noFix:
				noFix = true
			case r.fixUnknown:
				fixUnknown = true
			case fix == "":
				fix = r.fix
			default:
				c, err := cmp(r.fix, fix)
				if err != nil {
					fixUnknown = true
				} else if c > 0 {
					fix = r.fix
				}
			}
		case entryUndecidable:
			undecidable = true
		}
	}
	ev.Records = ids
	switch {
	case affected && noFix:
		ev.Status = model.DistroStatusUnfixed
		return distroDecision{verdict: verdictUnfixed, evidence: ev}
	case affected:
		ev.Status = model.DistroStatusAffected
		if !fixUnknown && !undecidable {
			ev.Fixed = fix
		}
		return distroDecision{verdict: verdictAffected, evidence: ev}
	case undecidable:
		return distroDecision{reason: "undecidable"}
	}
	best := ""
	for _, r := range rs {
		if best == "" {
			best = r.fix
			continue
		}
		c, err := cmp(r.fix, best)
		if err != nil {
			return distroDecision{reason: "undecidable"}
		}
		if c > 0 {
			best = r.fix
		}
	}
	ev.Status = model.DistroStatusFixed
	ev.Fixed = best
	return distroDecision{verdict: verdictFixed, evidence: ev}
}

// laterReleaseVerdict decides for a Debian release the data does not list
// (end of life: measured, bullseye is gone from both OSV and the Debian
// tracker since 2026-08).
//
// Debian's security tracker computes a release's status from the UNSTABLE
// fixed version unless the release carries its own note: a release whose
// package version is >= the version that fixed the CVE in unstable is fixed.
// A release-specific note is needed only when the release's version is BELOW
// that (a backport, or <no-dsa> / <ignored> / <postponed> to say it stays
// unfixed), so a note can never contradict "installed >= the lineage fix".
// The later releases' entries carry exactly that lineage fix when they have
// no backport of their own (DEBIAN-CVE-2021-3449: Debian:12/13/14 all
// "fixed 1.1.1k-1", although bookworm ships 3.0.x).
//
// It is used only for a release at or below debianLastEndOfLife that no
// CVE-specific record of the package names any more, and reads only the
// CVE-specific records (DEBIAN-CVE-*), which follow the tracker.
//
// So the ONLY verdict drawn here is distro_fixed, and only when there is at
// least one later Debian release entry and EVERY later release entry closes
// its range at or below the installed version. Anything else — no later
// entry, one still affected or unfixed, one not evaluable — is no verdict:
// a later release's fix above the installed version says nothing about the
// installed release, which may have had its own lower backport. Older
// releases' entries are never used (their backports are below the lineage).
func laterReleaseVerdict(t distroTarget, recs []*distroRecord, ev model.DistroEvidence, cmp versionCmp) distroDecision {
	var rs []entryResult
	var used []distroEntry
	var ids, ecos []string
	for _, r := range recs {
		for _, e := range r.Entries {
			if !strings.HasPrefix(strings.ToLower(e.Ecosystem), "debian") {
				continue
			}
			n, ok := debianEcosystemMajor(e.Ecosystem)
			if !ok {
				// "Debian:sid" or anything else this code cannot order:
				// it may be a later release (Codex M70 R1 High-3).
				return distroDecision{reason: "undecidable"}
			}
			if n <= t.releaseMajor {
				continue
			}
			res := evalEntry(t.version, e, cmp)
			if res.state != entryFixed {
				return distroDecision{reason: "later_release_not_fixed_at_installed"}
			}
			rs = append(rs, res)
			used = append(used, e)
			ids = appendUnique(ids, r.ID)
			ecos = appendUnique(ecos, e.Ecosystem)
		}
	}
	if len(rs) == 0 {
		return distroDecision{reason: "release_not_listed"}
	}
	d := combineExact(rs, ids, ev, cmp)
	if d.verdict == verdictFixed && d.evidence.Fixed != "" {
		// The named version must be outside every deciding entry's affected
		// set (Codex M70 R10 Medium-3, as in decide).
		for _, e := range used {
			if !outsideAffectedSet(d.evidence.Fixed, e, cmp) {
				d.evidence.Fixed = ""
				break
			}
		}
	}
	if d.verdict != verdictFixed {
		return distroDecision{reason: "undecidable"}
	}
	sort.Strings(ecos)
	d.evidence.Basis = model.DistroBasisLaterReleases
	d.evidence.Ecosystems = ecos
	return d
}

// debianEcosystemMajor reads "Debian:12" (or "Debian:6.0") as 12 (6).
func debianEcosystemMajor(eco string) (int, bool) {
	rest, ok := strings.CutPrefix(eco, "Debian:")
	if !ok {
		return 0, false
	}
	// Canonical forms only (Codex M70 R3 High-3, R4 High-1): "N" with no
	// leading zero, or one of OSV's historical names.
	if n, ok := debianHistoricalEcosystems[rest]; ok {
		return n, true
	}
	major := rest
	if !isDigits(major) || major[0] == '0' || len(major) > 3 {
		return 0, false
	}
	n, err := strconv.Atoi(major)
	return n, err == nil && n > 0
}

// debianHistoricalEcosystems are the dotted Debian ecosystem names OSV uses.
var debianHistoricalEcosystems = map[string]int{"3.0": 3, "3.1": 3, "4.0": 4, "5.0": 5, "6.0": 6}

// versionCmp compares two versions of the target's scheme.
type versionCmp func(a, b string) (int, error)

// errEpochAmbiguous: exactly one side states a non-zero epoch and the other
// states none. dpkg and rpm both read a missing epoch as 0, and that is
// usually right — but it is also exactly how an SBOM (or a feed) that dropped
// the epoch looks, and the two readings give opposite answers. Undecidable.
var errEpochAmbiguous = fmt.Errorf("%w: only one side states a non-zero epoch", pkgversion.ErrInvalidVersion)

func (t distroTarget) comparator() versionCmp {
	switch t.scheme {
	case schemeDpkg:
		return func(a, b string) (int, error) {
			va, err := pkgversion.ParseDpkg(a)
			if err != nil {
				return 0, err
			}
			vb, err := pkgversion.ParseDpkg(b)
			if err != nil {
				return 0, err
			}
			if (va.Epoch > 0 && !vb.HasEpoch) || (vb.Epoch > 0 && !va.HasEpoch) {
				return 0, errEpochAmbiguous
			}
			return va.Compare(vb), nil
		}
	case schemeRPM:
		return func(a, b string) (int, error) {
			ea, err := pkgversion.ParseRPMEVR(a)
			if err != nil {
				return 0, err
			}
			eb, err := pkgversion.ParseRPMEVR(b)
			if err != nil {
				return 0, err
			}
			if (ea.Epoch > 0 && !eb.HasEpoch) || (eb.Epoch > 0 && !ea.HasEpoch) {
				return 0, errEpochAmbiguous
			}
			return ea.Compare(eb), nil
		}
	}
	return func(string, string) (int, error) { return 0, pkgversion.ErrInvalidVersion }
}

// distroRangeEvent is one range event with its kind.
type distroRangeEvent struct {
	kind    string // introduced | fixed | last_affected | limit
	version string
	zero    bool // introduced "0": before every version
}

// evalEntry evaluates one affected entry for the installed version.
//
// Only ECOSYSTEM ranges are read (the distro's own version syntax). The
// evaluation is OSV's (schema "Evaluation"): events sorted by version, the
// installed version is affected after an `introduced` at or below it and
// until a `fixed` at or below it. A `last_affected` or `limit` event, an
// installed version below the first `introduced`, any version the comparator
// refuses, or a range type other than ECOSYSTEM that is the entry's only
// range: undecidable. An installed version listed in `versions` is affected
// whatever the ranges say (the list is evidence of the affected side only;
// its absence proves nothing).
func evalEntry(installed string, e distroEntry, cmp versionCmp) entryResult {
	// The affected set is the union of every range and the versions list
	// (OSV schema). A member that cannot be evaluated does not hide an
	// affected one, but forbids "fixed" (Codex M70 R1 High-4).
	// OSV's versions list is exact string membership (schema "Evaluation";
	// Codex M70 R7 Medium-3): "1.0" is not "1.0-0" even though dpkg orders
	// them equal.
	listed, undecidable := false, false
	for _, v := range e.Versions {
		if v == installed {
			listed = true
		}
	}
	var affectedRanges []entryResult
	var closings []string
	for _, r := range e.Ranges {
		if r.Type != "ECOSYSTEM" {
			undecidable = true
			continue
		}
		switch res := evalRange(installed, r.Events, cmp); res.state {
		case entryAffected:
			affectedRanges = append(affectedRanges, res)
		case entryFixed:
			closings = append(closings, res.fix)
		default:
			undecidable = true
		}
	}
	if len(affectedRanges) > 0 {
		out := entryResult{state: entryAffected}
		for _, r := range affectedRanges {
			switch {
			case r.noFix:
				return entryResult{state: entryAffected, noFix: true}
			case out.fix == "":
				out.fix = r.fix
			default:
				c, err := cmp(r.fix, out.fix)
				if err != nil {
					out.fixUnknown = true
				} else if c > 0 {
					out.fix = r.fix
				}
			}
		}
		// The candidate fix must leave every member of the affected set
		// (Codex M70 R5 Medium-3): another range it re-enters, a range this
		// code cannot evaluate, or a listed version equal to it all make it
		// unknown.
		if !out.fixUnknown && (undecidable || !outsideAffectedSet(out.fix, e, cmp)) {
			out.fixUnknown = true
		}
		if out.fixUnknown {
			out.fix = ""
		}
		return out
	}
	if listed {
		// Listed as affected, but no range says up to where.
		return entryResult{state: entryAffected, fixUnknown: true}
	}
	if undecidable || len(closings) == 0 {
		return entryResult{state: entryUndecidable}
	}
	best := closings[0]
	for _, c := range closings[1:] {
		o, err := cmp(c, best)
		if err != nil {
			return entryResult{state: entryUndecidable}
		}
		if o > 0 {
			best = c
		}
	}
	return entryResult{state: entryFixed, fix: best}
}

// outsideAffectedSet: version v is in no ECOSYSTEM range of e and not in its
// versions list (each range evaluated at v says "fixed", i.e. closed at or
// below v).
func outsideAffectedSet(v string, e distroEntry, cmp versionCmp) bool {
	for _, x := range e.Versions {
		if x == v {
			return false
		}
	}
	for _, r := range e.Ranges {
		if r.Type != "ECOSYSTEM" {
			return false
		}
		if evalRange(v, r.Events, cmp).state != entryFixed {
			return false
		}
	}
	return true
}

// evalRange evaluates one ECOSYSTEM range.
func evalRange(installed string, raw []client.OSVEvent, cmp versionCmp) entryResult {
	var evs []distroRangeEvent
	for _, e := range raw {
		n := 0
		var ev distroRangeEvent
		if e.Introduced != "" {
			n++
			ev = distroRangeEvent{kind: "introduced", version: e.Introduced, zero: e.Introduced == "0"}
		}
		if e.Fixed != "" {
			n++
			ev = distroRangeEvent{kind: "fixed", version: e.Fixed}
		}
		if e.LastAffected != "" {
			n++
			ev = distroRangeEvent{kind: "last_affected", version: e.LastAffected}
		}
		if e.Limit != "" {
			n++
			ev = distroRangeEvent{kind: "limit", version: e.Limit}
		}
		if n != 1 {
			return entryResult{} // an event must carry exactly one field
		}
		if ev.kind == "last_affected" || ev.kind == "limit" {
			return entryResult{}
		}
		evs = append(evs, ev)
	}
	if len(evs) == 0 {
		return entryResult{}
	}
	// Sort by version; "0" sorts first. A comparison error anywhere makes the
	// range undecidable.
	var sortErr error
	less := func(a, b distroRangeEvent) int {
		switch {
		case a.zero && b.zero:
			return 0
		case a.zero:
			return -1
		case b.zero:
			return 1
		}
		c, err := cmp(a.version, b.version)
		if err != nil && sortErr == nil {
			sortErr = err
		}
		return c
	}
	sort.SliceStable(evs, func(i, j int) bool { return less(evs[i], evs[j]) < 0 })
	if sortErr != nil {
		return entryResult{}
	}
	affected, everIntroduced := false, false
	closing := ""
	for _, ev := range evs {
		var c int
		if ev.zero {
			c = 1 // installed > "0"
		} else {
			var err error
			c, err = cmp(installed, ev.version)
			if err != nil {
				return entryResult{}
			}
		}
		if c < 0 {
			continue // event above the installed version
		}
		switch ev.kind {
		case "introduced":
			affected, everIntroduced = true, true
		case "fixed":
			if affected {
				closing = ev.version
			}
			affected = false
		}
	}
	if affected {
		// The lowest fixed event above the installed version, if any.
		for _, ev := range evs {
			if ev.kind != "fixed" {
				continue
			}
			c, err := cmp(installed, ev.version)
			if err != nil {
				return entryResult{}
			}
			if c < 0 {
				return entryResult{state: entryAffected, fix: ev.version}
			}
		}
		// Open-ended ("introduced 0", no fix): OSV writes that both for
		// "vulnerable, no fix yet" and for undecided statuses (Debian
		// "undetermined", Ubuntu "needs-triage"), so it says nothing for
		// certain (Codex M70 R6 High-2). No verdict, and the NVD label stays.
		return entryResult{}
	}
	if !everIntroduced || closing == "" {
		// Below the first introduced, or closed by something other than a
		// fix we saw: not a "fixed" statement.
		return entryResult{}
	}
	return entryResult{state: entryFixed, fix: closing}
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
