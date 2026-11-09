package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
)

// Package-level OSV query (M70): every OSV record for one (ecosystem, package),
// all pages. The distro step of a scan (service/distro_scan.go) uses it to read
// a distro's own fixed versions.
//
// Measured 2026-11-09 against the live api.osv.dev (no key, no rate limit
// published — the API documentation says "there are no limits on the API"):
//
//	Debian "openssl"            390 records,   799 KB, 1.9 s, one page
//	Debian "glibc"              189 records,   390 KB, 1.2 s, one page
//	Debian "linux"            3,000 records, 7.1 MB, 6.9 s, FIRST page of several
//	Debian "linux-signed-amd64"   0 records (`{}`), 0.35 s
//	Ubuntu:22.04:LTS "openssl"  100 records,   1.7 MB, 1.8 s
//	AlmaLinux:9 "openssl"        17 records,    60 KB, 0.5 s
//
// OSV pages a package query when it has more than 1,000 records or runs for
// more than 20 s; a page may even carry only a next_page_token. Every page is
// read; a walk that hits maxPages is an ERROR (ErrOSVQueryTruncated), not a
// short answer, because an unread page could hold the record that says the
// installed version is affected.

// maxOSVQueryPageBytes bounds one page. The largest measured page (Debian
// linux, 3,000 records) is 7.1 MB; OSV's own HTTP/1.1 response cap is 32 MiB.
const maxOSVQueryPageBytes = 32 << 20

// ErrOSVOffline is returned by QueryPackage in offline mode. Unlike
// GetVulnerability's (nil, nil), a package query never answers "no records"
// when it did not ask: an empty answer would read as "the distro has no data".
var ErrOSVOffline = errors.New("osv: offline mode, no query made")

// ErrOSVQueryTruncated: the walk hit its page budget with a next_page_token
// still pending.
var ErrOSVQueryTruncated = errors.New("osv: package query has more pages than the page budget")

// OSVPackageRecord is the part of an OSV record the distro step reads.
type OSVPackageRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Modified string   `json:"modified"`
	// Withdrawn is set (an RFC 3339 time) when the record was retracted.
	Withdrawn string        `json:"withdrawn"`
	Affected  []OSVAffected `json:"affected"`
}

// OSVPackageQueryResult is the whole answer of one package query.
type OSVPackageQueryResult struct {
	Records []OSVPackageRecord
	// Pages is how many HTTP requests the walk made (failed ones included).
	Pages int
}

type osvPackageQueryRequest struct {
	Package   OSVPackage `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackageQueryResponse struct {
	Vulns         []OSVPackageRecord `json:"vulns"`
	NextPageToken string             `json:"next_page_token"`
}

// GetRecordState reads ONE record by id (GET /vulns/{id}), which, unlike the
// package query, also returns WITHDRAWN records (Codex M70 R24 High-1): its
// modified and withdrawn times. A 404 is ErrOSVNotFound.
func (c *OSVClient) GetRecordState(ctx context.Context, id string) (OSVRecordState, error) {
	var none OSVRecordState
	if c.offline {
		return none, ErrOSVOffline
	}
	if !canonicalOSVID(id) {
		return none, fmt.Errorf("osv: %q is not an OSV id", id)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/vulns/"+neturl.PathEscape(id), nil)
	if err != nil {
		return none, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return none, fmt.Errorf("osv: get record: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return none, ErrOSVNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return none, fmt.Errorf("osv: get record returned status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOSVResponseBytes+1))
	if err != nil || len(raw) > maxOSVResponseBytes {
		return none, fmt.Errorf("osv: read record: bad body")
	}
	var r struct {
		ID        string          `json:"id"`
		Modified  string          `json:"modified"`
		Withdrawn string          `json:"withdrawn"`
		Affected  json.RawMessage `json:"affected"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.ID != id {
		return none, fmt.Errorf("osv: record %q: not the record asked for", id)
	}
	// An active record must carry a well-formed affected array, every
	// element validated as in a package query (Codex M70 R33 Medium-3): a
	// partial answer must not read as "no longer names the package".
	var affected []OSVAffected
	if r.Withdrawn == "" {
		if !bytes.HasPrefix(bytes.TrimSpace(r.Affected), []byte("[")) || json.Unmarshal(r.Affected, &affected) != nil {
			return none, fmt.Errorf("osv: record %q has no affected array", id)
		}
		for i, a := range affected {
			if err := validateAffected(a); err != nil {
				return none, fmt.Errorf("osv: record %q affected[%d]: %w", id, i, err)
			}
		}
	}
	if r.Modified == "" { // required by the schema (Codex M70 R31 Medium-3)
		return none, fmt.Errorf("osv: record %q has no modified time", id)
	}
	latest := time.Now().Add(maxOSVTimestampSkew)
	for _, ts := range []string{r.Modified, r.Withdrawn} {
		if ts == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || t.After(latest) {
			return none, fmt.Errorf("osv: record %q has a malformed or future time", id)
		}
	}
	st := OSVRecordState{Modified: r.Modified, Withdrawn: r.Withdrawn}
	for _, a := range affected {
		if a.Package.Name == "" && a.Package.Ecosystem == "" {
			continue // a package-less (GIT) entry
		}
		st.Packages = append(st.Packages, OSVPackage{Name: a.Package.Name, Ecosystem: a.Package.Ecosystem})
	}
	return st, nil
}

// OSVRecordState is what a lookup by id tells about one record: its times
// and the packages it names now (Codex M70 R32 Medium-2: a record edited to
// no longer name a package leaves the package's query without withdrawal).
type OSVRecordState struct {
	Modified, Withdrawn string
	Packages            []OSVPackage
}

// Names reports whether the record names package name in ecosystem family
// (the queried "Debian" covers "Debian:11"...).
func (s OSVRecordState) Names(family, name string) bool {
	for _, p := range s.Packages {
		if p.Name == name && (p.Ecosystem == family || strings.HasPrefix(p.Ecosystem, family+":")) {
			return true
		}
	}
	return false
}

// parseStrictPurl parses a package URL fully (Codex M70 R27 High-1):
// pkg:type/namespace.../name[@version][?qualifiers][#subpath]. Every part
// must be well formed: valid percent encoding, no empty path segment, a
// non-empty version after "@", qualifiers as key=value with lower-case keys
// and non-empty values, no empty subpath segment. It returns the decoded
// path segments, type lower-cased, namespaces lower-cased (deb / rpm
// namespaces are case-insensitive vendors), the name as is.
func parseStrictPurl(purl string) (segs []string, quals map[string]string, err error) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return nil, nil, fmt.Errorf("not a purl")
	}
	quals = map[string]string{}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		// Not trimmed (Codex M70 R32 Low-5): a leading / trailing / doubled
		// slash is an empty segment.
		for _, seg := range strings.Split(rest[i+1:], "/") {
			if v, err := neturl.PathUnescape(seg); err != nil || v == "" || v == "." || v == ".." || strings.Contains(v, "/") {
				return nil, nil, fmt.Errorf("bad subpath")
			}
		}
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		seen := map[string]bool{}
		for _, kv := range strings.Split(rest[i+1:], "&") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" || k != strings.ToLower(k) || seen[k] {
				return nil, nil, fmt.Errorf("bad qualifier %q", kv)
			}
			seen[k] = true
			for _, c := range k {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' {
					return nil, nil, fmt.Errorf("bad qualifier key %q", k)
				}
			}
			dv, err := neturl.PathUnescape(v)
			if err != nil || dv == "" {
				return nil, nil, fmt.Errorf("bad qualifier value for %q", k)
			}
			quals[k] = dv
		}
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 && !strings.Contains(rest[i:], "/") {
		if v, err := neturl.PathUnescape(rest[i+1:]); err != nil || v == "" {
			return nil, nil, fmt.Errorf("empty or malformed version")
		}
		rest = rest[:i]
	}
	raw := strings.Split(rest, "/")
	if len(raw) < 2 {
		return nil, nil, fmt.Errorf("no name")
	}
	out := make([]string, len(raw))
	for i, seg := range raw {
		v, err := neturl.PathUnescape(seg)
		if err != nil || v == "" {
			return nil, nil, fmt.Errorf("bad path segment %d", i)
		}
		if i < len(raw)-1 {
			v = strings.ToLower(v)
		}
		out[i] = v
	}
	return out, quals, nil
}

// Release codenames, for checking a purl's distro qualifier against the
// entry's ecosystem (Codex M70 R31 High-2). A release missing here (a new
// one) is accepted with any codename that is not another known release's.
var (
	debianCodenames = map[string]string{"3.0": "woody", "3.1": "sarge", "4.0": "etch", "5.0": "lenny", "6.0": "squeeze",
		"7": "wheezy", "8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie",
		"14": "forky", "15": "duke"}
	ubuntuCodenames = map[string]string{"12.04": "precise", "14.04": "trusty", "16.04": "xenial", "18.04": "bionic",
		"20.04": "focal", "22.04": "jammy", "22.10": "kinetic", "23.04": "lunar", "23.10": "mantic", "24.04": "noble",
		"24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute", "26.10": "stonking"}
)

// purlQualifiersAgree: on a Debian / Ubuntu entry, an arch qualifier names
// the source package, and a distro qualifier names the entry's release (its
// codename is one "/" part of Ubuntu Pro streams such as "esm-apps/xenial"
// or "trusty/esm").
func purlQualifiersAgree(ecosystem, typ string, quals map[string]string) error {
	if typ == "rpm" {
		// An architecture-specific rpm entry is not a statement about the
		// component's architecture, which is not compared (Codex M70 R33
		// High-2): refused until it is.
		if a, ok := quals["arch"]; ok && a != "src" && a != "noarch" {
			return fmt.Errorf("arch=%s: architecture-specific rpm entries are not supported", a)
		}
		return rpmDistroAgrees(ecosystem, quals)
	}
	if typ != "deb" {
		return nil
	}
	if a, ok := quals["arch"]; ok && a != "source" {
		return fmt.Errorf("arch=%s: not the source package", a)
	}
	distro, ok := quals["distro"]
	if !ok {
		return nil
	}
	parts := strings.Split(ecosystem, ":")
	var table map[string]string
	release := ""
	switch parts[0] {
	case "Debian":
		table = debianCodenames
		if len(parts) == 2 {
			release = parts[1]
		}
		if r, ok := strings.CutPrefix(distro, "debian-"); ok && r == release {
			return nil
		}
	case "Ubuntu":
		table = ubuntuCodenames
		for _, p := range parts[1:] {
			if len(p) == 5 && p[2] == '.' {
				release = p
			}
		}
	default:
		return nil
	}
	// Ubuntu Pro streams carry the codename as one "/" part
	// ("esm-apps/xenial", "trusty/esm"); Debian's is the codename alone.
	words := []string{distro}
	if parts[0] == "Ubuntu" {
		words = strings.Split(distro, "/")
	}
	want, known := table[release]
	named := false
	for _, w := range words {
		if known && w == want {
			named = true
			continue
		}
		for r, name := range table {
			if name == w && r != release {
				return fmt.Errorf("distro=%s names release %s, not %s", distro, r, ecosystem)
			}
		}
	}
	if known && !named {
		return fmt.Errorf("distro=%s does not name %s (%s)", distro, ecosystem, want)
	}
	return nil
}

// rpmDistroAgrees: on an AlmaLinux / Rocky Linux entry, a purl distro
// qualifier ("almalinux-9", "rocky-linux-9.3", "el9") names the entry's
// major release (Codex M70 R32 High-1). A qualifier without a release
// number, or naming another family, is refused.
func rpmDistroAgrees(ecosystem string, quals map[string]string) error {
	distro, ok := quals["distro"]
	if !ok {
		return nil
	}
	family, release, _ := strings.Cut(ecosystem, ":")
	var prefixes []string
	switch family {
	case "AlmaLinux":
		prefixes = []string{"almalinux-", "alma-", "el"}
	case "Rocky Linux":
		prefixes = []string{"rocky-linux-", "rocky-", "el"}
	default:
		return nil
	}
	major, _, _ := strings.Cut(release, ".")
	d := strings.ToLower(distro)
	for _, p := range prefixes {
		rest, ok := strings.CutPrefix(d, p)
		if !ok {
			continue
		}
		got, _, _ := strings.Cut(rest, ".")
		if got != "" && got == major {
			return nil
		}
		return fmt.Errorf("distro=%s does not name %s", distro, ecosystem)
	}
	return fmt.Errorf("distro=%s is not a %s release", distro, family)
}

// validateUbuntuBinaries checks Ubuntu's ecosystem_specific.binaries, when
// present: a list of objects each with a non-empty, bounded binary_name
// (Codex M70 R27 Medium-4: a malformed list must fail, not read as absent).
func validateUbuntuBinaries(es map[string]interface{}) error {
	raw, present := es["binaries"]
	if !present {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return fmt.Errorf("ecosystem_specific.binaries is not a list")
	}
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("ecosystem_specific.binaries[%d] is not an object", i)
		}
		name, ok := m["binary_name"].(string)
		if !ok || name == "" || len(name) > MaxOSVFieldBytes || !canonicalToken(name) { // R33 Medium-4
			return fmt.Errorf("ecosystem_specific.binaries[%d] has no usable binary_name", i)
		}
	}
	return nil
}

// PackageQueryLimits bound one package query.
type PackageQueryLimits struct {
	// MaxPages is the most requests the walk may make.
	MaxPages int
	// MaxTotalBytes bounds the response bytes of the whole walk (every page
	// together), so a package with a huge history cannot hold an unbounded
	// amount of memory (Codex M70 R2 High-3). 0 means maxOSVQueryPageBytes.
	MaxTotalBytes int64
}

// QueryPackage returns every OSV record for (ecosystem, name), following
// next_page_token for at most maxPages requests. before is called before every
// request (the caller's pacing); an error from it ends the walk with that
// error. Any HTTP status other than 200, an undecodable or oversized body, or a
// walk longer than maxPages is an error: there is no partial answer.
func (c *OSVClient) QueryPackage(ctx context.Context, ecosystem, name string, maxPages int, before func(context.Context) error) (OSVPackageQueryResult, error) {
	var out OSVPackageQueryResult
	pages, err := c.QueryPackageEach(ctx, ecosystem, name, PackageQueryLimits{MaxPages: maxPages, MaxTotalBytes: int64(maxPages) * maxOSVQueryPageBytes},
		before, func(recs []OSVPackageRecord) error {
			out.Records = append(out.Records, recs...)
			return nil
		})
	out.Pages = pages
	return out, err
}

// QueryPackageEach is QueryPackage that hands each page's records to onPage
// as it arrives (so the caller can reduce them at once) instead of holding the
// whole answer. An error from onPage ends the walk with it. pages counts the
// requests made, failed ones included. The walk is an error — never a short
// answer — when it would exceed lim.
func (c *OSVClient) QueryPackageEach(ctx context.Context, ecosystem, name string, lim PackageQueryLimits,
	before func(context.Context) error, onPage func([]OSVPackageRecord) error) (pages int, err error) {
	if c.offline {
		return 0, ErrOSVOffline
	}
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("osv: package query needs an ecosystem and a name")
	}
	if lim.MaxPages < 1 {
		lim.MaxPages = 1
	}
	if lim.MaxTotalBytes <= 0 {
		lim.MaxTotalBytes = maxOSVQueryPageBytes
	}
	token := ""
	seen := map[string]bool{}
	ids := map[string]bool{}
	var spent int64
	for {
		if pages >= lim.MaxPages {
			return pages, fmt.Errorf("%w (%d pages, %s %q)", ErrOSVQueryTruncated, lim.MaxPages, ecosystem, name)
		}
		if before != nil {
			if err := before(ctx); err != nil {
				return pages, err
			}
		}
		pages++
		remaining := lim.MaxTotalBytes - spent
		page, n, err := c.queryPackagePage(ctx, osvPackageQueryRequest{
			Package:   OSVPackage{Name: name, Ecosystem: ecosystem},
			PageToken: token,
		}, remaining)
		spent += n
		if err != nil {
			return pages, err
		}
		// An id appears once in a walk (OSV: the later-modified entry of an
		// id is authoritative, so two of them mean the walk straddled an
		// update). Codex M70 R21 High-2.
		for _, r := range page.Vulns {
			if ids[r.ID] {
				return pages, fmt.Errorf("osv: package query returned record %q twice", r.ID)
			}
			ids[r.ID] = true
		}
		if err := onPage(page.Vulns); err != nil {
			return pages, err
		}
		if page.NextPageToken == "" {
			return pages, nil
		}
		if seen[page.NextPageToken] {
			// A server handing back a token it already gave would loop until
			// the budget; say what it is instead.
			return pages, fmt.Errorf("osv: package query for %s %q repeated a page token", ecosystem, name)
		}
		seen[page.NextPageToken] = true
		token = page.NextPageToken
	}
}

// validatePackageRecords refuses a structurally partial answer (Codex M70
// R10 High-1, R11 High-2). Every record needs an id. A withdrawn record needs
// an RFC 3339 `withdrawn` and nothing else. An active record needs an RFC
// 3339 `modified`, an `affected` ARRAY (present, not null) and at least one
// entry for the queried package in the queried ecosystem (exactly, or a
// release of it: "Debian" -> "Debian:11"). A record the caller would
// silently drop could be the one that says "affected".
// maxOSVTimestampSkew is how far in the future an OSV timestamp may lie: a
// later one would hold the revision guard forever (Codex M70 R14 High-1).
const maxOSVTimestampSkew = 24 * time.Hour

func validatePackageRecords(raw []byte, q OSVPackage) error {
	latest := time.Now().Add(maxOSVTimestampSkew)
	validTime := func(s string) bool {
		ts, err := time.Parse(time.RFC3339Nano, s)
		return err == nil && !ts.After(latest)
	}
	var env struct {
		Vulns []json.RawMessage `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("osv: decode package query response: %w", err)
	}
	for i, rv := range env.Vulns {
		var r struct {
			ID        string           `json:"id"`
			Aliases   []string         `json:"aliases"`
			Upstream  []string         `json:"upstream"`
			Modified  string           `json:"modified"`
			Withdrawn string           `json:"withdrawn"`
			Affected  *json.RawMessage `json:"affected"`
		}
		if err := json.Unmarshal(rv, &r); err != nil {
			return fmt.Errorf("osv: package query record %d: %w", i, err)
		}
		if !canonicalOSVID(r.ID) {
			return fmt.Errorf("osv: package query record %d has no canonical id", i)
		}
		// Every identity the caller matches on is canonical: a CVE-like id,
		// alias or upstream entry spelt otherwise would be silently dropped
		// later (Codex M70 R19 High-2).
		if err := checkCVELike(r.ID); err != nil {
			return fmt.Errorf("osv: package query record %q: %w", r.ID, err)
		}
		for _, a := range append(append([]string(nil), r.Aliases...), r.Upstream...) {
			if !canonicalOSVID(a) {
				return fmt.Errorf("osv: package query record %q has a non-canonical alias %q", r.ID, a)
			}
			if err := checkCVELike(a); err != nil {
				return fmt.Errorf("osv: package query record %q: %w", r.ID, err)
			}
		}
		if r.Modified != "" && !validTime(r.Modified) {
			return fmt.Errorf("osv: package query record %q has a malformed or future modified", r.ID)
		}
		if r.Withdrawn != "" {
			if !validTime(r.Withdrawn) {
				return fmt.Errorf("osv: package query record %q has a malformed or future withdrawn", r.ID)
			}
			continue
		}
		if r.Modified == "" {
			return fmt.Errorf("osv: package query record %q has no valid modified", r.ID)
		}
		if r.Affected == nil || !bytes.HasPrefix(bytes.TrimSpace(*r.Affected), []byte("[")) {
			return fmt.Errorf("osv: package query record %q has no affected array", r.ID)
		}
		var affected []OSVAffected
		if err := json.Unmarshal(*r.Affected, &affected); err != nil {
			return fmt.Errorf("osv: package query record %q: %w", r.ID, err)
		}
		// Every element must be complete: a truncated one dropped later
		// could have been another range for the same package (Codex M70
		// R15 High-1).
		for j, a := range affected {
			if err := validateAffected(a); err != nil {
				return fmt.Errorf("osv: package query record %q affected[%d]: %w", r.ID, j, err)
			}
		}
		named := false
		for _, a := range affected {
			if a.Package.Name == q.Name && (a.Package.Ecosystem == q.Ecosystem || strings.HasPrefix(a.Package.Ecosystem, q.Ecosystem+":")) {
				named = true
				break
			}
		}
		if !named {
			return fmt.Errorf("osv: package query record %q names no %s %q entry", r.ID, q.Ecosystem, q.Name)
		}
	}
	return nil
}

// validateAffected: a package with a name and an ecosystem; every range with
// a type and at least one event; every event with exactly one field; no
// empty listed version.
// MaxOSVFieldBytes bounds every identity / version string of an answer
// (names, ecosystems, ids, versions, binaries): far above any real value,
// and what keeps encoded evidence small (Codex M70 R22 High-3).
const MaxOSVFieldBytes = 256

func validateAffected(a OSVAffected) error {
	if a.Package.Name == "" && a.Package.Ecosystem == "" && a.Package.Purl == "" {
		// OSV's package-less entry for supplementary GIT ranges (Codex M70
		// R23 Medium-4): valid only with GIT ranges, and ignored by the
		// distro step (it matches the queried package only).
		if len(a.Ranges) == 0 {
			return fmt.Errorf("package-less entry without GIT ranges")
		}
		for i, v := range a.Versions { // tag names (Codex M70 R24 Medium-2)
			if !canonicalToken(v) {
				return fmt.Errorf("package-less entry versions[%d] %q not canonical", i, v)
			}
		}
		for i, r := range a.Ranges {
			if r.Type != "GIT" || len(r.Events) == 0 {
				return fmt.Errorf("package-less entry range %d is not a GIT range", i)
			}
		}
		return nil
	}
	if a.Package.Purl != "" {
		if err := purlAgrees(a.Package); err != nil {
			return err
		}
	}
	if strings.HasPrefix(a.Package.Ecosystem, "Ubuntu") {
		if err := validateUbuntuBinaries(a.EcosystemSpecific); err != nil {
			return err
		}
	}
	// Canonical strings (Codex M70 R18 High-2): a name or a version is
	// printable ASCII without any whitespace; an ecosystem may have inner
	// spaces ("Rocky Linux:9") but none at either end. Anything else would
	// be dropped or normalised later instead of failing.
	if !canonicalToken(a.Package.Name) || !canonicalEcosystem(a.Package.Ecosystem) {
		return fmt.Errorf("package name %q / ecosystem %q not canonical", a.Package.Name, a.Package.Ecosystem)
	}
	for i, r := range a.Ranges {
		if strings.TrimSpace(r.Type) == "" || len(r.Events) == 0 {
			return fmt.Errorf("range %d without a type or events", i)
		}
		for j, e := range r.Events {
			n := 0
			for _, f := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
				if f != "" {
					if !canonicalToken(f) {
						return fmt.Errorf("range %d event %d version %q not canonical", i, j, f)
					}
					n++
				}
			}
			if n != 1 {
				return fmt.Errorf("range %d event %d has %d fields", i, j, n)
			}
		}
	}
	for i, v := range a.Versions {
		if !canonicalToken(v) {
			return fmt.Errorf("versions[%d] %q not canonical", i, v)
		}
	}
	return nil
}

// checkCVELike: an identity that mentions a CVE (case-insensitively "CVE-"
// at the start or after "DEBIAN-" / "UBUNTU-") must be exactly CVE-YYYY-NNNN…
// with an upper-case, exact prefix.
func checkCVELike(id string) error {
	up := strings.ToUpper(id)
	if !strings.Contains(up, "CVE-") {
		return nil
	}
	// Exactly one of "CVE-…", "DEBIAN-CVE-…", "UBUNTU-CVE-…", upper-case and
	// canonical; anything else naming a CVE ("DEBIAN-UBUNTU-CVE-…",
	// "cve-…") is malformed (Codex M70 R19 High-2, R24 Medium-3).
	rest := up
	if r, ok := strings.CutPrefix(up, "DEBIAN-"); ok {
		rest = r
	} else if r, ok := strings.CutPrefix(up, "UBUNTU-"); ok {
		rest = r
	}
	if id != up || !canonicalCVE(rest) {
		return fmt.Errorf("non-canonical CVE identity %q", id)
	}
	return nil
}

func canonicalCVE(s string) bool {
	rest, ok := strings.CutPrefix(s, "CVE-")
	if !ok {
		return false
	}
	y, n, ok := strings.Cut(rest, "-")
	if !ok || len(y) != 4 || len(n) < 4 {
		return false
	}
	for _, c := range y + n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// purlAgrees: an affected package's purl names the same package (name) and,
// for the distro ecosystems this build reads, the same packaging type
// (Codex M70 R22 High-2).
func purlAgrees(p OSVPackage) error {
	segs, quals, err := parseStrictPurl(p.Purl)
	if err != nil {
		return fmt.Errorf("package purl %q: %w", p.Purl, err)
	}
	if err := purlQualifiersAgree(p.Ecosystem, segs[0], quals); err != nil {
		return fmt.Errorf("package purl %q: %w", p.Purl, err)
	}
	typ := segs[0]
	if segs[len(segs)-1] != p.Name {
		return fmt.Errorf("package purl %q does not name %q", p.Purl, p.Name)
	}
	want, ns := "", []string(nil)
	switch {
	case strings.HasPrefix(p.Ecosystem, "Debian"):
		want, ns = "deb", []string{"debian"}
	case strings.HasPrefix(p.Ecosystem, "Ubuntu"):
		want, ns = "deb", []string{"ubuntu"}
	case strings.HasPrefix(p.Ecosystem, "AlmaLinux"):
		want, ns = "rpm", []string{"almalinux"}
	case strings.HasPrefix(p.Ecosystem, "Rocky Linux"):
		want, ns = "rpm", []string{"rocky", "rocky-linux"}
	}
	if want != "" && typ != want {
		return fmt.Errorf("package purl %q is not a %s package", p.Purl, want)
	}
	// The namespace is the distro (vendor) of the ecosystem (Codex M70 R23
	// High-3).
	if ns != nil {
		got := ""
		if len(segs) == 3 {
			got = segs[1]
		}
		okNS := false
		for _, n := range ns {
			okNS = okNS || got == n
		}
		if !okNS {
			return fmt.Errorf("package purl %q does not name the %s distro", p.Purl, p.Ecosystem)
		}
	}
	return nil
}

// canonicalOSVID: OSV's id character set, [A-Za-z0-9:_.-]+ (Codex M70 R21
// High-3).
func canonicalOSVID(s string) bool {
	if s == "" || len(s) > MaxOSVFieldBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' || c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// canonicalToken: non-empty printable ASCII without whitespace.
func canonicalToken(s string) bool {
	if s == "" || len(s) > MaxOSVFieldBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// canonicalEcosystem: non-empty printable ASCII, inner single spaces only.
func canonicalEcosystem(s string) bool {
	if s == "" || len(s) > MaxOSVFieldBytes || s[0] == ' ' || s[len(s)-1] == ' ' || strings.Contains(s, "  ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// queryPackagePage fetches one page, reading at most min(budget, one page's
// cap) bytes; n is the bytes read.
func (c *OSVClient) queryPackagePage(ctx context.Context, q osvPackageQueryRequest, budget int64) (page osvPackageQueryResponse, n int64, err error) {
	limit := int64(maxOSVQueryPageBytes)
	if budget < limit {
		limit = budget
	}
	if limit <= 0 {
		return page, 0, fmt.Errorf("%w: byte budget spent", ErrOSVQueryTruncated)
	}
	body, err := json.Marshal(q)
	if err != nil {
		return page, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return page, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return page, 0, fmt.Errorf("osv: package query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return page, 0, fmt.Errorf("osv: package query returned status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	n = int64(len(raw))
	if err != nil {
		return page, n, fmt.Errorf("osv: read package query response: %w", err)
	}
	if n > limit {
		return page, n, fmt.Errorf("%w: response exceeds the remaining %d-byte budget", ErrOSVQueryTruncated, limit)
	}
	// The body must be a JSON object: `{}` (no records) or {"vulns": [...]}.
	// Anything else — an HTML error page from a proxy, `null`, an array — is
	// not an answer.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return page, n, fmt.Errorf("osv: package query response is not a JSON object")
	}
	// The answer is `{}` (no records), or carries a `vulns` ARRAY and/or a
	// non-empty next_page_token. Any other object (`{"error":...}`,
	// `{"vulns":null}`) is not an answer (Codex M70 R6 Medium-3).
	var env map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return page, n, fmt.Errorf("osv: decode package query response: %w", err)
	}
	if len(env) == 0 && q.PageToken != "" {
		// `{}` is "no records" only as the FIRST page; after a token it is a
		// lost or rejected continuation (Codex M70 R15 High-2).
		return page, n, fmt.Errorf("osv: package query continuation page is empty")
	}
	if len(env) > 0 {
		vulnsRaw, hasVulns := env["vulns"]
		if hasVulns && !bytes.HasPrefix(bytes.TrimSpace(vulnsRaw), []byte("[")) {
			return page, n, fmt.Errorf("osv: package query response has a non-array vulns")
		}
		var tok string
		if raw, ok := env["next_page_token"]; ok {
			// A JSON string, when present (null would read as "last page";
			// Codex M70 R23 High-2).
			if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte(`"`)) || json.Unmarshal(raw, &tok) != nil {
				return page, n, fmt.Errorf("osv: package query response has a bad next_page_token")
			}
		}
		if !hasVulns && tok == "" {
			return page, n, fmt.Errorf("osv: package query response carries neither vulns nor a page token")
		}
	}
	if err := json.Unmarshal(trimmed, &page); err != nil {
		return page, n, fmt.Errorf("osv: decode package query response: %w", err)
	}
	if q.PageToken != "" && len(page.Vulns) == 0 && page.NextPageToken == "" {
		// A continuation with no records and no further token: the walk was
		// cut, not finished (Codex M70 R16 High-1). A token-only
		// intermediate page (records later) is fine.
		return page, n, fmt.Errorf("osv: package query continuation page is empty")
	}
	if err := validatePackageRecords(trimmed, q.Package); err != nil {
		return osvPackageQueryResponse{}, n, err
	}
	return page, n, nil
}
