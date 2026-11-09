package model

import "time"

// DistroEvidence is what a distro label (MatchDistroAffected /
// MatchDistroUnfixed / MatchDistroFixed, M70) stores in
// component_vulnerabilities.match_evidence and what the vulnerability list
// returns as match_evidence. It is the reviewer's evidence: where the distro's
// statement came from and which versions it compared.
type DistroEvidence struct {
	// Source is the data source: "osv" (OSV.dev's distro ecosystems).
	Source string `json:"source"`
	// SourceURL is the endpoint the data came from (SBOMHUB_OSV_URL or
	// OSV's public API). Revisions are compared only within one endpoint.
	SourceURL string `json:"source_url,omitempty"`
	// Status is the distro's statement about the installed version:
	// "affected" (a fix exists above it), "unfixed" (no fix released),
	// "fixed" (installed >= the fixed version).
	Status string `json:"status"`
	// Basis is "release" when the data names the installed release itself,
	// or "later_releases" when it does not (an end-of-life Debian release,
	// dropped from the data) and every LATER Debian release the record names
	// is fixed at or below the installed version. Debian's own tracker treats
	// a release without a release-specific note as fixed at the unstable fix
	// version; "later_releases" applies that rule and says so. It is only
	// ever used for "fixed".
	Basis string `json:"basis"`
	// Release is the OSV ecosystem of the installed release ("Debian:11",
	// "Ubuntu:22.04:LTS", "AlmaLinux:9").
	Release string `json:"release"`
	// Ecosystems lists the releases whose data decided a "later_releases"
	// verdict.
	Ecosystems []string `json:"ecosystems,omitempty"`
	// Package is the distro package the data is about (the SOURCE package
	// for Debian / Ubuntu, the binary rpm for AlmaLinux / Rocky Linux).
	Package string `json:"package"`
	// Installed is the installed version as compared (distro syntax).
	Installed string `json:"installed"`
	// Fixed is the decisive fixed version: the version to upgrade to for
	// "affected", the version already reached for "fixed"; empty for
	// "unfixed".
	Fixed string `json:"fixed,omitempty"`
	// Records are the OSV record ids the verdict rests on.
	Records []string `json:"records"`
	// FetchedAt is when the distro data was fetched from the source.
	FetchedAt time.Time `json:"fetched_at"`
	// DataModified is the data's own revision: the newest `modified` of the
	// package's OSV records, as fixed-width UTC RFC 3339 (sorts as text). A
	// relabel never replaces evidence of a newer revision with an older one.
	DataModified string `json:"data_modified,omitempty"`
}

// Distro evidence vocabulary.
const (
	DistroSourceOSV          = "osv"
	DistroStatusAffected     = "affected"
	DistroStatusUnfixed      = "unfixed"
	DistroStatusFixed        = "fixed"
	DistroBasisRelease       = "release"
	DistroBasisLaterReleases = "later_releases"
)
