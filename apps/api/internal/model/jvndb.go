package model

import (
	"regexp"
	"time"
)

// JVNDBAdvisoryRef is one JVN iPedia advisory attached to a CVE the catalogue
// already holds (migration 072). It is read from the JVNDB RSS feeds and is
// SUPPLEMENTARY: the RSS carries product-level CPEs without version ranges,
// so it never creates or removes a finding, and reading it is never reported
// as a JVN check.
type JVNDBAdvisoryRef struct {
	// ID is the JVNDB identifier, e.g. "JVNDB-2026-044393".
	ID string `json:"id"`
	// Title is the advisory's Japanese title as published by JVN iPedia.
	Title string `json:"title"`
	// URL is the canonical JVN iPedia page of the advisory, derived from ID
	// (JVNDBAdvisoryURL), never taken from the feed.
	URL string `json:"url"`
	// Published / Modified are dcterms:issued / dcterms:modified of the RSS
	// item; omitted when the feed carried none (or an unparsable one).
	Published *time.Time `json:"published,omitempty"`
	Modified  *time.Time `json:"modified,omitempty"`
}

// jvndbIDPattern is the JVNDB identifier grammar the feed uses and migration
// 072's CHECK constraint enforces.
var jvndbIDPattern = regexp.MustCompile(`^JVNDB-([0-9]{4})-[0-9]{6,12}$`)

// ValidJVNDBID reports whether id is a well-formed JVNDB identifier.
func ValidJVNDBID(id string) bool {
	return jvndbIDPattern.MatchString(id)
}

// JVNDBAdvisoryURL returns the canonical JVN iPedia (Japanese) page of a JVNDB
// id, or "" for a malformed id. The page lives under the id's year:
// https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-044393.html.
func JVNDBAdvisoryURL(id string) string {
	m := jvndbIDPattern.FindStringSubmatch(id)
	if m == nil {
		return ""
	}
	return "https://jvndb.jvn.jp/ja/contents/" + m[1] + "/" + id + ".html"
}
