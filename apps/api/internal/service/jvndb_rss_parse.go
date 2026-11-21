package service

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// JVNDB RSS (JVNRSS 2.0, RSS 1.0 / RDF) parsing. The feeds are documented at
// https://jvndb.jvn.jp/ja/feed/ ("JVNDBRSS"); each <item> carries
//
//	<sec:identifier>JVNDB-2026-044393</sec:identifier>
//	<title>（日本語のタイトル）</title>
//	<sec:references source="CVE" id="CVE-2026-114938">…</sec:references>
//	<sec:cpe version="2.2" vendor=… product=…>cpe:/a:oracle:openjdk</sec:cpe>
//	<dcterms:issued> / <dcterms:modified> / <dc:date>
//
// Only the id, the title, the dates and the CVE references are kept. The CPEs
// carry no version ranges and are not used; the description is not stored.

const (
	nsRDF    = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	nsRSS10  = "http://purl.org/rss/1.0/"
	nsJVNSec = "http://jvn.jp/rss/mod_sec/"
	nsDC     = "http://purl.org/dc/elements/1.1/"
	nsDCTerm = "http://purl.org/dc/terms/"

	// jvndbMaxItemsPerFeed bounds one feed. The largest feed measured (the
	// 2026 year feed, 99 MB on 2026-11-21) holds well under this.
	jvndbMaxItemsPerFeed = 250000
	// jvndbMaxTitleRunes matches migration 072's CHECK.
	jvndbMaxTitleRunes = 1000
	// jvndbMaxCVEsPerItem bounds the CVE references kept for one advisory.
	jvndbMaxCVEsPerItem = 500
)

var jvndbCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// ErrJVNDBFeedMalformed marks a feed whose document structure is not a
// JVNDB RSS feed (not XML, wrong root, DOCTYPE, wrong encoding, too many
// items). Individual malformed items are not this error: they are skipped
// and counted.
var ErrJVNDBFeedMalformed = errors.New("jvndb rss: malformed feed")

type jvndbRSSRef struct {
	Source string `xml:"source,attr"`
	ID     string `xml:"id,attr"`
}

type jvndbRSSItem struct {
	Title      string        `xml:"http://purl.org/rss/1.0/ title"`
	Identifier string        `xml:"http://jvn.jp/rss/mod_sec/ identifier"`
	References []jvndbRSSRef `xml:"http://jvn.jp/rss/mod_sec/ references"`
	Date       string        `xml:"http://purl.org/dc/elements/1.1/ date"`
	Issued     string        `xml:"http://purl.org/dc/terms/ issued"`
	Modified   string        `xml:"http://purl.org/dc/terms/ modified"`
}

// JVNDBParseStats summarises one parsed feed.
type JVNDBParseStats struct {
	Items    int // <item> elements seen
	Accepted int // items handed to the callback
	Rejected int // items skipped as malformed (no valid id, empty title)
	// OldestModified is the earliest dcterms:modified among accepted items;
	// the sync compares it with its previous success to detect a gap.
	OldestModified *time.Time
}

// ParseJVNDBRSS streams a JVNDB RSS document from r and calls fn for every
// valid item, in document order. It is strict about the document (UTF-8
// only, no DOCTYPE, root rdf:RDF, nothing after the root) and lenient about
// single items (a malformed one is counted in Rejected and skipped). fn's
// error stops the parse and is returned as is. Memory is bounded by one item
// at a time; the caller bounds the total size of r.
func ParseJVNDBRSS(r io.Reader, fn func(repository.JVNDBAdvisoryRecord) error) (JVNDBParseStats, error) {
	var st JVNDBParseStats
	dec := xml.NewDecoder(r)
	dec.Strict = true
	// No CharsetReader: a document declaring anything but UTF-8 is refused
	// by encoding/xml itself.
	dec.CharsetReader = nil

	malformed := func(format string, a ...any) (JVNDBParseStats, error) {
		return st, fmt.Errorf("%w: %s", ErrJVNDBFeedMalformed, fmt.Sprintf(format, a...))
	}

	sawRoot := false
	rootClosed := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return malformed("xml: %v", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			return malformed("DOCTYPE / directive not allowed")
		case xml.ProcInst:
			if t.Target != "xml" || sawRoot {
				return malformed("processing instruction %q not allowed", t.Target)
			}
		case xml.Comment:
		case xml.CharData:
			if (!sawRoot || rootClosed) && strings.TrimSpace(string(t)) != "" {
				return malformed("text outside the root element")
			}
		case xml.StartElement:
			if rootClosed {
				return malformed("content after the root element")
			}
			if !sawRoot {
				if t.Name.Space != nsRDF || t.Name.Local != "RDF" {
					return malformed("root element is %s:%s, want rdf:RDF", t.Name.Space, t.Name.Local)
				}
				sawRoot = true
				continue
			}
			// A direct child of rdf:RDF (the decoder consumes nested
			// elements through DecodeElement / Skip).
			if t.Name.Space == nsRSS10 && t.Name.Local == "item" {
				st.Items++
				if st.Items > jvndbMaxItemsPerFeed {
					return malformed("more than %d items", jvndbMaxItemsPerFeed)
				}
				var it jvndbRSSItem
				if err := dec.DecodeElement(&it, &t); err != nil {
					return malformed("item %d: %v", st.Items, err)
				}
				rec, ok := normaliseJVNDBItem(it)
				if !ok {
					st.Rejected++
					continue
				}
				st.Accepted++
				if rec.Modified != nil && (st.OldestModified == nil || rec.Modified.Before(*st.OldestModified)) {
					m := *rec.Modified
					st.OldestModified = &m
				}
				if err := fn(rec); err != nil {
					return st, err
				}
				continue
			}
			if err := dec.Skip(); err != nil {
				return malformed("xml: %v", err)
			}
		case xml.EndElement:
			// Only the root's end reaches here (children are consumed).
			rootClosed = true
		}
	}
	if !sawRoot {
		return malformed("no root element")
	}
	if !rootClosed {
		return malformed("root element not closed")
	}
	return st, nil
}

// normaliseJVNDBItem validates one item. It returns false when the item has
// no valid JVNDB id or no usable title; bad CVE references and bad dates are
// dropped individually without rejecting the item.
func normaliseJVNDBItem(it jvndbRSSItem) (repository.JVNDBAdvisoryRecord, bool) {
	id := strings.TrimSpace(it.Identifier)
	if !model.ValidJVNDBID(id) {
		return repository.JVNDBAdvisoryRecord{}, false
	}
	title := cleanJVNDBTitle(it.Title)
	if title == "" {
		return repository.JVNDBAdvisoryRecord{}, false
	}
	rec := repository.JVNDBAdvisoryRecord{ID: id, Title: title}
	seen := map[string]bool{}
	for _, ref := range it.References {
		if strings.TrimSpace(ref.Source) != "CVE" {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(ref.ID))
		if !jvndbCVEPattern.MatchString(cve) || seen[cve] {
			continue
		}
		if len(rec.CVEs) >= jvndbMaxCVEsPerItem {
			break
		}
		seen[cve] = true
		rec.CVEs = append(rec.CVEs, cve)
	}
	rec.Published = parseJVNDBTime(it.Issued)
	rec.Modified = parseJVNDBTime(it.Modified)
	if rec.Modified == nil {
		rec.Modified = parseJVNDBTime(it.Date)
	}
	if rec.Published == nil {
		rec.Published = parseJVNDBTime(it.Date)
	}
	return rec, true
}

// cleanJVNDBTitle collapses whitespace, drops control and format characters
// (bidi overrides among them) and caps the length.
func cleanJVNDBTitle(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if space {
			if n+1 >= jvndbMaxTitleRunes {
				break
			}
			b.WriteByte(' ')
			n++
			space = false
		}
		if n >= jvndbMaxTitleRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

var jvndbTimeLayouts = []string{
	time.RFC3339,             // 2026-11-21T17:00:01+09:00
	"2006-01-02T15:04Z07:00", // 2026-11-19T16:12+09:00 (the feed's usual item form)
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02",
}

// parseJVNDBTime parses a W3CDTF timestamp of the feed; nil when absent or
// unparsable, or outside 1980..(now+2y) (a typo, not a date).
func parseJVNDBTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range jvndbTimeLayouts {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if t.Year() < 1980 || t.After(time.Now().AddDate(2, 0, 0)) {
			return nil
		}
		t = t.UTC()
		return &t
	}
	return nil
}
