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
	// jvndbMaxItemBytes bounds one <item> in the document. Real items are
	// 1-9 KB (the recent feed, 2026-11-21); an item beyond this fails the
	// feed rather than being materialised.
	jvndbMaxItemBytes = 1 << 20
	// jvndbMaxTokenBytes bounds the input one XML token (a text node, a tag
	// with its attributes) may span. encoding/xml materialises a whole token
	// before returning it, so the limit is enforced in the reader underneath
	// (jvndbTokenGuard), before the allocation.
	jvndbMaxTokenBytes = 1 << 20
	// jvndbMaxDepth bounds element nesting below rdf:RDF (the feed uses 4).
	jvndbMaxDepth = 32
	// jvndbMaxFieldBytes bounds the text kept from one item field (the title
	// cap is 1000 runes, at most 4 bytes each).
	jvndbMaxFieldBytes = 4 * jvndbMaxTitleRunes
)

var jvndbCVEPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// ErrJVNDBFeedMalformed marks a feed whose document structure is not a
// JVNDB RSS feed (not XML, wrong root, DOCTYPE, wrong encoding, too many
// items). Individual malformed items are not this error: they are skipped
// and counted.
var ErrJVNDBFeedMalformed = errors.New("jvndb rss: malformed feed")

type jvndbRSSRef struct {
	Source string
	ID     string
}

type jvndbRSSItem struct {
	Title      string
	Identifier string
	References []jvndbRSSRef // CVE references only, bounded
	// RefsOverflow: more CVE references than were kept.
	RefsOverflow bool
	Date         string
	Issued       string
	Modified     string
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
	guard := &jvndbTokenGuard{r: r, limit: jvndbMaxTokenBytes}
	dec := xml.NewDecoder(guard)
	dec.Strict = true
	// No CharsetReader: a document declaring anything but UTF-8 is refused
	// by encoding/xml itself.
	dec.CharsetReader = nil

	malformed := func(format string, a ...any) (JVNDBParseStats, error) {
		return st, fmt.Errorf("%w: %s", ErrJVNDBFeedMalformed, fmt.Sprintf(format, a...))
	}

	sawRoot := false
	rootClosed := false
	sawChannel := false
	for {
		tok, err := dec.Token()
		guard.reset()
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
				it, err := decodeJVNDBItem(dec, guard)
				if err != nil {
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
			if t.Name.Space == nsRSS10 && t.Name.Local == "channel" {
				sawChannel = true
			}
			if err := skipJVNDBElement(dec, guard); err != nil {
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
	// Codex R1: an RDF document without the RSS channel, or one whose every
	// item was rejected, is not a JVNDB feed (an error page, a schema change)
	// and must not be recorded as a complete read.
	if !sawChannel {
		return malformed("no rss channel")
	}
	if st.Items > 0 && st.Accepted == 0 {
		return malformed("all %d items rejected", st.Items)
	}
	return st, nil
}

// decodeJVNDBItem reads one <item> (its start element already consumed)
// token by token, keeping only the fields used, each bounded, and failing
// when the item exceeds jvndbMaxItemBytes of input.
func decodeJVNDBItem(dec *xml.Decoder, guard *jvndbTokenGuard) (jvndbRSSItem, error) {
	var it jvndbRSSItem
	start := dec.InputOffset()
	depth := 1
	var field *string
	var buf strings.Builder
	for {
		if dec.InputOffset()-start > jvndbMaxItemBytes {
			return it, fmt.Errorf("item larger than %d bytes", jvndbMaxItemBytes)
		}
		tok, err := dec.Token()
		guard.reset()
		if err != nil {
			return it, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			field = nil
			if depth > jvndbMaxDepth {
				return it, fmt.Errorf("elements nested deeper than %d", jvndbMaxDepth)
			}
			if depth != 2 {
				continue
			}
			buf.Reset()
			switch {
			case t.Name.Space == nsRSS10 && t.Name.Local == "title":
				field = &it.Title
			case t.Name.Space == nsJVNSec && t.Name.Local == "identifier":
				field = &it.Identifier
			case t.Name.Space == nsDC && t.Name.Local == "date":
				field = &it.Date
			case t.Name.Space == nsDCTerm && t.Name.Local == "issued":
				field = &it.Issued
			case t.Name.Space == nsDCTerm && t.Name.Local == "modified":
				field = &it.Modified
			case t.Name.Space == nsJVNSec && t.Name.Local == "references":
				var ref jvndbRSSRef
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "source":
						ref.Source = a.Value
					case "id":
						ref.ID = a.Value
					}
				}
				// Twice the kept cap leaves room for duplicates and bad ids.
				if strings.TrimSpace(ref.Source) == "CVE" {
					if len(it.References) < 2*jvndbMaxCVEsPerItem {
						it.References = append(it.References, ref)
					} else {
						it.RefsOverflow = true
					}
				}
			}
		case xml.CharData:
			if field != nil && depth == 2 {
				room := jvndbMaxFieldBytes - buf.Len()
				if room > 0 {
					if len(t) > room {
						t = t[:room]
					}
					buf.Write(t)
				}
			}
		case xml.EndElement:
			if depth == 2 && field != nil {
				*field = buf.String()
				field = nil
			}
			depth--
			if depth == 0 {
				return it, nil
			}
		}
	}
}

// normaliseJVNDBItem validates one item. It returns false when the item has
// no valid JVNDB id, no usable title or no usable modification time; bad CVE
// references and a bad issued date are dropped individually.
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
	// The CVE set replaces the stored one, so it must be complete: an item
	// with a CVE reference that cannot be read, or more than the cap, is
	// rejected rather than stored with a partial set (Codex R4).
	if it.RefsOverflow {
		return repository.JVNDBAdvisoryRecord{}, false
	}
	seen := map[string]bool{}
	for _, ref := range it.References {
		if strings.TrimSpace(ref.Source) != "CVE" {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(ref.ID))
		if !jvndbCVEPattern.MatchString(cve) {
			return repository.JVNDBAdvisoryRecord{}, false
		}
		if seen[cve] {
			continue
		}
		if len(rec.CVEs) >= jvndbMaxCVEsPerItem {
			return repository.JVNDBAdvisoryRecord{}, false
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
	// Without a modification time the item cannot be ordered against the
	// stored row (a stale year feed could overwrite it, or it a newer one):
	// reject it (Codex R3). Every item of the real feeds carries one.
	if rec.Modified == nil {
		return repository.JVNDBAdvisoryRecord{}, false
	}
	return rec, true
}

// cleanJVNDBTitle collapses whitespace, drops control and format characters
// (bidi overrides among them) and caps the length.
func cleanJVNDBTitle(s string) string {
	// A field cut at jvndbMaxFieldBytes may end inside a character.
	s = strings.ToValidUTF8(s, "")
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

// jvndbClockSkew is how far in the future a feed date may lie and still be
// believed (the CVE sync's allowance). A later one would block genuine
// updates, or close a gap, until the clock catches up (Codex R4).
const jvndbClockSkew = 24 * time.Hour

// parseJVNDBTime parses a W3CDTF timestamp of the feed; nil when absent or
// unparsable, before 1980, or more than jvndbClockSkew in the future.
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
		if t.Year() < 1980 || t.After(time.Now().Add(jvndbClockSkew)) {
			return nil
		}
		t = t.UTC()
		return &t
	}
	return nil
}

// skipJVNDBElement consumes the element whose start was just read, like
// xml.Decoder.Skip but resetting the token guard between tokens.
func skipJVNDBElement(dec *xml.Decoder, guard *jvndbTokenGuard) error {
	depth := 1
	for depth > 0 {
		tok, err := dec.Token()
		guard.reset()
		if err != nil {
			return err
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
			if depth > jvndbMaxDepth {
				return fmt.Errorf("elements nested deeper than %d", jvndbMaxDepth)
			}
		case xml.EndElement:
			depth--
		}
	}
	return nil
}

// jvndbTokenGuard fails a read once more than limit bytes were read since the
// last reset. The parser resets it after every token, so no single token can
// make the decoder buffer more than about limit bytes (plus its read-ahead).
type jvndbTokenGuard struct {
	r     io.Reader
	limit int64
	used  int64
}

func (g *jvndbTokenGuard) reset() { g.used = 0 }

func (g *jvndbTokenGuard) Read(p []byte) (int, error) {
	if g.used >= g.limit {
		return 0, fmt.Errorf("an XML token larger than %d bytes", g.limit)
	}
	if room := g.limit - g.used; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := g.r.Read(p)
	g.used += int64(n)
	return n, err
}
