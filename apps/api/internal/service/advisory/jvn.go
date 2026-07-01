package advisory

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// JVNParser converts JVN (Japan Vulnerability Notes) advisories into a
// ParsedAdvisory.
//
// JVN ships data in three shapes in practice:
//
//  1. MyJVN RSS getVulnOverviewList — RDF/XML with rdf:Description blocks
//     and a short Japanese summary.
//  2. MyJVN getVulnDetailInfo — RDF/XML with extended vuldef:* fields.
//  3. JVN iPedia JSON (newer API) — JSON with embedded English text.
//
// All three carry free-form description text where vulnerable-function /
// affected-path hints live. We treat the parser as "feed me whatever you have"
// and look at the bytes:
//
//   - *JVNAdvisory or JVNAdvisory: use directly (no parse).
//   - []byte / json.RawMessage / string: detect XML vs JSON by first non-ws
//     byte and decode accordingly.
//
// ※要確認: the iPedia JSON schema is still in beta and field names may shift.
// Once the M1-5 triage runner is wired, integration tests against the live
// endpoint will tell us if we need to add fallbacks.
type JVNParser struct{}

// NewJVNParser returns a stateless JVNParser.
func NewJVNParser() *JVNParser { return &JVNParser{} }

// Source returns SourceJVN.
func (p *JVNParser) Source() Source { return SourceJVN }

// JVNAdvisory is the canonical in-memory representation. Both the XML and JSON
// decoders normalize into this shape before extraction.
type JVNAdvisory struct {
	JVNDBID     string // e.g. "JVNDB-2024-000001"
	CVEID       string // optional CVE alias
	Title       string
	Description string   // free-text body, locale-mixed
	References  []string // affected URLs
}

// JVN RSS XML structures. We keep this internal to the package — the existing
// service.JVNRSSFeed lives in a different package and using it here would
// create a coupling we don't want.
type jvnRDF struct {
	XMLName xml.Name     `xml:"RDF"`
	Items   []jvnRSSItem `xml:"item"`
}

type jvnRSSItem struct {
	Title       string         `xml:"title"`
	Identifier  string         `xml:"identifier"`
	Description string         `xml:"description"`
	Link        string         `xml:"link"`
	References  []jvnReference `xml:"references"`
}

type jvnReference struct {
	ID    string `xml:"id,attr"`
	Title string `xml:",chardata"`
}

// jvnVulDef is a stripped MyJVN getVulnDetailInfo entry. The upstream schema
// nests under a vuldef:Vulinfo element with many sub-children; we only care
// about the description text.
type jvnVulDef struct {
	XMLName     xml.Name `xml:"Vulinfo"`
	VulinfoID   string   `xml:"VulinfoID"`
	VulinfoData struct {
		Title      string `xml:"Title"`
		Overview   string `xml:"VulinfoDescription>Overview"`
		Impact     string `xml:"Impact>ImpactItem>Description"`
		References []struct {
			ID    string `xml:"id,attr"`
			Title string `xml:",chardata"`
		} `xml:"Related>RelatedItem"`
	} `xml:"VulinfoData"`
}

// jvnIpediaJSON is the JVN iPedia JSON envelope. Field names are taken from
// public docs — keep this list narrow on purpose. ※要確認 (see type docstring).
type jvnIpediaJSON struct {
	VulinfoID   string `json:"vulinfo_id"`
	CVE         string `json:"cve_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	References  []struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	} `json:"references"`
}

// Parse implements Parser. See type docstring for accepted payload types.
func (p *JVNParser) Parse(ctx context.Context, payload any) (*ParsedAdvisory, error) {
	adv, err := normalizeJVNPayload(payload)
	if err != nil {
		return nil, err
	}
	if adv == nil {
		return nil, nil
	}

	// Compose the corpus the regex extractors run on.
	text := strings.TrimSpace(adv.Description)
	if adv.Title != "" {
		if text != "" {
			text = adv.Title + "\n\n" + text
		} else {
			text = adv.Title
		}
	}

	cveID := adv.CVEID
	if cveID == "" {
		cveID = adv.JVNDBID
	}

	parsed := &ParsedAdvisory{
		CVEID:          cveID,
		Source:         SourceJVN,
		VulnFuncs:      extractVulnFuncs(text),
		AffectedPaths:  extractAffectedPaths(text),
		RequiredConfig: extractRequiredConfig(text),
		RequiredEnv:    extractRequiredEnv(text),
		RawExcerpt:     text,
		FetchedAt:      time.Now().UTC(),
	}
	return parsed.Normalize(), nil
}

func normalizeJVNPayload(payload any) (*JVNAdvisory, error) {
	switch v := payload.(type) {
	case nil:
		return nil, nil
	case *JVNAdvisory:
		if v == nil {
			return nil, nil
		}
		return v, nil
	case JVNAdvisory:
		return &v, nil
	case []byte:
		return decodeJVNBytes(v)
	case json.RawMessage:
		return decodeJVNBytes(v)
	case string:
		return decodeJVNBytes([]byte(v))
	default:
		return nil, fmt.Errorf("jvn parser: unsupported payload type %T", payload)
	}
}

func decodeJVNBytes(data []byte) (*JVNAdvisory, error) {
	trimmed := skipBOMAndWS(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	first := trimmed[0]
	switch first {
	case '<':
		return decodeJVNXML(data)
	case '{', '[':
		return decodeJVNJSON(data)
	default:
		return nil, fmt.Errorf("jvn parser: cannot detect payload format from byte %q", first)
	}
}

func decodeJVNXML(data []byte) (*JVNAdvisory, error) {
	// Try MyJVN RSS first.
	var rdf jvnRDF
	if err := xml.Unmarshal(data, &rdf); err == nil && len(rdf.Items) > 0 {
		it := rdf.Items[0]
		adv := &JVNAdvisory{
			JVNDBID:     it.Identifier,
			Title:       it.Title,
			Description: it.Description,
		}
		for _, ref := range it.References {
			if strings.HasPrefix(ref.ID, "CVE-") && adv.CVEID == "" {
				adv.CVEID = ref.ID
			}
			if ref.Title != "" {
				adv.References = append(adv.References, ref.Title)
			}
		}
		return adv, nil
	}
	// Try VulDetail.
	var vd jvnVulDef
	if err := xml.Unmarshal(data, &vd); err == nil && vd.VulinfoID != "" {
		body := strings.TrimSpace(vd.VulinfoData.Overview)
		if vd.VulinfoData.Impact != "" {
			if body != "" {
				body += "\n\n"
			}
			body += vd.VulinfoData.Impact
		}
		adv := &JVNAdvisory{
			JVNDBID:     vd.VulinfoID,
			Title:       vd.VulinfoData.Title,
			Description: body,
		}
		for _, r := range vd.VulinfoData.References {
			if strings.HasPrefix(r.ID, "CVE-") && adv.CVEID == "" {
				adv.CVEID = r.ID
			}
		}
		return adv, nil
	}
	return nil, fmt.Errorf("jvn parser: XML did not match RSS or VulinfoDetail shape")
}

func decodeJVNJSON(data []byte) (*JVNAdvisory, error) {
	// Allow either an object or a single-element array.
	if data[0] == '[' {
		var arr []jvnIpediaJSON
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil, fmt.Errorf("jvn parser: decode iPedia JSON array: %w", err)
		}
		if len(arr) == 0 {
			return nil, nil
		}
		return ipediaToAdvisory(arr[0]), nil
	}
	var obj jvnIpediaJSON
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("jvn parser: decode iPedia JSON: %w", err)
	}
	if obj.VulinfoID == "" && obj.CVE == "" && obj.Description == "" {
		return nil, nil
	}
	return ipediaToAdvisory(obj), nil
}

func ipediaToAdvisory(in jvnIpediaJSON) *JVNAdvisory {
	adv := &JVNAdvisory{
		JVNDBID:     in.VulinfoID,
		CVEID:       in.CVE,
		Title:       in.Title,
		Description: in.Description,
	}
	for _, r := range in.References {
		if r.Title != "" {
			adv.References = append(adv.References, r.Title)
		}
	}
	return adv
}

func skipBOMAndWS(b []byte) []byte {
	// Skip UTF-8 BOM.
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	for len(b) > 0 {
		switch b[0] {
		case ' ', '\t', '\n', '\r':
			b = b[1:]
		default:
			return b
		}
	}
	return b
}
