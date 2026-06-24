package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// NVDParser converts raw NVD CVE records (https://services.nvd.nist.gov/rest/json/cves/2.0)
// into ParsedAdvisory. It accepts either:
//
//   - a *NVDCVEPayload (already-unmarshalled struct), or
//   - a []byte / json.RawMessage containing a single CVE entry, or
//   - a []byte containing a full NVDResponse (in which case the first
//     vulnerability is used).
//
// Other types return an error.
type NVDParser struct{}

// NewNVDParser returns a stateless NVDParser.
func NewNVDParser() *NVDParser { return &NVDParser{} }

// Source returns SourceNVD.
func (p *NVDParser) Source() Source { return SourceNVD }

// NVDCVEPayload is the minimal subset of NVD's CVE JSON we need. It deliberately
// duplicates fields from internal/service/nvd.go rather than importing them,
// because that file's NVDCVE is unexported semantics-wise (lives in the service
// package, would create a circular import once the service depends on advisory).
//
// Reference: https://nvd.nist.gov/developers/vulnerabilities
type NVDCVEPayload struct {
	ID           string                 `json:"id"`
	Published    string                 `json:"published"`
	LastModified string                 `json:"lastModified"`
	Descriptions []NVDDescription       `json:"descriptions"`
	References   []NVDReference         `json:"references"`
	Configurations []NVDConfiguration   `json:"configurations"`
	Weaknesses   []NVDWeakness          `json:"weaknesses"`
}

// NVDDescription is one localised description block.
type NVDDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NVDReference is one external URL.
type NVDReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

// NVDConfiguration captures CPE configurations. Used opportunistically to spot
// "must be configured with X" style constraints.
type NVDConfiguration struct {
	Operator string     `json:"operator"`
	Nodes    []NVDNode  `json:"nodes"`
}

// NVDNode is one node in the CPE applicability tree.
type NVDNode struct {
	Operator string           `json:"operator"`
	Negate   bool             `json:"negate"`
	CPEMatch []NVDCPEMatch    `json:"cpeMatch"`
}

// NVDCPEMatch is one CPE applicability match.
type NVDCPEMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

// NVDWeakness wraps a CWE classification.
type NVDWeakness struct {
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Description []NVDDescription  `json:"description"`
}

// nvdEnvelope and nvdEntry mirror the upstream list response shape so we can
// accept full pages as input too.
type nvdEnvelope struct {
	Vulnerabilities []nvdEntry `json:"vulnerabilities"`
}

type nvdEntry struct {
	CVE NVDCVEPayload `json:"cve"`
}

// Parse implements Parser. See type docstring for accepted payload types.
func (p *NVDParser) Parse(ctx context.Context, payload any) (*ParsedAdvisory, error) {
	cve, err := normalizeNVDPayload(payload)
	if err != nil {
		return nil, err
	}
	if cve == nil {
		return nil, nil
	}

	desc := pickEnglishDescription(cve.Descriptions)
	parsed := &ParsedAdvisory{
		CVEID:          cve.ID,
		Source:         SourceNVD,
		VulnFuncs:      extractVulnFuncs(desc),
		AffectedPaths:  extractAffectedPaths(desc),
		RequiredConfig: extractRequiredConfig(desc),
		RequiredEnv:    extractRequiredEnv(desc),
		RawExcerpt:     desc,
		FetchedAt:      time.Now().UTC(),
	}
	return parsed.Normalize(), nil
}

func normalizeNVDPayload(payload any) (*NVDCVEPayload, error) {
	switch v := payload.(type) {
	case nil:
		return nil, nil
	case *NVDCVEPayload:
		if v == nil {
			return nil, nil
		}
		return v, nil
	case NVDCVEPayload:
		return &v, nil
	case []byte:
		return decodeNVDBytes(v)
	case json.RawMessage:
		return decodeNVDBytes(v)
	case string:
		return decodeNVDBytes([]byte(v))
	default:
		return nil, fmt.Errorf("nvd parser: unsupported payload type %T", payload)
	}
}

func decodeNVDBytes(data []byte) (*NVDCVEPayload, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Try the envelope first (full list response).
	var env nvdEnvelope
	if err := json.Unmarshal(data, &env); err == nil && len(env.Vulnerabilities) > 0 {
		cve := env.Vulnerabilities[0].CVE
		return &cve, nil
	}
	// Fallback to a single CVE.
	var single NVDCVEPayload
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, fmt.Errorf("nvd parser: decode payload: %w", err)
	}
	if single.ID == "" {
		// Try one more shape: an entry wrapper {"cve": {...}}.
		var wrap nvdEntry
		if err := json.Unmarshal(data, &wrap); err == nil && wrap.CVE.ID != "" {
			return &wrap.CVE, nil
		}
	}
	return &single, nil
}

func pickEnglishDescription(descs []NVDDescription) string {
	for _, d := range descs {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(descs) > 0 {
		return descs[0].Value
	}
	return ""
}
