package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sbomhub/sbomhub/internal/client"
)

// GHSAParser converts a GHSA global advisory (see internal/client.GHSAAdvisory)
// into a ParsedAdvisory. It accepts:
//
//   - a *client.GHSAAdvisory (already-fetched), or
//   - a client.GHSAAdvisory value, or
//   - a []byte / json.RawMessage / string containing the advisory JSON.
//
// Other types return an error.
type GHSAParser struct{}

// NewGHSAParser returns a stateless GHSAParser.
func NewGHSAParser() *GHSAParser { return &GHSAParser{} }

// Source returns SourceGHSA.
func (p *GHSAParser) Source() Source { return SourceGHSA }

// Parse implements Parser. See type docstring for accepted payload types.
func (p *GHSAParser) Parse(ctx context.Context, payload any) (*ParsedAdvisory, error) {
	adv, err := normalizeGHSAPayload(payload)
	if err != nil {
		return nil, err
	}
	if adv == nil {
		return nil, nil
	}

	// Combined free-text corpus for the regex extractors. Summary first because
	// it is usually the most specific sentence.
	text := adv.Summary
	if adv.Description != "" {
		if text != "" {
			text += "\n\n"
		}
		text += adv.Description
	}

	// Pull GHSA's explicit vulnerable_functions field where present. GitHub
	// surfaces this at advisory top level for some ecosystems and inside the
	// per-vulnerability records for others, so we union both.
	funcs := append([]string(nil), adv.VulnerableFunctions...)
	for _, v := range adv.Vulnerabilities {
		funcs = append(funcs, v.VulnerableFunctions...)
	}
	// Heuristic extraction as a backstop.
	funcs = append(funcs, extractVulnFuncs(text)...)

	cveID := adv.CVEID
	if cveID == "" {
		// Fall back to identifiers list, then to the GHSA id itself so the
		// downstream excerpt is never keyed on an empty string.
		for _, id := range adv.Identifiers {
			if id.Type == "CVE" && id.Value != "" {
				cveID = id.Value
				break
			}
		}
		if cveID == "" {
			cveID = adv.GHSAID
		}
	}

	parsed := &ParsedAdvisory{
		CVEID:          cveID,
		Source:         SourceGHSA,
		VulnFuncs:      funcs,
		AffectedPaths:  extractAffectedPaths(text),
		RequiredConfig: extractRequiredConfig(text),
		RequiredEnv:    extractRequiredEnv(text),
		RawExcerpt:     text,
		FetchedAt:      time.Now().UTC(),
	}
	return parsed.Normalize(), nil
}

func normalizeGHSAPayload(payload any) (*client.GHSAAdvisory, error) {
	switch v := payload.(type) {
	case nil:
		return nil, nil
	case *client.GHSAAdvisory:
		if v == nil {
			return nil, nil
		}
		return v, nil
	case client.GHSAAdvisory:
		return &v, nil
	case []byte:
		return decodeGHSABytes(v)
	case json.RawMessage:
		return decodeGHSABytes(v)
	case string:
		return decodeGHSABytes([]byte(v))
	default:
		return nil, fmt.Errorf("ghsa parser: unsupported payload type %T", payload)
	}
}

func decodeGHSABytes(data []byte) (*client.GHSAAdvisory, error) {
	if len(data) == 0 {
		return nil, nil
	}
	// Try single advisory first.
	var adv client.GHSAAdvisory
	if err := json.Unmarshal(data, &adv); err == nil && (adv.GHSAID != "" || adv.CVEID != "") {
		return &adv, nil
	}
	// Fallback: array (list endpoint).
	var advs []client.GHSAAdvisory
	if err := json.Unmarshal(data, &advs); err != nil {
		return nil, fmt.Errorf("ghsa parser: decode payload: %w", err)
	}
	if len(advs) == 0 {
		return nil, nil
	}
	return &advs[0], nil
}
