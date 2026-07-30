package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/sbomhub/sbomhub/internal/config"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/service"
)

// buildEgressGuards assembles the per-purpose outbound destination policies
// from the process configuration.
//
// It governs the four places a TENANT can name a destination: the issue tracker
// base URL, the Slack / Discord notification webhooks, the diff webhook, and
// the per-tenant Azure OpenAI endpoint. It deliberately does NOT govern
// operator-supplied destinations — the SBOMHUB_*_URL feed mirrors, the Ollama
// base URL from SBOMHUB_LLM_OLLAMA_URL / OLLAMA_HOST, the billing provider API
// — because the operator already controls the process, and applying the policy
// there would break the documented self-hosted Ollama deployment for no gain.
//
// A malformed SBOMHUB_EGRESS_ALLOWED_INTERNAL is returned as an error rather
// than skipped: an operator who mistypes an exemption otherwise believes they
// have opened a path that is in fact still closed, and the usual next move
// after that confusion is to set SBOMHUB_EGRESS_ALLOW_PRIVATE=true and open
// everything.
func buildEgressGuards(cfg *config.Config) (*egress.Set, error) {
	hosts, cidrs, err := egress.ParseExemptions(cfg.EgressAllowedInternal)
	if err != nil {
		return nil, fmt.Errorf("SBOMHUB_EGRESS_ALLOWED_INTERNAL: %w", err)
	}

	nat64, err := parseNAT64Prefixes(cfg.EgressNAT64Prefixes)
	if err != nil {
		return nil, fmt.Errorf("SBOMHUB_EGRESS_NAT64_PREFIXES: %w", err)
	}

	settings := egress.Settings{
		AllowPrivate:          cfg.EgressAllowPrivate,
		PrivateHostExemptions: hosts,
		PrivateCIDRExemptions: cidrs,
		NAT64Prefixes:         nat64,
		AllowProxy:            cfg.EgressAllowProxy,
	}
	// SaaS keeps the pre-existing issue tracker hostname allowlist. Self-hosted
	// leaves it empty, matching the previous behaviour of
	// IssueTrackerService.allowedDomains.
	if cfg.IsSaaS() {
		settings.IssueTrackerAllowedHosts = service.AllowedIssueTrackerDomains
	}

	cidrStrings := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		cidrStrings = append(cidrStrings, c.String())
	}
	nat64Strings := make([]string, 0, len(nat64))
	for _, p := range nat64 {
		nat64Strings = append(nat64Strings, p.String())
	}
	slog.Info("Outbound egress policy for tenant-configured destinations",
		"nat64_prefixes", nat64Strings,
		"allow_private", settings.AllowPrivate,
		"exempt_hosts", hosts,
		"exempt_cidrs", cidrStrings,
		"allow_proxy", settings.AllowProxy,
		"issue_tracker_allowed_hosts", settings.IssueTrackerAllowedHosts,
		"note", "cloud metadata and other blocked-class addresses are refused regardless of allow_private")
	if settings.AllowProxy {
		// Loud, because it changes what the guard can promise: with a proxy the
		// dialer only ever inspects the proxy's address.
		slog.Warn("SBOMHUB_EGRESS_ALLOW_PROXY is set: HTTP_PROXY/HTTPS_PROXY will be honoured for tenant-configured destinations",
			"consequence", "the egress guard inspects the proxy address, not the final destination — the destination policy must be enforced on the proxy")
	}

	return egress.NewSet(settings), nil
}

// parseNAT64Prefixes parses and validates the operator-declared RFC 6052
// translation prefixes.
//
// A malformed entry is an error rather than a skipped entry, for the same
// reason as the exemption list: an operator who believes a prefix is being
// decoded, when it is not, has a hole they cannot see.
func parseNAT64Prefixes(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		entry := strings.TrimSpace(field)
		if entry == "" {
			continue
		}
		prefix, perr := netip.ParsePrefix(entry)
		if perr != nil {
			return nil, fmt.Errorf("%q is not a CIDR prefix", entry)
		}
		if verr := egress.ValidateNAT64Prefix(prefix); verr != nil {
			return nil, verr
		}
		masked := prefix.Masked()
		// Overlapping declarations are either redundant (an exact duplicate) or
		// ambiguous: two prefixes of different lengths covering the same address
		// read the embedded IPv4 octets from different offsets, so for most
		// addresses they disagree about the destination (Codex round 7, Medium;
		// wording corrected in round 8 — duplicates decode identically, and even
		// differing layouts coincide for some addresses). The classifier refuses
		// an address whose readings disagree, but an operator who wrote an
		// overlapping pair has made a mistake and should be told at startup
		// rather than discovering it as an intermittent refusal.
		for _, existing := range out {
			if existing.Overlaps(masked) {
				return nil, fmt.Errorf("prefixes %s and %s overlap; they are either redundant or decode a translated address to different IPv4 destinations", existing, masked)
			}
		}
		out = append(out, masked)
	}
	return out, nil
}
