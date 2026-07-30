package egress

import (
	"fmt"
	"net/netip"
	"strings"
)

// Purpose names the outbound integration a Policy governs. It appears in every
// refusal message so an operator reading a log line knows which setting screen
// produced the destination.
type Purpose string

const (
	// PurposeIssueTracker covers issue_tracker_connections.base_url — the Jira
	// / Backlog / GitHub Issues REST roots.
	PurposeIssueTracker Purpose = "issue_tracker"
	// PurposeNotificationWebhook covers notification_settings.slack_webhook_url
	// and .discord_webhook_url.
	PurposeNotificationWebhook Purpose = "notification_webhook"
	// PurposeDiffWebhook covers tenant_diff_webhook_settings.webhook_url.
	PurposeDiffWebhook Purpose = "diff_webhook"
	// PurposeTenantLLM covers tenant_llm_config.azure_endpoint (and any future
	// per-tenant provider base URL).
	PurposeTenantLLM Purpose = "tenant_llm"
)

// Policy is the destination rule set for one Purpose.
//
// A Policy is only ever applied to destinations a TENANT can choose.
// Operator-supplied destinations (feed URLs from SBOMHUB_*_URL, the Ollama base
// URL from SBOMHUB_LLM_OLLAMA_URL / OLLAMA_HOST, the Lemon Squeezy API root)
// are deliberately NOT guarded: the operator already controls the process, so
// filtering their own configuration buys no security and would break the
// documented "Ollama on localhost" deployment.
type Policy struct {
	// Purpose labels refusals.
	Purpose Purpose

	// AllowPrivate permits ClassPrivate destinations (RFC1918, loopback, CGNAT,
	// IPv6 ULA). ClassBlocked destinations are refused even when this is true.
	AllowPrivate bool

	// PrivateHostExemptions are hostnames whose ClassPrivate destinations are
	// permitted even when AllowPrivate is false. Matching is case-insensitive,
	// exact or as a parent domain ("corp.example" matches "jira.corp.example").
	//
	// This is the narrow version of AllowPrivate: it lets an operator name the
	// one internal Jira they run without opening the whole internal network.
	PrivateHostExemptions []string

	// PrivateCIDRExemptions are networks whose ClassPrivate destinations are
	// permitted even when AllowPrivate is false.
	PrivateCIDRExemptions []netip.Prefix

	// AllowedHosts, when non-empty, restricts the destination hostname to this
	// list (exact or parent-domain match). This is the SaaS allowlist; empty
	// means "any hostname", subject to the IP rules above.
	AllowedHosts []string

	// AllowPlaintextHTTP permits http:// destinations. https:// is always
	// permitted. Schemes other than http/https are always refused.
	AllowPlaintextHTTP bool

	// MaxRedirects caps redirect hops. Zero means redirects are not followed at
	// all (the 3xx is handed back to the caller as an ordinary response).
	// Every followed hop is re-validated against this Policy.
	MaxRedirects int

	// NAT64Prefixes are operator-declared RFC 6052 translation prefixes.
	// Addresses under them are classified by the IPv4 address they embed rather
	// than as opaque IPv6. See ValidateNAT64Prefix.
	NAT64Prefixes []netip.Prefix

	// AllowProxy permits HTTP_PROXY / HTTPS_PROXY to be honoured.
	//
	// Default false, and that is a security decision rather than an oversight.
	// When a proxy is in play Go hands the dialer the PROXY's address, and the
	// proxy — not this package — resolves and connects to the real destination.
	// The dial-time guarantee this package exists to provide simply does not
	// hold: the guard would approve the proxy while the refused destination is
	// reached over the connection it approved. Codex round 1 (High).
	//
	// Setting it true is a deliberate delegation: the destination policy then
	// has to be enforced on the proxy.
	AllowProxy bool
}

// privateAllowedForHost reports whether ClassPrivate destinations are permitted
// for this host, taking the blanket AllowPrivate and the per-host exemptions
// into account.
func (p Policy) privateAllowedForHost(host string) bool {
	if p.AllowPrivate {
		return true
	}
	return hostMatches(host, p.PrivateHostExemptions)
}

// privateAllowedForAddr reports whether ClassPrivate is permitted for a
// specific resolved address, taking the CIDR exemptions into account.
//
// Both the address that will be dialed and the EFFECTIVE address the
// classification was reached on are tested. They differ on a NAT64 network: the
// dial address is IPv6 while the classification came from the embedded IPv4.
// An operator writing SBOMHUB_EGRESS_ALLOWED_INTERNAL=192.168.0.0/16 is
// thinking in IPv4, and matching only the outer address would leave that
// exemption silently ineffective — pushing them toward the blanket
// ALLOW_PRIVATE switch instead (Codex round 5, Low).
func (p Policy) privateAllowedForAddr(host string, addr, effective netip.Addr) bool {
	if p.privateAllowedForHost(host) {
		return true
	}
	probes := []netip.Addr{addr.WithZone("").Unmap()}
	if eff := effective.WithZone("").Unmap(); eff.IsValid() && eff != probes[0] {
		probes = append(probes, eff)
	}
	for _, cidr := range p.PrivateCIDRExemptions {
		// Prefixes reaching a Guard have been through normalisePrefix, but a
		// Policy can also be built in code (tests, future callers), so normalise
		// defensively rather than silently never matching.
		norm, err := normalisePrefix(cidr)
		if err != nil {
			continue
		}
		for _, probe := range probes {
			if norm.Contains(probe) {
				return true
			}
		}
	}
	return false
}

// hostAllowed reports whether the hostname passes the AllowedHosts allowlist.
func (p Policy) hostAllowed(host string) bool {
	if len(p.AllowedHosts) == 0 {
		return true
	}
	return hostMatches(host, p.AllowedHosts)
}

// hostMatches reports whether host equals, or is a subdomain of, any entry.
//
// The subdomain test compares against "."+entry so that "notgithub.com" does
// not match the entry "github.com" — the trap a bare strings.HasSuffix walks
// into.
func hostMatches(host string, entries []string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, e := range entries {
		d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(e), "."))
		if d == "" {
			continue
		}
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// ParseExemptions splits an operator-supplied comma/whitespace separated list
// into CIDR prefixes and hostnames. A bare IP address is accepted and becomes a
// single-address prefix.
//
// Entries that parse as neither are returned in the error: silently dropping a
// mistyped exemption would leave the operator believing they had opened a path
// that is still closed, which is the failure mode that makes people disable the
// guard wholesale.
func ParseExemptions(raw string) (hosts []string, cidrs []netip.Prefix, err error) {
	var bad []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		entry := strings.TrimSpace(field)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, perr := netip.ParsePrefix(entry)
			if perr != nil {
				bad = append(bad, entry)
				continue
			}
			normalised, nerr := normalisePrefix(prefix)
			if nerr != nil {
				bad = append(bad, entry)
				continue
			}
			cidrs = append(cidrs, normalised)
			continue
		}
		if addr, aerr := netip.ParseAddr(entry); aerr == nil {
			cidrs = append(cidrs, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(entry, "."))
		if !isPlausibleHostname(name) {
			bad = append(bad, entry)
			continue
		}
		hosts = append(hosts, name)
	}
	if len(bad) > 0 {
		return nil, nil, fmt.Errorf("egress: not an IP address, CIDR or hostname: %s", strings.Join(bad, ", "))
	}
	return hosts, cidrs, nil
}

// isPlausibleHostname reports whether name has DNS-label shape.
//
// Codex round 4 (Low): the previous check only refused entries containing URL
// punctuation, so ".", "*", "foo..bar" and "-lead" were accepted as exemptions,
// silently matched nothing, and left the operator believing they had opened a
// path. Single-label names are deliberately accepted — internal hosts routinely
// have no dot — and the underscore is accepted because internal DNS and service
// records use it in practice.
func isPlausibleHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// normalisePrefix converts an IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/N) into
// the equivalent IPv4 prefix, and masks the result.
//
// Codex round 1 (Low): without this, an operator writing
// "::ffff:10.0.0.0/104" got a prefix that netip.Prefix.Contains can never match,
// because the addresses it is compared against are unmapped before the test and
// Contains does not cross address families. The exemption silently did nothing —
// the worst shape for an opt-in, because the operator's next move is to give up
// on the narrow switch and set SBOMHUB_EGRESS_ALLOW_PRIVATE instead.
//
// A mapped prefix shorter than /96 spans more than the IPv4 space, so there is
// no IPv4 prefix it is equivalent to; it is rejected rather than reinterpreted.
func normalisePrefix(p netip.Prefix) (netip.Prefix, error) {
	if !p.Addr().Is4In6() {
		return p.Masked(), nil
	}
	if p.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("egress: IPv4-mapped prefix %s is shorter than /96 and spans more than the IPv4 space", p)
	}
	return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked(), nil
}

// clonePolicy deep-copies a Policy's slices.
//
// Codex round 1 (Low): a Guard shallow-copied the Policy it was constructed
// with, so the caller kept a live handle on the backing arrays of AllowedHosts
// and the exemption lists. Mutating them afterwards changed live policy — and,
// because a Guard is shared across request goroutines, did so as a data race.
func clonePolicy(p Policy) Policy {
	out := p
	if p.PrivateHostExemptions != nil {
		out.PrivateHostExemptions = append([]string(nil), p.PrivateHostExemptions...)
	}
	if p.AllowedHosts != nil {
		out.AllowedHosts = append([]string(nil), p.AllowedHosts...)
	}
	if p.PrivateCIDRExemptions != nil {
		out.PrivateCIDRExemptions = append([]netip.Prefix(nil), p.PrivateCIDRExemptions...)
	}
	if p.NAT64Prefixes != nil {
		out.NAT64Prefixes = append([]netip.Prefix(nil), p.NAT64Prefixes...)
	}
	return out
}
