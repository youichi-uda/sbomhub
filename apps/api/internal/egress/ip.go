package egress

import (
	"fmt"
	"net/netip"
)

// Class is the destination category an IP address falls into.
//
// The split into three (rather than the usual private/public boolean) exists
// because the two things an operator wants are different questions:
//
//   - "may this deployment talk to RFC1918 / loopback at all?" — a genuine
//     product decision. A self-hosted SBOMHub sitting next to an internal Jira
//     or an Ollama node has to be able to say yes.
//   - "may this deployment talk to the cloud metadata endpoint?" — never a
//     product decision. 169.254.169.254 is not an issue tracker.
//
// ClassPrivate answers the first, ClassBlocked the second.
type Class int

const (
	// ClassPublic is a globally routable destination: always permitted by IP
	// policy (a hostname allowlist may still reject it).
	ClassPublic Class = iota
	// ClassPrivate is an internal-but-plausible destination (RFC1918, loopback,
	// CGNAT, IPv6 ULA). Permitted only when the policy opts in.
	ClassPrivate
	// ClassBlocked is a destination with no legitimate use as an HTTP endpoint
	// for tenant-configured egress. Never permitted, by any policy.
	ClassBlocked
)

func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassPrivate:
		return "private"
	case ClassBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

// classifiedPrefix pairs a CIDR with the human-readable reason reported when a
// destination lands in it. The reason is echoed to tenant admins (it is
// self-authored and carries no remote content), so it is written to be
// actionable rather than merely accurate.
type classifiedPrefix struct {
	prefix netip.Prefix
	reason string
}

// blockedPrefixes are destinations that are refused regardless of policy.
//
// Every entry is here because it is either (a) an address with a special
// meaning to the host's own network stack, or (b) an address family whose only
// realistic use in an SSRF payload is to reach something the tenant should not
// reach. Sources: RFC 6890 (special-purpose registries), RFC 3927 / RFC 4291
// (link-local), RFC 7526 (6to4 deprecated), RFC 6052 (NAT64).
//
// Link-local (169.254.0.0/16, fe80::/10) is the load-bearing entry: it covers
// the AWS/GCP/Azure/Alibaba instance metadata service at 169.254.169.254. The
// metadata endpoints that are NOT link-local are listed separately below,
// because those are the ones a range-based rule would miss.
var blockedPrefixes = []classifiedPrefix{
	// --- IPv4 ---
	{netip.MustParsePrefix("0.0.0.0/8"), "this-network / unspecified (RFC 6890) — resolves to the local host on most stacks"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local — this range carries the cloud instance metadata service (169.254.169.254)"},
	// 192.0.0.0/24 is blocked as a block rather than entry by entry. Two of its
	// addresses — 192.0.0.9 (PCP anycast, RFC 7723) and 192.0.0.10 (TURN
	// anycast, RFC 8155) — ARE globally routable, so this is deliberately
	// broader than "non-global" (Codex round 3, Low). Neither is an HTTP
	// endpoint, and neither is a plausible issue tracker, webhook receiver or
	// LLM endpoint, so the false-positive cost is nil while the alternative —
	// enumerating the non-global assignments and re-checking them against the
	// IANA registry over time — is a maintenance burden with no benefit.
	{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments (RFC 6890) — includes the NAT64 discovery and protocol anycast addresses"},
	{netip.MustParsePrefix("192.0.2.0/24"), "TEST-NET-1 documentation range (RFC 5737)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking range (RFC 2544)"},
	{netip.MustParsePrefix("198.51.100.0/24"), "TEST-NET-2 documentation range (RFC 5737)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "TEST-NET-3 documentation range (RFC 5737)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "reserved for future use (RFC 1112) — includes the 255.255.255.255 broadcast address"},
	{netip.MustParsePrefix("192.88.99.0/24"), "6to4 relay anycast (RFC 7526, deprecated)"},

	// --- Cloud metadata endpoints that are NOT link-local ---
	//
	// These are the whole reason this table exists separately from
	// privatePrefixes. Each sits inside a range an operator may legitimately
	// want to open — or looks routable — so classifying them by range alone
	// would put the instance credential endpoint behind the same switch as the
	// internal Jira. Codex round 1 (High) caught the two that were sitting
	// inside ClassPrivate ranges and were therefore reachable once
	// SBOMHUB_EGRESS_ALLOW_PRIVATE was set.
	//
	// Azure's "wireserver" host agent endpoint: routable-looking, answers only
	// from inside an Azure VM.
	{netip.MustParsePrefix("168.63.129.16/32"), "Azure platform host agent (wireserver)"},
	// Alibaba Cloud metadata. Inside 100.64.0.0/10 (CGNAT), which is a
	// ClassPrivate range.
	{netip.MustParsePrefix("100.100.100.200/32"), "Alibaba Cloud instance metadata"},

	// --- IPv6 ---
	{netip.MustParsePrefix("::/128"), "unspecified address"},
	{netip.MustParsePrefix("100::/64"), "discard-only prefix (RFC 6666)"},
	// 2001::/23 is the IETF Protocol Assignments block in its entirety, blocked
	// as one range rather than sub-allocation by sub-allocation (Codex round 4,
	// Low). It contains Teredo (2001::/32, which encapsulates an operator-chosen
	// IPv4 destination), IPv6 benchmarking (2001:2::/48), AMT, AS112-v6, and
	// several anycast addresses — a mixture of globally routable and not, whose
	// membership changes as IANA allocates. None of them is an HTTP endpoint a
	// tenant would configure as an issue tracker or webhook receiver, so the
	// blanket rule is the right call TODAY — it is a deliberate policy
	// trade-off, not a permanently safe one (Codex round 5, Low, corrected an
	// earlier claim that it "does not need re-checking"). Anyone editing this
	// table should re-read the IANA special-purpose registry for this range.
	// Global unicast allocated to RIRs starts at 2001:200::/23, well clear of
	// this.
	{netip.MustParsePrefix("2001::/23"), "IETF protocol assignments (RFC 2928) — includes Teredo, which encapsulates an operator-chosen IPv4 destination"},
	{netip.MustParsePrefix("2001:db8::/32"), "documentation range (RFC 3849)"},
	{netip.MustParsePrefix("3fff::/20"), "IPv6 documentation range (RFC 9637)"},
	{netip.MustParsePrefix("5f00::/16"), "locally scoped SRv6 SIDs (RFC 9602)"},
	{netip.MustParsePrefix("fe80::/10"), "IPv6 link-local"},
	{netip.MustParsePrefix("fec0::/10"), "deprecated IPv6 site-local (RFC 3879)"},
	{netip.MustParsePrefix("ff00::/8"), "IPv6 multicast"},
	// AWS IMDS over IPv6. Inside fc00::/7 (unique local), which is a
	// ClassPrivate range — Codex round 1 (High).
	{netip.MustParsePrefix("fd00:ec2::254/128"), "AWS instance metadata service over IPv6"},
	// Google Cloud metadata over IPv6, likewise inside fc00::/7 — Codex round 4
	// (Low).
	{netip.MustParsePrefix("fd20:ce::254/128"), "Google Cloud instance metadata over IPv6"},
	// 64:ff9b:1::/48 is the LOCAL-USE IPv4/IPv6 translation prefix (RFC 8215).
	// Unlike the well-known /96 below it is technology-agnostic: the embedded
	// IPv4 address may sit at any of several offsets, so there is no correct
	// way to decode and judge it. Blocked outright rather than classified as
	// ordinary public IPv6 — Codex round 1 (Medium).
	//
	// This is a real cost, not a free win (Codex round 3, Low): an IPv6-only
	// deployment that reaches the IPv4 internet through a NAT64 using this
	// prefix cannot use any guarded sink, and no setting re-opens it. Making it
	// ClassPrivate instead would be worse — an opaque layout could translate to
	// the metadata address, and the operator opt-in would then hand that over.
	// Documented as a limitation in docs/security/egress.md §5 rather than
	// papered over with another switch.
	{netip.MustParsePrefix("64:ff9b:1::/48"), "local-use IPv4/IPv6 translation prefix (RFC 8215) — embedded destination is not decodable"},
	{netip.MustParsePrefix("100:0:0:1::/64"), "dummy prefix (RFC 9780)"},
}

// privatePrefixes are internal destinations that a self-hosted operator may
// legitimately want to reach and that are therefore gated on policy rather
// than refused outright.
var privatePrefixes = []classifiedPrefix{
	{netip.MustParsePrefix("10.0.0.0/8"), "RFC 1918 private range"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT range (RFC 6598)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "IPv4 loopback"},
	{netip.MustParsePrefix("172.16.0.0/12"), "RFC 1918 private range"},
	{netip.MustParsePrefix("192.168.0.0/16"), "RFC 1918 private range"},
	{netip.MustParsePrefix("::1/128"), "IPv6 loopback"},
	{netip.MustParsePrefix("fc00::/7"), "IPv6 unique local address"},
}

// nat64Prefix is the well-known NAT64 prefix (RFC 6052 §2.1). An address in it
// is a wrapper around an IPv4 destination in its low 32 bits, so it is
// classified by that embedded address rather than as an opaque IPv6 address —
// otherwise 64:ff9b::a9fe:a9fe would sail past every IPv4 rule above.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// NAT64PrefixLengths are the prefix lengths RFC 6052 §2.2 defines for
// IPv4-embedded IPv6 addresses. The embedded IPv4 address sits at a different
// offset for each, and the octet at bits 64..72 is reserved (u == 0).
var NAT64PrefixLengths = []int{32, 40, 48, 56, 64, 96}

// ValidateNAT64Prefix reports whether p is usable as an RFC 6052 translation
// prefix — i.e. whether nat64Embedded can decode addresses under it.
//
// Codex round 4 (Medium): only the well-known /96 was decoded, so a deployment
// using its own NAT64 prefix (RFC 6052 permits /32, /40, /48, /56, /64 and /96)
// had every IPv4 rule in this file quietly bypassed for translated traffic —
// an address under a custom prefix looked like ordinary public IPv6. RFC 6052
// §5 says exactly this: filtering applied to IPv4 must also be applied to the
// embedded addresses. Operators declare their prefix with
// SBOMHUB_EGRESS_NAT64_PREFIXES.
func ValidateNAT64Prefix(p netip.Prefix) error {
	if !p.Addr().Is6() || p.Addr().Is4In6() {
		return fmt.Errorf("egress: NAT64 prefix %s is not an IPv6 prefix", p)
	}
	lengthOK := false
	for _, bits := range NAT64PrefixLengths {
		if p.Bits() == bits {
			lengthOK = true
			break
		}
	}
	if !lengthOK {
		return fmt.Errorf("egress: NAT64 prefix %s has length /%d; RFC 6052 defines /32, /40, /48, /56, /64 and /96", p, p.Bits())
	}

	base := p.Masked().Addr()

	// RFC 6052 §2.2: bits 64..71 (byte 8, the "u" octet) MUST be zero. For a
	// /96 that octet is inside the prefix, so the PREFIX itself has to carry a
	// zero there — Codex round 5 (Medium). For the shorter lengths the octet is
	// outside the prefix and is checked per address in nat64Embedded.
	if p.Bits() == 96 && base.As16()[8] != 0 {
		return fmt.Errorf("egress: NAT64 prefix %s has a non-zero octet at bits 64..71; RFC 6052 requires it to be zero", p)
	}

	// The three fixed embedding formats already have RFC-defined semantics and
	// are decoded ahead of declared prefixes, so a declaration overlapping one
	// would silently do nothing. Checked before the blocked-range test below so
	// that declaring the well-known prefix reports the actionable reason rather
	// than an artefact of decoding its all-zero base.
	for _, fixed := range []netip.Prefix{nat64Prefix, sixToFourPrefix, ipv4CompatiblePrefix} {
		if p.Overlaps(fixed) {
			return fmt.Errorf("egress: NAT64 prefix %s overlaps the built-in translation prefix %s, which is always decoded; remove the declaration", p, fixed)
		}
	}

	// A declared prefix must not be able to re-open something the fixed tables
	// refuse absolutely — Codex round 5 (Medium). Before this check, declaring
	// 64:ff9b:1::/48 (or fe80::/64, or any prefix inside 2001::/23) made every
	// address under it decode to its embedded IPv4 and, when that IPv4 was
	// public, classify as ClassPublic — which contradicts the invariant that no
	// policy re-enables ClassBlocked.
	if class, reason := classifyFixed(base); class == ClassBlocked {
		return fmt.Errorf("egress: NAT64 prefix %s is inside a permanently blocked range (%s) and cannot be declared as a translation prefix", p, reason)
	}
	if base.IsLoopback() {
		return fmt.Errorf("egress: NAT64 prefix %s is a loopback prefix", p)
	}
	return nil
}

// nat64Embedded extracts the IPv4 address an RFC 6052 §2.2 translation address
// carries, for a prefix of the given length. Byte 8 is the reserved "u" octet
// and is skipped by every layout that spans it.
//
// It reports false when the address is not a well-formed RFC 6052 translated
// address — specifically when the u-octet is non-zero (Codex round 5, Medium).
// The caller then falls through to the ordinary tables rather than trusting a
// decode, which matters for a declared prefix inside ULA: a native (untranslated)
// host in that network with a "public-looking" value at the embedded offsets
// would otherwise have been classified public and escaped the private gate.
func nat64Embedded(addr netip.Addr, prefixBits int) (netip.Addr, bool) {
	b := addr.As16()
	if b[8] != 0 {
		return netip.Addr{}, false
	}
	switch prefixBits {
	case 32:
		return netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), true
	case 40:
		return netip.AddrFrom4([4]byte{b[5], b[6], b[7], b[9]}), true
	case 48:
		return netip.AddrFrom4([4]byte{b[6], b[7], b[9], b[10]}), true
	case 56:
		return netip.AddrFrom4([4]byte{b[7], b[9], b[10], b[11]}), true
	case 64:
		return netip.AddrFrom4([4]byte{b[9], b[10], b[11], b[12]}), true
	case 96:
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// sixToFourPrefix is the 6to4 prefix (RFC 3056, deprecated by RFC 7526). Bits
// 16..48 hold an IPv4 address; same reasoning as nat64Prefix.
var sixToFourPrefix = netip.MustParsePrefix("2002::/16")

// ipv4CompatiblePrefix is the deprecated "IPv4-compatible IPv6" form
// (::a.b.c.d, RFC 4291 §2.5.5.1). ::ffff:a.b.c.d (IPv4-mapped) is handled by
// Unmap() before this is consulted.
var ipv4CompatiblePrefix = netip.MustParsePrefix("::/96")

// Classify reports which Class an address belongs to, together with a reason
// string suitable for surfacing to the tenant admin who configured it.
//
// The address is unmapped first, so ::ffff:169.254.169.254 and 169.254.169.254
// classify identically. Tunnel/translation forms that embed an IPv4 address
// (NAT64, 6to4, IPv4-compatible) are decoded and classified by the address
// they embed — an embedded public address stays public, an embedded metadata
// address is blocked.
func Classify(addr netip.Addr) (Class, string) {
	class, reason, _ := ClassifyDetailed(addr, nil)
	return class, reason
}

// ClassifyWith is Classify with additional operator-declared RFC 6052 NAT64
// translation prefixes. Addresses under one of those prefixes are decoded and
// classified by the IPv4 address they embed, exactly as the well-known
// 64:ff9b::/96 already is.
func ClassifyWith(addr netip.Addr, nat64Prefixes []netip.Prefix) (Class, string) {
	class, reason, _ := ClassifyDetailed(addr, nat64Prefixes)
	return class, reason
}

// ClassifyDetailed additionally returns the EFFECTIVE address the verdict was
// reached on — the embedded IPv4 address for a translated form, and the input
// otherwise.
//
// Callers need it because a CIDR exemption an operator writes is about the
// address they think in terms of. On a NAT64 network the dial address is IPv6
// while the operator's internal network is IPv4, so an exemption of
// 192.168.0.0/16 has to be testable against the embedded 192.168.1.1 and not
// only against the outer 2001:db8::c0a8:101 (Codex round 5, Low).
//
// Evaluation order, and why:
//
//  1. The permanently-blocked tables. Nothing an operator declares may re-open
//     these, so they come before any declaration is consulted (Codex round 5,
//     Medium — declared prefixes used to run first and could turn a blocked
//     address into ClassPublic by decoding it).
//  2. The three fixed embedding formats (well-known NAT64, 6to4,
//     IPv4-compatible), whose semantics are defined by RFC and not by an
//     operator.
//  3. Operator-declared NAT64 prefixes.
//  4. The private tables, then netip's own predicates as a backstop.
//  5. IPv6 outside the delegated global-unicast range 2000::/3.
func ClassifyDetailed(addr netip.Addr, nat64Prefixes []netip.Prefix) (Class, string, netip.Addr) {
	if !addr.IsValid() {
		return ClassBlocked, "not a valid IP address", addr
	}
	// Strip the zone before prefix matching: netip.Prefix.Contains reports
	// false for any address carrying a zone, which would silently turn
	// fe80::1%eth0 into "public".
	addr = addr.WithZone("").Unmap()

	// (1) Absolute refusals first.
	for _, p := range blockedPrefixes {
		if p.prefix.Contains(addr) {
			return ClassBlocked, p.reason, addr
		}
	}

	if addr.Is6() {
		// (2) Fixed embedding formats.
		if inner, preservesDestination, ok := embeddedIPv4(addr); ok {
			// The effective address is only propagated when the embedded IPv4
			// address IS the destination. For 6to4 it is the RELAY's address, so
			// reporting it would let an exemption written for one IPv4 host widen
			// to the whole /48 routed through that relay — Codex round 6 (Low).
			effective := addr
			if preservesDestination {
				effective = inner
			}
			class, reason, _ := ClassifyDetailed(inner, nil)
			if class == ClassPublic {
				return ClassPublic, "", effective
			}
			return class, reason + " (reached via an IPv6 address embedding " + inner.String() + ")", effective
		}
		// (3) Operator-declared translation prefixes. An operator who says
		// "this /48 is my NAT64" is describing their own network, and the
		// embedded address is the real destination.
		//
		// A malformed translated address (non-zero u-octet) does NOT match:
		// nat64Embedded reports false and the address falls through to the
		// tables below, so a native host inside a declared ULA prefix keeps its
		// private classification.
		//
		// EVERY matching declaration is evaluated, and disagreement is resolved
		// fail-closed — Codex rounds 7 and 8 (Medium).
		//
		// Overlapping declarations of different lengths decode different embedded
		// addresses from the same input (a /32 and a /40 covering one address read
		// the IPv4 octets from different offsets). A first-match loop therefore
		// made the verdict depend on the order the operator happened to list them
		// in. Two things follow from that:
		//
		//   - if the decodes DISAGREE about the destination at all, the address is
		//     ambiguous and is refused. Round 8 caught that taking merely the most
		//     restrictive CLASS was not enough: two readings can both be
		//     ClassPrivate while naming different addresses, and the effective
		//     address is what a narrow CIDR exemption is matched against — so the
		//     ordering still decided whether an exemption applied.
		//   - if they agree, the single verdict is used.
		//
		// Overlapping declarations are also refused at startup
		// (cmd/server.parseNAT64Prefixes); this is the defence in depth for a
		// caller that assembles a Policy directly.
		var (
			worst          = ClassPublic
			worstReason    string
			worstEffective = addr
			decoded        netip.Addr
			ambiguous      bool
			matched        bool
		)
		for _, p := range nat64Prefixes {
			// Every declared prefix is re-validated here rather than trusted —
			// Codex round 6 (Medium). The production path validates at startup
			// (cmd/server.parseNAT64Prefixes), but this function is exported, and
			// an unvalidated prefix could otherwise defeat the (5) rule below:
			// declaring 4000::/32 would decode 4000:0:808:808:: to 8.8.8.8 and
			// return ClassPublic for an address that is ClassBlocked with a nil
			// list. The invariant "no declaration re-opens ClassBlocked" has to
			// hold for callers of this function, not only for the wiring above it.
			//
			// The cost is nil for the overwhelmingly common case: the list is
			// empty, so this loop does not run at all.
			if !p.Contains(addr) || ValidateNAT64Prefix(p) != nil {
				continue
			}
			inner, ok := nat64Embedded(addr, p.Bits())
			if !ok {
				continue
			}
			if matched && inner != decoded {
				ambiguous = true
			}
			class, reason, _ := ClassifyDetailed(inner, nil)
			if !matched || class > worst {
				worst = class
				worstReason = reason
				worstEffective = inner
			}
			if !matched {
				decoded = inner
			}
			matched = true
		}
		switch {
		case ambiguous:
			return ClassBlocked,
				"overlapping declared NAT64 prefixes decode this address to different destinations, so it cannot be judged",
				addr
		case matched:
			if worst == ClassPublic {
				return ClassPublic, "", worstEffective
			}
			return worst, worstReason + " (reached via a declared NAT64 prefix, which embeds " + worstEffective.String() + ")", worstEffective
		}
	}

	// (4) Policy-gated internal ranges.
	for _, p := range privatePrefixes {
		if p.prefix.Contains(addr) {
			return ClassPrivate, p.reason, addr
		}
	}
	// Backstop for anything the tables above miss. netip's own predicates are
	// consulted after the tables on purpose: the tables carry the reason
	// strings and are the reviewable statement of policy, while these catch
	// address forms a future Go release may recognise before this list is
	// updated.
	switch {
	case addr.IsUnspecified():
		return ClassBlocked, "unspecified address", addr
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast(), addr.IsLinkLocalMulticast():
		return ClassBlocked, "multicast", addr
	case addr.IsLinkLocalUnicast():
		return ClassBlocked, "link-local", addr
	case addr.IsLoopback():
		return ClassPrivate, "loopback", addr
	case addr.IsPrivate():
		return ClassPrivate, "private range", addr
	}

	// (5) IPv6 outside 2000::/3 is not delegated for global unicast at all, so
	// an address there is either reserved by the IETF or locally invented
	// (Codex round 5, Low). 2000::/3 is the stable delegation boundary, so this
	// rule needs no maintenance as IANA allocates inside it. Every legitimate
	// non-global form that lives outside 2000::/3 — ULA, link-local, multicast,
	// loopback, the well-known NAT64 prefix — has already been classified above.
	//
	// NOTE the deliberate gap: unallocated space INSIDE 2000::/3 (3000::/5 and
	// friends) still classifies as ClassPublic. Enumerating IANA's allocations
	// within 2000::/3 would go stale, and a stale allowlist is worse than this
	// gap. It is listed in docs/security/egress.md §5.
	if addr.Is6() && !globalUnicastV6.Contains(addr) {
		return ClassBlocked, "outside the delegated IPv6 global unicast range 2000::/3 (reserved or locally assigned)", addr
	}

	return ClassPublic, "", addr
}

// globalUnicastV6 is the range IANA delegates IPv6 global unicast from.
var globalUnicastV6 = netip.MustParsePrefix("2000::/3")

// classifyFixed classifies an address using only the rules an operator cannot
// influence. Used by ValidateNAT64Prefix to refuse a declaration that would
// otherwise re-open a permanently blocked range.
func classifyFixed(addr netip.Addr) (Class, string) {
	class, reason, _ := ClassifyDetailed(addr, nil)
	return class, reason
}

// embeddedIPv4 extracts the IPv4 address carried inside an IPv6 tunnel or
// translation address, if the address is one of the forms that carries one.
// The second return value reports whether the embedded address is the
// DESTINATION (NAT64, IPv4-compatible) or merely the relay that carries the
// traffic (6to4). Both are classified by the embedded address — reaching a 6to4
// address whose relay is internal does reach something internal — but only a
// destination-preserving form may be used to match a CIDR exemption, since an
// exemption naming one relay host would otherwise widen to every address routed
// through it.
func embeddedIPv4(addr netip.Addr) (inner netip.Addr, preservesDestination, ok bool) {
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true, true
	case sixToFourPrefix.Contains(addr):
		// RFC 3056: bits 16..48 hold the 6to4 ROUTER's IPv4 address, not the
		// address of the host being talked to.
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), false, true
	case ipv4CompatiblePrefix.Contains(addr):
		// ::0.0.0.0 (unspecified) and ::0.0.0.1 (loopback) are inside ::/96 but
		// are not IPv4-compatible addresses; leave them to the prefix tables so
		// they keep their own reason strings.
		if addr.IsUnspecified() || addr.IsLoopback() {
			return netip.Addr{}, false, false
		}
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true, true
	}
	return netip.Addr{}, false, false
}
