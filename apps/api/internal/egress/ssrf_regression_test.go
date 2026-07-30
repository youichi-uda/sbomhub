package egress

// ssrf_regression_test.go — the M50 SSRF regression suite.
//
// Every test here exists because a specific defect was found and fixed, and each
// one is written so that reverting its fix makes it FAIL (verified by reverting
// each fix in turn against this file). The "Codex round N" markers name the
// review round that surfaced the defect; they are kept because they are the only
// record of WHY a rule that looks arbitrary — the u-octet check, the 2000::/3
// backstop, the ambiguity refusal — is there at all.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Codex round 1, High: environment proxy bypasses the dialer -------------
//
// With Proxy set, Go hands DialContext the PROXY address, not the destination.
// The guard then approves the proxy and the proxy connects wherever the URL
// says — so a policy-refused destination is reached over a connection the
// guard blessed.

func TestGuard_TenantPolicyDoesNotUseAnEnvironmentProxy(t *testing.T) {
	g := New(testPolicy("test"))
	if g.Transport().Proxy != nil {
		t.Error("tenant-purpose guards must not consult a proxy: the dialer would only ever see the proxy's address, and the proxy would choose the real destination")
	}
}

func TestGuard_ProxyReachesRefusedDestination(t *testing.T) {
	var internalHits atomic.Int32
	internal := newServerOn(t, "127.0.0.1", func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	// A minimal forward proxy: it receives an absolute-URI request and fetches
	// the target itself. This is what an operator's HTTP_PROXY does.
	proxy := newServerOn(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(r.URL.String()) //nolint:noctx,gosec // stands in for a forward proxy
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
	})

	p := testPolicy("test")
	// Exempt only the proxy's address, as an operator's routable proxy would be.
	p.PrivateCIDRExemptions = []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}
	g := New(p)

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	tr := g.Transport().Clone()
	tr.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: g.CheckRedirect}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, internal.URL, nil)
	resp, derr := client.Do(req)
	if derr == nil {
		_ = resp.Body.Close()
	}
	// Demonstration half: with a proxy in the path, the guard approved the
	// proxy's address and the proxy went on to reach a destination the same
	// policy refuses. If this ever stops happening the test has stopped
	// demonstrating the thing it exists to justify.
	if n := internalHits.Load(); n != 1 {
		t.Fatalf("the proxy reached the refused destination %d time(s), want 1 — this test no longer demonstrates why Proxy is disabled", n)
	}
	// Assertion half: the shipped configuration must therefore not hand out a
	// proxy-using transport at all.
	if g.Transport().Proxy != nil {
		t.Error("guard transport still consults a proxy")
	}
}

// --- Codex round 1, High: URL-level policy on the INITIAL request -----------
//
// CheckRedirect only fires on redirects. Without a RoundTripper-level check,
// scheme and hostname-allowlist rules apply only if the caller happened to run
// ValidateURL first — which makes the guarantee depend on every call site.

func TestGuard_ClientEnforcesSchemeOnInitialRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	addr := netip.MustParseAddr(host)

	// https-only policy, with the address exempted so only the SCHEME can
	// refuse the request.
	p := Policy{
		Purpose:               "https-only",
		AllowPlaintextHTTP:    false,
		MaxRedirects:          3,
		PrivateCIDRExemptions: []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())},
	}
	resp, err := New(p).Client(5 * time.Second).Get(srv.URL) //nolint:noctx // exercised via Client
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the client to refuse a plaintext http:// initial request under an https-only policy")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("expected ErrBlockedDestination, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server was reached %d time(s) despite the https-only policy", n)
	}
}

func TestGuard_ClientEnforcesAllowedHostsOnInitialRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resolver := &stubResolver{table: map[string][]string{
		"evil.example.test": {"127.0.0.1"},
	}}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	p := Policy{
		Purpose:               "allowlist",
		AllowPlaintextHTTP:    true,
		MaxRedirects:          3,
		AllowedHosts:          []string{"github.com"},
		PrivateCIDRExemptions: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	g := New(p).WithResolver(resolver)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://evil.example.test:"+port+"/", nil)
	resp, err := g.Client(5 * time.Second).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the client to refuse a host outside the allowlist on the initial request")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("expected ErrBlockedDestination, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server was reached %d time(s) despite the hostname allowlist", n)
	}
}

// --- Codex round 1, High: metadata endpoints hiding inside private ranges ---

func TestClassify_CloudMetadataInsidePrivateRangesIsBlocked(t *testing.T) {
	// Each of these sits inside a range this package otherwise treats as
	// ClassPrivate, so an operator opting into internal destinations would have
	// opened them. They are cloud metadata endpoints; the package's stated rule
	// is that metadata is never an opt-in.
	cases := map[string]string{
		"100.100.100.200": "Alibaba Cloud metadata (inside 100.64.0.0/10 CGNAT)",
		"fd00:ec2::254":   "AWS IMDS over IPv6 (inside fc00::/7 ULA)",
	}
	for addrStr, why := range cases {
		addr := netip.MustParseAddr(addrStr)
		if got, _ := Classify(addr); got != ClassBlocked {
			t.Errorf("Classify(%s) = %v, want ClassBlocked — %s", addrStr, got, why)
		}
	}
}

func TestGuard_AllowPrivateDoesNotOpenIPv6Metadata(t *testing.T) {
	p := testPolicy("selfhost")
	p.AllowPrivate = true
	g := New(p)
	for _, target := range []string{"[fd00:ec2::254]:80", "100.100.100.200:80"} {
		if _, err := g.DialContext(context.Background(), "tcp", target); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("DialContext(%q) with AllowPrivate = %v, want ErrBlockedDestination", target, err)
		}
	}
}

// --- Codex round 1, Medium: further special-purpose ranges ------------------

func TestClassify_AdditionalSpecialPurposeRanges(t *testing.T) {
	blocked := []string{
		"192.88.99.1",     // 6to4 relay anycast (RFC 7526, deprecated)
		"64:ff9b:1::1",    // local-use IPv4/IPv6 translation (RFC 8215)
		"64:ff9b:1::c000", // same prefix, no universally correct embedded offset
		"100:0:0:1::1",    // dummy prefix (RFC 9780)
		"2001:2::1",       // IPv6 benchmarking (RFC 5180)
		"3fff::1",         // IPv6 documentation (RFC 9637)
		"5f00::1",         // locally scoped SRv6 SIDs (RFC 9602)
		"fec0::1",         // deprecated site-local (RFC 3879)
	}
	for _, s := range blocked {
		addr := netip.MustParseAddr(s)
		if got, _ := Classify(addr); got != ClassBlocked {
			t.Errorf("Classify(%s) = %v, want ClassBlocked", s, got)
		}
	}
}

// --- Codex round 1, Low: inherited TLS dialers / TLS config -----------------

func TestGuard_TransportHasNoInheritedTLSDialer(t *testing.T) {
	tr := New(testPolicy("test")).Transport()
	if tr.DialTLSContext != nil {
		t.Error("DialTLSContext must be nil, or HTTPS skips the guarded DialContext entirely")
	}
	if tr.DialTLS != nil { //nolint:staticcheck // deprecated field, checked precisely because Go still honours it
		t.Error("DialTLS must be nil, or HTTPS skips the guarded DialContext entirely")
	}
	if tr.TLSClientConfig != nil {
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must not be inherited")
		}
		if tr.TLSClientConfig.ServerName != "" {
			t.Error("a pinned ServerName must not be inherited — it would override SNI for every destination")
		}
	}
}

// TestGuard_TransportIsNotDerivedFromDefaultTransport guards the inheritance
// path itself: a process that customises http.DefaultTransport (a library
// init(), a test helper) must not be able to change what this package dials
// through.
func TestGuard_TransportIsNotDerivedFromDefaultTransport(t *testing.T) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Skip("http.DefaultTransport is not a *http.Transport in this Go release")
	}
	saved := base.Proxy
	t.Cleanup(func() { base.Proxy = saved })

	sentinel := func(*http.Request) (*url.URL, error) { return url.Parse("http://sentinel.invalid") }
	base.Proxy = sentinel

	if New(testPolicy("test")).Transport().Proxy != nil {
		t.Error("guard transport picked up a mutation of http.DefaultTransport")
	}
}

// --- Codex round 1, Low: IPv4-mapped CIDR exemptions ------------------------

func TestParseExemptions_NormalisesMappedIPv4Prefixes(t *testing.T) {
	_, cidrs, err := ParseExemptions("::ffff:10.0.0.0/104")
	if err != nil {
		t.Fatalf("ParseExemptions: %v", err)
	}
	if len(cidrs) != 1 {
		t.Fatalf("cidrs = %v, want 1", cidrs)
	}
	if !cidrs[0].Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Errorf("exemption %s does not contain 10.0.0.1 — a mapped prefix never matches an unmapped address", cidrs[0])
	}
}

func TestParseExemptions_RejectsShortMappedPrefix(t *testing.T) {
	if _, _, err := ParseExemptions("::ffff:0:0/95"); err == nil {
		t.Error("a mapped prefix shorter than /96 spans more than IPv4 and must be refused rather than silently reinterpreted")
	}
}

// --- Codex round 1, Low: policy slices must not alias caller memory ---------

func TestGuard_PolicySlicesAreCopied(t *testing.T) {
	hosts := []string{"jira.corp.example"}
	allowed := []string{"github.com"}
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}

	// AllowedHosts aliasing, on its own guard.
	gAllowed := New(Policy{
		Purpose:            "test",
		AllowPlaintextHTTP: true,
		AllowedHosts:       allowed,
	})
	allowed[0] = "evil.example"
	if err := gAllowed.ValidateURL("https://evil.example/x"); err == nil {
		t.Error("mutating the caller's AllowedHosts slice changed the guard's allowlist")
	}

	snap := gAllowed.Policy()
	if len(snap.AllowedHosts) > 0 {
		snap.AllowedHosts[0] = "evil.example"
	}
	if err := gAllowed.ValidateURL("https://evil.example/x"); err == nil {
		t.Error("mutating the slice returned by Policy() changed the guard's allowlist")
	}

	// PrivateHostExemptions aliasing, on a guard with NO allowlist — Codex
	// round 3 (Low): with an allowlist present the hostname refusal fired
	// first and masked this, so removing the deep copy of this one slice left
	// the test green.
	gExempt := New(Policy{
		Purpose:               "test",
		AllowPlaintextHTTP:    true,
		PrivateHostExemptions: hosts,
	}).WithResolver(&stubResolver{table: map[string][]string{
		"jira.corp.example": {"10.1.2.3"},
		"evil.example":      {"10.1.2.3"},
	}})
	hosts[0] = "evil.example"
	if _, err := gExempt.DialContext(context.Background(), "tcp", "evil.example:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("mutating the caller's PrivateHostExemptions slice opened a new host: %v", err)
	}
	exemptCtx, exemptCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer exemptCancel()
	if _, err := gExempt.DialContext(exemptCtx, "tcp", "jira.corp.example:80"); errors.Is(err, ErrBlockedDestination) {
		t.Errorf("the originally-exempted host must still pass policy: %v", err)
	}

	// CIDR-exemption aliasing, with no allowlist in the way.
	gCIDR := New(Policy{
		Purpose:               "test",
		AllowPlaintextHTTP:    true,
		PrivateCIDRExemptions: cidrs,
	})
	cidrs[0] = netip.MustParsePrefix("0.0.0.0/0")
	if err := gCIDR.ValidateURL("https://10.99.0.1/x"); err == nil {
		t.Error("mutating the caller's CIDR exemption slice opened a new range")
	}
	if err := gCIDR.ValidateURL("https://10.1.0.1/x"); err != nil {
		t.Errorf("the originally-exempted range must still be permitted: %v", err)
	}
}

// TestGuard_ResolutionFailsAtConnectTimeAfterSucceedingAtValidation reproduces
// the predecessor's fail-open in its exact shape: the validation-time lookup is
// the one that fails, and the connect-time lookup succeeds.
//
// The old isBlockedHost returned false ("not blocked") on a lookup error, so a
// name that NXDOMAINed for the validation lookup and answered 127.0.0.1 for the
// connect lookup passed validation and landed on loopback. Measured with the
// pre-M50 code on 2026-07-30: isBlockedHost("this-name-does-not-resolve-m50
// .invalid") == false.
//
// Codex round 3 (Low) noted TestGuard_ResolutionFailureIsRefused only covers a
// single failed lookup; this covers the two-lookup sequence.
func TestGuard_ResolutionFailsAtValidationThenSucceedsAtConnect(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))

	resolver := &sequenceResolver{answers: [][]string{
		nil,           // lookup 1 (validation time): NXDOMAIN
		{"127.0.0.1"}, // lookup 2 (connect time): loopback
		{"127.0.0.1"}, // and thereafter
	}}
	g := New(testPolicy("test")).WithResolver(resolver)

	target := "http://flaky.example.test:" + port + "/"

	// Step 1: the validation-time lookup fails. The predecessor read that as
	// "not blocked"; ValidateURL does not resolve at all, so it neither passes
	// nor fails on this basis.
	if _, err := resolver.LookupNetIP(context.Background(), "ip", "flaky.example.test"); err == nil {
		t.Fatal("the priming lookup was supposed to fail")
	}
	if err := g.ValidateURL(target); err != nil {
		t.Fatalf("ValidateURL should not depend on resolution: %v", err)
	}

	// Step 2: the connect-time lookup succeeds, and answers loopback.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	resp, err := g.Client(5 * time.Second).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the connect-time answer to be refused")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("err = %v, want ErrBlockedDestination", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the loopback listener was reached %d time(s)", n)
	}
}

// sequenceResolver returns a different answer for each successive lookup; a nil
// entry is a resolution failure.
type sequenceResolver struct {
	answers [][]string
	n       atomic.Int32
}

func (r *sequenceResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	i := int(r.n.Add(1)) - 1
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	answers := r.answers[i]
	if answers == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, 0, len(answers))
	for _, a := range answers {
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}

// --- URL-shape probes -------------------------------------------------------

// TestGuard_ObfuscatedIPLiteralsAreCaughtAtDialTime covers the classic SSRF
// filter-evasion encodings — dotted-hex, bare decimal, and the 4-in-6 bracket
// form.
//
// Only the last is an IP literal as far as netip.ParseAddr is concerned, so the
// first two reach ValidateURL as ordinary hostnames and pass it. Measured with
// net/url on 2026-07-30 (go1.26.4): url.Parse leaves "0x7f.0.0.1" and
// "2130706433" as hostnames. That is fine, and is the reason the enforcement
// point is the dialer: whatever a permissive resolver turns them into is
// classified before anything connects.
func TestGuard_ObfuscatedIPLiteralsAreCaughtAtDialTime(t *testing.T) {
	// A resolver that behaves like a permissive libc and resolves the
	// obfuscated forms to loopback.
	resolver := &stubResolver{table: map[string][]string{
		"0x7f.0.0.1": {"127.0.0.1"},
		"2130706433": {"127.0.0.1"},
	}}
	g := New(testPolicy("test")).WithResolver(resolver)

	for _, host := range []string{"0x7f.0.0.1", "2130706433"} {
		if _, err := g.DialContext(context.Background(), "tcp", host+":80"); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("DialContext(%q) = %v, want ErrBlockedDestination", host, err)
		}
	}

	// The bracketed 4-in-6 form IS a literal and is refused before any lookup.
	if err := g.ValidateURL("http://[::ffff:127.0.0.1]/"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("ValidateURL(4-in-6 loopback) = %v, want ErrBlockedDestination", err)
	}
}

// TestGuard_UserinfoDoesNotDisguiseTheHost pins that the host used for policy is
// the host Go will connect to. Measured with net/url (go1.26.4):
// "https://example.com@127.0.0.1/" has Hostname() == "127.0.0.1", and
// "https://127.0.0.1:80@example.com/" has Hostname() == "example.com".
func TestGuard_UserinfoDoesNotDisguiseTheHost(t *testing.T) {
	g := New(testPolicy("test"))
	if err := g.ValidateURL("http://example.com@127.0.0.1/"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("userinfo before a loopback host must not exempt it: %v", err)
	}
	// The mirror image must NOT be refused: the real host is public.
	if err := g.ValidateURL("http://127.0.0.1:80@example.com/"); err != nil {
		t.Errorf("a loopback-looking userinfo on a public host must not be refused: %v", err)
	}
}

// --- Codex round 4 -----------------------------------------------------------

// TestClassify_CustomNAT64PrefixIsDecoded is the round-4 (Medium) regression.
//
// RFC 6052 §2.2 defines six translation-prefix lengths. Only the well-known /96
// was decoded, so a deployment using its own NAT64 prefix had every IPv4 rule in
// ip.go bypassed for translated traffic: the address looked like ordinary public
// IPv6 and was permitted.
//
// Byte layouts checked against RFC 6052 §2.2 Figure 1. The reserved "u" octet at
// bits 64..72 is skipped by every layout that spans it.
func TestClassify_CustomNAT64PrefixIsDecoded(t *testing.T) {
	cases := []struct {
		prefix string
		addr   string
		class  Class
		note   string
	}{
		// 2a01:4f8::/32 embeds the IPv4 address in bytes 4..8.
		{"2a01:4f8::/32", "2a01:4f8:a9fe:a9fe::", ClassBlocked, "/32 -> 169.254.169.254"},
		{"2a01:4f8::/32", "2a01:4f8:c0a8:101::", ClassPrivate, "/32 -> 192.168.1.1"},
		{"2a01:4f8::/32", "2a01:4f8:808:808::", ClassPublic, "/32 -> 8.8.8.8"},
		// /40 embeds bytes 5,6,7 then 9 (byte 8 is the reserved u octet).
		{"2a01:4f8:aa00::/40", "2a01:4f8:aaa9:fea9:fe::", ClassBlocked, "/40 -> 169.254.169.254"},
		// /48 embeds bytes 6,7 then 9,10.
		{"2a01:4f8:aabb::/48", "2a01:4f8:aabb:a9fe:a9:fe00::", ClassBlocked, "/48 -> 169.254.169.254"},
		// /56 embeds byte 7 then 9,10,11.
		{"2a01:4f8:aabb:cc00::/56", "2a01:4f8:aabb:cca9:00fe:a9fe::", ClassBlocked, "/56 -> 169.254.169.254"},
		// /64 embeds bytes 9,10,11,12.
		{"2a01:4f8:aabb:ccdd::/64", "2a01:4f8:aabb:ccdd:00a9:fea9:fe00:0", ClassBlocked, "/64 -> 169.254.169.254"},
		// /96 embeds bytes 12..16.
		{"2a01:4f8:aabb:ccdd:0:1122::/96", "2a01:4f8:aabb:ccdd:0:1122:a9fe:a9fe", ClassBlocked, "/96 -> 169.254.169.254"},
	}
	for _, tc := range cases {
		t.Run(tc.note, func(t *testing.T) {
			p := netip.MustParsePrefix(tc.prefix)
			if err := ValidateNAT64Prefix(p); err != nil {
				t.Fatalf("ValidateNAT64Prefix(%s): %v", tc.prefix, err)
			}
			addr := netip.MustParseAddr(tc.addr)

			// Without the declaration the address is opaque public IPv6 — this
			// is the state the fix removes for declared prefixes.
			if tc.class != ClassPublic {
				if got, _ := Classify(addr); got != ClassPublic {
					t.Fatalf("undeclared: Classify(%s) = %v, want ClassPublic (the test premise)", tc.addr, got)
				}
			}
			got, reason := ClassifyWith(addr, []netip.Prefix{p})
			if got != tc.class {
				t.Errorf("ClassifyWith(%s, %s) = %v (%q), want %v", tc.addr, tc.prefix, got, reason, tc.class)
			}
		})
	}
}

func TestValidateNAT64Prefix(t *testing.T) {
	for _, ok := range []string{
		"2a01:4f8::/32", "2a01:4f8:aa00::/40", "2a01:4f8:aabb::/48",
		"2a01:4f8:aabb:cc00::/56", "2a01:4f8:aabb:ccdd::/64",
		"2a01:4f8:aabb:ccdd:0:1122::/96",
		"fd00:1234::/32", // ULA is a legitimate network-specific prefix
	} {
		if err := ValidateNAT64Prefix(netip.MustParsePrefix(ok)); err != nil {
			t.Errorf("ValidateNAT64Prefix(%s) = %v, want nil", ok, err)
		}
	}
	bad := map[string]string{
		"10.0.0.0/8":          "not IPv6",
		"2a01:4f8::/44":       "not an RFC 6052 length",
		"2a01:4f8::/128":      "not an RFC 6052 length",
		"::ffff:10.0.0.0/104": "IPv4-mapped, not IPv6",
		// Codex round 5 (Medium): a declaration must not be able to re-open a
		// permanently blocked range by decoding addresses under it.
		"64:ff9b:1::/48": "inside the permanently blocked RFC 8215 local-use prefix",
		"fe80::/64":      "link-local",
		"2001:2::/48":    "inside the blocked 2001::/23",
		"ff00::/32":      "multicast",
		"::/32":          "unspecified / overlaps the IPv4-compatible format",
		"2002::/32":      "overlaps the built-in 6to4 format",
		"64:ff9b::/96":   "overlaps the built-in well-known NAT64 prefix (always decoded)",
		// Codex round 5 (Medium): RFC 6052 requires bits 64..71 to be zero, and
		// for a /96 that octet is inside the prefix itself.
		"2a01:4f8:aabb:ccdd:eeff:1122::/96": "non-zero u-octet inside the prefix",
	}
	for prefix, why := range bad {
		if err := ValidateNAT64Prefix(netip.MustParsePrefix(prefix)); err == nil {
			t.Errorf("ValidateNAT64Prefix(%s) = nil, want an error — %s", prefix, why)
		}
	}
}

// TestClassify_DeclaredNAT64CannotReopenBlockedRange is the round-5 (Medium)
// invariant: no declaration re-enables ClassBlocked. The declaration is rejected
// at startup, and even if one were forced through in code the fixed tables are
// consulted first.
func TestClassify_DeclaredNAT64CannotReopenBlockedRange(t *testing.T) {
	// 64:ff9b:1:808:8:800:: under a /48 declaration would decode to 8.8.8.8.
	forced := []netip.Prefix{netip.MustParsePrefix("64:ff9b:1::/48")}
	addr := netip.MustParseAddr("64:ff9b:1:808:8:800::")
	if got, reason := ClassifyWith(addr, forced); got != ClassBlocked {
		t.Errorf("ClassifyWith(%s, 64:ff9b:1::/48) = %v (%q), want ClassBlocked", addr, got, reason)
	}
	// Same for a declaration inside link-local.
	forced = []netip.Prefix{netip.MustParsePrefix("fe80::/64")}
	addr = netip.MustParseAddr("fe80::0:808:808:0")
	if got, reason := ClassifyWith(addr, forced); got != ClassBlocked {
		t.Errorf("ClassifyWith(%s, fe80::/64) = %v (%q), want ClassBlocked", addr, got, reason)
	}
}

// TestClassify_NonZeroUOctetFallsThroughToTheTables is the round-5 (Medium)
// u-octet regression: a native host inside a declared ULA prefix, whose bytes
// happen to look like a public embedded address, must keep its private
// classification rather than being decoded as if it were translated.
func TestClassify_NonZeroUOctetFallsThroughToTheTables(t *testing.T) {
	declared := []netip.Prefix{netip.MustParsePrefix("fd00:1234::/32")}

	// u-octet zero → a real RFC 6052 translated address → decodes to 8.8.8.8.
	translated := netip.MustParseAddr("fd00:1234:808:808::")
	if got, _ := ClassifyWith(translated, declared); got != ClassPublic {
		t.Errorf("ClassifyWith(%s) = %v, want ClassPublic (a well-formed translated address)", translated, got)
	}

	// u-octet non-zero → NOT a translated address → stays ULA → ClassPrivate.
	native := netip.MustParseAddr("fd00:1234:808:808:ff00::")
	if native.As16()[8] == 0 {
		t.Fatalf("test vector %s has a zero u-octet; it is not exercising the case", native)
	}
	if got, _ := ClassifyWith(native, declared); got != ClassPrivate {
		t.Errorf("ClassifyWith(%s) = %v, want ClassPrivate (non-zero u-octet is not a translated address)", native, got)
	}
}

// TestClassify_ReservedIPv6OutsideGlobalUnicastIsBlocked — Codex round 5 (Low):
// the default branch used to permit IPv6 outside the delegated 2000::/3.
func TestClassify_ReservedIPv6OutsideGlobalUnicastIsBlocked(t *testing.T) {
	for _, s := range []string{"1000::1", "4000::1", "8000::1", "fbff::1"} {
		if got, _ := Classify(netip.MustParseAddr(s)); got != ClassBlocked {
			t.Errorf("Classify(%s) = %v, want ClassBlocked (outside 2000::/3)", s, got)
		}
	}
	// The legitimate non-global forms outside 2000::/3 keep their own classes.
	for _, tc := range []struct {
		addr  string
		class Class
	}{
		{"fc00::1", ClassPrivate},
		{"::1", ClassPrivate},
		{"fe80::1", ClassBlocked},
		{"ff02::1", ClassBlocked},
		{"64:ff9b::808:808", ClassPublic},
	} {
		if got, reason := Classify(netip.MustParseAddr(tc.addr)); got != tc.class {
			t.Errorf("Classify(%s) = %v (%q), want %v", tc.addr, got, reason, tc.class)
		}
	}
	// And global unicast stays public.
	for _, s := range []string{"2000::1", "2606:4700::1111", "2c0f::1"} {
		if got, reason := Classify(netip.MustParseAddr(s)); got != ClassPublic {
			t.Errorf("Classify(%s) = %v (%q), want ClassPublic", s, got, reason)
		}
	}
}

// TestGuard_CIDRExemptionMatchesTheEmbeddedAddress — Codex round 5 (Low): on a
// NAT64 network the dial address is IPv6 while the operator's exemption is
// written in IPv4.
func TestGuard_CIDRExemptionMatchesTheEmbeddedAddress(t *testing.T) {
	p := testPolicy("nat64")
	p.NAT64Prefixes = []netip.Prefix{netip.MustParsePrefix("fd00:1234::/32")}
	p.PrivateCIDRExemptions = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	g := New(p)

	// 192.168.1.1 behind the declared prefix, exempted by the IPv4 CIDR.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := g.DialContext(ctx, "tcp", "[fd00:1234:c0a8:101::]:80"); errors.Is(err, ErrBlockedDestination) {
		t.Errorf("the IPv4 CIDR exemption must cover the embedded address: %v", err)
	}
	// 10.0.0.1 behind the same prefix is NOT exempted.
	if _, err := g.DialContext(ctx, "tcp", "[fd00:1234:a00:1::]:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a non-exempt embedded address must still be refused, got %v", err)
	}
}

// TestGuard_CustomNAT64PrefixAppliesAtDialTime confirms the declaration reaches
// the enforcement point, not just the classifier.
func TestGuard_CustomNAT64PrefixAppliesAtDialTime(t *testing.T) {
	p := testPolicy("nat64")
	p.NAT64Prefixes = []netip.Prefix{netip.MustParsePrefix("2a01:4f8::/32")}
	g := New(p)

	if _, err := g.DialContext(context.Background(), "tcp", "[2a01:4f8:a9fe:a9fe::]:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("dial through a declared NAT64 prefix to the metadata address = %v, want ErrBlockedDestination", err)
	}
	if err := g.ValidateURL("http://[2a01:4f8:c0a8:101::]/"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("RFC1918 behind a declared NAT64 prefix = %v, want ErrBlockedDestination", err)
	}
}

// TestClassify_GCPIPv6MetadataIsBlocked — Codex round 4 (Low). Inside fc00::/7,
// so the private opt-in would otherwise have opened it.
func TestClassify_GCPIPv6MetadataIsBlocked(t *testing.T) {
	if got, _ := Classify(netip.MustParseAddr("fd20:ce::254")); got != ClassBlocked {
		t.Errorf("Classify(fd20:ce::254) = %v, want ClassBlocked", got)
	}
	p := testPolicy("selfhost")
	p.AllowPrivate = true
	if _, err := New(p).DialContext(context.Background(), "tcp", "[fd20:ce::254]:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("AllowPrivate must not open the GCP IPv6 metadata address, got %v", err)
	}
}

// TestClassify_IETFProtocolAssignmentsBlockIsWholeRange — Codex round 4 (Low):
// 2001:5::1 sits in the non-global default portion of 2001::/23 and was
// classified public.
func TestClassify_IETFProtocolAssignmentsBlockIsWholeRange(t *testing.T) {
	for _, s := range []string{"2001::1", "2001:2::1", "2001:5::1", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if got, _ := Classify(netip.MustParseAddr(s)); got != ClassBlocked {
			t.Errorf("Classify(%s) = %v, want ClassBlocked", s, got)
		}
	}
	// RIR-allocated global unicast starts at 2001:200::/23 and must stay public.
	for _, s := range []string{"2001:200::1", "2001:4860:4860::8888"} {
		if got, _ := Classify(netip.MustParseAddr(s)); got != ClassPublic {
			t.Errorf("Classify(%s) = %v, want ClassPublic", s, got)
		}
	}
}

// TestParseExemptions_RejectsMalformedHostnames — Codex round 4 (Low): these
// were accepted, matched nothing, and left the operator believing a path was
// open.
func TestParseExemptions_RejectsMalformedHostnames(t *testing.T) {
	for _, bad := range []string{".", "..", "*", "*.corp.example", "foo..bar", "-lead.example", "trail-.example"} {
		if _, _, err := ParseExemptions(bad); err == nil {
			t.Errorf("ParseExemptions(%q) = nil, want an error", bad)
		}
	}
	for _, good := range []string{"jira", "jira.corp.example", "JIRA.Corp.Example", "a_b.corp.example", "x1-2.corp.example"} {
		hosts, _, err := ParseExemptions(good)
		if err != nil {
			t.Errorf("ParseExemptions(%q) = %v, want nil", good, err)
			continue
		}
		if len(hosts) != 1 {
			t.Errorf("ParseExemptions(%q) produced %v", good, hosts)
		}
	}
}

// TestGuard_MalformedURLMessageDoesNotEchoInput — Codex round 4 (Low): the parse
// error from net/url quotes the whole malformed input, and handlers echo these
// messages at 400.
func TestGuard_MalformedURLMessageDoesNotEchoInput(t *testing.T) {
	g := New(testPolicy("test"))
	err := g.ValidateURL("https://exa mple.com/PATH-MARKER?q=<script>")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, leak := range []string{"PATH-MARKER", "<script>", "q="} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("message echoes %q: %q", leak, err.Error())
		}
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a malformed URL should still be a policy refusal, got %v", err)
	}
}

// --- Codex round 6 -----------------------------------------------------------

// TestClassify_UnvalidatedDeclaredPrefixCannotReopenBlocked is the round-6
// (Medium) regression.
//
// ClassifyWith is exported, so its invariant — no declaration re-opens
// ClassBlocked — has to hold for a caller that never went through the startup
// validation. 4000::/32 is outside the delegated 2000::/3 range, so
// 4000:0:808:808:: is ClassBlocked with a nil list; passing 4000::/32 as a
// declared prefix used to decode it to 8.8.8.8 and return ClassPublic.
func TestClassify_UnvalidatedDeclaredPrefixCannotReopenBlocked(t *testing.T) {
	unvalidated := []netip.Prefix{netip.MustParsePrefix("4000::/32")}
	addr := netip.MustParseAddr("4000:0:808:808::")

	// Premise: the declaration is one the startup gate rejects.
	if err := ValidateNAT64Prefix(unvalidated[0]); err == nil {
		t.Fatal("premise failed: 4000::/32 should be refused by ValidateNAT64Prefix")
	}
	// Premise: blocked without any declaration.
	if got, _ := Classify(addr); got != ClassBlocked {
		t.Fatalf("premise failed: Classify(%s) = %v, want ClassBlocked", addr, got)
	}
	// The invariant.
	if got, reason := ClassifyWith(addr, unvalidated); got != ClassBlocked {
		t.Errorf("ClassifyWith(%s, 4000::/32) = %v (%q), want ClassBlocked", addr, got, reason)
	}
}

// TestGuard_SixToFourExemptionDoesNotWiden is the round-6 (Low) regression.
//
// A 6to4 address embeds the RELAY's IPv4 address, not the destination's. Testing
// a CIDR exemption against it would let "exempt 10.0.0.1/32" permit every
// address under 2002:0a00:0001::/48 — far more than the operator wrote.
func TestGuard_SixToFourExemptionDoesNotWiden(t *testing.T) {
	p := testPolicy("sixtofour")
	p.PrivateCIDRExemptions = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}
	g := New(p)

	// 2002:0a00:0001:: embeds relay 10.0.0.1 — classified private (the relay is
	// internal), and the exemption must NOT cover the outer address.
	if err := g.ValidateURL("http://[2002:a00:1::1234]/"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a 6to4 address must not inherit the relay's IPv4 exemption: %v", err)
	}
	// The exemption still works for the IPv4 host itself.
	if err := g.ValidateURL("http://10.0.0.1/x"); err != nil {
		t.Errorf("the exemption must still cover the IPv4 host it names: %v", err)
	}
	// And a NAT64 address, where the embedded address IS the destination, does
	// inherit it.
	if err := g.ValidateURL("http://[64:ff9b::a00:1]/"); err != nil {
		t.Errorf("NAT64 is destination-preserving, so the exemption applies: %v", err)
	}
}

// --- Codex round 7 -----------------------------------------------------------

// TestClassify_OverlappingDeclaredPrefixesTakeTheMostRestrictive is the round-7
// (Medium) regression.
//
// Two declarations of different lengths covering the same address read the
// embedded IPv4 octets from different offsets, so they disagree about the
// destination. Under a first-match loop the verdict depended on the order the
// operator listed them in.
//
// Vectors, derived from RFC 6052 §2.2 offsets and verified by the premise
// assertions below. Address fd00:12a9:8a9:fea9:fe:: has bytes
// fd 00 12 a9 08 a9 fe a9 00 fe:
//
//	/32 reads bytes 4..7   -> 8.169.254.169    -> ClassPublic
//	/40 reads bytes 5,6,7,9 -> 169.254.169.254 -> ClassBlocked
func TestClassify_OverlappingDeclaredPrefixesTakeTheMostRestrictive(t *testing.T) {
	addr := netip.MustParseAddr("fd00:12a9:8a9:fea9:fe::")
	p32 := netip.MustParsePrefix("fd00:12a9::/32")
	p40 := netip.MustParsePrefix("fd00:12a9:800::/40")

	for _, p := range []netip.Prefix{p32, p40} {
		if err := ValidateNAT64Prefix(p); err != nil {
			t.Fatalf("premise: %s should be a valid declaration: %v", p, err)
		}
	}
	if got, _, _ := ClassifyDetailed(addr, []netip.Prefix{p32}); got != ClassPublic {
		t.Fatalf("premise: the /32 reading should be ClassPublic, got %v", got)
	}
	if got, _, _ := ClassifyDetailed(addr, []netip.Prefix{p40}); got != ClassBlocked {
		t.Fatalf("premise: the /40 reading should be ClassBlocked, got %v", got)
	}

	// With both declared, in EITHER order, the blocked reading must win.
	for _, order := range [][]netip.Prefix{{p32, p40}, {p40, p32}} {
		got, reason, _ := ClassifyDetailed(addr, order)
		if got != ClassBlocked {
			t.Errorf("ClassifyDetailed(%s, %v) = %v (%q), want ClassBlocked — the verdict must not depend on declaration order",
				addr, order, got, reason)
		}
	}
}

// TestParseExemptions_OverlappingNAT64IsRefusedAtStartup documents that the
// classifier's fail-closed resolution above is defence in depth: the operator
// gets told about the mistake. (The refusal itself lives in
// cmd/server.parseNAT64Prefixes and is covered by its own test there.)
func TestClassify_OverlappingDeclarationsPreferBlockedOverPrivate(t *testing.T) {
	// Same construction, but the /32 reading is private rather than public, to
	// confirm the ordering is by severity and not merely "not public".
	addr := netip.MustParseAddr("fd00:12a9:aa9:fea9:fe::") // byte 4 = 0x0a
	p32 := netip.MustParsePrefix("fd00:12a9::/32")
	p40 := netip.MustParsePrefix("fd00:12a9:a00::/40")

	if got, _, _ := ClassifyDetailed(addr, []netip.Prefix{p32}); got != ClassPrivate {
		t.Fatalf("premise: the /32 reading (10.169.254.169) should be ClassPrivate, got %v", got)
	}
	if got, _, _ := ClassifyDetailed(addr, []netip.Prefix{p40}); got != ClassBlocked {
		t.Fatalf("premise: the /40 reading should be ClassBlocked, got %v", got)
	}
	for _, order := range [][]netip.Prefix{{p32, p40}, {p40, p32}} {
		if got, _, _ := ClassifyDetailed(addr, order); got != ClassBlocked {
			t.Errorf("ClassifyDetailed(%s, %v) = %v, want ClassBlocked", addr, order, got)
		}
	}
}

// --- Codex round 8 -----------------------------------------------------------

// TestClassify_AmbiguousOverlappingDeclarationsAreRefused is the round-8
// (Medium) regression.
//
// Round 7 made the CLASS order-independent by taking the most restrictive one.
// That was not enough: two readings can both be ClassPrivate while naming
// DIFFERENT addresses, and the effective address is what a narrow CIDR exemption
// is matched against — so the declaration order still decided whether an
// exemption applied. Disagreement is now refused outright.
//
// Vectors: address fd00:12a9:aa9:fe0a:1::  bytes fd 00 12 a9 0a a9 fe 0a 00 01
//
//	/32 reads bytes 4..7    -> 10.169.254.10 -> ClassPrivate
//	/40 reads bytes 5,6,7,9 -> 169.254.10.1  -> ClassBlocked (link-local)
//
// so for the equal-class case a second vector is used below.
func TestClassify_AmbiguousOverlappingDeclarationsAreRefused(t *testing.T) {
	// Both readings ClassPrivate, different addresses:
	//   bytes: fd 00 12 a9 0a 0a 01 02 00 03
	//   /32 -> 10.10.1.2     (private)
	//   /40 -> 10.1.2.3      (private)
	addr := netip.MustParseAddr("fd00:12a9:a0a:102:3::")
	p32 := netip.MustParsePrefix("fd00:12a9::/32")
	p40 := netip.MustParsePrefix("fd00:12a9:a00::/40")

	c32, _, e32 := ClassifyDetailed(addr, []netip.Prefix{p32})
	c40, _, e40 := ClassifyDetailed(addr, []netip.Prefix{p40})
	if c32 != ClassPrivate || c40 != ClassPrivate {
		t.Fatalf("premise: both readings should be ClassPrivate, got %v and %v", c32, c40)
	}
	if e32 == e40 {
		t.Fatalf("premise: the two readings should name different addresses, both gave %s", e32)
	}

	for _, order := range [][]netip.Prefix{{p32, p40}, {p40, p32}} {
		got, reason, eff := ClassifyDetailed(addr, order)
		if got != ClassBlocked {
			t.Errorf("ClassifyDetailed(%s, %v) = %v (%q, effective %s), want ClassBlocked — two readings disagree",
				addr, order, got, reason, eff)
		}
	}

	// An exemption covering ONE of the two readings must not rescue it.
	p := testPolicy("ambiguous")
	p.NAT64Prefixes = []netip.Prefix{p32, p40}
	p.PrivateCIDRExemptions = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if err := New(p).ValidateURL("http://[" + addr.String() + "]/"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("an exemption must not permit an ambiguous address: %v", err)
	}
}

// TestClassify_AgreeingOverlappingDeclarationsAreNotRefused keeps the ambiguity
// rule from over-reaching: an exact duplicate declaration decodes identically,
// which is redundant rather than ambiguous.
func TestClassify_AgreeingOverlappingDeclarationsAreNotRefused(t *testing.T) {
	addr := netip.MustParseAddr("fd00:1234:808:808::")
	p := netip.MustParsePrefix("fd00:1234::/32")

	single, _, _ := ClassifyDetailed(addr, []netip.Prefix{p})
	dup, _, _ := ClassifyDetailed(addr, []netip.Prefix{p, p})
	if single != dup {
		t.Errorf("a duplicated declaration changed the verdict: %v -> %v", single, dup)
	}
	if dup != ClassPublic {
		t.Errorf("verdict = %v, want ClassPublic (8.8.8.8 behind the declared prefix)", dup)
	}
}
