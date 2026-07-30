package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver answers from a fixed table. Used so the rebinding scenario can
// be driven without an external network or a DNS server.
type stubResolver struct {
	table map[string][]string
	calls atomic.Int32
}

func (s *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	s.calls.Add(1)
	answers, ok := s.table[host]
	if !ok {
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

// rebindingResolver answers the first lookup with a routable address and every
// later lookup with loopback — the DNS rebinding attack in its minimal form.
type rebindingResolver struct {
	first  string
	later  string
	served atomic.Int32
}

func (r *rebindingResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	n := r.served.Add(1)
	pick := r.later
	if n == 1 {
		pick = r.first
	}
	addr, err := netip.ParseAddr(pick)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{addr}, nil
}

func testPolicy(p Purpose) Policy {
	return Policy{Purpose: p, AllowPlaintextHTTP: true, MaxRedirects: 3}
}

// TestGuard_RebindingCannotReachLoopback is the DNS rebinding regression.
//
// The resolver hands out a routable address for the validation lookup and
// 127.0.0.1 for every lookup after it. Under the old design — validate with
// net.LookupIP, then hand the URL to an ordinary http.Client — that sequence
// lands the request on loopback, because the client resolves again when it
// connects and gets the second answer.
//
// Here ValidateURL passes (it sees the routable answer, exactly as the attack
// intends) and the request still never reaches the loopback listener, because
// the address the dialer inspects is the address the dialer connects to.
func TestGuard_RebindingCannotReachLoopback(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))
	if err != nil {
		t.Fatalf("split httptest address: %v", err)
	}

	resolver := &rebindingResolver{first: "93.184.216.34", later: "127.0.0.1"}
	g := New(testPolicy("test")).WithResolver(resolver)

	target := "http://rebind.example.test:" + port + "/"

	// Step 1: the URL-level check passes — it has nothing to object to, and by
	// design it does not resolve the name at all.
	if verr := g.ValidateURL(target); verr != nil {
		t.Fatalf("ValidateURL should pass for a hostname it cannot judge: %v", verr)
	}
	if resolver.served.Load() != 0 {
		t.Fatalf("ValidateURL resolved a hostname (%d lookups); it is documented not to", resolver.served.Load())
	}

	// Step 2: burn the first (routable) answer, standing in for the
	// validation-time net.LookupIP the predecessor performed. That lookup is
	// what an attacker aims the public answer at.
	first, err := resolver.LookupNetIP(context.Background(), "ip", "rebind.example.test")
	if err != nil {
		t.Fatalf("priming lookup: %v", err)
	}
	if got := first[0].String(); got != "93.184.216.34" {
		t.Fatalf("priming lookup returned %s, want the public answer", got)
	}

	// Step 3: the request. Every lookup from here on answers loopback.
	client := g.Client(5 * time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the guarded client to refuse the rebound address, got a response")
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("expected ErrBlockedDestination, got %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the loopback listener was reached %d time(s) despite the guard", n)
	}
}

// TestGuard_RebindingWithMixedAnswersIsRefused covers the variant where the
// hostname resolves to a public AND a loopback address at the same time. A
// guard that accepts the name because "an" answer is public, then lets the
// stdlib pick, is exploitable via happy-eyeballs ordering.
func TestGuard_RebindingWithMixedAnswersIsRefused(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))

	resolver := &stubResolver{table: map[string][]string{
		"mixed.example.test": {"127.0.0.1", "93.184.216.34"},
	}}
	g := New(testPolicy("test")).WithResolver(resolver)

	// Short deadline: the only permitted candidate (93.184.216.34) is a routable
	// address this test has no intention of reaching, so the dial is expected to
	// time out. What matters is that the loopback candidate was dropped, not how
	// the surviving one fares.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	client := g.Client(3 * time.Second)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://mixed.example.test:"+port+"/", nil)
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("loopback answer was dialed %d time(s); the guard must drop it and keep only permitted answers", n)
	}
}

// TestGuard_ResolutionFailureIsRefused is the fail-open regression.
//
// The predecessor (service.isBlockedHost) returned false — "not blocked" — when
// net.LookupIP failed, with the comment "If we can't resolve, allow it (will
// fail on actual connection)".
func TestGuard_ResolutionFailureIsRefused(t *testing.T) {
	resolver := &stubResolver{table: map[string][]string{}}
	g := New(testPolicy("test")).WithResolver(resolver)

	_, err := g.DialContext(context.Background(), "tcp", "nowhere.example.test:80")
	if err == nil {
		t.Fatal("expected a refusal when the name does not resolve, got nil")
	}
	if !strings.Contains(err.Error(), "cannot resolve") {
		t.Errorf("expected a resolution-failure refusal, got %v", err)
	}
}

// TestGuard_EmptyAnswerIsRefused covers the "resolved successfully to nothing"
// shape, which is a different code path from a resolver error.
func TestGuard_EmptyAnswerIsRefused(t *testing.T) {
	resolver := &stubResolver{table: map[string][]string{"empty.example.test": {}}}
	g := New(testPolicy("test")).WithResolver(resolver)

	_, err := g.DialContext(context.Background(), "tcp", "empty.example.test:80")
	if !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("expected ErrBlockedDestination, got %v", err)
	}
}

// TestGuard_RedirectToLoopbackIsRefused drives a real redirect chain: a
// listener that 302s onto another listener bound to loopback.
func TestGuard_RedirectToLoopbackIsRefused(t *testing.T) {
	var internalHits atomic.Int32
	internal := newServerOn(t, "127.0.0.1", func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	var redirectorHits atomic.Int32
	redirector := newServerOn(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		http.Redirect(w, r, internal.URL, http.StatusFound)
	})

	// The redirector is reachable only because the test exempts its address,
	// standing in for "a routable host the tenant is allowed to configure".
	// The redirect target is a different address and is not exempt.
	p := testPolicy("test")
	p.PrivateCIDRExemptions = []netip.Prefix{netip.MustParsePrefix("127.0.0.2/32")}
	g := New(p)

	client := g.Client(5 * time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, redirector.URL, nil)
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if redirectorHits.Load() == 0 {
		t.Fatal("the exempted first hop should have been reached; the test is not exercising the redirect")
	}
	if n := internalHits.Load(); n != 0 {
		t.Fatalf("the redirect target was reached %d time(s); redirects must be re-checked", n)
	}
}

// newServerOn starts an httptest server bound to a specific loopback address,
// so a test can distinguish "the host the policy permits" from "the host it
// must not reach" — httptest.NewServer puts everything on 127.0.0.1, where an
// address-based exemption cannot tell the two apart.
func newServerOn(t *testing.T, ip string, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot bind %s (needed to separate permitted from forbidden hosts): %v", ip, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestGuard_RedirectHopCap stops an endpoint from walking an unbounded chain.
func TestGuard_RedirectHopCap(t *testing.T) {
	var hops atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	addr := netip.MustParseAddr(host)
	p := testPolicy("test")
	p.MaxRedirects = 2
	p.PrivateCIDRExemptions = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}
	g := New(p)

	resp, err := g.Client(5 * time.Second).Get(srv.URL) //nolint:noctx // exercised via Client, ctx not needed
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("expected the hop cap to stop the chain")
	}
	if !strings.Contains(err.Error(), "stopped after 2 redirects") {
		t.Fatalf("expected the hop-cap message, got %v", err)
	}
	// 1 initial + 2 followed hops.
	if n := hops.Load(); n != 3 {
		t.Errorf("server saw %d requests, want 3 (initial + MaxRedirects)", n)
	}
}

// TestGuard_NoRedirectPolicy covers the diff_webhook shape: MaxRedirects == 0
// means the 3xx is handed back as a response rather than followed.
func TestGuard_NoRedirectPolicy(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(redirector.URL, "http://"))
	addr := netip.MustParseAddr(host)
	p := testPolicy("test")
	p.MaxRedirects = 0
	p.PrivateCIDRExemptions = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}

	resp, err := New(p).Client(5 * time.Second).Get(redirector.URL) //nolint:noctx // exercised via Client, ctx not needed
	if err != nil {
		t.Fatalf("expected the 3xx to come back as a response, got %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if n := internalHits.Load(); n != 0 {
		t.Errorf("redirect target reached %d time(s) under MaxRedirects=0", n)
	}
}

func TestGuard_ValidateURL(t *testing.T) {
	strict := New(Policy{Purpose: "strict", MaxRedirects: 3})
	lax := New(testPolicy("lax"))

	cases := []struct {
		name    string
		guard   *Guard
		url     string
		wantErr bool
	}{
		{"https public host", strict, "https://example.com/api", false},
		{"http refused when plaintext disallowed", strict, "http://example.com/api", true},
		{"http allowed when policy permits", lax, "http://example.com/api", false},
		{"file scheme", lax, "file:///etc/passwd", true},
		{"gopher scheme", lax, "gopher://example.com/", true},
		{"no host", lax, "https://", true},
		{"host-less authority", lax, "http://:8080/x", true},
		{"loopback literal", lax, "http://127.0.0.1:8080/x", true},
		{"metadata literal", lax, "http://169.254.169.254/latest/meta-data/", true},
		{"metadata literal decimal", lax, "http://[::ffff:169.254.169.254]/", true},
		{"nat64 metadata literal", lax, "http://[64:ff9b::a9fe:a9fe]/", true},
		{"userinfo does not fool the host check", lax, "http://example.com@127.0.0.1/", true},
		{"unresolvable name passes validation", lax, "http://nowhere.example.test/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.guard.ValidateURL(tc.url)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateURL(%q) = nil, want an error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateURL(%q) = %v, want nil", tc.url, err)
			}
		})
	}
}

func TestGuard_ValidateURL_AllowedHosts(t *testing.T) {
	p := testPolicy("allowlist")
	p.AllowedHosts = []string{"github.com", "atlassian.net"}
	g := New(p)

	if err := g.ValidateURL("https://api.github.com/x"); err != nil {
		t.Errorf("api.github.com should be allowed: %v", err)
	}
	if err := g.ValidateURL("https://evil.example/x"); err == nil {
		t.Error("evil.example should be refused by the allowlist")
	}
	if err := g.ValidateURL("https://notgithub.com/x"); err == nil {
		t.Error("notgithub.com must not match the github.com entry")
	}
}

// TestGuard_AllowPrivateOptIn is the self-hosted escape hatch: with the opt-in
// set, an internal destination is reachable again.
func TestGuard_AllowPrivateOptIn(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer internal.Close()

	p := testPolicy("selfhost")
	p.AllowPrivate = true
	resp, err := New(p).Client(5 * time.Second).Get(internal.URL) //nolint:noctx // exercised via Client, ctx not needed
	if err != nil {
		t.Fatalf("AllowPrivate should permit loopback: %v", err)
	}
	defer resp.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
}

// TestGuard_AllowPrivateDoesNotOpenBlockedClass keeps the two tiers distinct:
// the self-hosted opt-in must not reach the metadata service.
func TestGuard_AllowPrivateDoesNotOpenBlockedClass(t *testing.T) {
	p := testPolicy("selfhost")
	p.AllowPrivate = true
	g := New(p)

	if err := g.ValidateURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("AllowPrivate must not permit the cloud metadata address")
	}
	if _, err := g.DialContext(context.Background(), "tcp", "169.254.169.254:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("dial to metadata address: got %v, want ErrBlockedDestination", err)
	}
}

// TestGuard_CIDRExemption is the narrow opt-in: one internal network is
// reachable, the rest of RFC1918 is not.
func TestGuard_CIDRExemption(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer internal.Close()

	host, _, _ := net.SplitHostPort(strings.TrimPrefix(internal.URL, "http://"))
	addr := netip.MustParseAddr(host)

	p := testPolicy("narrow")
	p.PrivateCIDRExemptions = []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())}
	g := New(p)

	resp, err := g.Client(5 * time.Second).Get(internal.URL) //nolint:noctx // exercised via Client, ctx not needed
	if err != nil {
		t.Fatalf("the exempted address should be reachable: %v", err)
	}
	defer resp.Body.Close()

	if _, err := g.DialContext(context.Background(), "tcp", "10.99.99.99:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a non-exempt private address should still be refused, got %v", err)
	}
}

// TestGuard_HostExemption covers the by-name form of the narrow opt-in.
func TestGuard_HostExemption(t *testing.T) {
	resolver := &stubResolver{table: map[string][]string{
		"jira.corp.example":  {"10.1.2.3"},
		"other.corp.example": {"10.1.2.4"},
	}}
	p := testPolicy("narrow")
	p.PrivateHostExemptions = []string{"jira.corp.example"}
	g := New(p).WithResolver(resolver)

	// No listener on 10.1.2.3, so a permitted destination surfaces as a connect
	// timeout rather than a policy refusal. That distinction is the assertion,
	// and the short deadline keeps the timeout from costing DefaultDialTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := g.DialContext(ctx, "tcp", "jira.corp.example:80")
	if errors.Is(err, ErrBlockedDestination) {
		t.Errorf("the exempted host should pass policy, got %v", err)
	}
	_, err = g.DialContext(ctx, "tcp", "other.corp.example:80")
	if !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("a non-exempt host should be refused, got %v", err)
	}
}

// TestGuard_ControlRejectsInternal exercises the connect-time hook directly.
func TestGuard_ControlRejectsInternal(t *testing.T) {
	g := New(testPolicy("test"))
	if err := g.controlFor("")("tcp", "169.254.169.254:80", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("control(metadata) = %v, want ErrBlockedDestination", err)
	}
	if err := g.controlFor("")("tcp", "127.0.0.1:80", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("control(loopback) = %v, want ErrBlockedDestination", err)
	}
	if err := g.controlFor("")("tcp", "8.8.8.8:80", nil); err != nil {
		t.Errorf("control(public) = %v, want nil", err)
	}
	if err := g.controlFor("")("tcp", "not-an-address", nil); err == nil {
		t.Error("control(garbage) should fail closed")
	}
	if err := g.controlFor("")("tcp", "example.com:80", nil); !errors.Is(err, ErrBlockedDestination) {
		t.Errorf("control(hostname) should fail closed, got %v", err)
	}
}

// TestGuard_DialLiteralInternalIsRefused covers the no-DNS path: an IP literal
// in the URL never reaches the resolver, so the literal branch must classify.
func TestGuard_DialLiteralInternalIsRefused(t *testing.T) {
	g := New(testPolicy("test"))
	for _, target := range []string{
		"127.0.0.1:8080",
		"169.254.169.254:80",
		"[::1]:8080",
		"[64:ff9b::a9fe:a9fe]:80",
		"10.0.0.1:80",
	} {
		if _, err := g.DialContext(context.Background(), "tcp", target); !errors.Is(err, ErrBlockedDestination) {
			t.Errorf("DialContext(%q) = %v, want ErrBlockedDestination", target, err)
		}
	}
}

func TestOperatorControlled_AllowsPrivateButNotMetadata(t *testing.T) {
	g := OperatorControlled()
	if err := g.ValidateURL("http://localhost:11434/api/chat"); err != nil {
		t.Errorf("operator-controlled guard should allow localhost: %v", err)
	}
	if err := g.ValidateURL("http://169.254.169.254/"); err == nil {
		t.Error("operator-controlled guard should still refuse the metadata address")
	}
}

func TestNewSet_PurposeShapes(t *testing.T) {
	set := NewSet(Settings{IssueTrackerAllowedHosts: []string{"github.com"}})

	if set.IssueTracker.Policy().AllowPlaintextHTTP {
		t.Error("issue_tracker must remain https-only")
	}
	if set.DiffWebhook.Policy().MaxRedirects != 0 {
		t.Error("diff_webhook must not follow redirects")
	}
	if set.NotificationWebhook.Policy().MaxRedirects == 0 {
		t.Error("notification_webhook is expected to follow redirects (re-checked per hop)")
	}
	for name, g := range map[string]*Guard{
		"issue_tracker": set.IssueTracker,
		"notification":  set.NotificationWebhook,
		"diff_webhook":  set.DiffWebhook,
		"tenant_llm":    set.TenantLLM,
	} {
		if g.Policy().AllowPrivate {
			t.Errorf("%s: AllowPrivate must default to false", name)
		}
		if err := g.ValidateURL("https://169.254.169.254/"); err == nil {
			t.Errorf("%s: metadata address must be refused", name)
		}
	}
}

func TestDestinationError_Message(t *testing.T) {
	err := &DestinationError{Purpose: PurposeDiffWebhook, Host: "evil.example", Addr: "127.0.0.1", Reason: "IPv4 loopback"}
	got := err.Error()
	for _, want := range []string{"diff_webhook", "evil.example", "127.0.0.1", "IPv4 loopback"} {
		if !strings.Contains(got, want) {
			t.Errorf("error message %q missing %q", got, want)
		}
	}
	if !errors.Is(err, ErrBlockedDestination) {
		t.Error("DestinationError must satisfy errors.Is(ErrBlockedDestination)")
	}
}
