package client

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

	"github.com/sbomhub/sbomhub/internal/egress"
)

// serverOn starts an httptest server on a specific loopback address so a test
// can tell "the host policy permits" apart from "the host policy must refuse".
// httptest.NewServer puts everything on 127.0.0.1, where an address-based
// exemption cannot distinguish the two.
func serverOn(t *testing.T, ip string, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", ip, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config:   &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second},
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// permitFirstHopOnly is a guard that permits exactly one internal address —
// standing in for "a routable host the tenant is allowed to configure" — so
// that the request reaches the redirector and the assertion is about the
// redirect, not about the first hop.
func permitFirstHopOnly(allowed string) *egress.Guard {
	addr := netip.MustParseAddr(allowed)
	set := egress.Settings{
		PrivateCIDRExemptions: []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())},
	}
	return egress.NewSet(set).IssueTracker
}

// TestIssueTrackerClients_RedirectDoesNotReachLoopback is the M50 regression for
// the Jira / Backlog / GitHub-Issues sinks.
//
// Measured before the fix (2026-07-30, go1.26.4): with the pre-M50 constructors
// — a bare &http.Client{Timeout: 30s}, no CheckRedirect — each of the three
// clients followed the 302 and the loopback listener recorded exactly 1 hit.
// The tenant-controlled value here is issue_tracker_connections.base_url, whose
// only guard was a validation-time DNS check on the CONFIGURED host; the
// redirect target was never examined.
//
// After the fix the first hop still succeeds (the test exempts its address) and
// the redirect is refused, so the loopback counter stays at zero.
func TestIssueTrackerClients_RedirectDoesNotReachLoopback(t *testing.T) {
	var internalHits atomic.Int32
	internal := serverOn(t, "127.0.0.1", func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","key":"X-1","self":"x"}`))
	})

	var redirectorHits atomic.Int32
	redirector := serverOn(t, "127.0.0.2", func(w http.ResponseWriter, r *http.Request) {
		redirectorHits.Add(1)
		http.Redirect(w, r, internal.URL+r.URL.Path, http.StatusFound)
	})

	// The clients require https by policy, so drive the http URL through an
	// explicitly plaintext-permitting variant of the same guard. The IP rules —
	// the thing under test — are identical.
	guard := permitFirstHopOnly("127.0.0.2")
	plaintextPolicy := guard.Policy()
	plaintextPolicy.AllowPlaintextHTTP = true
	guard = egress.New(plaintextPolicy)

	fastBackoff := BackoffPolicy{MaxRetries: 0, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("jira", func(t *testing.T) {
		internalHits.Store(0)
		redirectorHits.Store(0)
		c := NewJiraClient(redirector.URL, "u@example.com", "tok").WithEgress(guard).WithBackoffPolicy(fastBackoff)
		_, _ = c.GetIssue(ctx, "X-1")
		assertRedirectRefused(t, &redirectorHits, &internalHits, internal.URL)
	})

	t.Run("backlog", func(t *testing.T) {
		internalHits.Store(0)
		redirectorHits.Store(0)
		c := NewBacklogClient(redirector.URL, "tok").WithEgress(guard).WithBackoffPolicy(fastBackoff)
		_, _ = c.GetIssue(ctx, "X-1")
		assertRedirectRefused(t, &redirectorHits, &internalHits, internal.URL)
	})

	t.Run("github", func(t *testing.T) {
		internalHits.Store(0)
		redirectorHits.Store(0)
		c := NewGitHubIssuesClient(redirector.URL, "tok").WithEgress(guard).WithBackoffPolicy(fastBackoff)
		_, _ = c.GetIssue(ctx, "o/r", 1)
		assertRedirectRefused(t, &redirectorHits, &internalHits, internal.URL)
	})
}

func assertRedirectRefused(t *testing.T, first, second *atomic.Int32, internalURL string) {
	t.Helper()
	if first.Load() == 0 {
		t.Fatal("the permitted first hop was never reached; the test is not exercising a redirect")
	}
	if n := second.Load(); n != 0 {
		t.Errorf("redirect target %s was reached %d time(s)", internalURL, n)
	}
}

// TestIssueTrackerClients_DefaultGuardRefusesLoopback pins the constructor
// default. A caller that builds one of these clients and forgets to attach a
// guard gets the strict policy, not an unguarded http.Client.
//
// Codex round 3 (Low) found the first version of this test vacuous: it pointed
// an https:// URL at a plaintext httptest.Server, so reverting the constructors
// to a bare &http.Client{} left it green — the TLS handshake failed before the
// handler ran, and "there was an error" proved nothing about WHY. The assertion
// is now errors.Is(err, egress.ErrBlockedDestination), which no TLS or connect
// failure satisfies.
func TestIssueTrackerClients_DefaultGuardRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	// https:// because the issue-tracker policy is https-only; the address
	// refusal happens in the dialer, before any handshake is attempted.
	httpsURL := strings.Replace(internal.URL, "http://", "https://", 1)
	fastBackoff := BackoffPolicy{MaxRetries: 0, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, jerr := NewJiraClient(httpsURL, "u@example.com", "t").WithBackoffPolicy(fastBackoff).GetIssue(ctx, "X-1")
	if !errors.Is(jerr, egress.ErrBlockedDestination) {
		t.Errorf("jira: err = %v, want ErrBlockedDestination from the default guard", jerr)
	}
	_, berr := NewBacklogClient(httpsURL, "t").WithBackoffPolicy(fastBackoff).GetIssue(ctx, "X-1")
	if !errors.Is(berr, egress.ErrBlockedDestination) {
		t.Errorf("backlog: err = %v, want ErrBlockedDestination from the default guard", berr)
	}
	_, gerr := NewGitHubIssuesClient(httpsURL, "t").WithBackoffPolicy(fastBackoff).GetIssue(ctx, "o/r", 1)
	if !errors.Is(gerr, egress.ErrBlockedDestination) {
		t.Errorf("github: err = %v, want ErrBlockedDestination from the default guard", gerr)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("loopback listener reached %d time(s) with the default guard", n)
	}
}
