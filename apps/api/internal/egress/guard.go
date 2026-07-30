// Package egress is the single place that decides where tenant-configured
// outbound HTTP is allowed to go.
//
// # Why the enforcement point is the dialer
//
// The obvious design — parse the URL, resolve the hostname, refuse if any
// answer is internal, then hand the URL to an ordinary http.Client — does not
// work. The client resolves the name again when it connects, and an attacker
// who controls the authoritative DNS for the name can answer with a routable
// address for the validation lookup and 127.0.0.1 for the connect lookup. The
// check and the connection are two different facts about the world.
//
// So the enforcement point here is net.Dialer: the address the guard inspects
// is the address the guard then connects to, in the same call, with no second
// resolution in between.
//
// The URL-level rules that an address cannot express — the scheme, the hostname
// allowlist — are enforced one layer up, in a RoundTripper that runs on every
// request. Guard.ValidateURL is the same check exposed for settings handlers to
// call when a tenant saves a URL; it is there to give the admin a 400 with a
// readable message instead of a delivery that fails hours later. Its presence at
// a call site is a UX affordance, not the thing that stops the attack, and no
// comment in this package should say otherwise.
//
// Redirects are the same problem wearing a different hat: a destination that
// passes every check can answer 302 with a Location pointing anywhere. Two
// things cover that. The guarded dialer applies to redirect hops as well,
// because the hop reuses the same Transport — so a redirect to an internal
// address is refused at connect time whether or not anything inspected the
// Location header. On top of that, CheckRedirect re-runs the URL-level rules
// (scheme, hostname allowlist) on every hop, which the dialer cannot see.
//
// # What is guarded and what is not
//
// Only destinations a tenant can choose. Operator-supplied destinations — the
// vulnerability feed mirrors behind SBOMHUB_NVD_URL and friends, the Ollama
// base URL from SBOMHUB_LLM_OLLAMA_URL / OLLAMA_HOST, the Lemon Squeezy API
// root — are not guarded. Filtering the operator's own environment against the
// operator's own policy buys nothing (they control the process) and would break
// the documented self-hosted Ollama deployment, whose default base URL is
// http://localhost:11434.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ErrBlockedDestination is the sentinel that every POLICY DENIAL satisfies, so
// callers can distinguish "the policy refused this" from "the network was
// unreachable" without string matching.
//
// It deliberately does NOT cover every error this package returns: a resolution
// failure (DialContext, below) is a refusal in the sense that nothing gets
// connected, but it is reported as the wrapped resolver error so that a DNS
// outage stays distinguishable from a destination the operator has forbidden.
// Codex round 3 (Low) caught an earlier version of this comment claiming all
// refusals were covered.
var ErrBlockedDestination = errors.New("egress: destination not permitted")

// DestinationError describes a refused destination.
//
// The Reason text is self-authored — it comes from this package's own tables —
// so handlers may echo the message to the tenant admin who configured the URL.
// Host and Addr are NOT self-authored: Host is the hostname from the URL the
// admin supplied (or, on a redirect hop, from a remote Location header), and
// Addr is what the resolver returned. Both are normalised (netip / url.Hostname
// parsing), which bounds them to hostname and address shapes rather than
// arbitrary text, and the request path is never included. Codex round 3 (Low)
// caught the earlier "entirely self-authored" claim; the accurate statement is
// that echoing this reflects a normalised copy of the admin's own input plus
// text this package wrote.
type DestinationError struct {
	Purpose Purpose
	Host    string
	Addr    string
	Reason  string
}

func (e *DestinationError) Error() string {
	var b strings.Builder
	b.WriteString("egress")
	if e.Purpose != "" {
		b.WriteString(" (")
		b.WriteString(string(e.Purpose))
		b.WriteString(")")
	}
	b.WriteString(": destination ")
	if e.Host != "" {
		b.WriteString(e.Host)
		if e.Addr != "" && e.Addr != e.Host {
			b.WriteString(" -> " + e.Addr)
		}
	} else if e.Addr != "" {
		b.WriteString(e.Addr)
	}
	b.WriteString(" is not permitted: ")
	b.WriteString(e.Reason)
	return b.String()
}

func (e *DestinationError) Is(target error) bool { return target == ErrBlockedDestination }

// Resolver is the name-resolution seam. Production uses net.DefaultResolver;
// tests substitute a stub so a rebinding scenario can be driven without any
// external network or DNS server.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DefaultDialTimeout bounds the TCP connect for a single candidate address.
const DefaultDialTimeout = 10 * time.Second

// Guard applies a Policy to outbound HTTP.
type Guard struct {
	policy   Policy
	resolver Resolver
	// transport is built once per Guard and shared by every Client() this
	// Guard hands out. Sharing it matters: the issue-tracker clients are
	// constructed per operation, and giving each one its own Transport would
	// give each one its own connection pool — turning what used to be reuse of
	// http.DefaultTransport's pool into a fresh TCP (and TLS) handshake per
	// ticket, plus idle sockets that nothing reuses.
	//
	// Reuse is also the safer direction with respect to rebinding: a pooled
	// connection was opened to an address this Guard accepted, so re-using it
	// cannot land on an address a later DNS answer introduces.
	transport *http.Transport
}

// New returns a Guard enforcing the given Policy against the system resolver.
func New(p Policy) *Guard {
	return newGuard(p, net.DefaultResolver)
}

func newGuard(p Policy, r Resolver) *Guard {
	g := &Guard{policy: clonePolicy(p), resolver: r}
	g.transport = g.buildTransport()
	return g
}

// WithResolver returns a Guard with the same Policy and a substituted name
// resolver. Test seam.
//
// It builds a new Guard rather than copying this one: the cached transport
// closes over the receiver's DialContext, so a shallow copy would keep dialing
// through the ORIGINAL resolver and the substitution would silently not apply.
func (g *Guard) WithResolver(r Resolver) *Guard {
	if r == nil {
		return g
	}
	return newGuard(g.policy, r)
}

// Policy returns a snapshot of the policy this Guard enforces.
//
// The slices are copied: a caller that mutated them would otherwise be
// rewriting live policy on a Guard that request goroutines are dialing through.
func (g *Guard) Policy() Policy { return clonePolicy(g.policy) }

// ValidateURL checks the parts of a destination that are visible without
// connecting: the scheme, the presence of a hostname, the hostname allowlist,
// and — when the host is written as a literal address — the address class.
//
// This is an input-validation convenience so a tenant admin saving a bad URL
// gets an immediate, explainable 400. It is deliberately NOT the defence: a
// hostname that resolves internally only fails at dial time, which is the point
// of the package. Callers must never treat a ValidateURL pass as permission to
// use an unguarded client.
func (g *Guard) ValidateURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// The parse error from net/url quotes the whole malformed input back.
		// Handlers echo these messages at 400, so return a fixed string instead
		// and leave the detail to the caller's own logging — Codex round 4
		// (Low) caught the surrounding comments claiming the messages carried no
		// caller-supplied text while this one carried all of it.
		return &DestinationError{Purpose: g.policy.Purpose, Reason: "URL is malformed"}
	}
	return g.validateParsedURL(parsed)
}

func (g *Guard) validateParsedURL(parsed *url.URL) error {
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !g.policy.AllowPlaintextHTTP {
			return &DestinationError{
				Purpose: g.policy.Purpose,
				Host:    parsed.Hostname(),
				Reason:  "URL must use the https scheme",
			}
		}
	default:
		return &DestinationError{
			Purpose: g.policy.Purpose,
			Host:    parsed.Hostname(),
			Reason:  fmt.Sprintf("scheme %q is not supported (expected http or https)", parsed.Scheme),
		}
	}

	host := parsed.Hostname()
	if host == "" {
		return &DestinationError{
			Purpose: g.policy.Purpose,
			Reason:  "URL has no host",
		}
	}
	if !g.policy.hostAllowed(host) {
		return &DestinationError{
			Purpose: g.policy.Purpose,
			Host:    host,
			Reason:  "host is not in the allowed domain list",
		}
	}
	// A literal address can be judged now; a name generally cannot, and is left
	// to the dialer.
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.checkAddr(host, addr)
	}
	// "localhost" and anything under ".localhost" are the one name family that
	// can be judged without resolving: RFC 6761 §6.3 reserves them for the
	// loopback interface, and a resolver that answers otherwise is
	// misconfigured. Judging them here preserves the immediate, readable
	// rejection the predecessor gave for "https://localhost/api" — the dialer
	// would refuse them a moment later anyway.
	if isLocalhostName(host) {
		if !g.policy.privateAllowedForHost(host) {
			return &DestinationError{
				Purpose: g.policy.Purpose,
				Host:    host,
				Reason:  "localhost is reserved for the loopback interface (RFC 6761) — internal destinations are disabled (set SBOMHUB_EGRESS_ALLOW_PRIVATE=true, or list this host in SBOMHUB_EGRESS_ALLOWED_INTERNAL, to permit it)",
			}
		}
	}
	return nil
}

// isLocalhostName reports whether host is "localhost" or a name under the
// reserved .localhost TLD.
func isLocalhostName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// checkAddr is the single decision point for "may this process open a
// connection to this address". Both the DialContext path and the dialer's
// Control hook funnel through it.
func (g *Guard) checkAddr(host string, addr netip.Addr) error {
	class, reason, effective := ClassifyDetailed(addr, g.policy.NAT64Prefixes)
	switch class {
	case ClassBlocked:
		return &DestinationError{Purpose: g.policy.Purpose, Host: host, Addr: addr.String(), Reason: reason}
	case ClassPrivate:
		if !g.policy.privateAllowedForAddr(host, addr, effective) {
			return &DestinationError{
				Purpose: g.policy.Purpose,
				Host:    host,
				Addr:    addr.String(),
				Reason:  reason + " — internal destinations are disabled (set SBOMHUB_EGRESS_ALLOW_PRIVATE=true, or list this host in SBOMHUB_EGRESS_ALLOWED_INTERNAL, to permit it)",
			}
		}
	case ClassPublic:
	}
	return nil
}

// lookupNetwork maps the Transport's network argument onto the address family
// argument LookupNetIP expects.
func lookupNetwork(network string) string {
	switch network {
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	default:
		return "ip"
	}
}

// DialContext resolves the destination, refuses every address the Policy
// rejects, and connects to one of the addresses it just accepted — never to a
// name, so there is no second resolution for an attacker to answer differently.
//
// A resolution failure is a refusal, not a pass. The predecessor of this code
// (issue_tracker.isBlockedHost) returned "not blocked" when net.LookupIP
// failed, with a comment explaining that the connection would fail anyway. That
// reasoning is wrong in the case that matters: a name that fails to resolve on
// the validation path and resolves fine on the connection path is precisely the
// attack, and it is also how a transient resolver hiccup turns a guard off.
func (g *Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress (%s): cannot split destination %q: %w", g.policy.Purpose, addr, err)
	}

	var candidates []netip.Addr
	if literal, perr := netip.ParseAddr(host); perr == nil {
		candidates = []netip.Addr{literal}
	} else {
		resolved, rerr := g.resolver.LookupNetIP(ctx, lookupNetwork(network), host)
		if rerr != nil {
			return nil, fmt.Errorf("egress (%s): cannot resolve %q: %w", g.policy.Purpose, host, rerr)
		}
		candidates = resolved
	}
	if len(candidates) == 0 {
		return nil, &DestinationError{Purpose: g.policy.Purpose, Host: host, Reason: "hostname resolved to no addresses"}
	}

	var permitted []netip.Addr
	var refusal error
	for _, c := range candidates {
		if cerr := g.checkAddr(host, c); cerr != nil {
			if refusal == nil {
				refusal = cerr
			}
			continue
		}
		permitted = append(permitted, c)
	}
	if len(permitted) == 0 {
		if refusal != nil {
			return nil, refusal
		}
		return nil, &DestinationError{Purpose: g.policy.Purpose, Host: host, Reason: "no permitted address"}
	}

	// Control re-checks the concrete address immediately before connect. With
	// the loop below dialing literals this is the same verdict twice over —
	// which is the intent: the guarantee "the address checked is the address
	// connected" then holds structurally rather than by reading the loop.
	//
	// The hostname is carried into the hook because the policy's per-host
	// exemptions are keyed on it; without it a host an operator explicitly
	// exempted would pass the loop above and then be refused here.
	dialer := &net.Dialer{
		Timeout:   DefaultDialTimeout,
		KeepAlive: 30 * time.Second,
		Control:   g.controlFor(host),
	}

	var lastErr error
	for _, c := range permitted {
		conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(c.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

// controlFor builds the net.Dialer.Control hook for a dial to requestHost. The
// hook is called with the concrete address the socket is about to connect to,
// which is what makes it the last word on the destination.
func (g *Guard) controlFor(requestHost string) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ipPart, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("egress (%s): cannot split connect address %q: %w", g.policy.Purpose, address, err)
		}
		addr, perr := netip.ParseAddr(ipPart)
		if perr != nil {
			// Unreachable in practice — Control is always handed a literal —
			// but a value we cannot classify must not be treated as permitted.
			return &DestinationError{Purpose: g.policy.Purpose, Host: requestHost, Addr: ipPart, Reason: "connect address is not a literal IP"}
		}
		return g.checkAddr(requestHost, addr)
	}
}

// CheckRedirect is the http.Client redirect hook. It enforces the hop cap and
// re-applies the URL-level rules (scheme, hostname allowlist) that the dialer
// cannot see. IP-level policy needs no help here: the hop goes through the same
// guarded Transport.
func (g *Guard) CheckRedirect(req *http.Request, via []*http.Request) error {
	if g.policy.MaxRedirects <= 0 {
		return http.ErrUseLastResponse
	}
	if len(via) > g.policy.MaxRedirects {
		return fmt.Errorf("egress (%s): stopped after %d redirects", g.policy.Purpose, g.policy.MaxRedirects)
	}
	return g.validateParsedURL(req.URL)
}

// Transport returns the http.Transport whose only connection path is the
// guarded dialer.
//
// It enforces the ADDRESS rules only. The scheme rule and the hostname
// allowlist are URL-level and live one layer up, so a caller that installs this
// directly gets a partially-enforcing client. Use Client or RoundTripper.
//
// The returned pointer is the one every client from this Guard shares. Its
// fields MUST NOT be mutated: doing so races with in-flight requests, and
// changing DialContext, DialTLSContext or Proxy removes the guarantee this
// package exists for. Codex round 4 (Low) flagged an earlier version of this
// comment for suggesting connection-pool tuning through it.
func (g *Guard) Transport() *http.Transport {
	return g.transport
}

// buildTransport constructs the transport from scratch.
//
// It deliberately does NOT clone http.DefaultTransport. Clone() copies every
// exported field, and three of them would silently undo this package (Codex
// round 1, Low):
//
//   - DialTLS / DialTLSContext: when either is set Go uses it for https and
//     never calls DialContext, so the guarded dialer would be bypassed for
//     exactly the scheme that matters most.
//   - TLSClientConfig.ServerName: a pinned name overrides SNI and certificate
//     verification for every destination.
//   - TLSClientConfig.InsecureSkipVerify: self-explanatory.
//
// DefaultTransport is process-global and any dependency's init() can mutate it,
// so inheriting from it means this package's guarantees depend on what else is
// linked into the binary. The timeouts below are DefaultTransport's own values,
// copied deliberately rather than inherited.
func (g *Guard) buildTransport() *http.Transport {
	t := &http.Transport{
		DialContext:           g.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// TLSClientConfig stays nil: the Transport then derives ServerName from
		// the request URL's hostname and verifies the certificate against it,
		// which is what keeps TLS honest even though DialContext opened the
		// socket to a literal address.
		TLSClientConfig: nil,
	}
	if g.policy.AllowProxy {
		// The operator has explicitly delegated destination policy to their
		// proxy. See Policy.AllowProxy.
		t.Proxy = http.ProxyFromEnvironment
	}
	return t
}

// guardedRoundTripper applies the URL-level rules to EVERY request, not just to
// redirect hops.
//
// Codex round 1 (High): CheckRedirect fires only when a redirect is being
// followed, and DialContext sees an address rather than a URL — so before this
// existed, the scheme rule and the hostname allowlist were enforced on the
// initial request only if the caller had separately remembered to run
// ValidateURL. That made the guarantee a property of every call site instead of
// a property of the client, which is the same shape of mistake this package was
// written to remove.
type guardedRoundTripper struct {
	guard *Guard
	base  http.RoundTripper
}

func (rt *guardedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.guard.validateParsedURL(req.URL); err != nil {
		return nil, err
	}
	return rt.base.RoundTrip(req)
}

// RoundTripper returns the fully guarded round tripper: URL-level rules on
// every request, address rules at dial time.
func (g *Guard) RoundTripper() http.RoundTripper {
	return &guardedRoundTripper{guard: g, base: g.transport}
}

// Client returns an http.Client wired to this Guard: URL-level rules on every
// request, guarded dialer, guarded redirect policy, and the caller's overall
// timeout.
//
// This — not Transport() — is the entry point that enforces the whole Policy.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		Transport:     g.RoundTripper(),
		CheckRedirect: g.CheckRedirect,
	}
}
