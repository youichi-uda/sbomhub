package egress

import "net/netip"

// defaultMaxRedirects is the hop cap for the purposes that follow redirects at
// all. Three is enough for the redirects real services emit (http->https, a
// renamed GitHub repository, a vanity host in front of Jira) without giving a
// hostile endpoint an unbounded chain to walk.
const defaultMaxRedirects = 3

// Settings are the operator-controlled inputs that shape every Policy. They
// come from the environment; see internal/config for the variable names and
// docs/security/egress.md for the operator-facing description.
type Settings struct {
	// AllowPrivate opens ClassPrivate destinations (RFC1918, loopback, CGNAT,
	// IPv6 ULA) for every tenant-configured purpose. Default false, in every
	// deployment mode. Blocked-class destinations stay refused regardless.
	AllowPrivate bool

	// PrivateHostExemptions / PrivateCIDRExemptions open ClassPrivate for
	// specific hosts or networks without opening it wholesale.
	PrivateHostExemptions []string
	PrivateCIDRExemptions []netip.Prefix

	// NAT64Prefixes are operator-declared RFC 6052 translation prefixes, so that
	// addresses under them are judged by the IPv4 address they embed. Without
	// this, a deployment reaching IPv4 through its own NAT64 prefix has every
	// IPv4 rule in ip.go bypassed for translated traffic.
	NAT64Prefixes []netip.Prefix

	// AllowProxy honours HTTP_PROXY / HTTPS_PROXY for tenant-configured egress.
	// Default false: with a proxy in play the dialer only ever sees the proxy's
	// address and the proxy chooses the real destination, so the dial-time
	// guarantee does not hold. Setting it true delegates destination policy to
	// the proxy. See Policy.AllowProxy.
	AllowProxy bool

	// IssueTrackerAllowedHosts is the SaaS-mode hostname allowlist for issue
	// tracker base URLs. Empty means "any hostname" (self-hosted default),
	// which is the pre-existing behaviour of
	// IssueTrackerService.allowedDomains.
	IssueTrackerAllowedHosts []string
}

// Set holds one Guard per tenant-configurable outbound purpose. Wiring passes
// the individual Guards to the services that own each sink, so a service can
// only reach the destinations its own purpose permits.
type Set struct {
	IssueTracker        *Guard
	NotificationWebhook *Guard
	DiffWebhook         *Guard
	TenantLLM           *Guard
}

// NewSet builds the per-purpose Guards.
//
// The differences between the purposes are deliberate and each has a reason:
//
//   - issue_tracker refuses plaintext http. That is pre-existing behaviour
//     (validateBaseURL required https since the connection carries an API
//     token) and is kept.
//   - diff_webhook does not follow redirects. Also pre-existing (M48): a 307
//     preserves method and body, and the format=slack signing exemption is
//     evaluated against the configured host, so a redirect could carry an
//     unsigned payload off that host.
//   - notification_webhook and tenant_llm follow redirects up to the cap. They
//     followed redirects before this package existed; every hop is now
//     re-validated and dialed through the guard, so following is no longer the
//     hole it was, and refusing outright would break deployments that rely on
//     an http->https or vanity-host redirect.
//   - notification_webhook and tenant_llm allow plaintext http, matching what
//     their handlers accepted before. Tightening those to https-only is a
//     separate, user-visible change and is not folded into a security fix.
func NewSet(s Settings) *Set {
	base := Policy{
		AllowPrivate:          s.AllowPrivate,
		PrivateHostExemptions: s.PrivateHostExemptions,
		PrivateCIDRExemptions: s.PrivateCIDRExemptions,
		NAT64Prefixes:         s.NAT64Prefixes,
		AllowProxy:            s.AllowProxy,
	}

	issueTracker := base
	issueTracker.Purpose = PurposeIssueTracker
	issueTracker.AllowedHosts = s.IssueTrackerAllowedHosts
	issueTracker.AllowPlaintextHTTP = false
	issueTracker.MaxRedirects = defaultMaxRedirects

	notification := base
	notification.Purpose = PurposeNotificationWebhook
	notification.AllowPlaintextHTTP = true
	notification.MaxRedirects = defaultMaxRedirects

	diff := base
	diff.Purpose = PurposeDiffWebhook
	diff.AllowPlaintextHTTP = true
	diff.MaxRedirects = 0

	llm := base
	llm.Purpose = PurposeTenantLLM
	llm.AllowPlaintextHTTP = true
	llm.MaxRedirects = defaultMaxRedirects

	return &Set{
		IssueTracker:        New(issueTracker),
		NotificationWebhook: New(notification),
		DiffWebhook:         New(diff),
		TenantLLM:           New(llm),
	}
}

// OperatorControlled returns a Guard for destinations that come from the
// operator rather than from a tenant: internal addresses are permitted and
// plaintext http is permitted.
//
// It exists so that a call site which is NOT tenant-driven has to say so, in
// code, at the call site — rather than reaching a guard-taking constructor with
// a nil and getting the same effect by accident. cmd/llm-bench is the intended
// user: its destination comes from the operator's own flags.
//
// It is not a bypass of the whole package: ClassBlocked destinations (cloud
// metadata, multicast, tunnel forms embedding them) are still refused, because
// no operator CLI has a reason to POST a chat completion at 169.254.169.254.
//
// Never reachable from an HTTP handler.
func OperatorControlled() *Guard {
	return New(Policy{
		Purpose:            "operator_controlled",
		AllowPrivate:       true,
		AllowPlaintextHTTP: true,
		MaxRedirects:       defaultMaxRedirects,
		// The operator's proxy configuration applies to the operator's own
		// destinations. There is no tenant-supplied address here for a proxy to
		// launder.
		AllowProxy: true,
	})
}
