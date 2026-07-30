package client

import (
	"net/http"
	"time"

	"github.com/sbomhub/sbomhub/internal/egress"
)

// issueTrackerHTTPTimeout is the per-request budget shared by the Jira,
// Backlog and GitHub Issues clients. It matches the value each constructor used
// before the egress guard was introduced.
const issueTrackerHTTPTimeout = 30 * time.Second

// guardedIssueTrackerClient builds the *http.Client an issue-tracker client
// uses.
//
// The base URL of these clients is issue_tracker_connections.base_url, which a
// tenant administrator types into a settings screen. A nil guard is therefore
// NOT "no policy needed" — it is a call site that forgot to say which policy
// applies, and the safe reading of that is the strictest policy we have. So a
// nil guard produces a client that permits nothing internal, rather than an
// unguarded http.Client.
//
// Tests that need to reach an httptest.Server on loopback pass a guard built
// with AllowPrivate (see egress.OperatorControlled) or inject their own client
// via WithEgress.
func guardedIssueTrackerClient(g *egress.Guard) *http.Client {
	if g == nil {
		g = egress.NewSet(egress.Settings{}).IssueTracker
	}
	return g.Client(issueTrackerHTTPTimeout)
}

// WithEgress routes this client's requests through the supplied egress guard.
//
// The production caller is internal/service.IssueTrackerService, which passes
// the guard built from the deployment's SBOMHUB_EGRESS_* configuration. Passing
// nil is a no-op rather than a downgrade: the constructor already installed the
// strictest guard, and a nil here means the caller had nothing more specific to
// say, not that policy should be dropped.
func (c *JiraClient) WithEgress(g *egress.Guard) *JiraClient {
	if g != nil {
		c.httpClient = g.Client(issueTrackerHTTPTimeout)
	}
	return c
}

// WithEgress routes this client's requests through the supplied egress guard.
// See JiraClient.WithEgress.
func (c *BacklogClient) WithEgress(g *egress.Guard) *BacklogClient {
	if g != nil {
		c.httpClient = g.Client(issueTrackerHTTPTimeout)
	}
	return c
}

// WithEgress routes this client's requests through the supplied egress guard.
// See JiraClient.WithEgress.
func (c *GitHubIssuesClient) WithEgress(g *egress.Guard) *GitHubIssuesClient {
	if g != nil {
		c.httpClient = g.Client(issueTrackerHTTPTimeout)
	}
	return c
}
