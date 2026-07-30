package client

import "github.com/sbomhub/sbomhub/internal/egress"

// The three helpers below exist because the production constructors now install
// the strict tenant-egress guard by default, and these tests point their
// clients at httptest.Server instances bound to loopback — a destination that
// guard is specifically there to refuse.
//
// Rather than weaken the default, each test declares that its destination is
// operator-chosen (which, in a test, it is). Keeping that explicit is the point:
// if a future production call site ever needs an unguarded client it has to say
// so in the same visible way, instead of inheriting one.
//
// testJiraClient takes email as a parameter even though every current caller
// passes the same address: it mirrors NewJiraClient's signature so the sed-style
// substitution that introduced it stays reviewable against the constructor.
func testJiraClient(baseURL, email, apiToken string) *JiraClient { //nolint:unparam // mirrors NewJiraClient's signature
	return NewJiraClient(baseURL, email, apiToken).WithEgress(egress.OperatorControlled())
}

func testBacklogClient(baseURL, apiKey string) *BacklogClient {
	return NewBacklogClient(baseURL, apiKey).WithEgress(egress.OperatorControlled())
}

func testGitHubIssuesClient(baseURL, token string) *GitHubIssuesClient {
	return NewGitHubIssuesClient(baseURL, token).WithEgress(egress.OperatorControlled())
}
