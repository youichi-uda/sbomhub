package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// GitHubIssuesClient is a client for the GitHub Issues REST API, used by the
// issue-tracker integration (F355, M24-1) alongside JiraClient / BacklogClient.
//
// Reference: https://docs.github.com/en/rest/issues/issues
// API version: 2026-03-10 (latest supported per
// docs.github.com/en/rest/about-the-rest-api/api-versions, verified via
// WebFetch 2026-07-02).
//
// Rate-limit hardening (F277 pattern, applied at birth rather than retrofitted):
// every request routes through doRequest, which handles GitHub's three
// documented rate-limit shapes (docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api,
// verified via WebFetch 2026-07-02; third shape added by F364, M24 R2):
//
//   - primary: 403 or 429 with X-RateLimit-Remaining: 0 — wait until the
//     X-RateLimit-Reset instant (UTC epoch seconds);
//   - secondary: 403 or 429 with Retry-After (delta-seconds) — wait that long;
//   - secondary, header-less: 403 whose body says "secondary rate limit" with
//     neither marker header — GitHub documents that some secondary-limit
//     responses carry no Retry-After at all. Detected by a body sniff (the
//     ghsa.go 403 body-sniff precedent) and retried on the BackoffPolicy
//     fallback.
//
// Precedence follows GitHub's own tiered guidance: Retry-After first, then
// X-RateLimit-Reset (only when X-RateLimit-Remaining is 0 — the reset header
// is present on EVERY GitHub response, so consulting it unconditionally would
// stall a secondary-limited request for up to an hour), then the exponential
// BackoffPolicy fallback. Header-derived waits are not capped by
// BackoffPolicy.MaxDelay — this mirrors the Jira/Backlog F277 behaviour — but
// the retry loop honours the caller's context.Context so long waits abort
// promptly on shutdown.
//
// Header-less secondary-limit wait (F364 decision, documented rather than
// silently chosen): GitHub's guidance for a secondary limit without
// Retry-After is "wait at least one minute before retrying". The fallback
// deliberately stays on the BackoffPolicy defaults (1s initial, 30s cap, 3
// retries) instead of a 60s in-loop floor: doRequest serves interactive
// create-ticket / test-connection handler requests, where a minutes-long
// stall is worse than failing fast, and the ticket_sync scheduler runs
// SyncTicket inside a per-tenant tx (see scheduler/ticket_sync.go's F269
// ADR) where 3 x 60s of in-tx waiting would trip managed-PG
// idle-in-transaction timeouts. Exhaustion surfaces ErrRateLimitExhausted
// and the scheduler's 5-minute cycle retries the sync — comfortably beyond
// the one-minute guidance — while an operator-facing request fails with an
// explicit, retryable error instead of hanging.
//
// Auth uses "Authorization: Bearer <token>" (same scheme as client/ghsa.go).
// The token is never placed in a URL query parameter and never included in an
// error message or log line (F65/F84 secret discipline).
type GitHubIssuesClient struct {
	httpClient    *http.Client
	baseURL       string
	token         string
	backoffPolicy BackoffPolicy
}

const (
	// githubIssuesAPIBase is the default API root. Self-hosted GitHub
	// Enterprise Server instances override it via NewGitHubIssuesClient's
	// baseURL argument (typically "https://HOST/api/v3").
	githubIssuesAPIBase = "https://api.github.com"
	// githubIssuesAPIVersion pins the REST API version header. 2026-03-10 is
	// the latest supported version (verified via WebFetch 2026-07-02); it
	// matches the value client/ghsa.go pins for the advisories endpoint.
	githubIssuesAPIVersion = "2026-03-10"
	// githubIssuesUserAgent identifies this integration. GitHub rejects
	// requests without a User-Agent header.
	githubIssuesUserAgent = "sbomhub-issue-tracker/1.0"
)

// Sentinel errors so the issue_tracker service layer can distinguish
// credential problems (401), permission problems (403), and missing repos /
// issues (404) from transient transport failures via errors.Is. The wrapping
// error text includes the (UTF-8-safe truncated) response body but never the
// token.
var (
	// ErrGitHubUnauthorized is returned on HTTP 401 — the token is missing,
	// malformed, revoked, or expired.
	ErrGitHubUnauthorized = errors.New("github: unauthorized")
	// ErrGitHubForbidden is returned on HTTP 403 that carries no recognized
	// rate-limit marker (no Retry-After header, X-RateLimit-Remaining != 0,
	// and no "secondary rate limit" body text — F364). That is most likely a
	// permission failure — the token lacks access to the repository (missing
	// scope, SAML/SSO not authorized, or issues disabled) — but a throttle
	// response that matches none of GitHub's documented markers would land
	// here too, so the error text hedges rather than asserting "permission".
	ErrGitHubForbidden = errors.New("github: forbidden")
	// ErrGitHubNotFound is returned on HTTP 404 — the repository or issue
	// does not exist, or the token cannot see it (GitHub deliberately
	// returns 404 instead of 403 for private repos the token cannot read).
	ErrGitHubNotFound = errors.New("github: not found")
	// ErrGitHubInvalidRepo is returned when a project key does not parse as
	// "owner/repo". The request is rejected client-side before any HTTP call.
	ErrGitHubInvalidRepo = errors.New("github: invalid owner/repo project key")
)

// githubRepoSegmentRe validates a single owner or repo path segment.
// Defensive allowlist per the F355 spec: GitHub's own rules are narrower
// (owners cannot contain "_" or "."), but this pattern is tight enough to
// exclude every path- or query-meaningful character ("/", "?", "#", "%",
// whitespace, ...), so a malformed project key can never rewrite the request
// path.
var githubRepoSegmentRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]+$`)

// splitGitHubRepo parses an "owner/repo" project key (the issue-tracker
// connection's DefaultProjectKey shape for GitHub) into its two segments.
// Rejections wrap ErrGitHubInvalidRepo. Dot-only segments ("." / "..") are
// rejected explicitly even though the regexp permits them, so a hostile key
// cannot smuggle path traversal into the request URL.
func splitGitHubRepo(repoFullName string) (owner, repo string, err error) {
	parts := strings.Split(repoFullName, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("github: project key %q must be \"owner/repo\": %w",
			truncate(repoFullName, 100), ErrGitHubInvalidRepo)
	}
	for _, part := range parts {
		if !githubRepoSegmentRe.MatchString(part) {
			return "", "", fmt.Errorf("github: project key %q must be \"owner/repo\" with segments matching [A-Za-z0-9_.-]+: %w",
				truncate(repoFullName, 100), ErrGitHubInvalidRepo)
		}
		if strings.Trim(part, ".") == "" {
			return "", "", fmt.Errorf("github: project key %q contains a dot-only path segment: %w",
				truncate(repoFullName, 100), ErrGitHubInvalidRepo)
		}
	}
	return parts[0], parts[1], nil
}

// NewGitHubIssuesClient creates a new GitHub Issues client with
// production-safe rate-limit defaults (3 retries, 1s initial delay, 30s cap,
// full jitter — see DefaultBackoffPolicy). baseURL is usually
// "https://api.github.com"; pass a GitHub Enterprise Server API root to
// target a self-hosted instance, or "" for the default. token is sent as
// "Authorization: Bearer <token>"; it should be a fine-grained PAT with
// Issues read/write on the target repository (or a classic PAT with repo
// scope). Use WithBackoffPolicy to override the retry cadence for tests.
func NewGitHubIssuesClient(baseURL, token string) *GitHubIssuesClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = githubIssuesAPIBase
	}
	return &GitHubIssuesClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:       strings.TrimRight(baseURL, "/"),
		token:         token,
		backoffPolicy: DefaultBackoffPolicy(),
	}
}

// WithBackoffPolicy overrides the retry cadence. Primarily used by tests to
// shrink InitialDelay so httptest exercises complete in milliseconds. Returns
// the receiver for chaining.
func (c *GitHubIssuesClient) WithBackoffPolicy(p BackoffPolicy) *GitHubIssuesClient {
	c.backoffPolicy = p
	return c
}

// GitHubIssue is a partial mapping of the GitHub issue schema, capturing only
// the fields the issue-tracker integration needs (F128-F132 defensive JSON
// posture: unknown fields are ignored, absent fields decode to zero values
// and are validated by the calling method).
type GitHubIssue struct {
	Number   int         `json:"number"`
	Title    string      `json:"title"`
	State    string      `json:"state"` // "open" or "closed"
	HTMLURL  string      `json:"html_url"`
	Assignee *GitHubUser `json:"assignee,omitempty"`
}

// GitHubUser is the subset of the GitHub user schema used for assignees.
type GitHubUser struct {
	Login string `json:"login"`
}

// CreateGitHubIssueInput represents input for creating a GitHub issue.
type CreateGitHubIssueInput struct {
	// Repo is the "owner/repo" project key.
	Repo string
	// Title is the issue title (required — GitHub rejects empty titles with
	// a 422, so the client rejects them before the round trip).
	Title string
	// Body is the issue body in GitHub-flavored Markdown (optional).
	Body string
	// Labels are attached verbatim (optional). Labels that do not exist in
	// the repository are created by GitHub when the token has permission.
	Labels []string
}

// TestConnection verifies the token can see the repository via
// GET /repos/{owner}/{repo}. A 200 response means the connection is usable;
// 401/403/404 surface as ErrGitHubUnauthorized / ErrGitHubForbidden /
// ErrGitHubNotFound respectively so the service layer can report a precise
// failure reason before persisting a connection.
func (c *GitHubIssuesClient) TestConnection(ctx context.Context, repoFullName string) error {
	owner, repo, err := splitGitHubRepo(repoFullName)
	if err != nil {
		return err
	}
	// Decode into a throwaway map (same shape as JiraClient.TestConnection)
	// so a 200 from a misconfigured proxy serving HTML still fails loudly.
	var result map[string]interface{}
	return c.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo)),
		nil, &result)
}

// CreateIssue creates a new issue via POST /repos/{owner}/{repo}/issues and
// returns the created issue (issue number + html_url are the fields the
// ticket record persists). The response is validated defensively: a 2xx
// response whose body lacks a positive issue number is an error, never a
// silently-zero ticket key.
func (c *GitHubIssuesClient) CreateIssue(ctx context.Context, input CreateGitHubIssueInput) (*GitHubIssue, error) {
	owner, repo, err := splitGitHubRepo(input.Repo)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Title) == "" {
		return nil, fmt.Errorf("github: issue title must not be empty")
	}

	payload := map[string]interface{}{
		"title": input.Title,
	}
	if input.Body != "" {
		payload["body"] = input.Body
	}
	if len(input.Labels) > 0 {
		payload["labels"] = input.Labels
	}

	var issue GitHubIssue
	if err := c.doRequest(ctx, http.MethodPost,
		fmt.Sprintf("/repos/%s/%s/issues", url.PathEscape(owner), url.PathEscape(repo)),
		payload, &issue); err != nil {
		return nil, err
	}
	if issue.Number <= 0 {
		return nil, fmt.Errorf("github: create issue response for %s/%s is missing a positive issue number", owner, repo)
	}
	return &issue, nil
}

// GetIssue fetches an issue via GET /repos/{owner}/{repo}/issues/{number}.
// Note that the GitHub Issues API also serves pull requests through this
// endpoint (every PR is an issue), so a ticket that was manually converted /
// cross-linked still resolves.
//
// SyncTicket consumes this directly (F367) — state normalisation and the
// defensive empty-state error live in the service's GitHub sync arm, next to
// the identical Jira/Backlog handling. A GetIssueStatus state-only wrapper
// existed until F367 and was removed once consumer-less (F280 discipline).
func (c *GitHubIssuesClient) GetIssue(ctx context.Context, repoFullName string, issueNumber int) (*GitHubIssue, error) {
	owner, repo, err := splitGitHubRepo(repoFullName)
	if err != nil {
		return nil, err
	}
	if issueNumber <= 0 {
		return nil, fmt.Errorf("github: issue number must be positive, got %d", issueNumber)
	}

	var issue GitHubIssue
	if err := c.doRequest(ctx, http.MethodGet,
		fmt.Sprintf("/repos/%s/%s/issues/%d", url.PathEscape(owner), url.PathEscape(repo), issueNumber),
		nil, &issue); err != nil {
		return nil, err
	}
	return &issue, nil
}

// isGitHubRateLimited reports whether a response is one of GitHub's three
// documented rate-limit shapes. 429 is always a rate limit. 403 is a rate
// limit only when it carries a rate-limit marker: Retry-After for the
// secondary limit, X-RateLimit-Remaining: 0 for the primary limit, or —
// F364, the header-less secondary form — a body that says "secondary rate
// limit" ("You have exceeded a secondary rate limit. Please wait a few
// minutes before you try again." with neither marker header; body sniff per
// the ghsa.go 403 precedent, matched case-insensitively and on the
// distinctive "secondary rate limit" phrase so a permission body mentioning
// "rate limit" in passing is not misclassified). A 403 with no marker at all
// is treated as a permission failure that retrying cannot fix.
func isGitHubRateLimited(status int, retryAfter, rateLimitRemaining string, body []byte) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if status != http.StatusForbidden {
		return false
	}
	if strings.TrimSpace(retryAfter) != "" {
		return true
	}
	if strings.TrimSpace(rateLimitRemaining) == "0" {
		return true
	}
	return strings.Contains(strings.ToLower(string(body)), "secondary rate limit")
}

func (c *GitHubIssuesClient) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	// Marshal the request body once; retries reuse the encoded bytes with a
	// fresh reader per attempt (F301 body-reuse contract — a rate-limited
	// CreateIssue has not been accepted by GitHub, so a retry is safe).
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("github: failed to marshal request body: %w", err)
		}
	}

	// F277 pattern: retry loop handles GitHub's primary (403/429 +
	// X-RateLimit-Remaining: 0 + X-RateLimit-Reset) and secondary (403/429 +
	// Retry-After) rate limits. attempt == 0 is the initial request;
	// attempts 1..N are retries capped by c.backoffPolicy.MaxRetries.
	maxRetries := c.backoffPolicy.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt <= maxRetries; attempt++ {
		var reqBody io.Reader
		if encoded != nil {
			reqBody = bytes.NewReader(encoded)
		}

		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
		if err != nil {
			return fmt.Errorf("github: failed to create request: %w", err)
		}

		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", githubIssuesAPIVersion)
		req.Header.Set("User-Agent", githubIssuesUserAgent)
		if encoded != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.token != "" {
			// Header-only auth — the token never appears in the URL (F65/F84).
			req.Header.Set("Authorization", "Bearer "+c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("github: failed to execute request: %w", err)
		}

		// F300/F309: bound the response body read at maxResponseBodyBytes
		// (8 MiB) so a hostile or misconfigured upstream that streams a
		// multi-GB body under the 30s client-side timeout cannot exhaust
		// process memory. The cap applies universally (2xx / 4xx / 5xx /
		// 429) because this doRequest funnel carries every status class.
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		retryAfter := resp.Header.Get("Retry-After")
		rateLimitRemaining := resp.Header.Get("X-RateLimit-Remaining")
		rateLimitReset := resp.Header.Get("X-RateLimit-Reset")
		status := resp.StatusCode
		// F312: drain any unread remainder before Close so http.Transport
		// can return the underlying TCP+TLS connection to the idle pool
		// instead of aborting it and forcing a fresh handshake on retry.
		// io.Discard is bounded by the upstream body length, so no
		// unbounded read is introduced here.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("github: failed to read response: %w", readErr)
		}

		if isGitHubRateLimited(status, retryAfter, rateLimitRemaining, respBody) {
			lastStatus = status
			lastBody = respBody
			if attempt == maxRetries {
				break
			}
			// Tiered per GitHub's documented guidance: Retry-After first
			// (secondary limit), then X-RateLimit-Reset but only when the
			// remaining count is exhausted (primary limit — the reset
			// header is present on every response, so gating on
			// remaining == 0 avoids stalling a secondary-limit retry for
			// the rest of the primary window), then exponential backoff.
			// The header-less body-sniffed secondary form (F364) carries
			// neither header, so it lands on the plain BackoffPolicy
			// fallback — see the type docstring for why that fallback is
			// NOT floored at GitHub's one-minute guidance.
			fallback := c.backoffPolicy.Delay(attempt)
			if strings.TrimSpace(rateLimitRemaining) == "0" {
				fallback = RespectRateLimitReset(rateLimitReset, fallback)
			}
			delay := RespectRetryAfter(retryAfter, fallback)
			if err := waitOrDone(ctx, delay); err != nil {
				return err
			}
			continue
		}

		switch status {
		case http.StatusUnauthorized:
			return fmt.Errorf("github: API error 401 (token missing, revoked, or expired): %s: %w",
				truncate(string(respBody), 200), ErrGitHubUnauthorized)
		case http.StatusForbidden:
			return fmt.Errorf("github: API error 403 with no rate-limit markers — likely a permission failure (token lacks repository access, SSO not authorized, or issues disabled), though an unrecognized throttle response cannot be ruled out: %s: %w",
				truncate(string(respBody), 200), ErrGitHubForbidden)
		case http.StatusNotFound:
			return fmt.Errorf("github: API error 404 (repository or issue not found, or token cannot see it): %s: %w",
				truncate(string(respBody), 200), ErrGitHubNotFound)
		}

		if status >= 400 {
			return fmt.Errorf("github: API error: %d - %s", status, truncate(string(respBody), 200))
		}

		if result != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				return fmt.Errorf("github: failed to unmarshal response: %w", err)
			}
		}

		return nil
	}

	return fmt.Errorf("github: rate limit exhausted after %d retries (last status %d, body: %s): %w",
		maxRetries, lastStatus, truncate(string(lastBody), 200), ErrRateLimitExhausted)
}
