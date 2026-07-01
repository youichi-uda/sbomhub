package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// BacklogClient is a client for the Backlog API
//
// Rate-limit hardening (F277, M19-1): every request routes through doRequest,
// which handles HTTP 429 Too Many Requests by respecting the X-RateLimit-Reset
// header (Backlog / Nulab publish an epoch-seconds reset instant rather than
// the standard Retry-After — see developer.nulab.com/docs/backlog/rate-limit/,
// verified via WebFetch 2026-07-01) and falling back to Retry-After, then
// exponential backoff with full jitter. The retry loop honours the caller's
// context.Context so long backoffs abort promptly on shutdown.
type BacklogClient struct {
	httpClient    *http.Client
	baseURL       string
	apiKey        string
	backoffPolicy BackoffPolicy
}

// NewBacklogClient creates a new Backlog client with production-safe
// rate-limit defaults (3 retries, 1s initial delay, 30s cap, full jitter).
// Use WithBackoffPolicy to override for tests or aggressive callers.
func NewBacklogClient(baseURL, apiKey string) *BacklogClient {
	return &BacklogClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:       baseURL,
		apiKey:        apiKey,
		backoffPolicy: DefaultBackoffPolicy(),
	}
}

// WithBackoffPolicy overrides the retry cadence. Primarily used by tests to
// shrink InitialDelay so httptest exercises complete in milliseconds. Returns
// the receiver for chaining.
func (c *BacklogClient) WithBackoffPolicy(p BackoffPolicy) *BacklogClient {
	c.backoffPolicy = p
	return c
}

// BacklogIssue represents a Backlog issue
type BacklogIssue struct {
	ID          int              `json:"id"`
	ProjectID   int              `json:"projectId"`
	IssueKey    string           `json:"issueKey"`
	KeyID       int              `json:"keyId"`
	IssueType   BacklogIssueType `json:"issueType"`
	Summary     string           `json:"summary"`
	Description string           `json:"description"`
	Status      BacklogStatus    `json:"status"`
	Priority    BacklogPriority  `json:"priority"`
	Assignee    *BacklogUser     `json:"assignee"`
	Created     string           `json:"created"`
	Updated     string           `json:"updated"`
}

// BacklogIssueType represents a Backlog issue type
type BacklogIssueType struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// BacklogStatus represents a Backlog status
type BacklogStatus struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// BacklogPriority represents a Backlog priority
type BacklogPriority struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// BacklogUser represents a Backlog user
type BacklogUser struct {
	ID          int    `json:"id"`
	UserID      string `json:"userId"`
	Name        string `json:"name"`
	MailAddress string `json:"mailAddress"`
}

// BacklogProject represents a Backlog project
type BacklogProject struct {
	ID         int    `json:"id"`
	ProjectKey string `json:"projectKey"`
	Name       string `json:"name"`
}

// CreateBacklogIssueInput represents input for creating a Backlog issue
type CreateBacklogIssueInput struct {
	ProjectID   int
	IssueTypeID int
	PriorityID  int
	Summary     string
	Description string
}

// CreateIssue creates a new Backlog issue
func (c *BacklogClient) CreateIssue(ctx context.Context, input CreateBacklogIssueInput) (*BacklogIssue, error) {
	params := url.Values{}
	params.Set("projectId", strconv.Itoa(input.ProjectID))
	params.Set("issueTypeId", strconv.Itoa(input.IssueTypeID))
	params.Set("priorityId", strconv.Itoa(input.PriorityID))
	params.Set("summary", input.Summary)
	if input.Description != "" {
		params.Set("description", input.Description)
	}

	var issue BacklogIssue
	if err := c.doRequest(ctx, "POST", "/api/v2/issues", params, &issue); err != nil {
		return nil, err
	}

	return &issue, nil
}

// GetIssue gets a Backlog issue by key or ID
func (c *BacklogClient) GetIssue(ctx context.Context, issueKeyOrID string) (*BacklogIssue, error) {
	var issue BacklogIssue
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/v2/issues/%s", issueKeyOrID), nil, &issue); err != nil {
		return nil, err
	}

	return &issue, nil
}

// GetProjects gets available Backlog projects
func (c *BacklogClient) GetProjects(ctx context.Context) ([]BacklogProject, error) {
	var projects []BacklogProject
	if err := c.doRequest(ctx, "GET", "/api/v2/projects", nil, &projects); err != nil {
		return nil, err
	}

	return projects, nil
}

// GetIssueTypes gets issue types for a project
func (c *BacklogClient) GetIssueTypes(ctx context.Context, projectIDOrKey string) ([]BacklogIssueType, error) {
	var issueTypes []BacklogIssueType
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/v2/projects/%s/issueTypes", projectIDOrKey), nil, &issueTypes); err != nil {
		return nil, err
	}

	return issueTypes, nil
}

// GetPriorities gets available priorities
func (c *BacklogClient) GetPriorities(ctx context.Context) ([]BacklogPriority, error) {
	var priorities []BacklogPriority
	if err := c.doRequest(ctx, "GET", "/api/v2/priorities", nil, &priorities); err != nil {
		return nil, err
	}

	return priorities, nil
}

// TestConnection tests the Backlog connection
func (c *BacklogClient) TestConnection(ctx context.Context) error {
	var result map[string]interface{}
	return c.doRequest(ctx, "GET", "/api/v2/users/myself", nil, &result)
}

// GetIssueURL returns the web URL for an issue
func (c *BacklogClient) GetIssueURL(issueKey string) string {
	return fmt.Sprintf("%s/view/%s", c.baseURL, issueKey)
}

func (c *BacklogClient) doRequest(ctx context.Context, method, path string, params url.Values, result interface{}) error {
	// Add API key to params
	if params == nil {
		params = url.Values{}
	}
	params.Set("apiKey", c.apiKey)

	// Precompute the encoded form once so retries reuse it. The API key +
	// projectId are identical across attempts, so re-encoding per attempt
	// would burn CPU with no upside.
	encoded := params.Encode()
	fullURL := c.baseURL + path
	if method == "GET" {
		fullURL += "?" + encoded
	}

	// F277 (M19-1): retry loop handles HTTP 429 by respecting either
	// X-RateLimit-Reset (Backlog's documented header, epoch seconds) or
	// Retry-After (defensive fallback for proxies that inject it), then
	// exponential backoff.
	maxRetries := c.backoffPolicy.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	var lastStatus int
	var lastBody []byte
	for attempt := 0; attempt <= maxRetries; attempt++ {
		var reqBody io.Reader
		if method != "GET" {
			reqBody = bytes.NewReader([]byte(encoded))
		}

		req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		if method != "GET" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute request: %w", err)
		}

		// F300 (M20-3): bound the response body read at maxErrorBodyBytes so a
		// hostile or misconfigured upstream that streams a multi-GB body under
		// the 30s client-side timeout cannot exhaust process memory. Every
		// successful Backlog response fits comfortably under 64 KiB — the same
		// bound also caps 4xx/5xx error bodies used in the "Backlog API error"
		// diagnostic and the 429 body carried into ErrRateLimitExhausted.
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		retryAfter := resp.Header.Get("Retry-After")
		rateLimitReset := resp.Header.Get("X-RateLimit-Reset")
		status := resp.StatusCode
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("failed to read response: %w", readErr)
		}

		if status == http.StatusTooManyRequests {
			lastStatus = status
			lastBody = respBody
			if attempt == maxRetries {
				break
			}
			// Precedence: X-RateLimit-Reset (documented) > Retry-After
			// (defensive) > exponential backoff.
			fallback := RespectRetryAfter(retryAfter, c.backoffPolicy.Delay(attempt))
			delay := RespectRateLimitReset(rateLimitReset, fallback)
			if err := waitOrDone(ctx, delay); err != nil {
				return err
			}
			continue
		}

		if status >= 400 {
			return fmt.Errorf("Backlog API error: %d - %s", status, string(respBody))
		}

		if result != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}
		}

		return nil
	}

	return fmt.Errorf("backlog: rate limit exhausted after %d retries (last status %d, body: %s): %w",
		maxRetries, lastStatus, truncate(string(lastBody), 200), ErrRateLimitExhausted)
}
