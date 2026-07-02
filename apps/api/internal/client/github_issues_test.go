package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testGitHubBackoff returns a BackoffPolicy tuned for httptest — small delays
// so test runtime stays sub-second and no jitter so the retry cadence is
// deterministic (same convention as testJiraBackoff / testBacklogBackoff:
// InitialDelay=5ms, MaxDelay=50ms, Jitter=false; production defaults are
// 1s/30s/jitter per DefaultBackoffPolicy).
func testGitHubBackoff(maxRetries int) BackoffPolicy {
	return BackoffPolicy{
		MaxRetries:   maxRetries,
		InitialDelay: 5 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Jitter:       false,
	}
}

func TestNewGitHubIssuesClient(t *testing.T) {
	c := NewGitHubIssuesClient("https://api.github.com", "token123")
	if c == nil {
		t.Fatal("expected client to be created")
	}
	if c.baseURL != "https://api.github.com" {
		t.Errorf("unexpected baseURL: %s", c.baseURL)
	}
	if c.token != "token123" {
		t.Errorf("unexpected token: %s", c.token)
	}

	// Empty baseURL falls back to the public API root (GitHub Enterprise
	// callers pass their own API root explicitly).
	c = NewGitHubIssuesClient("", "token123")
	if c.baseURL != "https://api.github.com" {
		t.Errorf("expected default baseURL, got: %s", c.baseURL)
	}

	// Trailing slashes are trimmed so path joining cannot produce "//repos".
	c = NewGitHubIssuesClient("https://ghe.example.com/api/v3/", "token123")
	if c.baseURL != "https://ghe.example.com/api/v3" {
		t.Errorf("expected trailing slash trimmed, got: %s", c.baseURL)
	}
}

func TestGitHubIssuesClient_TestConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token123" {
			t.Errorf("unexpected Authorization header: %s", got)
		}
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("unexpected Accept header: %s", got)
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != githubIssuesAPIVersion {
			t.Errorf("unexpected X-GitHub-Api-Version header: %s", got)
		}
		if got := r.Header.Get("User-Agent"); got != githubIssuesUserAgent {
			t.Errorf("unexpected User-Agent header: %s", got)
		}
		// Token must ride the Authorization header only — never the URL.
		if strings.Contains(r.URL.RawQuery, "token123") {
			t.Errorf("token leaked into URL query: %s", r.URL.RawQuery)
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":        12345,
			"full_name": "acme/widget",
		})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")
	if err := client.TestConnection(context.Background(), "acme/widget"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGitHubIssuesClient_TestConnection_ErrorStatuses pins the 401/403/404
// discrimination contract: each maps to its own sentinel via errors.Is so the
// service layer can report a precise failure reason. A plain 403 (no
// rate-limit markers) must NOT be retried — it is a permission failure that
// retrying cannot fix — so the per-case hit counter also pins single-shot
// behaviour. F65/F84 secret discipline is asserted on every error string.
func TestGitHubIssuesClient_TestConnection_ErrorStatuses(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		sentinel error
	}{
		{"unauthorized_401", http.StatusUnauthorized, `{"message":"Bad credentials"}`, ErrGitHubUnauthorized},
		{"forbidden_403_not_rate_limit", http.StatusForbidden, `{"message":"Resource not accessible by personal access token"}`, ErrGitHubForbidden},
		{"not_found_404", http.StatusNotFound, `{"message":"Not Found"}`, ErrGitHubNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			client := NewGitHubIssuesClient(server.URL, "secret-token-value").
				WithBackoffPolicy(testGitHubBackoff(3))

			err := client.TestConnection(context.Background(), "acme/widget")
			if err == nil {
				t.Fatalf("expected error for status %d, got nil", tc.status)
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", tc.sentinel, err)
			}
			if strings.Contains(err.Error(), "secret-token-value") {
				t.Errorf("token leaked into error message: %v", err)
			}
			// 401/403/404 are terminal — exactly one request, no retry burn.
			if got := atomic.LoadInt32(&hits); got != 1 {
				t.Errorf("expected exactly 1 request (no retry on %d), got %d", tc.status, got)
			}
		})
	}
}

func TestGitHubIssuesClient_CreateIssue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/issues" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("unexpected content-type: %s", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token123" {
			t.Errorf("unexpected Authorization header: %s", got)
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}
		if body["title"] != "CVE-2026-0001 in acme-lib" {
			t.Errorf("unexpected title: %v", body["title"])
		}
		if body["body"] != "Critical vulnerability details" {
			t.Errorf("unexpected body: %v", body["body"])
		}
		labels, ok := body["labels"].([]interface{})
		if !ok || len(labels) != 2 || labels[0] != "security" {
			t.Errorf("unexpected labels: %v", body["labels"])
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"number":   42,
			"title":    "CVE-2026-0001 in acme-lib",
			"state":    "open",
			"html_url": "https://github.com/acme/widget/issues/42",
		})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")

	issue, err := client.CreateIssue(context.Background(), CreateGitHubIssueInput{
		Repo:   "acme/widget",
		Title:  "CVE-2026-0001 in acme-lib",
		Body:   "Critical vulnerability details",
		Labels: []string{"security", "sbomhub"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issue.Number != 42 {
		t.Errorf("unexpected issue number: %d", issue.Number)
	}
	if issue.HTMLURL != "https://github.com/acme/widget/issues/42" {
		t.Errorf("unexpected html_url: %s", issue.HTMLURL)
	}
	if issue.State != "open" {
		t.Errorf("unexpected state: %s", issue.State)
	}
}

// TestGitHubIssuesClient_CreateIssue_EmptyTitle pins the client-side reject:
// GitHub would 422 an empty title anyway, so the client refuses before
// spending a round trip (and a rate-limit token) on it.
func TestGitHubIssuesClient_CreateIssue_EmptyTitle(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")
	_, err := client.CreateIssue(context.Background(), CreateGitHubIssueInput{
		Repo:  "acme/widget",
		Title: "   ",
	})
	if err == nil {
		t.Fatal("expected error for empty title, got nil")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected 0 HTTP requests for client-side reject, got %d", got)
	}
}

// TestGitHubIssuesClient_CreateIssue_MissingNumber pins the defensive JSON
// posture (F128-F132): a 2xx response whose body lacks a positive issue
// number must error rather than persist a zero ticket key.
func TestGitHubIssuesClient_CreateIssue_MissingNumber(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"html_url":"https://github.com/acme/widget/issues/0"}`))
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")
	_, err := client.CreateIssue(context.Background(), CreateGitHubIssueInput{
		Repo:  "acme/widget",
		Title: "valid title",
	})
	if err == nil {
		t.Fatal("expected error for missing issue number, got nil")
	}
	if !strings.Contains(err.Error(), "issue number") {
		t.Errorf("expected missing-issue-number error, got: %v", err)
	}
}

func TestGitHubIssuesClient_GetIssueStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/issues/42" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"number":   42,
			"title":    "CVE-2026-0001 in acme-lib",
			"state":    "closed",
			"html_url": "https://github.com/acme/widget/issues/42",
			"assignee": map[string]interface{}{"login": "octocat"},
		})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")

	state, err := client.GetIssueStatus(context.Background(), "acme/widget", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != "closed" {
		t.Errorf("unexpected state: %s", state)
	}

	// GetIssue exposes the richer record (assignee for SyncTicket parity
	// with Jira/Backlog).
	issue, err := client.GetIssue(context.Background(), "acme/widget", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issue.Assignee == nil || issue.Assignee.Login != "octocat" {
		t.Errorf("unexpected assignee: %+v", issue.Assignee)
	}
}

// TestGitHubIssuesClient_GetIssueStatus_Defensive pins the malformed-response
// arms of the status poll: a missing state and an invalid issue number must
// both error instead of returning "".
func TestGitHubIssuesClient_GetIssueStatus_Defensive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"number":42}`))
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")

	if _, err := client.GetIssueStatus(context.Background(), "acme/widget", 42); err == nil {
		t.Error("expected error for response missing state, got nil")
	}
	if _, err := client.GetIssueStatus(context.Background(), "acme/widget", 0); err == nil {
		t.Error("expected error for non-positive issue number, got nil")
	}
}

// TestGitHubIssuesClient_RepoValidation pins the owner/repo project-key
// format gate: every malformed shape is rejected client-side with
// ErrGitHubInvalidRepo and zero HTTP requests, across all three public
// methods. Valid shapes (including dot-containing repo names) pass through
// to the wire.
func TestGitHubIssuesClient_RepoValidation(t *testing.T) {
	invalid := []struct {
		name string
		repo string
	}{
		{"empty", ""},
		{"no_slash", "acme"},
		{"three_segments", "acme/widget/extra"},
		{"empty_owner", "/widget"},
		{"empty_repo", "acme/"},
		{"space_in_owner", "ac me/widget"},
		{"space_in_repo", "acme/wid get"},
		{"percent_escape", "acme/wid%2Fget"},
		{"query_char", "acme/widget?x=1"},
		{"dot_traversal_owner", "../widget"},
		{"dot_traversal_repo", "acme/.."},
		{"single_dot_repo", "acme/."},
		{"unicode_owner", "acmé/widget"},
	}

	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")
	ctx := context.Background()

	for _, tc := range invalid {
		t.Run("invalid_"+tc.name, func(t *testing.T) {
			if err := client.TestConnection(ctx, tc.repo); !errors.Is(err, ErrGitHubInvalidRepo) {
				t.Errorf("TestConnection(%q): expected ErrGitHubInvalidRepo, got: %v", tc.repo, err)
			}
			if _, err := client.CreateIssue(ctx, CreateGitHubIssueInput{Repo: tc.repo, Title: "t"}); !errors.Is(err, ErrGitHubInvalidRepo) {
				t.Errorf("CreateIssue(%q): expected ErrGitHubInvalidRepo, got: %v", tc.repo, err)
			}
			if _, err := client.GetIssueStatus(ctx, tc.repo, 1); !errors.Is(err, ErrGitHubInvalidRepo) {
				t.Errorf("GetIssueStatus(%q): expected ErrGitHubInvalidRepo, got: %v", tc.repo, err)
			}
		})
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("expected 0 HTTP requests for invalid project keys, got %d", got)
	}

	valid := []string{"acme/widget", "a-b_c.d/e.f-g_h", "acme/re..po", "0/1"}
	for _, repo := range valid {
		owner, name, err := splitGitHubRepo(repo)
		if err != nil {
			t.Errorf("splitGitHubRepo(%q): unexpected error: %v", repo, err)
			continue
		}
		if owner+"/"+name != repo {
			t.Errorf("splitGitHubRepo(%q) round-trip mismatch: %s/%s", repo, owner, name)
		}
	}
}

// ---------------------------------------------------------------------------
// F277-pattern rate-limit hardening — all three documented GitHub shapes:
//   - secondary: 403/429 + Retry-After (delta-seconds)
//   - primary:   403/429 + X-RateLimit-Remaining: 0 + X-RateLimit-Reset (epoch)
//   - secondary, header-less (F364): 403 + "secondary rate limit" body, no
//     marker headers at all
// plus exhaustion, context-cancel abort, and POST body reuse across retries.
// The tests exercise doRequest through the public methods because the retry
// logic lives on the shared funnel.
// ---------------------------------------------------------------------------

// TestGitHubIssuesClient_RateLimit_SecondaryRetryAfter pins the secondary
// rate-limit shape: 403 + Retry-After. The client must classify the 403 as
// retryable (NOT ErrGitHubForbidden), wait the Retry-After delta, and succeed
// on the next attempt.
func TestGitHubIssuesClient_RateLimit_SecondaryRetryAfter(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"full_name": "acme/widget"})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	if err := client.TestConnection(context.Background(), "acme/widget"); err != nil {
		t.Fatalf("expected success after secondary-limit retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests (1 x 403+Retry-After + 1 x 200), got %d", got)
	}
}

// TestGitHubIssuesClient_RateLimit_SecondaryBodySniff pins the third,
// header-less secondary rate-limit shape (F364, M24 R2): 403 whose body says
// "secondary rate limit" with NO Retry-After and NO X-RateLimit-Remaining.
// Pre-F364 this shape fell through to the terminal ErrGitHubForbidden arm;
// it must instead be classified retryable, wait the BackoffPolicy fallback
// (no header to honor), and succeed on the next attempt.
func TestGitHubIssuesClient_RateLimit_SecondaryBodySniff(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			// Deliberately no rate-limit headers — the body is the only marker.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"You have exceeded a secondary rate limit. Please wait a few minutes before you try again.","documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"full_name": "acme/widget"})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	if err := client.TestConnection(context.Background(), "acme/widget"); err != nil {
		t.Fatalf("expected success after header-less secondary-limit retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests (1 x 403+body-marker + 1 x 200), got %d", got)
	}
}

// TestGitHubIssuesClient_RateLimit_PrimaryResetEpoch pins the primary
// rate-limit shape: 403 + X-RateLimit-Remaining: 0 + X-RateLimit-Reset (epoch
// seconds). The reset instant is "now", so RespectRateLimitReset clamps the
// wait to ~0 and the retry proceeds immediately.
func TestGitHubIssuesClient_RateLimit_PrimaryResetEpoch(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"full_name": "acme/widget"})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	if err := client.TestConnection(context.Background(), "acme/widget"); err != nil {
		t.Fatalf("expected success after primary-limit retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests (1 x 403+Reset + 1 x 200), got %d", got)
	}
}

// TestGitHubIssuesClient_RateLimit_429_Backoff pins the bare-429 arm: with no
// rate-limit headers at all the client falls back to the exponential
// BackoffPolicy and keeps retrying until success (three 429s then 200 — one
// shy of the MaxRetries=3 cap).
func TestGitHubIssuesClient_RateLimit_429_Backoff(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n <= 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"rate limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"full_name": "acme/widget"})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	start := time.Now()
	if err := client.TestConnection(context.Background(), "acme/widget"); err != nil {
		t.Fatalf("expected success after 3 x 429 + 200, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 4 {
		t.Errorf("expected 4 requests, got %d", got)
	}
	// Sanity cap to detect a runaway loop; generous for CI jitter.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("retry loop took too long: %v", elapsed)
	}
}

// TestGitHubIssuesClient_RateLimit_Exhausted verifies persistent 429s return
// a wrapped ErrRateLimitExhausted (errors.Is-detectable, same contract as the
// Jira/Backlog clients) and that the error never carries the token.
func TestGitHubIssuesClient_RateLimit_Exhausted(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"rate limited"}`))
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "secret-token-value").
		WithBackoffPolicy(testGitHubBackoff(2))

	err := client.TestConnection(context.Background(), "acme/widget")
	if err == nil {
		t.Fatal("expected rate-limit-exhausted error, got nil")
	}
	if !errors.Is(err, ErrRateLimitExhausted) {
		t.Errorf("errors.Is(err, ErrRateLimitExhausted) = false; err = %v", err)
	}
	if strings.Contains(err.Error(), "secret-token-value") {
		t.Errorf("token leaked into error message: %v", err)
	}
	// 1 initial + 2 retries = 3 total.
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("expected 3 requests (1 initial + 2 retries), got %d", got)
	}
}

// TestGitHubIssuesClient_RateLimit_ContextCancel pins the context-cancel
// abort path: while the client waits out a large Retry-After, cancelling the
// caller's context must return promptly rather than sleeping the full delay.
func TestGitHubIssuesClient_RateLimit_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := client.TestConnection(ctx, "acme/widget")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; err = %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancel did not abort promptly: %v", elapsed)
	}
}

// TestGitHubIssuesClient_RateLimit_POST_BodyReuse pins the F301 body-reuse
// contract on the write path: when a rate-limited CreateIssue is retried, the
// second attempt must send a request body byte-identical to the first (each
// attempt gets a fresh bytes.NewReader over the once-encoded payload).
func TestGitHubIssuesClient_RateLimit_POST_BodyReuse(t *testing.T) {
	var (
		mu           sync.Mutex
		capturedBody [][]byte
		hits         int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		mu.Lock()
		capturedBody = append(capturedBody, body)
		mu.Unlock()

		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"number":   7,
			"html_url": "https://github.com/acme/widget/issues/7",
		})
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123").
		WithBackoffPolicy(testGitHubBackoff(3))

	issue, err := client.CreateIssue(context.Background(), CreateGitHubIssueInput{
		Repo:   "acme/widget",
		Title:  "CVE-2026-0001 脆弱性: \"quoted\" \\ path/to/file",
		Body:   "multi-line\nJapanese 詳細",
		Labels: []string{"security"},
	})
	if err != nil {
		t.Fatalf("expected CreateIssue to succeed after 429 retry, got: %v", err)
	}
	if issue.Number != 7 {
		t.Fatalf("unexpected issue number: %d", issue.Number)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(capturedBody) != 2 {
		t.Fatalf("expected 2 captured bodies, got %d", len(capturedBody))
	}
	if !bytes.Equal(capturedBody[0], capturedBody[1]) {
		t.Errorf("retry request body not byte-equal to initial\n  hit1 (%d bytes): %s\n  hit2 (%d bytes): %s",
			len(capturedBody[0]), capturedBody[0], len(capturedBody[1]), capturedBody[1])
	}
}

// TestGitHubIssuesClient_BodyCap_8MiB pins the F300/F309 defensive read cap:
// a 200 response streaming more than maxResponseBodyBytes is truncated at
// 8 MiB, which surfaces as a JSON unmarshal error instead of unbounded memory
// growth. (The multi-line write also exercises the F312 drain path.)
func TestGitHubIssuesClient_BodyCap_8MiB(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Valid JSON overall, but > 8 MiB — the client's LimitReader cuts it
		// mid-token so json.Unmarshal must fail.
		_, _ = w.Write([]byte(`{"number":42,"state":"open","pad":"`))
		pad := bytes.Repeat([]byte("x"), maxResponseBodyBytes+1024)
		_, _ = w.Write(pad)
		_, _ = w.Write([]byte(`"}`))
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")

	_, err := client.GetIssueStatus(context.Background(), "acme/widget", 42)
	if err == nil {
		t.Fatal("expected unmarshal error for over-cap body, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("expected unmarshal error from truncated body, got: %v", err)
	}
}

// TestGitHubIssuesClient_MalformedJSON pins the defensive JSON parse on a
// small malformed 200 body.
func TestGitHubIssuesClient_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"number": 42,`))
	}))
	defer server.Close()

	client := NewGitHubIssuesClient(server.URL, "token123")

	if _, err := client.GetIssueStatus(context.Background(), "acme/widget", 42); err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
	if err := client.TestConnection(context.Background(), "acme/widget"); err == nil {
		t.Error("expected error for malformed JSON on TestConnection, got nil")
	}
}
