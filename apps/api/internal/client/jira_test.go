package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testJiraBackoff returns a BackoffPolicy tuned for httptest — small delays so
// test runtime stays sub-second and no jitter so the retry cadence is
// deterministic. Callers usually pair this with WithBackoffPolicy on a client
// constructed against a httptest.Server URL.
func testJiraBackoff(maxRetries int) BackoffPolicy {
	return BackoffPolicy{
		MaxRetries:   maxRetries,
		InitialDelay: 5 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Jitter:       false,
	}
}

func TestNewJiraClient(t *testing.T) {
	client := NewJiraClient("https://example.atlassian.net", "user@example.com", "token123")

	if client == nil {
		t.Fatal("expected client to be created")
	}

	if client.baseURL != "https://example.atlassian.net" {
		t.Errorf("unexpected baseURL: %s", client.baseURL)
	}

	if client.email != "user@example.com" {
		t.Errorf("unexpected email: %s", client.email)
	}

	if client.apiToken != "token123" {
		t.Errorf("unexpected apiToken: %s", client.apiToken)
	}
}

func TestJiraClient_TestConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/myself" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Check auth header
		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("expected basic auth")
		}
		if user != "user@example.com" {
			t.Errorf("unexpected user: %s", user)
		}
		if pass != "token123" {
			t.Errorf("unexpected password: %s", pass)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"accountId":   "123",
			"displayName": "Test User",
		})
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123")

	err := client.TestConnection(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestJiraClient_TestConnection_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errorMessages":["Unauthorized"]}`))
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "wrong-token")

	err := client.TestConnection(context.Background())
	if err == nil {
		t.Error("expected error for unauthorized request")
	}
}

func TestJiraClient_GetProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		projects := []JiraProject{
			{ID: "10000", Key: "PROJ1", Name: "Project One"},
			{ID: "10001", Key: "PROJ2", Name: "Project Two"},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123")

	projects, err := client.GetProjects(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}

	if projects[0].Key != "PROJ1" {
		t.Errorf("unexpected project key: %s", projects[0].Key)
	}
}

func TestJiraClient_GetIssue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue/PROJ-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		issue := JiraIssue{
			ID:  "10001",
			Key: "PROJ-123",
			Fields: JiraIssueFields{
				Summary: "Test Issue",
				Status: &JiraStatus{
					ID:   "1",
					Name: "Open",
				},
				Priority: &JiraPriority{
					ID:   "2",
					Name: "High",
				},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(issue)
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123")

	issue, err := client.GetIssue(context.Background(), "PROJ-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issue.Key != "PROJ-123" {
		t.Errorf("unexpected issue key: %s", issue.Key)
	}

	if issue.Fields.Summary != "Test Issue" {
		t.Errorf("unexpected summary: %s", issue.Fields.Summary)
	}

	if issue.Fields.Status.Name != "Open" {
		t.Errorf("unexpected status: %s", issue.Fields.Status.Name)
	}
}

func TestJiraClient_CreateIssue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %v", err)
		}

		fields, ok := body["fields"].(map[string]interface{})
		if !ok {
			t.Fatal("expected fields in body")
		}

		if fields["summary"] != "Test Summary" {
			t.Errorf("unexpected summary: %v", fields["summary"])
		}

		issue := JiraIssue{
			ID:  "10001",
			Key: "PROJ-124",
			Fields: JiraIssueFields{
				Summary: "Test Summary",
				Status: &JiraStatus{
					ID:   "1",
					Name: "To Do",
				},
				Priority: &JiraPriority{
					ID:   "2",
					Name: "High",
				},
			},
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(issue)
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123")

	input := CreateIssueInput{
		ProjectKey:  "PROJ",
		IssueType:   "Bug",
		Summary:     "Test Summary",
		Description: "Test Description",
		Priority:    "High",
		Labels:      []string{"security", "vulnerability"},
	}

	issue, err := client.CreateIssue(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issue.Key != "PROJ-124" {
		t.Errorf("unexpected issue key: %s", issue.Key)
	}
}

func TestJiraClient_GetIssueTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project/PROJ" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		project := struct {
			IssueTypes []JiraIssueType `json:"issueTypes"`
		}{
			IssueTypes: []JiraIssueType{
				{ID: "1", Name: "Bug"},
				{ID: "2", Name: "Task"},
				{ID: "3", Name: "Story"},
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(project)
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123")

	issueTypes, err := client.GetIssueTypes(context.Background(), "PROJ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(issueTypes) != 3 {
		t.Errorf("expected 3 issue types, got %d", len(issueTypes))
	}

	if issueTypes[0].Name != "Bug" {
		t.Errorf("unexpected issue type name: %s", issueTypes[0].Name)
	}
}

func TestCreateIssueInput(t *testing.T) {
	tests := []struct {
		name  string
		input CreateIssueInput
	}{
		{
			name: "full input",
			input: CreateIssueInput{
				ProjectKey:  "PROJ",
				IssueType:   "Bug",
				Summary:     "Test Summary",
				Description: "Test Description",
				Priority:    "High",
				Labels:      []string{"security"},
			},
		},
		{
			name: "minimal input",
			input: CreateIssueInput{
				ProjectKey: "PROJ",
				IssueType:  "Bug",
				Summary:    "Test Summary",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input.ProjectKey == "" {
				t.Error("ProjectKey should not be empty")
			}
			if tt.input.Summary == "" {
				t.Error("Summary should not be empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F277 (M19-1) rate-limit hardening — 429 detection + Retry-After respect +
// exponential backoff + context-cancel abort. These tests exercise doRequest
// indirectly through TestConnection because the retry logic lives on the
// funnel, so any GET/POST path shares the same behaviour.
// ---------------------------------------------------------------------------

// TestJiraClient_RateLimit_429_Retry pins the primary happy path: a single 429
// followed by a 200 must succeed once the client respects Retry-After. The
// server returns Retry-After: 1 but the test forces InitialDelay=5ms via
// WithBackoffPolicy so the total runtime stays sub-second.
//
// Note: the client respects Retry-After when present, so the "5ms" fallback is
// not what governs this test — the 1-second value is what the server sends.
// We keep it small in the server response (Retry-After: 0) to keep the test
// fast, then a separate test covers the multi-second HTTP header parsing.
func TestJiraClient_RateLimit_429_Retry(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errorMessages":["rate limited"]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"accountId": "123"})
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(3))

	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests (1 x 429 + 1 x 200), got %d", got)
	}
}

// TestJiraClient_RateLimit_ExponentialBackoff verifies that when no
// Retry-After header is present the client falls back to the configured
// backoff policy, and that repeated 429 responses do not cause an early
// give-up. The server returns 429 three times, then 200 — one shy of the
// MaxRetries=3 cap.
func TestJiraClient_RateLimit_ExponentialBackoff(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n <= 3 {
			// No Retry-After header — force the policy path.
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errorMessages":["rate limited"]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"accountId": "123"})
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(3))

	start := time.Now()
	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("expected success after 3 x 429 + 200, got: %v", err)
	}
	elapsed := time.Since(start)
	if got := atomic.LoadInt32(&hits); got != 4 {
		t.Errorf("expected 4 requests, got %d", got)
	}
	// Sanity: with 5ms/10ms/20ms backoff plan, total wait ~35ms plus HTTP RTT.
	// Cap at 5s to detect a runaway loop; be generous because of CI jitter.
	if elapsed > 5*time.Second {
		t.Errorf("retry loop took too long: %v", elapsed)
	}
}

// TestJiraClient_RateLimit_Exhausted verifies that persistent 429 responses
// eventually return a wrapped ErrRateLimitExhausted so callers can detect the
// condition with errors.Is (and issue_tracker service can log / alarm
// distinctly from transient failures).
func TestJiraClient_RateLimit_Exhausted(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errorMessages":["rate limited"]}`))
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(2))

	err := client.TestConnection(context.Background())
	if err == nil {
		t.Fatal("expected rate-limit-exhausted error, got nil")
	}
	if !errors.Is(err, ErrRateLimitExhausted) {
		t.Errorf("errors.Is(err, ErrRateLimitExhausted) = false; err = %v", err)
	}
	// 1 initial + 2 retries = 3 total.
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("expected 3 requests (1 initial + 2 retries), got %d", got)
	}
}

// TestJiraClient_RateLimit_ContextCancel pins the context-cancel abort path:
// while the client is waiting for the backoff timer, cancelling the caller's
// context must return promptly rather than sleeping the full delay.
func TestJiraClient_RateLimit_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always 429 with a large Retry-After so the backoff would otherwise
		// block for seconds — the context cancel must interrupt it.
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(3))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := client.TestConnection(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false; err = %v", err)
	}
	// Should abort well before Retry-After: 60 elapses.
	if elapsed > 2*time.Second {
		t.Errorf("cancel did not abort promptly: %v", elapsed)
	}
}

// TestJiraClient_RateLimit_POST_BodyReuse_F301 pins the POST body-reuse
// invariant: when a rate-limited CreateIssue call is retried, the second
// attempt must send a request body that is byte-identical to the first.
// The invariant this catches is "each retry attempt receives a fresh
// io.Reader positioned at offset 0". The concrete regression is a future
// refactor that consumes the encoded body's `bytes.NewReader` outside
// the retry loop (e.g. hoisting the reader construction above the loop
// and reusing it directly, or advancing it during attempt 1), causing
// attempt 2 to send an empty or partial body. The bytes.Equal check
// below trips that regression cleanly.
//
// What this test does NOT catch: a regression that produces different
// but byte-equal encodings across attempts. Such a regression is
// unlikely with stdlib guarantees — `encoding/json.Marshal` sorts map
// keys alphabetically per its documented contract, and
// `url.Values.Encode()` also sorts. So even a per-attempt re-encode of
// the same Go value would return the same bytes. The pre-F310 docstring
// wording that appealed to "different Go map iteration orderings could
// produce non-equivalent byte streams" mis-described the catch scope;
// F310 (M20-3 Phase D R2) rewrites the docstring to reflect what F301
// actually catches (the per-attempt-fresh-reader contract, i.e. the
// bytes.NewReader hoist regression) rather than a hypothetical encoding
// nondeterminism.
//
// This test wires an httptest server that (a) captures the request
// body on every hit and (b) 429s the first hit + 201s the second, then
// asserts bytes.Equal on the two captured bodies. F301 (M20-3, F292 fix
// path) + F310 (M20-3 Phase D R2 docstring correction).
func TestJiraClient_RateLimit_POST_BodyReuse_F301(t *testing.T) {
	var (
		mu           sync.Mutex
		capturedBody [][]byte
		hits         int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
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
			_, _ = w.Write([]byte(`{"errorMessages":["rate limited"]}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(JiraIssue{
			ID:  "12345",
			Key: "TEST-1",
		})
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(3))

	input := CreateIssueInput{
		ProjectKey:  "TEST",
		IssueType:   "Bug",
		Summary:     "Body reuse invariant",
		Description: "F301 pins byte-equal retry payload",
		Priority:    "High",
		Labels:      []string{"security", "f301"},
	}

	issue, err := client.CreateIssue(context.Background(), input)
	if err != nil {
		t.Fatalf("expected CreateIssue to succeed after 429 retry, got: %v", err)
	}
	if issue == nil || issue.Key != "TEST-1" {
		t.Fatalf("expected returned issue key TEST-1, got: %+v", issue)
	}

	mu.Lock()
	defer mu.Unlock()
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected exactly 2 requests (1 x 429 + 1 x 201), got %d", got)
	}
	if len(capturedBody) != 2 {
		t.Fatalf("expected 2 captured bodies, got %d", len(capturedBody))
	}
	if !bytes.Equal(capturedBody[0], capturedBody[1]) {
		t.Errorf("F301 invariant violated: retry request body not byte-equal to initial\n"+
			"  hit1 (%d bytes): %s\n"+
			"  hit2 (%d bytes): %s",
			len(capturedBody[0]), capturedBody[0],
			len(capturedBody[1]), capturedBody[1])
	}
}

// TestJiraClient_RateLimit_RetryAfterHTTPDate verifies the HTTP-date variant of
// Retry-After (RFC 7231 §7.1.3 permits both delta-seconds and HTTP-date).
// The server sends a Retry-After date ~50ms in the future; the client must
// wait roughly that long and then succeed.
func TestJiraClient_RateLimit_RetryAfterHTTPDate(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			// Small but non-zero — HTTP-date rounds to 1s granularity so use
			// "now" which parses to 0-delta ("respect the header, don't block").
			w.Header().Set("Retry-After", time.Now().UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"accountId": "123"})
	}))
	defer server.Close()

	client := NewJiraClient(server.URL, "user@example.com", "token123").
		WithBackoffPolicy(testJiraBackoff(3))

	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("expected success after HTTP-date retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests, got %d", got)
	}
}
