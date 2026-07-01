package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testBacklogBackoff returns a BackoffPolicy tuned for httptest — small delays
// so test runtime stays sub-second and no jitter so the retry cadence is
// deterministic.
func testBacklogBackoff(maxRetries int) BackoffPolicy {
	return BackoffPolicy{
		MaxRetries:   maxRetries,
		InitialDelay: 5 * time.Millisecond,
		MaxDelay:     50 * time.Millisecond,
		Jitter:       false,
	}
}

func TestNewBacklogClient(t *testing.T) {
	client := NewBacklogClient("https://example.backlog.com", "apikey123")

	if client == nil {
		t.Fatal("expected client to be created")
	}

	if client.baseURL != "https://example.backlog.com" {
		t.Errorf("unexpected baseURL: %s", client.baseURL)
	}

	if client.apiKey != "apikey123" {
		t.Errorf("unexpected apiKey: %s", client.apiKey)
	}
}

func TestBacklogClient_TestConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/users/myself" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Check API key in query params
		apiKey := r.URL.Query().Get("apiKey")
		if apiKey != "apikey123" {
			t.Errorf("unexpected apiKey: %s", apiKey)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     1,
			"userId": "testuser",
			"name":   "Test User",
		})
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	err := client.TestConnection(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBacklogClient_TestConnection_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"message":"Authentication failed"}]}`))
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "wrong-key")

	err := client.TestConnection(context.Background())
	if err == nil {
		t.Error("expected error for unauthorized request")
	}
}

func TestBacklogClient_GetProjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/projects" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		projects := []BacklogProject{
			{ID: 1, ProjectKey: "PROJ1", Name: "Project One"},
			{ID: 2, ProjectKey: "PROJ2", Name: "Project Two"},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(projects)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	projects, err := client.GetProjects(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}

	if projects[0].ProjectKey != "PROJ1" {
		t.Errorf("unexpected project key: %s", projects[0].ProjectKey)
	}
}

func TestBacklogClient_GetIssue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/issues/PROJ-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		issue := BacklogIssue{
			ID:       10001,
			IssueKey: "PROJ-123",
			Summary:  "Test Issue",
			Status: BacklogStatus{
				ID:   1,
				Name: "未対応",
			},
			Priority: BacklogPriority{
				ID:   2,
				Name: "高",
			},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(issue)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	issue, err := client.GetIssue(context.Background(), "PROJ-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issue.IssueKey != "PROJ-123" {
		t.Errorf("unexpected issue key: %s", issue.IssueKey)
	}

	if issue.Summary != "Test Issue" {
		t.Errorf("unexpected summary: %s", issue.Summary)
	}

	if issue.Status.Name != "未対応" {
		t.Errorf("unexpected status: %s", issue.Status.Name)
	}
}

func TestBacklogClient_CreateIssue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/issues" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		issue := BacklogIssue{
			ID:        10002,
			ProjectID: 1,
			IssueKey:  "PROJ-124",
			Summary:   "Test Summary",
			Status: BacklogStatus{
				ID:   1,
				Name: "未対応",
			},
			Priority: BacklogPriority{
				ID:   2,
				Name: "高",
			},
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(issue)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	input := CreateBacklogIssueInput{
		ProjectID:   1,
		IssueTypeID: 1,
		PriorityID:  2,
		Summary:     "Test Summary",
		Description: "Test Description",
	}

	issue, err := client.CreateIssue(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if issue.IssueKey != "PROJ-124" {
		t.Errorf("unexpected issue key: %s", issue.IssueKey)
	}
}

func TestBacklogClient_GetIssueTypes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/projects/PROJ/issueTypes" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		issueTypes := []BacklogIssueType{
			{ID: 1, Name: "バグ"},
			{ID: 2, Name: "タスク"},
			{ID: 3, Name: "要望"},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(issueTypes)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	issueTypes, err := client.GetIssueTypes(context.Background(), "PROJ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(issueTypes) != 3 {
		t.Errorf("expected 3 issue types, got %d", len(issueTypes))
	}

	if issueTypes[0].Name != "バグ" {
		t.Errorf("unexpected issue type name: %s", issueTypes[0].Name)
	}
}

func TestBacklogClient_GetPriorities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/priorities" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		priorities := []BacklogPriority{
			{ID: 2, Name: "高"},
			{ID: 3, Name: "中"},
			{ID: 4, Name: "低"},
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(priorities)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123")

	priorities, err := client.GetPriorities(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(priorities) != 3 {
		t.Errorf("expected 3 priorities, got %d", len(priorities))
	}
}

func TestBacklogClient_GetIssueURL(t *testing.T) {
	client := NewBacklogClient("https://example.backlog.com", "apikey123")

	tests := []struct {
		issueKey    string
		expectedURL string
	}{
		{"PROJ-123", "https://example.backlog.com/view/PROJ-123"},
		{"PROJ-1", "https://example.backlog.com/view/PROJ-1"},
		{"TEST-999", "https://example.backlog.com/view/TEST-999"},
	}

	for _, tt := range tests {
		t.Run(tt.issueKey, func(t *testing.T) {
			url := client.GetIssueURL(tt.issueKey)
			if url != tt.expectedURL {
				t.Errorf("GetIssueURL(%s) = %s, want %s", tt.issueKey, url, tt.expectedURL)
			}
		})
	}
}

func TestCreateBacklogIssueInput(t *testing.T) {
	tests := []struct {
		name  string
		input CreateBacklogIssueInput
	}{
		{
			name: "full input",
			input: CreateBacklogIssueInput{
				ProjectID:   1,
				IssueTypeID: 1,
				PriorityID:  2,
				Summary:     "Test Summary",
				Description: "Test Description",
			},
		},
		{
			name: "minimal input",
			input: CreateBacklogIssueInput{
				ProjectID:   1,
				IssueTypeID: 1,
				PriorityID:  3,
				Summary:     "Test Summary",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.input.ProjectID == 0 {
				t.Error("ProjectID should not be 0")
			}
			if tt.input.Summary == "" {
				t.Error("Summary should not be empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F277 (M19-1) rate-limit hardening — Backlog uses X-RateLimit-Reset (epoch
// seconds) as its documented retry-hint header rather than the standard
// Retry-After. The client honours X-RateLimit-Reset first, Retry-After next
// (defensive fallback), then exponential backoff.
// ---------------------------------------------------------------------------

// TestBacklogClient_RateLimit_429_Retry pins the primary happy path: a single
// 429 with X-RateLimit-Reset pointing at "now" (i.e. immediately eligible)
// followed by a 200 must succeed.
func TestBacklogClient_RateLimit_429_Retry(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Unix()))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errors":[{"message":"rate limited"}]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 1, "userId": "test"})
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123").
		WithBackoffPolicy(testBacklogBackoff(3))

	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests, got %d", got)
	}
}

// TestBacklogClient_RateLimit_RetryAfterFallback pins the defensive
// Retry-After path: some proxies fronting Backlog may inject the standard
// header even though the platform uses X-RateLimit-Reset. The client should
// honour either.
func TestBacklogClient_RateLimit_RetryAfterFallback(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": 1})
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123").
		WithBackoffPolicy(testBacklogBackoff(3))

	if err := client.TestConnection(context.Background()); err != nil {
		t.Fatalf("expected success after Retry-After retry, got: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("expected 2 requests, got %d", got)
	}
}

// TestBacklogClient_RateLimit_Exhausted verifies persistent 429 responses
// return a wrapped ErrRateLimitExhausted so callers can detect via errors.Is.
func TestBacklogClient_RateLimit_Exhausted(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"message":"rate limited"}]}`))
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123").
		WithBackoffPolicy(testBacklogBackoff(2))

	err := client.TestConnection(context.Background())
	if err == nil {
		t.Fatal("expected rate-limit-exhausted error, got nil")
	}
	if !errors.Is(err, ErrRateLimitExhausted) {
		t.Errorf("errors.Is(err, ErrRateLimitExhausted) = false; err = %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("expected 3 requests (1 initial + 2 retries), got %d", got)
	}
}

// TestBacklogClient_RateLimit_ContextCancel pins prompt abort when the caller
// cancels ctx during a backoff wait. Server sends a large X-RateLimit-Reset
// (60s out) so the client would otherwise block for the full window.
func TestBacklogClient_RateLimit_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(60*time.Second).Unix()))
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := NewBacklogClient(server.URL, "apikey123").
		WithBackoffPolicy(testBacklogBackoff(3))

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
	if elapsed > 2*time.Second {
		t.Errorf("cancel did not abort promptly: %v", elapsed)
	}
}
