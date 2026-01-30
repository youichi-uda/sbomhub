package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
