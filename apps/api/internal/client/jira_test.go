package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
