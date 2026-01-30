package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// JiraClient is a client for the Jira REST API
type JiraClient struct {
	httpClient *http.Client
	baseURL    string
	email      string
	apiToken   string
}

// NewJiraClient creates a new Jira client
func NewJiraClient(baseURL, email, apiToken string) *JiraClient {
	return &JiraClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:  baseURL,
		email:    email,
		apiToken: apiToken,
	}
}

// JiraIssue represents a Jira issue
type JiraIssue struct {
	ID     string          `json:"id"`
	Key    string          `json:"key"`
	Self   string          `json:"self"`
	Fields JiraIssueFields `json:"fields"`
}

// JiraIssueFields represents Jira issue fields
type JiraIssueFields struct {
	Summary     string          `json:"summary"`
	Description interface{}     `json:"description,omitempty"` // Can be string or ADF format
	Status      *JiraStatus     `json:"status,omitempty"`
	Priority    *JiraPriority   `json:"priority,omitempty"`
	Assignee    *JiraUser       `json:"assignee,omitempty"`
	IssueType   *JiraIssueType  `json:"issuetype,omitempty"`
	Project     *JiraProject    `json:"project,omitempty"`
	Labels      []string        `json:"labels,omitempty"`
}

// JiraStatus represents a Jira status
type JiraStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// JiraPriority represents a Jira priority
type JiraPriority struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// JiraUser represents a Jira user
type JiraUser struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"emailAddress,omitempty"`
}

// JiraIssueType represents a Jira issue type
type JiraIssueType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// JiraProject represents a Jira project
type JiraProject struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

// CreateIssueInput represents input for creating a Jira issue
type CreateIssueInput struct {
	ProjectKey  string
	IssueType   string
	Summary     string
	Description string
	Priority    string
	Labels      []string
}

// CreateIssue creates a new Jira issue
func (c *JiraClient) CreateIssue(ctx context.Context, input CreateIssueInput) (*JiraIssue, error) {
	// Build request body
	fields := map[string]interface{}{
		"project": map[string]string{
			"key": input.ProjectKey,
		},
		"summary": input.Summary,
		"issuetype": map[string]string{
			"name": input.IssueType,
		},
	}

	if input.Description != "" {
		// Use simple text description for broader compatibility
		fields["description"] = map[string]interface{}{
			"type":    "doc",
			"version": 1,
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{
							"type": "text",
							"text": input.Description,
						},
					},
				},
			},
		}
	}

	if input.Priority != "" {
		fields["priority"] = map[string]string{
			"name": input.Priority,
		}
	}

	if len(input.Labels) > 0 {
		fields["labels"] = input.Labels
	}

	body := map[string]interface{}{
		"fields": fields,
	}

	var issue JiraIssue
	if err := c.doRequest(ctx, "POST", "/rest/api/3/issue", body, &issue); err != nil {
		return nil, err
	}

	return &issue, nil
}

// GetIssue gets a Jira issue by key or ID
func (c *JiraClient) GetIssue(ctx context.Context, issueKeyOrID string) (*JiraIssue, error) {
	var issue JiraIssue
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/rest/api/3/issue/%s", issueKeyOrID), nil, &issue); err != nil {
		return nil, err
	}

	return &issue, nil
}

// GetProjects gets available Jira projects
func (c *JiraClient) GetProjects(ctx context.Context) ([]JiraProject, error) {
	var projects []JiraProject
	if err := c.doRequest(ctx, "GET", "/rest/api/3/project", nil, &projects); err != nil {
		return nil, err
	}

	return projects, nil
}

// GetIssueTypes gets issue types for a project
func (c *JiraClient) GetIssueTypes(ctx context.Context, projectKey string) ([]JiraIssueType, error) {
	var project struct {
		IssueTypes []JiraIssueType `json:"issueTypes"`
	}
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/rest/api/3/project/%s", projectKey), nil, &project); err != nil {
		return nil, err
	}

	return project.IssueTypes, nil
}

// TestConnection tests the Jira connection
func (c *JiraClient) TestConnection(ctx context.Context) error {
	var result map[string]interface{}
	return c.doRequest(ctx, "GET", "/rest/api/3/myself", nil, &result)
}

func (c *JiraClient) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(c.email, c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Jira API error: %d - %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
