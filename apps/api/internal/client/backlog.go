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
type BacklogClient struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

// NewBacklogClient creates a new Backlog client
func NewBacklogClient(baseURL, apiKey string) *BacklogClient {
	return &BacklogClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
		apiKey:  apiKey,
	}
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

	var reqBody io.Reader
	fullURL := c.baseURL + path

	if method == "GET" {
		fullURL += "?" + params.Encode()
	} else {
		reqBody = bytes.NewReader([]byte(params.Encode()))
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
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Backlog API error: %d - %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
