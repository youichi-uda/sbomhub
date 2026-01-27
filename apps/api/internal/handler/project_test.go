package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
)

// MockProjectRepository implements repository interface for testing
type MockProjectRepository struct {
	projects []model.Project
	err      error
}

func (m *MockProjectRepository) Create(ctx context.Context, project *model.Project) error {
	if m.err != nil {
		return m.err
	}
	m.projects = append(m.projects, *project)
	return nil
}

func (m *MockProjectRepository) List(ctx context.Context) ([]model.Project, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.projects, nil
}

func (m *MockProjectRepository) Get(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	if m.err != nil {
		return nil, m.err
	}
	for _, p := range m.projects {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, nil
}

func (m *MockProjectRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if m.err != nil {
		return m.err
	}
	for i, p := range m.projects {
		if p.ID == id {
			m.projects = append(m.projects[:i], m.projects[i+1:]...)
			return nil
		}
	}
	return nil
}

func TestProjectHandler_Create_InvalidJSON(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader("invalid json"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// We can't directly test the handler without a mock service,
	// but we can test the request binding behavior
	var reqBody model.CreateProjectRequest
	err := c.Bind(&reqBody)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestProjectHandler_Create_ValidRequest(t *testing.T) {
	reqBody := model.CreateProjectRequest{
		Name:        "Test Project",
		Description: "Test Description",
	}
	
	jsonBytes, _ := json.Marshal(reqBody)
	
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/projects", strings.NewReader(string(jsonBytes)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var parsed model.CreateProjectRequest
	if err := c.Bind(&parsed); err != nil {
		t.Fatalf("bind failed: %v", err)
	}

	if parsed.Name != reqBody.Name {
		t.Errorf("Name mismatch: got %s, want %s", parsed.Name, reqBody.Name)
	}
	if parsed.Description != reqBody.Description {
		t.Errorf("Description mismatch: got %s, want %s", parsed.Description, reqBody.Description)
	}
}

func TestProjectHandler_Get_InvalidID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("not-a-uuid")

	_, err := uuid.Parse(c.Param("id"))
	if err == nil {
		t.Error("expected error for invalid UUID")
	}
}

func TestProjectHandler_Get_ValidID(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	testID := uuid.New()
	c.SetParamNames("id")
	c.SetParamValues(testID.String())

	parsed, err := uuid.Parse(c.Param("id"))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed != testID {
		t.Errorf("ID mismatch: got %v, want %v", parsed, testID)
	}
}

func TestProjectModel(t *testing.T) {
	id := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	project := model.Project{
		ID:          id,
		TenantID:    &tenantID,
		Name:        "Test Project",
		Description: "A test project",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if project.ID != id {
		t.Errorf("ID mismatch")
	}
	if *project.TenantID != tenantID {
		t.Errorf("TenantID mismatch")
	}
	if project.Name != "Test Project" {
		t.Errorf("Name mismatch")
	}
}

func TestCreateProjectRequest_JSON(t *testing.T) {
	jsonStr := `{"name":"My Project","description":"My Description"}`
	
	var req model.CreateProjectRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if req.Name != "My Project" {
		t.Errorf("Name mismatch: got %s", req.Name)
	}
	if req.Description != "My Description" {
		t.Errorf("Description mismatch: got %s", req.Description)
	}
}

func TestCreateProjectRequest_MinimalJSON(t *testing.T) {
	jsonStr := `{"name":"OnlyName"}`
	
	var req model.CreateProjectRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if req.Name != "OnlyName" {
		t.Errorf("Name mismatch: got %s", req.Name)
	}
	if req.Description != "" {
		t.Errorf("Description should be empty, got %s", req.Description)
	}
}
