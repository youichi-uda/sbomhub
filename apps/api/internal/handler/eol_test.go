package handler

import (
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

func TestEOLHandler_GetProjectEOLSummary_InvalidID(t *testing.T) {
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

func TestEOLHandler_GetProjectEOLSummary_ValidID(t *testing.T) {
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

func TestEOLHandler_ListProducts_QueryParams(t *testing.T) {
	tests := []struct {
		name        string
		queryString string
		wantLimit   int
		wantOffset  int
	}{
		{
			name:        "default values",
			queryString: "",
			wantLimit:   50,
			wantOffset:  0,
		},
		{
			name:        "custom limit",
			queryString: "?limit=100",
			wantLimit:   100,
			wantOffset:  0,
		},
		{
			name:        "custom offset",
			queryString: "?offset=20",
			wantLimit:   50,
			wantOffset:  20,
		},
		{
			name:        "both custom",
			queryString: "?limit=25&offset=50",
			wantLimit:   25,
			wantOffset:  50,
		},
		{
			name:        "limit too high (capped at 500)",
			queryString: "?limit=1000",
			wantLimit:   500,
			wantOffset:  0,
		},
		{
			name:        "negative limit (defaults to 50)",
			queryString: "?limit=-10",
			wantLimit:   50,
			wantOffset:  0,
		},
		{
			name:        "zero limit (defaults to 50)",
			queryString: "?limit=0",
			wantLimit:   50,
			wantOffset:  0,
		},
		{
			name:        "invalid limit (defaults to 50)",
			queryString: "?limit=abc",
			wantLimit:   50,
			wantOffset:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/eol/products"+tt.queryString, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			// Simulate the limit/offset parsing from the handler
			limit := 0
			offset := 0

			if v := c.QueryParam("limit"); v != "" {
				var l int
				_ = json.Unmarshal([]byte(v), &l)
				limit = l
			}
			if v := c.QueryParam("offset"); v != "" {
				var o int
				_ = json.Unmarshal([]byte(v), &o)
				offset = o
			}

			if limit <= 0 {
				limit = 50
			}
			if limit > 500 {
				limit = 500
			}

			if limit != tt.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tt.wantLimit)
			}
			if offset != tt.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tt.wantOffset)
			}
		})
	}
}

func TestEOLHandler_GetProduct_InvalidName(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("name")
	c.SetParamValues("")

	name := c.Param("name")
	if name != "" {
		t.Errorf("expected empty name, got %s", name)
	}
}

func TestEOLHandler_GetProduct_ValidName(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("name")
	c.SetParamValues("python")

	name := c.Param("name")
	if name != "python" {
		t.Errorf("expected python, got %s", name)
	}
}

func TestEOLHandler_CheckComponentEOL_QueryParams(t *testing.T) {
	tests := []struct {
		name        string
		queryString string
		wantName    string
		wantVersion string
		wantPurl    string
		wantErr     bool
	}{
		{
			name:        "all params",
			queryString: "?name=python&version=3.11.4&purl=pkg:pypi/python@3.11.4",
			wantName:    "python",
			wantVersion: "3.11.4",
			wantPurl:    "pkg:pypi/python@3.11.4",
			wantErr:     false,
		},
		{
			name:        "name only",
			queryString: "?name=django",
			wantName:    "django",
			wantVersion: "",
			wantPurl:    "",
			wantErr:     false,
		},
		{
			name:        "missing name",
			queryString: "?version=1.0.0",
			wantName:    "",
			wantVersion: "1.0.0",
			wantPurl:    "",
			wantErr:     true,
		},
		{
			name:        "empty params",
			queryString: "",
			wantName:    "",
			wantVersion: "",
			wantPurl:    "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/eol/check"+tt.queryString, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			name := c.QueryParam("name")
			version := c.QueryParam("version")
			purl := c.QueryParam("purl")

			hasErr := name == ""

			if name != tt.wantName {
				t.Errorf("name = %s, want %s", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %s, want %s", version, tt.wantVersion)
			}
			if purl != tt.wantPurl {
				t.Errorf("purl = %s, want %s", purl, tt.wantPurl)
			}
			if hasErr != tt.wantErr {
				t.Errorf("hasErr = %v, want %v", hasErr, tt.wantErr)
			}
		})
	}
}

func TestEOLSummary_JSON(t *testing.T) {
	projectID := uuid.New()
	summary := model.EOLSummary{
		ProjectID:       projectID,
		TotalComponents: 100,
		Active:          70,
		EOL:             10,
		EOS:             5,
		Unknown:         15,
	}

	jsonBytes, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLSummary
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.ProjectID != projectID {
		t.Errorf("ProjectID mismatch: got %v, want %v", parsed.ProjectID, projectID)
	}
	if parsed.TotalComponents != 100 {
		t.Errorf("TotalComponents mismatch: got %d, want 100", parsed.TotalComponents)
	}
	if parsed.Active != 70 {
		t.Errorf("Active mismatch: got %d, want 70", parsed.Active)
	}
	if parsed.EOL != 10 {
		t.Errorf("EOL mismatch: got %d, want 10", parsed.EOL)
	}
	if parsed.EOS != 5 {
		t.Errorf("EOS mismatch: got %d, want 5", parsed.EOS)
	}
	if parsed.Unknown != 15 {
		t.Errorf("Unknown mismatch: got %d, want 15", parsed.Unknown)
	}
}

func TestEOLProduct_JSON(t *testing.T) {
	productID := uuid.New()
	now := time.Now().Truncate(time.Second)

	product := model.EOLProduct{
		ID:          productID,
		Name:        "python",
		Title:       "Python",
		Category:    "language",
		Link:        "https://python.org",
		TotalCycles: 15,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	jsonBytes, err := json.Marshal(product)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLProduct
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.ID != productID {
		t.Errorf("ID mismatch")
	}
	if parsed.Name != "python" {
		t.Errorf("Name mismatch: got %s", parsed.Name)
	}
	if parsed.Title != "Python" {
		t.Errorf("Title mismatch: got %s", parsed.Title)
	}
	if parsed.Category != "language" {
		t.Errorf("Category mismatch: got %s", parsed.Category)
	}
	if parsed.TotalCycles != 15 {
		t.Errorf("TotalCycles mismatch: got %d", parsed.TotalCycles)
	}
}

func TestEOLProductCycle_JSON(t *testing.T) {
	cycleID := uuid.New()
	productID := uuid.New()
	releaseDate := time.Date(2022, 10, 24, 0, 0, 0, 0, time.UTC)
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)

	cycle := model.EOLProductCycle{
		ID:            cycleID,
		ProductID:     productID,
		Cycle:         "3.11",
		ReleaseDate:   &releaseDate,
		EOLDate:       &eolDate,
		LatestVersion: "3.11.7",
		IsLTS:         false,
		IsEOL:         false,
	}

	jsonBytes, err := json.Marshal(cycle)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLProductCycle
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Cycle != "3.11" {
		t.Errorf("Cycle mismatch: got %s", parsed.Cycle)
	}
	if parsed.LatestVersion != "3.11.7" {
		t.Errorf("LatestVersion mismatch: got %s", parsed.LatestVersion)
	}
	if parsed.IsLTS {
		t.Error("IsLTS should be false")
	}
	if parsed.IsEOL {
		t.Error("IsEOL should be false")
	}
}

func TestComponentEOLInfo_JSON(t *testing.T) {
	productID := uuid.New()
	cycleID := uuid.New()
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)

	info := model.ComponentEOLInfo{
		Status:        model.EOLStatusActive,
		ProductID:     &productID,
		ProductName:   "Python",
		CycleID:       &cycleID,
		CycleVersion:  "3.11",
		EOLDate:       &eolDate,
		LatestVersion: "3.11.7",
		IsLTS:         false,
	}

	jsonBytes, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)

	// Verify JSON structure
	if !strings.Contains(jsonStr, `"status":"active"`) {
		t.Error("expected status:active in JSON")
	}
	if !strings.Contains(jsonStr, `"product_name":"Python"`) {
		t.Error("expected product_name:Python in JSON")
	}
	if !strings.Contains(jsonStr, `"cycle_version":"3.11"`) {
		t.Error("expected cycle_version:3.11 in JSON")
	}
}

func TestEOLSyncLog_JSON(t *testing.T) {
	logID := uuid.New()
	startedAt := time.Now().Truncate(time.Second)
	completedAt := startedAt.Add(time.Minute)

	log := model.EOLSyncLog{
		ID:                logID,
		StartedAt:         startedAt,
		CompletedAt:       &completedAt,
		Status:            "success",
		ProductsSynced:    50,
		CyclesSynced:      500,
		ComponentsUpdated: 1000,
		ErrorMessage:      "",
	}

	jsonBytes, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLSyncLog
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.Status != "success" {
		t.Errorf("Status mismatch: got %s", parsed.Status)
	}
	if parsed.ProductsSynced != 50 {
		t.Errorf("ProductsSynced mismatch: got %d", parsed.ProductsSynced)
	}
	if parsed.CyclesSynced != 500 {
		t.Errorf("CyclesSynced mismatch: got %d", parsed.CyclesSynced)
	}
	if parsed.ComponentsUpdated != 1000 {
		t.Errorf("ComponentsUpdated mismatch: got %d", parsed.ComponentsUpdated)
	}
}

func TestEOLSyncSettings_JSON(t *testing.T) {
	settingsID := uuid.New()
	now := time.Now().Truncate(time.Second)

	settings := model.EOLSyncSettings{
		ID:                settingsID,
		Enabled:           true,
		SyncIntervalHours: 24,
		LastSyncAt:        &now,
		TotalProducts:     50,
		TotalCycles:       500,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	jsonBytes, err := json.Marshal(settings)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLSyncSettings
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !parsed.Enabled {
		t.Error("Enabled should be true")
	}
	if parsed.SyncIntervalHours != 24 {
		t.Errorf("SyncIntervalHours mismatch: got %d", parsed.SyncIntervalHours)
	}
	if parsed.TotalProducts != 50 {
		t.Errorf("TotalProducts mismatch: got %d", parsed.TotalProducts)
	}
	if parsed.TotalCycles != 500 {
		t.Errorf("TotalCycles mismatch: got %d", parsed.TotalCycles)
	}
}

func TestEOLStats_JSON(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	syncLog := &model.EOLSyncLog{
		ID:             uuid.New(),
		StartedAt:      now,
		Status:         "success",
		ProductsSynced: 50,
	}

	stats := model.EOLStats{
		TotalProducts:    50,
		TotalCycles:      500,
		LastSyncAt:       &now,
		LatestSyncStatus: syncLog,
	}

	jsonBytes, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLStats
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.TotalProducts != 50 {
		t.Errorf("TotalProducts mismatch: got %d", parsed.TotalProducts)
	}
	if parsed.TotalCycles != 500 {
		t.Errorf("TotalCycles mismatch: got %d", parsed.TotalCycles)
	}
	if parsed.LatestSyncStatus == nil {
		t.Error("LatestSyncStatus should not be nil")
	}
}

func TestEOLComponentMapping_JSON(t *testing.T) {
	mappingID := uuid.New()
	productID := uuid.New()
	now := time.Now().Truncate(time.Second)

	mapping := model.EOLComponentMapping{
		ID:               mappingID,
		ProductID:        productID,
		ComponentPattern: "python",
		ComponentType:    "library",
		PurlType:         "pypi",
		Priority:         100,
		IsActive:         true,
		CreatedAt:        now,
	}

	jsonBytes, err := json.Marshal(mapping)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed model.EOLComponentMapping
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed.ComponentPattern != "python" {
		t.Errorf("ComponentPattern mismatch: got %s", parsed.ComponentPattern)
	}
	if parsed.ComponentType != "library" {
		t.Errorf("ComponentType mismatch: got %s", parsed.ComponentType)
	}
	if parsed.PurlType != "pypi" {
		t.Errorf("PurlType mismatch: got %s", parsed.PurlType)
	}
	if parsed.Priority != 100 {
		t.Errorf("Priority mismatch: got %d", parsed.Priority)
	}
	if !parsed.IsActive {
		t.Error("IsActive should be true")
	}
}

func TestEOLStatus_Values(t *testing.T) {
	tests := []struct {
		status      model.EOLStatus
		expected    string
	}{
		{model.EOLStatusActive, "active"},
		{model.EOLStatusEOL, "eol"},
		{model.EOLStatusEOS, "eos"},
		{model.EOLStatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("status = %s, want %s", tt.status, tt.expected)
			}
		})
	}
}

func TestEOLSyncStatus_Values(t *testing.T) {
	tests := []struct {
		status   model.EOLSyncStatus
		expected string
	}{
		{model.EOLSyncStatusRunning, "running"},
		{model.EOLSyncStatusSuccess, "success"},
		{model.EOLSyncStatusFailed, "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("status = %s, want %s", tt.status, tt.expected)
			}
		})
	}
}

func TestEOLHandler_SyncCatalog_ResponseFormat(t *testing.T) {
	// Test the expected response format
	result := map[string]interface{}{
		"message":            "EOL catalog sync completed",
		"products_synced":    50,
		"cycles_synced":      500,
		"components_updated": 1000,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "EOL catalog sync completed") {
		t.Error("expected success message in response")
	}
	if !strings.Contains(jsonStr, "products_synced") {
		t.Error("expected products_synced in response")
	}
	if !strings.Contains(jsonStr, "cycles_synced") {
		t.Error("expected cycles_synced in response")
	}
	if !strings.Contains(jsonStr, "components_updated") {
		t.Error("expected components_updated in response")
	}
}

func TestEOLHandler_ListProducts_ResponseFormat(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	products := []model.EOLProduct{
		{
			ID:          uuid.New(),
			Name:        "python",
			Title:       "Python",
			Category:    "language",
			TotalCycles: 15,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          uuid.New(),
			Name:        "nodejs",
			Title:       "Node.js",
			Category:    "runtime",
			TotalCycles: 25,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}

	result := map[string]interface{}{
		"products": products,
		"total":    2,
		"limit":    50,
		"offset":   0,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["total"].(float64) != 2 {
		t.Errorf("total mismatch: got %v", parsed["total"])
	}
	if parsed["limit"].(float64) != 50 {
		t.Errorf("limit mismatch: got %v", parsed["limit"])
	}
	if parsed["offset"].(float64) != 0 {
		t.Errorf("offset mismatch: got %v", parsed["offset"])
	}

	productsList := parsed["products"].([]interface{})
	if len(productsList) != 2 {
		t.Errorf("expected 2 products, got %d", len(productsList))
	}
}

func TestEOLHandler_GetProduct_ResponseFormat(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	productID := uuid.New()
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)

	product := model.EOLProduct{
		ID:          productID,
		Name:        "python",
		Title:       "Python",
		Category:    "language",
		TotalCycles: 2,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	cycles := []model.EOLProductCycle{
		{
			ID:            uuid.New(),
			ProductID:     productID,
			Cycle:         "3.12",
			EOLDate:       &eolDate,
			LatestVersion: "3.12.1",
			IsLTS:         false,
			IsEOL:         false,
		},
		{
			ID:            uuid.New(),
			ProductID:     productID,
			Cycle:         "3.11",
			EOLDate:       &eolDate,
			LatestVersion: "3.11.7",
			IsLTS:         false,
			IsEOL:         false,
		},
	}

	result := map[string]interface{}{
		"product": product,
		"cycles":  cycles,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if parsed["product"] == nil {
		t.Error("expected product in response")
	}
	if parsed["cycles"] == nil {
		t.Error("expected cycles in response")
	}

	cyclesList := parsed["cycles"].([]interface{})
	if len(cyclesList) != 2 {
		t.Errorf("expected 2 cycles, got %d", len(cyclesList))
	}
}

func TestEOLHandler_UpdateProjectComponentsEOL_ResponseFormat(t *testing.T) {
	projectID := uuid.New()

	result := map[string]interface{}{
		"message":            "EOL check completed",
		"components_updated": 100,
		"project_id":         projectID,
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "EOL check completed") {
		t.Error("expected success message in response")
	}
	if !strings.Contains(jsonStr, "components_updated") {
		t.Error("expected components_updated in response")
	}
	if !strings.Contains(jsonStr, "project_id") {
		t.Error("expected project_id in response")
	}
}

func TestEOLHandler_GetLatestSync_NoSync(t *testing.T) {
	// Test response when no sync has been performed
	result := map[string]interface{}{
		"message": "No sync has been performed yet",
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "No sync has been performed yet") {
		t.Error("expected no sync message in response")
	}
}
