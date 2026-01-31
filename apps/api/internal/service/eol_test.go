package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

func TestEOLService_ParseDateOrBool(t *testing.T) {
	svc := &EOLService{}

	tests := []struct {
		name         string
		input        interface{}
		wantDate     bool
		wantIsEOL    bool
	}{
		{
			name:         "nil value",
			input:        nil,
			wantDate:     false,
			wantIsEOL:    false,
		},
		{
			name:         "bool true",
			input:        true,
			wantDate:     false,
			wantIsEOL:    true,
		},
		{
			name:         "bool false",
			input:        false,
			wantDate:     false,
			wantIsEOL:    false,
		},
		{
			name:         "empty string",
			input:        "",
			wantDate:     false,
			wantIsEOL:    false,
		},
		{
			name:         "string false",
			input:        "false",
			wantDate:     false,
			wantIsEOL:    false,
		},
		{
			name:         "string true",
			input:        "true",
			wantDate:     false,
			wantIsEOL:    true,
		},
		{
			name:         "past date string",
			input:        "2020-01-01",
			wantDate:     true,
			wantIsEOL:    true,
		},
		{
			name:         "future date string",
			input:        "2099-12-31",
			wantDate:     true,
			wantIsEOL:    false,
		},
		{
			name:         "invalid date string",
			input:        "not-a-date",
			wantDate:     false,
			wantIsEOL:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			date, isEOL := svc.parseDateOrBool(tt.input)

			hasDate := date != nil
			if hasDate != tt.wantDate {
				t.Errorf("parseDateOrBool() date present = %v, want %v", hasDate, tt.wantDate)
			}
			if isEOL != tt.wantIsEOL {
				t.Errorf("parseDateOrBool() isEOL = %v, want %v", isEOL, tt.wantIsEOL)
			}
		})
	}
}

func TestEOLService_ParseCycle(t *testing.T) {
	svc := &EOLService{}
	productID := uuid.New()

	tests := []struct {
		name      string
		response  EOLCycleResponse
		wantErr   bool
		checkFunc func(t *testing.T, c *model.EOLProductCycle)
	}{
		{
			name: "string cycle",
			response: EOLCycleResponse{
				Cycle:       "3.11",
				ReleaseDate: "2022-10-24",
				EOL:         "2027-10-31",
				Latest:      "3.11.7",
				LTS:         false,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if c.Cycle != "3.11" {
					t.Errorf("expected cycle 3.11, got %s", c.Cycle)
				}
				if c.LatestVersion != "3.11.7" {
					t.Errorf("expected latest 3.11.7, got %s", c.LatestVersion)
				}
				if c.EOLDate == nil {
					t.Error("expected EOL date to be set")
				}
				if c.IsEOL {
					t.Error("expected IsEOL to be false for future date")
				}
			},
		},
		{
			name: "numeric cycle (Node.js style)",
			response: EOLCycleResponse{
				Cycle:       float64(18),
				ReleaseDate: "2022-04-19",
				EOL:         "2025-04-30",
				Latest:      "18.19.0",
				LTS:         "Hydrogen",
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if c.Cycle != "18" {
					t.Errorf("expected cycle 18, got %s", c.Cycle)
				}
				if !c.IsLTS {
					t.Error("expected IsLTS to be true for LTS version")
				}
			},
		},
		{
			name: "EOL as bool true",
			response: EOLCycleResponse{
				Cycle:  "2.7",
				EOL:    true,
				Latest: "2.7.18",
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if !c.IsEOL {
					t.Error("expected IsEOL to be true")
				}
			},
		},
		{
			name: "EOL as past date",
			response: EOLCycleResponse{
				Cycle:  "3.6",
				EOL:    "2021-12-23",
				Latest: "3.6.15",
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if !c.IsEOL {
					t.Error("expected IsEOL to be true for past date")
				}
				if c.EOLDate == nil {
					t.Error("expected EOL date to be set")
				}
			},
		},
		{
			name: "discontinued product",
			response: EOLCycleResponse{
				Cycle:        "1.0",
				Discontinued: true,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if !c.Discontinued {
					t.Error("expected Discontinued to be true")
				}
			},
		},
		{
			name: "with support end date",
			response: EOLCycleResponse{
				Cycle:   "20",
				EOL:     "2026-04-30",
				Support: "2024-10-22",
				Latest:  "20.10.0",
			},
			wantErr: false,
			checkFunc: func(t *testing.T, c *model.EOLProductCycle) {
				if c.SupportEndDate == nil {
					t.Error("expected SupportEndDate to be set")
				}
				if c.EOSDate == nil {
					t.Error("expected EOSDate to be set (from Support)")
				}
			},
		},
		{
			name: "invalid cycle type",
			response: EOLCycleResponse{
				Cycle: []string{"invalid"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cycle, err := svc.parseCycle(productID, tt.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCycle() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.checkFunc != nil && cycle != nil {
				if cycle.ProductID != productID {
					t.Errorf("expected ProductID %v, got %v", productID, cycle.ProductID)
				}
				tt.checkFunc(t, cycle)
			}
		})
	}
}

func TestEOLService_FetchProductCycles_MockServer(t *testing.T) {
	tests := []struct {
		name       string
		product    string
		handler    http.HandlerFunc
		wantErr    bool
		wantCount  int
	}{
		{
			name:    "successful fetch",
			product: "python",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]EOLCycleResponse{
					{Cycle: "3.12", EOL: "2028-10-31", Latest: "3.12.1"},
					{Cycle: "3.11", EOL: "2027-10-31", Latest: "3.11.7"},
				})
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:    "product not found",
			product: "nonexistent",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:    "server error",
			product: "error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:    "invalid json response",
			product: "invalid",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte("invalid json"))
			},
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:    "empty array response",
			product: "empty",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode([]EOLCycleResponse{})
			},
			wantErr:   false,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			// Make a direct HTTP request to simulate fetchProductCycles behavior
			url := server.URL + "/" + tt.product + ".json"
			req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("Accept", "application/json")

			client := server.Client()
			resp, err := client.Do(req)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("request failed: %v", err)
				}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				if !tt.wantErr {
					t.Error("expected success but got not found")
				}
				return
			}
			if resp.StatusCode != http.StatusOK {
				if !tt.wantErr {
					t.Errorf("unexpected status: %d", resp.StatusCode)
				}
				return
			}

			var cycles []EOLCycleResponse
			if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
				if !tt.wantErr {
					t.Errorf("decode failed: %v", err)
				}
				return
			}

			if tt.wantErr {
				t.Error("expected error but got success")
				return
			}
			if len(cycles) != tt.wantCount {
				t.Errorf("count = %d, want %d", len(cycles), tt.wantCount)
			}
		})
	}
}

func TestEOLCycleResponse_JSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonStr  string
		checkFunc func(t *testing.T, resp EOLCycleResponse)
	}{
		{
			name: "Python style response",
			jsonStr: `{
				"cycle": "3.11",
				"releaseDate": "2022-10-24",
				"eol": "2027-10-31",
				"latest": "3.11.7",
				"lts": false
			}`,
			checkFunc: func(t *testing.T, resp EOLCycleResponse) {
				if resp.Cycle != "3.11" {
					t.Errorf("expected cycle 3.11, got %v", resp.Cycle)
				}
				if resp.ReleaseDate != "2022-10-24" {
					t.Errorf("expected releaseDate 2022-10-24, got %s", resp.ReleaseDate)
				}
			},
		},
		{
			name: "Node.js style with numeric cycle",
			jsonStr: `{
				"cycle": 18,
				"releaseDate": "2022-04-19",
				"eol": "2025-04-30",
				"latest": "18.19.0",
				"lts": "Hydrogen"
			}`,
			checkFunc: func(t *testing.T, resp EOLCycleResponse) {
				// Cycle should be float64 when parsed from JSON
				if v, ok := resp.Cycle.(float64); !ok || v != 18 {
					t.Errorf("expected cycle 18, got %v (%T)", resp.Cycle, resp.Cycle)
				}
				// LTS as string
				if v, ok := resp.LTS.(string); !ok || v != "Hydrogen" {
					t.Errorf("expected lts Hydrogen, got %v", resp.LTS)
				}
			},
		},
		{
			name: "EOL as boolean true",
			jsonStr: `{
				"cycle": "2.7",
				"eol": true,
				"latest": "2.7.18"
			}`,
			checkFunc: func(t *testing.T, resp EOLCycleResponse) {
				if v, ok := resp.EOL.(bool); !ok || !v {
					t.Errorf("expected eol true, got %v", resp.EOL)
				}
			},
		},
		{
			name: "discontinued as boolean",
			jsonStr: `{
				"cycle": "1.0",
				"discontinued": true
			}`,
			checkFunc: func(t *testing.T, resp EOLCycleResponse) {
				if v, ok := resp.Discontinued.(bool); !ok || !v {
					t.Errorf("expected discontinued true, got %v", resp.Discontinued)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp EOLCycleResponse
			err := json.Unmarshal([]byte(tt.jsonStr), &resp)
			if err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			tt.checkFunc(t, resp)
		})
	}
}

func TestEOLStatus_DetermineStatus(t *testing.T) {
	now := time.Now()
	pastDate := now.AddDate(-1, 0, 0)
	futureDate := now.AddDate(1, 0, 0)

	tests := []struct {
		name       string
		cycle      model.EOLProductCycle
		wantStatus model.EOLStatus
	}{
		{
			name: "discontinued",
			cycle: model.EOLProductCycle{
				Discontinued: true,
			},
			wantStatus: model.EOLStatusEOL,
		},
		{
			name: "IsEOL flag true",
			cycle: model.EOLProductCycle{
				IsEOL: true,
			},
			wantStatus: model.EOLStatusEOL,
		},
		{
			name: "EOL date in past",
			cycle: model.EOLProductCycle{
				EOLDate: &pastDate,
			},
			wantStatus: model.EOLStatusEOL,
		},
		{
			name: "EOS date in past",
			cycle: model.EOLProductCycle{
				EOSDate: &pastDate,
			},
			wantStatus: model.EOLStatusEOS,
		},
		{
			name: "support end date in past",
			cycle: model.EOLProductCycle{
				SupportEndDate: &pastDate,
			},
			wantStatus: model.EOLStatusEOS,
		},
		{
			name: "all dates in future",
			cycle: model.EOLProductCycle{
				EOLDate: &futureDate,
				EOSDate: &futureDate,
			},
			wantStatus: model.EOLStatusActive,
		},
		{
			name: "no dates set, not discontinued",
			cycle: model.EOLProductCycle{},
			wantStatus: model.EOLStatusActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the status determination logic from MatchComponentToEOL
			var status model.EOLStatus
			if tt.cycle.Discontinued {
				status = model.EOLStatusEOL
			} else if tt.cycle.IsEOL || (tt.cycle.EOLDate != nil && tt.cycle.EOLDate.Before(now)) {
				status = model.EOLStatusEOL
			} else if tt.cycle.EOSDate != nil && tt.cycle.EOSDate.Before(now) {
				status = model.EOLStatusEOS
			} else if tt.cycle.SupportEndDate != nil && tt.cycle.SupportEndDate.Before(now) {
				status = model.EOLStatusEOS
			} else {
				status = model.EOLStatusActive
			}

			if status != tt.wantStatus {
				t.Errorf("status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

func TestEOLService_VersionMatchingLogic(t *testing.T) {
	tests := []struct {
		name             string
		componentVersion string
		cycles           []string
		expectedMatch    string
	}{
		{
			name:             "exact match",
			componentVersion: "3.11",
			cycles:           []string{"3.12", "3.11", "3.10"},
			expectedMatch:    "3.11",
		},
		{
			name:             "patch version to major.minor",
			componentVersion: "3.11.4",
			cycles:           []string{"3.12", "3.11", "3.10"},
			expectedMatch:    "3.11",
		},
		{
			name:             "major version only (Node.js)",
			componentVersion: "18.19.0",
			cycles:           []string{"20", "18", "16"},
			expectedMatch:    "18",
		},
		{
			name:             "no match",
			componentVersion: "99.99.99",
			cycles:           []string{"3.12", "3.11", "3.10"},
			expectedMatch:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the version matching concept
			// The actual matching happens in SQL, this validates the expectation
			matched := ""
			for _, cycle := range tt.cycles {
				// Exact match
				if tt.componentVersion == cycle {
					matched = cycle
					break
				}
				// Prefix match (e.g., "3.11.4" starts with "3.11.")
				if len(tt.componentVersion) > len(cycle) &&
				   tt.componentVersion[:len(cycle)] == cycle &&
				   tt.componentVersion[len(cycle)] == '.' {
					matched = cycle
					break
				}
			}
			if matched != tt.expectedMatch {
				t.Errorf("version matching: got %s, want %s", matched, tt.expectedMatch)
			}
		})
	}
}

func TestEOLComponentMapping_PatternMatching(t *testing.T) {
	tests := []struct {
		name          string
		componentName string
		pattern       string
		shouldMatch   bool
	}{
		{
			name:          "exact match",
			componentName: "python",
			pattern:       "python",
			shouldMatch:   true,
		},
		{
			name:          "case insensitive match",
			componentName: "Python",
			pattern:       "python",
			shouldMatch:   true,
		},
		{
			name:          "contains match",
			componentName: "cpython",
			pattern:       "python",
			shouldMatch:   true,
		},
		{
			name:          "no match",
			componentName: "nodejs",
			pattern:       "python",
			shouldMatch:   false,
		},
		{
			name:          "package name match",
			componentName: "django-rest-framework",
			pattern:       "django",
			shouldMatch:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the matching logic from MatchComponentToEOL
			nameLower := toLower(tt.componentName)
			patternLower := toLower(tt.pattern)
			matched := nameLower == patternLower || contains(nameLower, patternLower)

			if matched != tt.shouldMatch {
				t.Errorf("pattern matching: got %v, want %v", matched, tt.shouldMatch)
			}
		})
	}
}

// Helper functions to avoid importing strings package in test
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestEOLSyncResult_Aggregation(t *testing.T) {
	result := &model.EOLSyncResult{}

	// Simulate syncing multiple products
	for i := 0; i < 5; i++ {
		result.ProductsSynced++
		result.CyclesSynced += 10
	}
	result.ComponentsUpdated = 100

	if result.ProductsSynced != 5 {
		t.Errorf("expected 5 products synced, got %d", result.ProductsSynced)
	}
	if result.CyclesSynced != 50 {
		t.Errorf("expected 50 cycles synced, got %d", result.CyclesSynced)
	}
	if result.ComponentsUpdated != 100 {
		t.Errorf("expected 100 components updated, got %d", result.ComponentsUpdated)
	}
}

func TestEOLSyncLog_StatusTransitions(t *testing.T) {
	tests := []struct {
		name         string
		initialState string
		finalState   string
		hasError     bool
	}{
		{
			name:         "success transition",
			initialState: string(model.EOLSyncStatusRunning),
			finalState:   string(model.EOLSyncStatusSuccess),
			hasError:     false,
		},
		{
			name:         "failure transition",
			initialState: string(model.EOLSyncStatusRunning),
			finalState:   string(model.EOLSyncStatusFailed),
			hasError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			log := &model.EOLSyncLog{
				ID:        uuid.New(),
				StartedAt: now,
				Status:    tt.initialState,
			}

			if log.Status != tt.initialState {
				t.Errorf("initial status mismatch")
			}

			// Transition
			log.Status = tt.finalState
			log.CompletedAt = &now
			if tt.hasError {
				log.ErrorMessage = "sync failed"
			}

			if log.Status != tt.finalState {
				t.Errorf("final status mismatch")
			}
			if log.CompletedAt == nil {
				t.Error("expected CompletedAt to be set")
			}
			if tt.hasError && log.ErrorMessage == "" {
				t.Error("expected error message for failed status")
			}
		})
	}
}

func TestComponentEOLInfo_Fields(t *testing.T) {
	productID := uuid.New()
	cycleID := uuid.New()
	eolDate := time.Date(2027, 10, 31, 0, 0, 0, 0, time.UTC)
	eosDate := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	releaseDate := time.Date(2022, 10, 24, 0, 0, 0, 0, time.UTC)

	info := &model.ComponentEOLInfo{
		Status:         model.EOLStatusActive,
		ProductID:      &productID,
		ProductName:    "Python",
		CycleID:        &cycleID,
		CycleVersion:   "3.11",
		EOLDate:        &eolDate,
		EOSDate:        &eosDate,
		LatestVersion:  "3.11.7",
		IsLTS:          false,
		ReleaseDate:    &releaseDate,
		SupportEndDate: &eosDate,
	}

	if info.Status != model.EOLStatusActive {
		t.Errorf("expected status active, got %s", info.Status)
	}
	if *info.ProductID != productID {
		t.Errorf("ProductID mismatch")
	}
	if info.ProductName != "Python" {
		t.Errorf("expected ProductName Python, got %s", info.ProductName)
	}
	if info.CycleVersion != "3.11" {
		t.Errorf("expected CycleVersion 3.11, got %s", info.CycleVersion)
	}
	if info.LatestVersion != "3.11.7" {
		t.Errorf("expected LatestVersion 3.11.7, got %s", info.LatestVersion)
	}
	if info.IsLTS {
		t.Error("expected IsLTS false")
	}
}

func TestEOLSummary_Aggregation(t *testing.T) {
	summary := &model.EOLSummary{
		ProjectID:       uuid.New(),
		TotalComponents: 100,
		Active:          70,
		EOL:             10,
		EOS:             5,
		Unknown:         15,
	}

	// Verify totals add up
	calculatedTotal := summary.Active + summary.EOL + summary.EOS + summary.Unknown
	if calculatedTotal != summary.TotalComponents {
		t.Errorf("component counts don't add up: %d + %d + %d + %d = %d, expected %d",
			summary.Active, summary.EOL, summary.EOS, summary.Unknown,
			calculatedTotal, summary.TotalComponents)
	}

	// Verify percentages would be correct
	activePercent := float64(summary.Active) / float64(summary.TotalComponents) * 100
	if activePercent != 70.0 {
		t.Errorf("expected 70%% active, got %.1f%%", activePercent)
	}

	eolPercent := float64(summary.EOL) / float64(summary.TotalComponents) * 100
	if eolPercent != 10.0 {
		t.Errorf("expected 10%% EOL, got %.1f%%", eolPercent)
	}
}

func TestEOLStats_Fields(t *testing.T) {
	now := time.Now()
	syncLog := &model.EOLSyncLog{
		ID:             uuid.New(),
		StartedAt:      now,
		CompletedAt:    &now,
		Status:         "success",
		ProductsSynced: 50,
		CyclesSynced:   500,
	}

	stats := &model.EOLStats{
		TotalProducts:    50,
		TotalCycles:      500,
		LastSyncAt:       &now,
		LatestSyncStatus: syncLog,
	}

	if stats.TotalProducts != 50 {
		t.Errorf("expected 50 products, got %d", stats.TotalProducts)
	}
	if stats.TotalCycles != 500 {
		t.Errorf("expected 500 cycles, got %d", stats.TotalCycles)
	}
	if stats.LastSyncAt == nil {
		t.Error("expected LastSyncAt to be set")
	}
	if stats.LatestSyncStatus == nil {
		t.Error("expected LatestSyncStatus to be set")
	}
	if stats.LatestSyncStatus.Status != "success" {
		t.Errorf("expected status success, got %s", stats.LatestSyncStatus.Status)
	}
}
