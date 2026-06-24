package handler

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

func TestSummariseVulnerabilities(t *testing.T) {
	tests := []struct {
		name string
		in   []model.Vulnerability
		want VulnerabilitySummaryCount
	}{
		{
			name: "empty",
			in:   nil,
			want: VulnerabilitySummaryCount{Total: 0},
		},
		{
			name: "mixed severities",
			in: []model.Vulnerability{
				{Severity: "CRITICAL"},
				{Severity: "critical"},
				{Severity: "High"},
				{Severity: "MEDIUM"},
				{Severity: "low"},
				{Severity: "LOW"},
				{Severity: ""},
				{Severity: "informational"},
			},
			want: VulnerabilitySummaryCount{
				Critical: 2, High: 1, Medium: 1, Low: 2, Unknown: 2, Total: 8,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summariseVulnerabilities(tt.in)
			if got != tt.want {
				t.Errorf("summariseVulnerabilities() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
