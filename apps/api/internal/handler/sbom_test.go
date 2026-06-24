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
		{
			// Codex R1 fix: KEV is counted orthogonally to the CVSS bucket
			// (a KEV-listed CVE also lands in CRITICAL/HIGH/etc). The CLI's
			// `--fail-on kev` reads this bucket via scan-status; without it
			// the threshold silently never trips.
			name: "kev orthogonal to severity",
			in: []model.Vulnerability{
				{Severity: "CRITICAL", InKEV: true},
				{Severity: "HIGH", InKEV: true},
				{Severity: "MEDIUM", InKEV: false},
				{Severity: "LOW"},
			},
			want: VulnerabilitySummaryCount{
				Critical: 1, High: 1, Medium: 1, Low: 1, KEV: 2, Total: 4,
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
