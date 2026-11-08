package config

import (
	"strings"
	"testing"
	"time"
)

// M62: SBOMHUB_SCAN_DEADLINE bounds one SBOM scan (NVD + JVN).
func TestScanDeadline(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr string
	}{
		{"", 30 * time.Minute, ""},
		{"  ", 30 * time.Minute, ""},
		{"45m", 45 * time.Minute, ""},
		{"2h", 2 * time.Hour, ""},
		{"1m", time.Minute, ""},
		{"24h", 24 * time.Hour, ""},
		{"30", 0, "duration"},
		{"off", 0, "cannot be disabled"},
		{"0", 0, "cannot be disabled"},
		{"-5m", 0, "at least 1m"},
		{"59s", 0, "at least 1m"},
		{"25h", 0, "at most 24h"},
		{"nonsense", 0, "duration"},
	}
	for _, tc := range cases {
		c := &Config{ScanDeadlineRaw: tc.raw}
		got, err := c.ScanDeadline()
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: err = %v, want one containing %q", tc.raw, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %s, %v; want %s", tc.raw, got, err, tc.want)
		}
	}
}

func TestScanDeadlineIsReadFromTheEnvironment(t *testing.T) {
	t.Setenv("SBOMHUB_SCAN_DEADLINE", "40m")
	if got := Load().ScanDeadlineRaw; got != "40m" {
		t.Errorf("ScanDeadlineRaw = %q, want 40m", got)
	}
}
