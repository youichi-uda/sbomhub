package service

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", nvdRetryAfterDefault},
		{"garbage", nvdRetryAfterDefault},
		{"-5", nvdRetryAfterDefault},
		{"+5", nvdRetryAfterDefault},
		{"0", time.Second},
		{"17", 17 * time.Second},
		{" 17 ", 17 * time.Second},
		{"999999999999999999999", nvdRetryAfterMax}, // overflows int64: still a delay, clamped
		{"9223372036854775808", nvdRetryAfterMax},
		{"7200", nvdRetryAfterMax},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), time.Second},
		{now.Add(48 * time.Hour).Format(http.TimeFormat), nvdRetryAfterMax},
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// An HTTP-date deadline is rounded UP to whole seconds (Codex R2): with now at
// .800 and the deadline 9.2 s away, 9 would send the caller back too early.
func TestParseRetryAfter_HTTPDateRoundsUp(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 800_000_000, time.UTC)
	deadline := time.Date(2026, 11, 9, 12, 0, 10, 0, time.UTC) // 9.2 s after now
	if got := parseRetryAfter(deadline.Format(http.TimeFormat), now); got != 10*time.Second {
		t.Fatalf("got %s, want 10s", got)
	}
}
