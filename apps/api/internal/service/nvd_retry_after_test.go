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
		{"0", time.Second},
		{"17", 17 * time.Second},
		{" 17 ", 17 * time.Second},
		{"999999999999999999999", nvdRetryAfterDefault}, // overflows int64: unparsable
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
