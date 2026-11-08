package config

import (
	"testing"
	"time"
)

func TestNVDReconcileInterval(t *testing.T) {
	cases := []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{
		{"", DefaultNVDReconcileInterval, false},
		{"off", 0, false},
		{" Disabled ", 0, false},
		{"false", 0, false},
		{"0", 0, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"720h", 720 * time.Hour, false},
		{"24h", 24 * time.Hour, false},
		{"1h", 0, true},      // shorter than the daily delta sync
		{"0d", 0, true},      // a zero count of days is not "off"
		{"-3d", 0, true},     // negative
		{"monthly", 0, true}, // unparseable: refused, not defaulted
		{"30", 0, true},      // a bare number has no unit
		{"1.5d", 0, true},    // whole days only
		{"-720h", 0, true},   // negative duration
	}
	for _, c := range cases {
		got, err := (&Config{NVDReconcileIntervalRaw: c.raw}).NVDReconcileInterval()
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", c.raw, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("%q: got %s, want %s", c.raw, got, c.want)
		}
	}
}
