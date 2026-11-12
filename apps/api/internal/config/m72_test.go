package config

import (
	"testing"
	"time"
)

func TestM72RedisBreaker(t *testing.T) {
	for _, c := range []struct {
		thr, cool string
		wantN     int
		wantD     time.Duration
		wantErr   bool
	}{
		{"", "", 5, 5 * time.Second, false},
		{"3", "30s", 3, 30 * time.Second, false},
		{" 1000 ", "5m", 1000, 5 * time.Minute, false},
		{"0", "", 0, 0, true},
		{"1001", "", 0, 0, true},
		{"x", "", 0, 0, true},
		{"", "500ms", 0, 0, true},
		{"", "6m", 0, 0, true},
		{"", "off", 0, 0, true},
	} {
		cfg := &Config{RedisBreakerThresholdRaw: c.thr, RedisBreakerCooldownRaw: c.cool}
		n, d, err := cfg.RedisBreaker()
		if (err != nil) != c.wantErr || (!c.wantErr && (n != c.wantN || d != c.wantD)) {
			t.Errorf("(%q,%q) = %d %s %v", c.thr, c.cool, n, d, err)
		}
	}
}

func TestM72ScanTenantConcurrency(t *testing.T) {
	for _, c := range []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{"", 2, false},
		{"off", 0, false},
		{"OFF", 0, false},
		{"1", 1, false},
		{"64", 64, false},
		{"0", 0, true},
		{"65", 0, true},
		{"-1", 0, true},
		{"two", 0, true},
	} {
		n, err := (&Config{ScanTenantConcurrencyRaw: c.raw}).ScanTenantConcurrency()
		if (err != nil) != c.wantErr || (!c.wantErr && n != c.want) {
			t.Errorf("%q = %d %v", c.raw, n, err)
		}
	}
}
