package config

import "testing"

// SBOMHUB_JVN (2026-11): on (default) | off. Anything else refuses startup,
// like the M72 settings, rather than silently picking a default.
func TestJVNSwitch_Parse(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		enabled bool
		ok      bool
	}{
		{"", true, true},
		{"on", true, true},
		{"ON", true, true},
		{" off ", false, true},
		{"Off", false, true},
		{"false", false, false},
		{"0", false, false},
		{"disabled", false, false},
		{"yes", false, false},
		{"of", false, false},
	} {
		c := &Config{JVNRaw: tc.raw}
		got, err := c.JVNEnabled()
		if tc.ok != (err == nil) {
			t.Errorf("SBOMHUB_JVN=%q: err = %v, want ok=%t", tc.raw, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.enabled {
			t.Errorf("SBOMHUB_JVN=%q: enabled = %t, want %t", tc.raw, got, tc.enabled)
		}
	}
}

func TestJVNSwitch_ReadFromEnvironment(t *testing.T) {
	t.Setenv("SBOMHUB_JVN", "off")
	c := Load()
	if c.JVNRaw != "off" {
		t.Errorf("JVNRaw = %q, want the SBOMHUB_JVN value", c.JVNRaw)
	}
}
