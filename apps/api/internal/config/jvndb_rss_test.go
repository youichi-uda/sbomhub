package config

import (
	"testing"
	"time"
)

func TestJVNDBRSSSettings(t *testing.T) {
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	ok := []struct {
		url, interval, from string
		want                JVNDBRSSSettings
	}{
		{"", "", "", JVNDBRSSSettings{Interval: 6 * time.Hour}},
		{"", "OFF", "", JVNDBRSSSettings{}},
		{"https://mirror.example/jvndb/ja/rss/", "12h", "2024", JVNDBRSSSettings{BaseURL: "https://mirror.example/jvndb/ja/rss/", Interval: 12 * time.Hour, BackfillFrom: 2024}},
		{"http://10.0.0.5:8080/rss", "1h", "1988", JVNDBRSSSettings{BaseURL: "http://10.0.0.5:8080/rss", Interval: time.Hour, BackfillFrom: 1988}},
		{"", "2d", "2026", JVNDBRSSSettings{Interval: 48 * time.Hour, BackfillFrom: 2026}},
	}
	for _, c := range ok {
		got, err := (&Config{JVNDBRSSURL: c.url, JVNDBRSSIntervalRaw: c.interval, JVNDBRSSBackfillFromRaw: c.from}).JVNDBRSS(now)
		if err != nil || got != c.want {
			t.Errorf("%+v: got %+v, %v; want %+v", c, got, err, c.want)
		}
	}
	bad := []struct{ url, interval, from string }{
		{"ftp://x/rss", "", ""},
		{"/relative", "", ""},
		{"https://x/rss?token=1", "", ""},
		{"https://user:pw@x/rss", "", ""},
		{"https://x/rss#f", "", ""},
		{"", "30m", ""},
		{"", "49h", ""},
		{"", "3d", ""},
		{"", "false", ""},
		{"", "0", ""},
		{"", "", "1987"},
		{"", "", "2027"},
		{"", "", "last-year"},
		{"", "off", "2024"},
	}
	for _, c := range bad {
		if _, err := (&Config{JVNDBRSSURL: c.url, JVNDBRSSIntervalRaw: c.interval, JVNDBRSSBackfillFromRaw: c.from}).JVNDBRSS(now); err == nil {
			t.Errorf("%+v: want a startup refusal", c)
		}
	}
}

func TestJVNDBRSSSettingsFromEnv(t *testing.T) {
	t.Setenv("SBOMHUB_JVNDB_RSS_URL", "https://m.example/rss")
	t.Setenv("SBOMHUB_JVNDB_RSS_INTERVAL", "3h")
	t.Setenv("SBOMHUB_JVNDB_RSS_BACKFILL_FROM", "2025")
	c := Load()
	if c.JVNDBRSSURL != "https://m.example/rss" || c.JVNDBRSSIntervalRaw != "3h" || c.JVNDBRSSBackfillFromRaw != "2025" {
		t.Fatalf("Load did not read the SBOMHUB_JVNDB_RSS_* variables: %+v", []string{c.JVNDBRSSURL, c.JVNDBRSSIntervalRaw, c.JVNDBRSSBackfillFromRaw})
	}
}
