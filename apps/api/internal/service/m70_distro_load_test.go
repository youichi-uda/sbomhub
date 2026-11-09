package service

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// load: one OSV query per package, reduced to the package's own entries; an
// empty answer is "no records", not an error; a failure is an error, never
// an empty answer.
func TestM70DistroLoad(t *testing.T) {
	r := &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"},
		fail: map[string]int{"Debian|bash": http.StatusServiceUnavailable}}
	s := NewDistroService(nil, r.start().URL, nil, false)
	s.gap = 0
	at := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	pace := s.pacer()

	l, hit, pages, err := s.load(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, pace)
	recs := l.recs
	if err != nil || hit || pages != 1 || !l.fetchedAt.Equal(at) || l.revision == "" {
		t.Fatalf("openssl: err=%v hit=%v pages=%d at=%v rev=%q", err, hit, pages, l.fetchedAt, l.revision)
	}
	// 390 records, all naming openssl; 4 name no CVE at all (DSA-2343-1,
	// DSA-3197-2, DSA-3673-2, DSA-4539-3: regression / update advisories) and
	// cannot speak about a link, so they are dropped.
	if len(recs) != 386 {
		t.Errorf("openssl: %d records, want 386 of the 390 OSV returned", len(recs))
	}

	l, _, pages, err = s.load(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "linux-signed-amd64"}, pace)
	if err != nil || len(l.recs) != 0 || pages != 1 {
		t.Errorf("linux-signed-amd64 (`{}`): recs=%d pages=%d err=%v", len(l.recs), pages, err)
	}

	if _, _, pages, err = s.load(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "bash"}, pace); err == nil || pages != 1 {
		t.Errorf("a 503 must be an error: pages=%d err=%v", pages, err)
	}
	if got := len(r.requests()); got != 3 {
		t.Errorf("%d requests, want 3", got)
	}
}

// The pacer spaces requests by the gap and gives up when the context ends.
func TestM70DistroPacer(t *testing.T) {
	s := &DistroService{gap: 40 * time.Millisecond}
	pace := s.pacer()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := pace(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 80*time.Millisecond {
		t.Errorf("3 paced calls took %v, want >= 2 gaps", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pace(ctx); err == nil {
		t.Error("a cancelled context was paced")
	}
}
