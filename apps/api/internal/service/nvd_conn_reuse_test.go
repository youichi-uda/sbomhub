package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Codex R3: a refused NVD lookup (403/429/503) returned without reading the
// response body, so the keep-alive connection could not be reused and every
// refused lookup — exactly while NVD is throttling us — opened a new one.
func TestSearchByCVEID_RefusedLookupReusesConnection(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(strings.Repeat("rate limited ", 15000)))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	svc := NewNVDService(nil, nil, "", srv.URL, false)
	for i := 0; i < 3; i++ {
		if _, err := svc.SearchByCVEID(context.Background(), "CVE-2024-1234"); err == nil {
			t.Fatal("want an error")
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("3 refused lookups opened %d connections, want 1 (body not drained)", n)
	}
}
