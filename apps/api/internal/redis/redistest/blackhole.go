// Package redistest has test helpers for Redis failure modes.
package redistest

import (
	"io"
	"net"
	"sync"
	"testing"
)

// BlackHole starts a TCP listener that accepts every connection and never
// answers: it reads and discards whatever the client sends, so a client's
// write succeeds and its read waits forever. It models a Redis that is
// network-reachable but hung (a stopped process behind a live socket, a
// stalled proxy), which is the case a refused connection does not cover.
//
// It returns a redis:// URL for the listener and closes everything at the
// end of the test.
func BlackHole(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("black hole listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return "redis://" + ln.Addr().String()
}
