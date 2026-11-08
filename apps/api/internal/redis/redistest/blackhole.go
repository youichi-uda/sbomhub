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
		mu     sync.Mutex
		closed bool
		conns  []net.Conn
		wg     sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Register under the same lock cleanup takes, so a connection
			// accepted while cleanup runs is either closed by cleanup or
			// closed here — never left open with a reader blocked on it.
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			conns = append(conns, c)
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		_ = ln.Close()
		wg.Wait()
	})
	return "redis://" + ln.Addr().String()
}
