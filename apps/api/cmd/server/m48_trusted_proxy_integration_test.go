//go:build integration

package main

// M48 FO-6 in proxy mode (SBOMHUB_TRUSTED_PROXIES), end to end.
//
// The public-link brute-force budget (M48 FO-6) is charged per client IP, and
// the audit log records a client IP; both are c.RealIP(), i.e. whatever
// Echo#IPExtractor main() installs from SBOMHUB_TRUSTED_PROXIES (M56,
// appmw.ClientIPExtractor). The unit tests drive ClientIPExtractor and the
// middleware separately on hand-built echo instances, so none of them proves
// that the SERVER uses the extractor for these two consumers. This test
// builds and starts the real server binary, with its real middleware chain,
// database and Redis, configured to trust exactly 127.0.0.1 as a proxy, and
// talks to it from two loopback source addresses:
//
//   - 127.0.0.1, the trusted proxy: its X-Forwarded-For is honoured, so the
//     rate-limit key, the audit row and the access log carry the forwarded
//     client address (and a client-prepended hop in front of it is skipped);
//   - 127.0.0.2, an untrusted peer: its X-Forwarded-For / X-Real-IP are
//     ignored, so everything is charged to 127.0.0.2 and rotating spoofed
//     headers cannot buy a fresh rate-limit budget.
//
// Run with (the compose stack's DATABASE_URL / MIGRATE_DATABASE_URL /
// REDIS_URL / ENCRYPTION_KEY in the environment, migrations applied):
//
//	cd apps/api && go test -tags=integration -count=1 -run M48TrustedProxy ./cmd/server
//
// It needs 127.0.0.2 on the loopback interface (Linux has all of 127/8).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "github.com/lib/pq"
	goredis "github.com/redis/go-redis/v9"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

const (
	m48TrustedPeer   = "127.0.0.1"
	m48UntrustedPeer = "127.0.0.2"
)

// syncBuffer is a goroutine-safe sink for the server's stdout/stderr.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type m48Server struct {
	base string
	out  *syncBuffer
}

// startM48Server builds ./cmd/server and runs it with trustedProxies.
func startM48Server(t *testing.T, trustedProxies string) *m48Server {
	t.Helper()
	for _, k := range []string{"DATABASE_URL", "MIGRATE_DATABASE_URL", "REDIS_URL"} {
		if os.Getenv(k) == "" {
			t.Skipf("%s not set", k)
		}
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain not on PATH: %v", err)
	}
	bin := t.TempDir() + "/sbomhub-server"
	build := exec.Command(goBin, "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	out := &syncBuffer{}
	cmd := exec.Command(bin)
	// An empty working directory: main() calls godotenv.Load(), and a
	// developer's .env must not leak settings (a CLERK_SECRET_KEY) in.
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(),
		"PORT="+fmt.Sprint(port),
		"SBOMHUB_AUTH_MODE=anonymous",
		"CLERK_SECRET_KEY=",
		"SBOMHUB_OFFLINE=true",
		"SBOMHUB_TRUSTED_PROXIES="+trustedProxies,
	)
	if os.Getenv("APP_ENV") == "" {
		cmd.Env = append(cmd.Env, "APP_ENV=development")
	}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			t.Logf("server output:\n%s", out.String())
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case err := <-exited:
			t.Fatalf("server exited during startup: %v\n%s", err, out.String())
		default:
		}
		resp, err := http.Get(base + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not healthy after 90s\n%s", out.String())
		}
		time.Sleep(250 * time.Millisecond)
	}
	return &m48Server{base: base, out: out}
}

// clientFrom returns an HTTP client whose connections originate from src.
func clientFrom(t *testing.T, src string) *http.Client {
	t.Helper()
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:       d.DialContext,
			DisableKeepAlives: true,
		},
	}
}

func m48Rand(t *testing.T, n int64) int64 {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		t.Fatal(err)
	}
	return v.Int64()
}

// m48Request sends one request and returns the status. ua makes the request
// findable in audit_logs and in the access log.
func m48Request(t *testing.T, c *http.Client, method, url, ua string, headers map[string]string, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("User-Agent", ua)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func m48IPHash(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

// failCount sums the public-link per-IP failure counters for ip (every
// window bucket — a run can straddle a bucket boundary).
func failCount(t *testing.T, rdb *goredis.Client, ip string) int64 {
	t.Helper()
	ctx := context.Background()
	var total int64
	iter := rdb.Scan(ctx, 0, "publiclink:fail:ip:"+m48IPHash(ip)+":*", 100).Iterator()
	for iter.Next(ctx) {
		n, err := rdb.Get(ctx, iter.Val()).Int64()
		if err != nil {
			t.Fatalf("read %s: %v", iter.Val(), err)
		}
		total += n
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	return total
}

func clearFailCounters(t *testing.T, rdb *goredis.Client, ip string) {
	t.Helper()
	ctx := context.Background()
	iter := rdb.Scan(ctx, 0, "publiclink:fail:ip:"+m48IPHash(ip)+":*", 100).Iterator()
	for iter.Next(ctx) {
		if err := rdb.Del(ctx, iter.Val()).Err(); err != nil {
			t.Fatal(err)
		}
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
}

// auditIP returns the ip_address of the audit row written for the request
// sent with user agent ua.
func auditIP(t *testing.T, db *sql.DB, ua string) string {
	t.Helper()
	var ip sql.NullString
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := db.QueryRow(`SELECT host(ip_address) FROM audit_logs WHERE user_agent = $1`, ua).Scan(&ip)
		if err == nil {
			return ip.String
		}
		if err != sql.ErrNoRows || time.Now().After(deadline) {
			t.Fatalf("audit row for %q: %v", ua, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// accessLogIP returns remote_ip of the server's access-log line for ua.
func accessLogIP(t *testing.T, s *m48Server, ua string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sc := bufio.NewScanner(strings.NewReader(s.out.String()))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			var rec map[string]any
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec["msg"] != "http request" || rec["user_agent"] != ua {
				continue
			}
			ip, _ := rec["remote_ip"].(string)
			return ip
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access-log line for %q", ua)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestM48TrustedProxy_ServerWiring(t *testing.T) {
	srv := startM48Server(t, m48TrustedPeer)

	trusted := clientFrom(t, m48TrustedPeer)
	untrusted := clientFrom(t, m48UntrustedPeer)
	if resp, err := untrusted.Get(srv.base + "/api/v1/health"); err != nil {
		t.Fatalf("cannot connect from %s (is it on the loopback interface?): %v", m48UntrustedPeer, err)
	} else {
		_ = resp.Body.Close()
	}

	opt, err := goredis.ParseURL(os.Getenv("REDIS_URL"))
	if err != nil {
		t.Fatal(err)
	}
	rdb := goredis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() }) // registered first, so it runs last
	db, err := sql.Open("postgres", os.Getenv("MIGRATE_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	run := fmt.Sprintf("m48tp-%d", m48Rand(t, 1<<40))
	// Fresh documentation-range addresses per run, so counters left by an
	// earlier run in the same window cannot satisfy an assertion.
	clientA := fmt.Sprintf("203.0.113.%d", 1+m48Rand(t, 254))
	clientD := fmt.Sprintf("192.0.2.%d", 1+m48Rand(t, 254))
	spoofB := fmt.Sprintf("198.51.100.%d", 1+m48Rand(t, 254))
	spoofC := fmt.Sprintf("198.51.100.%d", 1+m48Rand(t, 254))
	t.Cleanup(func() {
		for _, ip := range []string{clientA, clientD, spoofB, spoofC, m48UntrustedPeer} {
			clearFailCounters(t, rdb, ip)
		}
	})

	publicURL := func() string {
		return fmt.Sprintf("%s/api/v1/public/%s-%d", srv.base, run, m48Rand(t, 1<<40))
	}
	projectsURL := srv.base + "/api/v1/projects"

	t.Run("trusted proxy: forwarded client is the identity", func(t *testing.T) {
		hdr := map[string]string{"X-Forwarded-For": clientA}
		peerBefore := failCount(t, rdb, m48TrustedPeer)

		ua := run + "-trusted-audit"
		if got := m48Request(t, trusted, http.MethodPost, projectsURL, ua, hdr, `{"name":"`+ua+`"}`); got != http.StatusCreated {
			t.Fatalf("create project: status %d", got)
		}
		if ip := auditIP(t, db, ua); ip != clientA {
			t.Errorf("audit ip = %q, want the forwarded client %q", ip, clientA)
		}
		if ip := accessLogIP(t, srv, ua); ip != clientA {
			t.Errorf("access log remote_ip = %q, want %q", ip, clientA)
		}

		ua = run + "-trusted-ratelimit"
		if got := m48Request(t, trusted, http.MethodGet, publicURL(), ua, hdr, ""); got != http.StatusForbidden {
			t.Fatalf("public link with a bad token: status %d, want 403", got)
		}
		if n := failCount(t, rdb, clientA); n != 1 {
			t.Errorf("failure budget of the forwarded client = %d, want 1", n)
		}
		if n := failCount(t, rdb, m48TrustedPeer); n != peerBefore {
			t.Errorf("the proxy's own address was charged (%d -> %d); the budget must follow the client", peerBefore, n)
		}
	})

	t.Run("trusted proxy: a client-prepended hop is not believed", func(t *testing.T) {
		// The client sent "X-Forwarded-For: spoofC"; the proxy appended the
		// address it saw (clientD). Only the proxy's entry is trustworthy.
		ua := run + "-chain"
		hdr := map[string]string{"X-Forwarded-For": spoofC + ", " + clientD}
		if got := m48Request(t, trusted, http.MethodPost, projectsURL, ua, hdr, `{"name":"`+ua+`"}`); got != http.StatusCreated {
			t.Fatalf("create project: status %d", got)
		}
		if ip := auditIP(t, db, ua); ip != clientD {
			t.Errorf("audit ip = %q, want the proxy-appended hop %q", ip, clientD)
		}
	})

	t.Run("untrusted peer: forwarding headers are ignored", func(t *testing.T) {
		clearFailCounters(t, rdb, m48UntrustedPeer)
		hdr := map[string]string{"X-Forwarded-For": spoofB, "X-Real-IP": spoofB}

		ua := run + "-untrusted-audit"
		if got := m48Request(t, untrusted, http.MethodPost, projectsURL, ua, hdr, `{"name":"`+ua+`"}`); got != http.StatusCreated {
			t.Fatalf("create project: status %d", got)
		}
		if ip := auditIP(t, db, ua); ip != m48UntrustedPeer {
			t.Errorf("audit ip = %q, want the TCP peer %q (spoofed %q)", ip, m48UntrustedPeer, spoofB)
		}
		if ip := accessLogIP(t, srv, ua); ip != m48UntrustedPeer {
			t.Errorf("access log remote_ip = %q, want %q", ip, m48UntrustedPeer)
		}

		ua = run + "-untrusted-ratelimit"
		if got := m48Request(t, untrusted, http.MethodGet, publicURL(), ua, hdr, ""); got != http.StatusForbidden {
			t.Fatalf("public link with a bad token: status %d, want 403", got)
		}
		if n := failCount(t, rdb, m48UntrustedPeer); n != 1 {
			t.Errorf("failure budget of the TCP peer = %d, want 1", n)
		}
		if n := failCount(t, rdb, spoofB); n != 0 {
			t.Errorf("the spoofed address was charged %d times", n)
		}
	})

	t.Run("untrusted peer: rotating spoofed headers cannot escape the budget", func(t *testing.T) {
		clearFailCounters(t, rdb, m48UntrustedPeer)
		for i := 0; i < appmw.PublicLinkFailuresPerIP; i++ {
			hdr := map[string]string{"X-Forwarded-For": fmt.Sprintf("10.%d.%d.%d", i%250, (i/250)%250, 1+i%200)}
			if got := m48Request(t, untrusted, http.MethodGet, publicURL(), run+"-rotate", hdr, ""); got != http.StatusForbidden {
				t.Fatalf("attempt %d: status %d, want 403 (budget not yet spent)", i+1, got)
			}
		}
		hdr := map[string]string{"X-Forwarded-For": "10.250.250.250"}
		if got := m48Request(t, untrusted, http.MethodGet, publicURL(), run+"-rotate", hdr, ""); got != http.StatusTooManyRequests {
			t.Fatalf("attempt %d with yet another spoofed address: status %d, want 429",
				appmw.PublicLinkFailuresPerIP+1, got)
		}
	})
}
