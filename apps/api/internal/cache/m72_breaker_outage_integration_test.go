//go:build integration

package cache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
)

// M72: what a Redis outage costs a scan and a rate-limited request, without
// and with the circuit breaker, against a real throwaway Redis that the test
// stops (docker stop: connection refused) or freezes (docker pause: the port
// still accepts, nothing answers) in the middle of the run.
//
// Needs REDIS_URL and M72_REDIS_CONTAINER (the container behind it, which
// the test stops and restarts — never point it at a shared Redis). It logs
// the measurements; it asserts that without the breaker every call pays the
// outage, that with it each breaker class pays for at most threshold calls
// plus a probe or two, and that Redis is used again after it comes back.

const (
	m72Components = 20 // cache lookups of one simulated scan
	m72Requests   = 10 // rate-limit round trips (one per API request)
)

var m72Charge = goredis.NewScript(`local n = redis.call('INCR', KEYS[1]) redis.call('EXPIRE', KEYS[1], 60) return n`)

type m72Run struct {
	scanTotal time.Duration
	scanLat   []time.Duration
	reqTotal  time.Duration
	reqLat    []time.Duration
	recovery  time.Duration
}

func pct(d []time.Duration, p float64) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[int(float64(len(s)-1)*p)]
}

// paid counts the calls that waited on the outage (refused dials take
// ~400ms here, hung reads the full bound) rather than failing fast.
func paid(lat []time.Duration) int {
	n := 0
	for _, d := range lat {
		if d > 50*time.Millisecond {
			n++
		}
	}
	return n
}

func docker(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker %v: %v: %s", args, err, out)
	}
}

func waitPing(t *testing.T, url string) {
	t.Helper()
	opt, _ := goredis.ParseURL(url)
	c := goredis.NewClient(opt)
	defer c.Close()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		err := c.Ping(ctx).Err()
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("redis did not come back: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func m72Measure(t *testing.T, url, container, mode string, withBreaker bool) m72Run {
	t.Helper()
	opts, err := sbomredis.Options(url)
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(opts)
	defer client.Close()
	if withBreaker {
		client.AddHook(sbomredis.NewBreakers(sbomredis.BreakerConfig{}).Hook()) // production setup and defaults
	}
	nvd := NewNVDCache(client)
	ctx := context.Background()
	for i := 0; i < 10; i++ { // warm the pool
		if _, err := nvd.Get(ctx, "warm", fmt.Sprint(i)); err != nil {
			t.Fatalf("warm-up: %v", err)
		}
	}

	switch mode {
	case "stop":
		docker(t, "stop", "-t", "0", container)
	case "pause":
		docker(t, "pause", container)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if mode == "stop" {
			docker(t, "start", container)
		} else {
			docker(t, "unpause", container)
		}
		waitPing(t, url)
	}
	defer restore()

	var r m72Run
	start := time.Now()
	for i := 0; i < m72Components; i++ {
		s := time.Now()
		_, _ = nvd.Get(ctx, "component", fmt.Sprint(i)) // an error is a miss
		r.scanLat = append(r.scanLat, time.Since(s))
	}
	r.scanTotal = time.Since(start)
	start = time.Now()
	for i := 0; i < m72Requests; i++ {
		s := time.Now()
		cctx, cancel := sbomredis.CommandContext(ctx) // what RateLimitByAPIKey does
		_ = m72Charge.Run(cctx, client, []string{"m72:charge"}).Err()
		cancel()
		r.reqLat = append(r.reqLat, time.Since(s))
	}
	r.reqTotal = time.Since(start)

	restore()
	// Recovery: how long until the cache answers again.
	start = time.Now()
	for {
		if err := client.Set(ctx, "m72:recovered", "1", time.Minute).Err(); err == nil {
			break
		}
		if time.Since(start) > 30*time.Second {
			t.Fatalf("client did not recover within 30s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.recovery = time.Since(start)
	return r
}

func TestM72BreakerOutageLatency(t *testing.T) {
	url, container := os.Getenv("REDIS_URL"), os.Getenv("M72_REDIS_CONTAINER")
	if url == "" || container == "" {
		t.Skip("requires REDIS_URL and M72_REDIS_CONTAINER (a throwaway Redis container)")
	}
	var report strings.Builder
	fmt.Fprintf(&report, "\n%d cache lookups (1s bound each) + %d rate-limit round trips (3s bound each); breaker threshold %d, cool-down %s\n",
		m72Components, m72Requests, sbomredis.DefaultBreakerThreshold, sbomredis.DefaultBreakerCooldown)
	for _, mode := range []string{"stop", "pause"} {
		before := m72Measure(t, url, container, mode, false)
		after := m72Measure(t, url, container, mode, true)
		for _, x := range []struct {
			name string
			r    m72Run
		}{{"without breaker", before}, {"with breaker   ", after}} {
			fmt.Fprintf(&report, "docker %-5s %s: scan total %8s (p50 %8s, p99 %8s) | requests total %8s (p50 %8s, p99 %8s) | recovery %s\n",
				mode, x.name,
				x.r.scanTotal.Round(time.Millisecond), pct(x.r.scanLat, .5).Round(time.Microsecond), pct(x.r.scanLat, .99).Round(time.Microsecond),
				x.r.reqTotal.Round(time.Millisecond), pct(x.r.reqLat, .5).Round(time.Microsecond), pct(x.r.reqLat, .99).Round(time.Microsecond),
				x.r.recovery.Round(time.Millisecond))
		}
		// Without the breaker every call pays the outage; with it, each
		// class pays for at most threshold calls plus one probe per elapsed
		// cool-down (the cache and the rate limiter are separate classes).
		for _, w := range []struct {
			name          string
			before, after []time.Duration
		}{{"scan", before.scanLat, after.scanLat}, {"requests", before.reqLat, after.reqLat}} {
			if paid(w.before) != len(w.before) {
				t.Errorf("%s %s without breaker: only %d of %d calls paid the outage", mode, w.name, paid(w.before), len(w.before))
			}
			if max := sbomredis.DefaultBreakerThreshold + 2; paid(w.after) > max {
				t.Errorf("%s %s with breaker: %d calls paid the outage, want <= %d", mode, w.name, paid(w.after), max)
			}
		}
		if after.recovery > sbomredis.DefaultBreakerCooldown+5*time.Second {
			t.Errorf("%s: recovery with the breaker took %s", mode, after.recovery)
		}
	}
	t.Log(report.String())
}
