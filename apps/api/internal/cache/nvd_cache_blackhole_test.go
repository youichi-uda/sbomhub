package cache

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	sbomredis "github.com/sbomhub/sbomhub/internal/redis"
	"github.com/sbomhub/sbomhub/internal/redis/redistest"
)

// The scanner treats a cache error as a miss and goes on to NVD. That only
// works if the error arrives: against a hung Redis each cache call must give
// up within OpTimeout even when the caller's context has no deadline
// (the scan context's deadline is the whole scan's, up to 24h).
func TestNVDCache_BlackHoledRedisFailsFast(t *testing.T) {
	opts, err := sbomredis.Options(redistest.BlackHole(t))
	if err != nil {
		t.Fatal(err)
	}
	c := goredis.NewClient(opts)
	defer c.Close()
	nc := NewNVDCache(c)
	bound := OpTimeout + time.Second

	ops := map[string]func() error{
		"get":    func() error { _, err := nc.Get(context.Background(), "openssl", "3.0.0"); return err },
		"set":    func() error { return nc.Set(context.Background(), "openssl", "3.0.0", nil) },
		"delete": func() error { return nc.Delete(context.Background(), "openssl", "3.0.0") },
		"stats":  func() error { _, err := nc.GetStats(context.Background()); return err },
		"clear":  func() error { return nc.Clear(context.Background()) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			err := op()
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("cache op against a hung Redis returned no error")
			}
			if elapsed > bound {
				t.Fatalf("%s took %v (bound %v)", name, elapsed, bound)
			}
		})
	}
}
