//go:build integration

package handler

import (
	"context"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service"
)

type m72CountHook struct{ n *atomic.Int64 }

func (h m72CountHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h m72CountHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error { h.n.Add(1); return next(ctx, cmd) }
}
func (h m72CountHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error { h.n.Add(int64(len(cmds))); return next(ctx, cmds) }
}

// Codex M72 R15 Medium-2: scan-status touches the shared status only after
// the SBOM was found in the caller's project (RLS-scoped). Another project's
// (or tenant's) SBOM id gets its 404 without any Redis read.
func TestM72ScanStatus_ForeignSBOMIsNotReadFromRedis(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("requires REDIS_URL")
	}
	appURL, migURL := m46b1HandlerEnv(t)
	migDB := m46b1OpenOrSkip(t, migURL)
	appDB := m46b1OpenOrSkip(t, appURL)
	seed := m47SeedAll(t, migDB, "m72foreign")

	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	var n atomic.Int64
	rdb.AddHook(m72CountHook{&n})
	h := &SbomHandler{
		sbomService: service.NewSbomService(repository.NewSbomRepository(appDB), repository.NewComponentRepository(appDB)),
		scanTracker: service.NewScanTracker().WithRedis(rdb),
	}
	// WithRedis reads Redis's eviction settings once (CONFIG GET); count only
	// what the request does.
	n.Store(0)
	// sbom2 belongs to the tenant's OTHER project.
	code, body := m47Call(t, appDB, m47Req{
		method:     http.MethodGet,
		target:     "/api/v1/projects/" + seed.projectID.String() + "/sboms/" + seed.sbom2ID.String() + "/scan-status",
		paramNames: []string{"id", "sbom_id"},
		paramVals:  []string{seed.projectID.String(), seed.sbom2ID.String()},
		tenantID:   seed.tenantID,
	}, h.ScanStatus)
	if code != http.StatusNotFound {
		t.Fatalf("foreign sbom: %d %s, want 404", code, body)
	}
	if got := n.Load(); got != 0 {
		t.Fatalf("a foreign SBOM's status was read from Redis (%d commands) before the ownership check", got)
	}
}
