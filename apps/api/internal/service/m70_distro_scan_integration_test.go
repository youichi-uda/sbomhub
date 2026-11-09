//go:build integration

// M70 — the distro step against a real PostgreSQL (and Redis when REDIS_URL is
// set): relabels in the scan's own short write transaction, under RLS, with
// the rank rule, and reports a data failure as a reason without touching a
// label.
//
//	cd apps/api && DATABASE_URL=... MIGRATE_DATABASE_URL=... [REDIS_URL=...] \
//	    go test -tags=integration -count=1 -run M70 ./internal/service
package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const m70SyftOpenSSL = "pkg:deb/debian/openssl@1.1.1k-1?arch=amd64&distro=debian-11"

// m70Vuln returns the catalogue id of cveID, creating the row if this
// database has none (cve_id is globally unique; a row another test made is
// reused, one made here is deleted afterwards).
func m70Vuln(t *testing.T, migDB *sql.DB, cveID string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := migDB.QueryRow(`SELECT id FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&id)
	if err == nil {
		return id
	}
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return seedVulnVS(t, migDB, cveID)
}

func m70Link(t *testing.T, migDB *sql.DB, comp, vuln uuid.UUID, method string) {
	t.Helper()
	var m any
	if method != "" {
		m = method
	}
	if _, err := migDB.Exec(`INSERT INTO component_vulnerabilities (component_id, vulnerability_id, detected_at, match_method)
		VALUES ($1, $2, NOW(), $3)`, comp, vuln, m); err != nil {
		t.Fatalf("link: %v", err)
	}
}

type m70Row struct {
	method   string
	evidence model.DistroEvidence
	hasEv    bool
}

func m70Read(t *testing.T, migDB *sql.DB, comp, vuln uuid.UUID) m70Row {
	t.Helper()
	var method sql.NullString
	var ev []byte
	if err := migDB.QueryRow(`SELECT match_method, match_evidence FROM component_vulnerabilities
		WHERE component_id = $1 AND vulnerability_id = $2`, comp, vuln).Scan(&method, &ev); err != nil {
		t.Fatal(err)
	}
	r := m70Row{method: method.String}
	if len(ev) > 0 {
		r.hasEv = true
		if err := json.Unmarshal(ev, &r.evidence); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

type m70Env struct {
	migDB, appDB   *sql.DB
	tenant, sbom   uuid.UUID
	project        uuid.UUID
	openssl, plain uuid.UUID
	v0286, v3449   uuid.UUID
	v1292, vNoRec  uuid.UUID
	compRepo       *repository.ComponentRepository
}

// m70Seed: an SBOM with Debian 11 openssl 1.1.1k-1 (Syft's purl) and a
// non-distro component, linked as M60 would have linked them.
//
//	openssl -> CVE-2023-0286 (DSA-5343-1, bullseye only: fixed at 1.1.1n-0+deb11u4 -> affected)
//	openssl -> CVE-2021-3449 (DEBIAN-CVE: Debian 12/13/14 fixed at 1.1.1k-1 -> fixed, later_releases)
//	openssl -> CVE-2022-1292 (DSA-5139-1, one CVE: fixed in bullseye at 1.1.1n-0+deb11u2 -> affected)
//	openssl -> CVE-2009-0591 (no Debian openssl record in OSV -> unchanged)
//	plain   -> CVE-2021-3449 (nvd_cpe, not a distro package)
func m70Seed(t *testing.T, label string) m70Env {
	t.Helper()
	appURL, migURL := vexSuggestionsTestEnv(t)
	e := m70Env{migDB: openOrSkipVS(t, migURL), appDB: openOrSkipVS(t, appURL)}
	if !schemaReadyVS(t, e.migDB) {
		t.FailNow()
	}
	e.tenant = seedTenantVS(t, e.migDB, label)
	e.project = uuid.New()
	seedProjectVS(t, e.migDB, e.tenant, e.project, label+"-"+e.project.String())
	e.sbom = seedSbomVS(t, e.migDB, e.tenant, e.project)
	e.openssl = seedComponentVS(t, e.migDB, e.tenant, e.sbom, "openssl", "1.1.1k-1", m70SyftOpenSSL)
	e.plain = seedComponentVS(t, e.migDB, e.tenant, e.sbom, "openssl", "1.1.1k", "pkg:generic/openssl@1.1.1k")
	e.v0286 = m70Vuln(t, e.migDB, "CVE-2023-0286")
	e.v3449 = m70Vuln(t, e.migDB, "CVE-2021-3449")
	e.v1292 = m70Vuln(t, e.migDB, "CVE-2022-1292")
	e.vNoRec = m70Vuln(t, e.migDB, "CVE-2009-0591")
	for _, v := range []uuid.UUID{e.v0286, e.v3449, e.v1292, e.vNoRec} {
		m70Link(t, e.migDB, e.openssl, v, "nvd_cpe_unverified")
	}
	m70Link(t, e.migDB, e.plain, e.v3449, "nvd_cpe")
	e.compRepo = repository.NewComponentRepository(e.appDB)
	return e
}

func m70Service(t *testing.T, e m70Env, osvURL string, dc *cache.DistroCache) *DistroService {
	t.Helper()
	s := NewDistroService(e.compRepo, osvURL, dc, false)
	s.gap = 0
	return s
}

func m70DebianReplay(t *testing.T) *replayOSV {
	return &replayOSV{t: t, routes: map[string]string{"Debian|openssl": "debian_openssl"}}
}

func TestM70DistroScan_RelabelsWithEvidence(t *testing.T) {
	e := m70Seed(t, "m70relabel")
	r := m70DebianReplay(t)
	svc := m70Service(t, e, r.start().URL, nil)
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)

	rep, err := svc.ScanComponentsWithReport(ctx, e.sbom)
	if err != nil {
		t.Fatalf("scan: %v (report %+v)", err, rep)
	}
	t.Logf("report: %+v", rep)
	if got := r.requests(); len(got) != 1 || got[0] != "Debian|openssl" {
		t.Errorf("OSV requests = %q, want one query for Debian openssl", got)
	}
	// 3 relabels + 1 no-verdict watermark (Codex M70 R13 High-1).
	if rep.Affected != 2 || rep.Fixed != 1 || rep.Unfixed != 0 || rep.Relabelled != 4 || rep.Targeted != 1 || rep.Packages != 1 {
		t.Errorf("report %+v", rep)
	}

	a := m70Read(t, e.migDB, e.openssl, e.v0286)
	if a.method != "distro_affected" || a.evidence.Fixed != "1.1.1n-0+deb11u4" ||
		a.evidence.Basis != "release" || a.evidence.Release != "Debian:11" || a.evidence.Installed != "1.1.1k-1" ||
		len(a.evidence.Records) == 0 || a.evidence.FetchedAt.IsZero() {
		t.Errorf("CVE-2023-0286 = %+v", a)
	}
	f := m70Read(t, e.migDB, e.openssl, e.v3449)
	if f.method != "distro_fixed" || f.evidence.Basis != "later_releases" || f.evidence.Fixed != "1.1.1k-1" ||
		f.evidence.Status != "fixed" || len(f.evidence.Ecosystems) == 0 {
		t.Errorf("CVE-2021-3449 = %+v", f)
	}
	// Label unchanged; only the watermark of the check is stored.
	if u := m70Read(t, e.migDB, e.openssl, e.vNoRec); u.method != "nvd_cpe_unverified" || u.evidence.Status != "" || u.evidence.DataModified == "" {
		t.Errorf("CVE-2009-0591 (no record) = %+v, want unchanged label with a watermark", u)
	}
	if p := m70Read(t, e.migDB, e.plain, e.v3449); p.method != "nvd_cpe" || p.hasEv {
		t.Errorf("the non-distro component's link was touched: %+v", p)
	}

	// The vulnerability list: CVE-2021-3449 is fixed for the Debian package
	// but still matched by the other component, so the CVE shows nvd_cpe,
	// not distro_fixed; CVE-2023-0286 shows distro_affected with evidence.
	var vulns []model.Vulnerability
	scope, _ := ScanScopeFrom(ctx)
	if err := scope.ReadTx(ctx, func(txCtx context.Context) error {
		var lerr error
		vulns, lerr = e.compRepo.GetVulnerabilities(txCtx, e.sbom, "")
		return lerr
	}); err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Vulnerability{}
	for _, v := range vulns {
		got[v.CVEID] = v
	}
	if v := got["CVE-2021-3449"]; v.MatchMethod != "nvd_cpe" || v.MatchConfidence != "high" || len(v.MatchEvidence) != 0 {
		t.Errorf("list CVE-2021-3449 = %q / %q / %s", v.MatchMethod, v.MatchConfidence, v.MatchEvidence)
	}
	if v := got["CVE-2023-0286"]; v.MatchMethod != "distro_affected" || v.MatchConfidence != "high" || len(v.MatchEvidence) == 0 {
		t.Errorf("list CVE-2023-0286 = %q / %q / %s", v.MatchMethod, v.MatchConfidence, v.MatchEvidence)
	}
	if v := got["CVE-2009-0591"]; v.MatchMethod != "nvd_cpe_unverified" || v.MatchConfidence != "low" || len(v.MatchEvidence) != 0 {
		t.Errorf("list CVE-2009-0591 = %q / %q / %s", v.MatchMethod, v.MatchConfidence, v.MatchEvidence)
	}

	// Drop the other component's link: the CVE is now ONLY "fixed by the
	// distro", and the list says so.
	if _, err := e.migDB.Exec(`DELETE FROM component_vulnerabilities WHERE component_id = $1`, e.plain); err != nil {
		t.Fatal(err)
	}
	if err := scope.ReadTx(ctx, func(txCtx context.Context) error {
		var lerr error
		vulns, lerr = e.compRepo.GetVulnerabilities(txCtx, e.sbom, "")
		return lerr
	}); err != nil {
		t.Fatal(err)
	}
	for _, v := range vulns {
		if v.CVEID == "CVE-2021-3449" && (v.MatchMethod != "distro_fixed" || v.MatchConfidence != "distro_fixed" || len(v.MatchEvidence) == 0) {
			t.Errorf("list CVE-2021-3449 alone = %q / %q / %s", v.MatchMethod, v.MatchConfidence, v.MatchEvidence)
		}
	}

	// A rescan with unchanged data changes no row.
	rep2, err := svc.ScanComponentsWithReport(ctx, e.sbom)
	if err != nil || rep2.Relabelled != 0 {
		t.Errorf("rescan: relabelled=%d err=%v", rep2.Relabelled, err)
	}
}

// The NVD sweep's writer can never take a distro label back down, and the
// distro step's rank rule keeps an "affected" finding from being cleared to
// "fixed" by a later scan.
func TestM70DistroScan_RankRule(t *testing.T) {
	e := m70Seed(t, "m70rank")
	// A previous scan found CVE-2021-3449 affected (a hypothetical data state).
	if _, err := e.migDB.Exec(`UPDATE component_vulnerabilities SET match_method = 'distro_affected',
		match_evidence = '{"source":"osv","status":"affected"}' WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v3449); err != nil {
		t.Fatal(err)
	}
	svc := m70Service(t, e, m70DebianReplay(t).start().URL, nil)
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	if _, err := svc.ScanComponentsWithReport(ctx, e.sbom); err != nil {
		t.Fatal(err)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v3449); r.method != "distro_affected" {
		t.Errorf("distro_affected was relabelled to %q", r.method)
	}
	// The NVD writer (LinkComponent) re-linking with a weaker method.
	vulnRepo := repository.NewVulnerabilityRepository(e.appDB)
	scope, _ := ScanScopeFrom(ctx)
	if err := scope.writeTx(ctx, e.sbom, func(txCtx context.Context) error {
		for _, v := range []uuid.UUID{e.v0286, e.v3449} {
			if err := vulnRepo.LinkComponent(txCtx, e.openssl, v, model.MatchNVDCPEDistro); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_affected" || !r.hasEv {
		t.Errorf("NVD writer downgraded distro_affected: %+v", r)
	}
}

// A data failure is a reason, and leaves every label as it was.
func TestM70DistroScan_DataFailureIsAReason(t *testing.T) {
	e := m70Seed(t, "m70fail")
	r := &replayOSV{t: t, fail: map[string]int{"Debian|openssl": http.StatusBadGateway}}
	svc := m70Service(t, e, r.start().URL, nil)
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	rep, err := svc.ScanComponentsWithReport(ctx, e.sbom)
	if err == nil {
		t.Fatal("a failed distro-data fetch returned nil")
	}
	if got := ScanReasons(err); len(got) != 1 || got[0] != ScanReasonDistroDataFailed {
		t.Errorf("reasons = %v, want [distro_data_failed]", got)
	}
	if rep.FetchFailures != 1 || rep.LinksKeptForFailure != 4 || rep.Relabelled != 0 {
		t.Errorf("report %+v", rep)
	}
	for _, v := range []uuid.UUID{e.v0286, e.v3449, e.v1292, e.vNoRec} {
		if row := m70Read(t, e.migDB, e.openssl, v); row.method != "nvd_cpe_unverified" || row.hasEv {
			t.Errorf("label changed after a failed fetch: %+v", row)
		}
	}
}

// Offline: no request, no relabel, no failure.
func TestM70DistroScan_Offline(t *testing.T) {
	e := m70Seed(t, "m70offline")
	r := m70DebianReplay(t)
	s := NewDistroService(e.compRepo, r.start().URL, nil, true)
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	if err := s.ScanComponents(ctx, e.sbom); err != nil {
		t.Fatal(err)
	}
	if got := r.requests(); len(got) != 0 {
		t.Errorf("offline made requests: %q", got)
	}
	if row := m70Read(t, e.migDB, e.openssl, e.v0286); row.method != "nvd_cpe_unverified" {
		t.Errorf("offline relabelled: %+v", row)
	}
}

// RelabelDistro never reaches another tenant's link, whatever id it is given.
func TestM70RelabelDistro_TenantBoundary(t *testing.T) {
	a := m70Seed(t, "m70tenantA")
	b := m70Seed(t, "m70tenantB")
	ctx := WithScanScope(context.Background(), a.appDB, a.tenant)
	scope, _ := ScanScopeFrom(ctx)
	changed := true
	if err := scope.writeTx(ctx, a.sbom, func(txCtx context.Context) error {
		var err error
		changed, err = a.compRepo.RelabelDistro(txCtx, b.openssl, b.v0286, model.MatchDistroFixed, []byte(`{"source":"osv"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("tenant A relabelled tenant B's link")
	}
	if row := m70Read(t, b.migDB, b.openssl, b.v0286); row.method != "nvd_cpe_unverified" {
		t.Errorf("tenant B's link = %+v", row)
	}
}

// With Redis: the second scan is served from the cache (no OSV request) and
// decides the same.
func TestM70DistroScan_RedisCache(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("redis: %v", err)
	}
	e := m70Seed(t, "m70cache")
	r := m70DebianReplay(t)
	srvURL := r.start().URL
	key := cache.DistroCacheKey(distroSource(srvURL), "Debian", "openssl")
	_ = rdb.Del(context.Background(), key).Err()
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })
	svc := m70Service(t, e, srvURL, cache.NewDistroCache(rdb))
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	rep1, err := svc.ScanComponentsWithReport(ctx, e.sbom)
	if err != nil {
		t.Fatal(err)
	}
	// Reset the labels and scan again: served from Redis.
	if _, err := e.migDB.Exec(`UPDATE component_vulnerabilities SET match_method = 'nvd_cpe_unverified', match_evidence = NULL WHERE component_id = $1`, e.openssl); err != nil {
		t.Fatal(err)
	}
	rep2, err := svc.ScanComponentsWithReport(ctx, e.sbom)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.requests(); len(got) != 1 {
		t.Errorf("OSV requests = %q, want 1 (the second scan from the cache)", got)
	}
	if rep2.CacheHits != 1 || rep2.Requests != 0 || rep2.Affected != rep1.Affected || rep2.Fixed != rep1.Fixed || rep2.Relabelled != 4 {
		t.Errorf("cold %+v / warm %+v", rep1, rep2)
	}
}

// Codex M70 R3 High-6: a CACHE HIT also waits for a process-wide slot.
func TestM70DistroLoad_CacheHitTakesASlot(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	r := m70DebianReplay(t)
	srvURL := r.start().URL
	key := cache.DistroCacheKey(distroSource(srvURL), "Debian", "openssl")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })
	s := NewDistroService(nil, srvURL, cache.NewDistroCache(rdb), false)
	s.gap = 0
	k := distroFetchKey{ecosystem: "Debian", pkg: "openssl"}
	if _, hit, _, err := s.load(context.Background(), k, s.pacer()); err != nil || hit {
		t.Fatalf("cold load: hit=%v err=%v", hit, err)
	}
	for i := 0; i < cap(distroQuerySlots); i++ {
		distroQuerySlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(distroQuerySlots); i++ {
			<-distroQuerySlots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if hit, _, err := s.loadSlotted(ctx, k, s.pacer(), func(distroLoad) error { return nil }); err == nil || hit {
		t.Errorf("a cache hit proceeded without a slot: hit=%v err=%v", hit, err)
	}
}

// Codex M70 R8 High-4: neither the database nor the cache lets older data
// replace newer data.
func TestM70DistroFreshness_DBAndCache(t *testing.T) {
	e := m70Seed(t, "m70fresh")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	write := func(ev string) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, func(txCtx context.Context) error {
			_, err := e.compRepo.RelabelDistro(txCtx, e.openssl, e.v0286, model.MatchDistroAffected, []byte(ev))
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"source":"osv","fixed":"v3","data_modified":"2026-11-09T00:00:00.000000000Z"}`)
	write(`{"source":"osv","fixed":"v2","data_modified":"2026-11-08T00:00:00.000000000Z"}`)
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.evidence.Fixed != "v3" {
		t.Errorf("older evidence replaced newer: %+v", r)
	}
	write(`{"source":"osv","fixed":"v4","data_modified":"2026-11-10T00:00:00.000000000Z"}`)
	// Cross-method: an older "affected" cannot replace a newer "fixed"
	// either (Codex M70 R10 Medium-2).
	if err := scope.writeTx(ctx, e.sbom, func(txCtx context.Context) error {
		_, err := e.compRepo.RelabelDistro(txCtx, e.openssl, e.v3449, model.MatchDistroFixed,
			[]byte(`{"source":"osv","fixed":"f","data_modified":"2026-11-10T00:00:00.000000000Z"}`))
		if err != nil {
			return err
		}
		_, err = e.compRepo.RelabelDistro(txCtx, e.openssl, e.v3449, model.MatchDistroAffected,
			[]byte(`{"source":"osv","fixed":"a","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v3449); r.method != "distro_fixed" {
		t.Errorf("an older affected replaced a newer fixed: %+v", r)
	}
	// Another endpoint (a mirror): its revisions are not comparable, the
	// rank rule decides (Codex M70 R11 High-1).
	if err := scope.writeTx(ctx, e.sbom, func(txCtx context.Context) error {
		_, err := e.compRepo.RelabelDistro(txCtx, e.openssl, e.v3449, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"mirror","fixed":"m","data_modified":"2026-01-01T00:00:00.000000000Z"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v3449); r.method != "distro_affected" || r.evidence.Fixed != "m" {
		t.Errorf("another endpoint's affected was blocked by an incomparable revision: %+v", r)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.evidence.Fixed != "v4" {
		t.Errorf("newer evidence not written: %+v", r)
	}

	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	c := cache.NewDistroCache(rdb)
	key := cache.DistroCacheKey("test-fresh", "Debian", "p")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })
	now := time.Now()
	set := func(gen string, payload string) {
		t.Helper()
		if _, err := c.Set(context.Background(), "test-fresh", "Debian", "p", cache.DistroCacheEntry{FetchedAt: now, Generation: gen, Payload: []byte(payload)}); err != nil {
			t.Fatal(err)
		}
	}
	g1, g2 := c.NextGeneration(context.Background()), c.NextGeneration(context.Background())
	if g1 == "" || g2 <= g1 {
		t.Fatalf("generations %q %q", g1, g2)
	}
	set(g2, `"new"`)
	set(g1, `"old"`)
	got, err := c.Get(context.Background(), "test-fresh", "Debian", "p")
	if err != nil || got == nil || string(got.Payload) != `"new"` {
		t.Errorf("cache = %+v, %v; want the newer payload", got, err)
	}
}

// Codex M70 R12 High-1: a stale distro label is cleared back to the method
// the link had before the distro step — only with data of the same endpoint
// that is at least as new.
func TestM70ClearDistro_RestoresPriorMethod(t *testing.T) {
	e := m70Seed(t, "m70clear")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	ev := `{"source":"osv","source_id":"A","data_modified":"2026-11-05T00:00:00.000000000Z"}`
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed, []byte(ev))
		return err
	})
	run(func(c context.Context) error { // fixed -> affected keeps the ORIGINAL prior method
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected, []byte(ev))
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_affected" {
		t.Fatalf("%+v", r)
	}
	for _, g := range []string{
		`{"source_id":"B","data_modified":"2026-11-09T00:00:00.000000000Z"}`, // another endpoint
		`{"source_id":"A","data_modified":"2026-11-01T00:00:00.000000000Z"}`, // older data
	} {
		run(func(c context.Context) error {
			_, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286, []byte(g))
			return err
		})
		// Another source's check is recorded in the watermark (R29 High-1),
		// but neither clears the label.
		if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_affected" {
			t.Errorf("cleared with guard %s: %+v", g, r)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286, []byte(`{"source_id":"A","data_modified":"2026-11-06T00:00:00.000000000Z"}`))
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "nvd_cpe_unverified" || r.evidence.Status != "" ||
		r.evidence.DataModified != "2026-11-06T00:00:00.000000000Z" {
		t.Errorf("after clear: %+v, want nvd_cpe_unverified with only the watermark", r)
	}
}

// Codex M70 R13 High-1 / Medium-4 / Medium-6 (database and cache).
func TestM70Watermark_AndPriorMethod(t *testing.T) {
	e := m70Seed(t, "m70wm")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	// A no-verdict check with NEWER data leaves its watermark; a delayed
	// scan with OLDER data cannot then label the link.
	run(func(c context.Context) error {
		_, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.vNoRec, []byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-09T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.vNoRec, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older data labelled a link a newer check had seen")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.vNoRec); r.method != "nvd_cpe_unverified" {
		t.Errorf("%+v", r)
	}
	// prior_method follows a stronger NVD method while the distro label stays.
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-05T00:00:00.000000000Z"}`))
		return err
	})
	vulnRepo := repository.NewVulnerabilityRepository(e.appDB)
	run(func(c context.Context) error {
		return vulnRepo.LinkComponent(c, e.openssl, e.v0286, model.MatchNVDCPEDistro)
	})
	var prior string
	if err := e.migDB.QueryRow(`SELECT match_method || '/' || (match_evidence->>'prior_method') FROM component_vulnerabilities
		WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v0286).Scan(&prior); err != nil {
		t.Fatal(err)
	}
	if prior != "distro_fixed/nvd_cpe_distro" {
		t.Errorf("method/prior = %q, want distro_fixed/nvd_cpe_distro", prior)
	}
	// A clear restores it and keeps the watermark: older data cannot relabel.
	run(func(c context.Context) error {
		_, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286, []byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-07T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-05T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older data re-labelled a cleared link")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "nvd_cpe_distro" || r.evidence.DataModified != "2026-11-07T00:00:00.000000000Z" {
		t.Errorf("after clear: %+v", r)
	}
}

// Codex M70 R14 High-4: LinkComponent's prior_method update never reaches
// another tenant's link.
func TestM70LinkComponent_PriorMethodTenantBoundary(t *testing.T) {
	a := m70Seed(t, "m70priorA")
	b := m70Seed(t, "m70priorB")
	ctxB := WithScanScope(context.Background(), b.appDB, b.tenant)
	scopeB, _ := ScanScopeFrom(ctxB)
	if err := scopeB.writeTx(ctxB, b.sbom, func(c context.Context) error {
		_, err := b.compRepo.RelabelDistro(c, b.openssl, b.v0286, model.MatchDistroFixed, []byte(`{"source":"osv"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctxA := WithScanScope(context.Background(), a.appDB, a.tenant)
	scopeA, _ := ScanScopeFrom(ctxA)
	vulnRepo := repository.NewVulnerabilityRepository(a.appDB)
	if err := scopeA.writeTx(ctxA, a.sbom, func(c context.Context) error {
		return vulnRepo.LinkComponent(c, b.openssl, b.v0286, model.MatchNVDCPE)
	}); err != nil {
		t.Fatal(err)
	}
	var prior string
	if err := b.migDB.QueryRow(`SELECT COALESCE(match_evidence->>'prior_method', '') FROM component_vulnerabilities
		WHERE component_id = $1 AND vulnerability_id = $2`, b.openssl, b.v0286).Scan(&prior); err != nil {
		t.Fatal(err)
	}
	if prior != "nvd_cpe_unverified" {
		t.Errorf("tenant A rewrote tenant B's prior_method to %q", prior)
	}
}

// Codex M70 R16 High-2: the cache never replaces a higher data revision with
// a lower one, whatever the generations; generation breaks ties only.
func TestM70DistroCache_RevisionBeforeGeneration(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	c := cache.NewDistroCache(rdb)
	key := cache.DistroCacheKey("test-rev", "Debian", "p")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key, key+":lg").Err() })
	_ = rdb.Del(context.Background(), key, key+":lg").Err()
	set := func(gen, dm, payload string) {
		t.Helper()
		if _, err := c.Set(context.Background(), "test-rev", "Debian", "p", cache.DistroCacheEntry{FetchedAt: time.Now(),
			Generation: gen, DataModified: dm, Payload: []byte(payload)}); err != nil {
			t.Fatal(err)
		}
	}
	get := func() string {
		t.Helper()
		e, err := c.Get(context.Background(), "test-rev", "Debian", "p")
		if err != nil || e == nil {
			t.Fatalf("get: %v %v", e, err)
		}
		return string(e.Payload)
	}
	set("00000000000000000001", "2026-11-09T00:00:00.000000000Z", `"R2"`)
	set("00000000000000000002", "2026-11-08T00:00:00.000000000Z", `"R1-later-fetch"`) // later fetch, older data
	// A completed lower-revision observation drops the kept payload (Codex
	// M70 R43 High-1, R49 High-1): it is never replaced by the lower one,
	// and the package is read again.
	raw, _ := rdb.Get(context.Background(), key).Result()
	if strings.Contains(raw, `"R1-later-fetch"`) {
		t.Errorf("older revision replaced newer: %s", raw)
	}
	if e, err := c.Get(context.Background(), "test-rev", "Debian", "p"); err != nil || e != nil {
		t.Errorf("superseded entry served: %+v %v", e, err)
	}
	set("00000000000000000003", "2026-11-09T00:00:00.000000000Z", `"R2-again"`) // same revision, later fetch
	if got := get(); got != `"R2-again"` {
		t.Errorf("equal revision, later generation not written: %s", got)
	}
	set("00000000000000000001", "2026-11-09T00:00:00.000000000Z", `"R2-old-gen"`)
	if got := get(); got != `"R2-again"` {
		t.Errorf("equal revision, earlier generation overwrote: %s", got)
	}
}

// Codex M70 R17 High-1: a write refused by the rank rule still advances the
// link's watermark, so an overlapping scan holding OLDER data cannot clear
// the label afterwards: affected@R1 -> fixed@R3 refused -> clear@R2 refused.
func TestM70Watermark_AdvancesWhenRankRefuses(t *testing.T) {
	e := m70Seed(t, "m70wmrank")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"r1","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	})
	// Rank refuses across sources (R41: within one source, newer data
	// replaces); the refused check still advances THAT source's watermark.
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"T","fixed":"r3","data_modified":"2026-11-03T00:00:00.000000000Z"}`))
		if changed {
			t.Error("rank allowed affected -> fixed across sources")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"T","fixed":"t2","data_modified":"2026-11-02T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older data of T went through after T's newer check")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_affected" || r.evidence.Fixed != "r1" {
		t.Errorf("%+v", r)
	}
}

// Codex M70 R21 High-1: a fetch that LOSES the cache race uses the winner.
func TestM70DistroLoad_LoserUsesTheWinner(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	r := m70DebianReplay(t)
	srvURL := r.start().URL
	dc := cache.NewDistroCache(rdb)
	s := NewDistroService(nil, srvURL, dc, false)
	s.gap = 0
	key := cache.DistroCacheKey(s.sourceID, "Debian", "openssl")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })
	// A winner with a NEWER revision is already cached, as if another scan
	// stored it while this one was fetching.
	winner := distroCachePayload{Version: distroCachePayloadVersion, Records: []distroRecord{{ID: "DSA-WIN", CVEs: []string{"CVE-2021-0001"},
		Releases: 1, Packages: 1, Modified: normaliseModified("2026-11-08T00:00:00Z"), Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "9.9-1")}}}, IDs: []string{"DSA-WIN"}}
	raw, _ := json.Marshal(winner)
	// The fetched data's own revision: the winner has the SAME revision and
	// a later generation (a fetch that started later), so it is kept and
	// the loser uses it. (A winner of a HIGHER revision is dropped by the
	// lower observation instead, R49 High-1: see below.)
	first, _, _, err := s.loadFetch(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dc.Set(context.Background(), s.sourceID, "Debian", "openssl", cache.DistroCacheEntry{FetchedAt: time.Now(),
		Payload: raw, DataModified: first.revision, Generation: "99999999999999999999"}); err != nil {
		t.Fatal(err)
	}
	// Bypass the read of the cache for this load so it fetches and loses.
	l, hit, _, err := s.loadFetch(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer())
	if err != nil || len(l.recs) != 1 || l.recs[0].ID != "DSA-WIN" || hit {
		t.Errorf("loser did not use the winner: err=%v hit=%v %d records", err, hit, len(l.recs))
	}
	// A winner of a higher revision: this lower observation drops it and
	// uses its own complete answer.
	if _, err := dc.Set(context.Background(), s.sourceID, "Debian", "openssl", cache.DistroCacheEntry{FetchedAt: time.Now(),
		Payload: raw, DataModified: "2099-01-01T00:00:00.000000000Z", Generation: "99999999999999999999"}); err != nil {
		t.Fatal(err)
	}
	l, _, _, err = s.loadFetch(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer())
	if err != nil || len(l.recs) == 1 {
		t.Errorf("higher-revision winner used: err=%v %d records", err, len(l.recs))
	}
}

// Codex M70 R22 High-1: the no-verdict settlement decides on the row as it
// is when written: a distro label written by an older scan in between is
// cleared, a non-distro link gets the watermark.
func TestM70SettleNoVerdict_IsStateAdaptive(t *testing.T) {
	e := m70Seed(t, "m70settle")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	// An older scan labels the link after a newer scan read it as non-distro.
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-05T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("the newer no-verdict did not settle the link")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "nvd_cpe_unverified" || r.evidence.Status != "" {
		t.Errorf("%+v, want the older distro label cleared", r)
	}
}

// Codex M70 R27 Medium-3: a rank-refused check from ANOTHER source moves the
// watermark but not the label's support; that source's no-verdict cannot
// clear the label.
func TestM70Settle_OtherSourceCannotClear(t *testing.T) {
	e := m70Seed(t, "m70othersrc")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"A","fixed":"r1","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"B","fixed":"r3","data_modified":"2026-11-03T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		_, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286,
			[]byte(`{"source":"osv","source_id":"B","data_modified":"2026-11-04T00:00:00.000000000Z"}`))
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_affected" || r.evidence.Fixed != "r1" {
		t.Errorf("%+v", r)
	}
}

// Codex M70 R24/R27: ClearDistroWithdrawn clears only a row resting on
// exactly the given records and watermark, and keeps the watermark.
func TestM70ClearDistroWithdrawn(t *testing.T) {
	e := m70Seed(t, "m70wdclear")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	const rev = "2026-11-05T00:00:00.000000000Z"
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","records":["A"],"data_modified":"`+rev+`"}`))
		return err
	})
	for _, p := range []string{
		`{"source_id":"S","records":["B"],"tombstones":{"B":"` + rev + `"},"wm_rev":"` + rev + `"}`,                    // other records
		`{"source_id":"T","records":["A"],"tombstones":{"A":"` + rev + `"},"wm_rev":"` + rev + `"}`,                    // other source
		`{"source_id":"S","records":["A"],"tombstones":{"A":"` + rev + `"},"wm_rev":"2026-11-04T00:00:00.000000000Z"}`, // watermark moved
		`{"source_id":"S","records":[],"tombstones":{},"wm_rev":"` + rev + `"}`,
	} {
		run(func(c context.Context) error {
			changed, err := e.compRepo.ClearDistroWithdrawn(c, e.openssl, e.v0286, []byte(p))
			if changed {
				t.Errorf("%s cleared", p)
			}
			return err
		})
	}
	run(func(c context.Context) error {
		changed, err := e.compRepo.ClearDistroWithdrawn(c, e.openssl, e.v0286, []byte(`{"source_id":"S","records":["A"],"tombstones":{"A":"`+rev+`"},"wm_rev":"`+rev+`"}`))
		if !changed {
			t.Error("exact withdrawn clear refused")
		}
		return err
	})
	var method sql.NullString
	var wmSrc, wmRev string
	if err := e.migDB.QueryRow(`SELECT match_method, match_evidence->>'wm_source', match_evidence->>'wm_rev' FROM component_vulnerabilities
		WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v0286).Scan(&method, &wmSrc, &wmRev); err != nil {
		t.Fatal(err)
	}
	if method.String != "nvd_cpe_unverified" || wmSrc != "S" || wmRev != rev {
		t.Errorf("method=%q wm=%s/%s, want the prior method and the kept watermark", method.String, wmSrc, wmRev)
	}
	// An older scan can no longer relabel it.
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","records":["A"],"data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older data relabelled after the withdrawn clear")
		}
		return err
	})
}

// Codex M70 R28 High-1: the watermark is kept per source; a write from
// source B does not erase source A's, so an overlapping A scan with older
// data is still refused.
func TestM70Watermark_PerSource(t *testing.T) {
	e := m70Seed(t, "m70wmsrc")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"A","fixed":"a10","data_modified":"2026-11-10T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"B","fixed":"b","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"A","fixed":"a5","data_modified":"2026-11-05T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older source-A data relabelled after a source-B write")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_fixed" || r.evidence.Fixed != "b" {
		t.Errorf("%+v", r)
	}
	// Newer A data still goes through.
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"A","fixed":"a11","data_modified":"2026-11-11T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("newer source-A data refused")
		}
		return err
	})
}

// Codex M70 R29 High-1: a no-verdict from source B under a label of source
// A records B's revision, so a delayed older B scan cannot relabel.
func TestM70Settle_OtherSourceAdvancesItsWatermark(t *testing.T) {
	e := m70Seed(t, "m70othwm")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"A","fixed":"a","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286,
			[]byte(`{"source":"osv","source_id":"B","data_modified":"2026-11-20T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("B's check was not recorded")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_fixed" || r.evidence.Fixed != "a" {
		t.Errorf("%+v, want A's label kept", r)
	}
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"B","fixed":"b10","data_modified":"2026-11-10T00:00:00.000000000Z"}`))
		if changed {
			t.Error("older B data relabelled after B's newer no-verdict")
		}
		return err
	})
}

// Codex M70 R29 High-2: a withdrawn clear leaves tombstones; a delayed scan
// whose evidence cites the withdrawn record cannot bring the label back,
// while evidence on other records still can.
func TestM70ClearDistroWithdrawn_Tombstones(t *testing.T) {
	e := m70Seed(t, "m70tomb")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	const rev = "2026-11-05T00:00:00.000000000Z"
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"r","records":["R"],"data_modified":"`+rev+`"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.ClearDistroWithdrawn(c, e.openssl, e.v0286, []byte(`{"source_id":"S","records":["R"],"tombstones":{"R":"`+rev+`"},"wm_rev":"`+rev+`"}`))
		if !changed {
			t.Error("withdrawn clear refused")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"r","records":["R"],"data_modified":"`+rev+`"}`))
		if changed {
			t.Error("the withdrawn record's label came back")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"q","records":["Q"],"data_modified":"`+rev+`"}`))
		if !changed {
			t.Error("evidence on another record refused")
		}
		return err
	})
	// The tombstone survives the relabel.
	var tomb string
	if err := e.migDB.QueryRow(`SELECT COALESCE(match_evidence->'withdrawn_by_source'->>'S', '') FROM component_vulnerabilities
		WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v0286).Scan(&tomb); err != nil {
		t.Fatal(err)
	}
	if tomb != `{"R": "`+rev+`"}` {
		t.Errorf("tombstones %q", tomb)
	}
	// Data from after the change (the record restored) is not blocked.
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"r2","records":["R"],"data_modified":"2026-11-09T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("newer evidence on the restored record refused")
		}
		return err
	})
}

// Codex M70 R32 Medium-3: the prior-method promotion never waits for a row
// another transaction holds.
func TestM70PromotePriorMethod_SkipsLockedRows(t *testing.T) {
	e := m70Seed(t, "m70skiplock")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	if err := scope.writeTx(ctx, e.sbom, func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	holder, err := e.migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`SELECT 1 FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2 FOR UPDATE`, e.openssl, e.v0286); err != nil {
		t.Fatal(err)
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := time.Now()
	if err := scope.writeTx(wctx, e.sbom, func(c context.Context) error {
		tx, _ := database.TxFromContext(c)
		return repository.PromoteDistroPriorMethod(c, tx, e.openssl, e.v0286, model.MatchNVDCPE)
	}); err != nil {
		t.Fatalf("promotion: %v", err)
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Errorf("promotion waited %v for a locked row", d)
	}
}

// Codex M70 R37 High-1: ReplaceDistroWithdrawn sets the current verdict over
// a stronger label whose records were withdrawn, only on the exact row read.
func TestM70ReplaceDistroWithdrawn(t *testing.T) {
	e := m70Seed(t, "m70replwd")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	const rev = "2026-11-05T00:00:00.000000000Z"
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"a","records":["A","B"],"data_modified":"`+rev+`"}`))
		return err
	})
	fixedEv := []byte(`{"source":"osv","source_id":"S","status":"fixed","fixed":"b","records":["B"],"data_modified":"2026-11-01T00:00:00.000000000Z"}`)
	run(func(c context.Context) error {
		changed, err := e.compRepo.ReplaceDistroWithdrawn(c, e.openssl, e.v0286, model.MatchDistroFixed, fixedEv,
			[]byte(`{"source_id":"S","records":["A"],"tombstones":{"A":"`+rev+`"},"wm_rev":"`+rev+`","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		if changed {
			t.Error("replaced with the wrong record list")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.ReplaceDistroWithdrawn(c, e.openssl, e.v0286, model.MatchDistroFixed, fixedEv,
			[]byte(`{"source_id":"S","records":["A","B"],"tombstones":{"A":"2026-11-06T00:00:00.000000000Z"},"wm_rev":"`+rev+`","data_modified":"2026-11-01T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("exact withdrawn replace refused")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_fixed" || r.evidence.Fixed != "b" {
		t.Errorf("%+v", r)
	}
	var prior, wm, tomb string
	if err := e.migDB.QueryRow(`SELECT COALESCE(match_evidence->>'prior_method',''), match_evidence->'wm_by_source'->>'S', match_evidence->'withdrawn_by_source'->'S'->>'A'
		FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v0286).Scan(&prior, &wm, &tomb); err != nil {
		t.Fatal(err)
	}
	if prior != "nvd_cpe_unverified" || wm != rev || tomb != "2026-11-06T00:00:00.000000000Z" {
		t.Errorf("prior=%q wm=%q tomb=%q", prior, wm, tomb)
	}
}

// Codex M70 R38 Medium-1: a distro label without its evidence object is
// refused by the database, and the generic linker never writes one.
func TestM70DistroLabelNeedsEvidence(t *testing.T) {
	e := m70Seed(t, "m70needev")
	if _, err := e.migDB.Exec(`UPDATE component_vulnerabilities SET match_method = 'distro_affected', match_evidence = NULL
		WHERE component_id = $1 AND vulnerability_id = $2`, e.openssl, e.v0286); err == nil {
		t.Error("a distro label without evidence was stored")
	}
	if err := repository.NewVulnerabilityRepository(e.appDB).LinkComponent(context.Background(), e.openssl, e.v0286, model.MatchDistroAffected); err == nil {
		t.Error("LinkComponent accepted a distro method")
	}
}

// Codex M70 R39 High-1: the distro writer never waits on a row another
// transaction holds; the row is left for the next scan and counted.
func TestM70LockDistroLink_NoWait(t *testing.T) {
	e := m70Seed(t, "m70nowait")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	holder, err := e.migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`SELECT 1 FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2 FOR UPDATE`, e.openssl, e.v0286); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := scope.writeTx(ctx, e.sbom, func(c context.Context) error {
		if _, ok, err := e.compRepo.LockDistroLink(c, e.openssl, e.v0286); err != nil || ok {
			t.Errorf("locked a held row: ok=%v err=%v", ok, err)
		}
		m, ok, err := e.compRepo.LockDistroLink(c, e.openssl, e.v3449)
		if err != nil || !ok || m != "nvd_cpe_unverified" {
			t.Errorf("free row: %q ok=%v err=%v", m, ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Errorf("waited %v", d)
	}
}

// Codex M70 R41 High-1: strictly newer data of the label's own source
// replaces it whatever the rank; equal-revision data does not.
func TestM70RelabelDistro_SameSourceNewerReplaces(t *testing.T) {
	e := m70Seed(t, "m70samesrc")
	ctx := WithScanScope(context.Background(), e.appDB, e.tenant)
	scope, _ := ScanScopeFrom(ctx)
	run := func(fn func(txCtx context.Context) error) {
		t.Helper()
		if err := scope.writeTx(ctx, e.sbom, fn); err != nil {
			t.Fatal(err)
		}
	}
	run(func(c context.Context) error {
		_, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroAffected,
			[]byte(`{"source":"osv","source_id":"S","fixed":"a","data_modified":"2026-11-10T00:00:00.000000000Z"}`))
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","fixed":"same","data_modified":"2026-11-10T00:00:00.000000000Z"}`))
		if changed {
			t.Error("equal-revision fixed replaced affected")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","fixed":"newer","data_modified":"2026-11-11T00:00:00.000000000Z"}`))
		if !changed {
			t.Error("newer same-source fixed did not replace affected")
		}
		return err
	})
	if r := m70Read(t, e.migDB, e.openssl, e.v0286); r.method != "distro_fixed" || r.evidence.Fixed != "newer" {
		t.Errorf("%+v", r)
	}
}

// Codex M70 R43 High-1: a pre-withdrawal answer cached by an OLDER fetch is
// not used once a newer fetch completed with the record gone: that fetch
// uses its own answer, and later loads read the package again.
func TestM70DistroLoad_NewerObservationBeatsOlderCachedRevision(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	queries := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries++
		_, _ = io.WriteString(w, `{}`) // the record is gone
	}))
	t.Cleanup(srv.Close)
	dc := cache.NewDistroCache(rdb)
	s := NewDistroService(nil, srv.URL, dc, false)
	s.gap = 0
	key := cache.DistroCacheKey(s.sourceID, "Debian", "p")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key, key+":lg").Err() })
	_ = rdb.Del(context.Background(), key, key+":lg").Err()
	old := distroCachePayload{Version: distroCachePayloadVersion, Records: []distroRecord{{ID: "DSA-OLD", CVEs: []string{"CVE-2021-0001"},
		Releases: 1, Packages: 1, Modified: normaliseModified("2026-11-08T00:00:00Z"), Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "0.9-1")}}}, IDs: []string{"DSA-OLD"}}
	raw, _ := json.Marshal(old)
	if _, err := dc.Set(context.Background(), s.sourceID, "Debian", "p", cache.DistroCacheEntry{FetchedAt: time.Now(),
		Payload: raw, DataModified: "2026-11-08T00:00:00.000000000Z", Generation: "00000000000000000001"}); err != nil {
		t.Fatal(err)
	}
	pace := func(context.Context) error { return nil }
	k := distroFetchKey{ecosystem: "Debian", pkg: "p"}
	l, _, _, err := s.loadFetch(context.Background(), k, pace)
	if err != nil || len(l.recs) != 0 {
		t.Fatalf("newer fetch: %d records, err=%v; want its own empty answer", len(l.recs), err)
	}
	if _, hit, _, err := s.load(context.Background(), k, pace); err != nil || hit || queries != 2 {
		t.Errorf("hit=%v queries=%d err=%v; the superseded entry must not be served", hit, queries, err)
	}
}

// Codex M70 R44 High-1: without its generation fence an entry is a miss.
func TestM70DistroCache_MissingFenceIsAMiss(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	c := cache.NewDistroCache(rdb)
	key := cache.DistroCacheKey("test-fence", "Debian", "p")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key, key+":lg").Err() })
	if _, err := c.Set(context.Background(), "test-fence", "Debian", "p", cache.DistroCacheEntry{FetchedAt: time.Now(),
		Generation: "00000000000000000005", DataModified: "2026-11-09T00:00:00.000000000Z", Payload: []byte(`"x"`)}); err != nil {
		t.Fatal(err)
	}
	if e, _ := c.Get(context.Background(), "test-fence", "Debian", "p"); e == nil {
		t.Fatal("fresh entry not served")
	}
	ttlP, _ := rdb.PTTL(context.Background(), key).Result()
	ttlF, _ := rdb.PTTL(context.Background(), key+":lg").Result()
	if ttlF < ttlP-time.Second {
		t.Errorf("fence ttl %v shorter than payload %v", ttlF, ttlP)
	}
	_ = rdb.Del(context.Background(), key+":lg").Err()
	if e, err := c.Get(context.Background(), "test-fence", "Debian", "p"); e != nil || err != nil {
		t.Errorf("entry without fence served: %+v %v", e, err)
	}
}

// Codex M70 R49 High-1: a completed lower-revision observation drops the
// kept payload whatever the fetch order.
func TestM70DistroCache_LowerRevisionInvalidates(t *testing.T) {
	url := os.Getenv("REDIS_URL")
	if url == "" {
		t.Skip("REDIS_URL not set")
	}
	opt, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opt)
	t.Cleanup(func() { _ = rdb.Close() })
	c := cache.NewDistroCache(rdb)
	key := cache.DistroCacheKey("test-inval", "Debian", "p")
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key, key+":lg").Err() })
	_ = rdb.Del(context.Background(), key, key+":lg").Err()
	set := func(gen, dm string) bool {
		won, err := c.Set(context.Background(), "test-inval", "Debian", "p", cache.DistroCacheEntry{FetchedAt: time.Now(),
			Generation: gen, DataModified: dm, Payload: []byte(`"x"`)})
		if err != nil {
			t.Fatal(err)
		}
		return won
	}
	set("00000000000000000002", "2026-11-09T00:00:00.000000000Z") // B: started later, pre-withdrawal
	if set("00000000000000000001", "") {                          // A: started earlier, saw the withdrawal
		t.Error("lower revision won")
	}
	if e, _ := c.Get(context.Background(), "test-inval", "Debian", "p"); e != nil {
		t.Error("the pre-withdrawal payload is still served")
	}
}
