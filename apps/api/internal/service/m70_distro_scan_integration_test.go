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
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/sbomhub/sbomhub/internal/cache"
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
			changed, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286, []byte(g))
			if changed {
				t.Errorf("cleared with guard %s", g)
			}
			return err
		})
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
	t.Cleanup(func() { _ = rdb.Del(context.Background(), key).Err() })
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
	if got := get(); got != `"R2"` {
		t.Errorf("older revision replaced newer: %s", got)
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
	run(func(c context.Context) error {
		changed, err := e.compRepo.RelabelDistro(c, e.openssl, e.v0286, model.MatchDistroFixed,
			[]byte(`{"source":"osv","source_id":"S","fixed":"r3","data_modified":"2026-11-03T00:00:00.000000000Z"}`))
		if changed {
			t.Error("rank allowed affected -> fixed")
		}
		return err
	})
	run(func(c context.Context) error {
		changed, err := e.compRepo.SettleDistroNoVerdict(c, e.openssl, e.v0286,
			[]byte(`{"source":"osv","source_id":"S","data_modified":"2026-11-02T00:00:00.000000000Z"}`))
		if changed {
			t.Error("an older clear went through after newer data was processed")
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
		Releases: 1, Packages: 1, Modified: normaliseModified("2026-11-08T00:00:00Z"), Entries: []distroEntry{entry("Debian:11", "i", "0", "f", "9.9-1")}}}}
	raw, _ := json.Marshal(winner)
	if _, err := dc.Set(context.Background(), s.sourceID, "Debian", "openssl", cache.DistroCacheEntry{FetchedAt: time.Now(),
		Payload: raw, DataModified: "2026-11-08T12:00:00.000000000Z", Generation: "99999999999999999999"}); err != nil {
		t.Fatal(err)
	}
	// Bypass the read of the cache for this load so it fetches and loses.
	l, hit, _, err := s.loadFetch(context.Background(), distroFetchKey{ecosystem: "Debian", pkg: "openssl"}, s.pacer())
	if err != nil || len(l.recs) != 1 || l.recs[0].ID != "DSA-WIN" || hit {
		t.Errorf("loser did not use the winner: err=%v hit=%v %d records", err, hit, len(l.recs))
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
