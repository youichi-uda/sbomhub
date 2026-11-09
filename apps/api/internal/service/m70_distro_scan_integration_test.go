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
	v3711, v3449   uuid.UUID
	v0778, vNoRec  uuid.UUID
	compRepo       *repository.ComponentRepository
}

// m70Seed: an SBOM with Debian 11 openssl 1.1.1k-1 (Syft's purl) and a
// non-distro component, linked as M60 would have linked them.
//
//	openssl -> CVE-2021-3711 (DSA-4963-1: fixed in bullseye at 1.1.1k-1+deb11u1 -> affected)
//	openssl -> CVE-2021-3449 (DEBIAN-CVE: Debian 12/13/14 fixed at 1.1.1k-1 -> fixed, later_releases)
//	openssl -> CVE-2022-0778 (DSA-5103-1: fixed in bullseye at 1.1.1k-1+deb11u2 -> affected)
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
	e.v3711 = m70Vuln(t, e.migDB, "CVE-2021-3711")
	e.v3449 = m70Vuln(t, e.migDB, "CVE-2021-3449")
	e.v0778 = m70Vuln(t, e.migDB, "CVE-2022-0778")
	e.vNoRec = m70Vuln(t, e.migDB, "CVE-2009-0591")
	for _, v := range []uuid.UUID{e.v3711, e.v3449, e.v0778, e.vNoRec} {
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
	if rep.Affected != 2 || rep.Fixed != 1 || rep.Unfixed != 0 || rep.Relabelled != 3 || rep.Targeted != 1 || rep.Packages != 1 {
		t.Errorf("report %+v", rep)
	}

	a := m70Read(t, e.migDB, e.openssl, e.v3711)
	if a.method != "distro_affected" || a.evidence.Fixed != "1.1.1k-1+deb11u1" ||
		a.evidence.Basis != "release" || a.evidence.Release != "Debian:11" || a.evidence.Installed != "1.1.1k-1" ||
		len(a.evidence.Records) == 0 || a.evidence.FetchedAt.IsZero() {
		t.Errorf("CVE-2021-3711 = %+v", a)
	}
	f := m70Read(t, e.migDB, e.openssl, e.v3449)
	if f.method != "distro_fixed" || f.evidence.Basis != "later_releases" || f.evidence.Fixed != "1.1.1k-1" ||
		f.evidence.Status != "fixed" || len(f.evidence.Ecosystems) == 0 {
		t.Errorf("CVE-2021-3449 = %+v", f)
	}
	if u := m70Read(t, e.migDB, e.openssl, e.vNoRec); u.method != "nvd_cpe_unverified" || u.hasEv {
		t.Errorf("CVE-2009-0591 (no record) = %+v, want unchanged", u)
	}
	if p := m70Read(t, e.migDB, e.plain, e.v3449); p.method != "nvd_cpe" || p.hasEv {
		t.Errorf("the non-distro component's link was touched: %+v", p)
	}

	// The vulnerability list: CVE-2021-3449 is fixed for the Debian package
	// but still matched by the other component, so the CVE shows nvd_cpe,
	// not distro_fixed; CVE-2021-3711 shows distro_affected with evidence.
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
	if v := got["CVE-2021-3711"]; v.MatchMethod != "distro_affected" || v.MatchConfidence != "high" || len(v.MatchEvidence) == 0 {
		t.Errorf("list CVE-2021-3711 = %q / %q / %s", v.MatchMethod, v.MatchConfidence, v.MatchEvidence)
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
		for _, v := range []uuid.UUID{e.v3711, e.v3449} {
			if err := vulnRepo.LinkComponent(txCtx, e.openssl, v, model.MatchNVDCPEDistro); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if r := m70Read(t, e.migDB, e.openssl, e.v3711); r.method != "distro_affected" || !r.hasEv {
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
	for _, v := range []uuid.UUID{e.v3711, e.v3449, e.v0778, e.vNoRec} {
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
	if row := m70Read(t, e.migDB, e.openssl, e.v3711); row.method != "nvd_cpe_unverified" {
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
		changed, err = a.compRepo.RelabelDistro(txCtx, b.openssl, b.v3711, model.MatchDistroFixed, []byte(`{"source":"osv"}`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("tenant A relabelled tenant B's link")
	}
	if row := m70Read(t, b.migDB, b.openssl, b.v3711); row.method != "nvd_cpe_unverified" {
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
	if rep2.CacheHits != 1 || rep2.Requests != 0 || rep2.Affected != rep1.Affected || rep2.Fixed != rep1.Fixed || rep2.Relabelled != 3 {
		t.Errorf("cold %+v / warm %+v", rep1, rep2)
	}
}
