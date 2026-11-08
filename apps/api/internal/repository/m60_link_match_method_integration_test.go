//go:build integration

// Package repository — M60: component_vulnerabilities.match_method and
// components.cpes (migration 067).
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M60' ./internal/repository
package repository

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/model"
)

// The relabel rule: a link's method only ever moves to a STRICTLY stronger
// one, whatever order the scanners write it in, and a pre-M60 (NULL) link is
// labelled by the first scan that reproduces it.
func TestM60LinkComponent_RelabelsOnlyUpward(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	v := m57ScannerVuln(t, migDB, m55MetaCVEID())
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(context.Background(), v); err != nil {
		t.Fatalf("create: %v", err)
	}

	// A pre-M60 link: written without a method.
	{
		tx, _, commit := m57OpenTenantTx(t, appDB, tenantID)
		if _, err := tx.Exec(`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
			componentID, v.ID); err != nil {
			t.Fatalf("legacy link: %v", err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}

	read := func() string {
		t.Helper()
		var m *string
		if err := migDB.QueryRow(`SELECT match_method FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`,
			componentID, v.ID).Scan(&m); err != nil {
			t.Fatalf("read method: %v", err)
		}
		if m == nil {
			return "<NULL>"
		}
		return *m
	}
	if got := read(); got != "<NULL>" {
		t.Fatalf("legacy link method = %s", got)
	}

	steps := []struct {
		write model.MatchMethod
		want  string
	}{
		{model.MatchJVNKeyword, "jvn_keyword"},      // NULL (unknown) -> labelled
		{model.MatchNVDKeyword, "jvn_keyword"},      // same rank: first label stays
		{model.MatchNVDCPEDistro, "nvd_cpe_distro"}, // stronger
		{model.MatchNVDCPE, "nvd_cpe"},              // stronger still
		{model.MatchJVNKeyword, "nvd_cpe"},          // JVN after NVD never downgrades
		{model.MatchCVESyncKeyword, "nvd_cpe"},
		{model.MatchNVDCPEDistro, "nvd_cpe"},
	}
	for i, st := range steps {
		_, ctx, commit := m57OpenTenantTx(t, appDB, tenantID)
		if err := repo.LinkComponent(ctx, componentID, v.ID, st.write); err != nil {
			t.Fatalf("step %d LinkComponent(%s): %v", i, st.write, err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
		if got := read(); got != st.want {
			t.Errorf("step %d: after writing %s the stored method is %s, want %s", i, st.write, got, st.want)
		}
	}

	var n int
	if err := migDB.QueryRow(`SELECT COUNT(*) FROM component_vulnerabilities WHERE component_id = $1`, componentID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("link rows = %d, want 1 (relabelling must not duplicate)", n)
	}

	// The per-SBOM list projects the stored method (real SQL, not a mock).
	tx, ctx, commit := m57OpenTenantTx(t, appDB, tenantID)
	var sbomID uuid.UUID
	if err := tx.QueryRow(`SELECT sbom_id FROM components WHERE id = $1`, componentID).Scan(&sbomID); err != nil {
		t.Fatal(err)
	}
	for _, list := range []func() ([]model.Vulnerability, error){
		func() ([]model.Vulnerability, error) {
			return NewComponentRepository(appDB).GetVulnerabilities(ctx, sbomID, "cvss")
		},
		func() ([]model.Vulnerability, error) {
			return NewComponentRepository(appDB).GetVulnerabilitiesPaginated(ctx, sbomID, 10, 0, "cvss")
		},
	} {
		vs, err := list()
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(vs) != 1 || vs[0].MatchMethod != "nvd_cpe" || vs[0].MatchConfidence != "high" {
			t.Errorf("list projection = %+v, want one row nvd_cpe/high", vs)
		}
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
}

// A fresh link carries its method; an invalid method is refused before any
// statement (so it cannot poison the scanner's tenant transaction) and the
// CHECK refuses one written by any other path.
func TestM60LinkComponent_WritesMethodAndRefusesUnknownOnes(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	v := m57ScannerVuln(t, migDB, m55MetaCVEID())
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	tx, ctx, commit := m57OpenTenantTx(t, appDB, tenantID)
	if err := repo.LinkComponent(ctx, componentID, v.ID, "bogus"); !errors.Is(err, ErrInvalidMatchMethod) {
		t.Fatalf("invalid method: err = %v, want ErrInvalidMatchMethod", err)
	}
	// The tx is still usable: nothing was sent.
	if err := repo.LinkComponent(ctx, componentID, v.ID, model.MatchNVDCPE); err != nil {
		t.Fatalf("link after a refused method: %v (the refusal reached the database)", err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	_ = tx
	var m string
	if err := migDB.QueryRow(`SELECT match_method FROM component_vulnerabilities WHERE component_id = $1`, componentID).Scan(&m); err != nil {
		t.Fatal(err)
	}
	if m != "nvd_cpe" {
		t.Errorf("method = %q, want nvd_cpe", m)
	}

	// The CHECK (braces) for writers that bypass the repository.
	if _, err := migDB.Exec(`UPDATE component_vulnerabilities SET match_method = 'bogus' WHERE component_id = $1`, componentID); err == nil {
		t.Errorf("CHECK accepted match_method = 'bogus'")
	}
}

// Writing an existing link with a weaker-or-equal method must not LOCK the
// row: the scanner's tenant transaction stays open for the whole sweep, and
// the CVE-sync linker (or another tenant tx) touching the same row would
// otherwise wait behind it. `ON CONFLICT DO UPDATE ... WHERE false` would
// lock it; this statement must not.
func TestM60LinkComponent_NoRowLockWhenNothingIsRelabelled(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	v := m57ScannerVuln(t, migDB, m55MetaCVEID())
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	{
		_, ctx, commit := m57OpenTenantTx(t, appDB, tenantID)
		if err := repo.LinkComponent(ctx, componentID, v.ID, model.MatchNVDCPE); err != nil {
			t.Fatal(err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}

	// Sweep A re-links with a weaker method and keeps its tx open.
	_, ctxA, _ := m57OpenTenantTx(t, appDB, tenantID)
	if err := repo.LinkComponent(ctxA, componentID, v.ID, model.MatchJVNKeyword); err != nil {
		t.Fatal(err)
	}

	// Another writer must get the row immediately.
	txB, err := migDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = txB.Rollback() }()
	if _, err := txB.Exec(`SET LOCAL lock_timeout = '500ms'`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := txB.Exec(`UPDATE component_vulnerabilities SET detected_at = NOW() WHERE component_id = $1 AND vulnerability_id = $2`,
		componentID, v.ID); err != nil {
		t.Errorf("concurrent writer blocked by a no-op relabel (%v after %s): the statement locked the row", err, time.Since(start))
	}
}

// components.cpes round-trips in order, and "no CPEs" is NULL, not '{}'.
func TestM60ComponentCPEs_RoundTrip(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, seeded := m54SeedComponentForLink(t, migDB)
	// components FORCEs RLS, for the migrator role too: read inside a tenant tx.
	var sbomID uuid.UUID
	{
		tx, _, commit := m57OpenTenantTx(t, appDB, tenantID)
		if err := tx.QueryRow(`SELECT sbom_id FROM components WHERE id = $1`, seeded).Scan(&sbomID); err != nil {
			t.Fatal(err)
		}
		if err := commit(); err != nil {
			t.Fatal(err)
		}
	}
	cpes := []string{
		"cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
		"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
	}
	withID, withoutID := uuid.New(), uuid.New()
	tx, ctx, commit := m57OpenTenantTx(t, appDB, tenantID)
	repo := NewComponentRepository(appDB)
	for _, c := range []*model.Component{
		{ID: withID, TenantID: tenantID, SbomID: sbomID, Name: "log4j-core", Version: "2.14.1", Type: "library", CPEs: cpes, CreatedAt: time.Now()},
		{ID: withoutID, TenantID: tenantID, SbomID: sbomID, Name: "nocpe", Version: "1", Type: "library", CreatedAt: time.Now()},
	} {
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("create %s: %v", c.Name, err)
		}
	}
	got, err := repo.ListScanTargetsBySbom(ctx, sbomID)
	if err != nil {
		t.Fatal(err)
	}
	var isNull bool
	if err := tx.QueryRow(`SELECT cpes IS NULL FROM components WHERE id = $1`, withoutID).Scan(&isNull); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	byID := map[uuid.UUID]model.Component{}
	for _, c := range got {
		byID[c.ID] = c
	}
	if !reflect.DeepEqual(byID[withID].CPEs, cpes) {
		t.Errorf("CPEs = %q, want %q", byID[withID].CPEs, cpes)
	}
	if byID[withoutID].CPEs != nil {
		t.Errorf("no-CPE component read back %q, want nil", byID[withoutID].CPEs)
	}
	if !isNull {
		t.Errorf("a component without CPEs is stored as a non-NULL array")
	}
}

// Codex M60 R1 Medium: when another transaction inserts a WEAK link for the
// same pair and commits while this LinkComponent waits on the conflict, the
// upward relabel must still happen. A single-statement CTE cannot see that
// row (its snapshot predates the commit), so the call "succeeded" and the
// weak label stayed. Typical shape: the CVE-sync linker and an upload scan
// writing the same link at the same time.
func TestM60LinkComponent_RelabelsARowInsertedConcurrently(t *testing.T) {
	appURL, migURL := rlsTestEnv(t)
	appDB := openOrSkip(t, appURL)
	migDB := openOrSkip(t, migURL)

	tenantID, componentID := m54SeedComponentForLink(t, migDB)
	v := m57ScannerVuln(t, migDB, m55MetaCVEID())
	repo := NewVulnerabilityRepository(appDB)
	if err := repo.Create(context.Background(), v); err != nil {
		t.Fatal(err)
	}

	// A: inserts the weak link and holds it uncommitted.
	_, ctxA, commitA := m57OpenTenantTx(t, appDB, tenantID)
	if err := repo.LinkComponent(ctxA, componentID, v.ID, model.MatchJVNKeyword); err != nil {
		t.Fatal(err)
	}

	// B: the strong write, which must wait on A's uncommitted row.
	_, ctxB, commitB := m57OpenTenantTx(t, appDB, tenantID)
	done := make(chan error, 1)
	go func() { done <- repo.LinkComponent(ctxB, componentID, v.ID, model.MatchNVDCPE) }()

	select {
	case err := <-done:
		t.Fatalf("B did not wait for A's uncommitted insert (err=%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := commitA(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("B: %v", err)
	}
	if err := commitB(); err != nil {
		t.Fatal(err)
	}

	var m string
	if err := migDB.QueryRow(`SELECT match_method FROM component_vulnerabilities WHERE component_id = $1 AND vulnerability_id = $2`,
		componentID, v.ID).Scan(&m); err != nil {
		t.Fatal(err)
	}
	if m != "nvd_cpe" {
		t.Errorf("stored method = %s, want nvd_cpe: the relabel was lost to a concurrent weak insert", m)
	}
}
