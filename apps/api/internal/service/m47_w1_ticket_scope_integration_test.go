//go:build integration

// Package service — M47 W1: POST /api/v1/vulnerabilities/:vuln_id/ticket
// must bind (vulnerability_id, project_id) to the caller's tenant BEFORE it
// talks to a third-party issue tracker.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 \
//	    -run 'M47W1Ticket' ./internal/service
//
// This route is the only one in the M47 set whose side effect is EXTERNAL.
// Pre-fix the handler took :vuln_id from the path and project_id from the
// BODY, checked neither against the tenant nor against each other, and went
// straight on to create an issue in Jira / Backlog / GitHub. The local row
// was written afterwards, so the DB-layer defences (the vulnerability_tickets
// composite (tenant_id, project_id) FK; RLS) could at best fail AFTER an
// unauthorised issue already existed in someone else's tracker — an effect no
// rollback undoes.
//
// The test therefore asserts the ORDER, not just the status code: a counting
// httptest server stands in for the tracker and must receive ZERO requests.
package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/egress"
	"github.com/sbomhub/sbomhub/internal/repository"
)

type m47TicketSeed struct {
	tenantID  uuid.UUID
	projectID uuid.UUID
	vulnID    uuid.UUID
}

func m47TicketEnv(t *testing.T) (appURL, migURL string) {
	t.Helper()
	appURL, migURL = os.Getenv("DATABASE_URL"), os.Getenv("MIGRATE_DATABASE_URL")
	if appURL == "" || migURL == "" {
		t.Skip("ticket scope integration test requires DATABASE_URL (sbomhub_app) and " +
			"MIGRATE_DATABASE_URL (sbomhub_migrator)")
	}
	return appURL, migURL
}

func m47TicketOpen(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Skipf("sql.Open failed (%v) - skipping", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("DB unreachable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m47TicketSeedAll seeds tenant + project + sbom + component + a global
// vulnerability linked to that component.
func m47TicketSeedAll(t *testing.T, migDB *sql.DB, label string) m47TicketSeed {
	t.Helper()
	s := m47TicketSeed{tenantID: uuid.New()}
	org := "m47tk-" + label + "-" + s.tenantID.String()
	if _, err := migDB.Exec(
		`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $3, $4)`,
		s.tenantID, org, "m47tk "+label, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tenantID := s.tenantID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("C27 cleanup: delete tenant %s: %v", tenantID, err)
		}
	})

	exec := func(query string, args ...any) {
		t.Helper()
		tx, err := migDB.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
			t.Fatalf("SET LOCAL: %v", err)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			t.Fatalf("exec as tenant: %v\nquery: %s", err, query)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	s.projectID = uuid.New()
	sbomID, componentID := uuid.New(), uuid.New()
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $3)`, s.projectID, s.tenantID, "m47tk-"+label)
	exec(`INSERT INTO sboms (id, tenant_id, project_id, format, version, raw_data, created_at)
	      VALUES ($1, $2, $3, 'cyclonedx', '1.5', '{}'::jsonb, NOW())`, sbomID, s.tenantID, s.projectID)
	exec(`INSERT INTO components (id, tenant_id, sbom_id, name, version, type, purl, created_at)
	      VALUES ($1, $2, $3, 'libtk', '1.0', 'library', 'pkg:generic/libtk@1.0', NOW())`,
		componentID, s.tenantID, sbomID)

	s.vulnID = uuid.New()
	cveID := fmt.Sprintf("CVE-2093-%07d", uuid.New().ID()%10000000)
	if _, err := migDB.Exec(`
		INSERT INTO vulnerabilities (id, cve_id, description, severity, cvss_score)
		VALUES ($1, $2, 'm47 ticket vuln', 'HIGH', 7.5)`, s.vulnID, cveID); err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}
	vulnID := s.vulnID
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM vulnerabilities WHERE id = $1`, vulnID); err != nil {
			t.Errorf("C27 cleanup: delete vulnerability %s: %v", vulnID, err)
		}
	})
	if _, err := migDB.Exec(
		`INSERT INTO component_vulnerabilities (component_id, vulnerability_id) VALUES ($1, $2)`,
		componentID, s.vulnID); err != nil {
		t.Fatalf("link component to vulnerability: %v", err)
	}
	return s
}

// m47TicketService builds the service with a fixed 32-byte key so the test
// can encrypt the seeded connection's token with the same cipher.
func m47TicketService(appDB *sql.DB) *IssueTrackerService {
	key := []byte("0123456789abcdef0123456789abcdef")
	return NewIssueTrackerService(
		repository.NewIssueTrackerRepository(appDB),
		repository.NewVulnerabilityRepository(appDB),
		key,
		// The test server is on 127.0.0.1, which the tenant-egress policy
		// refuses by default (M50). The destination here is chosen by the
		// test, not by a tenant, so it declares that explicitly.
		egress.OperatorControlled(),
	)
}

// m47SeedConnection inserts an issue_tracker_connections row pointing at
// baseURL. It is inserted directly (not through CreateConnection) because
// CreateConnection performs a live connectivity probe, which would pollute
// the request counter this test depends on.
func m47SeedConnection(t *testing.T, migDB *sql.DB, svc *IssueTrackerService, tenantID uuid.UUID, baseURL string) uuid.UUID {
	t.Helper()
	token, err := svc.encrypt("m47-token")
	if err != nil {
		t.Fatalf("encrypt token: %v", err)
	}
	connID := uuid.New()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO issue_tracker_connections
			(id, tenant_id, tracker_type, name, base_url, auth_type, auth_token_encrypted,
			 default_project_key, default_issue_type, is_active)
		VALUES ($1, $2, 'github', $3, $4, 'api_token', $5, 'acme/widget', 'Bug', true)`,
		connID, tenantID, "m47tk-"+connID.String()[:8], baseURL, token); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit connection: %v", err)
	}
	return connID
}

// m47TicketCount runs one COUNT(*) inside a migrator tx that has
// SET LOCAL app.current_tenant_id.
func m47TicketCount(t *testing.T, migDB *sql.DB, tenantID uuid.UUID, query string, args ...any) int {
	t.Helper()
	tx, err := migDB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("SET LOCAL: %v", err)
	}
	var n int
	if err := tx.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v\nquery: %s", err, query)
	}
	return n
}

// m47TicketTx runs fn inside an app-role tenant tx, exactly like a live
// request behind TenantTx, and commits regardless of outcome so the
// "no rows were written" assertions prove the service refused.
func m47TicketTx(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, fn func(ctx context.Context)) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatalf("appDB.Begin: %v", err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback()
		t.Fatalf("SET LOCAL: %v", err)
	}
	fn(database.WithTx(context.Background(), tx))
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tenant tx: %v", err)
	}
}

// TestM47W1TicketScope_ForeignTargetsNeverReachTheTracker is the core
// reproduction. Three hostile shapes, one contract each time: the scope
// sentinel, zero rows, and — the load-bearing part — zero outbound requests.
func TestM47W1TicketScope_ForeignTargetsNeverReachTheTracker(t *testing.T) {
	appURL, migURL := m47TicketEnv(t)
	migDB := m47TicketOpen(t, migURL)
	appDB := m47TicketOpen(t, appURL)

	var hits int64
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1,"number":1,"title":"x","html_url":"http://x","state":"open"}`))
	}))
	defer tracker.Close()

	caller := m47TicketSeedAll(t, migDB, "caller")
	victim := m47TicketSeedAll(t, migDB, "victim")
	svc := m47TicketService(appDB)
	connID := m47SeedConnection(t, migDB, svc, caller.tenantID, tracker.URL)

	cases := []struct {
		name  string
		vuln  uuid.UUID
		proj  uuid.UUID
		notes string
	}{
		{
			name:  "another tenant's vulnerability against my own project",
			vuln:  victim.vulnID,
			proj:  caller.projectID,
			notes: "the global vulnerabilities cache has no RLS, so the id resolves for anyone",
		},
		{
			name:  "my own vulnerability against another tenant's project",
			vuln:  caller.vulnID,
			proj:  victim.projectID,
			notes: "project_id comes from the BODY, so it was never tied to the session",
		},
		{
			name:  "a vulnerability that exists but affects nothing of mine",
			vuln:  victim.vulnID,
			proj:  victim.projectID,
			notes: "both ids are real and mutually consistent — only the TENANT is wrong",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := atomic.LoadInt64(&hits)
			var gotErr error
			m47TicketTx(t, appDB, caller.tenantID, func(ctx context.Context) {
				_, gotErr = svc.CreateTicket(ctx, caller.tenantID, CreateTicketInput{
					VulnerabilityID: tc.vuln,
					ProjectID:       tc.proj,
					ConnectionID:    connID,
					ProjectKey:      "acme/widget",
					Summary:         "m47",
					Description:     "m47",
				})
			})
			if !errors.Is(gotErr, ErrTicketTargetNotInProject) {
				t.Errorf("CreateTicket(%s) err = %v, want ErrTicketTargetNotInProject (%s)", tc.name, gotErr, tc.notes)
			}
			if after := atomic.LoadInt64(&hits); after != before {
				t.Errorf("the external tracker received %d request(s) for a rejected ticket — "+
					"the scope check MUST run before any outbound call (an issue filed in "+
					"someone else's tracker cannot be rolled back)", after-before)
			}
			// vulnerability_tickets is FORCE RLS and its legacy policy uses
			// current_setting() WITHOUT the missing_ok flag, so an unbound
			// read errors rather than returning nothing — count inside a
			// tenant-bound tx.
			rows := m47TicketCount(t, migDB, caller.tenantID,
				`SELECT COUNT(*) FROM vulnerability_tickets WHERE vulnerability_id = $1 AND connection_id = $2`,
				tc.vuln, connID)
			if rows != 0 {
				t.Errorf("vulnerability_tickets rows for a rejected ticket = %d, want 0", rows)
			}
		})
	}
}

// TestM47W1TicketScope_ScopeCheckPrecedesConnectionResolution pins the
// ORDER independently of the network: with an unknown connection_id, a
// pre-fix run answered the connection error first ("connection not found",
// a 400), which proves the connection was resolved before the target was
// validated. Post-fix the scope sentinel wins.
func TestM47W1TicketScope_ScopeCheckPrecedesConnectionResolution(t *testing.T) {
	appURL, migURL := m47TicketEnv(t)
	migDB := m47TicketOpen(t, migURL)
	appDB := m47TicketOpen(t, appURL)

	caller := m47TicketSeedAll(t, migDB, "order-caller")
	victim := m47TicketSeedAll(t, migDB, "order-victim")
	svc := m47TicketService(appDB)

	var gotErr error
	m47TicketTx(t, appDB, caller.tenantID, func(ctx context.Context) {
		_, gotErr = svc.CreateTicket(ctx, caller.tenantID, CreateTicketInput{
			VulnerabilityID: victim.vulnID,
			ProjectID:       caller.projectID,
			ConnectionID:    uuid.New(), // does not exist
			Summary:         "m47",
		})
	})
	if !errors.Is(gotErr, ErrTicketTargetNotInProject) {
		t.Errorf("err = %v, want ErrTicketTargetNotInProject "+
			"(a connection error here means the connection was resolved BEFORE the target was validated)", gotErr)
	}
}

// TestM47W1TicketScope_LegitimateTargetStillReachesTheTracker proves the
// guard is a scope check and not a blanket block: the caller's own
// (vulnerability, project) pair gets past it and the tracker IS contacted.
func TestM47W1TicketScope_LegitimateTargetStillReachesTheTracker(t *testing.T) {
	appURL, migURL := m47TicketEnv(t)
	migDB := m47TicketOpen(t, migURL)
	appDB := m47TicketOpen(t, appURL)

	var hits int64
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1,"number":1,"title":"m47","html_url":"http://example.invalid/1","state":"open"}`))
	}))
	defer tracker.Close()

	caller := m47TicketSeedAll(t, migDB, "ok")
	svc := m47TicketService(appDB)
	connID := m47SeedConnection(t, migDB, svc, caller.tenantID, tracker.URL)

	var gotErr error
	m47TicketTx(t, appDB, caller.tenantID, func(ctx context.Context) {
		_, gotErr = svc.CreateTicket(ctx, caller.tenantID, CreateTicketInput{
			VulnerabilityID: caller.vulnID,
			ProjectID:       caller.projectID,
			ConnectionID:    connID,
			ProjectKey:      "acme/widget",
			Summary:         "m47 legit",
			Description:     "m47 legit",
		})
	})
	if errors.Is(gotErr, ErrTicketTargetNotInProject) {
		t.Fatalf("the caller's OWN (vulnerability, project) pair was rejected: %v", gotErr)
	}
	if atomic.LoadInt64(&hits) == 0 {
		t.Error("the tracker was never contacted for a legitimate target — the guard is over-blocking")
	}
}
