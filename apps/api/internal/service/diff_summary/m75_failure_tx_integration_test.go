//go:build integration

// M75 (Codex R1 High): a failed diff summary's llm_calls and ai_failed audit
// rows survive the rollback of the request transaction (TenantTx rolls back
// the 500 the handler answers), because FailureTx commits them on their own.
//
//	cd apps/api && go test -tags=integration -count=1 -run M75DiffSummary ./internal/service/diff_summary
package diff_summary

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
	"github.com/sbomhub/sbomhub/internal/service/triage"
)

func m75Open(t *testing.T, env string) *sql.DB {
	t.Helper()
	url := os.Getenv(env)
	if url == "" {
		t.Skip("requires DATABASE_URL and MIGRATE_DATABASE_URL")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping %s: %v", env, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestM75DiffSummary_FailureRowsSurviveRequestRollback(t *testing.T) {
	migDB := m75Open(t, "MIGRATE_DATABASE_URL")
	appDB := m75Open(t, "DATABASE_URL")

	f := newFixture(t)
	org := "m75-diff-" + f.tenantID.String()
	if _, err := migDB.Exec(`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $2, $2)`, f.tenantID, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, f.tenantID) })

	prov := &fakeProvider{name: "openai", model: "m", resp: &llm.CompleteResponse{
		Content: `{"summary":"cut`, OutputTokens: 1024, FinishReason: "length", RawResponse: []byte(`{}`)}}
	svc := NewService(Config{
		Diff: f.diffSvc, Provider: prov,
		LLMCalls:  repository.NewLLMCallsRepository(appDB),
		Audit:     repository.NewAuditRepository(appDB),
		FailureTx: triage.NewDBTxManager(appDB),
	})

	// The request transaction, as TenantTx opens it; rolled back below as
	// TenantTx does for the 500.
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, f.tenantID.String()); err != nil {
		t.Fatal(err)
	}
	_, genErr := svc.Generate(database.WithTx(context.Background(), tx), Request{
		TenantID: f.tenantID, ProjectID: f.projectID, FromSbomID: f.fromID, ToSbomID: f.toID,
	})
	_ = tx.Rollback()
	if genErr == nil {
		t.Fatal("truncated answer accepted")
	}

	// Read back as the app role in a fresh tenant-bound tx (RLS).
	rtx, err := appDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rtx.Rollback() }()
	if _, err := rtx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, f.tenantID.String()); err != nil {
		t.Fatal(err)
	}
	var finish, errMsg, body string
	var callID uuid.UUID
	if err := rtx.QueryRow(`SELECT id, finish_reason, error_message, response_body FROM llm_calls
		WHERE tenant_id = $1 AND purpose = $2`, f.tenantID, LLMCallPurposeDiffSummary).
		Scan(&callID, &finish, &errMsg, &body); err != nil {
		t.Fatalf("llm_calls row lost with the request rollback: %v", err)
	}
	if finish != "length" || errMsg == "" || body != `{"summary":"cut` {
		t.Errorf("row finish=%q error=%q body=%q", finish, errMsg, body)
	}
	var n int
	if err := rtx.QueryRow(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`,
		f.tenantID, AuditActionAIFailed).Scan(&n); err != nil || n != 1 {
		t.Errorf("ai_failed audit rows = %d (err %v), want 1", n, err)
	}
}

// Codex R3 High: the request holds a main-pool connection (TenantTx) while
// FailureTx asks for another. With FailureTx on the SAME pool, saturating
// the pool with failing summaries deadlocks it; production therefore gives
// FailureTx its own small pool (cmd/server/main.go, aiFailureDB). This pins
// that shape: a main pool of ONE connection, held by the request tx, and the
// failure rows still commit through the separate pool.
func TestM75DiffSummary_FailureTxOnSeparatePoolDoesNotDeadlock(t *testing.T) {
	migDB := m75Open(t, "MIGRATE_DATABASE_URL")
	mainDB := m75Open(t, "DATABASE_URL")
	mainDB.SetMaxOpenConns(1)
	failureDB := m75Open(t, "DATABASE_URL")
	if v := os.Getenv("M75_SAME_POOL"); v != "" {
		failureDB = mainDB // reproduces the deadlock (times out)
	}

	f := newFixture(t)
	org := "m75-pool-" + f.tenantID.String()
	if _, err := migDB.Exec(`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $2, $2)`, f.tenantID, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = migDB.Exec(`DELETE FROM tenants WHERE id = $1`, f.tenantID) })

	svc := NewService(Config{
		Diff:      f.diffSvc,
		Provider:  &fakeProvider{name: "openai", model: "m", resp: &llm.CompleteResponse{Content: "{", FinishReason: "length"}},
		LLMCalls:  repository.NewLLMCallsRepository(mainDB),
		Audit:     repository.NewAuditRepository(mainDB),
		FailureTx: triage.NewDBTxManager(failureDB),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := mainDB.BeginTx(ctx, nil) // the only main-pool connection
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, f.tenantID.String()); err != nil {
		t.Fatal(err)
	}
	_, genErr := svc.Generate(database.WithTx(ctx, tx), Request{
		TenantID: f.tenantID, ProjectID: f.projectID, FromSbomID: f.fromID, ToSbomID: f.toID,
	})
	if !errors.Is(genErr, llm.ErrTruncatedResponse) {
		t.Fatalf("Generate err = %v, want ErrTruncatedResponse (a pool wait would surface as a context deadline)", genErr)
	}
}
