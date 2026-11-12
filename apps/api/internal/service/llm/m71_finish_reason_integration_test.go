//go:build integration

// M71: llm_calls.finish_reason is VARCHAR(30) and providers' values were
// stored unchecked. A value the column cannot hold made the llm_calls INSERT
// fail, and on the success path that INSERT shares the draft's write
// transaction, so the whole triage / CRA run failed.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run 'M71' ./internal/service/llm
package llm_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/repository"
	"github.com/sbomhub/sbomhub/internal/service/llm"
)

func m71Open(t *testing.T, env string) *sql.DB {
	t.Helper()
	url := os.Getenv(env)
	if url == "" {
		t.Skip("requires DATABASE_URL (sbomhub_app) and MIGRATE_DATABASE_URL (sbomhub_migrator)")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open %s: %v", env, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping %s: %v (configured, so a broken environment, not an absent one)", env, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// m71Insert writes one llm_calls row as the app role inside a tenant tx and
// reads its finish_reason back.
func m71Insert(t *testing.T, appDB *sql.DB, tenantID uuid.UUID, finish string) (string, error) {
	t.Helper()
	tx, err := appDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatal(err)
	}
	ctx := database.WithTx(context.Background(), tx)
	id := uuid.New()
	if err := repository.NewLLMCallsRepository(appDB).Insert(ctx, &repository.LLMCall{
		ID: id, TenantID: tenantID, Purpose: "vex_triage", Provider: "openai", Model: "m",
		PromptHash: strings.Repeat("a", 64), ResponseHash: strings.Repeat("b", 64),
		FinishReason: finish,
	}); err != nil {
		return "", err
	}
	var got sql.NullString
	if err := tx.QueryRow(`SELECT finish_reason FROM llm_calls WHERE id = $1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got.String, nil
}

func TestM71FinishReason_NormalisedValueAlwaysInserts(t *testing.T) {
	migDB := m71Open(t, "MIGRATE_DATABASE_URL")
	appDB := m71Open(t, "DATABASE_URL")
	tenantID := uuid.New()
	org := "m71-llm-" + tenantID.String()
	if _, err := migDB.Exec(`INSERT INTO tenants (id, clerk_org_id, name, slug) VALUES ($1, $2, $2, $2)`, tenantID, org); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := migDB.Exec(`DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup tenant: %v", err)
		}
	})

	raw := []string{
		strings.Repeat("X", 31),         // pq 22001 value too long for type character varying(30)
		"stop\x00",                      // pq 22021 invalid byte sequence
		"st\xffop",                      // pq 22021
		"model_context_window_exceeded", // 29: the longest value a provider documents today
		"STOP",
	}
	// Reproduction (measured 2026-11-13, PostgreSQL 15): the first three raw
	// values fail the INSERT.
	for _, v := range raw[:3] {
		if _, err := m71Insert(t, appDB, tenantID, v); err == nil {
			t.Logf("note: raw %q inserted (reproduction no longer fails)", v)
		}
	}
	for _, v := range raw {
		want := llm.NormalizeFinishReason(v)
		got, err := m71Insert(t, appDB, tenantID, want)
		if err != nil {
			t.Errorf("normalised %q (from %q) failed to insert: %v", want, v, err)
			continue
		}
		if got != want {
			t.Errorf("round-trip: got %q want %q", got, want)
		}
	}
}
