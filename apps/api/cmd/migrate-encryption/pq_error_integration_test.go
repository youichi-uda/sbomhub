//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

// TestIntegration_RealServerErrorIsPQError triggers a real unique violation
// on a live PostgreSQL through the tool's own openDB (lib/pq) and checks that
//
//  1. the driver hands back *pq.Error with SQLSTATE 23505 — the type isDBErr
//     matches. This is the fact that made the old *pgconn.PgError (jackc/pgconn
//     v1) branch dead code: no pgx driver is registered, so that type never
//     reaches this tool;
//  2. that real error, bare and wrapped with %w as the tool's call sites do,
//     classifies as a DB error (exit 2) and is never skipped by
//     --continue-on-error.
//
// Needs MIGRATE_DATABASE_URL (any role that may create a TEMP table); skipped
// otherwise. CI runs it from rls-integration.yml.
func TestIntegration_RealServerErrorIsPQError(t *testing.T) {
	dsn := os.Getenv("MIGRATE_DATABASE_URL")
	if dsn == "" {
		t.Skip("MIGRATE_DATABASE_URL not set")
	}
	db, err := openDB("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := db.Conn(ctx) // TEMP tables are per-session: pin one connection
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `CREATE TEMP TABLE m_enc_uniq (id int PRIMARY KEY)`); err != nil {
		t.Fatalf("create temp table: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO m_enc_uniq VALUES (1)`); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	_, dupErr := conn.ExecContext(ctx, `INSERT INTO m_enc_uniq VALUES (1)`)
	if dupErr == nil {
		t.Fatal("duplicate insert succeeded; expected a unique violation")
	}

	if got := reflect.TypeOf(dupErr).String(); got != "*pq.Error" {
		t.Fatalf("driver error type = %s, want *pq.Error (err: %v)", got, dupErr)
	}
	var sqlstate interface{ SQLState() string }
	if !errors.As(dupErr, &sqlstate) || sqlstate.SQLState() != "23505" {
		t.Fatalf("SQLSTATE = %v, want 23505 (unique_violation)", dupErr)
	}

	for name, e := range map[string]error{
		"bare":    dupErr,
		"wrapped": fmt.Errorf("update tenant_llm_config.encrypted_api_key row=x: %w", dupErr),
	} {
		if !isDBErr(e) {
			t.Errorf("%s: isDBErr = false for a real server error", name)
		}
		if isContinuableRowErr(e) {
			t.Errorf("%s: a real server error would be skipped by --continue-on-error", name)
		}
		if c := classifyErr(e); c != exitDBError {
			t.Errorf("%s: classifyErr = %d, want exitDBError (%d)", name, c, exitDBError)
		}
	}
}
