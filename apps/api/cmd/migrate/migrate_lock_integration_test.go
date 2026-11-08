//go:build integration

package main

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// cmd/migrate takes the same advisory lock as the API's startup migration
// (internal/database.MigrationLockKey). Two `migrate up` runs against one
// empty database must both succeed and apply every file exactly once; without
// the lock both create schema_migrations and apply 001 at the same time and
// one fails.
//
//	cd apps/api && go test -tags=integration -count=1 -run MigrateLock ./cmd/migrate
func TestMigrateLock_ConcurrentUpRuns(t *testing.T) {
	base := os.Getenv("MIGRATE_DATABASE_URL")
	if base == "" {
		t.Skip("MIGRATE_DATABASE_URL not set")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	name := "sbomhub_cmdmiglock_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatalf("create scratch database (the migrator role needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		_ = admin.Close()
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name

	// migrateUp reads migrations/*.up.sql relative to the working directory,
	// as the tool does when run from apps/api.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	files, err := filepath.Glob("migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations found from %s: %v", filepath.Join(wd, "..", ".."), err)
	}

	const runners = 2
	errs := make([]error, runners)
	pools := make([]*sql.DB, runners)
	for i := range pools {
		pools[i], err = sql.Open("postgres", u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer pools[i].Close()
		if err := pools[i].Ping(); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range pools {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = run(pools[i], "up", nil)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("runner %d: %v", i, err)
		}
	}
	var applied int
	if err := pools[0].QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != len(files) {
		t.Errorf("schema_migrations rows = %d, want %d", applied, len(files))
	}
}
