//go:build integration

package database

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/migrations"
)

// Two API replicas that boot against the same database both run Migrate.
// Without a lock both read the same (empty) schema_migrations, both execute
// the same migration, and the loser fails on a duplicate object or on the
// schema_migrations primary key — aborting that replica's boot, or, for a
// migration whose effect is not idempotent (an UPDATE / INSERT backfill),
// applying it twice before the loser's INSERT into schema_migrations fails.
//
// Run with:
//
//	cd apps/api && go test -tags=integration -count=1 -run MigrateLock ./internal/database
//
// Needs MIGRATE_DATABASE_URL for a role with CREATEDB (sbomhub_migrator has
// it, see install.sh); each test creates and drops its own scratch database,
// so the shared schema is never touched.

// scratchDB creates an empty database and returns a DSN for it.
func scratchDB(t *testing.T) string {
	t.Helper()
	base := os.Getenv("MIGRATE_DATABASE_URL")
	if base == "" {
		t.Skip("MIGRATE_DATABASE_URL not set")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := "sbomhub_miglock_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		t.Fatalf("create scratch database (the migrator role needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		a, err := sql.Open("postgres", base)
		if err != nil {
			t.Errorf("reopen for drop: %v", err)
			return
		}
		defer a.Close()
		if _, err := a.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Errorf("drop scratch database %s: %v", name, err)
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

func openPool(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// runConcurrently starts n migrators (each with its own pool, as separate
// replicas would have) at the same instant and returns their errors.
func runConcurrently(t *testing.T, dsn string, n int, fsys fstest.MapFS, real bool) []error {
	t.Helper()
	pools := make([]*sql.DB, n)
	for i := range pools {
		pools[i] = openPool(t, dsn)
		if err := pools[i].Ping(); err != nil {
			t.Fatal(err)
		}
	}
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range pools {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if real {
				errs[i] = Migrate(pools[i], migrations.FS)
			} else {
				errs[i] = Migrate(pools[i], fsys)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

// The race made deterministic: the first migration sleeps, so both migrators
// are certainly past "read schema_migrations" before either commits. The
// second migration is a non-idempotent backfill, which shows what a lost race
// costs beyond a failed boot.
func TestMigrateLock_ConcurrentMigratorsOnEmptyDB(t *testing.T) {
	dsn := scratchDB(t)
	fsys := fstest.MapFS{
		"001_slow.up.sql":       {Data: []byte(`CREATE TABLE race_slow (id int); SELECT pg_sleep(1.5);`)},
		"002_backfill.up.sql":   {Data: []byte(`CREATE TABLE IF NOT EXISTS race_log (n int); INSERT INTO race_log VALUES (1);`)},
		"002_backfill.down.sql": {Data: []byte(`DROP TABLE race_log;`)},
	}

	errs := runConcurrently(t, dsn, 2, fsys, false)
	for i, err := range errs {
		if err != nil {
			t.Errorf("migrator %d failed: %v", i, err)
		}
	}

	db := openPool(t, dsn)
	var applied, logged int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Errorf("schema_migrations rows = %d, want 2", applied)
	}
	if err := db.QueryRow(`SELECT count(*) FROM race_log`).Scan(&logged); err != nil {
		t.Fatalf("race_log missing: %v", err)
	}
	if logged != 1 {
		t.Errorf("the backfill ran %d times, want exactly once", logged)
	}
}

// The real migration set, three replicas at once against an empty database.
func TestMigrateLock_RealMigrationsThreeReplicas(t *testing.T) {
	dsn := scratchDB(t)
	errs := runConcurrently(t, dsn, 3, nil, true)
	for i, err := range errs {
		if err != nil {
			t.Errorf("replica %d failed: %v", i, err)
		}
	}
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			want++
		}
	}
	var applied int
	if err := openPool(t, dsn).QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != want {
		t.Errorf("schema_migrations rows = %d, want %d", applied, want)
	}
}

// A migrator that cannot get the lock waits, and gives up with a clear error
// after its wait budget instead of running unlocked or waiting forever.
func TestMigrateLock_WaitIsBoundedAndNamed(t *testing.T) {
	dsn := scratchDB(t)
	holderPool := openPool(t, dsn)
	ctx := context.Background()
	holder, err := holderPool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, MigrationLockKey); err != nil {
		t.Fatal(err)
	}

	fsys := fstest.MapFS{"001_x.up.sql": {Data: []byte(`CREATE TABLE never_created (id int);`)}}
	start := time.Now()
	err = MigrateWithOptions(ctx, openPool(t, dsn), fsys, MigrateOptions{LockWait: 1500 * time.Millisecond, LogEvery: 500 * time.Millisecond})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Migrate ran although another migrator held the lock")
	}
	if !strings.Contains(err.Error(), "migration lock") || !strings.Contains(err.Error(), "pid ") {
		t.Fatalf("error must name the migration lock and its holder, got: %v", err)
	}
	t.Logf("lock wait error: %v", err)
	if elapsed < 1400*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("gave up after %v, want ~1.5s", elapsed)
	}
	var exists bool
	if err := openPool(t, dsn).QueryRow(`SELECT to_regclass('never_created') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("a migration ran without the lock")
	}

	// Once the holder lets go, the next run proceeds.
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, MigrationLockKey); err != nil {
		t.Fatal(err)
	}
	if err := MigrateWithOptions(ctx, openPool(t, dsn), fsys, MigrateOptions{LockWait: 5 * time.Second}); err != nil {
		t.Fatalf("after release: %v", err)
	}
}

// Codex R1 Medium: the wait budget must cover getting a connection, not only
// the polling after it. With the pool exhausted, db.Conn used to block for
// ever on context.Background().
func TestMigrateLock_WaitCoversConnectionAcquisition(t *testing.T) {
	dsn := scratchDB(t)
	db := openPool(t, dsn)
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	hog, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer hog.Close()

	fsys := fstest.MapFS{"001_x.up.sql": {Data: []byte(`CREATE TABLE never_created (id int);`)}}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- MigrateWithOptions(ctx, db, fsys, MigrateOptions{LockWait: time.Second})
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "migration lock") {
			t.Fatalf("want a migration lock error, got %v", err)
		}
		if el := time.Since(start); el > 4*time.Second {
			t.Fatalf("gave up after %v, want ~1s", el)
		}
	case <-time.After(10 * time.Second):
		_ = hog.Close() // unblock the goroutine
		<-done
		t.Fatal("Migrate blocked on an exhausted pool past its lock wait")
	}
}

// Codex R2 Medium: a lock that only becomes free after the wait budget must
// not be taken late — the budget is the acquisition deadline.
func TestMigrateLock_NotAcquiredAfterDeadline(t *testing.T) {
	dsn := scratchDB(t)
	ctx := context.Background()
	holder, err := openPool(t, dsn).Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := holder.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, MigrationLockKey); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		_, _ = holder.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, MigrationLockKey)
	}()
	fsys := fstest.MapFS{"001_x.up.sql": {Data: []byte(`CREATE TABLE late_created (id int);`)}}
	start := time.Now()
	err = MigrateWithOptions(ctx, openPool(t, dsn), fsys, MigrateOptions{LockWait: 60 * time.Millisecond})
	if err == nil {
		t.Fatalf("lock taken after the 60ms budget (returned after %v)", time.Since(start))
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("gave up after %v, want ~60ms", el)
	}
}
