package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"
)

// MigrationLockKey is the session-level advisory lock every migrator takes
// before it reads schema_migrations: the API's startup auto-migration
// (Migrate) and cmd/migrate up / down. Derived from a namespaced string the
// same way as the scan lock (service.ScanLockKey), so it cannot coincide with
// a key another feature derives.
var MigrationLockKey = func() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("sbomhub.schema_migrations"))
	return int64(h.Sum64()) //nolint:gosec // a hash reinterpreted as a lock key; wrap-around is intended
}()

// DefaultMigrationLockWait is how long a migrator waits for another one to
// finish before giving up. Generous because the holder may be running a long
// migration; a replica that gives up exits and is restarted by its
// orchestrator, and waits again.
const DefaultMigrationLockWait = 10 * time.Minute

// defaultMigrationLockLogEvery is how often a waiting migrator says so.
const defaultMigrationLockLogEvery = 10 * time.Second

// migrationLockQueryTimeout bounds each statement of the acquisition loop.
const migrationLockQueryTimeout = 10 * time.Second

// migrationLockPoll is the retry interval of pg_try_advisory_lock.
const migrationLockPoll = 250 * time.Millisecond

// MigrateOptions tunes MigrateWithOptions. Zero values select the defaults.
type MigrateOptions struct {
	// LockWait bounds the wait for the migration lock.
	LockWait time.Duration
	// LogEvery is how often the wait is logged.
	LogEvery time.Duration
}

// Migrate runs all pending migrations automatically on startup.
// migrationsFS holds the migrations/*.sql files at its root.
//
// It holds MigrationLockKey for the whole run, so replicas booting against
// the same database apply migrations one at a time: the second waits, then
// reads a schema_migrations that already lists everything and applies
// nothing. Without the lock both read the same applied-set and execute the
// same files; the loser fails on a duplicate object (measured: two replicas
// on an empty database, "duplicate key value violates unique constraint
// pg_type_typname_nsp_index" from the concurrent CREATE TABLE IF NOT EXISTS
// schema_migrations), and a non-idempotent migration body can run twice.
func Migrate(db *sql.DB, migrationsFS fs.FS) error {
	return MigrateWithOptions(context.Background(), db, migrationsFS, MigrateOptions{})
}

// MigrateWithOptions is Migrate with an explicit context and lock options.
func MigrateWithOptions(ctx context.Context, db *sql.DB, migrationsFS fs.FS, opts MigrateOptions) error {
	conn, release, err := AcquireMigrationLock(ctx, db, opts)
	if err != nil {
		return err
	}
	defer release()

	// Everything below runs on the locked session: if that connection dies
	// the lock goes with it, and so does the ability to run DDL — there is
	// no window in which this migrator keeps going without the lock.
	if err := EnsureMigrationsTable(ctx, conn); err != nil {
		return err
	}

	// Get applied migrations
	applied, err := getAppliedMigrations(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get migration files. The FS holds them at its root (*.sql).
	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("failed to read migrations directory: %w", err)
	}

	// Filter and sort .up.sql files
	var upFiles []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			upFiles = append(upFiles, entry.Name())
		}
	}
	sort.Strings(upFiles)

	// Apply pending migrations
	appliedCount := 0
	for _, filename := range upFiles {
		version := extractVersion(filename)
		if applied[version] {
			continue
		}

		slog.Info("Applying migration", "version", version)

		content, err := fs.ReadFile(migrationsFS, filename)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			rollbackMigrationTx(tx, version)
			return fmt.Errorf("failed to apply migration %s: %w", version, err)
		}

		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			rollbackMigrationTx(tx, version)
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %s: %w", version, err)
		}

		slog.Info("Applied migration", "version", version)
		appliedCount++
	}

	if appliedCount > 0 {
		slog.Info("Migrations complete", "applied", appliedCount)
	} else {
		slog.Info("Database is up to date")
	}

	return nil
}

// EnsureMigrationsTable creates schema_migrations if it does not exist. Call
// it with the migration lock held: two concurrent CREATE TABLE IF NOT EXISTS
// of the same table can fail on the catalog's unique index.
func EnsureMigrationsTable(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}
	return nil
}

// AcquireMigrationLock takes MigrationLockKey on a dedicated connection from
// db and returns that connection — run the migrations on it — and a release
// function that unlocks and returns the connection.
//
// It polls pg_try_advisory_lock rather than blocking in pg_advisory_lock so
// the wait can be bounded and reported: every LogEvery it logs that it is
// waiting and which backend holds the lock, and after LockWait it gives up
// with an error naming the lock. The lock is session-level (it spans the
// per-file transactions); it is released explicitly, and by PostgreSQL if the
// session ends.
func AcquireMigrationLock(ctx context.Context, db *sql.DB, opts MigrateOptions) (*sql.Conn, func(), error) {
	wait := opts.LockWait
	if wait <= 0 {
		wait = DefaultMigrationLockWait
	}
	logEvery := opts.LogEvery
	if logEvery <= 0 {
		logEvery = defaultMigrationLockLogEvery
	}

	// Getting a connection counts against the wait, and every statement
	// below has its own short timeout (Codex R1 Medium: an exhausted pool or
	// a stalled server used to block db.Conn / the poll on the caller's
	// context, which at startup has no deadline).
	start := time.Now()
	deadline := start.Add(wait)
	cctx, cancelConn := context.WithDeadline(ctx, deadline)
	conn, err := db.Conn(cctx)
	cancelConn()
	if err != nil {
		return nil, nil, fmt.Errorf("migration lock: no database connection within %s: %w", wait, err)
	}

	nextLog := start
	for {
		// Each statement has its own short budget, so a stalled server
		// cannot hold the loop past the wait by more than one of them, and a
		// poll in flight at the deadline is not cancelled half way.
		var got bool
		qctx, cancelQ := context.WithTimeout(ctx, migrationLockQueryTimeout)
		err := conn.QueryRowContext(qctx, `SELECT pg_try_advisory_lock($1)`, MigrationLockKey).Scan(&got)
		cancelQ()
		if err != nil {
			// A cancelled poll may still have taken the lock server-side, so
			// the session is discarded, never returned to the pool.
			discardConn(conn)
			return nil, nil, fmt.Errorf("migration lock: %w", err)
		}
		if got {
			if waited := time.Since(start); waited >= migrationLockPoll {
				slog.Info("acquired migration lock", "waited", waited.Round(time.Millisecond).String())
			}
			break
		}
		now := time.Now()
		if !now.Before(deadline) {
			// The acquisition context has expired; describe the holder with
			// a short budget of its own.
			holder := migrationLockHolder(ctx, conn)
			discardConn(conn)
			return nil, nil, fmt.Errorf("migration lock: another migrator (%s) still held it after %s; "+
				"retry when it has finished", holder, wait)
		}
		if !now.Before(nextLog) {
			slog.Warn("waiting for migration lock held by another migrator",
				"holder", migrationLockHolder(ctx, conn),
				"waited", now.Sub(start).Round(time.Second).String(),
				"gives_up_after", wait.String())
			nextLog = now.Add(logEvery)
		}
		select {
		case <-ctx.Done():
			discardConn(conn)
			return nil, nil, fmt.Errorf("migration lock: %w", ctx.Err())
		case <-time.After(migrationLockPoll):
		}
	}

	release := func() {
		// A fresh context: the caller's may already be done, and an unlock
		// that is skipped leaves the lock on a pooled session.
		uctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var unlocked bool
		err := conn.QueryRowContext(uctx, `SELECT pg_advisory_unlock($1)`, MigrationLockKey).Scan(&unlocked)
		if err != nil || !unlocked {
			// Discard the session rather than return it to the pool still
			// holding the lock; closing it releases the lock server-side.
			slog.Warn("migration lock: unlock failed, discarding the connection", "error", err, "unlocked", unlocked)
			discardConn(conn)
			return
		}
		_ = conn.Close()
	}
	return conn, release, nil
}

// discardConn closes conn's underlying session instead of returning it to
// the pool. Ending the session releases any advisory lock it holds.
func discardConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
	_ = conn.Close()
}

// migrationLockHolder describes the session holding the migration lock, for
// the wait log. Best effort: it never fails the caller.
func migrationLockHolder(ctx context.Context, conn *sql.Conn) string {
	ctx, cancel := context.WithTimeout(ctx, migrationLockQueryTimeout)
	defer cancel()
	var pid sql.NullInt64
	var app, addr sql.NullString
	err := conn.QueryRowContext(ctx, `
		SELECT l.pid, a.application_name, a.client_addr::text
		FROM pg_locks l
		LEFT JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
		  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		  AND ((l.classid::bigint << 32) | l.objid::bigint) = $1
		LIMIT 1`, MigrationLockKey).Scan(&pid, &app, &addr)
	if err != nil || !pid.Valid {
		return "unknown session"
	}
	return fmt.Sprintf("pid %d, application %q, client %s", pid.Int64, app.String, addr.String)
}

// migrationQueryer is the read side shared by *sql.DB and *sql.Conn.
type migrationQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func getAppliedMigrations(ctx context.Context, db migrationQueryer) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}
	// No-partial-results contract (M46 Track C-3b): a truncated applied-set
	// would make startup auto-migration re-apply migrations that already
	// ran — usually a hard SQL failure (duplicate table / column) that
	// aborts boot with a much more confusing error than this one.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to enumerate applied migrations: %w", err)
	}

	return applied, nil
}

// rollbackMigrationTx rolls back a migration transaction after a failed
// statement. The rollback error is secondary (the primary failure is
// already being returned) but must not be silently discarded (errcheck,
// M46 Track C-3b): a failed ROLLBACK usually means the connection is
// broken, which the operator should see alongside the migration error.
func rollbackMigrationTx(tx *sql.Tx, version string) {
	if err := tx.Rollback(); err != nil {
		slog.Warn("rollback of migration transaction failed", "version", version, "error", err)
	}
}

func extractVersion(filename string) string {
	// Remove .up.sql or .down.sql suffix
	base := strings.TrimSuffix(filename, ".up.sql")
	base = strings.TrimSuffix(base, ".down.sql")
	return base
}
