package database

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strings"
)

// Migrate runs all pending migrations automatically on startup
// migrationsFS should be an embedded filesystem containing the migrations/*.sql files
func Migrate(db *sql.DB, migrationsFS embed.FS) error {
	// Ensure migrations table exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Get migration files from embedded FS
	// The FS is embedded at the root level (*.sql), so we read "."
	entries, err := migrationsFS.ReadDir(".")
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

		content, err := migrationsFS.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			rollbackMigrationTx(tx, version)
			return fmt.Errorf("failed to apply migration %s: %w", version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
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

func getAppliedMigrations(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
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
