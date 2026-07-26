package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: migrate <up|down|status>")
		os.Exit(1)
	}

	// Load .env
	_ = godotenv.Load()

	// Prefer MIGRATE_DATABASE_URL (sbomhub_migrator role) over DATABASE_URL.
	// DATABASE_URL is for the runtime app role (sbomhub_app, NOBYPASSRLS) and
	// generally lacks DDL permissions. We fall back to it for OSS users who
	// have not yet split their roles, with a loud warning.
	dbURL := os.Getenv("MIGRATE_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
		if dbURL != "" {
			log.Println("warning: MIGRATE_DATABASE_URL is not set; falling back to DATABASE_URL. " +
				"Set MIGRATE_DATABASE_URL to a sbomhub_migrator connection string for proper role separation.")
		}
	}
	if dbURL == "" {
		// G101 is a false positive here: this is the well-known local-dev
		// placeholder DSN (identical to the config.go DATABASE_URL
		// default), not a real credential, and the fallback is announced
		// with the loud warning below.
		dbURL = "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable" //nolint:gosec // G101: documented local-dev default DSN, not a secret
		log.Println("warning: neither MIGRATE_DATABASE_URL nor DATABASE_URL is set; using legacy default sbomhub:sbomhub@localhost.")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Ensure migrations table exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create migrations table: %v", err)
	}

	command := os.Args[1]
	switch command {
	case "up":
		if err := migrateUp(db); err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
	case "down":
		steps := 1
		if len(os.Args) > 2 {
			var perr error
			steps, perr = parseSteps(os.Args[2])
			if perr != nil {
				// `down` is destructive: refuse to guess. The pre-fix
				// fmt.Sscanf silently ran with steps=1 on garbage input.
				// perr already carries the offending value quoted by
				// strconv, so the raw os.Args value is not echoed (G706).
				log.Fatalf("Invalid steps argument: %v", perr)
			}
		}
		if err := migrateDown(db, steps); err != nil {
			log.Fatalf("Migration rollback failed: %v", err)
		}
	case "status":
		if err := showStatus(db); err != nil {
			log.Fatalf("Failed to show status: %v", err)
		}
	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func migrateUp(db *sql.DB) error {
	// Get applied migrations
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	// Get migration files
	files, err := filepath.Glob("migrations/*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	for _, file := range files {
		version := extractVersion(file)
		if applied[version] {
			continue
		}

		fmt.Printf("Applying migration: %s\n", filepath.Base(file))

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		if _, err := tx.Exec(string(content)); err != nil {
			rollbackTx(tx, version)
			return fmt.Errorf("failed to apply %s: %w", file, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			rollbackTx(tx, version)
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		fmt.Printf("Applied: %s\n", version)
	}

	fmt.Println("All migrations applied successfully")
	return nil
}

func migrateDown(db *sql.DB, steps int) error {
	// Get applied migrations in reverse order
	rows, err := db.Query("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT $1", steps)
	if err != nil {
		return err
	}
	defer rows.Close()

	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return err
		}
		versions = append(versions, version)
	}
	// No-partial-results contract (M46 Track C-3b): an iteration error must
	// abort the rollback run — silently rolling back only the versions read
	// before the failure would desync the operator's mental model of how
	// many steps actually ran.
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to enumerate applied migrations: %w", err)
	}

	for _, version := range versions {
		downFile := fmt.Sprintf("migrations/%s.down.sql", version)
		if _, err := os.Stat(downFile); os.IsNotExist(err) {
			return fmt.Errorf("down migration not found: %s", downFile)
		}

		fmt.Printf("Rolling back: %s\n", version)

		content, err := os.ReadFile(downFile)
		if err != nil {
			return err
		}

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		if _, err := tx.Exec(string(content)); err != nil {
			rollbackTx(tx, version)
			return fmt.Errorf("failed to rollback %s: %w", version, err)
		}

		if _, err := tx.Exec("DELETE FROM schema_migrations WHERE version = $1", version); err != nil {
			rollbackTx(tx, version)
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		fmt.Printf("Rolled back: %s\n", version)
	}

	return nil
}

func showStatus(db *sql.DB) error {
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	files, err := filepath.Glob("migrations/*.up.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	fmt.Println("Migration Status:")
	fmt.Println("-----------------")

	for _, file := range files {
		version := extractVersion(file)
		status := "Pending"
		if applied[version] {
			status = "Applied"
		}
		fmt.Printf("%-40s %s\n", version, status)
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
	// would make `up` re-apply migrations that already ran (usually a hard
	// SQL failure, e.g. duplicate table) and make `status` lie.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to enumerate applied migrations: %w", err)
	}

	return applied, nil
}

// parseSteps parses the `migrate down <steps>` argument. It replaces a
// fmt.Sscanf call whose error was discarded (errcheck, M46 Track C-3b) —
// garbage input used to silently run with steps=1, and "2abc" used to parse
// as 2. Destructive commands fail loudly instead of guessing.
func parseSteps(arg string) (int, error) {
	steps, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("steps must be a positive integer: %w", err)
	}
	if steps < 1 {
		return 0, fmt.Errorf("steps must be >= 1, got %d", steps)
	}
	return steps, nil
}

// rollbackTx rolls back a migration transaction after a failed statement.
// The rollback error is secondary (the primary failure is already being
// returned) but must not be silently discarded (errcheck, M46 Track C-3b):
// a failed ROLLBACK usually means the connection is broken and the operator
// should know before retrying.
func rollbackTx(tx *sql.Tx, version string) {
	if err := tx.Rollback(); err != nil {
		log.Printf("warning: rollback of migration %s failed: %v", version, err)
	}
}

func extractVersion(filename string) string {
	base := filepath.Base(filename)
	// Remove .up.sql or .down.sql suffix
	base = strings.TrimSuffix(base, ".up.sql")
	base = strings.TrimSuffix(base, ".down.sql")
	return base
}
