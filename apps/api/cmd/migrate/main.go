package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
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

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://sbomhub:sbomhub@localhost:5432/sbomhub?sslmode=disable"
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
			fmt.Sscanf(os.Args[2], "%d", &steps)
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
			tx.Rollback()
			return fmt.Errorf("failed to apply %s: %w", file, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", version); err != nil {
			tx.Rollback()
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
			tx.Rollback()
			return fmt.Errorf("failed to rollback %s: %w", version, err)
		}

		if _, err := tx.Exec("DELETE FROM schema_migrations WHERE version = $1", version); err != nil {
			tx.Rollback()
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

	return applied, nil
}

func extractVersion(filename string) string {
	base := filepath.Base(filename)
	// Remove .up.sql or .down.sql suffix
	base = strings.TrimSuffix(base, ".up.sql")
	base = strings.TrimSuffix(base, ".down.sql")
	return base
}
