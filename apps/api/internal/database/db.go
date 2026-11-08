package database

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func Connect(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	return db, nil
}

// catalogueMaxOpenConns sizes the pool ConnectCatalogue returns. Each
// connection is held for ONE autocommit statement (a catalogue INSERT or its
// follow-up id lookup), and a scan sweep issues at most one at a time (its
// database section is serialised — see service.NVDService.persistWorkItem), so
// a handful is enough to keep concurrent sweeps from queueing on it for long.
const catalogueMaxOpenConns = 4

// ConnectCatalogue opens the small, separate pool that
// repository.VulnerabilityRepository.Create writes the global CVE catalogue
// through (M57). It uses the same role and URL as the main pool; what makes it
// a separate pool is only that its connections are never the ones a tenant
// transaction is holding, which is what keeps "hold a tenant tx, then ask for
// a catalogue connection" from deadlocking once every main-pool connection is
// held by such a caller. See VulnerabilityRepository.WithCatalogueDB.
func ConnectCatalogue(databaseURL string) (*sql.DB, error) {
	db, err := Connect(databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(catalogueMaxOpenConns)
	db.SetMaxIdleConns(1)
	return db, nil
}
