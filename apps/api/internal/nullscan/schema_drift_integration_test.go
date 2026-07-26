//go:build integration

package nullscan

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestSchemaSnapshotDrift regenerates the nullability snapshot from the live
// database (migrations applied) and requires it to be byte-identical to the
// committed schema.json. This is the guard that keeps the hermetic analyzer
// honest: a migration that adds/alters a column without regenerating the
// snapshot fails here.
//
// Where it runs: .github/workflows/nullscan.yml (schema-drift job) boots
// postgres via docker compose, applies migrations as sbomhub_migrator, and
// runs this test with -tags=integration. Locally:
//
//	source <dbenv>  # DATABASE_URL / MIGRATE_DATABASE_URL
//	go test -tags=integration ./internal/nullscan/ -run TestSchemaSnapshotDrift -v
//
// To update the snapshot after a migration:
//
//	go run ./cmd/nullscan -dump-schema   # then commit internal/nullscan/schema.json
func TestSchemaSnapshotDrift(t *testing.T) {
	dsn := os.Getenv("MIGRATE_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("MIGRATE_DATABASE_URL / DATABASE_URL not set; skipping drift guard")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	live, err := DumpSchema(context.Background(), db)
	if err != nil {
		t.Fatalf("DumpSchema: %v", err)
	}
	liveJSON, err := live.MarshalDeterministic()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if string(liveJSON) != string(embeddedSchemaJSON) {
		// Print a compact table-level diff to make the failure actionable
		// without a JSON diff tool.
		committed, err := LoadEmbeddedSchema()
		if err != nil {
			t.Fatalf("committed schema.json unparsable: %v", err)
		}
		for _, name := range live.TableNames() {
			if _, ok := committed.Tables[name]; !ok {
				t.Errorf("table %q exists in DB but not in schema.json", name)
			}
		}
		for _, name := range committed.TableNames() {
			if _, ok := live.Tables[name]; !ok {
				t.Errorf("table %q exists in schema.json but not in DB", name)
			}
		}
		for _, name := range live.TableNames() {
			lc, cc := live.Tables[name], committed.Tables[name]
			if cc == nil {
				continue
			}
			for col, lv := range lc {
				if cv, ok := cc[col]; !ok {
					t.Errorf("%s.%s exists in DB but not in schema.json", name, col)
				} else if cv != lv {
					t.Errorf("%s.%s drifted: DB={nullable:%v type:%q} snapshot={nullable:%v type:%q}",
						name, col, lv.Nullable, lv.Type, cv.Nullable, cv.Type)
				}
			}
			for col := range cc {
				if _, ok := lc[col]; !ok {
					t.Errorf("%s.%s exists in schema.json but not in DB", name, col)
				}
			}
		}
		t.Fatal("schema.json is stale. Regenerate and commit it:\n" +
			"  cd apps/api && go run ./cmd/nullscan -dump-schema\n" +
			"  git add internal/nullscan/schema.json")
	}
}
