// Command nullscan detects "nullable SQL column scanned into a
// NULL-intolerant Go type" bugs (the B1/B2 class) across the API codebase.
//
// Modes:
//
//	nullscan -dump-schema
//	    Regenerate internal/nullscan/schema.json from the live database
//	    (MIGRATE_DATABASE_URL or DATABASE_URL). Run after adding/altering
//	    migrations, then commit the diff. Guarded against drift by
//	    TestSchemaSnapshotDrift (integration tag) in .github/workflows/nullscan.yml.
//
//	nullscan [flags] [packages...]
//	    Analyze (default packages: ./internal/...). Hermetic: uses the
//	    embedded schema.json, no database needed.
//
// Flags:
//
//	-json             machine-readable output
//	-baseline PATH    tolerate findings recorded in PATH; exit 1 only on NEW ones
//	-write-baseline   write the current findings to -baseline PATH and exit 0
//	-include-tests    also analyze _test.go files
//	-dir PATH         module root (default ".")
//
// Exit codes: 0 clean (or no new findings vs baseline), 1 findings, 2 error.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/lib/pq"

	"github.com/sbomhub/sbomhub/internal/nullscan"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		dumpSchema    = flag.Bool("dump-schema", false, "regenerate schema.json from the live DB and exit")
		schemaOut     = flag.String("schema-out", filepath.Join("internal", "nullscan", "schema.json"), "output path for -dump-schema (relative to -dir)")
		jsonOut       = flag.Bool("json", false, "emit machine-readable JSON")
		baselinePath  = flag.String("baseline", "", "baseline file: only NEW findings fail the run")
		writeBaseline = flag.Bool("write-baseline", false, "write current findings to -baseline and exit")
		includeTests  = flag.Bool("include-tests", false, "also analyze _test.go files")
		dir           = flag.String("dir", ".", "module root directory")
	)
	flag.Parse()

	if *dumpSchema {
		if err := doDumpSchema(*dir, *schemaOut); err != nil {
			fmt.Fprintf(os.Stderr, "nullscan: %v\n", err)
			return 2
		}
		return 0
	}

	schema, err := nullscan.LoadEmbeddedSchema()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nullscan: %v\n", err)
		return 2
	}

	patterns := flag.Args()
	if len(patterns) == 0 {
		patterns = []string{"./internal/..."}
	}
	rep, err := nullscan.Analyze(nullscan.Config{
		Dir:          *dir,
		Patterns:     patterns,
		IncludeTests: *includeTests,
		Schema:       schema,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nullscan: %v\n", err)
		return 2
	}

	if *writeBaseline {
		if *baselinePath == "" {
			fmt.Fprintln(os.Stderr, "nullscan: -write-baseline requires -baseline PATH")
			return 2
		}
		if err := rep.WriteBaseline(*baselinePath,
			"Known pre-existing nullscan findings (violations + unanalyzable). CI fails only on entries not covered here. Shrink this file in fix waves; target is an empty entries map."); err != nil {
			fmt.Fprintf(os.Stderr, "nullscan: write baseline: %v\n", err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "nullscan: wrote baseline with %d violations + %d unanalyzable to %s\n",
			len(rep.Violations), len(rep.Unanalyzable), *baselinePath)
		return 0
	}

	if *jsonOut {
		if err := rep.WriteJSON(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "nullscan: %v\n", err)
			return 2
		}
	} else {
		rep.WriteText(os.Stdout)
	}

	if *baselinePath != "" {
		bl, err := nullscan.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nullscan: %v\n", err)
			return 2
		}
		newFindings := rep.NewAgainst(bl)
		if len(newFindings) > 0 {
			fmt.Fprintf(os.Stderr, "nullscan: %d NEW finding(s) not covered by baseline %s:\n%s",
				len(newFindings), *baselinePath, nullscan.FormatFindingLines(newFindings))
			fmt.Fprintln(os.Stderr, "Fix them (COALESCE the column or use a NULL-tolerant scan target),")
			fmt.Fprintln(os.Stderr, "or — only for pre-existing debt being tracked deliberately — regenerate the baseline:")
			fmt.Fprintln(os.Stderr, "  go run ./cmd/nullscan -baseline internal/nullscan/baseline.json -write-baseline ./internal/...")
			return 1
		}
		return 0
	}

	if len(rep.Violations) > 0 || len(rep.Unanalyzable) > 0 {
		return 1
	}
	return 0
}

func doDumpSchema(dir, out string) error {
	dsn := os.Getenv("MIGRATE_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		return fmt.Errorf("-dump-schema needs MIGRATE_DATABASE_URL or DATABASE_URL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	schema, err := nullscan.DumpSchema(context.Background(), db)
	if err != nil {
		return err
	}
	data, err := schema.MarshalDeterministic()
	if err != nil {
		return err
	}
	path := out
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, out)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "nullscan: wrote %s (%d tables, %d views)\n", path, len(schema.Tables), len(schema.Views))
	return nil
}
