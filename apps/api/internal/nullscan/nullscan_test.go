package nullscan

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// testSchema mirrors the DDL described in testdata/src/testmod/q/q.go.
func testSchema() *Schema {
	return &Schema{
		GeneratedBy: "nullscan_test.go (in-memory)",
		Tables: map[string]map[string]Column{
			"things": {
				"id":          {Nullable: false, Type: "uuid"},
				"owner_id":    {Nullable: true, Type: "uuid"},
				"name":        {Nullable: false, Type: "text"},
				"description": {Nullable: true, Type: "text"},
				"score":       {Nullable: true, Type: "double precision"},
				"created_at":  {Nullable: false, Type: "timestamp with time zone"},
				"deleted_at":  {Nullable: true, Type: "timestamp with time zone"},
			},
			"refs": {
				"id":       {Nullable: false, Type: "bigint"},
				"thing_id": {Nullable: false, Type: "uuid"},
				"label":    {Nullable: true, Type: "text"},
			},
		},
		Views: map[string]map[string]Column{},
	}
}

func runTestdataAnalysis(t *testing.T) *Report {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("testdata", "src", "testmod"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Analyze(Config{
		Dir:      dir,
		Patterns: []string{"./..."},
		Schema:   testSchema(),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return rep
}

// findingSummary flattens a finding into "kind|identity|scantype-suffix" for
// order-insensitive comparison.
func findingSummary(f Finding) string {
	id := f.SQLExpr
	if f.Table != "" && f.Col != "" {
		id = f.Table + "." + f.Col
	}
	typ := f.ScanType
	if i := strings.LastIndex(typ, "/"); i >= 0 {
		typ = typ[i+1:]
	}
	return fmt.Sprintf("%s|%s|%s", f.Kind, id, typ)
}

func TestAnalyzeTestdataCorpus(t *testing.T) {
	rep := runTestdataAnalysis(t)

	byFunc := map[string][]string{}
	for _, f := range append(append(append([]Finding{}, rep.Violations...), rep.Warnings...), rep.Unanalyzable...) {
		byFunc[f.Func] = append(byFunc[f.Func], findingSummary(f))
	}

	// expectations: func -> exact multiset of finding summaries.
	// A substring match per element keeps reasons/types readable.
	expect := map[string][]string{
		"simpleViolation":       {"violation|things.description|string"},
		"coalesceOK":            nil,
		"pointerAndNullTypesOK": nil,
		"leftJoinNullSide":      {"violation|refs.id|int64"},
		"innerJoinSafe":         nil,
		"aggregateNull":         {"violation|MAX(score)|float64"},
		"groupedAggregate":      {"violation|MAX(score)|float64"},
		"caseWithoutElse":       {"violation|CASE WHEN"},
		"countMismatch":         {"unanalyzable|"},
		"dynamicSQL":            {"unanalyzable|"},
		"sprintfTail":           {"violation|things.description|string"},
		"conditionalWhere":      {"violation|things.description|string"},
		"uuidSilentZero":        {"warning|things.owner_id|uuid.UUID"},
		"uuidPointerOK":         nil,
		"namedByteSlice":        {"violation|things.description|json.RawMessage"},
		"scannerOK":             nil,
		"returningViolation":    {"violation|things.deleted_at|time.Time"},
		"cteFlow":               {"violation|cte:w.d|string"},
		"subqueryStar":          {"violation|things.description|string"},
		"scalarCountSubquery":   nil,
		"jsonExtraction":        {"violation|"},
		// gemini-r1 #3: first Scan pairs with its own query only
		"rowsVarReuse": {"violation|things.description|string"},
		// gemini-r1 #2: unreadable conditional branch surfaces even though
		// the readable branch matched
		"conditionalDynamicBranch": {"unanalyzable|"},
		// gemini-r2 #2: positional Sprintf verbs must refuse, not mis-map
		"positionalVerb": {"unanalyzable|"},
	}

	for fn, want := range expect {
		got := byFunc[fn]
		if len(got) != len(want) {
			t.Errorf("%s: got %d findings %v, want %d %v", fn, len(got), got, len(want), want)
			continue
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				if strings.Contains(g, w) || strings.HasPrefix(g, w) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: missing expected finding %q in %v", fn, w, got)
			}
		}
	}

	// no findings attributed to functions outside the expectation table
	for fn, got := range byFunc {
		if _, ok := expect[fn]; !ok {
			t.Errorf("unexpected findings in %s: %v", fn, got)
		}
	}

	// the LEFT JOIN violation must carry the outer-join reason
	for _, f := range rep.Violations {
		if f.Func == "leftJoinNullSide" && !strings.Contains(f.Reason, "outer join") {
			t.Errorf("leftJoinNullSide: reason should mention outer join, got %q", f.Reason)
		}
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	rep := runTestdataAnalysis(t)
	if len(rep.Violations) == 0 {
		t.Fatal("corpus should produce violations")
	}

	// current findings against their own baseline => no new
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := rep.WriteBaseline(path, "test"); err != nil {
		t.Fatal(err)
	}
	bl, err := LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := rep.NewAgainst(bl); len(n) != 0 {
		t.Fatalf("expected 0 new findings against own baseline, got %d: %v", len(n), n)
	}

	// empty baseline => everything gated is new
	empty := &Baseline{Version: 1, Entries: map[string]int{}}
	if n := rep.NewAgainst(empty); len(n) != len(rep.Violations)+len(rep.Unanalyzable) {
		t.Fatalf("expected all %d gated findings new against empty baseline, got %d",
			len(rep.Violations)+len(rep.Unanalyzable), len(n))
	}

	// removing one entry => exactly that finding resurfaces
	victim := rep.Violations[0]
	bl2, _ := LoadBaseline(path)
	if bl2.Entries[victim.Key] <= 0 {
		t.Fatalf("baseline missing victim key %q", victim.Key)
	}
	bl2.Entries[victim.Key]--
	if bl2.Entries[victim.Key] == 0 {
		delete(bl2.Entries, victim.Key)
	}
	n := rep.NewAgainst(bl2)
	if len(n) != 1 || n[0].Key != victim.Key {
		t.Fatalf("expected exactly the removed key %q to be new, got %v", victim.Key, n)
	}

	// baseline keys must not contain line numbers (line-shift stability)
	for k := range bl.Entries {
		if strings.Contains(k, ".go:") {
			t.Errorf("baseline key leaks file positions: %q", k)
		}
	}
}
