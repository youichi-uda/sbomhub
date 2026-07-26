package nullscan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Baseline holds the accepted set of finding keys (violations and
// unanalyzable entries) so CI can gate on "no NEW findings" while the
// existing debt is burned down. Keys are line-number-independent
// (pkg|func|table.column|scan-type ...), so unrelated edits do not
// invalidate them. Values are occurrence counts per key.
type Baseline struct {
	Version int            `json:"version"`
	Note    string         `json:"note,omitempty"`
	Entries map[string]int `json:"entries"`
}

// LoadBaseline reads a baseline file; a missing file yields an empty
// baseline (strict mode).
func LoadBaseline(path string) (*Baseline, error) {
	b := &Baseline{Version: 1, Entries: map[string]int{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	if err := json.Unmarshal(data, b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Entries == nil {
		b.Entries = map[string]int{}
	}
	return b, nil
}

// gated returns the findings that participate in the CI gate: violations and
// unanalyzable entries. Warnings (silent-zero uuid scans) are informational.
func (r *Report) gated() []Finding {
	out := make([]Finding, 0, len(r.Violations)+len(r.Unanalyzable))
	out = append(out, r.Violations...)
	out = append(out, r.Unanalyzable...)
	return out
}

// keyCounts aggregates gated findings by baseline key.
func (r *Report) keyCounts() map[string]int {
	m := map[string]int{}
	for _, f := range r.gated() {
		m[f.Key]++
	}
	return m
}

// NewAgainst returns gated findings whose key is absent from the baseline or
// whose per-key count exceeds the baselined count.
func (r *Report) NewAgainst(b *Baseline) []Finding {
	counts := r.keyCounts()
	budget := map[string]int{}
	for k, c := range b.Entries {
		budget[k] = c
	}
	var out []Finding
	for _, f := range r.gated() {
		if counts[f.Key] > budget[f.Key] {
			// consume one budget slot per finding; overflow => new
			if budget[f.Key] > 0 {
				budget[f.Key]--
				counts[f.Key]--
				continue
			}
			out = append(out, f)
		}
	}
	return out
}

// WriteBaseline serializes the current gated findings deterministically.
func (r *Report) WriteBaseline(path, note string) error {
	b := Baseline{Version: 1, Note: note, Entries: r.keyCounts()}
	data, err := json.MarshalIndent(&b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// WriteJSON emits the machine-readable report.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		*Report
		Counts map[string]int `json:"counts"`
	}{
		Report: r,
		Counts: map[string]int{
			"violations":   len(r.Violations),
			"warnings":     len(r.Warnings),
			"unanalyzable": len(r.Unanalyzable),
		},
	})
}

// WriteText emits the human-readable report.
func (r *Report) WriteText(w io.Writer) {
	section := func(title string, fs []Finding) {
		fmt.Fprintf(w, "== %s (%d) ==\n", title, len(fs))
		for _, f := range fs {
			loc := fmt.Sprintf("%s:%d", f.File, f.Line)
			target := f.SQLExpr
			if f.Table != "" && f.Col != "" {
				target = f.Table + "." + f.Col
			}
			fmt.Fprintf(w, "  %s  [%s] arg#%d %s <- %s\n      %s\n", loc, f.Func, f.ArgIndex, f.ScanType, target, f.Reason)
			if f.SQL != "" {
				fmt.Fprintf(w, "      sql: %s\n", f.SQL)
			}
		}
		fmt.Fprintln(w)
	}
	section("VIOLATIONS (nullable value -> NULL-intolerant Go type; 500 on NULL row)", r.Violations)
	section("WARNINGS (NULL scan silently keeps zero value; uuid.UUID class)", r.Warnings)
	section("UNANALYZABLE (analyzer refuses to guess; listed, never skipped)", r.Unanalyzable)
}

// FormatFindingLines renders findings compactly (used for "new vs baseline"
// error output).
func FormatFindingLines(fs []Finding) string {
	var sb strings.Builder
	for _, f := range fs {
		target := f.SQLExpr
		if f.Table != "" && f.Col != "" {
			target = f.Table + "." + f.Col
		}
		fmt.Fprintf(&sb, "  %s:%d [%s] %s arg#%d %s <- %s: %s\n",
			f.File, f.Line, f.Kind, f.Func, f.ArgIndex, f.ScanType, target, f.Reason)
	}
	return sb.String()
}

// SortedKeys is a small helper for deterministic debugging output.
func SortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
