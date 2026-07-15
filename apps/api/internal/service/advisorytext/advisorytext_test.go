package advisorytext

import (
	"encoding/json"
	"testing"
)

// TestTruncate pins the byte-exact truncation used across the triage and
// CRA prompt builders: strings at or under the limit pass through
// unchanged, over-limit strings are cut to n bytes and get the
// "...(truncated)" marker appended (so the prompt reader knows the value
// was elided rather than genuinely short).
func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"under_limit", "hello", 10, "hello"},
		{"at_limit", "hello", 5, "hello"},
		{"one_over", "hello", 4, "hell...(truncated)"},
		{"empty", "", 0, ""},
		{"zero_n_nonempty", "abc", 0, "...(truncated)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate(tc.s, tc.n); got != tc.want {
				t.Fatalf("Truncate(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

// TestJSONArrayEmpty pins the content-absence predicate for a single JSON
// array payload: nil / empty bytes, JSON null, and the (optionally
// whitespace-padded) empty-array literal all count as absent; any other
// shape — including a foreign non-array shape — counts as content.
func TestJSONArrayEmpty(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"nil", nil, true},
		{"empty_bytes", json.RawMessage(``), true},
		{"empty_array", json.RawMessage(`[]`), true},
		{"padded_empty_array", json.RawMessage(` [] `), true},
		{"json_null", json.RawMessage(`null`), true},
		{"populated_array", json.RawMessage(`["a"]`), false},
		{"multi_element", json.RawMessage(`[1,2]`), false},
		{"foreign_object", json.RawMessage(`{"x":1}`), false},
		{"foreign_scalar", json.RawMessage(`"str"`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := JSONArrayEmpty(tc.raw); got != tc.want {
				t.Fatalf("JSONArrayEmpty(%q) = %v, want %v", string(tc.raw), got, tc.want)
			}
		})
	}
}

// TestContentFree pins the row-level content-free predicate shared by the
// triage and CRA dropContentFreeExcerpts filters: a row is content-free
// iff RawExcerpt is empty AND every supplied structured array is empty.
// Any single populated field (excerpt or array), or a foreign-shaped
// array, keeps the row (lenient, mirroring the repository read).
func TestContentFree(t *testing.T) {
	empty := json.RawMessage(`[]`)
	cases := []struct {
		name    string
		excerpt string
		arrays  []json.RawMessage
		want    bool
	}{
		{"all_empty_literal_arrays", "", []json.RawMessage{empty, empty, empty, empty}, true},
		{"nil_arrays", "", []json.RawMessage{nil, nil, nil, nil}, true},
		{"null_and_padded", "", []json.RawMessage{json.RawMessage(`null`), json.RawMessage(` [] `), empty, empty}, true},
		{"no_arrays_empty_excerpt", "", nil, true},
		{"raw_excerpt_only", "buffer overflow", []json.RawMessage{empty, empty, empty, empty}, false},
		{"first_array_populated", "", []json.RawMessage{json.RawMessage(`["pkg.Foo"]`), empty, empty, empty}, false},
		{"last_array_populated", "", []json.RawMessage{empty, empty, empty, json.RawMessage(`["GODEBUG"]`)}, false},
		{"foreign_shape_counts_as_content", "", []json.RawMessage{json.RawMessage(`{"not":"array"}`), empty, empty, empty}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContentFree(tc.excerpt, tc.arrays...); got != tc.want {
				t.Fatalf("ContentFree(%q, %v) = %v, want %v", tc.excerpt, tc.arrays, got, tc.want)
			}
		})
	}
}

// TestRenderVulnFuncs_UnderBudgetBytePassthrough pins the prompt_hash
// stability contract: a payload whose raw byte length is at or under the
// budget is returned verbatim (no reserialization, no marker), so the
// common small case hashes identically to the stored bytes.
func TestRenderVulnFuncs_UnderBudgetBytePassthrough(t *testing.T) {
	cases := []string{
		`[]`,
		`["Parse","Unmarshal"]`,
		`["a.B","c.D","e.F"]`,
		`{"not":"an array but under budget"}`, // foreign shape still passes through untouched when small
	}
	for _, raw := range cases {
		if len(raw) > VulnFuncsPromptBudget {
			t.Fatalf("test fixture %q exceeds budget %d; pick a smaller payload", raw, VulnFuncsPromptBudget)
		}
		if got := RenderVulnFuncs(json.RawMessage(raw), VulnFuncsPromptBudget); got != raw {
			t.Fatalf("RenderVulnFuncs(%q) = %q, want byte-identical passthrough", raw, got)
		}
	}
}

// TestRenderVulnFuncs_AtBudgetBoundary pins that a payload whose length
// exactly equals the budget still passes through (the check is `<=`).
func TestRenderVulnFuncs_AtBudgetBoundary(t *testing.T) {
	raw := `["aaaa","bbbb"]` // len 15
	if got := RenderVulnFuncs(json.RawMessage(raw), len(raw)); got != raw {
		t.Fatalf("at-budget payload should pass through: got %q want %q", got, raw)
	}
}

// TestRenderVulnFuncs_OverBudgetKeepsWholeElements pins the elision
// behaviour: an over-budget string array keeps whole JSON elements until
// the budget is spent, closes the bracket, and appends " …(+N more)" for
// the elided tail so the model knows the list is incomplete.
func TestRenderVulnFuncs_OverBudgetKeepsWholeElements(t *testing.T) {
	raw := `["aaaa","bbbb","cccc"]` // len 22
	got := RenderVulnFuncs(json.RawMessage(raw), 10)
	want := `["aaaa"] …(+2 more)`
	if got != want {
		t.Fatalf("RenderVulnFuncs over budget = %q, want %q", got, want)
	}
}

// TestRenderVulnFuncs_OverBudgetForeignShapeFallsBackToTruncate pins the
// lenient fallback: an over-budget payload that does NOT parse as a string
// array degrades to the plain byte Truncate used elsewhere in the prompt.
func TestRenderVulnFuncs_OverBudgetForeignShapeFallsBackToTruncate(t *testing.T) {
	raw := `{"aaaaaaaaaaaaaaa":1}` // len 20, not a []string
	got := RenderVulnFuncs(json.RawMessage(raw), 10)
	want := Truncate(raw, 10)
	if got != want {
		t.Fatalf("foreign over-budget shape = %q, want Truncate fallback %q", got, want)
	}
	if want != `{"aaaaaaaa...(truncated)` {
		t.Fatalf("Truncate fallback sanity = %q", want)
	}
}

// TestVulnFuncsPromptBudget pins the shared budget constant value so a
// silent drift cannot desync the triage and CRA prompt renders.
func TestVulnFuncsPromptBudget(t *testing.T) {
	if VulnFuncsPromptBudget != 800 {
		t.Fatalf("VulnFuncsPromptBudget = %d, want 800", VulnFuncsPromptBudget)
	}
}
