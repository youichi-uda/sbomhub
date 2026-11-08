package service

import "testing"

// M60 self-review (before Codex R9): among pre-release qualifiers only the
// chain alpha < beta < rc is ordered the same by SemVer (lexical), Maven and
// PEP 440. "dev" is earliest in PEP 440 but sorts after "beta" lexically;
// "pre"/"preview" are aliases of "rc" in PEP 440 but sort before it
// lexically; "a" vs "alpha" are equal in PEP 440 and differ in SemVer. Those
// pairs are undecidable.
func TestM60SelfReview_PreReleaseOrderOnlyWhereSchemesAgree(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.0-alpha1", "2.0-beta1", -1},
		{"2.0-beta9", "2.0-rc1", -1},
		{"2.0a1", "2.0b1", -1},
		{"2.0b2", "2.0rc1", -1},
		{"2.0-rc1", "2.0-rc2", -1},
		{"2.0-snapshot", "2.0", -1}, // any pre-release vs the release: agreed
	} {
		if c, ok := compareVersions(tc.a, tc.b); !ok || c != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d,%v want %d", tc.a, tc.b, c, ok, tc.want)
		}
	}
	for _, tc := range []struct{ a, b string }{
		{"2.0-dev", "2.0-alpha"},
		{"2.0-pre1", "2.0-rc1"},
		{"2.0-preview", "2.0-rc"},
		{"2.0-cr1", "2.0-rc1"},
		{"2.0a1", "2.0-alpha1"},
		{"2.0-snapshot", "2.0-rc1"},
		{"9.0.0-M1", "9.0.0-RC1"},
	} {
		if c, ok := compareVersions(tc.a, tc.b); ok {
			t.Errorf("compareVersions(%q,%q) = %d decided; want undecidable", tc.a, tc.b, c)
		}
	}
}
