package pkgversion

import (
	"errors"
	"testing"
)

// rpmvercmpVectors is EVERY active RPMVERCMP(a, b, want) line of rpm's own
// test suite, tests/rpmvercmp.at,
// https://github.com/rpm-software-management/rpm/blob/master/tests/rpmvercmp.at
// at f8303cf4f40b (retrieved 2026-11-09), transcribed mechanically
// (sed over the file; 91 vectors, the same count as the file). The block the
// file disables with `dnl` ("arguably buggy behaviors", non-ASCII) is not
// asserted: ParseRPMEVR refuses non-ASCII, so those orderings never decide
// anything here.
var rpmvercmpVectors = []struct {
	a, b string
	want int
}{
	{"1.0", "1.0", 0},
	{"1.0", "2.0", -1},
	{"2.0", "1.0", 1},
	{"2.0.1", "2.0.1", 0},
	{"2.0", "2.0.1", -1},
	{"2.0.1", "2.0", 1},
	{"2.0.1a", "2.0.1a", 0},
	{"2.0.1a", "2.0.1", 1},
	{"2.0.1", "2.0.1a", -1},
	{"5.5p1", "5.5p1", 0},
	{"5.5p1", "5.5p2", -1},
	{"5.5p2", "5.5p1", 1},
	{"5.5p10", "5.5p10", 0},
	{"5.5p1", "5.5p10", -1},
	{"5.5p10", "5.5p1", 1},
	{"10xyz", "10.1xyz", -1},
	{"10.1xyz", "10xyz", 1},
	{"xyz10", "xyz10", 0},
	{"xyz10", "xyz10.1", -1},
	{"xyz10.1", "xyz10", 1},
	{"xyz.4", "xyz.4", 0},
	{"xyz.4", "8", -1},
	{"8", "xyz.4", 1},
	{"xyz.4", "2", -1},
	{"2", "xyz.4", 1},
	{"5.5p2", "5.6p1", -1},
	{"5.6p1", "5.5p2", 1},
	{"5.6p1", "6.5p1", -1},
	{"6.5p1", "5.6p1", 1},
	{"6.0.rc1", "6.0", 1},
	{"6.0", "6.0.rc1", -1},
	{"10b2", "10a1", 1},
	{"10a2", "10b2", -1},
	{"1.0aa", "1.0aa", 0},
	{"1.0a", "1.0aa", -1},
	{"1.0aa", "1.0a", 1},
	{"10.0001", "10.0001", 0},
	{"10.0001", "10.1", 0},
	{"10.1", "10.0001", 0},
	{"10.0001", "10.0039", -1},
	{"10.0039", "10.0001", 1},
	{"4.999.9", "5.0", -1},
	{"5.0", "4.999.9", 1},
	{"20101121", "20101121", 0},
	{"20101121", "20101122", -1},
	{"20101122", "20101121", 1},
	{"2_0", "2_0", 0},
	{"2.0", "2_0", 0},
	{"2_0", "2.0", 0},
	{"a", "a", 0},
	{"a+", "a+", 0},
	{"a+", "a_", 0},
	{"a_", "a+", 0},
	{"+a", "+a", 0},
	{"+a", "_a", 0},
	{"_a", "+a", 0},
	{"+_", "+_", 0},
	{"_+", "+_", 0},
	{"_+", "_+", 0},
	{"+", "_", 0},
	{"_", "+", 0},
	{"1.0~rc1", "1.0~rc1", 0},
	{"1.0~rc1", "1.0", -1},
	{"1.0", "1.0~rc1", 1},
	{"1.0~rc1", "1.0~rc2", -1},
	{"1.0~rc2", "1.0~rc1", 1},
	{"1.0~rc1~git123", "1.0~rc1~git123", 0},
	{"1.0~rc1~git123", "1.0~rc1", -1},
	{"1.0~rc1", "1.0~rc1~git123", 1},
	{"1.0^", "1.0^", 0},
	{"1.0^", "1.0", 1},
	{"1.0", "1.0^", -1},
	{"1.0^git1", "1.0^git1", 0},
	{"1.0^git1", "1.0", 1},
	{"1.0", "1.0^git1", -1},
	{"1.0^git1", "1.0^git2", -1},
	{"1.0^git2", "1.0^git1", 1},
	{"1.0^git1", "1.01", -1},
	{"1.01", "1.0^git1", 1},
	{"1.0^20160101", "1.0^20160101", 0},
	{"1.0^20160101", "1.0.1", -1},
	{"1.0.1", "1.0^20160101", 1},
	{"1.0^20160101^git1", "1.0^20160101^git1", 0},
	{"1.0^20160102", "1.0^20160101^git1", 1},
	{"1.0^20160101^git1", "1.0^20160102", -1},
	{"1.0~rc1^git1", "1.0~rc1^git1", 0},
	{"1.0~rc1^git1", "1.0~rc1", 1},
	{"1.0~rc1", "1.0~rc1^git1", -1},
	{"1.0^git1~pre", "1.0^git1~pre", 0},
	{"1.0^git1", "1.0^git1~pre", 1},
	{"1.0^git1~pre", "1.0^git1", -1},
}

func TestRPMVerCmp_UpstreamVectors(t *testing.T) {
	if len(rpmvercmpVectors) != 91 {
		t.Fatalf("%d vectors, want the 91 of rpmvercmp.at", len(rpmvercmpVectors))
	}
	for _, c := range rpmvercmpVectors {
		if got := RPMVerCmp(c.a, c.b); got != c.want {
			t.Errorf("RPMVerCmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// EVR-level behaviour (rpmVersionCompare: epoch, then version, then
// release), with real AlmaLinux / RHEL versions met in M70's OSV data.
func TestCompareRPMEVR(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1:3.0.1-41.el9_0", "1:3.0.1-41.el9_0", 0},
		{"1:3.0.1-41.el9_0", "1:3.0.1-43.el9_0", -1},
		{"1:3.0.7-27.el9", "1:3.0.1-47.el9_1", 1},
		{"1:3.0.7-6.el9_2", "1:3.0.7-27.el9", -1},
		{"3.0.7-27.el9", "1:3.0.1-41.el9_0", -1}, // missing epoch is 0
		{"0:3.0.7-27.el9", "3.0.7-27.el9", 0},
		{"2:1.0-1", "1:9.9-9", 1},
		{"1.0-1.el9", "1.0-1.el9_0", -1},
		{"1.0-1.el9_0", "1.0-1.el9_1", -1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0-1~bootstrap", "1.0-1", -1},
		{"2.17-326.el7_9", "2.17-325.el7_9", 1},
		{"2.17-326.el7_9.3", "2.17-326.el7_9", 1},
	} {
		got, err := CompareRPMEVR(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("CompareRPMEVR(%q, %q) = %d (%v), want %d", c.a, c.b, got, err, c.want)
		}
		back, err := CompareRPMEVR(c.b, c.a)
		if err != nil || back != -c.want {
			t.Errorf("CompareRPMEVR(%q, %q) = %d (%v), want %d (reverse)", c.b, c.a, back, err, -c.want)
		}
	}
}

func TestParseRPMEVR(t *testing.T) {
	for _, c := range []struct {
		in       string
		epoch    uint64
		hasEpoch bool
		v, r     string
	}{
		{"1:3.0.1-41.el9_0", 1, true, "3.0.1", "41.el9_0"},
		{"3.0.7-27.el9", 0, false, "3.0.7", "27.el9"},
		{"0:1.0-1", 0, true, "1.0", "1"},
		{"1.0^git1-1~pre", 0, false, "1.0^git1", "1~pre"},
		{" 1:2.3-4 ", 1, true, "2.3", "4"},
	} {
		e, err := ParseRPMEVR(c.in)
		if err != nil || e.Epoch != c.epoch || e.HasEpoch != c.hasEpoch || e.Version != c.v || e.Release != c.r {
			t.Errorf("ParseRPMEVR(%q) = %+v, %v", c.in, e, err)
		}
	}
	for _, s := range []string{
		"", " ", "1.0", // no release
		"1:1.0", ":1.0-1", "a:1.0-1", "-1:1.0-1", "4294967296:1.0-1", "99999999999999999999:1.0-1", // rpm epochs are uint32 (Codex M70 R43 Low-2)
		"1.0-", "-1", "1:-1", // empty version / release
		"1.0 0-1", "1.0-1 2", "1.0-1:2", "1.0é-1", "1.0-1\x7f",
	} {
		if e, err := ParseRPMEVR(s); err == nil {
			t.Errorf("ParseRPMEVR(%q) = %+v, want an error", s, e)
		} else if !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseRPMEVR(%q): %v does not wrap ErrInvalidVersion", s, err)
		}
		if _, err := CompareRPMEVR(s, "1.0-1"); err == nil {
			t.Errorf("CompareRPMEVR(%q, 1.0-1) did not fail", s)
		}
	}
}

func TestRPMEVRString(t *testing.T) {
	for _, s := range []string{"1:3.0.1-41.el9_0", "3.0.7-27.el9"} {
		e, err := ParseRPMEVR(s)
		if err != nil || e.String() != s {
			t.Errorf("String(%q) = %q (%v)", s, e.String(), err)
		}
	}
}

// Codex M70 R43 Low-2: rpm epochs above INT32_MAX up to UINT32_MAX are valid.
func TestParseRPMEVR_Uint32Epoch(t *testing.T) {
	for _, s := range []string{"2147483648:1.0-1", "4294967295:1.0-1"} {
		if _, err := ParseRPMEVR(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if c, err := CompareRPMEVR("4294967295:1.0-1", "2147483648:9.0-1"); err != nil || c <= 0 {
		t.Errorf("compare = %d, %v", c, err)
	}
}
