package pkgversion

import (
	"errors"
	"testing"
)

// Test vectors for the dpkg comparator.
//
// Sources (retrieved 2026-11-09):
//
//   - [apt] Debian APT, test/libapt/compareversion_test.cc (every active
//     EXPECT_VERSION; APT's runner also checks each one against
//     `dpkg --compare-versions`), https://github.com/Debian/apt/blob/main/test/libapt/compareversion_test.cc
//     at 6b128124271e.
//   - [dpkg] dpkg, lib/dpkg/t/t-version.c (test_version_compare and
//     test_version_parse), https://github.com/guillemj/dpkg/blob/main/lib/dpkg/t/t-version.c
//     at 7492eb3d9b1e.
//   - [policy] Debian Policy Manual §5.6.12 "Version"
//     (https://www.debian.org/doc/debian-policy/ch-controlfields.html#version):
//     the ordering example "~~, ~~a, ~, the empty part, a", "absence of the
//     debian_revision is equivalent to a debian_revision of 0", and the
//     letters-before-non-letters rule.
//
// Every vector is asserted in both directions.

type cmpCase struct {
	a, b string
	want int
	src  string
}

var dpkgCompareCases = []cmpCase{
	// [apt] Basic
	{"7.6p2-4", "7.6-0", 1, "apt"},
	{"1.0.3-3", "1.0-1", 1, "apt"},
	{"1.3", "1.2.2-2", 1, "apt"},
	{"1.3", "1.2.2", 1, "apt"},
	{"0-pre", "0-pre", 0, "apt"},
	{"0-pre", "0-pree", -1, "apt"},
	{"1.1.6r2-2", "1.1.6r-1", 1, "apt"},
	{"2.6b2-1", "2.6b-2", 1, "apt"},
	{"98.1p5-1", "98.1-pre2-b6-2", -1, "apt"},
	{"0.4a6-2", "0.4-1", 1, "apt"},
	{"1:3.0.5-2", "1:3.0.5.1", -1, "apt"},
	// [apt] Epochs
	{"1:0.4", "10.3", 1, "apt"},
	{"1:1.25-4", "1:1.25-8", -1, "apt"},
	{"0:1.18.36", "1.18.36", 0, "apt"},
	{"1.18.36", "1.18.35", 1, "apt"},
	{"0:1.18.36", "1.18.35", 1, "apt"},
	// [apt] Strangeness
	{"9:1.18.36:5.4-20", "10:0.5.1-22", -1, "apt"},
	{"9:1.18.36:5.4-20", "9:1.18.36:5.5-1", -1, "apt"},
	{"9:1.18.36:5.4-20", " 9:1.18.37:4.3-22", -1, "apt"},
	{"1.18.36-0.17.35-18", "1.18.36-19", 1, "apt"},
	{"1:1.2.13-3", "1:1.2.13-3.1", -1, "apt"},
	{"2.0.7pre1-4", "2.0.7r-1", -1, "apt"},
	{"0:0-0-0", "0-0", 1, "apt"},
	{"0", "0", 0, "apt"},
	{"0", "00", 0, "apt"},
	// [apt] DebianBug (#205960, #573592 = policy 5.6.12)
	{"3.0~rc1-1", "3.0-1", -1, "apt"},
	{"1.0", "1.0-0", 0, "apt"},
	{"0.2", "1.0-0", -1, "apt"},
	{"1.0", "1.0-0+b1", -1, "apt"},
	{"1.0", "1.0-0~", 1, "apt"},
	// [apt] CuptTests
	{"1.2.3", "1.2.3", 0, "apt"},
	{"4.4.3-2", "4.4.3-2", 0, "apt"},
	{"1:2ab:5", "1:2ab:5", 0, "apt"},
	{"7:1-a:b-5", "7:1-a:b-5", 0, "apt"},
	{"57:1.2.3abYZ+~-4-5", "57:1.2.3abYZ+~-4-5", 0, "apt"},
	{"1.2.3", "0:1.2.3", 0, "apt"},
	{"1.2.3", "1.2.3-0", 0, "apt"},
	{"009", "9", 0, "apt"},
	{"009ab5", "9ab5", 0, "apt"},
	{"1.2.3", "1.2.3-1", -1, "apt"},
	{"1.2.3", "1.2.4", -1, "apt"},
	{"1.2.4", "1.2.3", 1, "apt"},
	{"1.2.24", "1.2.3", 1, "apt"},
	{"0.10.0", "0.8.7", 1, "apt"},
	{"3.2", "2.3", 1, "apt"},
	{"1.3.2a", "1.3.2", 1, "apt"},
	{"0.5.0~git", "0.5.0~git2", -1, "apt"},
	{"2a", "21", -1, "apt"},
	{"1.3.2a", "1.3.2b", -1, "apt"},
	{"1:1.2.3", "1.2.4", 1, "apt"},
	{"1:1.2.3", "1:1.2.4", -1, "apt"},
	{"1.2a+~bCd3", "1.2a++", -1, "apt"},
	{"1.2a+~bCd3", "1.2a+~", 1, "apt"},
	{"5:2", "304-2", 1, "apt"},
	{"5:2", "304:2", -1, "apt"},
	{"25:2", "3:2", 1, "apt"},
	{"1:2:123", "1:12:3", -1, "apt"},
	{"1.2-5", "1.2-3-5", -1, "apt"},
	{"5.10.0", "5.005", 1, "apt"},
	{"3a9.8", "3.10.2", -1, "apt"},
	{"3a9.8", "3~10", 1, "apt"},
	{"1.4+OOo3.0.0~", "1.4+OOo3.0.0-4", -1, "apt"},
	{"2.4.7-1", "2.4.7-z", -1, "apt"},
	{"1.002-1+b2", "1.00", 1, "apt"},

	// [dpkg] test_version_compare (DPKG_VERSION_OBJECT(epoch, version, revision))
	{"0:1-1", "0:2-1", -1, "dpkg"},
	{"0:1-1", "0:1-2", -1, "dpkg"},
	{"0:0-0", "0:0-0", 0, "dpkg"},
	{"0:0-00", "0:00-0", 0, "dpkg"},
	{"1:2-3", "1:2-3", 0, "dpkg"},
	{"0:0-0", "1:0-0", -1, "dpkg"},
	{"0:0-a", "0:0-b", -1, "dpkg"},
	{"0:2-1", "0:1-1", 1, "dpkg"},
	// [dpkg] test_version_parse: each string parses to the same version as the object
	{"0", "0:0", 0, "dpkg"},
	{"0:0-0", "0:0-0", 0, "dpkg"},
	{"0:0.0-0.0", "0.0-0.0", 0, "dpkg"},
	{"1:0", "1:0", 0, "dpkg"},
	{"5:1", "5:1", 0, "dpkg"},
	{"0:0-0-0", "0-0-0", 0, "dpkg"},
	{"0:0-0-0-0", "0-0-0-0", 0, "dpkg"},
	{"0:0:0-0", "0:0:0-0", 0, "dpkg"},
	{"0:0:0:0-0", "0:0:0:0-0", 0, "dpkg"},
	{"0:0:0-0-0", "0:0:0-0-0", 0, "dpkg"},
	{"0:0-0:0-0", "0:0-0:0-0", 0, "dpkg"},
	{"0:09azAZ.-+~:-0", "0:09azAZ.-+~:-0", 0, "dpkg"},
	{"0:0-azAZ09.+~", "0:0-azAZ09.+~", 0, "dpkg"},
	{"  \t0:0-1", "0:0-1", 0, "dpkg"},
	{"0:0-1\t  ", "0:0-1", 0, "dpkg"},
	{"\t  0:0-1  \t", "0:0-1", 0, "dpkg"},

	// [policy] §5.6.12: "~~" < "~~a" < "~" < "" < "a", here as revisions and
	// as upstream suffixes.
	{"1.0-~~", "1.0-~~a", -1, "policy"},
	{"1.0-~~a", "1.0-~", -1, "policy"},
	{"1.0-~", "1.0", -1, "policy"},
	{"1.0", "1.0-a", -1, "policy"},
	{"1.0~~", "1.0~~a", -1, "policy"},
	{"1.0~~a", "1.0~", -1, "policy"},
	{"1.0~", "1.0", -1, "policy"},
	{"1.0", "1.0a", -1, "policy"},
	// [policy] letters sort before non-letters, '~' before everything.
	{"1.0a", "1.0+", -1, "policy"},
	{"1.0a", "1.0.", -1, "policy"},
	{"1.0Z", "1.0a", -1, "policy"}, // ASCII order among letters
	{"1.0~rc1", "1.0", -1, "policy"},

	// Real distro versions met in M70's data (Debian / Ubuntu security
	// updates); each ordering was cross-checked with `dpkg --compare-versions`
	// (dpkg 1.22.x on the dev host, 2026-11-09).
	{"1.1.1k-1", "1.1.1k-1+deb11u1", -1, "distro"},
	{"1.1.1k-1+deb11u2", "1.1.1n-0+deb11u1", -1, "distro"},
	{"1.1.1n-0+deb11u5", "1.1.1l-1", 1, "distro"},
	{"1.1.1w-0+deb11u1", "1.1.1w-0+deb11u2", -1, "distro"},
	{"3.0.11-1~deb12u2", "3.0.11-1", -1, "distro"},
	{"1.1.1k-1", "1.1.1k-1", 0, "distro"},
	{"1.1.1k-1", "1.1.1j-1", 1, "distro"},
	{"2.31-13+deb11u5", "2.31-13+b1", 1, "distro"},
	{"2.31-13+b1", "2.31-13", 1, "distro"},
	{"1:1.2.11.dfsg-2+deb11u2", "1.2.13.dfsg-1", 1, "distro"},
	{"1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.3", 1, "distro"},
	{"1.1.1-1ubuntu2.1~18.04.13", "1.1.1-1ubuntu2.1~18.04.9", 1, "distro"},
	{"1.1.1-1ubuntu2.1~18.04.23+esm1", "1.1.1-1ubuntu2.1~18.04.23", 1, "distro"},
	{"5.10.46-4", "5.10.46+4", -1, "distro"},
}

func TestCompareDpkg_Vectors(t *testing.T) {
	for _, c := range dpkgCompareCases {
		got, err := CompareDpkg(c.a, c.b)
		if err != nil {
			t.Errorf("[%s] CompareDpkg(%q, %q): %v", c.src, c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("[%s] CompareDpkg(%q, %q) = %d, want %d", c.src, c.a, c.b, got, c.want)
		}
		back, err := CompareDpkg(c.b, c.a)
		if err != nil || back != -c.want {
			t.Errorf("[%s] CompareDpkg(%q, %q) = %d (%v), want %d (reverse)", c.src, c.b, c.a, back, err, -c.want)
		}
	}
}

// [dpkg] test_version_parse: field-level results.
func TestParseDpkg_Fields(t *testing.T) {
	for _, c := range []struct {
		in                 string
		epoch              int
		hasEpoch           bool
		upstream, revision string
	}{
		{"0", 0, false, "0", ""},
		{"0:0", 0, true, "0", ""},
		{"0:0-0", 0, true, "0", "0"},
		{"0:0.0-0.0", 0, true, "0.0", "0.0"},
		{"1:0", 1, true, "0", ""},
		{"5:1", 5, true, "1", ""},
		{"0:0-0-0", 0, true, "0-0", "0"},
		{"0:0-0-0-0", 0, true, "0-0-0", "0"},
		{"0:0:0-0", 0, true, "0:0", "0"},
		{"0:0:0:0-0", 0, true, "0:0:0", "0"},
		{"0:0:0-0-0", 0, true, "0:0-0", "0"},
		{"0:0-0:0-0", 0, true, "0-0:0", "0"},
		{"0:09azAZ.-+~:-0", 0, true, "09azAZ.-+~:", "0"},
		{"0:0-azAZ09.+~", 0, true, "0", "azAZ09.+~"},
		{"  \t0:0-1", 0, true, "0", "1"},
		{"\t  0:0-1  \t", 0, true, "0", "1"},
		{"1.1.1k-1", 0, false, "1.1.1k", "1"},
		{"1:1.2.11.dfsg-2+deb11u2", 1, true, "1.2.11.dfsg", "2+deb11u2"},
	} {
		v, err := ParseDpkg(c.in)
		if err != nil {
			t.Errorf("ParseDpkg(%q): %v", c.in, err)
			continue
		}
		if v.Epoch != c.epoch || v.HasEpoch != c.hasEpoch || v.Upstream != c.upstream || v.Revision != c.revision {
			t.Errorf("ParseDpkg(%q) = %+v, want epoch=%d hasEpoch=%v upstream=%q revision=%q",
				c.in, v, c.epoch, c.hasEpoch, c.upstream, c.revision)
		}
	}
}

// [dpkg] test_version_parse failures, plus the corresponding Policy rules.
func TestDpkgParseFailures(t *testing.T) {
	bad := []string{
		"", "  ", // empty
		"0:",                           // nothing after the epoch
		":1.0",                         // empty epoch
		"1.0-",                         // empty revision
		"1:0-",                         // empty revision with epoch
		"0:0 0-1",                      // embedded blank
		"-1:0-1",                       // negative epoch
		"999999999999999999999999:0-1", // epoch overflow
		"2147483648:0-1",               // epoch > INT_MAX
		"a:0-0", "A:0-0",               // non-numeric epoch
		"-0", "0:-0", // empty upstream
		"0:abc3-0",  // upstream does not start with a digit
		"abc", "~1", // same, without epoch/revision
		"0:0-0:0", // ':' in the revision
		"1.0é-1",  // non-ASCII
	}
	// Every character dpkg rejects in the upstream version and in the revision.
	for _, c := range "!#@$%&/|\\<>()[]{};,_=*^'" {
		bad = append(bad, "0:0"+string(c)+"a-0")
	}
	for _, c := range "!#@$%&/|\\<>()[]{}:;,_=*^'" {
		bad = append(bad, "0:0-0"+string(c)+"0")
	}
	for _, s := range bad {
		if v, err := ParseDpkg(s); err == nil {
			t.Errorf("ParseDpkg(%q) = %+v, want an error", s, v)
		} else if !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ParseDpkg(%q) error %v does not wrap ErrInvalidVersion", s, err)
		}
		if _, err := CompareDpkg(s, "1.0"); err == nil {
			t.Errorf("CompareDpkg(%q, 1.0) did not fail", s)
		}
		if _, err := CompareDpkg("1.0", s); err == nil {
			t.Errorf("CompareDpkg(1.0, %q) did not fail", s)
		}
	}
	// The largest epoch dpkg accepts is INT_MAX.
	if v, err := ParseDpkg("2147483647:1"); err != nil || v.Epoch != 2147483647 {
		t.Errorf("ParseDpkg(INT_MAX epoch) = %+v, %v", v, err)
	}
}

// Ordering is a total preorder on what parses: spot-check transitivity over a
// chain built from the vectors above.
func TestCompareDpkg_Chain(t *testing.T) {
	chain := []string{"1.0~~", "1.0~~a", "1.0~", "1.0", "1.0-0+b1", "1.0-1", "1.0a", "1.0+", "1.0.1", "1:0.1"}
	for i := range chain {
		for j := range chain {
			got, err := CompareDpkg(chain[i], chain[j])
			want := sign(i - j)
			if err != nil || got != want {
				t.Errorf("CompareDpkg(%q, %q) = %d (%v), want %d", chain[i], chain[j], got, err, want)
			}
		}
	}
}

// [dpkg] test_version_compare builds some versions as objects, bypassing the
// parser (an upstream "a" would not parse): compare those directly.
func TestDpkgCompare_Objects(t *testing.T) {
	for _, c := range []struct {
		a, b Dpkg
		want int
	}{
		{Dpkg{Upstream: "a", Revision: "0"}, Dpkg{Upstream: "b", Revision: "0"}, -1},
		{Dpkg{Upstream: "0", Revision: "a"}, Dpkg{Upstream: "0", Revision: "b"}, -1},
		{Dpkg{Upstream: "0", Revision: "0"}, Dpkg{Epoch: 1, Upstream: "0", Revision: "0"}, -1},
		{Dpkg{Upstream: "0", Revision: "00"}, Dpkg{Upstream: "00", Revision: "0"}, 0},
		{Dpkg{Epoch: 1, Upstream: "2", Revision: "3"}, Dpkg{Epoch: 1, Upstream: "2", Revision: "3"}, 0},
	} {
		if got := c.a.Compare(c.b); got != c.want {
			t.Errorf("%+v vs %+v = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := c.b.Compare(c.a); got != -c.want {
			t.Errorf("%+v vs %+v = %d, want %d (reverse)", c.b, c.a, got, -c.want)
		}
	}
}

func TestDpkgString(t *testing.T) {
	for _, s := range []string{"1.0", "0:1.0", "1:2.3-4", "1.1.1k-1+deb11u1"} {
		v, err := ParseDpkg(s)
		if err != nil || v.String() != s {
			t.Errorf("String(%q) = %q (%v)", s, v.String(), err)
		}
	}
}
