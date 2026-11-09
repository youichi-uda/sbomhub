package pkgversion

import (
	"bufio"
	"compress/gzip"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestRPMVerCmp_DifferentialAgainstRPM replays 5,000 random pairs (alphabet
// "0123456789.~^+_-abzAZ", 1-9 characters, Python random seed 70) whose
// ordering was computed by the REAL rpm: `rpm.vercmp(a, b)` from the python3
// bindings of RPM 4.16.1.3 in the almalinux:9 image (sha256:245f8aab832f…),
// recorded 2026-11-09. RPMVerCmp agreed on all 5,000.
func TestRPMVerCmp_DifferentialAgainstRPM(t *testing.T) {
	f, err := os.Open("testdata/rpm-4.16.1.3_vercmp_5000.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(zr)
	n := 0
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) != 3 {
			t.Fatalf("bad line %q", sc.Text())
		}
		want, err := strconv.Atoi(p[2])
		if err != nil {
			t.Fatal(err)
		}
		if got := RPMVerCmp(p[0], p[1]); got != want {
			t.Errorf("RPMVerCmp(%q, %q) = %d, rpm 4.16.1.3 says %d", p[0], p[1], got, want)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 5000 {
		t.Errorf("%d pairs, want 5000", n)
	}
}
