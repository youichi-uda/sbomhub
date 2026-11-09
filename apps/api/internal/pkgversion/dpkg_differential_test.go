package pkgversion

import (
	"errors"
	"math/rand"
	"os/exec"
	"testing"
)

// TestCompareDpkg_DifferentialAgainstDpkg compares 4,000 random pairs with the
// real `dpkg --compare-versions` when dpkg is installed (Debian/Ubuntu hosts
// and CI runners); it is skipped elsewhere. Measured 2026-11-09 with dpkg
// 1.23.7: 1,506 pairs both sides accept, 1,506 agree; ParseDpkg is STRICTER
// than `dpkg --compare-versions` (which only warns about, e.g., an upstream
// version that does not start with a digit), never more lenient — a version
// it refuses keeps the M60 label instead of being compared.
func TestCompareDpkg_DifferentialAgainstDpkg(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg not installed")
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	r := rand.New(rand.NewSource(70)) //nolint:gosec // deterministic test input, not security
	alphabet := []byte("0123456789.~+-:abzAZ")
	gen := func() string {
		b := make([]byte, 1+r.Intn(9))
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		if r.Intn(2) == 0 {
			b[0] = byte('0' + r.Intn(10))
		}
		return string(b)
	}
	run := func(a, op, b string) int {
		err := exec.Command("dpkg", "--compare-versions", "--", a, op, b).Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("dpkg: %v", err)
		}
		return 0
	}
	compared := 0
	for i := 0; i < 4000; i++ {
		a, b := gen(), gen()
		_, ea := ParseDpkg(a)
		_, eb := ParseDpkg(b)
		lt, eq := run(a, "lt", b), run(a, "eq", b)
		dpkgOK := lt != 2 && eq != 2
		if ea == nil && eb == nil && !dpkgOK {
			t.Errorf("ParseDpkg accepts %q / %q, dpkg rejects them", a, b)
			continue
		}
		if ea != nil || eb != nil {
			continue
		}
		want := 1
		switch {
		case lt == 0:
			want = -1
		case eq == 0:
			want = 0
		}
		if got := mustCompare(t, a, b); got != want {
			t.Errorf("CompareDpkg(%q, %q) = %d, dpkg says %d", a, b, got, want)
		}
		compared++
	}
	if compared < 1000 {
		t.Errorf("only %d pairs compared; the generator no longer exercises the comparator", compared)
	}
}

func mustCompare(t *testing.T, a, b string) int {
	t.Helper()
	c, err := CompareDpkg(a, b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
