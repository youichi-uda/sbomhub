package reachability

// Divergence guard for the VENDORED analyzer sources — BACKEND side mirror of
// sbomhub-cli/internal/reachability/vendor_sync_test.go (M45 Wave 3, C4a).
//
// types.go, go_analyzer.go and npm_analyzer.go in this package are the
// originals; the CLI carries faithful copies (see the vendoring docstring in
// types.go). The sync contract is: apart from the header comment block, the
// file bodies are byte-identical across the two repos. This file enforces
// that contract from the backend side so an edit applied to only one copy —
// or a body edit that forgets to update the SHA pin — fails loudly on the
// next `go test ./...`.
//
// Two complementary checks (see vendored.sha256's header for the full
// what-it-proves discussion):
//
//   - TestVendoredAnalyzerMatchesPin: recomputes each file's normalised-body
//     SHA-256 and compares against vendored.sha256. Needs NO sibling repo, so
//     it runs in the backend's solo CI too — tamper-evident against "edited a
//     vendored file body without updating the pin".
//   - TestVendoredAnalyzerInSyncWithCLI: byte-compares the normalised bodies
//     against the CLI copies. Requires the sbom-all workspace layout (the
//     sbomhub-cli repo checked out next to sbomhub); skips otherwise. This is
//     the only check that proves true cross-repo equivalence.
//
// The _test.go files and testdata/ fixtures are intentionally divergent and
// are NOT covered (only the files in vendoredFiles are compared/pinned).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// vendoredFiles lists the files under the sync contract. Keep in sync with
// the vendoring note in types.go if more analyzer files are ever copied.
var vendoredFiles = []string{"types.go", "go_analyzer.go", "npm_analyzer.go"}

// stripVendorHeader returns the comparable body of a vendored source file:
// the `package ` clause line plus everything from the first non-blank,
// non-`//`-comment line after the package clause to EOF. Leading header
// comments (before `package`) and the contiguous comment/blank block
// immediately following the package clause are dropped — those regions
// intentionally differ between the backend original and the CLI copy.
//
// This MUST stay identical to the CLI's stripVendorHeader so both repos'
// pins and byte comparisons agree.
func stripVendorHeader(src string) (string, error) {
	lines := strings.Split(src, "\n")

	pkgIdx := -1
	for i, l := range lines {
		if strings.HasPrefix(l, "package ") {
			pkgIdx = i
			break
		}
	}
	if pkgIdx == -1 {
		return "", fmt.Errorf("no `package ` clause found")
	}

	// Skip the post-package header block: contiguous blank or //-comment
	// lines. The first remaining line is the start of the body proper.
	body := pkgIdx + 1
	for body < len(lines) {
		trimmed := strings.TrimSpace(lines[body])
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			body++
			continue
		}
		break
	}
	if body >= len(lines) {
		return "", fmt.Errorf("no body found after the package clause")
	}

	return lines[pkgIdx] + "\n" + strings.Join(lines[body:], "\n"), nil
}

// firstDiffLine reports the 1-based line number (within the normalised
// bodies) and the differing line pair of the first mismatch, for the
// failure message. Returns 0 if the bodies are equal.
func firstDiffLine(a, b string) (int, string, string) {
	al := strings.Split(a, "\n")
	bl := strings.Split(b, "\n")
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	for i := 0; i < n; i++ {
		if al[i] != bl[i] {
			return i + 1, al[i], bl[i]
		}
	}
	if len(al) != len(bl) {
		la, lb := "<EOF>", "<EOF>"
		if n < len(al) {
			la = al[n]
		}
		if n < len(bl) {
			lb = bl[n]
		}
		return n + 1, la, lb
	}
	return 0, "", ""
}

// vendoredBodyHash returns the hex SHA-256 of a vendored source file's
// normalised body (stripVendorHeader), matching how vendored.sha256 is
// generated.
func vendoredBodyHash(src string) (string, error) {
	body, err := stripVendorHeader(src)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:]), nil
}

// parsePinFile parses vendored.sha256 into filename -> expected hex hash.
// Blank lines and '#'-prefixed comment lines are ignored.
func parsePinFile(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed pin line %q: want '<sha256>  <filename>'", line)
		}
		out[fields[1]] = fields[0]
	}
	return out, nil
}

// TestVendoredAnalyzerMatchesPin fails if any vendored source file's
// normalised-body SHA-256 has drifted from the pinned value in
// vendored.sha256 — i.e. someone edited a vendored file without updating the
// pin (or vice versa). Needs no sibling repo, so it also runs in solo CI.
func TestVendoredAnalyzerMatchesPin(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the vendored sources")
	}
	dir := filepath.Dir(thisFile)

	pinRaw, err := os.ReadFile(filepath.Join(dir, "vendored.sha256"))
	if err != nil {
		t.Fatalf("read pin file: %v", err)
	}
	pinned, err := parsePinFile(string(pinRaw))
	if err != nil {
		t.Fatalf("parse pin file: %v", err)
	}

	for _, name := range vendoredFiles {
		want, present := pinned[name]
		if !present {
			t.Errorf("vendored.sha256 has no pin entry for %s", name)
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		got, err := vendoredBodyHash(string(src))
		if err != nil {
			t.Errorf("hash %s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("vendored %s normalised-body SHA-256 has drifted from the "+
				"pin in vendored.sha256:\n  pinned: %s\n  actual: %s\n\n"+
				"If you intentionally changed the analyzer: apply the SAME diff "+
				"to BOTH repo copies, then update the '%s' line in vendored.sha256 "+
				"in BOTH repos to the actual hash above. If you did NOT mean to "+
				"change it, revert your edit.", name, want, got, name)
		}
	}

	// A pin entry with no matching vendored file means the two lists drifted.
	for name := range pinned {
		found := false
		for _, v := range vendoredFiles {
			if v == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vendored.sha256 pins unknown file %q not in vendoredFiles", name)
		}
	}
}

// TestVendoredAnalyzerInSyncWithCLI fails if the vendored analyzer sources in
// this package have drifted from the CLI copies in
// sbomhub-cli/internal/reachability/ (header comments excluded, see
// stripVendorHeader). It is the backend-side mirror of the CLI's
// TestVendoredAnalyzerInSyncWithBackend and requires the sbom-all workspace
// layout; it skips when the sibling CLI repo is not checked out.
func TestVendoredAnalyzerInSyncWithCLI(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed; cannot locate the vendored sources")
	}
	backendDir := filepath.Dir(thisFile)
	// backendDir = .../sbom-all/sbomhub/apps/api/internal/service/reachability
	// Six parents reach the sbom-all workspace root, then descend into the CLI.
	cliDir := filepath.Clean(filepath.Join(
		backendDir, "..", "..", "..", "..", "..", "..",
		"sbomhub-cli", "internal", "reachability"))

	if _, err := os.Stat(cliDir); err != nil {
		t.Skipf("sibling CLI repo not found at %s (%v) — this is a "+
			"local-dev-only divergence guard: it needs the sbom-all "+
			"workspace layout with the sbomhub-cli repo checked out next to "+
			"sbomhub. The backend CI checks out sbomhub alone, so skipping "+
			"there is expected (the SHA pin still guards this repo).",
			cliDir, err)
	}

	for _, name := range vendoredFiles {
		t.Run(name, func(t *testing.T) {
			backendPath := filepath.Join(backendDir, name)
			cliPath := filepath.Join(cliDir, name)

			backendSrc, err := os.ReadFile(backendPath)
			if err != nil {
				t.Fatalf("read backend original %s: %v", backendPath, err)
			}
			cliSrc, err := os.ReadFile(cliPath)
			if err != nil {
				t.Fatalf("read CLI copy %s: %v", cliPath, err)
			}

			backendBody, err := stripVendorHeader(string(backendSrc))
			if err != nil {
				t.Fatalf("normalise backend original %s: %v", backendPath, err)
			}
			cliBody, err := stripVendorHeader(string(cliSrc))
			if err != nil {
				t.Fatalf("normalise CLI copy %s: %v", cliPath, err)
			}

			if backendBody != cliBody {
				line, bl, cl := firstDiffLine(backendBody, cliBody)
				t.Errorf("vendored %s has drifted between the backend original "+
					"and the CLI copy (first difference at normalised-body line "+
					"%d):\n  backend (%s):\n    %q\n  CLI     (%s):\n    %q\n\n"+
					"Recovery: the two copies must stay byte-identical apart "+
					"from their header comment blocks. Apply the SAME diff to "+
					"BOTH copies in a single change, and regenerate vendored.sha256 "+
					"in BOTH repos; do not let either side evolve alone.",
					name, line, backendPath, bl, cliPath, cl)
			}
		})
	}
}
