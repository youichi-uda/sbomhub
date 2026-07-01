// Tests for the toolchain alignment lint (F243, M16-2 #104).
//
// Every scenario points `run` at a self-contained testdata fixture that
// stages a miniature repo root (apps/api/go.mod plus whichever
// downstream files are relevant to the case). The fixtures are
// intentionally tiny — the point is to exercise the alignment rule for
// each layer independently, not to reproduce a full sbomhub tree.
//
// Fixtures kept in `testdata/` (Go's special path the toolchain ignores
// for build) and pointed at via `--repo-root testdata/<fixture>`:
//
//	good_all_aligned/                    — go.mod 1.26.4 + Dockerfile 1.26.4 + workflow 1.26
//	                                       → clean, exit 0
//	bad_dockerfile_drift/                — go.mod 1.26.4 + Dockerfile 1.25.8
//	                                       → drift, exit 1
//	bad_workflow_drift/                  — go.mod 1.26.4 + workflow 1.24
//	                                       → drift, exit 1
//	bad_tools_gomod_drift/               — go.mod 1.26.4 + tools/lint-migration-rls
//	                                       toolchain 1.25.0 → drift, exit 1
//	bad_apps_service_dockerfile_drift/   — F247 (M16-2 Phase D R2): go.mod 1.26.4 +
//	                                       apps/newsvc/Dockerfile 1.25.8 (drift) +
//	                                       apps/api/Dockerfile 1.26.4 (aligned) +
//	                                       apps/web/Dockerfile FROM node: (skipped) +
//	                                       packages/mcp-server/Dockerfile FROM node:
//	                                       (skipped). Pins the widened glob
//	                                       (apps/*/Dockerfile* + packages/*/Dockerfile*)
//	                                       and the FROM-golang: silent-skip.
//	                                       → drift, exit 1
//
// We also exercise the tool against the real repo root
// (`../../` from this package) as a smoke test — a refactor that
// accidentally flags a currently-clean pin should be caught at PR time.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runLint drives the package-level `run` function with stdout/stderr
// buffers so assertions can inspect the produced text. Mirrors the
// CLI entry point's argv shape (no program name).
func runLint(t *testing.T, args ...string) (exit int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	exit = run(args, &outBuf, &errBuf)
	return exit, outBuf.String(), errBuf.String()
}

// TestFixtures walks the four scripted testdata fixtures and pins the
// per-fixture exit code + presence of the load-bearing substrings in
// the output. The intent is that any future refactor of the detection
// rule or the output format must consciously update the assertions
// here — silent output changes would break the CI log scrapers that
// downstream tooling (Codex review, PR comments) may key on.
func TestFixtures(t *testing.T) {
	cases := []struct {
		name              string
		fixture           string
		wantExit          int
		wantStdoutContain []string
		wantStderrContain []string
	}{
		{
			name:     "good_all_aligned exits 0 with ok summary",
			fixture:  "good_all_aligned",
			wantExit: 0,
			wantStdoutContain: []string{
				"lint-toolchain-alignment: ok",
				// Truth version appears verbatim so operators can grep
				// the log to confirm which patch was in effect at CI time.
				"1.26.4",
				// A minor-precision workflow pin (1.26) against a
				// patch-precision truth (1.26.4) is legal — the ok
				// summary should not surface it as a warning.
				"aligned",
			},
		},
		{
			name:     "bad_dockerfile_drift exits 1 with file + expected + actual",
			fixture:  "bad_dockerfile_drift",
			wantExit: 1,
			wantStdoutContain: []string{
				"drift: Dockerfile",
				"apps/api/Dockerfile",
				"expected: 1.26.4",
				"actual:   1.25.8",
			},
			wantStderrContain: []string{
				"FAIL",
				"drift from apps/api/go.mod",
			},
		},
		{
			name:     "bad_workflow_drift exits 1 with workflow path + expected + actual",
			fixture:  "bad_workflow_drift",
			wantExit: 1,
			wantStdoutContain: []string{
				"drift: workflow",
				".github/workflows/x.yml",
				"expected: 1.26.4",
				// Workflow pins may be minor-precision, so the reported
				// `actual` echoes back whatever the file wrote (1.24
				// here — a two-minor drift from truth 1.26).
				"actual:   1.24",
			},
			wantStderrContain: []string{
				"FAIL",
			},
		},
		{
			name:     "bad_tools_gomod_drift exits 1 with tools go.mod path + expected + actual",
			fixture:  "bad_tools_gomod_drift",
			wantExit: 1,
			wantStdoutContain: []string{
				"drift: tools go.mod",
				"tools/lint-migration-rls/go.mod",
				"expected: 1.26.4",
				"actual:   1.25.0",
			},
			wantStderrContain: []string{
				"FAIL",
			},
		},
		{
			// F247 (M16-2 Phase D R2): the pre-F247 tool only globbed
			// `apps/api/Dockerfile` + `docker/Dockerfile*`, so a future
			// `apps/newsvc/Dockerfile` or `packages/<pkg>/Dockerfile`
			// would silently skip. Post-F247 the glob is widened to
			// `apps/*/Dockerfile*` + `packages/*/Dockerfile*` +
			// `docker/Dockerfile*`, and this fixture proves both the
			// widened catch (apps/newsvc/Dockerfile is picked up and
			// flagged) AND the FROM-golang: silent-skip
			// (apps/web/Dockerfile + packages/mcp-server/Dockerfile
			// use `FROM node:` and produce zero findings — a false-
			// positive here would immediately show up as an unexpected
			// second drift entry).
			name:     "bad_apps_service_dockerfile_drift exits 1 with widened glob + FROM-golang filter",
			fixture:  "bad_apps_service_dockerfile_drift",
			wantExit: 1,
			wantStdoutContain: []string{
				"drift: Dockerfile",
				"apps/newsvc/Dockerfile",
				"expected: 1.26.4",
				"actual:   1.25.8",
			},
			wantStderrContain: []string{
				"FAIL",
				// Sanity: exactly one drift emitted — the node-based
				// Dockerfiles under apps/web and packages/mcp-server
				// must NOT produce findings, so the FAIL header
				// reports 1 pin drift, not 2 or 3.
				"1 Go toolchain pin(s) drift",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join("testdata", tc.fixture)
			exit, stdout, stderr := runLint(t, "--repo-root", root)
			if exit != tc.wantExit {
				t.Fatalf("exit = %d, want %d; stdout=%q stderr=%q",
					exit, tc.wantExit, stdout, stderr)
			}
			for _, want := range tc.wantStdoutContain {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout missing %q; got: %s", want, stdout)
				}
			}
			for _, want := range tc.wantStderrContain {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr missing %q; got: %s", want, stderr)
				}
			}
		})
	}
}

// TestGoodFixture_Verbose asserts the --verbose output on the happy
// path lists every cross-checked file. The verbose summary is what
// orchestrators grep for when diagnosing a suspected drift, so its
// contents are part of the contract.
func TestGoodFixture_Verbose(t *testing.T) {
	exit, stdout, stderr := runLint(t, "--repo-root", filepath.Join("testdata", "good_all_aligned"), "--verbose")
	if exit != 0 {
		t.Fatalf("expected exit 0, got %d; stderr=%q", exit, stderr)
	}
	wantSubstrings := []string{
		"checked: Dockerfile",
		"apps/api/Dockerfile",
		"checked: workflow",
		".github/workflows/x.yml",
		"go-version: 1.26",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(stdout, want) {
			t.Errorf("verbose stdout missing %q; got: %s", want, stdout)
		}
	}
}

// TestBadRepoRoot asserts that a --repo-root without a valid
// apps/api/go.mod exits with the config-error code (2), NOT the drift
// code (1). CI must be able to distinguish a broken setup (missing
// truth) from a real regression (pin drift).
func TestBadRepoRoot(t *testing.T) {
	exit, _, stderr := runLint(t, "--repo-root", "/nonexistent/repo/root")
	if exit != 2 {
		t.Fatalf("expected exit 2 (config error), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "read truth source") {
		t.Errorf("expected 'read truth source' in stderr, got: %s", stderr)
	}
}

// TestMissingToolchainDirective asserts that a truth-source go.mod
// without a `toolchain goX.Y.Z` line is rejected as a config error.
// A minor-precision truth (`go 1.26` alone) cannot be cross-checked
// against patch-precision downstream pins, so the tool refuses to
// silently degrade the alignment invariant.
func TestMissingToolchainDirective(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "apps", "api")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "module foo\n\ngo 1.26\n"
	if err := os.WriteFile(filepath.Join(sub, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	exit, _, stderr := runLint(t, "--repo-root", dir)
	if exit != 2 {
		t.Fatalf("expected exit 2 (missing toolchain), got %d; stderr=%q", exit, stderr)
	}
	if !strings.Contains(stderr, "no `toolchain goX.Y.Z` directive") {
		t.Errorf("expected missing-toolchain error, got: %s", stderr)
	}
}

// TestRealRepo runs the lint against the real repository (parent of
// tools/lint-toolchain-alignment). This is the same smoke test
// TestRealMigrations plays in lint-migration-rls — a refactor of the
// detection rule that accidentally starts flagging a currently-clean
// production pin should be caught here at PR time, not by a
// downstream red workflow.
//
// The test skips (does not fail) if the real repo root is unreachable
// (e.g. when the tool is vendored into a different tree).
func TestRealRepo(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "apps", "api", "go.mod")); err != nil {
		t.Skipf("real repo root %q not reachable: %v", root, err)
	}
	exit, stdout, stderr := runLint(t, "--repo-root", root)
	if exit != 0 {
		t.Fatalf("real repo failed alignment lint! This is the regression you came here to fix.\nstdout=%s\nstderr=%s",
			stdout, stderr)
	}
}
