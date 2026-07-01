// Package main implements the toolchain alignment lint — a defensive CI
// gate that guarantees a single source of truth (apps/api/go.mod's
// `toolchain` directive) is echoed exactly by every downstream Go
// toolchain pin (other modules' `toolchain` directives, Dockerfile
// `golang:` base image tags, and GitHub Actions setup-go `go-version`
// inputs).
//
// Why this exists
// ===============
//
// In the M15-3 fix cycle (F240) a routine bump of `apps/api/go.mod`'s
// toolchain from 1.25.x to 1.26.4 was landed without updating
// `apps/api/Dockerfile`'s `FROM` tag. The Dockerfile still pinned
// `golang:1.25.8-alpine`, so the docker-smoke workflow silently failed
// on `go: go.mod requires go >= 1.26.0`, and four downstream CI
// workflows went RED on `main`. The drift was caught only by Claude's
// Phase D Round 2 broader-sweep review — the M15-3 Codex R1 review had
// scope-limited itself out of the diff and missed it.
//
// F241 (M15 Round 3) added a companion cosmetic fix: workflow header
// docstrings referred to `go 1.24.11` as the pinned toolchain, months
// stale relative to `go.mod`. Those two findings crystallised
// anti-pattern 55 (see `sbomhub-internal/planning/STATUS.md` M15 close
// section): **infra pin drift across the go.mod / Dockerfile / workflow
// triad is a human-error class that MUST be automated**, following the
// same pattern as M13-5's `lint-migration-rls`.
//
// Detection rule
// ==============
//
// The truth source is the `toolchain go<X.Y.Z>` directive in
// `apps/api/go.mod`. Every reference to a Go toolchain version
// elsewhere in the repository must agree with this line, at either
// patch precision (`X.Y.Z`) or minor precision (`X.Y`).
//
// Three layers are cross-checked:
//
//  1. **Other Go modules** — every `tools/*/go.mod` (including this
//     tool's own module: the lint is self-dogfooded). Their
//     `toolchain go<X.Y.Z>` line must match the truth patch exactly. A
//     `go <X.Y>` line is advisory minimum-version and is NOT part of
//     the alignment contract (it may legitimately lag by a patch or a
//     minor).
//
//  2. **Dockerfile FROM tags** — the scan picks up every Dockerfile
//     under `apps/<service>/Dockerfile*`, `packages/<pkg>/Dockerfile*`,
//     and `docker/Dockerfile*`. `apps/api/Dockerfile` and
//     `docker/Dockerfile.bench` are the two current sites that
//     actually pin a Go base image; `apps/web/Dockerfile` uses `node:`
//     and is silently filtered out (see below). F247 (M16-2 Phase D R2)
//     widened the glob from a hard-coded `apps/api/Dockerfile` +
//     `docker/Dockerfile*` list to the full `apps/*/Dockerfile*` +
//     `packages/*/Dockerfile*` + `docker/Dockerfile*` set so a future
//     `apps/api/Dockerfile.dev`, `packages/mcp-server/Dockerfile`,
//     etc. is covered without touching this tool.
//     A `FROM golang:<version>[-<flavor>]` tag may pin either patch
//     or minor precision (`golang:1.26.4-alpine` or `golang:1.26-alpine`).
//     If patch is used it must match truth exactly; if minor is used,
//     the M.N must match truth's M.N. Non-alpine flavors (`-bookworm`,
//     `-bullseye`, etc.) are accepted — only the X.Y[.Z] portion is
//     compared. **Only Dockerfiles whose first FROM directive starts
//     with `FROM golang:` participate in the alignment cross-check**;
//     a `FROM node:`, `FROM python:`, `FROM alpine:`, or any other
//     non-Go base is skipped entirely so a polyglot repo does not
//     produce false positives for images that intentionally do not
//     ship the Go toolchain.
//
//  3. **GitHub Actions workflows** — every `.github/workflows/*.yml`
//     file. A step that pins an explicit `go-version:` string is
//     checked against the truth with the same M.N / M.N.Z rule as
//     Dockerfiles. A step that uses `go-version-file: <path>` is
//     inherently self-aligning and is skipped — the whole point of
//     `go-version-file` is that setup-go reads truth (or a module
//     go.mod cross-checked separately in layer 1) directly, so drift
//     is structurally impossible for that step.
//
// New Dockerfile or workflow additions
// ====================================
//
// Adding a new Dockerfile or workflow that pins a Go version REQUIRES
// either:
//
//	(a) hard-coding a tag matching the current truth (every future
//	    `go.mod` toolchain bump will need to update this file too —
//	    the lint will catch the drift at PR time), OR
//	(b) using `go-version-file: apps/api/go.mod` in a workflow (or
//	    another module `go.mod` whose toolchain is already tracked
//	    under layer 1).
//
// (b) is strictly preferred for workflows; for Dockerfiles, hard-coded
// tags are the only viable form (there is no `FROM golang:${TOOLCHAIN}`
// primitive that reads `go.mod`) so the lint is the enforcement.
//
// CI invocation
// =============
//
//	go run ./tools/lint-toolchain-alignment --repo-root .
//
// or, from inside the module dir:
//
//	(cd tools/lint-toolchain-alignment && go run . --repo-root ../..)
//
// The latter shape is what `.github/workflows/toolchain-lint.yml` uses.
//
// Exit codes
// ==========
//
//	0 — all referenced Go version pins match the truth source.
//	1 — at least one drift detected. Stdout lists file / expected / actual
//	    for each drift; stderr echoes a compact `FAIL` header.
//	2 — usage / I/O error (bad --repo-root, unreadable `go.mod`, missing
//	    truth `toolchain` directive, etc.).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// versionRef is a parsed reference to a Go toolchain version found
// anywhere in the repo (or the truth line itself). `hasPatch` is false
// for minor-precision pins (`1.26`) and true for patch-precision pins
// (`1.26.4`); the two forms are handled uniformly by the covers()
// method below.
//
// `raw` preserves the exact string form the value was captured from
// (`1.26`, `1.26.4`, etc.) so error messages can echo what the operator
// wrote rather than a re-serialised form.
type versionRef struct {
	major    int
	minor    int
	patch    int
	hasPatch bool
	raw      string
}

// covers returns true if a downstream reference agrees with the truth
// source under the alignment rule:
//
//   - patch-precision downstream (`1.26.4`) → must match the truth's
//     major, minor, AND patch exactly.
//   - minor-precision downstream (`1.26`)   → must match the truth's
//     major and minor. The patch is not asserted (operator opted out of
//     patch pinning by omitting it).
//
// The truth is expected to always be patch-precision — that's what a
// well-formed `apps/api/go.mod` toolchain line looks like — but the
// helper is defensive against a future truth reference that lacks a
// patch (it would fall through the second clause).
func (truth versionRef) covers(ref versionRef) bool {
	if truth.major != ref.major || truth.minor != ref.minor {
		return false
	}
	if ref.hasPatch {
		return truth.hasPatch && truth.patch == ref.patch
	}
	return true
}

// driftFinding is one alignment violation — a single downstream
// reference (file + line) whose pinned version disagrees with the
// truth.
//
// The struct is deliberately flat so that `sort.Slice` on `[]driftFinding`
// (used to produce deterministic output) is a one-liner keyed on
// (layer, file, line).
type driftFinding struct {
	layer    string // "tools go.mod" | "Dockerfile" | "workflow"
	file     string // repo-relative path
	line     int    // 1-indexed source line for grep / editor jump
	expected string // truth's raw form (typically `1.26.4`)
	actual   string // whatever the file actually pinned
	context  string // full trigger line, trimmed, for the audit echo
}

// scanReport is the aggregated output of one repo-root walk. Findings
// are the drift list; checked / skipped are the cross-checked and
// auto-follow file paths respectively, used for the verbose summary.
type scanReport struct {
	findings []driftFinding
	checked  []string // "<layer>: <path>" strings, alignment verified
	skipped  []string // "<layer>: <path>" strings, auto-follow (go-version-file)
}

// Regex patterns are compiled once at package init so a `go test` driver
// that runs many fixtures does not re-compile per fixture.
//
// The truth-source pattern and the downstream module-toolchain pattern
// are identical in shape — both require patch precision because a
// well-formed toolchain line in a Go module always names the patch. A
// `go 1.X` line (without `.Z`) is the module's minimum-version hint,
// NOT the toolchain, and is intentionally not treated as an alignment
// signal.
var (
	// reToolchain: `toolchain goX.Y.Z` (leading/trailing whitespace
	// tolerated by the line-trim in the callers). Anchored with ^ / $
	// so a `go 1.26.0` line above doesn't accidentally match.
	reToolchain = regexp.MustCompile(`^toolchain\s+go(\d+)\.(\d+)\.(\d+)\s*$`)

	// reDockerGolangFrom: `FROM golang:<version>[-<flavor>][ AS <name>]`.
	//
	// The version segment allows either M.N or M.N.Z. A trailing flavor
	// suffix (`-alpine`, `-alpine3.20`, `-bookworm`, `-bullseye`, etc.)
	// is accepted but not required. A `AS <stage-name>` label is also
	// accepted so multi-stage builds are covered.
	//
	// Non-`golang:` FROM lines (e.g. `FROM alpine:3.20` for the runtime
	// stage) do not match — this is by design; the tool only cares
	// about the Go toolchain image.
	reDockerGolangFrom = regexp.MustCompile(`^FROM\s+golang:(\d+)\.(\d+)(?:\.(\d+))?(?:-[A-Za-z0-9._-]+)?(?:\s+AS\s+\S+)?\s*$`)

	// reWorkflowGoVersion: `go-version: <value>` inside a YAML step.
	//
	// The value may be single-quoted, double-quoted, or bare. Only
	// string-literal versions are handled — expressions like
	// `${{ matrix.go }}` are left alone (they aren't a static pin and
	// so cannot drift against the truth in the way this lint checks).
	reWorkflowGoVersion = regexp.MustCompile(`^\s*go-version\s*:\s*['"]?(\d+)\.(\d+)(?:\.(\d+))?['"]?\s*$`)

	// reWorkflowGoVersionFile: `go-version-file: <path>`. A step
	// containing this directive is skipped — setup-go resolves the
	// referenced module's toolchain directly, so drift is
	// structurally impossible at this step. (The referenced module's
	// own `toolchain` line IS still cross-checked by layer 1 when it
	// lives under `tools/*/go.mod`.)
	reWorkflowGoVersionFile = regexp.MustCompile(`^\s*go-version-file\s*:\s*\S+\s*$`)
)

// parseTruth loads and parses `apps/api/go.mod`'s `toolchain` directive.
//
// The truth line is required to be patch-precision (`toolchain goX.Y.Z`).
// A `go 1.X` line by itself does NOT satisfy the truth requirement — the
// tool cannot compare a minor-precision truth against patch-precision
// downstream pins meaningfully (`golang:1.26.4-alpine` would appear to
// drift against a `go 1.26` truth even though it's the intended state).
//
// Returns exit-code-2 semantics (config error) if the file is missing
// or the directive is absent.
func parseTruth(root string) (versionRef, string, error) {
	path := filepath.Join(root, "apps", "api", "go.mod")
	body, err := os.ReadFile(path)
	if err != nil {
		return versionRef{}, path, fmt.Errorf("read truth source %s: %w", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if m := reToolchain.FindStringSubmatch(trimmed); m != nil {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			patch, _ := strconv.Atoi(m[3])
			return versionRef{
				major:    major,
				minor:    minor,
				patch:    patch,
				hasPatch: true,
				raw:      fmt.Sprintf("%d.%d.%d", major, minor, patch),
			}, path, nil
		}
	}
	return versionRef{}, path, fmt.Errorf(
		"no `toolchain goX.Y.Z` directive in truth source %s "+
			"(alignment requires a patch-precision toolchain line; "+
			"a bare `go 1.X` line is not sufficient)",
		path)
}

// parseModuleToolchain reads a downstream `go.mod`-style file body and
// returns its `toolchain goX.Y.Z` directive if present. `found` is false
// when the file has no toolchain line at all — that's not an error,
// some standalone tool modules legitimately omit the toolchain and
// inherit whatever the caller's `go` binary happens to be.
//
// Also returned: the 1-indexed line number the directive was seen on,
// for editor-jump error messages.
func parseModuleToolchain(body string) (ref versionRef, line int, found bool) {
	for i, raw := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(raw)
		if m := reToolchain.FindStringSubmatch(trimmed); m != nil {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			patch, _ := strconv.Atoi(m[3])
			return versionRef{
				major:    major,
				minor:    minor,
				patch:    patch,
				hasPatch: true,
				raw:      fmt.Sprintf("%d.%d.%d", major, minor, patch),
			}, i + 1, true
		}
	}
	return versionRef{}, 0, false
}

// checkModulesGoMod walks `tools/*/go.mod` (including the lint tool's
// own module — self-dogfood) and returns any drift.
//
// Modules WITHOUT a `toolchain` directive are silently skipped: their
// contract with the toolchain is inherited from the caller, and the
// M16-2 alignment invariant only extends to explicit patch-pinned
// modules.
func checkModulesGoMod(root string, truth versionRef, report *scanReport) error {
	pattern := filepath.Join(root, "tools", "*", "go.mod")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob %s: %w", pattern, err)
	}
	sort.Strings(matches)
	for _, path := range matches {
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		ref, line, found := parseModuleToolchain(string(body))
		if !found {
			// Not an error; recorded as neither checked nor skipped so
			// the verbose summary reflects the module was seen but had
			// nothing to check.
			continue
		}
		if truth.covers(ref) {
			report.checked = append(report.checked,
				fmt.Sprintf("tools go.mod: %s (toolchain go%s)", rel, ref.raw))
			continue
		}
		report.findings = append(report.findings, driftFinding{
			layer:    "tools go.mod",
			file:     rel,
			line:     line,
			expected: truth.raw,
			actual:   ref.raw,
			context:  fmt.Sprintf("toolchain go%s", ref.raw),
		})
	}
	return nil
}

// dockerfileTargets returns the Dockerfile paths this tool inspects.
// The scan covers three glob layers so any new service, package, or
// build variant is picked up without touching this tool:
//
//   - `apps/<service>/Dockerfile*` — every apps/* subtree's Dockerfile
//     and variants (e.g. `apps/api/Dockerfile`, `apps/api/Dockerfile.dev`,
//     `apps/web/Dockerfile`).
//   - `packages/<pkg>/Dockerfile*` — same for packages/* (e.g. a
//     future `packages/mcp-server/Dockerfile`).
//   - `docker/Dockerfile*` — the shared/bench Dockerfiles (e.g.
//     `docker/Dockerfile.bench`).
//
// F247 (M16-2 Phase D R2) widened this from the pre-F247 hard-coded
// `apps/api/Dockerfile` + `docker/Dockerfile*` list. Non-Go Dockerfiles
// (`apps/web/Dockerfile` currently, which uses `node:`) are collected
// here and filtered out in `checkDockerfiles` by the `FROM golang:`
// prefix check — so this function returns "candidates to inspect", not
// "candidates to enforce alignment on".
//
// The returned slice is sorted and deduplicated so downstream output
// is deterministic regardless of filesystem enumeration order.
func dockerfileTargets(root string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	globPatterns := []string{
		filepath.Join(root, "apps", "*", "Dockerfile*"),
		filepath.Join(root, "packages", "*", "Dockerfile*"),
		filepath.Join(root, "docker", "Dockerfile*"),
	}
	for _, pat := range globPatterns {
		globbed, err := filepath.Glob(pat)
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", pat, err)
		}
		for _, p := range globbed {
			// Skip directories accidentally caught by Dockerfile*
			// (e.g. a Dockerfile.d/ subtree).
			info, err := os.Stat(p)
			if err != nil || info.IsDir() {
				continue
			}
			add(p)
		}
	}

	sort.Strings(out)
	return out, nil
}

// checkDockerfiles reads every Dockerfile target and cross-checks each
// `FROM golang:<version>...` line against the truth. A Dockerfile with
// zero `FROM golang:` lines (e.g. a scratch runtime that only pulls
// alpine + a pre-built binary) is skipped without a finding — the tool
// only cares about places that explicitly pin the Go toolchain.
func checkDockerfiles(root string, truth versionRef, report *scanReport) error {
	targets, err := dockerfileTargets(root)
	if err != nil {
		return err
	}
	for _, path := range targets {
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		anyGolangFrom := false
		for i, raw := range strings.Split(string(body), "\n") {
			trimmed := strings.TrimSpace(raw)
			m := reDockerGolangFrom.FindStringSubmatch(trimmed)
			if m == nil {
				continue
			}
			anyGolangFrom = true
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			var patch int
			hasPatch := m[3] != ""
			if hasPatch {
				patch, _ = strconv.Atoi(m[3])
			}
			ref := versionRef{
				major:    major,
				minor:    minor,
				patch:    patch,
				hasPatch: hasPatch,
				raw:      versionRefRaw(major, minor, patch, hasPatch),
			}
			if truth.covers(ref) {
				report.checked = append(report.checked,
					fmt.Sprintf("Dockerfile: %s:%d (FROM golang:%s)", rel, i+1, ref.raw))
				continue
			}
			report.findings = append(report.findings, driftFinding{
				layer:    "Dockerfile",
				file:     rel,
				line:     i + 1,
				expected: truth.raw,
				actual:   ref.raw,
				context:  trimmed,
			})
		}
		if !anyGolangFrom {
			// A Dockerfile with no golang: base image is not in scope;
			// don't record it as checked, but don't error either.
			continue
		}
	}
	return nil
}

// versionRefRaw formats a captured version tuple back to its textual
// form, preserving whether the operator used patch or minor precision.
// This is what shows up in the `expected/actual` echo — a truth of
// `1.26.4` and a downstream `1.26` remain distinguishable in output.
func versionRefRaw(major, minor, patch int, hasPatch bool) string {
	if hasPatch {
		return fmt.Sprintf("%d.%d.%d", major, minor, patch)
	}
	return fmt.Sprintf("%d.%d", major, minor)
}

// checkWorkflows walks `.github/workflows/*.yml` (both `.yml` and
// `.yaml` extensions) and cross-checks any explicit `go-version:`
// pin against the truth. A step with `go-version-file:` is recorded
// under `skipped` and does not participate in alignment.
//
// The scan is line-based: each YAML file may contain multiple setup-go
// steps in different jobs, and each is independently checked. The order
// of go-version-file / go-version lines within a step does not matter
// (setup-go itself picks one).
func checkWorkflows(root string, truth versionRef, report *scanReport) error {
	dir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no workflows in this repo root, nothing to check
		}
		return fmt.Errorf("read %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml") {
			continue
		}
		files = append(files, filepath.Join(dir, n))
	}
	sort.Strings(files)

	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		for i, raw := range strings.Split(string(body), "\n") {
			// Strip trailing whitespace but preserve indentation for
			// the trimmed-line YAML anchors. TrimSpace on the LHS of
			// the regex tolerates arbitrary YAML depth.
			trimmed := strings.TrimRight(raw, " \t\r")
			if reWorkflowGoVersionFile.MatchString(trimmed) {
				report.skipped = append(report.skipped,
					fmt.Sprintf("workflow: %s:%d (%s)", rel, i+1, strings.TrimSpace(trimmed)))
				continue
			}
			m := reWorkflowGoVersion.FindStringSubmatch(trimmed)
			if m == nil {
				continue
			}
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			var patch int
			hasPatch := m[3] != ""
			if hasPatch {
				patch, _ = strconv.Atoi(m[3])
			}
			ref := versionRef{
				major:    major,
				minor:    minor,
				patch:    patch,
				hasPatch: hasPatch,
				raw:      versionRefRaw(major, minor, patch, hasPatch),
			}
			if truth.covers(ref) {
				report.checked = append(report.checked,
					fmt.Sprintf("workflow: %s:%d (go-version: %s)", rel, i+1, ref.raw))
				continue
			}
			report.findings = append(report.findings, driftFinding{
				layer:    "workflow",
				file:     rel,
				line:     i + 1,
				expected: truth.raw,
				actual:   ref.raw,
				context:  strings.TrimSpace(trimmed),
			})
		}
	}
	return nil
}

// run is the testable entry point — splitting it out of main() lets
// main_test.go drive the lint with synthetic --repo-root arguments and
// capture stdout / stderr without forking a subprocess.
//
// argv excludes the program name (caller passes os.Args[1:]). The
// return value is the process exit code so test code can assert on it
// without goroutine-hostile os.Exit shenanigans.
func run(argv []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint-toolchain-alignment", flag.ContinueOnError)
	fs.SetOutput(stderr)

	repoRoot := fs.String("repo-root", ".", "repository root (contains apps/api/go.mod)")
	verbose := fs.Bool("verbose", false, "print every cross-checked and skipped file on success")

	if err := fs.Parse(argv); err != nil {
		// flag.ContinueOnError already wrote the usage message to stderr.
		return 2
	}

	if *repoRoot == "" {
		fmt.Fprintln(stderr, "lint-toolchain-alignment: --repo-root is required")
		return 2
	}

	truth, truthPath, err := parseTruth(*repoRoot)
	if err != nil {
		fmt.Fprintf(stderr, "lint-toolchain-alignment: %v\n", err)
		return 2
	}

	report := &scanReport{}
	if err := checkModulesGoMod(*repoRoot, truth, report); err != nil {
		fmt.Fprintf(stderr, "lint-toolchain-alignment: %v\n", err)
		return 2
	}
	if err := checkDockerfiles(*repoRoot, truth, report); err != nil {
		fmt.Fprintf(stderr, "lint-toolchain-alignment: %v\n", err)
		return 2
	}
	if err := checkWorkflows(*repoRoot, truth, report); err != nil {
		fmt.Fprintf(stderr, "lint-toolchain-alignment: %v\n", err)
		return 2
	}

	// Deterministic finding order: (layer, file, line) so CI log diffs
	// don't ping-pong across runs.
	sort.SliceStable(report.findings, func(i, j int) bool {
		a, b := report.findings[i], report.findings[j]
		if a.layer != b.layer {
			return a.layer < b.layer
		}
		if a.file != b.file {
			return a.file < b.file
		}
		return a.line < b.line
	})

	if len(report.findings) == 0 {
		truthRel, err := filepath.Rel(*repoRoot, truthPath)
		if err != nil {
			truthRel = truthPath
		}
		fmt.Fprintf(stdout,
			"lint-toolchain-alignment: ok — %d pin(s) aligned to Go %s (truth: %s), %d workflow step(s) auto-follow via go-version-file\n",
			len(report.checked), truth.raw, truthRel, len(report.skipped))
		if *verbose {
			for _, s := range report.checked {
				fmt.Fprintf(stdout, "  checked: %s\n", s)
			}
			for _, s := range report.skipped {
				fmt.Fprintf(stdout, "  skipped: %s\n", s)
			}
		}
		return 0
	}

	fmt.Fprintf(stderr, "lint-toolchain-alignment: FAIL — %d Go toolchain pin(s) drift from apps/api/go.mod (truth: %s)\n",
		len(report.findings), truth.raw)
	// Findings are written to stdout as well as summarised on stderr so
	// scripting callers can `grep` either stream. The line-by-line drift
	// echo lives on stdout for a compact single-source review.
	for _, f := range report.findings {
		fmt.Fprintf(stdout, "  drift: %s (%s:%d)\n", f.layer, f.file, f.line)
		fmt.Fprintf(stdout, "    expected: %s\n", f.expected)
		fmt.Fprintf(stdout, "    actual:   %s\n", f.actual)
		if f.context != "" {
			fmt.Fprintf(stdout, "    context:  %s\n", f.context)
		}
	}
	fmt.Fprintln(stdout, "  fix: update the drifted pin to match the truth in apps/api/go.mod,")
	fmt.Fprintln(stdout, "       or (for workflows) switch to `go-version-file: apps/api/go.mod`")
	fmt.Fprintln(stdout, "       so setup-go auto-follows the module toolchain.")
	return 1
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
