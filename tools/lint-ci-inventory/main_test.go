package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// parseWorkflow
// ---------------------------------------------------------------------

func TestParseWorkflow_NameWinsOverJobID(t *testing.T) {
	const body = `---
name: Web E2E

'on':
  pull_request:
    paths:
      - 'apps/web/**'

permissions:
  contents: read

jobs:
  web-e2e:
    name: Playwright smoke (home / dashboard / api-health)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

  web-e2e-full:
    # DO NOT edit ` + "`name:`" + ` — it is a required status check.
    name: Playwright full suite (26 specs against seeded stack)
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("web-e2e.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	got := []string{}
	for _, j := range jobs {
		got = append(got, j.line())
	}
	want := []string{
		"web-e2e.yml :: web-e2e :: Playwright smoke (home / dashboard / api-health)",
		"web-e2e.yml :: web-e2e-full :: Playwright full suite (26 specs against seeded stack)",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A job without `name:` reports under its YAML key — this is how
// `build-and-push` (docker-publish.yml) becomes a required check name.
func TestParseWorkflow_FallsBackToJobID(t *testing.T) {
	const body = `name: Docker Publish
on:
  push:
    branches: [main]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("docker-publish.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if len(jobs) != 1 || jobs[0].checkName != "build-and-push" {
		t.Fatalf("got %+v, want one job named build-and-push", jobs)
	}
	if jobs[0].namedExplicitly {
		t.Error("no `name:` was written")
	}
}

// The `on:` block also has keys named like jobs; they must not leak in.
func TestParseWorkflow_IgnoresOnBlockKeys(t *testing.T) {
	const body = `name: X
on:
  push:
    branches:
      - main
  pull_request:
  workflow_dispatch:

jobs:
  only-job:
    name: the only job
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if len(jobs) != 1 || jobs[0].id != "only-job" {
		t.Fatalf("got %+v, want exactly the one job", jobs)
	}
}

// Anti-vacuity: a file with no jobs must be an ERROR, never a silent
// "nothing to check here".
func TestParseWorkflow_NoJobsIsAnError(t *testing.T) {
	const body = `name: X
on:
  push:
`
	if _, err := parseWorkflow("x.yml", body); err == nil {
		t.Fatal("expected an error for a workflow with no jobs")
	}
}

func TestParseWorkflow_MalformedYamlIsAnError(t *testing.T) {
	const body = "name: X\njobs:\n\t- tab indent is illegal\n"
	if _, err := parseWorkflow("x.yml", body); err == nil {
		t.Fatal("expected a parse error")
	}
}

// ---------------------------------------------------------------------
// YAML shapes the hand-rolled scanner got wrong.
//
// Each of these was a review finding while this lint scanned lines
// instead of parsing. They are kept as regression tests for the choice of
// a real parser: if anyone reverts to hand-rolling, they come back.
// ---------------------------------------------------------------------

func TestParseWorkflow_YamlShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "escaped single quote",
			body: "name: X\non:\n  push:\njobs:\n  audit:\n    name: 'API''s audit'\n",
			want: "API's audit",
		},
		{
			name: "unicode escape in a double-quoted scalar",
			body: "name: X\non:\n  push:\njobs:\n  audit:\n    name: \"security \\u30b2\\u30fc\\u30c8\"\n",
			want: "security ゲート",
		},
		{
			name: "inline comment after a plain scalar",
			body: "name: X\non:\n  push:\njobs:\n  g:\n    name: Security gate # required check\n",
			want: "Security gate",
		},
		{
			name: "hash inside a quoted scalar is not a comment",
			body: "name: X\non:\n  push:\njobs:\n  g:\n    name: 'gate #3' # a comment\n",
			want: "gate #3",
		},
		{
			name: "anchor and alias",
			body: "gate_name: &gate Security gate\non:\n  push:\njobs:\n  g:\n    name: *gate\n",
			want: "Security gate",
		},
		{
			name: "jobs key carrying a comment",
			body: "name: X\non:\n  push:\njobs: # repository gates\n  g:\n    name: build-and-test\n",
			want: "build-and-test",
		},
		{
			name: "folded block scalar name",
			body: "name: X\non:\n  push:\njobs:\n  g:\n    name: >-\n      folded name\n",
			want: "folded name",
		},
		{
			name: "flow mapping job body",
			body: "name: X\non:\n  push:\njobs:\n  g: {name: compact gate, runs-on: ubuntu-latest}\n",
			want: "compact gate",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			jobs, err := parseWorkflow("x.yml", c.body)
			if err != nil {
				t.Fatalf("parseWorkflow: %v", err)
			}
			if len(jobs) != 1 || jobs[0].checkName != c.want {
				t.Fatalf("got %q, want %q", jobs[0].checkName, c.want)
			}
		})
	}
}

// A quoted job key used to be dropped silently, taking a required status
// check with it while the file's other jobs kept the anti-vacuity guard
// quiet.
func TestParseWorkflow_QuotedJobKey(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  visible:
    name: visible
  'hidden':
    name: required-hidden
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("got %d jobs, want 2", len(jobs))
	}
	if jobs[1].checkName != "required-hidden" {
		t.Fatalf("got %q", jobs[1].checkName)
	}
}

// ---------------------------------------------------------------------
// matchesJob / expandNames
// ---------------------------------------------------------------------

func TestMatchesJob(t *testing.T) {
	plain := job{file: "a.yml", id: "j", checkName: "static gate (hermetic)", namedExplicitly: true}
	matrix := job{
		file: "b.yml", id: "k", namedExplicitly: true,
		checkName:   "install.sh must succeed on ${{ matrix.os }}",
		matrixOrder: []string{"os"},
		matrix:      map[string][]string{"os": {"ubuntu-latest", "macos-latest"}},
	}
	// A name that STARTS with an expression has an empty literal prefix;
	// HasPrefix(x, "") is true for every x, so without the `i > 0` guard
	// this job would vouch for every required check in the snapshot.
	leading := job{
		file: "c.yml", id: "l", checkName: "${{ matrix.os }} build",
		namedExplicitly: true, matrixIsPartial: true,
	}

	cases := []struct {
		required string
		j        job
		want     bool
	}{
		{"static gate (hermetic)", plain, true},
		{"static gate", plain, false},
		{"install.sh must succeed on ubuntu-latest", matrix, true},
		{"install.sh must succeed on macos-latest", matrix, true},
		{"install.sh must succeed on windows-latest", matrix, false},
		{"anything at all", leading, false},
		{"${{ matrix.os }} build", leading, true},
	}
	for _, c := range cases {
		if got := matchesJob(c.required, c.j); got != c.want {
			t.Errorf("matchesJob(%q, %q) = %v, want %v", c.required, c.j.checkName, got, c.want)
		}
	}
}

// Dropping a matrix leg is an ordinary edit ("we no longer support
// windows"). The snapshot must then report the stale name.
func TestMatrixLegRemovalIsCaught(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: install.sh must succeed on ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os:
          - ubuntu-latest
          - macos-latest
`
	jobs, err := parseWorkflow("install-smoke.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	j := jobs[0]
	if got := j.matrix["os"]; len(got) != 2 || got[0] != "ubuntu-latest" {
		t.Fatalf("matrix os = %v", got)
	}
	if !matchesJob("install.sh must succeed on macos-latest", j) {
		t.Error("a surviving leg must match")
	}
	if matchesJob("install.sh must succeed on windows-latest", j) {
		t.Error("a dropped matrix leg must NOT match")
	}
}

func TestMatrixInlineListForm(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: build ${{ matrix.go }}
    strategy:
      matrix:
        go: ['1.25', '1.26']
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("build 1.26", jobs[0]) || matchesJob("build 1.24", jobs[0]) {
		t.Fatalf("inline matrix not expanded: %v", jobs[0].matrix)
	}
}

// A comma inside a quoted list element is part of the value.
func TestMatrixInlineListRespectsQuotes(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: build ${{ matrix.label }}
    strategy:
      matrix:
        label: ['linux, amd64']
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("build linux, amd64", jobs[0]) {
		t.Fatalf("got matrix %v", jobs[0].matrix)
	}
}

// `include:` adds legs this lint does not model. Expanding only the
// declared axes would report a LIVE required check as stale and block
// `main`; the lenient prefix fallback is the safe direction.
func TestMatrixIncludeFallsBackToPrefix(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: install.sh must succeed on ${{ matrix.os }}
    strategy:
      matrix:
        os:
          - ubuntu-latest
        include:
          - os: windows-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !jobs[0].matrixIsPartial {
		t.Fatal("include: should mark the matrix partial")
	}
	if !matchesJob("install.sh must succeed on windows-latest", jobs[0]) {
		t.Error("an include-only leg must still be accepted (lenient fallback)")
	}
}

// Removing the last supported OS and leaving `os: []` produces NO legs.
func TestEmptyMatrixProducesNoNames(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: build ${{ matrix.os }}
    strategy:
      matrix:
        os: []
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	names, ok := expandNames(jobs[0])
	if !ok {
		t.Fatal("an explicitly empty list is readable")
	}
	if len(names) != 0 {
		t.Fatalf("expected no names, got %v", names)
	}
	if matchesJob("build ubuntu-latest", jobs[0]) {
		t.Error("an empty matrix must not vouch for any required check")
	}
}

// C: `namedExplicitly` was declared and read but NEVER ASSIGNED, so a
// NAMED required job that gained a matrix got expanded to `id (leg)` and
// its live required check was reported stale — a red `main` on a correct
// change. This test failed before the assignment was added.
func TestNamedMatrixJobKeepsExplicitName(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  checks:
    name: Required gate
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !jobs[0].namedExplicitly {
		t.Fatal("`name:` was explicit — namedExplicitly must be set")
	}
	if !matchesJob("Required gate", jobs[0]) {
		t.Error("the explicit name must still be vouched for")
	}
	if matchesJob("checks (ubuntu-latest)", jobs[0]) {
		t.Error("an explicitly named job does not report under the leg form")
	}
}

// A job with no `name:` that becomes a matrix job reports as `id (leg)`,
// in YAML DECLARATION order.
func TestNamelessMatrixJobExpandsToLegNames(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu-latest]
        go: ['1.26']
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	names, ok := expandNames(jobs[0])
	if !ok || len(names) != 1 {
		t.Fatalf("got %v ok=%v", names, ok)
	}
	if names[0] != "build (ubuntu-latest, 1.26)" {
		t.Fatalf("got %q, want declaration order", names[0])
	}
	if matchesJob("build", jobs[0]) {
		t.Error("the pre-matrix check name must NOT be vouched for")
	}
}

// ---------------------------------------------------------------------
// run() end-to-end, against scripted repo trees
// ---------------------------------------------------------------------

func scaffold(t *testing.T, inventory, required string) string {
	t.Helper()
	root := t.TempDir()
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(wf, "alpha.yml"), `name: Alpha
on:
  push:

jobs:
  build:
    name: build-and-test
    runs-on: ubuntu-latest
`)
	write(filepath.Join(wf, "beta.yml"), `name: Beta
on:
  push:

jobs:
  gate:
    name: static gate (hermetic)
    runs-on: ubuntu-latest
`)
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(docs, "ci-inventory.md"),
		"# CI inventory\n\n"+
			genBegin+"\n\n```text\n"+inventory+"```\n\n"+genEnd+"\n\n"+
			reqBegin+"\n\n```text\n"+required+"```\n\n"+reqEnd+"\n")
	return root
}

const fullInventory = "alpha.yml :: build :: build-and-test\n" +
	"beta.yml :: gate :: static gate (hermetic)\n"

const fullRequired = "build-and-test\nstatic gate (hermetic)\n"

func runOK(t *testing.T, root string) []string {
	t.Helper()
	var out strings.Builder
	findings, err := run(root, false, false, &out)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return findings
}

func TestRun_CleanTree(t *testing.T) {
	if f := runOK(t, scaffold(t, fullInventory, fullRequired)); len(f) != 0 {
		t.Fatalf("expected no findings, got %v", f)
	}
}

// The exact regression this lint exists for: a workflow lands, nobody
// updates the doc.
func TestRun_UndocumentedWorkflowIsAFinding(t *testing.T) {
	root := scaffold(t, "alpha.yml :: build :: build-and-test\n", fullRequired)
	f := runOK(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "ADD: beta.yml :: gate :: static gate (hermetic)") {
		t.Fatalf("expected the missing beta.yml job to be reported, got %v", f)
	}
}

func TestRun_StaleInventoryEntryIsAFinding(t *testing.T) {
	root := scaffold(t, fullInventory+"gamma.yml :: ghost :: long gone\n", fullRequired)
	f := runOK(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "REMOVE: gamma.yml :: ghost :: long gone") {
		t.Fatalf("expected the stale entry to be reported, got %v", f)
	}
}

// Renaming a job silently detaches a required status check and leaves
// `main` unmergeable. That must be a red lint, not a stuck branch.
func TestRun_RenamedRequiredJobIsAFinding(t *testing.T) {
	root := scaffold(t, fullInventory, fullRequired)
	wf := filepath.Join(root, ".github", "workflows", "beta.yml")
	body, err := os.ReadFile(wf)
	if err != nil {
		t.Fatal(err)
	}
	renamed := strings.Replace(string(body), "static gate (hermetic)", "static gate", 1)
	if err := os.WriteFile(wf, []byte(renamed), 0o644); err != nil {
		t.Fatal(err)
	}
	f := runOK(t, root)
	if !strings.Contains(strings.Join(f, "\n"),
		`required status check "static gate (hermetic)" is not produced by any job`) {
		t.Fatalf("expected the detached required check to be reported, got %v", f)
	}
}

func TestRun_EmptyRequiredSnapshotIsAFinding(t *testing.T) {
	root := scaffold(t, fullInventory, "")
	f := runOK(t, root)
	if len(f) != 1 || !strings.Contains(f[0], "snapshot is empty") {
		t.Fatalf("expected the empty-snapshot guard to fire, got %v", f)
	}
}

func TestRun_FixRewritesTheBlock(t *testing.T) {
	root := scaffold(t, "alpha.yml :: build :: build-and-test\n", fullRequired)
	var out strings.Builder
	f, err := run(root, true, false, &out)
	if err != nil {
		t.Fatalf("run --fix: %v", err)
	}
	if len(f) != 0 {
		t.Fatalf("--fix should leave the tree clean, got %v", f)
	}
	doc, err := os.ReadFile(filepath.Join(root, "docs", "ci-inventory.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "beta.yml :: gate :: static gate (hermetic)") {
		t.Fatalf("--fix did not write the missing entry:\n%s", doc)
	}
	var out2 strings.Builder
	if _, err := run(root, true, false, &out2); err != nil {
		t.Fatalf("second --fix: %v", err)
	}
	if !strings.Contains(out2.String(), "already up to date") {
		t.Fatalf("second --fix should be a no-op, got %q", out2.String())
	}
}

// `--fix` must not leave a stray temp file behind, and must preserve mode.
func TestFixIsAtomicAndLeavesNoTempFile(t *testing.T) {
	root := scaffold(t, "alpha.yml :: build :: build-and-test\n", fullRequired)
	var out strings.Builder
	if _, err := run(root, true, false, &out); err != nil {
		t.Fatalf("run --fix: %v", err)
	}
	docs := filepath.Join(root, "docs")
	entries, err := os.ReadDir(docs)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "ci-inventory.md" {
			t.Errorf("--fix left %s behind in %s", e.Name(), docs)
		}
	}
	info, err := os.Stat(filepath.Join(docs, "ci-inventory.md"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", info.Mode().Perm())
	}
}

// Anti-vacuity at the top level: an empty workflows dir must be an error,
// not "the doc covers everything (there is nothing)".
func TestRun_NoWorkflowsIsAnError(t *testing.T) {
	root := scaffold(t, fullInventory, fullRequired)
	wf := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(wf)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(wf, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	var out strings.Builder
	if _, err := run(root, false, false, &out); err == nil {
		t.Fatal("expected an error for an empty workflows directory")
	}
}

func TestRun_MissingMarkerIsAnError(t *testing.T) {
	root := scaffold(t, fullInventory, fullRequired)
	docPath := filepath.Join(root, "docs", "ci-inventory.md")
	body, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.Replace(string(body), genBegin, "", 1)
	if err := os.WriteFile(docPath, []byte(stripped), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if _, err := run(root, false, false, &out); err == nil {
		t.Fatal("expected an error when the generated-block marker is gone")
	}
}

// ---------------------------------------------------------------------
// The real repository
// ---------------------------------------------------------------------

// Keeps the scripted fixtures honest: whatever shape the actual workflow
// files have, the parser must find every one of them and at least one job
// in each. No magic count — an ordinary workflow consolidation must not
// turn this red.
func TestRealRepositoryParses(t *testing.T) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows")); err != nil {
		t.Skipf("not running inside the repo: %v", err)
	}
	jobs, err := collectJobs(root)
	if err != nil {
		t.Fatalf("collectJobs: %v", err)
	}
	var onDisk []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(root, ".github", "workflows", pat))
		if err != nil {
			t.Fatal(err)
		}
		onDisk = append(onDisk, m...)
	}
	if len(onDisk) == 0 {
		t.Fatal("no workflow files found on disk")
	}
	if got := countFiles(jobs); got != len(onDisk) {
		t.Fatalf("parsed jobs from %d files, but %d workflow files exist", got, len(onDisk))
	}
	for _, j := range jobs {
		if j.checkName == "" {
			t.Errorf("%s :: %s has an empty check name", j.file, j.id)
		}
	}
}

// Derives the "N of the 17 required checks came from workflows the doc
// never mentioned" figure quoted in the package comment and in
// docs/ci-inventory.md, so the number in prose cannot drift from the
// repository. An earlier revision claimed 12; the real figure is 9 —
// dr-rehearsal.yml and release.yml produce no required check.
func TestRequiredFromUndocumented(t *testing.T) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows")); err != nil {
		t.Skipf("not running inside the repo: %v", err)
	}
	undocumented := map[string]bool{
		"dr-rehearsal.yml": true, "golden-path-e2e.yml": true, "mcp-server-ci.yml": true,
		"migration-lint.yml": true, "migration-lock-lint.yml": true, "nullscan.yml": true,
		"project-scope-e2e.yml": true, "release.yml": true,
		"scheduler-integration.yml": true, "toolchain-lint.yml": true,
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(docRel)))
	if err != nil {
		t.Fatal(err)
	}
	required, err := extractBlock(string(raw), reqBegin, reqEnd)
	if err != nil {
		t.Fatal(err)
	}
	jobs, err := collectJobs(root)
	if err != nil {
		t.Fatal(err)
	}
	var fromUndocumented []string
	for _, name := range required {
		for _, j := range jobs {
			if matchesJob(name, j) {
				if undocumented[j.file] {
					fromUndocumented = append(fromUndocumented, j.file+" :: "+name)
				}
				break
			}
		}
	}
	t.Logf("required=%d, from undocumented workflows=%d:\n  %s",
		len(required), len(fromUndocumented), strings.Join(fromUndocumented, "\n  "))
	if len(fromUndocumented) != 9 {
		t.Fatalf("expected 9 required checks from undocumented workflows, got %d — "+
			"update the figure in the package comment and in docs/ci-inventory.md",
			len(fromUndocumented))
	}
}

// An OBJECT matrix axis referenced as `${{ matrix.target.os }}` is a
// normal way to pair values. Half-expanding it produced a name nothing
// emits and reported a LIVE required check as stale.
func TestObjectMatrixFallsBackToPrefix(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  smoke:
    name: install.sh must succeed on ${{ matrix.target.os }}
    strategy:
      matrix:
        target:
          - os: ubuntu-latest
            arch: amd64
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if _, ok := expandNames(jobs[0]); ok {
		t.Fatal("a dotted/object matrix must not be treated as expandable")
	}
	if !matchesJob("install.sh must succeed on ubuntu-latest", jobs[0]) {
		t.Error("the lenient prefix fallback must still accept the live check")
	}
}

// Adding `exclude:` to a nameless matrix job is ordinary. Its checks are
// `id (leg)`, and the check name carries no expression to prefix-match
// on, so the leg form has to be accepted rather than called stale.
func TestNamelessPartialMatrixAcceptsLegForm(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        exclude:
          - os: windows-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("build (ubuntu-latest)", jobs[0]) {
		t.Error("a live leg check must be accepted")
	}
}

// A non-matrix expression in the name is resolved by GitHub at run time.
func TestNonMatrixExpressionNameIsLenient(t *testing.T) {
	const body = `name: X
'on':
  pull_request:

jobs:
  gate:
    name: gate (${{ github.event_name }})
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("gate (pull_request)", jobs[0]) {
		t.Error("the run-time-resolved check name must be accepted")
	}
	if matchesJob("something else", jobs[0]) {
		t.Error("the literal prefix must still be required")
	}
}

// An `include:`-only matrix stores no axes but is still a matrix job:
// its checks are `id (leg)`.
func TestIncludeOnlyNamelessMatrixAcceptsLegForm(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("build (ubuntu-latest)", jobs[0]) {
		t.Error("a live leg check must be accepted")
	}
}

// A non-matrix expression surviving the expansion is resolved at run time.
func TestMixedMatrixAndRuntimeExpressionIsLenient(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  gate:
    name: gate ${{ matrix.os }} / ${{ github.event_name }}
    strategy:
      matrix:
        os: [ubuntu-latest]
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("gate ubuntu-latest / pull_request", jobs[0]) {
		t.Error("the run-time-resolved check name must be accepted")
	}
}

// A name that STARTS with an expression still has a literal suffix.
func TestLeadingExpressionNameAnchorsOnSuffix(t *testing.T) {
	const body = `name: X
'on':
  pull_request:

jobs:
  gate:
    name: ${{ github.event_name }} gate
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("pull_request gate", jobs[0]) {
		t.Error("the live check must be accepted via the literal suffix")
	}
	if matchesJob("pull_request build", jobs[0]) {
		t.Error("the literal suffix must still be required")
	}
}

// A name that is entirely one expression has no literal to anchor on.
// Accepting is the safe direction: too lenient only hides a stale entry,
// too strict blocks `main` on a live check.
func TestWhollyExpressionNameIsAccepted(t *testing.T) {
	const body = `name: X
'on':
  pull_request:

jobs:
  gate:
    name: ${{ github.event_name }}
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if !matchesJob("pull_request", jobs[0]) {
		t.Error("the live check must be accepted")
	}
}

// A folded block scalar carries a trailing newline that the line-wise
// snapshot can never have.
func TestFoldedBlockScalarNameIsTrimmed(t *testing.T) {
	const body = "name: X\non:\n  push:\njobs:\n  gate:\n    name: >\n      Required gate\n"
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if jobs[0].checkName != "Required gate" {
		t.Fatalf("got %q", jobs[0].checkName)
	}
	if !matchesJob("Required gate", jobs[0]) {
		t.Error("the snapshot line must match")
	}
}
