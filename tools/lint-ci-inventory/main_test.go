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
  push:
    branches:
      - main

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
    steps:
      - name: Checkout
        uses: actions/checkout@v4
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
    steps:
      - run: echo hi
`
	jobs, err := parseWorkflow("docker-publish.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if len(jobs) != 1 || jobs[0].checkName != "build-and-push" {
		t.Fatalf("got %+v, want one job named build-and-push", jobs)
	}
}

// The `on:` block also has 2-space keys (`push:`, `pull_request:`); they
// must not be mistaken for jobs.
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

// Anti-vacuity: a file this lint cannot read must be an ERROR, never a
// silent "no jobs here, nothing to check".
func TestParseWorkflow_UnreadableFileIsAnError(t *testing.T) {
	const body = `name: X
on: {push: {branches: [main]}}
jobs: {compact: {runs-on: ubuntu-latest}}
`
	if _, err := parseWorkflow("x.yml", body); err == nil {
		t.Fatal("expected an error for a flow-mapping jobs block, got nil")
	}
}

// A job key with an inline body would otherwise be read as a job with no
// steps and no name — a silent drop of everything nested inside it.
func TestParseWorkflow_InlineJobBodyIsAnError(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  good:
    name: fine
    runs-on: ubuntu-latest
  compact: {runs-on: ubuntu-latest, name: sneaky}
`
	_, err := parseWorkflow("x.yml", body)
	if err == nil || !strings.Contains(err.Error(), "compact") {
		t.Fatalf("expected an inline-body error naming the job, got %v", err)
	}
}

// A quoted job key is valid YAML but outside what this scanner reads.
// Dropping it silently would hide a whole job — the file's other jobs
// keep the "no jobs found" guard quiet — so it must be a loud error.
func TestParseWorkflow_QuotedJobKeyIsAnError(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  visible:
    name: visible
    runs-on: ubuntu-latest
  'hidden':
    name: required-hidden
    runs-on: ubuntu-latest
`
	_, err := parseWorkflow("x.yml", body)
	if err == nil || !strings.Contains(err.Error(), "hidden") {
		t.Fatalf("expected an error naming the unreadable key, got %v", err)
	}
}

// A quoted `'name':` key would otherwise fall through and record the job
// under its ID — the wrong check name, with no error.
func TestParseWorkflow_QuotedNameKeyIsAnError(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  build:
    'name': required-gate
    runs-on: ubuntu-latest
`
	_, err := parseWorkflow("x.yml", body)
	if err == nil || !strings.Contains(err.Error(), "required-gate") {
		t.Fatalf("expected an error naming the unreadable name key, got %v", err)
	}
}

// A trailing comment on the job key is fine.
func TestParseWorkflow_TrailingCommentOnJobKey(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  build: # the only job
    name: build-and-test
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if len(jobs) != 1 || jobs[0].checkName != "build-and-test" {
		t.Fatalf("got %+v", jobs)
	}
}

func TestParseWorkflow_BlockScalarNameIsAnError(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  j:
    name: >
      folded name
    runs-on: ubuntu-latest
`
	_, err := parseWorkflow("x.yml", body)
	if err == nil || !strings.Contains(err.Error(), "block-scalar") {
		t.Fatalf("expected a block-scalar error, got %v", err)
	}
}

// GitHub shows `Security gate`; keeping the raw line would record the
// comment as part of the check name.
func TestParseWorkflow_StripsInlineComment(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  j:
    name: Security gate # required check
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if jobs[0].checkName != "Security gate" {
		t.Fatalf("got %q, want %q", jobs[0].checkName, "Security gate")
	}
}

// A quoted value keeps everything inside the quotes, including a `#`.
func TestParseWorkflow_QuotedNameKeepsHash(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  j:
    name: 'gate #3' # a comment
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if jobs[0].checkName != "gate #3" {
		t.Fatalf("got %q, want %q", jobs[0].checkName, "gate #3")
	}
}

func TestParseWorkflow_UnquotesName(t *testing.T) {
	const body = `name: X
on:
  push:

jobs:
  j:
    name: 'quoted name'
    runs-on: ubuntu-latest
`
	jobs, err := parseWorkflow("x.yml", body)
	if err != nil {
		t.Fatalf("parseWorkflow: %v", err)
	}
	if jobs[0].checkName != "quoted name" {
		t.Fatalf("got %q", jobs[0].checkName)
	}
}

// ---------------------------------------------------------------------
// matchesJob
// ---------------------------------------------------------------------

func TestMatchesJob(t *testing.T) {
	plain := job{file: "a.yml", id: "j", checkName: "static gate (hermetic)"}
	matrix := job{file: "b.yml", id: "k", checkName: "install.sh must succeed on ${{ matrix.os }}"}

	// A name that STARTS with an expression has an empty literal prefix.
	// HasPrefix(x, "") is true for every x, so without the `i > 0` guard
	// this job would vouch for every required check in the snapshot.
	leading := job{file: "c.yml", id: "l", checkName: "${{ matrix.os }} build"}

	cases := []struct {
		required string
		j        job
		want     bool
	}{
		{"static gate (hermetic)", plain, true},
		{"static gate", plain, false},
		{"install.sh must succeed on ubuntu-latest", matrix, true},
		{"install.sh must succeed on macos-latest", matrix, true},
		{"install.sh must fail on macos-latest", matrix, false},
		{"anything at all", leading, false},
		{"${{ matrix.os }} build", leading, true},
	}
	for _, c := range cases {
		if got := matchesJob(c.required, c.j); got != c.want {
			t.Errorf("matchesJob(%q, %q) = %v, want %v", c.required, c.j.checkName, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------
// run() end-to-end, against scripted repo trees
// ---------------------------------------------------------------------

// scaffold writes a minimal repo: two workflows and a doc whose blocks
// are filled from the caller's strings.
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
	joined := strings.Join(f, "\n")
	if !strings.Contains(joined, `required status check "static gate (hermetic)" is not produced by any job`) {
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
	// Idempotent.
	var out2 strings.Builder
	if _, err := run(root, true, false, &out2); err != nil {
		t.Fatalf("second --fix: %v", err)
	}
	if !strings.Contains(out2.String(), "already up to date") {
		t.Fatalf("second --fix should be a no-op, got %q", out2.String())
	}
}

// `--fix` must not leave a stray temp file behind, and must preserve the
// document's mode.
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
// in each.
func TestRealRepositoryParses(t *testing.T) {
	root := "../.."
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows")); err != nil {
		t.Skipf("not running inside the repo: %v", err)
	}
	jobs, err := collectJobs(root)
	if err != nil {
		t.Fatalf("collectJobs: %v", err)
	}
	if countFiles(jobs) < 20 {
		t.Fatalf("only %d workflow files parsed — the scanner has drifted", countFiles(jobs))
	}
	for _, j := range jobs {
		if j.checkName == "" {
			t.Errorf("%s :: %s has an empty check name", j.file, j.id)
		}
	}
}
