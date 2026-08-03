// Command lint-ci-inventory keeps docs/ci-inventory.md honest about what
// CI actually runs.
//
// # Why this exists
//
// docs/ci-inventory.md calls itself "レポジトリの状態の真実 (source of
// truth)" and is read alongside the branch protection settings. It was
// written when the repo had 5 workflows. By the time this lint landed the
// repo had 21, and TEN of them were absent from the document entirely:
//
//	dr-rehearsal.yml         golden-path-e2e.yml    mcp-server-ci.yml
//	migration-lint.yml       migration-lock-lint.yml nullscan.yml
//	project-scope-e2e.yml    release.yml            scheduler-integration.yml
//	toolchain-lint.yml
//
// Twelve of the seventeen required status checks on `main` came from those
// undocumented files. A "source of truth" that omits two thirds of the
// gates it claims to inventory is worse than no document: it is read, it
// is believed, and it is wrong. Nothing detected the drift because nothing
// compared the document to the directory.
//
// # What it checks
//
//  1. GENERATED BLOCK. docs/ci-inventory.md carries a fenced block
//     between the `workflow-job-inventory` markers with one line per CI
//     job. That block must set-equal the jobs actually declared under
//     .github/workflows/. A new workflow, a new job, a renamed job or a
//     deleted workflow all turn this red, with the exact lines to add and
//     remove. `--fix` rewrites the block.
//
//  2. REQUIRED CHECK REFERENTIAL INTEGRITY. The document also carries a
//     hand-maintained snapshot of `main`'s required status checks (taken
//     from `gh api .../branches/main/protection`). Every name in it must
//     still be produced by some job in (1). GitHub matches required checks
//     by NAME, so renaming a job's `name:` silently detaches the required
//     check and leaves `main` unmergeable until a human edits the
//     protection rule. This turns that trap into a red lint instead of a
//     stuck branch.
//
// It deliberately does NOT try to verify the required-check list against
// GitHub: the lint is hermetic and offline (no token, no network, runs on
// forks). The list is a snapshot, and the lint enforces that the snapshot
// still refers to jobs that exist.
//
// # YAML parsing
//
// Stdlib only, so the workflow files are scanned line-wise rather than
// parsed as YAML: after a column-0 `jobs:` key, a 2-space-indented
// `<id>:` opens a job and the first 4-space-indented `name:` inside it
// supplies its check name (GitHub falls back to the job id when `name:`
// is absent). That covers the shape every workflow in this repo uses. It
// is narrow on purpose, and it fails loudly rather than quietly: a
// workflow file that yields zero jobs is an error naming the file, so a
// future formatting change (flow mappings, YAML anchors, a job whose name
// is a block scalar) cannot degrade this lint into a scan that finds
// nothing and passes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	genBegin = "<!-- BEGIN GENERATED: workflow-job-inventory -->"
	genEnd   = "<!-- END GENERATED: workflow-job-inventory -->"
	reqBegin = "<!-- BEGIN SNAPSHOT: required-status-checks -->"
	reqEnd   = "<!-- END SNAPSHOT: required-status-checks -->"

	docRel       = "docs/ci-inventory.md"
	workflowsRel = ".github/workflows"
)

var (
	reJobID   = regexp.MustCompile(`^  ([A-Za-z_][A-Za-z0-9_.\-]*):\s*$`)
	reJobName = regexp.MustCompile(`^    name:\s*(\S.*?)\s*$`)
	reTopKey  = regexp.MustCompile(`^[A-Za-z_'"]`)
)

// job is one CI job: the workflow file it lives in, its YAML key, and the
// name GitHub will show (and match required status checks against).
type job struct {
	file      string // basename, e.g. "web-e2e.yml"
	id        string // YAML key under `jobs:`
	checkName string // `name:` if present, else id
}

func (j job) line() string {
	return fmt.Sprintf("%s :: %s :: %s", j.file, j.id, j.checkName)
}

// parseWorkflow extracts the jobs declared in one workflow file.
//
// Returns an error when the file declares no jobs at all — see the
// package comment on failing loudly.
func parseWorkflow(base, body string) ([]job, error) {
	var (
		jobs   []job
		inJobs bool
		cur    *job
		lines  = strings.Split(body, "\n")
		flush  = func() {}
	)
	flush = func() {
		if cur != nil {
			if cur.checkName == "" {
				cur.checkName = cur.id
			}
			jobs = append(jobs, *cur)
			cur = nil
		}
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		if !inJobs {
			if line == "jobs:" {
				inJobs = true
			}
			continue
		}
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		// A new column-0 key closes the `jobs:` mapping.
		if reTopKey.MatchString(line) {
			break
		}
		if m := reJobID.FindStringSubmatch(line); m != nil {
			flush()
			cur = &job{file: base, id: m[1]}
			continue
		}
		if cur != nil && cur.checkName == "" {
			if m := reJobName.FindStringSubmatch(line); m != nil {
				v := strings.TrimSpace(m[1])
				if v == "|" || v == ">" || strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
					return nil, fmt.Errorf(
						"%s: job %q uses a block-scalar `name:` which this lint cannot read; "+
							"give it a plain single-line name or teach the lint",
						base, cur.id)
				}
				cur.checkName = unquote(v)
			}
		}
	}
	flush()

	if len(jobs) == 0 {
		return nil, fmt.Errorf(
			"%s: no jobs found. Either the file declares none (delete it) or its "+
				"formatting is outside what this lint can read (see the package comment "+
				"in tools/lint-ci-inventory/main.go)", base)
	}
	return jobs, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// collectJobs scans every workflow file under .github/workflows.
func collectJobs(root string) ([]job, error) {
	dir := filepath.Join(root, filepath.FromSlash(workflowsRel))
	var paths []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, fmt.Errorf("glob %s: %w", pat, err)
		}
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("no workflow files under %s — refusing to report an empty inventory as clean", dir)
	}
	var all []job
	for _, p := range paths {
		body, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		jobs, err := parseWorkflow(filepath.Base(p), string(body))
		if err != nil {
			return nil, err
		}
		all = append(all, jobs...)
	}
	sort.Slice(all, func(i, k int) bool {
		if all[i].file != all[k].file {
			return all[i].file < all[k].file
		}
		return all[i].id < all[k].id
	})
	return all, nil
}

// extractBlock returns the lines strictly between begin and end markers.
func extractBlock(doc, begin, end string) ([]string, error) {
	bi := strings.Index(doc, begin)
	if bi < 0 {
		return nil, fmt.Errorf("marker %s not found in %s", begin, docRel)
	}
	rest := doc[bi+len(begin):]
	ei := strings.Index(rest, end)
	if ei < 0 {
		return nil, fmt.Errorf("marker %s not found after %s in %s", end, begin, docRel)
	}
	var out []string
	for _, l := range strings.Split(rest[:ei], "\n") {
		l = strings.TrimRight(l, " \t\r")
		if l == "" || strings.HasPrefix(l, "```") {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// matchesJob reports whether a required status check name is produced by
// this job. Matrix jobs expand `${{ matrix.x }}` at run time, so a job
// whose name carries a template matches any check sharing its literal
// prefix.
func matchesJob(required string, j job) bool {
	if required == j.checkName {
		return true
	}
	if i := strings.Index(j.checkName, "${{"); i >= 0 {
		return strings.HasPrefix(required, j.checkName[:i])
	}
	return false
}

func diff(want, got []string) (missing, extra []string) {
	w := map[string]bool{}
	for _, l := range want {
		w[l] = true
	}
	g := map[string]bool{}
	for _, l := range got {
		g[l] = true
	}
	for _, l := range want {
		if !g[l] {
			missing = append(missing, l)
		}
	}
	for _, l := range got {
		if !w[l] {
			extra = append(extra, l)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

func rewriteBlock(doc string, jobs []job) (string, error) {
	bi := strings.Index(doc, genBegin)
	if bi < 0 {
		return "", fmt.Errorf("marker %s not found in %s", genBegin, docRel)
	}
	ei := strings.Index(doc, genEnd)
	if ei < 0 || ei < bi {
		return "", fmt.Errorf("marker %s not found after %s in %s", genEnd, genBegin, docRel)
	}
	var b strings.Builder
	b.WriteString(doc[:bi+len(genBegin)])
	b.WriteString("\n\n```text\n")
	for _, j := range jobs {
		b.WriteString(j.line())
		b.WriteString("\n")
	}
	b.WriteString("```\n\n")
	b.WriteString(doc[ei:])
	return b.String(), nil
}

// run performs the whole check. Returns the findings (empty == clean).
func run(root string, fix bool, verbose bool, stdout *strings.Builder) ([]string, error) {
	jobs, err := collectJobs(root)
	if err != nil {
		return nil, err
	}
	docPath := filepath.Join(root, filepath.FromSlash(docRel))
	raw, err := os.ReadFile(docPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", docPath, err)
	}
	doc := string(raw)

	want := make([]string, 0, len(jobs))
	for _, j := range jobs {
		want = append(want, j.line())
	}

	if fix {
		updated, err := rewriteBlock(doc, jobs)
		if err != nil {
			return nil, err
		}
		if updated != doc {
			if err := os.WriteFile(docPath, []byte(updated), 0o644); err != nil {
				return nil, fmt.Errorf("write %s: %w", docPath, err)
			}
			fmt.Fprintf(stdout, "rewrote the generated block in %s (%d jobs)\n", docRel, len(jobs))
		} else {
			fmt.Fprintf(stdout, "%s already up to date (%d jobs)\n", docRel, len(jobs))
		}
		doc = updated
	}

	var findings []string

	got, err := extractBlock(doc, genBegin, genEnd)
	if err != nil {
		return nil, err
	}
	missing, extra := diff(want, got)
	for _, l := range missing {
		findings = append(findings, fmt.Sprintf(
			"%s: CI job is not in the generated inventory block — ADD: %s", docRel, l))
	}
	for _, l := range extra {
		findings = append(findings, fmt.Sprintf(
			"%s: generated inventory block names a job that no longer exists — REMOVE: %s", docRel, l))
	}

	required, err := extractBlock(doc, reqBegin, reqEnd)
	if err != nil {
		return nil, err
	}
	if len(required) == 0 {
		findings = append(findings, fmt.Sprintf(
			"%s: the required-status-checks snapshot is empty — refusing to treat that as clean", docRel))
	}
	for _, name := range required {
		matched := false
		for _, j := range jobs {
			if matchesJob(name, j) {
				matched = true
				break
			}
		}
		if !matched {
			findings = append(findings, fmt.Sprintf(
				"%s: required status check %q is not produced by any job under %s. "+
					"GitHub matches required checks BY NAME, so a job rename detaches the "+
					"check and leaves `main` unmergeable until the protection rule is edited. "+
					"Either restore the job's `name:` or update the snapshot after changing "+
					"branch protection.", docRel, name, workflowsRel))
		}
	}

	if verbose {
		fmt.Fprintf(stdout, "workflows scanned: %d job(s) across %d file(s)\n",
			len(jobs), countFiles(jobs))
		for _, j := range jobs {
			fmt.Fprintf(stdout, "  %s\n", j.line())
		}
		fmt.Fprintf(stdout, "required status checks in snapshot: %d\n", len(required))
	}
	sort.Strings(findings)
	return findings, nil
}

func countFiles(jobs []job) int {
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.file] = true
	}
	return len(seen)
}

func main() {
	root := flag.String("repo-root", ".", "path to the repository root")
	fix := flag.Bool("fix", false, "rewrite the generated inventory block in "+docRel)
	verbose := flag.Bool("verbose", false, "print the full job inventory")
	flag.Parse()

	var out strings.Builder
	findings, err := run(*root, *fix, *verbose, &out)
	fmt.Print(out.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "lint-ci-inventory: %v\n", err)
		os.Exit(2)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\nlint-ci-inventory: %d finding(s)\n\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(os.Stderr, "  - %s\n", f)
		}
		fmt.Fprintf(os.Stderr,
			"\nRegenerate the inventory block with:\n"+
				"  (cd tools/lint-ci-inventory && go run . --repo-root ../.. --fix)\n"+
				"then describe the new workflow/job in prose in %s as well — the block is\n"+
				"an index, not a substitute for the §2 tables.\n", docRel)
		os.Exit(1)
	}
	fmt.Printf("lint-ci-inventory: OK — %s covers every job under %s\n", docRel, workflowsRel)
}
