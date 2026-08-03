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
	// A 2-space-indented key under `jobs:` opens a job. The trailing
	// group captures anything after the colon so a shape this lint cannot
	// read (`  build: {runs-on: x}`) becomes a loud error instead of a
	// silently dropped job — a trailing `# comment` is the one tolerated
	// case.
	reJobID = regexp.MustCompile(`^  ([A-Za-z_][A-Za-z0-9_.\-]*):(.*)$`)
	// Any 2-space-indented key at all. A line that looks like a job key
	// but does not match reJobID (a quoted `'hidden':`, say) must be an
	// ERROR, not a silently dropped job — see parseWorkflow.
	reAnyJobKey = regexp.MustCompile(`^  \S.*:`)
	reJobName   = regexp.MustCompile(`^    name:\s*(\S.*?)\s*$`)
	// A quoted `'name':` key is valid YAML that reJobName cannot read.
	// Falling through would leave the job reporting under its ID, i.e. a
	// wrong check name recorded with no error — see parseWorkflow.
	reQuotedNameKey = regexp.MustCompile(`^    ['"]name['"]\s*:`)
	reTopKey        = regexp.MustCompile(`^[A-Za-z_'"]`)
	reJobsOpen      = regexp.MustCompile(`^jobs:\s*(#.*)?$`)

	// `strategy:` / `      matrix:` open the block; `        os:` is a key
	// inside it, `          - ubuntu-latest` an item, `        os: [a, b]`
	// the inline form. Read only well enough to expand a `name:` template.
	reStrategyOpen = regexp.MustCompile(`^    strategy:\s*$`)
	reMatrixOpen   = regexp.MustCompile(`^      matrix:\s*$`)
	reMatrixKey    = regexp.MustCompile(`^        ([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$`)
	reMatrixItem   = regexp.MustCompile(`^          -\s*(\S.*?)\s*$`)
	reMatrixAdjust = regexp.MustCompile(`^        (include|exclude):`)
)

// job is one CI job: the workflow file it lives in, its YAML key, and the
// name GitHub will show (and match required status checks against).
type job struct {
	file      string // basename, e.g. "web-e2e.yml"
	id        string // YAML key under `jobs:`
	checkName string // `name:` if present, else id
	// matrix values keyed by `matrix.<key>`, when the job declares a
	// `strategy.matrix` this scanner could read. Empty for a plain job.
	matrix map[string][]string
	// The matrix uses `include:` / `exclude:`, which add or remove legs
	// this scanner does not model. Expanding the declared keys alone
	// would then MISS legs and report a live required check as stale —
	// a false positive that blocks `main`. Fall back to prefix matching
	// instead, which is lenient. (Review finding under the declared
	// threat model.)
	matrixIsPartial bool
	// `name:` was written explicitly. A matrix job WITHOUT one reports as
	// `<id> (<leg>)`, not as `<id>` — so turning a plain required job into
	// a matrix job changes its check names, and keeping `<id>` would have
	// vouched for the now-nonexistent old check. (Review finding under the
	// declared threat model.)
	namedExplicitly bool
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
		jobs       []job
		inJobs     bool
		cur        *job
		inStrategy bool
		inMatrix   bool
		matrixKey  string
		lines      = strings.Split(body, "\n")
		flush      = func() {}
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
			// `jobs: # repository gates` is valid YAML. Requiring an exact
			// `jobs:` made an ordinary comment turn the whole file into
			// "no jobs found" — a hard error on a correct workflow.
			// (Review finding under the declared threat model.)
			if reJobsOpen.MatchString(line) {
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
			if rest := strings.TrimSpace(m[2]); rest != "" && !strings.HasPrefix(rest, "#") {
				return nil, fmt.Errorf(
					"%s: job %q is declared as %q, which this lint cannot read "+
						"(it expects `  <id>:` with the job body indented below). "+
						"Reformat it or teach the lint — silently dropping the job would "+
						"let an undocumented required status check slip through",
					base, m[1], strings.TrimSpace(line))
			}
			flush()
			cur = &job{file: base, id: m[1], matrix: map[string][]string{}}
			inStrategy, inMatrix, matrixKey = false, false, ""
			continue
		}

		// strategy.matrix, read only well enough to expand a `name:`
		// template. Anything unexpected simply leaves the map empty, and
		// expandNames falls back to prefix matching.
		if cur != nil {
			if reStrategyOpen.MatchString(line) {
				inStrategy, inMatrix, matrixKey = true, false, ""
				continue
			}
			if inStrategy && reMatrixOpen.MatchString(line) {
				inMatrix, matrixKey = true, ""
				continue
			}
			if inMatrix {
				if reMatrixAdjust.MatchString(line) {
					cur.matrixIsPartial = true
					matrixKey = ""
					continue
				}
				if m := reMatrixItem.FindStringSubmatch(line); m != nil && matrixKey != "" {
					cur.matrix[matrixKey] = append(cur.matrix[matrixKey], scalarValue(m[1]))
					continue
				}
				if m := reMatrixKey.FindStringSubmatch(line); m != nil {
					matrixKey = m[1]
					rest := strings.TrimSpace(m[2])
					// `os: [ubuntu-latest] # windows removed` — the natural
					// edit when dropping a leg. Without stripping the
					// comment the list stopped looking readable and the
					// lenient prefix fallback accepted the stale check.
					// (Review finding under the declared threat model.)
					if i := strings.Index(rest, "] #"); i >= 0 {
						rest = strings.TrimSpace(rest[:i+1])
					}
					if strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
						// Declared inline, so its contents ARE known — even
						// when empty. `os: []` (the last supported OS just
						// removed) produces no legs at all, and the stale
						// required check naming the old leg has to be
						// reported rather than accepted on a bare prefix.
						// (Review finding under the declared threat model.)
						cur.matrix[matrixKey] = []string{}
						for _, v := range strings.Split(rest[1:len(rest)-1], ",") {
							if v = scalarValue(v); v != "" {
								cur.matrix[matrixKey] = append(cur.matrix[matrixKey], v)
							}
						}
					}
					continue
				}
				// Dedented out of the matrix block.
				inMatrix, matrixKey = false, ""
			}
			if inStrategy && !strings.HasPrefix(line, "      ") {
				inStrategy = false
			}
		}
		// A 2-space key that reJobID could not read is a job this lint
		// cannot see. Dropping it silently would hide a whole job — and
		// possibly a required status check — from the inventory, while the
		// file's OTHER jobs kept the "no jobs found" guard quiet.
		// (Review finding, High.)
		if reAnyJobKey.MatchString(line) {
			return nil, fmt.Errorf(
				"%s: %q looks like a job key but is not in the `  <id>:` form this lint "+
					"reads (quoted or non-identifier keys are not supported). Reformat it "+
					"or teach the lint — silently dropping the job would let an "+
					"undocumented required status check slip through",
				base, strings.TrimSpace(line))
		}
		if cur != nil && cur.checkName == "" {
			if reQuotedNameKey.MatchString(line) {
				return nil, fmt.Errorf(
					"%s: job %q declares its name as %q, which this lint cannot read; "+
						"use an unquoted `name:` key — falling back to the job id would "+
						"record the WRONG check name with no error",
					base, cur.id, strings.TrimSpace(line))
			}
			if m := reJobName.FindStringSubmatch(line); m != nil {
				v := strings.TrimSpace(m[1])
				if v == "|" || v == ">" || strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
					return nil, fmt.Errorf(
						"%s: job %q uses a block-scalar `name:` which this lint cannot read; "+
							"give it a plain single-line name or teach the lint",
						base, cur.id)
				}
				cur.checkName = scalarValue(v)
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

// scalarValue reads a single-line YAML scalar: strips the quotes of a
// quoted value, and cuts a trailing ` #` comment off a plain one.
//
// Keeping the raw text recorded `name: Security gate # required check` as
// the check name, while GitHub reports `Security gate` — a mismatch that
// would then be "fixed" by writing the wrong name into the inventory.
// (Review finding, High.)
// A single-quoted YAML scalar escapes a quote by doubling it, so
// `'API”s audit'` decodes to `API's audit`. Stopping at the first inner
// quote read it as `API` — and since the wrong value went into BOTH the
// parse and the `--fix` output, the two agreed and the lint reported
// clean. An author adding an apostrophe to a job name and a formatter
// quoting the line is all it takes. (Review finding under the declared
// threat model.) Double-quoted scalars use backslash escapes instead.
func scalarValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '\'' {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				return b.String()
			}
			b.WriteByte(s[i])
		}
		return s // unterminated; hand back the raw text so it mismatches loudly
	}
	if len(s) >= 2 && s[0] == '"' {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			if s[i] == '"' {
				return b.String()
			}
			b.WriteByte(s[i])
		}
		return s
	}
	if i := strings.Index(s, " #"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
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

var reMatrixRef = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// expandNames returns every check name a job can produce.
//
// A matrix job's `name:` carries `${{ matrix.os }}`, so the check GitHub
// reports is one name per matrix leg. Expanding them makes the
// required-check reference test exact: DROPPING a matrix leg (a normal
// edit — "we no longer support windows") now reports the stale required
// check instead of silently accepting it, because the old leg's name is
// no longer produced by anything. That accident is exactly what the
// snapshot exists to catch. (Review finding under the declared threat
// model.)
//
// Returns ok=false when the name references a matrix key this scanner
// could not read; the caller then falls back to prefix matching, which is
// lenient rather than spuriously red.
func expandNames(j job) ([]string, bool) {
	refs := reMatrixRef.FindAllStringSubmatch(j.checkName, -1)
	if len(refs) == 0 {
		if j.namedExplicitly || len(j.matrix) == 0 {
			return []string{j.checkName}, true
		}
		// No `name:` and a matrix: GitHub reports `<id> (<leg>, …)`.
		if j.matrixIsPartial {
			return nil, false
		}
		keys := make([]string, 0, len(j.matrix))
		for k := range j.matrix {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		combos := []string{""}
		for _, k := range keys {
			values := j.matrix[k]
			var next []string
			for _, c := range combos {
				for _, v := range values {
					if c == "" {
						next = append(next, v)
					} else {
						next = append(next, c+", "+v)
					}
				}
			}
			combos = next
		}
		names := make([]string, 0, len(combos))
		for _, c := range combos {
			names = append(names, fmt.Sprintf("%s (%s)", j.id, c))
		}
		return names, true
	}
	if j.matrixIsPartial {
		return nil, false
	}
	names := []string{j.checkName}
	for _, ref := range refs {
		key := ref[1]
		values, ok := j.matrix[key]
		if !ok {
			// Key not readable at all: stay lenient.
			return nil, false
		}
		if len(values) == 0 {
			// Readable and empty: the job produces no check names.
			return nil, true
		}
		var next []string
		for _, n := range names {
			for _, v := range values {
				next = append(next, strings.ReplaceAll(n, ref[0], v))
			}
		}
		names = next
	}
	return names, true
}

// matchesJob reports whether a required status check name is produced by
// this job.
func matchesJob(required string, j job) bool {
	// Expansion first, and authoritative when it succeeds. A literal
	// `required == j.checkName` shortcut would keep vouching for the
	// pre-matrix name of a job that has since become a matrix job.
	if names, ok := expandNames(j); ok {
		for _, n := range names {
			if required == n {
				return true
			}
		}
		return false
	}
	if required == j.checkName {
		return true
	}
	// Unreadable matrix: fall back to the literal prefix before the first
	// expression. `i > 0`, not `i >= 0` — a name that STARTS with an
	// expression has an empty literal prefix, and HasPrefix(x, "") is true
	// for every x, so such a job would vouch for every required check in
	// the snapshot and hide all of them.
	if i := strings.Index(j.checkName, "${{"); i > 0 {
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

// writeFileAtomic replaces path via a same-directory temp file + rename.
//
// `--fix` rewrites the WHOLE of docs/ci-inventory.md, a hand-written
// document. A plain os.WriteFile truncates first, so an interrupted or
// failing write leaves a truncated doc with no copy of what was there.
// rename(2) within a directory is atomic, so a reader sees either the old
// document or the new one. (Review finding, Medium.)
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// No-op once the rename has succeeded.
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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
			if err := writeFileAtomic(docPath, []byte(updated)); err != nil {
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
