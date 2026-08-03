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
// NINE of the seventeen required status checks on `main` came from those
// undocumented files. (An earlier revision of this comment said twelve.
// That was wrong: dr-rehearsal.yml and release.yml produce no required
// check, so the count is nine. TestRequiredFromUndocumented derives it.)
// A "source of truth" that omits over half the gates it claims to
// inventory is worse than no document: it is read, it is believed, and it
// is wrong. Nothing detected the drift because nothing compared the
// document to the directory.
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
// A real YAML parser (github.com/goccy/go-yaml), not a line scanner.
//
// This used to hand-roll the scan to keep the module stdlib-only. Review
// rounds then produced a steady stream of findings that were all the same
// defect wearing different clothes — an incomplete YAML implementation:
//
//	'API''s audit'           escaped quote read as `API`
//	"security ゲ..."     escape sequence copied through literally
//	name: *gate_name         anchor recorded as the literal `*gate_name`
//	jobs: # comment          exact-match on `jobs:` => "no jobs found"
//	'quoted-job-key':        silently dropped, taking a required check with it
//	label: ['linux, amd64']  split on the comma inside the quotes
//	os: [] / include:        matrix legs mis-expanded in both directions
//
// Every one was real, and several were false positives that would have
// turned `main` red on a correct workflow. They stopped being findings
// the moment the parsing was handed to a parser. The module boundary —
// not the absence of dependencies — is what keeps tooling out of the
// production backend's dependency graph, exactly as this module's go.mod
// has said since it was created.
//
// gopkg.in/yaml.v3 is archived and unmaintained as of 2026; goccy/go-yaml
// is the maintained implementation and passes more of the YAML test
// suite. This repo treats "libraries stay current" as a security-product
// rule, so the archived one was not an option.
//
// What still fails loudly rather than quietly: a workflow file that
// declares no jobs is an error naming the file, and an empty workflows
// directory is an error, so the lint cannot degrade into a scan that
// finds nothing and passes.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

const (
	genBegin = "<!-- BEGIN GENERATED: workflow-job-inventory -->"
	genEnd   = "<!-- END GENERATED: workflow-job-inventory -->"
	reqBegin = "<!-- BEGIN SNAPSHOT: required-status-checks -->"
	reqEnd   = "<!-- END SNAPSHOT: required-status-checks -->"

	docRel       = "docs/ci-inventory.md"
	workflowsRel = ".github/workflows"
)

// `${{ matrix.os }}`. A DOTTED path (`matrix.target.os`) is deliberately
// not matched here — see expandNames.
var reMatrixRef = regexp.MustCompile(`\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// Any matrix reference at all, dotted or not, so a shape the simple one
// cannot expand is detected rather than half-expanded.
var reAnyMatrixRef = regexp.MustCompile(`\$\{\{\s*matrix\.[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}`)

// job is one CI job: the workflow file it lives in, its YAML key, and the
// name GitHub will show (and match required status checks against).
type job struct {
	file      string // basename, e.g. "web-e2e.yml"
	id        string // YAML key under `jobs:`
	checkName string // `name:` if present, else id
	// `name:` was written explicitly. A matrix job WITHOUT one reports as
	// `<id> (<leg>)`, not as `<id>`, so turning a plain required job into
	// a matrix job changes its check names.
	namedExplicitly bool
	// matrix axes in YAML DECLARATION order — GitHub's default name for a
	// nameless matrix job is `id (v1, v2)` in that order.
	matrixOrder []string
	matrix      map[string][]string
	// The matrix uses `include:` / `exclude:`, or an axis this lint could
	// not read. Expanding the declared axes alone would then MISS legs and
	// report a live required check as stale — a false positive that blocks
	// `main`. Fall back to prefix matching, which is lenient.
	matrixIsPartial bool
}

func (j job) line() string {
	return fmt.Sprintf("%s :: %s :: %s", j.file, j.id, j.checkName)
}

// ---------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------

// yamlString renders a scalar the way GitHub shows it in a check name.
// The parser hands back numbers as numbers, so `go: [1.26]` must render
// as `1.26`, not `1.26e+00`.
func yamlString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

// parseWorkflow extracts the jobs declared in one workflow file.
//
// Returns an error when the file declares no jobs at all — see the
// package comment on failing loudly.
func parseWorkflow(base, body string) ([]job, error) {
	// UseOrderedMap so EVERY mapping comes back as a yaml.MapSlice, not
	// just the top level: the matrix axes have to keep their declaration
	// order, because GitHub's default name for a nameless matrix job is
	// `id (v1, v2)` in that order.
	var doc yaml.MapSlice
	if err := yaml.UnmarshalWithOptions([]byte(body), &doc, yaml.UseOrderedMap()); err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}

	var jobsNode any
	for _, item := range doc {
		if fmt.Sprint(item.Key) == "jobs" {
			jobsNode = item.Value
		}
	}
	jobsMap, ok := jobsNode.(yaml.MapSlice)
	if !ok {
		return nil, fmt.Errorf(
			"%s: no `jobs:` mapping found. Either the file declares none (delete it) "+
				"or its top level is not shaped like a GitHub Actions workflow", base)
	}

	var jobs []job
	for _, entry := range jobsMap {
		id := fmt.Sprint(entry.Key)
		j := job{file: base, id: id, checkName: id, matrix: map[string][]string{}}

		spec, _ := entry.Value.(yaml.MapSlice)
		for _, field := range spec {
			switch fmt.Sprint(field.Key) {
			case "name":
				j.checkName = yamlString(field.Value)
				j.namedExplicitly = true
			case "strategy":
				strategy, isMap := field.Value.(yaml.MapSlice)
				if !isMap {
					j.matrixIsPartial = true
					continue
				}
				for _, sf := range strategy {
					if fmt.Sprint(sf.Key) != "matrix" {
						continue
					}
					matrix, isMatrixMap := sf.Value.(yaml.MapSlice)
					if !isMatrixMap {
						j.matrixIsPartial = true
						continue
					}
					for _, axis := range matrix {
						key := fmt.Sprint(axis.Key)
						if key == "include" || key == "exclude" {
							j.matrixIsPartial = true
							continue
						}
						values, isList := axis.Value.([]any)
						if !isList {
							// An axis this lint cannot read (an expression).
							j.matrixIsPartial = true
							continue
						}
						if _, seen := j.matrix[key]; !seen {
							j.matrixOrder = append(j.matrixOrder, key)
						}
						legs := make([]string, 0, len(values))
						nonScalar := false
						for _, v := range values {
							switch v.(type) {
							case yaml.MapSlice, map[string]any, []any:
								// An OBJECT matrix axis
								// (`target: [{os: …, arch: …}]`, referenced
								// as `${{ matrix.target.os }}`). Rendering
								// it as a string would produce a name
								// nothing emits and report a LIVE required
								// check as stale. (Review finding: false
								// positive.)
								nonScalar = true
							}
							legs = append(legs, yamlString(v))
						}
						if nonScalar {
							j.matrixIsPartial = true
							continue
						}
						j.matrix[key] = legs
					}
				}
			}
		}
		jobs = append(jobs, j)
	}

	if len(jobs) == 0 {
		return nil, fmt.Errorf(
			"%s: `jobs:` is empty — refusing to report a workflow with no jobs as clean", base)
	}
	return jobs, nil
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

// ---------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------

// expandNames returns every check name a job can produce.
//
// A matrix job's `name:` carries `${{ matrix.os }}`, so the check GitHub
// reports is one name per matrix leg. Expanding them makes the
// required-check reference test exact: DROPPING a matrix leg (a normal
// edit — "we no longer support windows") reports the stale required check
// instead of silently accepting it.
//
// Returns ok=false when the job's matrix could not be read; the caller
// falls back to prefix matching, which is lenient rather than spuriously
// red.
func expandNames(j job) ([]string, bool) {
	refs := reMatrixRef.FindAllStringSubmatch(j.checkName, -1)
	// A dotted reference this expander does not model: stay lenient.
	if len(reAnyMatrixRef.FindAllString(j.checkName, -1)) != len(refs) {
		return nil, false
	}
	// Any OTHER `${{ … }}` expression — `gate (${{ github.event_name }})`
	// is an ordinary way to label a check — is resolved by GitHub at run
	// time, not here. Comparing the raw text would report a live required
	// check as stale. (Review finding: false positive.)
	if len(refs) == 0 && strings.Contains(j.checkName, "${{") {
		return nil, false
	}
	if len(refs) == 0 {
		if j.namedExplicitly || (len(j.matrix) == 0 && !j.matrixIsPartial) {
			return []string{j.checkName}, true
		}
		// No `name:` and a matrix: GitHub reports `<id> (<leg>, …)`.
		if j.matrixIsPartial {
			return nil, false
		}
		combos := []string{""}
		for _, k := range j.matrixOrder {
			var next []string
			for _, c := range combos {
				for _, v := range j.matrix[k] {
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
		values, ok := j.matrix[ref[1]]
		if !ok {
			return nil, false
		}
		if len(values) == 0 {
			// Readable and empty: the job produces no check names at all.
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
	for _, n := range names {
		if strings.Contains(n, "${{") {
			// A non-matrix expression survived the expansion
			// (`gate ${{ matrix.os }} / ${{ github.event_name }}`).
			// GitHub resolves it at run time; comparing the raw text
			// would call a live check stale.
			return nil, false
		}
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
	// Unresolved expressions: anchor on the literal text around them.
	// Using only the prefix rejected `${{ github.event_name }} gate`
	// outright (empty prefix), and an empty prefix alone would match
	// everything — so require BOTH ends, and at least one of them to be
	// non-empty. (Review findings: false positives.)
	if i := strings.Index(j.checkName, "${{"); i >= 0 {
		prefix := j.checkName[:i]
		suffix := ""
		if k := strings.LastIndex(j.checkName, "}}"); k >= 0 {
			suffix = j.checkName[k+2:]
		}
		if prefix == "" && suffix == "" {
			// The whole name is one expression (`name: ${{ github.event_name }}`).
			// There is no literal to anchor on, so this job cannot be
			// distinguished from any other — accept, rather than call a
			// live required check stale. Being too lenient can only hide a
			// stale entry; being too strict blocks `main`. (Review
			// finding: false positive.)
			return true
		}
		return strings.HasPrefix(required, prefix) &&
			strings.HasSuffix(required, suffix) &&
			len(required) >= len(prefix)+len(suffix)
	}
	// A NAMELESS job whose matrix could not be expanded (an `include:` /
	// `exclude:`, say) reports as `<id> (<leg>)`, and its check name
	// carries no expression to take a prefix from. Accept the leg form
	// rather than call a live check stale. (Review finding: false
	// positive.)
	if !j.namedExplicitly && (len(j.matrix) > 0 || j.matrixIsPartial) {
		return required == j.id || strings.HasPrefix(required, j.id+" (")
	}
	return false
}

// ---------------------------------------------------------------------
// Document
// ---------------------------------------------------------------------

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

// ---------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------

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
