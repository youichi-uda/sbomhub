package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// M53 W1 (Codex round 1, Low #3) — pin the WORKFLOW, not only the route.
//
// The rest of this wave is Go: the route registration, its middleware chain and
// its project-scope classification are all pinned by AST tests. None of that
// touches .github/workflows/sbom-upload.yml, and the workflow is where the
// defect was actually visible — `continue-on-error: true` is what turned "the
// scan trigger has never worked with an API key" into a green run for months.
// Codex's repro was exact: restoring that one line left `go test ./...` green.
//
// So this file asserts the three properties of the scan step that make a
// failure LOUD, over the shipped YAML. It is a text check rather than a YAML
// parse on purpose — apps/api has no YAML dependency, and every property here
// is a literal token whose absence is the regression.
// ---------------------------------------------------------------------------

const m53WorkflowPath = "../../../../.github/workflows/sbom-upload.yml"

func m53Workflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(m53WorkflowPath)
	if err != nil {
		t.Fatalf("read %s: %v", m53WorkflowPath, err)
	}
	return string(raw)
}

// m53RunBlock returns the SHELL BODY of the named step — the lines under its
// `run: |`, with every `#` comment line dropped.
//
// Stripping comments is load-bearing (Codex round 2, Low): the first version of
// this file counted tokens over the raw step text, and the step's own comments
// name the very flags being counted, so a comment mentioning `--fail-with-body`
// made the count agree while an executable one was missing. A guard that its own
// prose can satisfy is not a guard.
func m53RunBlock(t *testing.T, stepName string) string {
	t.Helper()
	body := m53Workflow(t)

	anchor := "- name: " + stepName
	idx := strings.Index(body, anchor)
	if idx < 0 {
		t.Fatalf("%s no longer contains a step named %q — this guard is blind. If the "+
			"step was deliberately removed, delete its assertions with it.", m53WorkflowPath, stepName)
	}
	rest := body[idx:]
	runIdx := strings.Index(rest, "run: |")
	if runIdx < 0 {
		t.Fatalf("step %q has no `run: |` block", stepName)
	}
	lines := strings.Split(rest[runIdx:], "\n")[1:]

	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// The block ends at the first line that is neither blank nor indented
		// past the step's own keys — i.e. the next `- name:` or step key.
		if trimmed != "" && !strings.HasPrefix(line, "          ") {
			break
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		t.Fatalf("parsed an empty run block for step %q — the parser is blind", stepName)
	}
	return strings.Join(out, "\n")
}

// TestM53ScanStepFailsLoudly is the direct guard on the regression.
func TestM53ScanStepFailsLoudly(t *testing.T) {
	body := m53Workflow(t)

	// Anchored to a YAML key, not a substring: the step's own comment explains
	// that `continue-on-error: true` was removed, and a substring match would
	// therefore fail on the explanation for the fix.
	if regexp.MustCompile(`(?m)^\s*continue-on-error\s*:`).MatchString(body) {
		t.Errorf("%s sets `continue-on-error`. It was removed in M53 W1 because it was "+
			"the single reason a scan trigger that answered 404/401 for every API key never "+
			"turned a run red. A step that cannot fail cannot report anything.", m53WorkflowPath)
	}

	scan := m53RunBlock(t, "Trigger Vulnerability Scan")

	for _, want := range []struct{ token, why string }{
		{"set -euo pipefail",
			"GitHub already runs the step as `bash -e {0}`, so what this adds is `-u` " +
				"(an unset variable must not become an empty segment of a URL) and " +
				"`pipefail`"},
		{`!= "200"`,
			"the read-back's status must be compared EXACTLY. curl --fail-with-body " +
				"only fails on >= 400, so a 3xx (these calls do not follow redirects) or " +
				"an unexpected 2xx from a proxy would pass"},
		{`!= "202"`,
			"the scan trigger answers 202 Accepted; anything else means no scan was " +
				"started and the step must not print that one was"},
	} {
		if !strings.Contains(scan, want.token) {
			t.Errorf("the scan step's shell in %s does not contain %q — %s",
				m53WorkflowPath, want.token, want.why)
		}
	}

	// Three refusals: read-back status, missing .id, scan status. Counting them
	// is what catches "one of the three checks was deleted" — each `if` above
	// is useless without its `exit 1`.
	if n := strings.Count(scan, "exit 1"); n < 3 {
		t.Errorf("the scan step's shell has %d `exit 1`(s), want at least 3 (read-back "+
			"status, missing .id, scan status). A check whose branch does not exit is a "+
			"log line, not a gate.", n)
	}
}

// TestM53UploadStepFailsLoudly holds the upload step to the same bar.
//
// It is not what this wave set out to fix, but it is the same defect one step
// earlier (Codex round 2, Medium, reported against the scan step): the upload
// relied on `curl --fail-with-body`, which passes on a 3xx, and then printed
// "SBOM uploaded successfully!". Leaving that next to the step just hardened
// would have been a strange place to stop — and this workflow's whole failure
// mode was a step that reported success it had not earned.
func TestM53UploadStepFailsLoudly(t *testing.T) {
	upload := m53RunBlock(t, "Upload SBOM to SBOMHub")

	if !strings.Contains(upload, `!= "201"`) {
		t.Errorf("the upload step's shell in %s does not compare the status to 201. "+
			"curl --fail-with-body passes on a 3xx, so the step would print "+
			"\"SBOM uploaded successfully!\" with nothing uploaded.", m53WorkflowPath)
	}
	if n := strings.Count(upload, "exit 1"); n < 3 {
		t.Errorf("the upload step's shell has %d `exit 1`(s), want at least 3 (missing "+
			"PROJECT_ID, missing API key, non-201 upload)", n)
	}
}

// TestM53ScanInputIsWiredAndOptIn covers the OTHER half of Codex round 1's
// Medium #1, which is the more surprising half.
//
// POST /api/v1/projects/:id/sbom ALREADY starts a tracked NVD/JVN scan of its
// own (SbomHandler.startBackgroundScan), and always has. Measured on a
// throwaway stack 2026-08-05: uploading the fixture with NO subsequent /scan
// call produced one component_vulnerabilities row and left
// GET /sboms/:sbom_id/scan-status reporting `"status":"completed"` with
// `"critical":1`. So the workflow's third step was never the thing that made
// the SBOM get scanned — it is a RE-scan, and once the route was made reachable
// it became a second, UNTRACKED sweep of an SBOM the server had just scanned
// (measured on the same stack: NVD absorbed by its Redis cache with
// `cache_hits=1, api_calls=0`, JVN issuing a fresh outbound request because it
// has no cache; the row count did not change and scan-status did not move,
// because the manual route has no ScanTracker).
//
// Hence `default: false`. Doing otherwise would have made this wave ADD
// duplicated outbound traffic to every dispatch, in the name of fixing a silent
// failure. With the default off, the observable behaviour of a plain dispatch is
// unchanged by M53 W1 — the SBOM is still scanned, once, by the upload — and the
// input now means something when it is switched on.
func TestM53ScanInputIsWiredAndOptIn(t *testing.T) {
	body := m53Workflow(t)

	if !regexp.MustCompile(`(?m)^\s*if:\s*\$\{\{\s*inputs\.scan\s*\}\}`).MatchString(body) {
		t.Errorf("%s does not gate the scan step on `if: ${{ inputs.scan }}`. The `scan` "+
			"input is declared at the top of the file; leaving it unread makes the form "+
			"control a lie.", m53WorkflowPath)
	}

	block := regexp.MustCompile(`(?s)scan:\s*\n(.*?)\n\s*\n`).FindStringSubmatch(body)
	if block == nil {
		t.Fatalf("%s no longer declares a `scan:` workflow_dispatch input — this guard is blind",
			m53WorkflowPath)
	}
	if !strings.Contains(block[1], "default: false") {
		t.Errorf("the `scan` input is not `default: false`:\n%s\n"+
			"POST /api/v1/projects/:id/sbom already runs a tracked NVD/JVN scan on ingest, so "+
			"defaulting this to true makes every dispatch sweep the same SBOM twice — the "+
			"second time without a ScanTracker, so nothing observes it.", block[1])
	}
}
