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

// TestM53ScanStepFailsLoudly is the direct guard on the regression.
func TestM53ScanStepFailsLoudly(t *testing.T) {
	body := m53Workflow(t)

	// The anchor. If the step is renamed or removed, everything below would
	// pass vacuously, so fail here instead.
	const anchor = "- name: Trigger Vulnerability Scan"
	idx := strings.Index(body, anchor)
	if idx < 0 {
		t.Fatalf("%s no longer contains a step named %q — this guard is blind. If the "+
			"step was deliberately removed, delete this test with it.", m53WorkflowPath, anchor)
	}
	step := body[idx:]

	// Anchored to a YAML key, not a substring: the step's own comment explains
	// that `continue-on-error: true` was removed, and a substring match would
	// therefore fail on the explanation for the fix.
	if regexp.MustCompile(`(?m)^\s*continue-on-error\s*:`).MatchString(body) {
		t.Errorf("%s sets `continue-on-error`. It was removed in M53 W1 because it was "+
			"the single reason a scan trigger that answered 404/401 for every API key never "+
			"turned a run red. A step that cannot fail cannot report anything.", m53WorkflowPath)
	}

	for _, want := range []struct{ token, why string }{
		{"set -euo pipefail",
			"without it the step's shell continues past a failed assignment and the " +
				"final `echo` still exits 0"},
		{"--fail-with-body",
			"curl exits 0 on a 4xx unless it is told not to, so a 403/401 from either " +
				"call would be printed and ignored — the same silence continue-on-error gave"},
		{"exit 1",
			"the read-back producing no `.id` must end the step; the pre-M53 version " +
				"treated it as `nothing to do` and exited 0"},
	} {
		if !strings.Contains(step, want.token) {
			t.Errorf("the scan step in %s does not contain %q — %s", m53WorkflowPath, want.token, want.why)
		}
	}

	// Two --fail-with-body: the read-back AND the scan trigger. One of them
	// carrying it while the other does not is exactly half a fix.
	if n := strings.Count(step, "--fail-with-body"); n < 2 {
		t.Errorf("the scan step uses --fail-with-body %d time(s), want 2 (the read-back and "+
			"the scan POST). A silent curl on either call re-opens the hole.", n)
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
