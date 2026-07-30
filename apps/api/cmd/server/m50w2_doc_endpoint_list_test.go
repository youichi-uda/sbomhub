package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// TestM50W2UpgradeDocEndpointListMatchesTheRouteTable keeps the operator-facing
// enumeration in docs/UPGRADE.md §2d in step with the code.
//
// §2d lists, verbatim, the endpoints a project-scoped API key may use. An
// operator uses that list to decide whether a key they are about to hand to a
// contractor is sufficient, so a list that drifts is worse than no list: it
// reads as authoritative. This test compares the fenced block against
// middleware.APIKeyRouteScopeKeys() and requires the difference to be exactly
// the nine routes §2d describes in prose instead (the four tenant-wide refusals,
// the two narrowed project lists, the two body-resolved CLI routes, and the
// stateless /cli/check).
//
// It does NOT check the prose around the list, only the fenced block.
func TestM50W2UpgradeDocEndpointListMatchesTheRouteTable(t *testing.T) {
	const docPath = "../../../../docs/UPGRADE.md"
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read %s: %v", docPath, err)
	}

	// The block is anchored on its first line so a different fenced block
	// elsewhere in the document cannot be picked up by accident.
	block := regexp.MustCompile("(?s)```\\n(POST   /api/v1/projects/:id/sbom\\n.*?)```").FindSubmatch(raw)
	if block == nil {
		t.Fatalf("docs/UPGRADE.md no longer contains the §2d fenced endpoint list "+
			"(anchored on %q). If the list was removed, remove this test and the "+
			"cross-references in docs/api.md and docs/api.ja.md that promise it.",
			"POST   /api/v1/projects/:id/sbom")
	}

	documented := map[string]bool{}
	for _, line := range strings.Split(string(block[1]), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			t.Errorf("malformed line in the §2d endpoint list: %q (want `METHOD /path`)", line)
			continue
		}
		documented[fields[0]+" "+fields[1]] = true
	}
	if len(documented) == 0 {
		t.Fatal("parsed no endpoints out of the §2d list — the regexp is blind")
	}

	classified := map[string]bool{}
	for _, k := range appmw.APIKeyRouteScopeKeys() {
		classified[k] = true
	}

	// Everything the document lists must be a real, classified route.
	var notARoute []string
	for k := range documented {
		if !classified[k] {
			notARoute = append(notARoute, k)
		}
	}
	sort.Strings(notARoute)
	for _, k := range notARoute {
		t.Errorf("docs/UPGRADE.md §2d lists %q as usable by a project-scoped key, but no "+
			"such route is classified in middleware.apiKeyRouteScope. The document is "+
			"promising an endpoint that does not exist.", k)
	}

	// And the routes the document leaves OUT must be exactly the nine it
	// describes in prose instead. Anything else means a new API-key-reachable
	// route was classified without §2d being updated.
	describedInProse := map[string]bool{
		"GET /api/v1/cli/projects":          true,
		"GET /api/v1/mcp/projects":          true,
		"GET /api/v1/mcp/dashboard/summary": true,
		"GET /api/v1/mcp/search/cve":        true,
		"GET /api/v1/mcp/search/component":  true,
		"POST /api/v1/mcp/sbom/diff":        true,
		"POST /api/v1/cli/upload":           true,
		"POST /api/v1/cli/projects":         true,
		"POST /api/v1/cli/check":            true,
	}
	var undocumented []string
	for k := range classified {
		if !documented[k] && !describedInProse[k] {
			undocumented = append(undocumented, k)
		}
	}
	sort.Strings(undocumented)
	for _, k := range undocumented {
		t.Errorf("%q is classified in middleware.apiKeyRouteScope but appears neither in "+
			"the docs/UPGRADE.md §2d list nor in this test's prose-described set. Add it to "+
			"the §2d list (if a project-scoped key may use it) or to describedInProse "+
			"(if §2d covers it in prose).", k)
	}

	// Guard against the prose set going stale in the other direction.
	for k := range describedInProse {
		if !classified[k] {
			t.Errorf("describedInProse lists %q, which is no longer a classified route", k)
		}
		if documented[k] {
			t.Errorf("%q is in BOTH the §2d fenced list and describedInProse; the fenced "+
				"list is meant to hold only the path-parameter routes", k)
		}
	}
}
