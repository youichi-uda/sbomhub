package middleware

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// newCtxWithParams builds a minimal echo.Context with the given path param
// bindings. It is the cheapest way to drive extractResourceID under test
// without spinning up the whole middleware chain — extractResourceID only
// touches c.Param() and c.ParamNames(), both of which are populated by
// SetParamNames / SetParamValues regardless of the underlying request.
func newCtxWithParams(t *testing.T, names []string, values []string) echo.Context {
	t.Helper()
	if len(names) != len(values) {
		t.Fatalf("test setup: %d param names but %d values", len(names), len(values))
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	return c
}

// assertResourceID is a tiny helper to keep the per-case tests readable.
func assertResourceID(t *testing.T, got *uuid.UUID, want uuid.UUID) {
	t.Helper()
	if got == nil {
		t.Fatalf("extractResourceID returned nil, want %s", want)
	}
	if *got != want {
		t.Errorf("extractResourceID = %s, want %s", got, want)
	}
}

// TestDetermineActionAndResource_APIKey pins F176 fix: the audit middleware
// must classify both the tenant-scoped /apikeys routes and the project-
// scoped /projects/:id/apikeys routes as apikey resources, not as project
// resources or as the default "unknown" bucket.
//
// Prior to the fix the branch at audit.go:140 matched "/api-keys" (with a
// hyphen) which never matched any real route. /projects/:id/apikeys was
// swallowed by the /projects branch (logged as project.created), and the
// tenant-level POST /apikeys fell into the default resource.created /
// unknown bucket. The apikey.created / apikey.deleted actions declared in
// model/audit.go and registered in service/audit.go were dead code.
func TestDetermineActionAndResource_APIKey(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		path         string // Echo route pattern as returned by c.Path()
		wantAction   string
		wantResource string
	}{
		// Tenant-level /apikeys routes (api/v1 group).
		{
			name:         "tenant POST /apikeys",
			method:       "POST",
			path:         "/api/v1/apikeys",
			wantAction:   model.ActionAPIKeyCreated,
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "tenant GET /apikeys",
			method:       "GET",
			path:         "/api/v1/apikeys",
			wantAction:   "apikey.viewed",
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "tenant DELETE /apikeys/:key_id",
			method:       "DELETE",
			path:         "/api/v1/apikeys/:key_id",
			wantAction:   model.ActionAPIKeyDeleted,
			wantResource: model.ResourceAPIKey,
		},

		// Project-level /projects/:id/apikeys routes — the regression we
		// are guarding against. Without the fix these fell through to the
		// /projects branch and were logged as project.created / project.
		{
			name:         "project POST /projects/:id/apikeys",
			method:       "POST",
			path:         "/api/v1/projects/:id/apikeys",
			wantAction:   model.ActionAPIKeyCreated,
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "project GET /projects/:id/apikeys",
			method:       "GET",
			path:         "/api/v1/projects/:id/apikeys",
			wantAction:   "apikey.viewed",
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "project DELETE /projects/:id/apikeys/:key_id",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/apikeys/:key_id",
			wantAction:   model.ActionAPIKeyDeleted,
			wantResource: model.ResourceAPIKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, resourceType := determineActionAndResource(tc.method, tc.path)
			if action != tc.wantAction {
				t.Errorf("action = %q, want %q (method=%s path=%s)",
					action, tc.wantAction, tc.method, tc.path)
			}
			if resourceType != tc.wantResource {
				t.Errorf("resourceType = %q, want %q (method=%s path=%s)",
					resourceType, tc.wantResource, tc.method, tc.path)
			}
		})
	}
}

// TestDetermineActionAndResource_ProjectNotShadowedByAPIKey is the inverse
// guard: classifying /apikeys before /projects must not regress regular
// project routes such as /projects/:id or /projects/:id/sbom.
func TestDetermineActionAndResource_ProjectNotShadowedByAPIKey(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		path         string
		wantAction   string
		wantResource string
	}{
		{
			name:         "POST /projects (project.created)",
			method:       "POST",
			path:         "/api/v1/projects",
			wantAction:   model.ActionProjectCreated,
			wantResource: model.ResourceProject,
		},
		{
			name:         "DELETE /projects/:id (project.deleted)",
			method:       "DELETE",
			path:         "/api/v1/projects/:id",
			wantAction:   model.ActionProjectDeleted,
			wantResource: model.ResourceProject,
		},
		{
			name:         "POST /projects/:id/sbom (sbom.uploaded)",
			method:       "POST",
			path:         "/api/v1/projects/:id/sbom",
			wantAction:   model.ActionSBOMUploaded,
			wantResource: model.ResourceSBOM,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, resourceType := determineActionAndResource(tc.method, tc.path)
			if action != tc.wantAction {
				t.Errorf("action = %q, want %q", action, tc.wantAction)
			}
			if resourceType != tc.wantResource {
				t.Errorf("resourceType = %q, want %q", resourceType, tc.wantResource)
			}
		})
	}
}

// TestExtractResourceID_APIKey_TenantRoute pins F186 for the tenant-scoped
// apikey route. DELETE /apikeys/:key_id used to drop resource_id to NULL
// because "key_id" was not in the priority list and there was no path-tail
// fallback. Combined with F176 (which fixed action classification), the
// audit row for an apikey delete had the right action but an unjoinable
// resource_id, breaking forensic queries that join audit_logs onto
// api_keys.id.
func TestExtractResourceID_APIKey_TenantRoute(t *testing.T) {
	keyUUID := uuid.New()
	c := newCtxWithParams(t, []string{"key_id"}, []string{keyUUID.String()})
	assertResourceID(t, extractResourceID(c), keyUUID)
}

// TestExtractResourceID_APIKey_ProjectRoute is the core F186 pin. The
// project-scoped key route binds both :id (project UUID) and :key_id
// (apikey UUID). Before the fix the iteration matched "id" first and the
// audit row recorded the project UUID, joining the apikey delete row onto
// the wrong subject row in dashboards and incident response queries.
func TestExtractResourceID_APIKey_ProjectRoute(t *testing.T) {
	projectUUID := uuid.New()
	keyUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "key_id"},
		[]string{projectUUID.String(), keyUUID.String()},
	)
	got := extractResourceID(c)
	assertResourceID(t, got, keyUUID)
	if got != nil && *got == projectUUID {
		t.Fatalf("extractResourceID returned project UUID %s; F186 regression "+
			"(key_id must beat id)", projectUUID)
	}
}

// TestExtractResourceID_VEX guards :vex_id on
// /projects/:id/vex/:vex_id (GET/PUT/DELETE).
func TestExtractResourceID_VEX(t *testing.T) {
	projectUUID := uuid.New()
	vexUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "vex_id"},
		[]string{projectUUID.String(), vexUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), vexUUID)
}

// TestExtractResourceID_CRADraft guards :draft_id on
// /projects/:id/vex-drafts/:draft_id (GET/decision/reanalyse).
func TestExtractResourceID_CRADraft(t *testing.T) {
	projectUUID := uuid.New()
	draftUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "draft_id"},
		[]string{projectUUID.String(), draftUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), draftUUID)
}

// TestExtractResourceID_CRAReport guards :report_id on
// /projects/:id/cra-reports/:report_id (GET/decision/reanalyse).
func TestExtractResourceID_CRAReport(t *testing.T) {
	projectUUID := uuid.New()
	reportUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "report_id"},
		[]string{projectUUID.String(), reportUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), reportUUID)
}

// TestExtractResourceID_METICriterion guards :criterion_id on
// /projects/:id/meti/assessment/:criterion_id/override.
func TestExtractResourceID_METICriterion(t *testing.T) {
	projectUUID := uuid.New()
	criterionUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "criterion_id"},
		[]string{projectUUID.String(), criterionUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), criterionUUID)
}

// TestExtractResourceID_LicensePolicy guards :policy_id on
// /projects/:id/licenses/:policy_id (GET/PUT/DELETE).
func TestExtractResourceID_LicensePolicy(t *testing.T) {
	projectUUID := uuid.New()
	policyUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "policy_id"},
		[]string{projectUUID.String(), policyUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), policyUUID)
}

// TestExtractResourceID_METIAssessment guards :assessment_id on
// /projects/:id/ssvc/assessments/:assessment_id (DELETE/history).
func TestExtractResourceID_METIAssessment(t *testing.T) {
	projectUUID := uuid.New()
	assessmentUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "assessment_id"},
		[]string{projectUUID.String(), assessmentUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), assessmentUUID)
}

// TestExtractResourceID_Vuln guards :vuln_id on both
// /projects/:id/vulnerabilities/:vuln_id/ssvc (nested project route) and
// /vulnerabilities/:vuln_id/ticket (tenant route). We verify both bindings
// here because the priority list must beat ":id" on the nested case.
func TestExtractResourceID_Vuln(t *testing.T) {
	t.Run("project nested", func(t *testing.T) {
		projectUUID := uuid.New()
		vulnUUID := uuid.New()
		c := newCtxWithParams(t,
			[]string{"id", "vuln_id"},
			[]string{projectUUID.String(), vulnUUID.String()},
		)
		assertResourceID(t, extractResourceID(c), vulnUUID)
	})
	t.Run("tenant scoped", func(t *testing.T) {
		vulnUUID := uuid.New()
		c := newCtxWithParams(t, []string{"vuln_id"}, []string{vulnUUID.String()})
		assertResourceID(t, extractResourceID(c), vulnUUID)
	})
}

// TestExtractResourceID_ProjectStillProjectUUID is the inverse guard: on a
// plain /projects/:id route (no child param bound) the priority list still
// has to return the project UUID. This prevents an overzealous "child
// always wins" reading of the fix from regressing project.deleted audit
// rows back to NULL.
func TestExtractResourceID_ProjectStillProjectUUID(t *testing.T) {
	projectUUID := uuid.New()
	c := newCtxWithParams(t, []string{"id"}, []string{projectUUID.String()})
	assertResourceID(t, extractResourceID(c), projectUUID)
}

// TestExtractResourceID_NoParams checks that routes without UUID path
// params (e.g. GET /projects, POST /apikeys, GET /dashboard) leave
// resource_id nil rather than e.g. erroring or returning a zero UUID.
func TestExtractResourceID_NoParams(t *testing.T) {
	c := newCtxWithParams(t, []string{}, []string{})
	if got := extractResourceID(c); got != nil {
		t.Errorf("extractResourceID = %v, want nil for no path params", got)
	}
}

// TestExtractResourceID_FallbackTailParam exercises the ParamNames()
// fallback. When a future route adds a novel `:<thing>_id` that is not in
// resourceIDParamPriority, the path-tail fallback must still capture it
// as a UUID so the audit row is joinable. Without the fallback we would
// silently regress to NULL until someone notices and edits the priority
// list.
//
// F199 follow-up: the ParamNames reverse-walk relies on Echo binding the
// path params in the SAME ORDER they appear in the route pattern, which
// is the contract the v4 router currently honours (Echo's Router.add()
// builds param names by appending while walking the trie, see
// echo/router.go::insert). A future Echo upgrade that broke that
// invariant — or a custom router with a different convention — would
// silently weaken the "child wins over parent" guarantee for ANY route
// that did not get an explicit entry in resourceIDParamPriority. If
// you upgrade Echo, run this test against the new binary BEFORE
// shipping; the test passes today only because the v4 binding order
// happens to match path order.
func TestExtractResourceID_FallbackTailParam(t *testing.T) {
	novelUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"future_widget_id"},
		[]string{novelUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), novelUUID)
}

// TestExtractResourceID_NonUUIDParamSkipped ensures non-UUID path values
// (e.g. :checkId, which carries a slug-style checklist response key) do
// not pollute resource_id. The function must return nil rather than
// silently storing a malformed UUID or an empty-but-non-nil pointer.
func TestExtractResourceID_NonUUIDParamSkipped(t *testing.T) {
	c := newCtxWithParams(t,
		[]string{"checkId"},
		[]string{"not-a-uuid-slug"},
	)
	if got := extractResourceID(c); got != nil {
		t.Errorf("extractResourceID = %v, want nil for non-UUID slug param", got)
	}
}

// TestExtractResourceID_SBOMID_F197 pins the :sbom_id slot of the
// priority list. The mid-tier slot exists because routes like
// /api/v1/projects/:id/sboms/:sbom_id/scan-status bind both :id
// (project UUID) and :sbom_id (SBOM UUID); the audit row should join
// onto sboms.id, not projects.id, since the request operates on the
// SBOM. F186 added :sbom_id to the list but no test asserted the
// nested-route ordering, so a future reorder that put :id before
// :sbom_id would silently regress.
func TestExtractResourceID_SBOMID_F197(t *testing.T) {
	projectUUID := uuid.New()
	sbomUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"id", "sbom_id"},
		[]string{projectUUID.String(), sbomUUID.String()},
	)
	got := extractResourceID(c)
	assertResourceID(t, got, sbomUUID)
	if got != nil && *got == projectUUID {
		t.Fatalf("extractResourceID returned project UUID %s; F197 regression "+
			"(sbom_id must beat id on /projects/:id/sboms/:sbom_id/* routes)",
			projectUUID)
	}
}

// TestExtractResourceID_ProjectID_F197 pins the :project_id slot of the
// priority list. The slot exists for tenant-scoped routes that take a
// project UUID under the name :project_id rather than :id — currently
// hypothetical at the route layer but pinned defensively so a future
// route that adds :project_id (e.g. a cross-resource lookup like
// /api/v1/triage/:project_id/...) lands on the right column and is not
// shadowed by an unrelated :id later in the path.
func TestExtractResourceID_ProjectID_F197(t *testing.T) {
	projectUUID := uuid.New()
	c := newCtxWithParams(t,
		[]string{"project_id"},
		[]string{projectUUID.String()},
	)
	assertResourceID(t, extractResourceID(c), projectUUID)
}

// TestExtractResourceID_CVEParam_NilResourceID_F196 pins NULL-by-design
// behaviour for :cve_id path params. CVE identifiers ("CVE-2021-44228")
// are not UUIDs by spec — the MITRE CVE record format is
// "CVE-YYYY-NNNNNN+" with a 4-digit year and 4+ digit sequence — so
// uuid.Parse rejects them in both the priority list walk and the
// tail-walk fallback. Routes whose only path param is :cve_id therefore
// record resource_id = NULL.
//
// The only currently-known route binding :cve_id is
//
//	/projects/:id/ssvc/cve/:cve_id
//
// where the parent :id rescues the audit row by recording the project
// UUID instead. Standalone CVE-keyed routes (e.g. /kev/:cve_id,
// /vulnerabilities/:cve_id/details) would record resource_id = NULL.
//
// Future-fix path (M14 candidate): record the CVE id as a string field
// inside the audit details map (`details->>'cve_id'`) so forensic
// queries can join on it without needing the audit middleware to grow
// a "non-UUID resource id" slot. That requires extending CreateAuditLogInput
// to carry an optional `Details["cve_id"]` write path; out of scope for
// M13 Phase D.
func TestExtractResourceID_CVEParam_NilResourceID_F196(t *testing.T) {
	// Standalone CVE-keyed route: only :cve_id is bound. Must return
	// nil because "CVE-2021-44228" is not a UUID.
	t.Run("standalone cve route", func(t *testing.T) {
		c := newCtxWithParams(t,
			[]string{"cve_id"},
			[]string{"CVE-2021-44228"},
		)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for CVE-keyed route "+
				"(CVE IDs are not UUIDs by spec)", got)
		}
	})

	// /kev/CVE-2021-44228 — KEV-keyed route, no parent UUID to rescue.
	// Resource_id MUST be nil; F196 NULL-by-design pin.
	t.Run("kev catalog route", func(t *testing.T) {
		c := newCtxWithParams(t,
			[]string{"cve_id"},
			[]string{"CVE-2014-6271"},
		)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for /kev/:cve_id", got)
		}
	})

	// /projects/:id/ssvc/cve/:cve_id — :id rescues the row. Asserts
	// the rescue path still works so the doc note in audit.go remains
	// accurate: nested CVE routes record the project UUID, standalone
	// CVE routes record NULL.
	t.Run("nested route rescued by project id", func(t *testing.T) {
		projectUUID := uuid.New()
		c := newCtxWithParams(t,
			[]string{"id", "cve_id"},
			[]string{projectUUID.String(), "CVE-2021-44228"},
		)
		assertResourceID(t, extractResourceID(c), projectUUID)
	})
}

// TestExtractResourceID_PostSuccessContextKey_F208 is the F208 / M14-1
// meta-test that pins the explicit-handler-override path
// (ContextKeyAuditResourceID) at the FRONT of extractResourceID's
// strategy chain.
//
// Pre-F208 limitation (F190, M13 Phase D doc-only): create-style POST
// routes whose newly-minted UUID lives in the response body — but
// whose path carries only a PARENT UUID — recorded audit_logs.resource_id
// pointing at the parent rather than the new row. Examples:
//
//	POST /projects/:id/vex          → recorded :id (project), not vex.id
//	POST /projects/:id/cra-reports  → recorded :id (project), not report.id
//	POST /projects/:id/apikeys      → recorded :id (project), not key.id
//	POST /vulnerabilities/:vuln_id/ticket → recorded :vuln_id, not ticket.id
//
// Joining audit_logs.resource_id onto the created table's primary key
// silently dropped (NULL case) or joined onto the wrong subject (parent
// id case) for every <resource>.created row — the CRA/VEX/METI evidence
// layer compliance gap the F190 docstring warned about.
//
// F208 closes the limitation by:
//
//  1. Adding ContextKeyAuditResourceID + SetAuditResourceID helper in
//     middleware/audit.go.
//  2. Adding path 1 to extractResourceID that consults the context key
//     BEFORE the priority list — explicit handler override wins so
//     parent-only paths cannot shadow the new row.
//  3. Inserting SetAuditResourceID(c, newID) calls in every create
//     handler (apikey/cra_reports/issue_tracker/license/project/
//     public_link/report/sbom/ssvc/vex/vex_drafts).
//
// This meta-test pins the middleware contract: every create-route
// resource family is represented in the coverage table below. Adding
// a future create handler that mints a new UUID requires adding a
// matching row here so the F208 contract stays universally closed.
// (anti-pattern 48 anchor — pattern-level coverage instead of per-bug
// fix-and-forget.)
func TestExtractResourceID_PostSuccessContextKey_F208(t *testing.T) {
	// Coverage table: one row per create-route resource family fixed
	// in M14-1. The "paramNames" / "paramValues" columns model what
	// Echo would bind on the route; "setID" is what the handler is
	// expected to publish via SetAuditResourceID right before its
	// success return.
	//
	// The test asserts that extractResourceID returns setID for every
	// row regardless of which (parent) UUIDs the path carries — i.e.
	// the explicit override beats the priority list AND the
	// ParamNames fallback.
	//
	// F217 / F218 / F219 (M14 Phase D round 1 fix, anti-pattern 48
	// universal defense): the coverage table now also pins the
	// (action, resource_type) pair determineActionAndResource emits for
	// the same route pattern. This catches a class of bug where the
	// handler's SetAuditResourceID(c, newID) publishes a child-table
	// UUID but the middleware classifier still routes the path to a
	// DIFFERENT resource_type — producing audit_logs rows whose
	// (resource_type, resource_id) JOIN onto a table the resource_id
	// does not live in (the F217 ticket / F218 triage root cause). The
	// per-row "path" + "method" columns drive determineActionAndResource;
	// the per-row "wantAction" + "wantResource" columns pin the
	// resulting classification so a future asymmetric drift between a
	// SetAuditResourceID call and the corresponding classify branch is
	// caught at CI rather than at forensic-join time.
	type row struct {
		name         string
		method       string
		path         string // Echo route pattern (matches c.Path())
		paramNames   []string
		paramVals    []string
		setID        uuid.UUID
		wantAction   string
		wantResource string
	}

	mkUUID := func() uuid.UUID { return uuid.New() }

	// Generate fresh UUIDs per case so a stray cross-case leak fails
	// loudly rather than masquerading as a pass.
	projectUUID := mkUUID()
	vulnUUID := mkUUID()
	cases := []row{
		// Tenant-level creates (no path UUID at all — pre-F208 this
		// recorded NULL).
		{
			name:         "POST /projects (project.created)",
			method:       "POST",
			path:         "/api/v1/projects",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   model.ActionProjectCreated,
			wantResource: model.ResourceProject,
		},
		{
			name:         "POST /apikeys (apikey.created tenant-level)",
			method:       "POST",
			path:         "/api/v1/apikeys",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   model.ActionAPIKeyCreated,
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "POST /integrations (integration.created)",
			method:       "POST",
			path:         "/api/v1/integrations",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   "integration.created",
			wantResource: "integration",
		},
		{
			name:         "POST /reports/generate (report.generated)",
			method:       "POST",
			path:         "/api/v1/reports/generate",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   "report.generated",
			wantResource: "report",
		},

		// Project-nested creates (pre-F208 recorded :id = project UUID
		// instead of new row UUID — joins to the new table dropped).
		{
			name:         "POST /projects/:id/vex (vex.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/vex",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionVEXCreated,
			wantResource: model.ResourceVEX,
		},
		{
			name:         "POST /projects/:id/apikeys (apikey.created project-level)",
			method:       "POST",
			path:         "/api/v1/projects/:id/apikeys",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionAPIKeyCreated,
			wantResource: model.ResourceAPIKey,
		},
		{
			name:         "POST /projects/:id/licenses (license_policy.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/licenses",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionLicensePolicyCreated,
			wantResource: model.ResourceLicensePolicy,
		},
		{
			name:         "POST /projects/:id/public-links (public_link.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/public-links",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionPublicLinkCreated,
			wantResource: model.ResourcePublicLink,
		},
		{
			name:         "POST /projects/:id/sbom (sbom.uploaded)",
			method:       "POST",
			path:         "/api/v1/projects/:id/sbom",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionSBOMUploaded,
			wantResource: model.ResourceSBOM,
		},
		{
			// F218 (M14 Phase D round 1 fix): triage/run now classifies
			// as vex_draft.created so the audit row joins on
			// vex_drafts.id (the handler's published draft UUID).
			name:         "POST /projects/:id/triage/run (vex_draft.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/triage/run",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionVEXDraftCreated,
			wantResource: model.ResourceVEXDraft,
		},
		{
			name:         "POST /projects/:id/cra-reports/run (cra_report.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/cra-reports/run",
			paramNames:   []string{"id"},
			paramVals:    []string{projectUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionCRAReportRun,
			wantResource: model.ResourceCRAReport,
		},

		// Routes with TWO bound UUIDs in the priority list (pre-F208
		// recorded :vuln_id or :draft_id, both wrong subjects).
		{
			name:         "POST /projects/:id/vulnerabilities/:vuln_id/ssvc (ssvc_assessment.created)",
			method:       "POST",
			path:         "/api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc",
			paramNames:   []string{"id", "vuln_id"},
			paramVals:    []string{projectUUID.String(), vulnUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionSSVCAssessed,
			wantResource: model.ResourceSSVC,
		},
		{
			name:         "POST /projects/:id/vulnerabilities/:vuln_id/ssvc/auto (ssvc_assessment.auto)",
			method:       "POST",
			path:         "/api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc/auto",
			paramNames:   []string{"id", "vuln_id"},
			paramVals:    []string{projectUUID.String(), vulnUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionSSVCAssessed,
			wantResource: model.ResourceSSVC,
		},
		{
			// F217 / F219 (M14 Phase D round 1 fix): pre-F217 the case
			// label was "(integration_ticket.created)" (aspirational —
			// the middleware actually classified this as
			// vulnerability.created so the audit row carried
			// resource_type="vulnerability" but resource_id=<ticket
			// UUID>, joining onto neither table). Post-F217 the
			// middleware emits ticket.created / ticket so the
			// SetAuditResourceID(c, ticket.ID) override in
			// IssueTrackerHandler.CreateTicket lands on a JOINable
			// (resource_type, resource_id) pair.
			name:         "POST /vulnerabilities/:vuln_id/ticket (ticket.created)",
			method:       "POST",
			path:         "/api/v1/vulnerabilities/:vuln_id/ticket",
			paramNames:   []string{"vuln_id"},
			paramVals:    []string{vulnUUID.String()},
			setID:        mkUUID(),
			wantAction:   model.ActionTicketCreated,
			wantResource: model.ResourceTicket,
		},

		// Reanalyse routes mint a FRESH row whose audit_logs.resource_id
		// must point at the new row, NOT the source :draft_id /
		// :report_id from the URL (history-preservation contract).
		{
			name:         "POST /projects/:id/vex-drafts/:draft_id/reanalyse (vex_draft.reanalysed → NEW draft)",
			method:       "POST",
			path:         "/api/v1/projects/:id/vex-drafts/:draft_id/reanalyse",
			paramNames:   []string{"id", "draft_id"},
			paramVals:    []string{projectUUID.String(), mkUUID().String()},
			setID:        mkUUID(),
			wantAction:   model.ActionVEXDraftReanalysed,
			wantResource: model.ResourceVEXDraft,
		},
		{
			name:         "POST /projects/:id/cra-reports/:report_id/reanalyse (cra_report.reanalysed → NEW report)",
			method:       "POST",
			path:         "/api/v1/projects/:id/cra-reports/:report_id/reanalyse",
			paramNames:   []string{"id", "report_id"},
			paramVals:    []string{projectUUID.String(), mkUUID().String()},
			setID:        mkUUID(),
			wantAction:   model.ActionCRAReportReanalysed,
			wantResource: model.ResourceCRAReport,
		},

		// F233 (M15-1 fix): CLI-family create routes. Pre-F233 these
		// classified as cli.upload / cli.action with resource_type="cli"
		// and resource_id=NULL — the audit_logs row for a CLI-driven
		// upload / project-create had no joinable target on sboms.id /
		// projects.id, breaking forensic parity with the tenant-side
		// /api/v1/... routes.
		//
		// Post-F233 the middleware branch classifies /cli/upload as
		// sbom.uploaded / sbom and /cli/projects as project.created /
		// project; the handler publishes the newly-minted UUID via
		// SetAuditResourceID so the F208 override-first path lands the
		// created row's UUID in resource_id even though the CLI paths
		// carry no UUID in the URL.
		{
			name:         "POST /cli/upload (sbom.uploaded via CLI)",
			method:       "POST",
			path:         "/api/v1/cli/upload",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   model.ActionSBOMUploaded,
			wantResource: model.ResourceSBOM,
		},
		{
			name:         "POST /cli/projects (project.created via CLI)",
			method:       "POST",
			path:         "/api/v1/cli/projects",
			paramNames:   nil,
			paramVals:    nil,
			setID:        mkUUID(),
			wantAction:   model.ActionProjectCreated,
			wantResource: model.ResourceProject,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCtxWithParams(t, tc.paramNames, tc.paramVals)
			SetAuditResourceID(c, tc.setID)
			got := extractResourceID(c)
			assertResourceID(t, got, tc.setID)

			// F217 / F218 / F219 (anti-pattern 48 universal defense):
			// pin the middleware's classify output for the same route
			// so a future SetAuditResourceID call and the matching
			// classify branch cannot drift apart silently. If this
			// fails with "want=ticket actualResource=vulnerability"
			// the symmetric handler/middleware mismatch is back
			// (F217 root cause) and the audit row's (resource_type,
			// resource_id) pair is no longer JOINable.
			action, resourceType := determineActionAndResource(tc.method, tc.path)
			if action != tc.wantAction {
				t.Errorf("classify action = %q, want %q (method=%s path=%s) — "+
					"anti-pattern 48 symmetric drift between SetAuditResourceID "+
					"and determineActionAndResource",
					action, tc.wantAction, tc.method, tc.path)
			}
			if resourceType != tc.wantResource {
				t.Errorf("classify resource_type = %q, want %q (method=%s path=%s) — "+
					"audit_logs.(resource_type, resource_id) no longer joins on the "+
					"table the handler-published resource_id lives in",
					resourceType, tc.wantResource, tc.method, tc.path)
			}
		})
	}
}

// TestExtractResourceID_PostSuccessContextKey_F208_TypeAssertions pins
// the two accepted type assertions (uuid.UUID and *uuid.UUID) so a
// future handler that publishes via service-returned pointer
// (*model.Project) keeps working without the call site needing a
// dereference at the boundary. This makes the F208 contract caller-
// friendly across the existing handler conventions (some return
// pointers, some return values).
func TestExtractResourceID_PostSuccessContextKey_F208_TypeAssertions(t *testing.T) {
	t.Run("value uuid.UUID", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		want := uuid.New()
		c.Set(ContextKeyAuditResourceID, want)
		assertResourceID(t, extractResourceID(c), want)
	})

	t.Run("pointer *uuid.UUID", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		want := uuid.New()
		c.Set(ContextKeyAuditResourceID, &want)
		assertResourceID(t, extractResourceID(c), want)
	})

	t.Run("nil pointer is treated as no value", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		var nilPtr *uuid.UUID
		c.Set(ContextKeyAuditResourceID, nilPtr)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for typed-nil pointer override", got)
		}
	})

	t.Run("uuid.Nil value is treated as no value", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		c.Set(ContextKeyAuditResourceID, uuid.Nil)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for uuid.Nil override "+
				"(prevents a default-initialised zero from poisoning forensic joins)", got)
		}
	})

	t.Run("uuid.Nil pointer is treated as no value", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		zero := uuid.Nil
		c.Set(ContextKeyAuditResourceID, &zero)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for *uuid.Nil override", got)
		}
	})

	t.Run("unrelated type is ignored (defensive — wrong c.Set call must not panic)", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		c.Set(ContextKeyAuditResourceID, "not-a-uuid-string")
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for non-UUID type at context key", got)
		}
	})
}

// TestExtractResourceID_PostSuccessContextKey_F208_PriorityListStillWorks
// pins the regression coverage for the F186 priority-list / ParamNames-
// fallback paths AFTER the F208 override was added. Without explicit
// pin, a future refactor that accidentally short-circuited the path
// when the context key was unset would silently regress every
// /projects/:id/<child>/:child_id delete route's audit row back to
// the F186-era project-UUID bug.
//
// Each subtest covers one strategy path without a context-key override:
//   - priorityList: routes where a named param in resourceIDParamPriority
//     wins (e.g. /apikeys/:key_id, /projects/:id/vex-drafts/:draft_id).
//   - paramNamesFallback: routes where the param name is not in the
//     priority list and the reverse-walk picks it up (e.g. a future
//     route binding :future_widget_id).
//   - nilForNoParams: confirms the function still returns nil when no
//     path params AND no context-key override are bound.
func TestExtractResourceID_PostSuccessContextKey_F208_PriorityListStillWorks(t *testing.T) {
	t.Run("priorityList: :key_id wins on DELETE /apikeys/:key_id (F186 regression net)", func(t *testing.T) {
		keyUUID := uuid.New()
		c := newCtxWithParams(t, []string{"key_id"}, []string{keyUUID.String()})
		assertResourceID(t, extractResourceID(c), keyUUID)
	})

	t.Run("priorityList: :draft_id wins over parent :id (F186 child-before-parent rule)", func(t *testing.T) {
		projectUUID := uuid.New()
		draftUUID := uuid.New()
		c := newCtxWithParams(t,
			[]string{"id", "draft_id"},
			[]string{projectUUID.String(), draftUUID.String()},
		)
		got := extractResourceID(c)
		assertResourceID(t, got, draftUUID)
		if got != nil && *got == projectUUID {
			t.Fatalf("F186 regression: parent :id shadowed child :draft_id "+
				"(got %s, want %s)", got, draftUUID)
		}
	})

	t.Run("paramNamesFallback: future :widget_id picked up by reverse walk", func(t *testing.T) {
		novelUUID := uuid.New()
		c := newCtxWithParams(t,
			[]string{"future_widget_id"},
			[]string{novelUUID.String()},
		)
		assertResourceID(t, extractResourceID(c), novelUUID)
	})

	t.Run("nilForNoParams: no path params + no override → nil", func(t *testing.T) {
		c := newCtxWithParams(t, nil, nil)
		if got := extractResourceID(c); got != nil {
			t.Errorf("extractResourceID = %v, want nil for empty context", got)
		}
	})
}

// TestDetermineActionAndResource_ProjectChildResources is the F189
// regression net for the F188 fix. F176 hoisted /apikeys above the
// /projects branch; F188 generalised the same pattern to every
// /projects/:id/<child> family — 18+ resource families at the time of
// this fix. Pre-F188 every nested family was logged as project.<verb>,
// breaking the audit_logs.(resource_type, resource_id) join key for
// the entire CRA / VEX / METI evidence layer.
//
// The table below pins one or more representative request shapes for
// each family. Adding a new /projects/:id/<thing> route should add a
// matching row here so the audit middleware regression catches it
// before the F188 swallow returns.
func TestDetermineActionAndResource_ProjectChildResources(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		path         string // Echo route pattern as returned by c.Path()
		wantAction   string
		wantResource string
	}{
		// ---- /vex (manual VEX statements) ---------------------------------
		{
			name:         "GET /projects/:id/vex (list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/vex",
			wantAction:   model.ActionVEXListed,
			wantResource: model.ResourceVEX,
		},
		{
			name:         "POST /projects/:id/vex (create)",
			method:       "POST",
			path:         "/api/v1/projects/:id/vex",
			wantAction:   model.ActionVEXCreated,
			wantResource: model.ResourceVEX,
		},
		{
			name:         "GET /projects/:id/vex/:vex_id (item)",
			method:       "GET",
			path:         "/api/v1/projects/:id/vex/:vex_id",
			wantAction:   "vex.viewed",
			wantResource: model.ResourceVEX,
		},
		{
			name:         "DELETE /projects/:id/vex/:vex_id",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/vex/:vex_id",
			wantAction:   model.ActionVEXDeleted,
			wantResource: model.ResourceVEX,
		},
		{
			name:         "GET /projects/:id/vex/export",
			method:       "GET",
			path:         "/api/v1/projects/:id/vex/export",
			wantAction:   "vex.viewed",
			wantResource: model.ResourceVEX,
		},

		// ---- /vex-drafts (AI VEX triage outputs) --------------------------
		// Segment-distinct from /vex so the /vex branch must NOT shadow
		// /vex-drafts even though both contain the substring "vex".
		{
			name:         "GET /projects/:id/vex-drafts (list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/vex-drafts",
			wantAction:   model.ActionVEXDraftListed,
			wantResource: model.ResourceVEXDraft,
		},
		{
			name:         "GET /projects/:id/vex-drafts/:draft_id (item)",
			method:       "GET",
			path:         "/api/v1/projects/:id/vex-drafts/:draft_id",
			wantAction:   model.ActionVEXDraftViewed,
			wantResource: model.ResourceVEXDraft,
		},
		{
			name:         "PUT /projects/:id/vex-drafts/:draft_id/decision",
			method:       "PUT",
			path:         "/api/v1/projects/:id/vex-drafts/:draft_id/decision",
			wantAction:   model.ActionVEXDraftDecisionUpdated,
			wantResource: model.ResourceVEXDraft,
		},
		{
			name:         "POST /projects/:id/vex-drafts/:draft_id/reanalyse",
			method:       "POST",
			path:         "/api/v1/projects/:id/vex-drafts/:draft_id/reanalyse",
			wantAction:   model.ActionVEXDraftReanalysed,
			wantResource: model.ResourceVEXDraft,
		},

		// ---- /triage (AI triage runner) -----------------------------------
		// F218 (M14 Phase D round 1 fix): triage/run now classifies as
		// vex_draft.created (the RunTriage handler mints a vex_draft
		// row and publishes its UUID via SetAuditResourceID). Pre-F218
		// the audit row carried (resource_type="triage",
		// resource_id=<vex_draft UUID>) which joined onto neither table
		// (no `triage` table exists).
		{
			name:         "POST /projects/:id/triage/run",
			method:       "POST",
			path:         "/api/v1/projects/:id/triage/run",
			wantAction:   model.ActionVEXDraftCreated,
			wantResource: model.ResourceVEXDraft,
		},

		// ---- /cra-reports (CRA report drafting, Wave M2-4) ----------------
		{
			name:         "POST /projects/:id/cra-reports/run",
			method:       "POST",
			path:         "/api/v1/projects/:id/cra-reports/run",
			wantAction:   model.ActionCRAReportRun,
			wantResource: model.ResourceCRAReport,
		},
		{
			name:         "GET /projects/:id/cra-reports (list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/cra-reports",
			wantAction:   model.ActionCRAReportListed,
			wantResource: model.ResourceCRAReport,
		},
		{
			name:         "GET /projects/:id/cra-reports/:report_id (item)",
			method:       "GET",
			path:         "/api/v1/projects/:id/cra-reports/:report_id",
			wantAction:   model.ActionCRAReportViewed,
			wantResource: model.ResourceCRAReport,
		},
		{
			name:         "PUT /projects/:id/cra-reports/:report_id/decision",
			method:       "PUT",
			path:         "/api/v1/projects/:id/cra-reports/:report_id/decision",
			wantAction:   model.ActionCRAReportDecisionUpdated,
			wantResource: model.ResourceCRAReport,
		},
		{
			name:         "POST /projects/:id/cra-reports/:report_id/reanalyse",
			method:       "POST",
			path:         "/api/v1/projects/:id/cra-reports/:report_id/reanalyse",
			wantAction:   model.ActionCRAReportReanalysed,
			wantResource: model.ResourceCRAReport,
		},

		// ---- /scan (vulnerability scan trigger) ---------------------------
		{
			name:         "POST /projects/:id/scan",
			method:       "POST",
			path:         "/api/v1/projects/:id/scan",
			wantAction:   model.ActionScanStarted,
			wantResource: model.ResourceScan,
		},

		// ---- /compliance --------------------------------------------------
		{
			name:         "GET /projects/:id/compliance",
			method:       "GET",
			path:         "/api/v1/projects/:id/compliance",
			wantAction:   model.ActionComplianceChecked,
			wantResource: model.ResourceCompliance,
		},
		{
			name:         "GET /projects/:id/compliance/report",
			method:       "GET",
			path:         "/api/v1/projects/:id/compliance/report",
			wantAction:   model.ActionComplianceChecked,
			wantResource: model.ResourceCompliance,
		},

		// ---- /notifications -----------------------------------------------
		{
			name:         "GET /projects/:id/notifications (list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/notifications",
			wantAction:   model.ActionNotificationListed,
			wantResource: model.ResourceNotification,
		},
		{
			name:         "PUT /projects/:id/notifications",
			method:       "PUT",
			path:         "/api/v1/projects/:id/notifications",
			wantAction:   model.ActionNotificationUpdated,
			wantResource: model.ResourceNotification,
		},
		{
			name:         "POST /projects/:id/notifications/test",
			method:       "POST",
			path:         "/api/v1/projects/:id/notifications/test",
			wantAction:   model.ActionNotificationCreated,
			wantResource: model.ResourceNotification,
		},

		// ---- /diff (M10-6 / M11-4 / M12-3) --------------------------------
		{
			name:         "GET /projects/:id/diff",
			method:       "GET",
			path:         "/api/v1/projects/:id/diff",
			wantAction:   model.ActionDiffViewed,
			wantResource: model.ResourceDiff,
		},
		{
			name:         "POST /projects/:id/diff/summary",
			method:       "POST",
			path:         "/api/v1/projects/:id/diff/summary",
			wantAction:   model.ActionDiffSummary,
			wantResource: model.ResourceDiff,
		},
		{
			name:         "GET /projects/:id/diff.csv",
			method:       "GET",
			path:         "/api/v1/projects/:id/diff.csv",
			wantAction:   model.ActionDiffViewed,
			wantResource: model.ResourceDiff,
		},
		{
			name:         "GET /projects/:id/diff.pdf",
			method:       "GET",
			path:         "/api/v1/projects/:id/diff.pdf",
			wantAction:   model.ActionDiffViewed,
			wantResource: model.ResourceDiff,
		},
		{
			name:         "GET /projects/:id/diff/graph (M12-3 graph view)",
			method:       "GET",
			path:         "/api/v1/projects/:id/diff/graph",
			wantAction:   model.ActionDiffGraphViewed,
			wantResource: model.ResourceDiff,
		},

		// ---- /ssvc --------------------------------------------------------
		// SSVC must beat /vulnerabilities on the nested
		// /projects/:id/vulnerabilities/:vuln_id/ssvc route — assert
		// the order in this same suite to catch a reorder.
		{
			name:         "GET /projects/:id/ssvc/defaults",
			method:       "GET",
			path:         "/api/v1/projects/:id/ssvc/defaults",
			wantAction:   model.ActionSSVCViewed,
			wantResource: model.ResourceSSVC,
		},
		{
			name:         "PUT /projects/:id/ssvc/defaults",
			method:       "PUT",
			path:         "/api/v1/projects/:id/ssvc/defaults",
			wantAction:   model.ActionSSVCAssessed,
			wantResource: model.ResourceSSVC,
		},
		{
			name:         "POST /projects/:id/vulnerabilities/:vuln_id/ssvc",
			method:       "POST",
			path:         "/api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc",
			wantAction:   model.ActionSSVCAssessed,
			wantResource: model.ResourceSSVC,
		},
		{
			name:         "POST /projects/:id/vulnerabilities/:vuln_id/ssvc/auto",
			method:       "POST",
			path:         "/api/v1/projects/:id/vulnerabilities/:vuln_id/ssvc/auto",
			wantAction:   model.ActionSSVCAssessed,
			wantResource: model.ResourceSSVC,
		},
		{
			name:         "DELETE /projects/:id/ssvc/assessments/:assessment_id",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/ssvc/assessments/:assessment_id",
			wantAction:   model.ActionSSVCDeleted,
			wantResource: model.ResourceSSVC,
		},

		// ---- /meti (Wave M3-4) --------------------------------------------
		{
			name:         "GET /projects/:id/meti/assessment",
			method:       "GET",
			path:         "/api/v1/projects/:id/meti/assessment",
			wantAction:   model.ActionMETIViewed,
			wantResource: model.ResourceMETI,
		},
		{
			name:         "POST /projects/:id/meti/assessment/refresh",
			method:       "POST",
			path:         "/api/v1/projects/:id/meti/assessment/refresh",
			wantAction:   model.ActionMETIRefreshed,
			wantResource: model.ResourceMETI,
		},
		{
			name:         "PUT /projects/:id/meti/assessment/:criterion_id/override",
			method:       "PUT",
			path:         "/api/v1/projects/:id/meti/assessment/:criterion_id/override",
			wantAction:   model.ActionMETIOverridden,
			wantResource: model.ResourceMETI,
		},
		{
			name:         "DELETE /projects/:id/meti/assessment/:criterion_id/override",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/meti/assessment/:criterion_id/override",
			wantAction:   model.ActionMETIOverridden,
			wantResource: model.ResourceMETI,
		},

		// ---- /licenses (license policies) ---------------------------------
		{
			name:         "GET /projects/:id/licenses",
			method:       "GET",
			path:         "/api/v1/projects/:id/licenses",
			wantAction:   model.ActionLicensePolicyListed,
			wantResource: model.ResourceLicensePolicy,
		},
		{
			name:         "POST /projects/:id/licenses",
			method:       "POST",
			path:         "/api/v1/projects/:id/licenses",
			wantAction:   model.ActionLicensePolicyCreated,
			wantResource: model.ResourceLicensePolicy,
		},
		{
			name:         "PUT /projects/:id/licenses/:policy_id",
			method:       "PUT",
			path:         "/api/v1/projects/:id/licenses/:policy_id",
			wantAction:   model.ActionLicensePolicyUpdated,
			wantResource: model.ResourceLicensePolicy,
		},
		{
			name:         "DELETE /projects/:id/licenses/:policy_id",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/licenses/:policy_id",
			wantAction:   model.ActionLicensePolicyDeleted,
			wantResource: model.ResourceLicensePolicy,
		},

		// ---- /evidence-pack -----------------------------------------------
		{
			name:         "POST /projects/:id/evidence-pack/build",
			method:       "POST",
			path:         "/api/v1/projects/:id/evidence-pack/build",
			wantAction:   model.ActionEvidencePackBuilt,
			wantResource: model.ResourceEvidencePack,
		},

		// ---- /checklist (METI checklist) ----------------------------------
		{
			name:         "GET /projects/:id/checklist",
			method:       "GET",
			path:         "/api/v1/projects/:id/checklist",
			wantAction:   model.ActionChecklistViewed,
			wantResource: model.ResourceChecklist,
		},
		{
			name:         "PUT /projects/:id/checklist/:checkId",
			method:       "PUT",
			path:         "/api/v1/projects/:id/checklist/:checkId",
			wantAction:   model.ActionChecklistUpdated,
			wantResource: model.ResourceChecklist,
		},
		{
			name:         "DELETE /projects/:id/checklist/:checkId",
			method:       "DELETE",
			path:         "/api/v1/projects/:id/checklist/:checkId",
			wantAction:   model.ActionChecklistDeleted,
			wantResource: model.ResourceChecklist,
		},

		// ---- /visualization -----------------------------------------------
		{
			name:         "GET /projects/:id/visualization",
			method:       "GET",
			path:         "/api/v1/projects/:id/visualization",
			wantAction:   model.ActionVisualizationViewed,
			wantResource: model.ResourceVisualization,
		},
		{
			name:         "PUT /projects/:id/visualization",
			method:       "PUT",
			path:         "/api/v1/projects/:id/visualization",
			wantAction:   model.ActionVisualizationUpdated,
			wantResource: model.ResourceVisualization,
		},

		// ---- /public-links ------------------------------------------------
		{
			name:         "POST /projects/:id/public-links",
			method:       "POST",
			path:         "/api/v1/projects/:id/public-links",
			wantAction:   model.ActionPublicLinkCreated,
			wantResource: model.ResourcePublicLink,
		},
		{
			name:         "GET /projects/:id/public-links",
			method:       "GET",
			path:         "/api/v1/projects/:id/public-links",
			wantAction:   model.ActionPublicLinkViewed,
			wantResource: model.ResourcePublicLink,
		},

		// ---- /kev (project-scoped) ----------------------------------------
		{
			name:         "GET /projects/:id/kev",
			method:       "GET",
			path:         "/api/v1/projects/:id/kev",
			wantAction:   model.ActionKEVViewed,
			wantResource: model.ResourceKEV,
		},

		// ---- /eol-* (project-scoped) --------------------------------------
		{
			name:         "GET /projects/:id/eol-summary",
			method:       "GET",
			path:         "/api/v1/projects/:id/eol-summary",
			wantAction:   model.ActionEOLViewed,
			wantResource: model.ResourceEOL,
		},
		{
			name:         "POST /projects/:id/eol-check",
			method:       "POST",
			path:         "/api/v1/projects/:id/eol-check",
			wantAction:   model.ActionEOLChecked,
			wantResource: model.ResourceEOL,
		},

		// ---- /sbom (nested - F188 sub-case) -------------------------------
		// Pre-F188 GET /projects/:id/sbom was classified as project.viewed
		// because the /projects branch only differentiated /sbom on
		// POST/DELETE. Now the hoist captures every method.
		{
			name:         "GET /projects/:id/sbom (nested read-back)",
			method:       "GET",
			path:         "/api/v1/projects/:id/sbom",
			wantAction:   model.ActionSBOMViewed,
			wantResource: model.ResourceSBOM,
		},
		{
			name:         "GET /projects/:id/sboms (list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/sboms",
			wantAction:   model.ActionSBOMViewed,
			wantResource: model.ResourceSBOM,
		},
		{
			name:         "GET /projects/:id/sboms/:sbom_id/scan-status",
			method:       "GET",
			path:         "/api/v1/projects/:id/sboms/:sbom_id/scan-status",
			wantAction:   model.ActionSBOMViewed,
			wantResource: model.ResourceSBOM,
		},
		{
			name:         "GET /projects/:id/components",
			method:       "GET",
			path:         "/api/v1/projects/:id/components",
			wantAction:   "project.viewed",
			wantResource: model.ResourceProject,
		},

		// ---- /vulnerabilities (nested) ------------------------------------
		{
			name:         "GET /projects/:id/vulnerabilities (nested list)",
			method:       "GET",
			path:         "/api/v1/projects/:id/vulnerabilities",
			wantAction:   model.ActionVulnerabilityListed,
			wantResource: model.ResourceVulnerability,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, resourceType := determineActionAndResource(tc.method, tc.path)
			if action != tc.wantAction {
				t.Errorf("action = %q, want %q (method=%s path=%s)",
					action, tc.wantAction, tc.method, tc.path)
			}
			if resourceType != tc.wantResource {
				t.Errorf("resourceType = %q, want %q (method=%s path=%s)",
					resourceType, tc.wantResource, tc.method, tc.path)
			}
		})
	}
}

// TestDetermineActionAndResource_APIKeyPathFalsePositive pins F202. The
// pre-F188 audit middleware used `strings.Contains(path, "/apikeys")`
// which would have false-matched a hypothetical /integrations/apikeys-sync
// route — pulling an integration-management request into the apikey
// audit bucket. The F188 segment-exact pathHasChildResource rules it
// out. The route doesn't exist today, but the test guards against
// reintroducing a substring-only check.
func TestDetermineActionAndResource_APIKeyPathFalsePositive(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		path         string
		wantResource string
		notResource  string // negative assertion — must NOT be this
	}{
		{
			name:         "/integrations/apikeys-sync is integration, not apikey",
			method:       "POST",
			path:         "/api/v1/integrations/apikeys-sync",
			wantResource: "integration",
			notResource:  model.ResourceAPIKey,
		},
		{
			name:         "/integrations/apikeys-sync GET is integration, not apikey",
			method:       "GET",
			path:         "/api/v1/integrations/apikeys-sync",
			wantResource: "integration",
			notResource:  model.ResourceAPIKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, resourceType := determineActionAndResource(tc.method, tc.path)
			if resourceType == tc.notResource {
				t.Fatalf("F202 regression: resource_type = %q for path %q; "+
					"the segment-exact pathHasChildResource must not match "+
					"/apikeys-sync as /apikeys", resourceType, tc.path)
			}
			if resourceType != tc.wantResource {
				t.Errorf("resourceType = %q, want %q (method=%s path=%s)",
					resourceType, tc.wantResource, tc.method, tc.path)
			}
		})
	}
}

// TestDetermineActionAndResource_TenantLevelNotSwallowedByProjectHoist
// pins the HasPrefix("/projects/") guard on the F188 hoist. Tenant-level
// paths that re-use a segment name from the hoist list (e.g.
// /settings/scan, /vulnerabilities/sync-epss) must still hit the
// tenant-level branches below the hoist — NOT the project-nested
// classification. Without the guard, /settings/scan would be
// misclassified as scan.started instead of settings.updated.
func TestDetermineActionAndResource_TenantLevelNotSwallowedByProjectHoist(t *testing.T) {
	cases := []struct {
		name         string
		method       string
		path         string
		wantAction   string
		wantResource string
	}{
		{
			name:         "GET /settings/scan (tenant settings, not project scan)",
			method:       "GET",
			path:         "/api/v1/settings/scan",
			wantAction:   "settings.viewed",
			wantResource: model.ResourceSettings,
		},
		{
			name:         "PUT /settings/scan (tenant settings update)",
			method:       "PUT",
			path:         "/api/v1/settings/scan",
			wantAction:   model.ActionSettingsUpdated,
			wantResource: model.ResourceSettings,
		},
		{
			name:         "GET /settings/scan/logs (tenant settings, not project scan)",
			method:       "GET",
			path:         "/api/v1/settings/scan/logs",
			wantAction:   "settings.viewed",
			wantResource: model.ResourceSettings,
		},
		{
			name:         "GET /vulnerabilities/sync-epss (tenant vuln, not project)",
			method:       "GET",
			path:         "/api/v1/vulnerabilities/sync-epss",
			wantAction:   model.ActionVulnerabilityViewed,
			wantResource: model.ResourceVulnerability,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, resourceType := determineActionAndResource(tc.method, tc.path)
			if action != tc.wantAction {
				t.Errorf("action = %q, want %q (method=%s path=%s)",
					action, tc.wantAction, tc.method, tc.path)
			}
			if resourceType != tc.wantResource {
				t.Errorf("resourceType = %q, want %q (method=%s path=%s)",
					resourceType, tc.wantResource, tc.method, tc.path)
			}
		})
	}
}

// TestDetermineActionAndResource_AllHoistedFamilies_NoProjectFallthrough
// pins F206 (anti-pattern 48 symmetric to F201). F201 added a default arm
// to the apikeys switch so a future PUT/PATCH route on /projects/:id/apikeys
// would not silently fall through to the /projects branch and re-introduce
// F188 mass-misclassification. The same anti-pattern existed on every other
// hoisted family switch — cra-reports / vex-drafts / vex / notifications /
// ssvc / meti / licenses / checklist / visualization / public-links /
// sbom / vulnerabilities all had at least one HTTP verb that was either
// missing today (e.g. checklist had no POST case, sbom had no PUT/PATCH
// case) or would land on OPTIONS / HEAD without a default.
//
// The F189 ProjectChildResources regression net above exercises only
// CURRENTLY-ROUTED (method, path) pairs, so method gaps are invisible to
// it by design. This meta-test enumerates every hoisted family x every
// standard HTTP method including OPTIONS, and asserts:
//
//  1. The resource_type is NEVER ResourceProject. Falling through to the
//     /projects branch is the F188 / F206 regression and is the primary
//     thing we are guarding against.
//
//  2. The resource_type matches the family's expected resource. A wrong
//     family (e.g. apikeys path resolving to ResourceVEX) would also
//     break the audit_logs.(resource_type, resource_id) join key on the
//     row, but in a less catastrophic way than falling through to
//     project.
//
//  3. The (action, resource) pair is non-empty — i.e. the path is not
//     silently skipped. A skipped path would drop the audit row entirely
//     and disappear from forensic queries with no warning.
//
// Adding a NEW /projects/:id/<thing> family to determineActionAndResource
// REQUIRES adding the family to the table below; otherwise the new
// family's OPTIONS / HEAD route can silently fall through and we lose
// the F206 invariant. The F189 ProjectChildResources test is also
// updated alongside (per-method positive assertions), but this meta-test
// is what catches the absence of a default arm — F189 only catches the
// absence of a wired-up method case.
func TestDetermineActionAndResource_AllHoistedFamilies_NoProjectFallthrough(t *testing.T) {
	// Families hoisted ABOVE the /projects branch in
	// determineActionAndResource. Each entry pins the canonical path for
	// the family and the expected resource_type. Paths use the Echo
	// route-pattern shape (`:id`) because that is what c.Path() returns
	// at request time.
	//
	// /apikeys is the only entry whose path is also valid at the tenant
	// level — the others are gated by the HasPrefix("/projects/") guard
	// so a tenant-level path with the same segment name falls through to
	// its own tenant branch (covered by
	// TestDetermineActionAndResource_TenantLevelNotSwallowedByProjectHoist).
	families := []struct {
		name     string
		path     string
		resource string
	}{
		{"apikeys", "/api/v1/projects/:id/apikeys", model.ResourceAPIKey},
		{"cra-reports", "/api/v1/projects/:id/cra-reports", model.ResourceCRAReport},
		{"vex-drafts", "/api/v1/projects/:id/vex-drafts", model.ResourceVEXDraft},
		// F218 (M14 Phase D round 1 fix): triage paths now classify as
		// vex_draft (the triage runner mints vex_draft rows; there is
		// no `triage` table to join onto).
		{"triage", "/api/v1/projects/:id/triage", model.ResourceVEXDraft},
		{"vex", "/api/v1/projects/:id/vex", model.ResourceVEX},
		{"scan", "/api/v1/projects/:id/scan", model.ResourceScan},
		{"compliance", "/api/v1/projects/:id/compliance", model.ResourceCompliance},
		{"notifications", "/api/v1/projects/:id/notifications", model.ResourceNotification},
		{"diff", "/api/v1/projects/:id/diff", model.ResourceDiff},
		{"ssvc", "/api/v1/projects/:id/ssvc", model.ResourceSSVC},
		{"meti", "/api/v1/projects/:id/meti", model.ResourceMETI},
		{"licenses", "/api/v1/projects/:id/licenses", model.ResourceLicensePolicy},
		{"evidence-pack", "/api/v1/projects/:id/evidence-pack", model.ResourceEvidencePack},
		{"checklist", "/api/v1/projects/:id/checklist", model.ResourceChecklist},
		{"visualization", "/api/v1/projects/:id/visualization", model.ResourceVisualization},
		{"public-links", "/api/v1/projects/:id/public-links", model.ResourcePublicLink},
		{"kev", "/api/v1/projects/:id/kev", model.ResourceKEV},
		{"eol-summary", "/api/v1/projects/:id/eol-summary", model.ResourceEOL},
		{"eol-check", "/api/v1/projects/:id/eol-check", model.ResourceEOL},
		{"sbom", "/api/v1/projects/:id/sbom", model.ResourceSBOM},
		{"sboms", "/api/v1/projects/:id/sboms", model.ResourceSBOM},
		{"vulnerabilities", "/api/v1/projects/:id/vulnerabilities", model.ResourceVulnerability},
	}
	// All standard HTTP methods plus OPTIONS, which is the most likely
	// future addition (CORS preflight). HEAD is intentionally omitted
	// because Echo treats HEAD as GET for routing, so the switch never
	// observes HEAD directly — but the default arms still cover it if a
	// future routing change exposes it.
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

	for _, fam := range families {
		for _, method := range methods {
			t.Run(fam.name+"_"+method, func(t *testing.T) {
				action, resource := determineActionAndResource(method, fam.path)

				// Guard 1: the family must NEVER fall through to the
				// /projects branch. This is the F188 / F206 regression
				// we are pinning.
				if resource == model.ResourceProject {
					t.Fatalf("F206 regression: family %s method %s "+
						"fell through to ResourceProject (action=%q, path=%s); "+
						"add a default arm to the family switch in audit.go",
						fam.name, method, action, fam.path)
				}

				// Guard 2: the family must resolve to its own resource
				// type. A wrong family would also break the
				// audit_logs.(resource_type, resource_id) join key.
				if resource != fam.resource {
					t.Errorf("family %s method %s resolved to resource %q, want %q "+
						"(action=%q, path=%s)",
						fam.name, method, resource, fam.resource, action, fam.path)
				}

				// Guard 3: (action, resource) must both be non-empty.
				// A silently-skipped path drops the audit row.
				if action == "" || resource == "" {
					t.Errorf("family %s method %s returned empty (action=%q, "+
						"resource=%q, path=%s); paths in the hoist block must "+
						"always emit an audit row",
						fam.name, method, action, resource, fam.path)
				}
			})
		}
	}
}

// TestCollectNonUUIDPathParams_F214 pins the M14-4 helper that feeds
// the audit details map. The helper must:
//
//  1. Return nil when no path params are bound (no allocation overhead
//     for routes that take no params at all — the common audit hot path).
//  2. Skip empty values (Echo binds unset path params to "" — we must
//     not write "cve_id": "" into details).
//  3. Skip UUID-parseable values (UUIDs already flow through
//     resource_id via extractResourceID; duplicating them in details is
//     redundant + would imply that resource_id was somehow not picked
//     up, which is a misleading signal during incident response).
//  4. Skip sensitive-name params (see sensitiveAuditParamNames doc —
//     defensive against a future route accidentally binding e.g.
//     :api_key in the path). The match is case-insensitive so neither
//     :api_key nor :APIKey nor :ApiKey can sneak through.
//  5. Preserve the raw param name as the map key (so the audit row
//     matches the route declaration and a reader can grep main.go for
//     the originating endpoint).
//  6. Capture multiple non-UUID params on the same route (e.g. a
//     hypothetical future /widgets/:slug/parts/:part_id).
func TestCollectNonUUIDPathParams_F214(t *testing.T) {
	projectUUID := uuid.New()
	cases := []struct {
		name   string
		params [][2]string // name, value
		want   map[string]string
	}{
		{
			name:   "no params bound",
			params: nil,
			want:   nil,
		},
		{
			name: "single CVE path param (the F196 motivating case)",
			params: [][2]string{
				{"cve_id", "CVE-2021-44228"},
			},
			want: map[string]string{"cve_id": "CVE-2021-44228"},
		},
		{
			name: "nested CVE under project: project :id is UUID → not duplicated, only cve_id captured",
			params: [][2]string{
				{"id", projectUUID.String()},
				{"cve_id", "CVE-2021-44228"},
			},
			want: map[string]string{"cve_id": "CVE-2021-44228"},
		},
		{
			name: "slug-style :checkId is captured (anti-pattern 48 universal closure)",
			params: [][2]string{
				{"id", projectUUID.String()},
				{"checkId", "supply-chain-management.05"},
			},
			want: map[string]string{"checkId": "supply-chain-management.05"},
		},
		{
			name: "all-UUID route returns nil (nothing to record)",
			params: [][2]string{
				{"id", projectUUID.String()},
				{"vuln_id", uuid.New().String()},
			},
			want: nil,
		},
		{
			name: "empty values are skipped",
			params: [][2]string{
				{"cve_id", ""},
				{"checkId", "abc"},
			},
			want: map[string]string{"checkId": "abc"},
		},
		{
			name: "sensitive :token is filtered even when non-UUID (defensive)",
			params: [][2]string{
				{"token", "secret-bearer-value"},
			},
			want: nil,
		},
		{
			name: "sensitive name match is case-insensitive — :APIKey filtered",
			params: [][2]string{
				{"APIKey", "sk-live-deadbeef"},
			},
			want: nil,
		},
		// F222 (M14 Phase D round 1 fix, anti-pattern 48 universal
		// closure supplement): forward-defensive deny-list additions.
		// None of these names appear in a current authenticated route,
		// so the assertions are strict-superset; they exist so a future
		// route binding e.g. :bearer / :jwt / :csrf as a path param
		// cannot leak the value into audit_logs.details without an
		// explicit removal from sensitiveAuditParamNames.
		{
			name: "F222 :Bearer is filtered (case-insensitive)",
			params: [][2]string{
				{"Bearer", "eyJhbGciOiJIUzI1NiJ9.payload.sig"},
			},
			want: nil,
		},
		{
			name: "F222 :JWT is filtered (case-insensitive)",
			params: [][2]string{
				{"JWT", "eyJhbGciOiJIUzI1NiJ9.payload.sig"},
			},
			want: nil,
		},
		{
			name: "F222 :csrf is filtered",
			params: [][2]string{
				{"csrf", "csrf-token-value"},
			},
			want: nil,
		},
		{
			name: "F222 :csrf_token is filtered (compound form)",
			params: [][2]string{
				{"csrf_token", "csrf-compound-form"},
			},
			want: nil,
		},
		{
			name: "F222 :nonce is filtered (replay-protection)",
			params: [][2]string{
				{"nonce", "abc123nonce"},
			},
			want: nil,
		},
		{
			name: "F222 :Signature is filtered (case-insensitive)",
			params: [][2]string{
				{"Signature", "hex-sha256-signature"},
			},
			want: nil,
		},
		{
			name: "F222 :hmac is filtered",
			params: [][2]string{
				{"hmac", "hmac-message-auth-code"},
			},
			want: nil,
		},
		{
			name: "F222 :Cookie is filtered (case-insensitive)",
			params: [][2]string{
				{"Cookie", "session_id=opaque"},
			},
			want: nil,
		},
		{
			name: "multi non-UUID params all captured (forward compat for future routes)",
			params: [][2]string{
				{"slug", "react"},
				{"version", "18.2.0"},
			},
			want: map[string]string{"slug": "react", "version": "18.2.0"},
		},
		{
			name: "product :name (eol/products/:name route shape) captured",
			params: [][2]string{
				{"name", "django"},
			},
			want: map[string]string{"name": "django"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names := make([]string, len(tc.params))
			vals := make([]string, len(tc.params))
			for i, p := range tc.params {
				names[i] = p[0]
				vals[i] = p[1]
			}
			c := newCtxWithParams(t, names, vals)
			got := collectNonUUIDPathParams(c)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d entries (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for k, wantV := range tc.want {
				if gotV, ok := got[k]; !ok {
					t.Errorf("missing key %q in result %v", k, got)
				} else if gotV != wantV {
					t.Errorf("key %q = %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}

// detailsCaptureMatcher is a sqlmock argument matcher that records the
// raw bytes of the matched driver.Value into target — used by the
// F214 end-to-end pin below to inspect the JSON-encoded details column
// the middleware persisted, without paying a Postgres round-trip.
type detailsCaptureMatcher struct {
	target *[]byte
}

func (d detailsCaptureMatcher) Match(v driver.Value) bool {
	switch b := v.(type) {
	case []byte:
		*d.target = append([]byte(nil), b...)
		return true
	case string:
		*d.target = []byte(b)
		return true
	}
	return false
}

// TestAudit_DetailsMap_NonUUIDParamCaptured_F214 is the end-to-end pin
// for M14-4 (closes F196). It drives the Audit() middleware against a
// sqlmock-backed AuditRepository on a route shaped like
// /projects/:id/ssvc/cve/:cve_id and asserts the INSERT's details
// JSON contains both cve_id and the request metadata.
//
// Coverage rationale (anti-pattern 48 + F206 meta-test family):
//   - the helper-level unit test (TestCollectNonUUIDPathParams_F214)
//     proves the param-walk filter is correct in isolation
//   - this integration test proves the helper output actually reaches
//     audit_logs.details via the live middleware → repository code
//     path, so a future refactor that accidentally drops the merge
//     loop in Audit() is caught here even if the helper still works
//   - asserting both keys present (cve_id) AND legacy keys still
//     present (path/method/status/latency_ms) pins additive semantics —
//     M14-4 must not regress the original details contract
func TestAudit_DetailsMap_NonUUIDParamCaptured_F214(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var capturedDetails []byte
	// Audit middleware ultimately calls AuditRepository.Create via the
	// auditRepo.Log wrapper. The INSERT shape lives in repository/audit.go
	// (`INSERT INTO audit_logs (...)`). We match the details column with
	// the capture matcher and accept anything for the rest.
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			sqlmock.AnyArg(),                                // id
			sqlmock.AnyArg(),                                // tenant_id
			sqlmock.AnyArg(),                                // user_id
			sqlmock.AnyArg(),                                // action
			sqlmock.AnyArg(),                                // resource_type
			sqlmock.AnyArg(),                                // resource_id
			detailsCaptureMatcher{target: &capturedDetails}, // details (JSON)
			sqlmock.AnyArg(),                                // ip_address
			sqlmock.AnyArg(),                                // user_agent
			sqlmock.AnyArg(),                                // created_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	auditRepo := repository.NewAuditRepository(db)
	mw := Audit(auditRepo)

	tenantID := uuid.New()
	userID := uuid.New()
	projectUUID := uuid.New()

	e := echo.New()
	// Register the route so c.Path() returns the route pattern (not the
	// concrete URL); determineActionAndResource lives off the pattern.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/projects/"+projectUUID.String()+"/ssvc/cve/CVE-2021-44228", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPath("/api/v1/projects/:id/ssvc/cve/:cve_id")
	c.SetParamNames("id", "cve_id")
	c.SetParamValues(projectUUID.String(), "CVE-2021-44228")
	c.Set(ContextKeyTenantID, tenantID)
	c.Set(ContextKeyUserID, userID)

	handler := func(c echo.Context) error {
		return c.NoContent(http.StatusOK)
	}
	if err := mw(handler)(c); err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}

	if len(capturedDetails) == 0 {
		t.Fatal("details JSON was not captured by sqlmock matcher")
	}
	var details map[string]interface{}
	if err := json.Unmarshal(capturedDetails, &details); err != nil {
		t.Fatalf("details JSON unmarshal: %v\nraw: %s", err, capturedDetails)
	}

	// Primary F214 assertion — :cve_id (non-UUID) must be present.
	if got, ok := details["cve_id"]; !ok {
		t.Errorf("details missing key cve_id; raw=%s", capturedDetails)
	} else if got != "CVE-2021-44228" {
		t.Errorf("details[cve_id] = %v, want %q", got, "CVE-2021-44228")
	}

	// :id is a UUID — must NOT be duplicated into details (already
	// captured as resource_id; copying it into details would be a
	// misleading signal during incident response).
	if _, ok := details["id"]; ok {
		t.Errorf("details unexpectedly contains UUID-shaped :id key (=%v); "+
			"UUID params must NOT be duplicated into details, they flow through resource_id",
			details["id"])
	}

	// Additive semantics: every pre-F214 details key must still be present.
	for _, k := range []string{"path", "method", "status", "latency_ms"} {
		if _, ok := details[k]; !ok {
			t.Errorf("F214 must be ADDITIVE — pre-existing details key %q missing; raw=%s",
				k, capturedDetails)
		}
	}
	if details["path"] != "/api/v1/projects/:id/ssvc/cve/:cve_id" {
		t.Errorf("details[path] = %v, want %q", details["path"],
			"/api/v1/projects/:id/ssvc/cve/:cve_id")
	}
	if details["method"] != "GET" {
		t.Errorf("details[method] = %v, want GET", details["method"])
	}
}

// TestDetermineActionAndResource_TicketFamily_AllMethods_F224 is the
// anti-pattern 48 universal-defense meta-test for the F217 ticket
// classifier branch. It mirrors the F206 / F208 family discipline at
// the tenant-level (vs. project-nested) ticket route surface.
//
// Coverage gap pre-F224:
//
//   - F206 (TestDetermineActionAndResource_AllHoistedFamilies_NoProjectFallthrough)
//     enumerates every PROJECT-NESTED /projects/:id/<child> family ×
//     every HTTP method and asserts the default arm does NOT fall
//     through to ResourceProject. The ticket branch lives ABOVE the
//     tenant /vulnerabilities branch (see F217 head comment in
//     audit.go), is tenant-scoped, and is NOT enumerated by F206.
//
//   - F208 (TestExtractResourceID_PostSuccessContextKey_F208) pins
//     ONE ticket route (POST /vulnerabilities/:vuln_id/ticket) for the
//     SetAuditResourceID handler/middleware symmetry contract. The
//     other three ticket-family routes
//     (POST /tickets/:id/sync, GET /tickets, GET /vulnerabilities/:vuln_id/tickets)
//     are untested at the (method × path) cell level.
//
// Without F224, a future refactor that drops the
// `pathHasChildResource(path, "tickets")` arm or shuffles the case
// order inside the ticket switch would silently regress GET /tickets
// (the tenant-wide list) to the default "unknown" bucket without any
// test catching the symptom until the audit dropdown filter went
// blank in production.
//
// The table below enumerates the 4 ticket routes × 7 standard HTTP
// methods (28 cells) and asserts:
//
//  1. resource_type == ResourceTicket (never falls through to
//     ResourceVulnerability via the /vulnerabilities tenant branch
//     that immediately follows the ticket arm — the F217 pre-fix
//     bug — and never to "unknown" via the default fallback at the
//     bottom of determineActionAndResource).
//  2. action matches the expected verb for the cell, including the
//     F225 ticket.updated / ticket.deleted promoted constants on
//     PUT/PATCH/DELETE/OPTIONS/HEAD.
//
// Adding a new ticket route to the router REQUIRES adding a row to
// the paths table here; otherwise that route's default-arm coverage is
// not enforced and a future fall-through bug ships unobserved.
func TestDetermineActionAndResource_TicketFamily_AllMethods_F224(t *testing.T) {
	// Echo route patterns (the shape c.Path() returns) for every
	// currently-routed ticket endpoint. /tickets and /tickets/:id/sync
	// are tenant-scoped; /vulnerabilities/:vuln_id/ticket{,s} are
	// tenant-scoped too (the /vulnerabilities branch above is
	// pre-empted by the ticket arm — see F217 head comment in
	// audit.go).
	paths := []string{
		"/api/v1/tickets",
		"/api/v1/tickets/:id/sync",
		"/api/v1/vulnerabilities/:vuln_id/ticket",
		"/api/v1/vulnerabilities/:vuln_id/tickets",
	}
	// All standard HTTP methods. OPTIONS / HEAD model the CORS
	// preflight + head-only-meta future routes — both must land on the
	// default arm and resolve to (ticket.updated, ticket) so neither
	// the /vulnerabilities tenant branch nor the "unknown" default at
	// the bottom of determineActionAndResource can swallow them.
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

	// expectedAction returns the verb the middleware emits for a given
	// (method, path) cell. Mirrors the ticket switch in audit.go::
	// determineActionAndResource so a divergence between this table
	// and the classifier is the precise failure mode the test is
	// designed to catch.
	expectedAction := func(method, path string) string {
		switch method {
		case "POST":
			if strings.HasSuffix(path, "/sync") {
				return model.ActionTicketSynced
			}
			return model.ActionTicketCreated
		case "GET":
			if strings.HasSuffix(path, "/tickets") {
				return model.ActionTicketListed
			}
			return model.ActionTicketViewed
		case "PUT", "PATCH":
			// F225: promoted from inline "ticket.updated" literal.
			return model.ActionTicketUpdated
		case "DELETE":
			// F225: promoted from inline "ticket.deleted" literal.
			return model.ActionTicketDeleted
		default:
			// OPTIONS / HEAD land on the default arm, which the F206
			// symmetric closure pins to ticket.updated so a future
			// CORS preflight cannot fall through to /vulnerabilities.
			return model.ActionTicketUpdated
		}
	}

	for _, path := range paths {
		for _, method := range methods {
			t.Run(method+" "+path, func(t *testing.T) {
				action, resource := determineActionAndResource(method, path)

				// Guard 1: resource_type must be ResourceTicket. Falling
				// through to ResourceVulnerability is the F217 pre-fix
				// regression we are guarding against on the tenant-level
				// ticket routes; falling through to "unknown" would mean
				// the default arm at the bottom of the classifier
				// swallowed the path (silent forensic-join gap).
				if resource != model.ResourceTicket {
					t.Fatalf("F224 regression: %s %s resolved to resource %q, "+
						"want %q (action=%q); the ticket arm above the "+
						"/vulnerabilities tenant branch must catch every "+
						"ticket-family path × method cell — anti-pattern 48 "+
						"universal defense for tenant-level ticket family",
						method, path, resource, model.ResourceTicket, action)
				}
				// Guard 2: action must match the expected verb. A drift
				// here means the switch arm and the dropdown registry
				// (service/audit.go GetAvailableActions) are out of sync.
				want := expectedAction(method, path)
				if action != want {
					t.Errorf("action = %q, want %q (method=%s path=%s)",
						action, want, method, path)
				}
				// Guard 3: both must be non-empty — a silently-skipped
				// path drops the audit row entirely.
				if action == "" || resource == "" {
					t.Errorf("%s %s emitted empty (action=%q, resource=%q); "+
						"ticket paths must always classify",
						method, path, action, resource)
				}
			})
		}
	}
}

// TestDetermineActionAndResource_CLIFamily_AllMethods_F233 is the
// anti-pattern 48/52 universal-defense meta-test for the F233 CLI
// classifier branch. It mirrors the F206 (project-nested families) and
// F224 (ticket family) N x M meta-test discipline at the CLI route
// surface.
//
// Coverage gap pre-F233:
//
//   - F206 (TestDetermineActionAndResource_AllHoistedFamilies_NoProjectFallthrough)
//     enumerates project-nested /projects/:id/<child> families only —
//     the CLI branch lives at the tenant surface and is NOT enumerated
//     by F206.
//   - F224 (TestDetermineActionAndResource_TicketFamily_AllMethods_F224)
//     pins the tenant-scoped ticket family; CLI is a distinct branch
//     with its own set of resource types (sbom for /upload, project
//     for /projects, cli for /check + default).
//
// Without F233 meta-test, a future refactor that drops the /upload or
// /projects sub-check in the CLI switch would silently regress those
// two routes back to cli.action / cli (the pre-F233 bug), breaking the
// audit_logs.(resource_type, resource_id) join key on every subsequent
// CLI-driven SBOM upload or project create without any test catching
// the symptom until the audit dropdown filter went blank in production.
//
// The table below enumerates the 3 CLI routes × 7 standard HTTP
// methods (21 cells) and asserts:
//
//  1. resource_type matches the expected resource for the cell:
//     - POST /cli/upload      → ResourceSBOM
//     - POST /cli/projects    → ResourceProject
//     - POST /cli/check       → "cli"
//     - GET  * / default arm  → "cli"
//  2. action matches the expected verb (sbom.uploaded /
//     project.created / cli.check / cli.accessed / cli.action).
//  3. Both are non-empty — a silently-skipped path drops the audit row.
//
// The default arm (PUT / PATCH / DELETE / OPTIONS / HEAD) MUST land on
// cli.action / cli, not fall through to the tenant branches below or
// to the "unknown" default at the bottom of determineActionAndResource.
// This is the F206 discipline applied to the CLI family.
//
// Adding a new /cli/<subroute> to the router REQUIRES adding a row to
// the paths table here; otherwise that route's default-arm coverage is
// not enforced and a future fall-through bug ships unobserved.
func TestDetermineActionAndResource_CLIFamily_AllMethods_F233(t *testing.T) {
	// Echo route patterns (the shape c.Path() returns) for every
	// currently-routed CLI endpoint. main.go registers:
	//   POST /cli/upload         (mints sbom UUID, F233 sbom.uploaded)
	//   POST /cli/check          (transient check, cli.check)
	//   GET  /cli/projects       (list, cli.accessed)
	//   GET  /cli/projects/:id   (item, cli.accessed)
	//   POST /cli/projects       (mints project UUID, F233 project.created)
	// The (:id) getter shares the /cli/projects table row — the classify
	// switch keys off HasSuffix / Contains rather than exact match so
	// both flows resolve identically.
	paths := []string{
		"/api/v1/cli/upload",
		"/api/v1/cli/projects",
		"/api/v1/cli/check",
	}
	// All standard HTTP methods. OPTIONS / HEAD model the CORS
	// preflight + head-only-meta future routes — both must land on the
	// default arm and resolve to (cli.action, "cli") so neither the
	// tenant branches nor the generic "unknown" default at the bottom
	// of determineActionAndResource can swallow them.
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

	// expected returns the (action, resource) pair the middleware
	// should emit for a given (method, path) cell. Mirrors the /cli
	// switch in audit.go::determineActionAndResource so a divergence
	// between this table and the classifier is the precise failure
	// mode the test is designed to catch.
	expected := func(method, path string) (string, string) {
		switch method {
		case "POST":
			if strings.Contains(path, "/upload") {
				return model.ActionSBOMUploaded, model.ResourceSBOM
			}
			if strings.Contains(path, "/check") {
				return "cli.check", "cli"
			}
			if strings.Contains(path, "/projects") {
				return model.ActionProjectCreated, model.ResourceProject
			}
			return "cli.action", "cli"
		case "GET":
			return "cli.accessed", "cli"
		default:
			// PUT / PATCH / DELETE / OPTIONS / HEAD → F206 default arm.
			return "cli.action", "cli"
		}
	}

	for _, path := range paths {
		for _, method := range methods {
			t.Run(method+" "+path, func(t *testing.T) {
				action, resource := determineActionAndResource(method, path)
				wantAction, wantResource := expected(method, path)

				// Guard 1: resource_type must match the expected class.
				// For POST /cli/upload this is ResourceSBOM (F233 fix);
				// pre-F233 it was "cli" which broke the join onto
				// sboms.id. For POST /cli/projects this is ResourceProject
				// (F233 fix); pre-F233 it was "cli" via the cli.action
				// fallthrough. For every other cell it is "cli".
				if resource != wantResource {
					t.Fatalf("F233 regression: %s %s resolved to resource %q, "+
						"want %q (action=%q); anti-pattern 48/52 universal "+
						"defense for CLI family — the classifier drifted "+
						"from the /cli branch specification",
						method, path, resource, wantResource, action)
				}

				// Guard 2: action must match the expected verb. A drift
				// here means the switch arm and the dropdown registry
				// (service/audit.go GetAvailableActions) are out of sync.
				if action != wantAction {
					t.Errorf("action = %q, want %q (method=%s path=%s)",
						action, wantAction, method, path)
				}

				// Guard 3: both must be non-empty — a silently-skipped
				// path drops the audit row entirely.
				if action == "" || resource == "" {
					t.Errorf("%s %s emitted empty (action=%q, resource=%q); "+
						"CLI paths must always classify",
						method, path, action, resource)
				}

				// Guard 4 (F206 anti-fallthrough): the CLI classifier
				// sits BEFORE the /projects tenant branch (in file
				// order). If the CLI switch ever missed a method arm
				// and fell out of the outer if-block, the tenant
				// branches below (which do HasPrefix(path, "/projects")
				// checks — /api/v1/cli/projects unfortunately begins
				// with "/cli/projects", not "/projects", so it would
				// NOT actually match, but a future refactor that moved
				// the strip step could regress this). Assert we did
				// NOT land on ResourceProject for /cli/upload or
				// /cli/check to make the intent explicit.
				if path != "/api/v1/cli/projects" && resource == model.ResourceProject {
					t.Fatalf("F233 anti-fallthrough: %s %s should NOT classify "+
						"as ResourceProject (only /cli/projects may) — got "+
						"action=%q, resource=%q", method, path, action, resource)
				}
			})
		}
	}
}

// TestPathHasChildResource_SegmentExact unit-tests the F202 helper in
// isolation: the segment-exact match must accept "/<name>" suffixes and
// "/<name>/" infixes but reject prefix-only collisions like
// "/<name>-something". A future contributor tempted to "simplify" the
// helper into a strings.Contains call would break this test and
// re-introduce F202.
func TestPathHasChildResource_SegmentExact(t *testing.T) {
	cases := []struct {
		path string
		name string
		want bool
	}{
		// Suffix match — the most common project-nested shape.
		{"/api/v1/projects/:id/apikeys", "apikeys", true},
		{"/api/v1/apikeys", "apikeys", true},
		// Infix match — sub-resource under the segment.
		{"/api/v1/projects/:id/apikeys/:key_id", "apikeys", true},
		{"/api/v1/projects/:id/vex/:vex_id", "vex", true},
		// Prefix-only collision must NOT match — F202.
		{"/api/v1/integrations/apikeys-sync", "apikeys", false},
		{"/api/v1/projects/:id/vex-drafts", "vex", false},
		{"/api/v1/projects/:id/vex-drafts/:draft_id", "vex", false},
		// Empty / unrelated path — must NOT match.
		{"", "vex", false},
		{"/", "vex", false},
		{"/api/v1/projects", "vex", false},
	}
	for _, tc := range cases {
		t.Run(tc.path+"::"+tc.name, func(t *testing.T) {
			if got := pathHasChildResource(tc.path, tc.name); got != tc.want {
				t.Errorf("pathHasChildResource(%q, %q) = %v, want %v",
					tc.path, tc.name, got, tc.want)
			}
		})
	}
}
