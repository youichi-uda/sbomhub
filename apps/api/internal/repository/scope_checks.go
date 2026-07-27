package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// M47 W1 — route-level ownership predicates.
//
// Every function in this file answers exactly one question: "does this
// caller-supplied id belong to the (tenant, project) the request claims?".
// They exist because a route that names a project in its path — or accepts a
// foreign-key id in its body — was, in several places, letting that id reach
// the storage layer unverified. RLS then had to carry the whole boundary
// alone, and for `api_keys` / `public_links` (RLS removed by migrations 028 /
// 030) there was nothing carrying it at all.
//
// Shape, deliberately uniform with the existing precedents in this package
// (ComponentBelongsToProject / ComponentLinkedToVulnInProject /
// GetCVEIDByIDInProject):
//
//   - belt: an EXPLICIT tenant_id / project_id predicate in the statement, so
//     the check still holds if RLS is ever disabled on the table (it already
//     is on two of them);
//   - braces: the FORCE RLS policies on the joined tables, active because the
//     caller runs inside the request's TenantTx. Callers MUST invoke these
//     from inside that tx so `SET LOCAL app.current_tenant_id` is bound —
//     without it the RLS half silently degrades to "0 rows", which these
//     predicates would then report as "not in scope" (fail-closed, never
//     fail-open).
//
// All of them return (false, nil) — never a distinguishing error — when the
// row does not exist, is invisible, or belongs to someone else. Service
// callers collapse that single answer into ONE sentinel that handlers map to
// 404, so the response cannot be used to probe for the existence of rows the
// caller may not see (the one-sentinel discipline established by
// GetCVEIDByIDInProject in 9704eb9 / e96cdec).

// projectInTenant reports whether projectID is a project of tenantID.
//
// `projects` is FORCE ROW LEVEL SECURITY, so the explicit `tenant_id = $1`
// predicate is the belt and the policy is the braces. It is the load-bearing
// half for callers whose own target table has NO tenant coupling at the FK
// layer — `api_keys` (no RLS since migration 028, no composite FK) is the
// only such table today, which is why this helper exists as a shared body
// rather than a single method.
func projectInTenant(ctx context.Context, q database.Queryable, tenantID, projectID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := q.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM projects p
			WHERE p.id = $2 AND p.tenant_id = $1
		)`, tenantID, projectID).Scan(&exists)
	return exists, err
}

// ProjectInTenant reports whether projectID belongs to tenantID.
//
// APIKeyService.CreateProjectKey is the caller. POST /projects/:id/apikeys
// never parsed :id for anything except the INSERT payload, and `api_keys` is
// the one child table with neither RLS (migration 028 removed it so the
// pre-TenantTx authn lookup can run) nor a composite (tenant_id, project_id)
// FK. The single-column FK to projects(id) accepted ANY existing project
// UUID, so an admin of tenant A could mint a key row hanging off tenant B's
// project graph — cross-tenant pollution that CASCADE-couples A's key to B's
// project lifetime, and an existence oracle for project UUIDs (a real project
// answered 201, a non-existent one 400 from the FK violation). This predicate
// is the ONLY defence available for that table.
func (r *APIKeyRepository) ProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) (bool, error) {
	return projectInTenant(ctx, r.q(ctx), tenantID, projectID)
}

// ProjectInTenant reports whether projectID belongs to tenantID.
//
// PublicLinkService.Create is the caller (Codex round 2, Low). `public_links`
// does carry the composite (tenant_id, project_id) FK, so a foreign project
// was already rejected at INSERT — but as an opaque constraint error the
// route rendered as 400, distinguishable from the 404 every other
// out-of-scope target returns, and it never fired at all for the legitimate
// "no sbom_id" form. This predicate makes the answer uniform.
func (r *PublicLinkRepository) ProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) (bool, error) {
	return projectInTenant(ctx, r.q(ctx), tenantID, projectID)
}

// KeyInProject reports whether the api_keys id is a PROJECT-level key of the
// given (tenant, project).
//
// Caller: APIKeyService.DeleteKey, behind DELETE
// /projects/:id/apikeys/:key_id. The repository DELETE filters on
// (id, tenant_id) only, so within a tenant an Admin acting through project
// A's URL could destroy project B's key — a destructive cross-project action
// on a table with no RLS to fall back on. The sibling LIST already filtered
// on both columns, which is what made the asymmetry visible.
//
// `project_id IS NOT DISTINCT FROM $2` is deliberately NOT used: a
// tenant-level key (project_id NULL) must never be deletable through a
// project-scoped route, so the plain equality (which is false for NULL) is
// the wanted behaviour. Tenant-level keys have their own
// DELETE /apikeys/:key_id route.
func (r *APIKeyRepository) KeyInProject(ctx context.Context, tenantID, projectID, keyID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || keyID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM api_keys k
			WHERE k.id = $3 AND k.tenant_id = $1 AND k.project_id = $2
		)`, tenantID, projectID, keyID).Scan(&exists)
	return exists, err
}

// ProjectInTenant reports whether projectID belongs to tenantID.
//
// ComplianceService's checklist / visualization writers are the callers.
// compliance_checklist_responses and sbom_visualization_settings DO carry the
// composite (tenant_id, project_id) FK from migration 041, so a cross-tenant
// project_id is already rejected — but by the FK, i.e. as a 500 with a
// driver-level constraint error, and only at write time. Checking here turns
// that into the same 404 every other out-of-scope id gets, keeps the read
// paths (which the FK cannot help) honest, and stops a probe from
// distinguishing "wrong tenant" (500) from "unknown project" (200 + empty).
func (r *ChecklistRepository) ProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) (bool, error) {
	return projectInTenant(ctx, r.q(ctx), tenantID, projectID)
}

// ProjectInTenant reports whether projectID belongs to tenantID. Twin of
// ChecklistRepository.ProjectInTenant — see there for the rationale.
func (r *VisualizationRepository) ProjectInTenant(ctx context.Context, tenantID, projectID uuid.UUID) (bool, error) {
	return projectInTenant(ctx, r.q(ctx), tenantID, projectID)
}

// SbomInProject reports whether sbomID is an SBOM of the given
// (tenant, project).
//
// Callers: PublicLinkService.Create / Update (the `sbom_id` body field) and
// the POST /projects/:id/scan route (the `?sbom_id=` query parameter).
// `sboms` is FORCE RLS and carries the composite (tenant_id, project_id) FK,
// but `public_links.sbom_id` is a bare single-column FK to sboms(id) — and
// public_links itself has NO RLS (migration 030, so the anonymous
// /public/:token route can resolve a token without tenant middleware). So a
// share link could be minted pointing at ANY sbom row in the database:
// another project's SBOM of the same tenant was then served verbatim through
// an anonymous, password-optional URL while the view header still named the
// link's own project. The explicit s.tenant_id/s.project_id predicates are
// the belt; the sboms RLS policy is the braces.
func (r *SbomRepository) SbomInProject(ctx context.Context, tenantID, projectID, sbomID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || sbomID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sboms s
			WHERE s.id = $3 AND s.tenant_id = $1 AND s.project_id = $2
		)`, tenantID, projectID, sbomID).Scan(&exists)
	return exists, err
}

// StatementInProject reports whether the vex_statement id belongs to the
// given (tenant, project).
//
// PUT / DELETE / GET /projects/:id/vex/:vex_id name a project and then ran
// `... WHERE id = $1`: the :id segment was decoration. Within a tenant that
// let any project's URL mutate or read any other project's VEX verdict — a
// compliance-record integrity break, and the audit row would attribute the
// change to the wrong project. Cross-tenant was held by RLS alone; this adds
// the explicit tenant_id predicate as the belt.
func (r *VEXRepository) StatementInProject(ctx context.Context, tenantID, projectID, statementID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || statementID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM vex_statements vs
			WHERE vs.id = $3 AND vs.tenant_id = $1 AND vs.project_id = $2
		)`, tenantID, projectID, statementID).Scan(&exists)
	return exists, err
}

// PolicyInProject reports whether the license_policies id belongs to the
// given (tenant, project). Exact twin of VEXRepository.StatementInProject for
// PUT / DELETE / GET /projects/:id/licenses/:policy_id, which had the same
// "the route names a project, the SQL does not" shape.
func (r *LicensePolicyRepository) PolicyInProject(ctx context.Context, tenantID, projectID, policyID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || policyID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM license_policies lp
			WHERE lp.id = $3 AND lp.tenant_id = $1 AND lp.project_id = $2
		)`, tenantID, projectID, policyID).Scan(&exists)
	return exists, err
}

// VulnerabilityInProject reports whether vulnerabilityID is linked (via
// component_vulnerabilities) to at least one component of the given
// (tenant, project) — i.e. the vulnerability actually affects that project.
//
// It is the boolean sibling of GetCVEIDByIDInProject (vulnerability.go): same
// join, same scoping rationale (the `vulnerabilities` table is a global
// NVD/EPSS cache with no RLS and component_vulnerabilities carries no
// tenant_id, so scope comes from the s.tenant_id / s.project_id predicates
// plus the FORCE RLS on components / sboms). Use this one where the caller
// needs only the membership answer and not the CVE id; use
// GetCVEIDByIDInProject where the authoritative CVE is also required.
//
// Callers: VEXService.CreateStatement (`vulnerability_id` in the POST body —
// the sibling `component_id` was already guarded by ComponentBelongsToProject
// while the vulnerability itself was not) and IssueTrackerService.CreateTicket
// (the caller-supplied (vuln_id, project_id) pair, which drives a write to a
// THIRD-PARTY issue tracker before anything is persisted locally).
func (r *VulnerabilityRepository) VulnerabilityInProject(ctx context.Context, tenantID, projectID, vulnerabilityID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || projectID == uuid.Nil || vulnerabilityID == uuid.Nil {
		return false, nil
	}
	var exists bool
	err := r.q(ctx).QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM component_vulnerabilities cv
			JOIN components c ON c.id = cv.component_id
			JOIN sboms s ON s.id = c.sbom_id
			WHERE cv.vulnerability_id = $3
			  AND s.tenant_id = $1
			  AND s.project_id = $2
		)`, tenantID, projectID, vulnerabilityID).Scan(&exists)
	return exists, err
}

// ---------------------------------------------------------------------------
// Scoped deletes (M47 W1, Codex round 2 Low ×3)
// ---------------------------------------------------------------------------
//
// The three routes below used to do check-then-act: a *InProject predicate,
// then the unscoped `DELETE ... WHERE id = $1`. That left two problems the
// handler could not solve on its own:
//
//   - the DELETE's own error was untyped, so a driver failure AFTER a
//     successful scope check was indistinguishable from "the row was not
//     there" and both rendered as 404, hiding real faults; and
//   - the two statements are a race. Inside one request transaction the
//     window is small, but it is not zero and it is not necessary.
//
// One conditional DELETE removes both: `RowsAffected() == 0` IS the
// out-of-scope answer (unknown id, other project, other tenant — all the
// same, as the one-sentinel rule requires), and any returned error is
// unambiguously infrastructure. Callers map the former to 404 and the latter
// to 500.
//
// These are new methods in a new file on purpose: the pre-existing Delete
// methods stay untouched (another wave owns their RowsAffected hardening),
// and nothing else in the codebase calls them differently.

// ErrScopedDeleteNoRows is returned by the scoped deletes below when the
// conditional DELETE matched nothing. It is the ONE answer for "unknown id",
// "another project's row" and "another tenant's row"; callers render it as
// 404. Any other error from these methods is an infrastructure fault.
var ErrScopedDeleteNoRows = errors.New("no row matched the scoped delete")

// scopedDelete runs one conditional DELETE and converts a zero-row result
// into ErrScopedDeleteNoRows.
func scopedDelete(ctx context.Context, q database.Queryable, query string, args ...any) error {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrScopedDeleteNoRows
	}
	return nil
}

// DeleteStatementInProject removes the vex_statement id, but only when it
// belongs to (tenant, project). Replaces StatementInProject + Delete for
// DELETE /projects/:id/vex/:vex_id.
func (r *VEXRepository) DeleteStatementInProject(ctx context.Context, tenantID, projectID, statementID uuid.UUID) error {
	if tenantID == uuid.Nil || projectID == uuid.Nil || statementID == uuid.Nil {
		return ErrScopedDeleteNoRows
	}
	return scopedDelete(ctx, r.q(ctx),
		`DELETE FROM vex_statements WHERE id = $3 AND tenant_id = $1 AND project_id = $2`,
		tenantID, projectID, statementID)
}

// DeletePolicyInProject removes the license_policies id, but only when it
// belongs to (tenant, project). Twin of DeleteStatementInProject.
func (r *LicensePolicyRepository) DeletePolicyInProject(ctx context.Context, tenantID, projectID, policyID uuid.UUID) error {
	if tenantID == uuid.Nil || projectID == uuid.Nil || policyID == uuid.Nil {
		return ErrScopedDeleteNoRows
	}
	return scopedDelete(ctx, r.q(ctx),
		`DELETE FROM license_policies WHERE id = $3 AND tenant_id = $1 AND project_id = $2`,
		tenantID, projectID, policyID)
}

// DeleteKeyInProject removes the api_keys id, but only when it is a
// PROJECT-level key of (tenant, project). The plain `project_id = $2`
// equality is deliberate: a tenant-level key (project_id NULL) must never be
// deletable through a project-scoped route — it has its own.
func (r *APIKeyRepository) DeleteKeyInProject(ctx context.Context, tenantID, projectID, keyID uuid.UUID) error {
	if tenantID == uuid.Nil || projectID == uuid.Nil || keyID == uuid.Nil {
		return ErrScopedDeleteNoRows
	}
	return scopedDelete(ctx, r.q(ctx),
		`DELETE FROM api_keys WHERE id = $3 AND tenant_id = $1 AND project_id = $2`,
		tenantID, projectID, keyID)
}
