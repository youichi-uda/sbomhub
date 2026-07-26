package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
)

// lookupProjectTenantID is the ONE resolver for "which tenant owns this
// project" (M46 B-1 Medium-1). Every repository that needs to populate a
// child row's tenant_id before an INSERT delegates here.
//
// Why a shared helper and not four copies: projects.tenant_id is
// DDL-nullable (migration 007 added the column without NOT NULL, and 045
// hardened the CHILD tables' tenant_id but not projects'), and
// uuid.UUID.Scan(nil) SUCCEEDS while silently leaving uuid.Nil — it never
// even writes to the receiver. A NULL-tenant project therefore made the
// bare-uuid.UUID versions return (uuid.Nil, nil), and the caller wrote
// uuid.Nil into sboms / license_policies / notification_* .tenant_id, or
// used it as the tenant scope for a subsequent read. Wave 2 fixed only
// vex.go; the other three (license.go, sbom.go, project.go) still had the
// silent-Nil shape, which is exactly the drift a single resolver
// prevents.
//
// COALESCE is deliberately NOT used: a tenant id has no meaningful
// default, so COALESCE(tenant_id, <something>) would just re-encode the
// silent-Nil bug with extra steps. NULL is an error.
//
// sql.ErrNoRows (unknown project) is returned unwrapped so callers can
// keep using errors.Is(err, sql.ErrNoRows) for their 404 mapping.
func lookupProjectTenantID(ctx context.Context, q database.Queryable, projectID uuid.UUID) (uuid.UUID, error) {
	var tenantID uuid.NullUUID
	if err := q.QueryRowContext(ctx,
		`SELECT tenant_id FROM projects WHERE id = $1`, projectID).Scan(&tenantID); err != nil {
		return uuid.Nil, err
	}
	if !tenantID.Valid {
		return uuid.Nil, fmt.Errorf("project %s has no tenant_id", projectID)
	}
	return tenantID.UUID, nil
}
