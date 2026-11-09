package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/model"
)

// SbomLink is one component -> vulnerability link of an SBOM, as the distro
// step (M70) reads it.
type SbomLink struct {
	ComponentID     uuid.UUID
	VulnerabilityID uuid.UUID
	CVEID           string
	// Method is the stored match_method, "" for NULL (a pre-M60 link).
	Method string
}

// ListSbomLinks reads every link of one SBOM's components. Run inside the
// scan's short tenant READ transaction: components FORCE row-level security,
// so outside a tenant transaction this returns nothing.
func (r *ComponentRepository) ListSbomLinks(ctx context.Context, sbomID uuid.UUID) ([]SbomLink, error) {
	rows, err := r.q(ctx).QueryContext(ctx, `
		SELECT cv.component_id, cv.vulnerability_id, v.cve_id, COALESCE(cv.match_method, '')
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = cv.component_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE c.sbom_id = $1
		ORDER BY cv.component_id, v.cve_id`, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SbomLink
	for rows.Next() {
		var l SbomLink
		if err := rows.Scan(&l.ComponentID, &l.VulnerabilityID, &l.CVEID, &l.Method); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// relabelDistroFreshness keeps a same-method refresh from replacing evidence
// of a NEWER data revision with an older one (two overlapping scans whose
// fetches straddled an OSV update; Codex M70 R8 High-4). data_modified is
// fixed-width UTC RFC 3339, so text order is time order; a missing one is
// the oldest.
const relabelDistroFreshness = `COALESCE(cv.match_evidence->>'data_modified', '') <= COALESCE($4::jsonb->>'data_modified', '')`

// ErrNotDistroMethod is returned before any statement when RelabelDistro is
// handed a method that is not a distro label.
var ErrNotDistroMethod = errors.New("relabel: not a distro match method")

// RelabelDistro sets a distro label and its evidence on an EXISTING link
// (M70). It never inserts: the distro step only relabels what the NVD / JVN
// sweeps linked, so a link removed meanwhile stays removed.
//
// The rank rule is LinkComponent's (model.MatchMethod.Rank): the stored method
// is replaced only by a strictly stronger one, so a link a scan once found
// distro_affected is never relabelled distro_fixed by a later one. A link that
// already carries THIS method gets its evidence refreshed (e.g. a newer fixed
// version), and only if the evidence changed other than its fetched_at, so an
// unchanged rescan locks no row.
//
// The component must be visible under the transaction's tenant GUC
// (components FORCE RLS): component_vulnerabilities has no policy of its own,
// and this keeps a component id from another tenant from ever being
// relabelled, whatever the caller passes. It reports whether a row changed.
func (r *ComponentRepository) RelabelDistro(ctx context.Context, componentID, vulnID uuid.UUID, method model.MatchMethod, evidence []byte) (bool, error) {
	if !method.IsDistro() {
		return false, fmt.Errorf("%w: %q", ErrNotDistroMethod, string(method))
	}
	if len(evidence) == 0 {
		return false, fmt.Errorf("relabel: a distro label needs its evidence")
	}
	res, err := r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_method = $3, match_evidence = $4::jsonb
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND (cv.match_method IS NULL
		        OR cv.match_method = ANY($5)
		        OR (cv.match_method = $3
		            AND (cv.match_evidence - 'fetched_at') IS DISTINCT FROM ($4::jsonb - 'fetched_at')
		            AND `+relabelDistroFreshness+`))`,
		componentID, vulnID, string(method), string(evidence), pq.Array(model.WeakerMatchMethods(method)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
