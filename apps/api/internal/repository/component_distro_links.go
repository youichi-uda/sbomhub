package repository

import (
	"context"
	"encoding/json"
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
	// Records / WMSource / WMRev: what a stored distro label rests on — its
	// evidence's OSV record ids and the link's watermark (M70).
	Records  []string
	WMSource string
	WMRev    string
}

// ListSbomLinks reads every link of one SBOM's components. Run inside the
// scan's short tenant READ transaction: components FORCE row-level security,
// so outside a tenant transaction this returns nothing.
func (r *ComponentRepository) ListSbomLinks(ctx context.Context, sbomID uuid.UUID) ([]SbomLink, error) {
	rows, err := r.q(ctx).QueryContext(ctx, `
		SELECT cv.component_id, cv.vulnerability_id, v.cve_id, COALESCE(cv.match_method, ''),
		       COALESCE(cv.match_evidence->'records', '[]'::jsonb)::text,
		       COALESCE(cv.match_evidence->>'wm_source', cv.match_evidence->>'source_id', ''),
		       COALESCE(cv.match_evidence->>'wm_rev', cv.match_evidence->>'data_modified', '')
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
		var records string
		if err := rows.Scan(&l.ComponentID, &l.VulnerabilityID, &l.CVEID, &l.Method, &records, &l.WMSource, &l.WMRev); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(records), &l.Records) != nil {
			l.Records = nil // not a list of ids: nothing to resolve
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// The distro step's writes (M70). Every one is guarded the same way:
//
//   - only a component visible under the transaction's tenant GUC
//     (components FORCE RLS; component_vulnerabilities has no policy);
//   - never with data OLDER than what the link already rests on: evidence
//     carries the data's source identity (source_id, a hash of the configured
//     endpoint) and revision (data_modified, fixed-width UTC RFC 3339, text
//     order = time order). Within one source, a write needs a revision at
//     least as new as the stored one; across sources revisions are not
//     comparable and the rank rule alone decides. The watermark stays on the
//     link after a clear and after a no-verdict check, so an overlapping scan
//     that fetched older data can never write afterwards (Codex M70 R8
//     High-4, R10 Medium-2, R11 High-1, R13 High-1).

const distroLabels = `'distro_affected', 'distro_unfixed', 'distro_fixed'`

// priorMethodVocabulary: the non-distro methods a clear may restore.
const priorMethodVocabulary = `'nvd_cpe', 'nvd_cpe_distro', 'nvd_cpe_unverified', 'nvd_keyword', 'jvn_keyword', 'cve_sync_keyword'`

// The link's watermark is (wm_source, wm_rev): the source and revision of the
// NEWEST data any write has checked the link against, advanced even when the
// rank rule refuses the label change (Codex M70 R17 High-1). An older link
// without it falls back to its evidence's source_id / data_modified.
const (
	storedWMSource = `COALESCE(cv.match_evidence->>'wm_source', cv.match_evidence->>'source_id')`
	storedWMRev    = `COALESCE(cv.match_evidence->>'wm_rev', cv.match_evidence->>'data_modified', '')`
)

// distroFreshness is the revision guard against the JSON parameter p.
func distroFreshness(p string) string {
	return `(` + storedWMSource + ` IS DISTINCT FROM (` + p + `::jsonb->>'source_id')
		        OR ` + storedWMRev + ` <= COALESCE(` + p + `::jsonb->>'data_modified', ''))`
}

// withWM appends the watermark of the JSON parameter p to the expression e.
func withWM(e, p string) string {
	return e + ` || jsonb_build_object('wm_source', ` + p + `::jsonb->>'source_id', 'wm_rev', COALESCE(` + p + `::jsonb->>'data_modified', ''))`
}

// relabelDistroFreshness is the guard RelabelDistro applies.
var relabelDistroFreshness = distroFreshness("$4")

// ErrNotDistroMethod is returned before any statement when RelabelDistro is
// handed a method that is not a distro label.
var ErrNotDistroMethod = errors.New("relabel: not a distro match method")

// RelabelDistro sets a distro label and its evidence on an EXISTING link. It
// never inserts: the distro step only relabels what the NVD / JVN sweeps
// linked, so a link removed meanwhile stays removed.
//
// The stored method is replaced only by a strictly stronger one
// (model.MatchMethod.Rank), so a link a scan once found distro_affected is
// never relabelled distro_fixed by a later one; a link already carrying THIS
// method gets its evidence refreshed when it changed other than fetched_at /
// prior_method. prior_method records the method before the FIRST distro
// label, carried across distro relabels, so ClearDistro can restore it. It
// reports whether a row changed.
func (r *ComponentRepository) RelabelDistro(ctx context.Context, componentID, vulnID uuid.UUID, method model.MatchMethod, evidence []byte) (bool, error) {
	if !method.IsDistro() {
		return false, fmt.Errorf("%w: %q", ErrNotDistroMethod, string(method))
	}
	if len(evidence) == 0 {
		return false, fmt.Errorf("relabel: a distro label needs its evidence")
	}
	res, err := r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_method = $3,
		       match_evidence = `+withWM(`$4::jsonb`, "$4")+` || jsonb_build_object('prior_method',
		           CASE WHEN cv.match_method IN (`+distroLabels+`)
		                THEN cv.match_evidence->'prior_method'
		                ELSE to_jsonb(cv.match_method) END)
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND (cv.match_method IS NULL
		        OR cv.match_method = ANY($5)
		        OR (cv.match_method = $3
		            AND (cv.match_evidence - 'fetched_at' - 'prior_method' - 'wm_source' - 'wm_rev')
		                IS DISTINCT FROM ($4::jsonb - 'fetched_at')))
		   AND `+relabelDistroFreshness,
		componentID, vulnID, string(method), string(evidence), pq.Array(model.WeakerMatchMethods(method)))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 1 {
		return n == 1, err
	}
	// Not relabelled (a stronger distro label, or nothing changed): the data
	// was still checked, so the watermark advances (Codex M70 R17 High-1).
	_, err = r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_evidence = `+withWM(`cv.match_evidence`, "$3")+`
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND cv.match_method IN (`+distroLabels+`)
		   AND cv.match_evidence IS NOT NULL
		   AND `+distroFreshness("$3")+`
		   AND (`+storedWMSource+` IS DISTINCT FROM ($3::jsonb->>'source_id')
		        OR `+storedWMRev+` IS DISTINCT FROM COALESCE($3::jsonb->>'data_modified', ''))`,
		componentID, vulnID, string(evidence))
	return false, err
}

// SettleDistroNoVerdict records that data of this source and revision gave
// NO verdict for the link, deciding on the row as it is NOW (one statement,
// so a concurrent relabel cannot slip between a read and this write — Codex
// M70 R22 High-1):
//
//   - under a distro label: the label the data no longer supports is
//     cleared back to the method the link had before the distro step
//     (evidence prior_method; NULL = unknown when there was none or it is not
//     a known method) — only with data of the SAME source at least as new;
//   - otherwise: the watermark is stored as its match_evidence (the API shows
//     evidence only for distro labels), so a scan holding OLDER data cannot
//     label the link afterwards — only when it changes and is not older.
//
// It reports whether a row changed.
func (r *ComponentRepository) SettleDistroNoVerdict(ctx context.Context, componentID, vulnID uuid.UUID, watermark []byte) (bool, error) {
	if len(watermark) == 0 {
		return false, fmt.Errorf("no-verdict: needs the data's watermark")
	}
	res, err := r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_method = CASE
		           WHEN cv.match_method IN (`+distroLabels+`) THEN
		               CASE WHEN cv.match_evidence->>'prior_method' IN (`+priorMethodVocabulary+`)
		                    THEN cv.match_evidence->>'prior_method' END
		           ELSE cv.match_method END,
		       match_evidence = `+withWM(`$3::jsonb`, "$3")+`
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND ((cv.match_method IN (`+distroLabels+`)
		         AND `+storedWMSource+` IS NOT DISTINCT FROM ($3::jsonb->>'source_id')
		         AND `+storedWMRev+` <= COALESCE($3::jsonb->>'data_modified', ''))
		     OR (COALESCE(cv.match_method, '') NOT IN (`+distroLabels+`)
		         AND cv.match_evidence IS DISTINCT FROM `+withWM(`$3::jsonb`, "$3")+`
		         AND `+distroFreshness("$3")+`))`,
		componentID, vulnID, string(watermark))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
