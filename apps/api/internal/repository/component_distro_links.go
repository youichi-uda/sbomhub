package repository

import (
	"context"
	"database/sql"
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
	// LabelSource / LabelRev: the source_id and data_modified of the stored
	// evidence itself (what the label rests on, not the last check).
	LabelSource string
	LabelRev    string
	// WMBySource: the newest revision checked per source (Codex M70 R28
	// High-1).
	WMBySource map[string]string
}

// RevFor is the newest revision of source src the link was checked
// against ("" when none).
func (l SbomLink) RevFor(src string) string {
	if r, ok := l.WMBySource[src]; ok {
		return r
	}
	if l.WMSource == src {
		return l.WMRev
	}
	return ""
}

// ListSbomLinks reads every link of one SBOM's components. Run inside the
// scan's short tenant READ transaction: components FORCE row-level security,
// so outside a tenant transaction this returns nothing.
func (r *ComponentRepository) ListSbomLinks(ctx context.Context, sbomID uuid.UUID) ([]SbomLink, error) {
	rows, err := r.q(ctx).QueryContext(ctx, `
		SELECT cv.component_id, cv.vulnerability_id, v.cve_id, COALESCE(cv.match_method, ''),
		       COALESCE(cv.match_evidence->'records', '[]'::jsonb)::text,
		       COALESCE(cv.match_evidence->>'wm_source', cv.match_evidence->>'source_id', ''),
		       COALESCE(cv.match_evidence->>'wm_rev', cv.match_evidence->>'data_modified', ''),
		       COALESCE(cv.match_evidence->>'source_id', ''),
		       COALESCE(cv.match_evidence->>'data_modified', ''),
		       COALESCE(cv.match_evidence->'wm_by_source', '{}'::jsonb)::text
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
		var records, bySource string
		if err := rows.Scan(&l.ComponentID, &l.VulnerabilityID, &l.CVEID, &l.Method, &records, &l.WMSource, &l.WMRev, &l.LabelSource, &l.LabelRev, &bySource); err != nil {
			return nil, err
		}
		if json.Unmarshal([]byte(bySource), &l.WMBySource) != nil {
			l.WMBySource = nil
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

// The watermark is kept PER SOURCE in wm_by_source {source_id: revision}
// (Codex M70 R28 High-1): with one watermark, a write from source B replaced
// source A's, and an overlapping A scan holding older data then passed the
// guard. wm_source / wm_rev stay as the last check (older rows have only
// them; they count as that source's entry).

// storedRevFor is the link's newest checked revision of p's source.
func storedRevFor(p string) string {
	return `COALESCE(cv.match_evidence->'wm_by_source'->>(` + p + `::jsonb->>'source_id'),
		        CASE WHEN ` + storedWMSource + ` IS NOT DISTINCT FROM (` + p + `::jsonb->>'source_id') THEN ` + storedWMRev + ` END,
		        '')`
}

// distroFreshness is the revision guard against the JSON parameter p: data
// at least as new as the newest of ITS source the link was checked against.
func distroFreshness(p string) string {
	return `(` + storedRevFor(p) + ` <= COALESCE(` + p + `::jsonb->>'data_modified', ''))`
}

// carriedWM is the stored per-source map, a legacy single watermark folded
// in.
const carriedWM = `(CASE WHEN ` + storedWMSource + ` IS NULL THEN '{}'::jsonb
		        ELSE jsonb_build_object(` + storedWMSource + `, ` + storedWMRev + `) END
		    || COALESCE(cv.match_evidence->'wm_by_source', '{}'::jsonb))`

// carriedTombstones: withdrawn_by_source {source_id: {record id: revision}},
// the records a withdrawn clear found withdrawn or edited out of the package
// and the revision of that change (Codex M70 R29 High-2, R32 Medium-2),
// carried across every write.
const carriedTombstones = `COALESCE(cv.match_evidence->'withdrawn_by_source', '{}'::jsonb)`

// withWM appends the watermark of the JSON parameter p (and the carried
// tombstones) to the expression e.
func withWM(e, p string) string {
	return e + ` || jsonb_build_object('wm_source', ` + p + `::jsonb->>'source_id', 'wm_rev', COALESCE(` + p + `::jsonb->>'data_modified', ''),
		    'wm_by_source', ` + carriedWM + ` || jsonb_build_object(COALESCE(` + p + `::jsonb->>'source_id', ''), COALESCE(` + p + `::jsonb->>'data_modified', '')),
		    'withdrawn_by_source', ` + carriedTombstones + `)`
}

// notTombstoned: the evidence p cites no record its source was found to
// have withdrawn (or edited out) at a revision the data p rests on is not
// newer than (Codex M70 R29 High-2): a scan that read the record before the
// change cannot bring the label back, while data from after it (the record
// restored) can.
func notTombstoned(p string) string {
	return `NOT EXISTS (
		    SELECT 1 FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(` + p + `::jsonb->'records') = 'array'
		                                                 THEN ` + p + `::jsonb->'records' ELSE '[]'::jsonb END) rec(id)
		     WHERE cv.match_evidence->'withdrawn_by_source'->(` + p + `::jsonb->>'source_id')->>rec.id
		           >= COALESCE(` + p + `::jsonb->>'data_modified', ''))`
}

// relabelDistroFreshness is the guard RelabelDistro applies.
var relabelDistroFreshness = distroFreshness("$4") + ` AND ` + notTombstoned("$4")

// ErrNotDistroMethod is returned before any statement when RelabelDistro is
// handed a method that is not a distro label.
var ErrNotDistroMethod = errors.New("relabel: not a distro match method")

// RelabelDistro sets a distro label and its evidence on an EXISTING link. It
// never inserts: the distro step only relabels what the NVD / JVN sweeps
// linked, so a link removed meanwhile stays removed.
//
// The stored method is replaced by a strictly stronger one
// (model.MatchMethod.Rank), or — whatever the rank — by strictly NEWER data
// of the stored label's own source (Codex M70 R41 High-1); so evidence of
// equal standing (the same revision, or another source) never relabels a
// distro_affected link distro_fixed, but the source's own update does; a link already carrying THIS
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
		        -- strictly NEWER data of the label's own source replaces any
		        -- distro label, whatever the rank: the rank rule orders
		        -- statements of equal standing, not a source's update of its
		        -- own statement (Codex M70 R41 High-1)
		        OR (cv.match_method IN (`+distroLabels+`)
		            AND cv.match_evidence->>'source_id' IS NOT DISTINCT FROM ($4::jsonb->>'source_id')
		            AND COALESCE(cv.match_evidence->>'data_modified', '') < COALESCE($4::jsonb->>'data_modified', ''))
		        OR (cv.match_method = $3
		            -- a refresh of the label's OWN source only (Codex M70 R53
		            -- Medium-1): another source's equal-rank evidence would
		            -- take the label over and then block the owner's update
		            AND cv.match_evidence->>'source_id' IS NOT DISTINCT FROM ($4::jsonb->>'source_id')
		            AND (cv.match_evidence - 'fetched_at' - 'prior_method' - 'wm_source' - 'wm_rev' - 'wm_by_source' - 'withdrawn_by_source')
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
		        OR `+storedWMRev+` IS DISTINCT FROM COALESCE($3::jsonb->>'data_modified', '')
		        OR `+storedRevFor("$3")+` IS DISTINCT FROM COALESCE($3::jsonb->>'data_modified', ''))`,
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
//     a known method) — only when the label's OWN evidence is of this source
//     and not newer;
//   - under a distro label of another source (or newer evidence): the label
//     stays and the check is merged into its per-source watermark (Codex M70
//     R29 High-1), so older data of this source cannot label it afterwards;
//   - otherwise: the watermark is stored as its match_evidence (the API shows
//     evidence only for distro labels), so a scan holding OLDER data cannot
//     label the link afterwards — only when it changes and is not older.
//
// It reports whether a row changed.
func (r *ComponentRepository) SettleDistroNoVerdict(ctx context.Context, componentID, vulnID uuid.UUID, watermark []byte) (bool, error) {
	changed, _, err := r.SettleDistroNoVerdictOutcome(ctx, componentID, vulnID, watermark)
	return changed, err
}

// SettleDistroNoVerdictOutcome is SettleDistroNoVerdict that also reports
// whether the row, when changed, still carries a distro label: a link read
// under a distro label that no longer does was cleared (Codex M70 R32
// Low-4: the report counts what was written).
func (r *ComponentRepository) SettleDistroNoVerdictOutcome(ctx context.Context, componentID, vulnID uuid.UUID, watermark []byte) (changed, stillDistro bool, err error) {
	if len(watermark) == 0 {
		return false, false, fmt.Errorf("no-verdict: needs the data's watermark")
	}
	// clear: a distro label resting on THIS source's evidence, not newer.
	clear := `(cv.match_method IN (` + distroLabels + `)
		         AND cv.match_evidence->>'source_id' IS NOT DISTINCT FROM ($3::jsonb->>'source_id')
		         AND COALESCE(cv.match_evidence->>'data_modified', '') <= COALESCE($3::jsonb->>'data_modified', ''))`
	// keep: a distro label of ANOTHER source (or newer evidence) stays, but
	// the check is recorded in its watermark (Codex M70 R29 High-1).
	keep := `(cv.match_method IN (` + distroLabels + `) AND NOT ` + clear + `)`
	newEvidence := `CASE WHEN ` + keep + ` THEN ` + withWM(`cv.match_evidence`, "$3") + ` ELSE ` + withWM(`$3::jsonb`, "$3") + ` END`
	// The statement is assembled in three parts: nullscan traces string
	// concatenation only to a fixed depth, and one 19-operand chain exceeds
	// it (the gate then cannot analyse the RETURNING scan at all).
	setPart := `
		UPDATE component_vulnerabilities cv
		   SET match_method = CASE
		           WHEN ` + clear + ` THEN
		               CASE WHEN cv.match_evidence->>'prior_method' IN (` + priorMethodVocabulary + `)
		                    THEN cv.match_evidence->>'prior_method' END
		           ELSE cv.match_method END,
		       match_evidence = ` + newEvidence
	wherePart := `
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND ` + distroFreshness("$3") + `
		   AND (` + clear + ` OR cv.match_evidence IS DISTINCT FROM ` + newEvidence + `)`
	err = r.q(ctx).QueryRowContext(ctx, setPart+wherePart+`
		RETURNING COALESCE(cv.match_method IN (`+distroLabels+`), false)`,
		componentID, vulnID, string(watermark)).Scan(&stillDistro)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, stillDistro, nil
}

// withdrawnWMRev: the source's watermark after a withdrawn clear — the
// newer of the one read and the data's own revision (a clear on data that
// did not go down still advances it; one on data that did keeps it).
const withdrawnWMRev = `GREATEST(COALESCE($3::jsonb->>'wm_rev', ''), COALESCE($3::jsonb->>'data_modified', ''))`

// ClearDistroWithdrawn clears a distro label whose evidence records were ALL
// withdrawn from OSV (Codex M70 R24 High-1, R27 High-2). OSV's package query
// omits withdrawn records, so the package revision can go down and the
// ordinary no-verdict settlement is refused by the revision guard. This
// clear does not claim any package revision: it keeps the link's watermark
// as it is, and applies only when the row still rests on exactly that
// evidence — the same source, the same record list and the same watermark
// it was read with (one statement, so nothing slips in between). p is
// {"source_id", "records", "tombstones" {id: revision}, "wm_rev",
// "data_modified"}; the source's watermark becomes the newer of wm_rev and
// data_modified, and the tombstones are kept. It reports whether a row
// changed (= the label was cleared).
func (r *ComponentRepository) ClearDistroWithdrawn(ctx context.Context, componentID, vulnID uuid.UUID, p []byte) (bool, error) {
	if len(p) == 0 {
		return false, fmt.Errorf("withdrawn clear: needs the evidence it rests on")
	}
	res, err := r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_method = CASE WHEN cv.match_evidence->>'prior_method' IN (`+priorMethodVocabulary+`)
		                           THEN cv.match_evidence->>'prior_method' END,
		       match_evidence = jsonb_build_object('wm_source', ($3::jsonb->>'source_id'), 'wm_rev', `+withdrawnWMRev+`,
		           'wm_by_source', `+carriedWM+` || jsonb_build_object($3::jsonb->>'source_id', `+withdrawnWMRev+`),
		           'withdrawn_by_source', `+mergedTombstones+`)
		 WHERE `+withdrawnRowGuard,
		componentID, vulnID, string(p))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// mergedTombstones: the stored tombstones with $3's added for its source.
const mergedTombstones = carriedTombstones + ` || jsonb_build_object($3::jsonb->>'source_id',
		               (CASE WHEN jsonb_typeof(cv.match_evidence->'withdrawn_by_source'->($3::jsonb->>'source_id')) = 'object'
		                     THEN cv.match_evidence->'withdrawn_by_source'->($3::jsonb->>'source_id') ELSE '{}'::jsonb END)
		               || ($3::jsonb->'tombstones'))`

// withdrawnRowGuard: the row still rests on exactly the evidence the
// withdrawal was resolved against ($3: source_id, records, tombstones,
// wm_rev), under the tenant GUC.
var withdrawnRowGuard = `cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   AND cv.match_method IN (` + distroLabels + `)
		   AND jsonb_typeof($3::jsonb->'records') = 'array'
		   AND jsonb_typeof($3::jsonb->'tombstones') = 'object'
		   AND ($3::jsonb->>'source_id') IS NOT NULL
		   AND jsonb_array_length($3::jsonb->'records') > 0
		   AND cv.match_evidence->>'source_id' IS NOT DISTINCT FROM ($3::jsonb->>'source_id')
		   AND cv.match_evidence->'records' = $3::jsonb->'records'
		   AND ` + storedRevFor("$3") + ` = COALESCE($3::jsonb->>'wm_rev', '')
		   AND COALESCE($3::jsonb->>'wm_rev', '') <> ''`

// ReplaceDistroWithdrawn sets the current verdict on a link whose stored
// label rests on records that were withdrawn or edited out (p, as for
// ClearDistroWithdrawn), whatever the rank (Codex M70 R37 High-1): the rank
// rule keeps a label against WEAKER evidence, not against its own evidence
// being gone. The guard is ClearDistroWithdrawn's; the watermark becomes the
// newer of the one read and the data's, and the tombstones are merged.
func (r *ComponentRepository) ReplaceDistroWithdrawn(ctx context.Context, componentID, vulnID uuid.UUID, method model.MatchMethod, evidence, p []byte) (bool, error) {
	if !method.IsDistro() {
		return false, fmt.Errorf("%w: %q", ErrNotDistroMethod, string(method))
	}
	if len(evidence) == 0 || len(p) == 0 {
		return false, fmt.Errorf("withdrawn replace: needs the evidence and what it replaces")
	}
	res, err := r.q(ctx).ExecContext(ctx, `
		UPDATE component_vulnerabilities cv
		   SET match_method = $4,
		       match_evidence = $5::jsonb || jsonb_build_object(
		           'prior_method', cv.match_evidence->'prior_method',
		           'wm_source', ($3::jsonb->>'source_id'), 'wm_rev', `+withdrawnWMRev+`,
		           'wm_by_source', `+carriedWM+` || jsonb_build_object($3::jsonb->>'source_id', `+withdrawnWMRev+`),
		           'withdrawn_by_source', `+mergedTombstones+`)
		 WHERE `+withdrawnRowGuard+`
		   AND ($5::jsonb->>'source_id') IS NOT DISTINCT FROM ($3::jsonb->>'source_id')`,
		componentID, vulnID, string(p), string(method), string(evidence))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// LockDistroLink takes the link's row lock WITHOUT waiting (Codex M70 R39
// High-1): the distro writer locks each row this way before its write, so it
// never waits on a row another transaction holds (the CVE sync, an NVD sweep)
// and cannot be part of a lock cycle; a row it cannot lock now is left for
// the next scan. It returns the row's method as locked (for counting what the
// write then changed); ok is false when the row is locked elsewhere or gone.
func (r *ComponentRepository) LockDistroLink(ctx context.Context, componentID, vulnID uuid.UUID) (method string, ok bool, err error) {
	err = r.q(ctx).QueryRowContext(ctx, `
		SELECT COALESCE(cv.match_method, '')
		  FROM component_vulnerabilities cv
		 WHERE cv.component_id = $1
		   AND cv.vulnerability_id = $2
		   AND EXISTS (SELECT 1 FROM components c WHERE c.id = cv.component_id)
		   FOR UPDATE OF cv SKIP LOCKED`, componentID, vulnID).Scan(&method)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return method, err == nil, err
}
