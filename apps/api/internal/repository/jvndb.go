package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// JVNDB RSS storage (migration 072). The three tables are GLOBAL catalogue
// data like `vulnerabilities` and `kev_catalog`: no tenant_id, no RLS. They
// are written only by the background sync (service.JVNDBRSSService) and read
// by every tenant's vulnerability list through AttachJVNDB.

// JVNDBAdvisoryRecord is one validated RSS item ready to be stored.
type JVNDBAdvisoryRecord struct {
	ID        string
	Title     string
	CVEs      []string // upper-case, validated, de-duplicated
	Published *time.Time
	Modified  *time.Time
}

// JVNDBFeedState is the stored sync state of one feed ("recent" or
// "year:YYYY").
type JVNDBFeedState struct {
	Feed          string
	SourceURL     string // the URL ETag / LastModified came from
	ETag          string
	LastModified  string
	LastAttemptAt *time.Time
	LastSuccessAt *time.Time
	LastStatus    string
	Completed     bool
}

// JVNDBFeedResult is what one sync attempt of a feed records.
type JVNDBFeedResult struct {
	Status        string // success | not_modified | failed | partial
	SourceURL     string // the URL fetched; stored with the validators
	ErrorMessage  string // generic text only, never upstream detail
	ETag          string // stored only on success / not_modified
	LastModified  string
	ItemsSeen     int
	ItemsWritten  int
	ItemsRejected int
	Completed     bool
	GapDetected   bool
}

// Feed status values (jvndb_feed_state.last_status CHECK).
const (
	JVNDBFeedStatusSuccess     = "success"
	JVNDBFeedStatusNotModified = "not_modified"
	JVNDBFeedStatusFailed      = "failed"
	JVNDBFeedStatusPartial     = "partial"
)

// maxJVNDBPerCVE bounds how many advisories one CVE carries on a list
// response. The real feed maps a CVE to one advisory (rarely two); the cap
// only keeps a pathological catalogue from inflating the page.
const maxJVNDBPerCVE = 5

// JVNDBRepository stores the JVNDB RSS catalogue.
type JVNDBRepository struct {
	db *sql.DB
}

// NewJVNDBRepository returns a repository on db. The sync runs outside any
// request transaction, so every statement goes to db directly.
func NewJVNDBRepository(db *sql.DB) *JVNDBRepository {
	return &JVNDBRepository{db: db}
}

// ClaimFeed atomically claims the next attempt of feed: it succeeds (ok=true)
// only when the feed was never attempted or its last attempt started at
// least minGap ago, and it stamps last_attempt_at in the same statement. This
// is what keeps several API replicas -- and a restart loop -- from fetching
// the same feed more than once per interval. The returned state is the one
// BEFORE this attempt (validators, last success).
func (r *JVNDBRepository) ClaimFeed(ctx context.Context, feed string, minGap time.Duration) (*JVNDBFeedState, bool, error) {
	if _, err := r.db.ExecContext(ctx,
		`INSERT INTO jvndb_feed_state (feed) VALUES ($1) ON CONFLICT (feed) DO NOTHING`, feed); err != nil {
		return nil, false, fmt.Errorf("jvndb: ensure feed state: %w", err)
	}
	// The CTE reads the row as it was before the UPDATE so the caller gets
	// the previous attempt's facts.
	const q = `
		WITH prev AS (
			SELECT feed, source_url, etag, last_modified, last_attempt_at, last_success_at, last_status, completed
			FROM jvndb_feed_state WHERE feed = $1 FOR UPDATE
		)
		UPDATE jvndb_feed_state s
		SET last_attempt_at = NOW(), last_status = 'running'
		FROM prev
		WHERE s.feed = prev.feed
		  AND (prev.last_attempt_at IS NULL OR prev.last_attempt_at <= NOW() - make_interval(secs => $2))
		RETURNING COALESCE(prev.feed, ''), COALESCE(prev.source_url, ''), COALESCE(prev.etag, ''), COALESCE(prev.last_modified, ''),
		          prev.last_attempt_at, prev.last_success_at, COALESCE(prev.last_status, ''), COALESCE(prev.completed, false)`
	var st JVNDBFeedState
	err := r.db.QueryRowContext(ctx, q, feed, minGap.Seconds()).Scan(
		&st.Feed, &st.SourceURL, &st.ETag, &st.LastModified, &st.LastAttemptAt, &st.LastSuccessAt, &st.LastStatus, &st.Completed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("jvndb: claim feed: %w", err)
	}
	return &st, true, nil
}

// FinishFeed records the outcome of the attempt ClaimFeed started. The
// conditional-GET validators are replaced only on success / not_modified,
// so a failed or partial run is fetched in full next time.
func (r *JVNDBRepository) FinishFeed(ctx context.Context, feed string, res JVNDBFeedResult) error {
	ok := res.Status == JVNDBFeedStatusSuccess || res.Status == JVNDBFeedStatusNotModified
	const q = `
		UPDATE jvndb_feed_state SET
			last_status     = $2,
			last_error      = NULLIF($3, ''),
			source_url      = CASE WHEN $4 THEN NULLIF($12, '') ELSE source_url END,
			etag            = CASE WHEN $4 THEN NULLIF($5, '') ELSE etag END,
			last_modified   = CASE WHEN $4 THEN NULLIF($6, '') ELSE last_modified END,
			last_success_at = CASE WHEN $4 THEN NOW() ELSE last_success_at END,
			items_seen      = $7,
			items_written   = $8,
			items_rejected  = $9,
			completed       = CASE WHEN $4 THEN (completed OR $10) ELSE completed END,
			gap_detected_at = CASE WHEN $11 THEN NOW() ELSE gap_detected_at END
		WHERE feed = $1`
	if _, err := r.db.ExecContext(ctx, q, feed, res.Status, res.ErrorMessage, ok,
		res.ETag, res.LastModified, res.ItemsSeen, res.ItemsWritten, res.ItemsRejected,
		res.Completed, res.GapDetected, res.SourceURL); err != nil {
		return fmt.Errorf("jvndb: finish feed: %w", err)
	}
	return nil
}

// FeedStates returns every stored feed state keyed by feed name.
func (r *JVNDBRepository) FeedStates(ctx context.Context) (map[string]JVNDBFeedState, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(feed, ''), COALESCE(source_url, ''), COALESCE(etag, ''), COALESCE(last_modified, ''),
		       last_attempt_at, last_success_at, COALESCE(last_status, ''), COALESCE(completed, false)
		FROM jvndb_feed_state`)
	if err != nil {
		return nil, fmt.Errorf("jvndb: read feed states: %w", err)
	}
	defer rows.Close()
	out := map[string]JVNDBFeedState{}
	for rows.Next() {
		var st JVNDBFeedState
		if err := rows.Scan(&st.Feed, &st.SourceURL, &st.ETag, &st.LastModified, &st.LastAttemptAt, &st.LastSuccessAt, &st.LastStatus, &st.Completed); err != nil {
			return nil, fmt.Errorf("jvndb: read feed states: %w", err)
		}
		out[st.Feed] = st
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("jvndb: read feed states: %w", err)
	}
	return out, nil
}

// ResetBackfill marks every year feed as not completed and drops its
// validators, so the backfill re-reads them (one per sync run). Used when the
// recent feed shows a gap the sync could not have seen.
func (r *JVNDBRepository) ResetBackfill(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE jvndb_feed_state SET completed = false, etag = NULL, last_modified = NULL, source_url = NULL
		WHERE feed LIKE 'year:%'`); err != nil {
		return fmt.Errorf("jvndb: reset backfill: %w", err)
	}
	return nil
}

// UpsertAdvisories writes one batch in a single transaction and returns how
// many advisories were written. An item whose dcterms:modified is OLDER than
// the stored row's is skipped (not counted), so a year feed published days
// ago cannot overwrite what the recent feed wrote since; an item with the
// same or a newer modified time replaces the title, the dates and the
// advisory's whole CVE set. Rows are written in id order so two concurrent
// batches touching the same advisories lock them in the same order.
func (r *JVNDBRepository) UpsertAdvisories(ctx context.Context, recs []JVNDBAdvisoryRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	sorted := make([]JVNDBAdvisoryRecord, len(recs))
	copy(sorted, recs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	written := 0
	err := database.WithTxFunc(ctx, r.db, func(ctx context.Context, tx *sql.Tx) error {
		for _, rec := range sorted {
			var id string
			err := tx.QueryRowContext(ctx, `
				INSERT INTO jvndb_advisories (jvndb_id, title, published_at, modified_at)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (jvndb_id) DO UPDATE SET
					title        = EXCLUDED.title,
					published_at = EXCLUDED.published_at,
					modified_at  = EXCLUDED.modified_at,
					updated_at   = NOW()
				WHERE COALESCE(EXCLUDED.modified_at, '-infinity'::timestamptz)
				   >= COALESCE(jvndb_advisories.modified_at, '-infinity'::timestamptz)
				RETURNING COALESCE(jvndb_id, '')`,
				rec.ID, rec.Title, rec.Published, rec.Modified).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				continue // stored row is newer
			}
			if err != nil {
				return fmt.Errorf("jvndb: upsert %s: %w", rec.ID, err)
			}
			cves := rec.CVEs
			if cves == nil {
				cves = []string{}
			}
			if _, err := tx.ExecContext(ctx, `
				DELETE FROM jvndb_advisory_cves
				WHERE jvndb_id = $1 AND NOT (cve_id = ANY($2::text[]))`,
				rec.ID, pq.Array(cves)); err != nil {
				return fmt.Errorf("jvndb: prune cves of %s: %w", rec.ID, err)
			}
			if len(cves) > 0 {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO jvndb_advisory_cves (jvndb_id, cve_id)
					SELECT $1, c FROM unnest($2::text[]) AS c
					ON CONFLICT DO NOTHING`,
					rec.ID, pq.Array(cves)); err != nil {
					return fmt.Errorf("jvndb: map cves of %s: %w", rec.ID, err)
				}
			}
			written++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

// AttachJVNDB fills Vulnerability.JVNDB for every row whose CVE id one or
// more stored JVNDB advisories reference. It issues one query through q (the
// caller's request transaction when there is one). It never adds or removes
// rows: the RSS data is supplementary. An error is returned rather than
// swallowed, like the rest of the list read (a failed statement inside the
// request transaction aborts it anyway).
func AttachJVNDB(ctx context.Context, q database.Queryable, vulns []model.Vulnerability) error {
	if len(vulns) == 0 {
		return nil
	}
	byCVE := map[string][]int{}
	keys := make([]string, 0, len(vulns))
	for i := range vulns {
		k := strings.ToUpper(strings.TrimSpace(vulns[i].CVEID))
		if !strings.HasPrefix(k, "CVE-") {
			continue
		}
		if _, seen := byCVE[k]; !seen {
			keys = append(keys, k)
		}
		byCVE[k] = append(byCVE[k], i)
	}
	if len(keys) == 0 {
		return nil
	}
	rows, err := q.QueryContext(ctx, `
		SELECT COALESCE(m.cve_id, ''), COALESCE(a.jvndb_id, ''), COALESCE(a.title, ''), a.published_at, a.modified_at
		FROM jvndb_advisory_cves m
		JOIN jvndb_advisories a ON a.jvndb_id = m.jvndb_id
		WHERE m.cve_id = ANY($1::text[])
		ORDER BY m.cve_id, a.published_at DESC NULLS LAST, a.jvndb_id DESC`,
		pq.Array(keys))
	if err != nil {
		return fmt.Errorf("jvndb: read advisories: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cve string
		var ref model.JVNDBAdvisoryRef
		if err := rows.Scan(&cve, &ref.ID, &ref.Title, &ref.Published, &ref.Modified); err != nil {
			return fmt.Errorf("jvndb: read advisories: %w", err)
		}
		ref.URL = model.JVNDBAdvisoryURL(ref.ID)
		if ref.URL == "" {
			continue
		}
		for _, i := range byCVE[cve] {
			if len(vulns[i].JVNDB) < maxJVNDBPerCVE {
				vulns[i].JVNDB = append(vulns[i].JVNDB, ref)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("jvndb: read advisories: %w", err)
	}
	return nil
}
