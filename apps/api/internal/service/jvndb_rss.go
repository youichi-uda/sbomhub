package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// JVNDB RSS ingestion (migration 072).
//
// JPCERT/CC suspended JVN iPedia and MyJVN on 2026-10-22 with no resumption
// date; the JVNDBRSS data feeds are still published. This service reads them
// as SUPPLEMENTARY information: the JVNDB id, the Japanese title and the dates
// of each advisory, keyed by the CVE ids it references, are attached to
// vulnerabilities NVD already supplied (repository.AttachJVNDB). It never
// creates or removes a finding (the RSS CPEs carry no version ranges) and is
// never reported as a JVN check: scan-status checked_sources / skipped_sources
// are not touched, because this is not a scan source and runs outside scans.
//
// Feeds (https://jvndb.jvn.jp/ja/feed/, measured 2026-11-21):
//
//	<base>/jvndb.rdf               new and updated advisories, the latest 500
//	                               items (~3 days), ~1.2 MB, regenerated hourly
//	<base>/years/jvndb_<YYYY>.rdf  every advisory with a JVNDB id of that year,
//	                               regenerated weekly; 0.1-99 MB each, ~600 MB
//	                               for 1988-2026 together
//
// Politeness: the recent feed is fetched at most once per interval
// (SBOMHUB_JVNDB_RSS_INTERVAL, default 6h) across ALL replicas -- the claim
// is a row in jvndb_feed_state, not process memory, so restarts do not
// refetch either -- with If-None-Match / If-Modified-Since. The year backfill
// is opt-in (SBOMHUB_JVNDB_RSS_BACKFILL_FROM) and reads ONE year feed per
// interval, newest first. Requests identify as a generic SBOMHub client.

const (
	// DefaultJVNDBRSSBaseURL is the directory holding jvndb.rdf and years/.
	DefaultJVNDBRSSBaseURL = "https://jvndb.jvn.jp/ja/rss"

	jvndbRecentFeed    = "recent"
	jvndbUserAgent     = "SBOMHub/1.0 (JVNDB RSS sync)"
	jvndbRecentMaxBody = 32 << 20  // 32 MiB; the feed is ~1.2 MB
	jvndbYearMaxBody   = 384 << 20 // 384 MiB; the largest year feed is ~99 MB
	jvndbRecentTimeout = 2 * time.Minute
	jvndbYearTimeout   = 20 * time.Minute
	jvndbBatchSize     = 500
	jvndbMaxRedirects  = 3
	// jvndbClaimSlack lets a ticker that fires a little early still claim.
	jvndbClaimSlack = time.Minute
)

// jvndbStore is the slice of JVNDBRepository the service uses.
type jvndbStore interface {
	ClaimFeed(ctx context.Context, feed string, minGap time.Duration) (*repository.JVNDBFeedState, bool, error)
	FinishFeed(ctx context.Context, feed string, res repository.JVNDBFeedResult) error
	FeedStates(ctx context.Context) (map[string]repository.JVNDBFeedState, error)
	ResetBackfill(ctx context.Context) error
	UpsertAdvisories(ctx context.Context, recs []repository.JVNDBAdvisoryRecord) (int, error)
}

// JVNDBRSSService fetches and stores the JVNDB RSS feeds.
type JVNDBRSSService struct {
	client       *http.Client
	store        jvndbStore
	baseURL      string
	offline      bool
	interval     time.Duration
	backfillFrom int
	now          func() time.Time
	// Body size limits (tests lower them).
	recentMaxBody int64
	yearMaxBody   int64
}

// NewJVNDBRSSService returns the service. baseURL "" means
// DefaultJVNDBRSSBaseURL; backfillFrom 0 disables the year backfill.
func NewJVNDBRSSService(store jvndbStore, baseURL string, offline bool, interval time.Duration, backfillFrom int) *JVNDBRSSService {
	if baseURL == "" {
		baseURL = DefaultJVNDBRSSBaseURL
	}
	return &JVNDBRSSService{
		client: &http.Client{
			// Per-request deadlines come from the context (recent vs year).
			CheckRedirect: jvndbCheckRedirect,
		},
		store:         store,
		baseURL:       strings.TrimRight(baseURL, "/"),
		offline:       offline,
		interval:      interval,
		backfillFrom:  backfillFrom,
		now:           time.Now,
		recentMaxBody: jvndbRecentMaxBody,
		yearMaxBody:   jvndbYearMaxBody,
	}
}

// WithHTTPClient replaces the HTTP client (tests). Its CheckRedirect is kept
// as given.
func (s *JVNDBRSSService) WithHTTPClient(c *http.Client) *JVNDBRSSService {
	s.client = c
	return s
}

func jvndbCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= jvndbMaxRedirects {
		return fmt.Errorf("jvndb rss: more than %d redirects", jvndbMaxRedirects)
	}
	if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("jvndb rss: redirect from https to a non-https URL refused")
	}
	return nil
}

// JVNDBFeedOutcome reports what one feed did in a sync run.
type JVNDBFeedOutcome struct {
	Feed     string
	Status   string // success | not_modified | failed | partial | skipped
	Seen     int
	Written  int
	Rejected int
	Gap      bool
}

// JVNDBSyncResult reports one Sync run.
type JVNDBSyncResult struct {
	Offline bool
	Feeds   []JVNDBFeedOutcome
}

// Sync runs one round: the recent feed, then at most one backfill year feed.
// With SBOMHUB_OFFLINE=true it makes no request. A feed another replica
// claimed within the interval is skipped. The returned error joins the
// failures of the feeds that were attempted.
func (s *JVNDBRSSService) Sync(ctx context.Context) (*JVNDBSyncResult, error) {
	res := &JVNDBSyncResult{}
	if s.offline {
		slog.Info("sync skipped: offline mode", "source", "jvndb_rss")
		res.Offline = true
		return res, nil
	}
	var errs []error

	out, err := s.syncFeed(ctx, jvndbRecentFeed, s.baseURL+"/jvndb.rdf", s.recentMaxBody, jvndbRecentTimeout)
	res.Feeds = append(res.Feeds, out)
	if err != nil {
		errs = append(errs, err)
	}

	if s.backfillFrom > 0 && ctx.Err() == nil {
		year, ok, err := s.nextBackfillYear(ctx)
		if err != nil {
			errs = append(errs, err)
		} else if ok {
			feed := "year:" + strconv.Itoa(year)
			u := fmt.Sprintf("%s/years/jvndb_%d.rdf", s.baseURL, year)
			out, err := s.syncFeed(ctx, feed, u, s.yearMaxBody, jvndbYearTimeout)
			res.Feeds = append(res.Feeds, out)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	return res, errors.Join(errs...)
}

// nextBackfillYear picks the newest configured year whose feed has not been
// read completely.
func (s *JVNDBRSSService) nextBackfillYear(ctx context.Context) (int, bool, error) {
	states, err := s.store.FeedStates(ctx)
	if err != nil {
		return 0, false, err
	}
	for y := s.now().Year(); y >= s.backfillFrom; y-- {
		st, ok := states["year:"+strconv.Itoa(y)]
		if !ok || !st.Completed {
			return y, true, nil
		}
	}
	return 0, false, nil
}

func (s *JVNDBRSSService) minGap() time.Duration {
	g := s.interval - jvndbClaimSlack
	if g < 0 {
		g = 0
	}
	return g
}

// syncFeed fetches one feed (if this replica claims it) and stores its items.
func (s *JVNDBRSSService) syncFeed(ctx context.Context, feed, feedURL string, maxBody int64, timeout time.Duration) (JVNDBFeedOutcome, error) {
	out := JVNDBFeedOutcome{Feed: feed, Status: "skipped"}
	prev, claimed, err := s.store.ClaimFeed(ctx, feed, s.minGap())
	if err != nil {
		return out, err
	}
	if !claimed {
		slog.Debug("jvndb rss: feed fetched recently (here or by another replica); skipped", "feed", feed)
		return out, nil
	}

	finish := func(r repository.JVNDBFeedResult) {
		out.Status = r.Status
		// Detached: record the outcome even when ctx was cancelled.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := s.store.FinishFeed(fctx, feed, r); err != nil {
			slog.Error("jvndb rss: record feed state failed", "feed", feed, "error", err)
		}
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, feedURL, nil)
	if err != nil {
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: "JVNDB RSS request could not be built"})
		return out, fmt.Errorf("jvndb rss %s: %w", feed, err)
	}
	req.Header.Set("User-Agent", jvndbUserAgent)
	req.Header.Set("Accept", "application/rdf+xml, application/xml;q=0.9, text/xml;q=0.8")
	// Validators are stored only after a fully read feed (FinishFeed), and
	// sent only to the URL they came from: after SBOMHUB_JVNDB_RSS_URL
	// changes, another server's Last-Modified could earn a false 304.
	if prev.SourceURL == feedURL {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("jvndb rss: fetch failed", "feed", feed, "error", err)
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: "JVNDB RSS fetch failed"})
		return out, fmt.Errorf("jvndb rss %s: fetch: %w", feed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		finish(repository.JVNDBFeedResult{
			Status: repository.JVNDBFeedStatusNotModified, SourceURL: feedURL,
			ETag: firstNonEmpty(resp.Header.Get("ETag"), prev.ETag), LastModified: firstNonEmpty(resp.Header.Get("Last-Modified"), prev.LastModified),
			Completed: feed != jvndbRecentFeed,
		})
		slog.Info("jvndb rss: feed not modified", "feed", feed)
		return out, nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: fmt.Sprintf("JVNDB RSS answered HTTP %d", resp.StatusCode)})
		return out, fmt.Errorf("jvndb rss %s: HTTP %d", feed, resp.StatusCode)
	}

	body := &jvndbLimitedReader{r: resp.Body, remaining: maxBody}
	var batch []repository.JVNDBAdvisoryRecord
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := s.store.UpsertAdvisories(ctx, batch)
		out.Written += n
		batch = batch[:0]
		return err
	}
	stats, perr := ParseJVNDBRSS(body, func(rec repository.JVNDBAdvisoryRecord) error {
		batch = append(batch, rec)
		if len(batch) >= jvndbBatchSize {
			return flush()
		}
		return nil
	})
	if perr == nil {
		perr = flush()
	}
	out.Seen, out.Rejected = stats.Items, stats.Rejected
	if body.exceeded {
		perr = fmt.Errorf("body exceeds %d bytes", maxBody)
	}
	if perr != nil {
		status := repository.JVNDBFeedStatusFailed
		if out.Written > 0 {
			status = repository.JVNDBFeedStatusPartial
		}
		slog.Warn("jvndb rss: feed not fully read", "feed", feed, "status", status,
			"items", out.Seen, "written", out.Written, "error", perr)
		finish(repository.JVNDBFeedResult{
			Status: status, ErrorMessage: "JVNDB RSS feed could not be read completely",
			ItemsSeen: out.Seen, ItemsWritten: out.Written, ItemsRejected: out.Rejected,
		})
		return out, fmt.Errorf("jvndb rss %s: %w", feed, perr)
	}

	// Gap: the recent feed holds only the latest 500 items. When even its
	// oldest item was modified after our previous success, advisories
	// modified in between may have scrolled out unseen.
	if feed == jvndbRecentFeed && prev != nil && prev.LastSuccessAt != nil &&
		stats.OldestModified != nil && stats.OldestModified.After(*prev.LastSuccessAt) {
		out.Gap = true
		if s.backfillFrom > 0 {
			if err := s.store.ResetBackfill(ctx); err != nil {
				slog.Error("jvndb rss: reset backfill failed", "error", err)
			}
			slog.Warn("jvndb rss: the recent feed no longer reaches back to the previous sync; re-reading the backfill years one per interval",
				"previous_success", prev.LastSuccessAt, "oldest_item_modified", stats.OldestModified)
		} else {
			slog.Warn("jvndb rss: the recent feed no longer reaches back to the previous sync; advisories modified in between may be missing (set SBOMHUB_JVNDB_RSS_BACKFILL_FROM to re-read the year feeds)",
				"previous_success", prev.LastSuccessAt, "oldest_item_modified", stats.OldestModified)
		}
	}

	finish(repository.JVNDBFeedResult{
		Status: repository.JVNDBFeedStatusSuccess, SourceURL: feedURL,
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
		ItemsSeen: out.Seen, ItemsWritten: out.Written, ItemsRejected: out.Rejected,
		Completed: feed != jvndbRecentFeed, GapDetected: out.Gap,
	})
	slog.Info("jvndb rss: feed stored", "feed", feed, "items", out.Seen,
		"written", out.Written, "rejected", out.Rejected, "gap", out.Gap)
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// jvndbLimitedReader reads at most remaining bytes and then reports EOF with
// exceeded set when more data was available, so an oversized body is refused
// rather than silently truncated into a "complete" feed.
type jvndbLimitedReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (l *jvndbLimitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var one [1]byte
		n, _ := l.r.Read(one[:])
		if n > 0 {
			l.exceeded = true
			return 0, errors.New("jvndb rss: body size limit exceeded")
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}
