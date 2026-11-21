package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
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
	jvndbRecentMaxBody = 8 << 20   // 8 MiB; the feed is ~1.2 MB
	jvndbYearMaxBody   = 192 << 20 // 192 MiB; the largest year feed is ~99 MB (2026-11-21)
	jvndbRecentTimeout = 2 * time.Minute
	jvndbYearTimeout   = 20 * time.Minute
	jvndbBatchSize     = 500
	jvndbMaxRedirects  = 3
	// jvndbClaimSlack lets a ticker that fires a little early still claim.
	jvndbClaimSlack = time.Minute
	// jvndbYearRegeneration is how often JVN iPedia regenerates the year
	// feeds (weekly, 2026-11-21). Without a Last-Modified, content read at
	// time T is taken to have been generated no later than T minus this.
	jvndbYearRegeneration = 7 * 24 * time.Hour
)

// jvndbStore is the slice of JVNDBRepository the service uses.
type jvndbStore interface {
	ClaimFeed(ctx context.Context, feed string, minGap time.Duration) (*repository.JVNDBFeedState, bool, error)
	FinishFeed(ctx context.Context, feed, attempt string, res repository.JVNDBFeedResult) error
	FeedStates(ctx context.Context) (map[string]repository.JVNDBFeedState, error)
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
	// via holds every request made so far: len(via) redirects have been
	// followed once this one is made.
	if len(via) > jvndbMaxRedirects {
		return fmt.Errorf("jvndb rss: more than %d redirects", jvndbMaxRedirects)
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("jvndb rss: redirect from https to a non-https URL refused")
	}
	// Validators belong to the URL that issued them; Go would copy them to
	// the redirect target (Codex R2).
	req.Header.Del("If-None-Match")
	req.Header.Del("If-Modified-Since")
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

	// Only the replica that claimed the recent feed in this interval runs
	// the backfill: the recent claim is global, so at most one year feed is
	// downloaded per interval for the whole deployment (Codex R2).
	if s.backfillFrom > 0 && out.Status != "skipped" && ctx.Err() == nil {
		years, err := s.backfillCandidates(ctx)
		if err != nil {
			errs = append(errs, err)
		}
		// At most one year feed per round: the first pending year this
		// replica can claim (another replica may hold a claim on one).
		for _, year := range years {
			out, err := s.syncFeed(ctx, "year:"+strconv.Itoa(year), s.yearURL(year), s.yearMaxBody, jvndbYearTimeout)
			if out.Status == "skipped" && err == nil {
				continue
			}
			res.Feeds = append(res.Feeds, out)
			if err != nil {
				errs = append(errs, err)
			}
			break
		}
	}
	return res, errors.Join(errs...)
}

func (s *JVNDBRSSService) yearURL(year int) string {
	return fmt.Sprintf("%s/years/jvndb_%d.rdf", s.baseURL, year)
}

// yearPending reports whether a year feed must be (re)read: never read
// completely, read from another source URL, or generated before the end of a
// gap the recent feed could not cover (it is then asked again, conditionally,
// until the weekly regeneration has been read).
func yearPending(st repository.JVNDBFeedState, ok bool, wantURL string, gapUntil *time.Time) bool {
	if !ok || !st.Completed || st.SourceURL != wantURL {
		return true
	}
	return gapUntil != nil && (st.ContentModifiedAt == nil || st.ContentModifiedAt.Before(*gapUntil))
}

// backfillCandidates lists the pending years, least recently attempted first
// (never attempted first, then newest year first), so a year that keeps
// failing or waits for its regeneration does not starve the others.
func (s *JVNDBRSSService) backfillCandidates(ctx context.Context) ([]int, error) {
	states, err := s.store.FeedStates(ctx)
	if err != nil {
		return nil, err
	}
	gapUntil := states[jvndbRecentFeed].GapUntil
	type cand struct {
		year int
		last *time.Time
	}
	var cands []cand
	for y := s.now().Year(); y >= s.backfillFrom; y-- {
		st, ok := states["year:"+strconv.Itoa(y)]
		if yearPending(st, ok, s.yearURL(y), gapUntil) {
			cands = append(cands, cand{y, st.LastAttemptAt})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i].last, cands[j].last
		switch {
		case a == nil && b != nil:
			return true
		case a != nil && b == nil:
			return false
		case a == nil && b == nil:
			return false // keep newest-first
		}
		return a.Before(*b)
	})
	years := make([]int, len(cands))
	for i, c := range cands {
		years[i] = c.year
	}
	return years, nil
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

	var finishErr error
	finish := func(r repository.JVNDBFeedResult) {
		out.Status = r.Status
		// Detached: record the outcome even when ctx was cancelled.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := s.store.FinishFeed(fctx, feed, prev.Attempt, r); err != nil {
			slog.Error("jvndb rss: record feed state failed", "feed", feed, "error", err)
			finishErr = fmt.Errorf("jvndb rss %s: record feed state: %w", feed, err)
		}
	}

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, feedURL, nil)
	if err != nil {
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: "JVNDB RSS request could not be built"})
		return out, errors.Join(fmt.Errorf("jvndb rss %s: %w", feed, err), finishErr)
	}
	req.Header.Set("User-Agent", jvndbUserAgent)
	req.Header.Set("Accept", "application/rdf+xml, application/xml;q=0.9, text/xml;q=0.8")
	// Validators are stored only after a fully read feed (FinishFeed), and
	// sent only to the URL they came from: after SBOMHUB_JVNDB_RSS_URL
	// changes, another server's Last-Modified could earn a false 304.
	conditional := false
	if prev.SourceURL == feedURL {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
			conditional = true
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
			conditional = true
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		slog.Warn("jvndb rss: fetch failed", "feed", feed, "error", err)
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: "JVNDB RSS fetch failed"})
		return out, errors.Join(fmt.Errorf("jvndb rss %s: fetch: %w", feed, err), finishErr)
	}
	defer resp.Body.Close()
	// Validators are kept only for an answer from the requested URL itself:
	// after any redirect (even one back to the same URL) they belong to
	// another exchange (Codex R1, R3). resp.Request.Response is the redirect
	// response that led to the final request, nil when there was none.
	direct := resp.Request != nil && resp.Request.Response == nil
	// A 304 is accepted only for a request that was actually conditional;
	// CheckRedirect strips the validators, so this also implies direct.
	finalConditional := resp.Request != nil &&
		(resp.Request.Header.Get("If-None-Match") != "" || resp.Request.Header.Get("If-Modified-Since") != "")

	if resp.StatusCode == http.StatusNotModified && conditional && finalConditional && direct {
		cm := s.lastModified(resp)
		etag, lastMod := s.validators(resp)
		finish(repository.JVNDBFeedResult{
			Status: repository.JVNDBFeedStatusNotModified, SourceURL: feedURL, ContentModifiedAt: cm,
			ETag: firstNonEmpty(etag, prev.ETag), LastModified: firstNonEmpty(lastMod, prev.LastModified),
			Completed: feed != jvndbRecentFeed,
		})
		slog.Info("jvndb rss: feed not modified", "feed", feed)
		return out, finishErr
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		finish(repository.JVNDBFeedResult{Status: repository.JVNDBFeedStatusFailed, ErrorMessage: fmt.Sprintf("JVNDB RSS answered HTTP %d", resp.StatusCode)})
		return out, errors.Join(fmt.Errorf("jvndb rss %s: HTTP %d", feed, resp.StatusCode), finishErr)
	}

	body := &jvndbLimitedReader{r: resp.Body, remaining: maxBody}
	var batch []repository.JVNDBAdvisoryRecord
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// rctx: the attempt's whole deadline covers its writes too, so an
		// attempt cannot outlive its claim (Codex R2).
		n, err := s.store.UpsertAdvisories(rctx, batch)
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
	// The recent feed always lists the latest advisories; an empty one is an
	// upstream fault, and recording it as a success would move
	// last_success_at and hide a later gap (Codex R3). Early year feeds can
	// legitimately be empty.
	if perr == nil && feed == jvndbRecentFeed && stats.Items == 0 {
		perr = errors.New("the recent feed has no item")
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
		return out, errors.Join(fmt.Errorf("jvndb rss %s: %w", feed, perr), finishErr)
	}

	// Gap: the recent feed holds only the latest 500 items. When even its
	// oldest item was modified after our previous success, advisories
	// modified in between may have scrolled out unseen. The end of that
	// window is stored (gap_until) whatever the backfill setting is, and every
	// configured year feed generated before it is read again -- now if the
	// backfill is on, or once it is switched on.
	var gapUntil *time.Time
	if feed == jvndbRecentFeed && prev.LastSuccessAt != nil &&
		stats.OldestModified != nil && stats.OldestModified.After(*prev.LastSuccessAt) {
		out.Gap = true
		gapUntil = stats.OldestModified
		slog.Warn("jvndb rss: the recent feed no longer reaches back to the previous sync; advisories modified in between may be missing until the year feeds generated after the gap are read (SBOMHUB_JVNDB_RSS_BACKFILL_FROM)",
			"previous_success", prev.LastSuccessAt, "oldest_item_modified", stats.OldestModified, "backfill_from", s.backfillFrom)
	}

	// Without a Last-Modified the generation time is unknown; bound it by the
	// weekly regeneration rather than taking the read time, so a stale copy
	// cannot close a gap early (Codex R2).
	contentModified := s.now().UTC().Add(-jvndbYearRegeneration)
	if lm := s.lastModified(resp); lm != nil {
		contentModified = *lm
	}
	etag, lastMod := s.validators(resp)
	if !direct {
		etag, lastMod = "", ""
	}
	finish(repository.JVNDBFeedResult{
		Status: repository.JVNDBFeedStatusSuccess, SourceURL: feedURL,
		ETag: etag, LastModified: lastMod,
		ItemsSeen: out.Seen, ItemsWritten: out.Written, ItemsRejected: out.Rejected,
		Completed: feed != jvndbRecentFeed, ContentModifiedAt: &contentModified, GapUntil: gapUntil,
	})
	if finishErr != nil {
		return out, finishErr
	}
	slog.Info("jvndb rss: feed stored", "feed", feed, "items", out.Seen,
		"written", out.Written, "rejected", out.Rejected, "gap", out.Gap)
	return out, nil
}

// jvndbMaxValidatorBytes bounds a stored ETag / Last-Modified: they are
// persisted and sent back on every later request.
const jvndbMaxValidatorBytes = 256

// lastModified is the answer's Last-Modified when it is present, parseable
// and not in the future beyond the clock-skew allowance (Codex R4); nil
// otherwise.
func (s *JVNDBRSSService) lastModified(resp *http.Response) *time.Time {
	lm, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	if err != nil || lm.After(s.now().Add(jvndbClockSkew)) {
		return nil
	}
	lm = lm.UTC()
	return &lm
}

// validators returns the ETag and Last-Modified worth storing: each only
// when short, and Last-Modified only when it is a usable date.
func (s *JVNDBRSSService) validators(resp *http.Response) (etag, lastMod string) {
	if e := resp.Header.Get("ETag"); len(e) <= jvndbMaxValidatorBytes {
		etag = e
	}
	if l := resp.Header.Get("Last-Modified"); len(l) <= jvndbMaxValidatorBytes && s.lastModified(resp) != nil {
		lastMod = l
	}
	return etag, lastMod
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
		// Probe for one more byte. Only a clean EOF ends the body; a
		// transport error at the boundary is passed on (Codex R5).
		var one [1]byte
		n, err := l.r.Read(one[:])
		if n > 0 {
			l.exceeded = true
			return 0, errors.New("jvndb rss: body size limit exceeded")
		}
		return 0, err
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}
