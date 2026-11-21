package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/sbomhub/sbomhub/internal/repository"
)

func readJVNDBFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/jvndb/recent_trimmed.rdf")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

func parseAll(t *testing.T, doc []byte) ([]repository.JVNDBAdvisoryRecord, JVNDBParseStats, error) {
	t.Helper()
	var got []repository.JVNDBAdvisoryRecord
	st, err := ParseJVNDBRSS(bytes.NewReader(doc), func(r repository.JVNDBAdvisoryRecord) error {
		got = append(got, r)
		return nil
	})
	return got, st, err
}

func TestParseJVNDBRSS_RealFeedFixture(t *testing.T) {
	got, st, err := parseAll(t, readJVNDBFixture(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Items != 7 || st.Accepted != 7 || st.Rejected != 0 || len(got) != 7 {
		t.Fatalf("stats = %+v, records = %d; want 7 accepted", st, len(got))
	}
	byID := map[string]repository.JVNDBAdvisoryRecord{}
	for _, r := range got {
		byID[r.ID] = r
	}
	r, ok := byID["JVNDB-2026-044393"]
	if !ok {
		t.Fatal("JVNDB-2026-044393 missing")
	}
	if r.Title != "OpenJDKにおけるヒープベースのバッファオーバーフローの脆弱性" {
		t.Errorf("title = %q", r.Title)
	}
	if len(r.CVEs) != 1 || r.CVEs[0] != "CVE-2026-114938" {
		t.Errorf("cves = %v (the JVNVU / 関連文書 / CWE references must not be taken as CVEs)", r.CVEs)
	}
	wantPub := time.Date(2026, 11, 19, 7, 12, 0, 0, time.UTC) // 16:12+09:00
	if r.Published == nil || !r.Published.Equal(wantPub) {
		t.Errorf("published = %v, want %v", r.Published, wantPub)
	}
	multi := byID["JVNDB-2026-039068"]
	if len(multi.CVEs) != 4 {
		t.Errorf("JVNDB-2026-039068 cves = %v, want 4", multi.CVEs)
	}
	// An updated advisory: issued and modified differ.
	upd := byID["JVNDB-2025-009576"]
	if upd.Published == nil || upd.Modified == nil || !upd.Modified.After(*upd.Published) {
		t.Errorf("JVNDB-2025-009576 dates = %v / %v, want modified after issued", upd.Published, upd.Modified)
	}
	if none := byID["JVNDB-2026-042402"]; len(none.CVEs) != 0 {
		t.Errorf("JVNDB-2026-042402 has no CVE reference, got %v", none.CVEs)
	}
	wantOldest := time.Date(2026, 11, 18, 8, 24, 0, 0, time.UTC) // 2026-11-18T17:24+09:00
	if st.OldestModified == nil || !st.OldestModified.Equal(wantOldest) {
		t.Errorf("oldest modified = %v, want %v", st.OldestModified, wantOldest)
	}
}

const jvndbDocHead = `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:sec="http://jvn.jp/rss/mod_sec/">
<channel rdf:about="x"><title>t</title></channel>
`

func jvndbItem(id, title string, refs string, modified string) string {
	return fmt.Sprintf(`<item rdf:about="x"><title>%s</title><sec:identifier>%s</sec:identifier>%s<dcterms:issued>2026-11-01T10:00+09:00</dcterms:issued><dcterms:modified>%s</dcterms:modified></item>
`, title, id, refs, modified)
}

func TestParseJVNDBRSS_ItemValidation(t *testing.T) {
	doc := jvndbDocHead +
		jvndbItem("JVNDB-2026-000001", "ok", `<sec:references source="CVE" id="cve-2026-1234"/><sec:references source="CVE" id="CVE-2026-1234"/><sec:references source="JVN" id="CVE-2026-9999"/>`, "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-26-1", "bad id", "", "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000002", "   ", "", "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000003", "a\u202eb\tc\n d", "", "2026-11-03T10:00:30+09:00") +
		`</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Items != 4 || st.Accepted != 2 || st.Rejected != 2 {
		t.Fatalf("stats = %+v, want 4 items, 2 accepted, 2 rejected", st)
	}
	if got[0].ID != "JVNDB-2026-000001" || len(got[0].CVEs) != 1 || got[0].CVEs[0] != "CVE-2026-1234" {
		t.Errorf("first = %+v: CVE ids are upper-cased, de-duplicated, non-CVE sources ignored", got[0])
	}
	if got[1].Title != "ab c d" {
		t.Errorf("title = %q, want bidi override removed and whitespace collapsed", got[1].Title)
	}
	if got[1].Modified == nil || !got[1].Modified.Equal(time.Date(2026, 11, 3, 1, 0, 30, 0, time.UTC)) {
		t.Errorf("modified with seconds = %v", got[1].Modified)
	}
}

func TestParseJVNDBRSS_StrictDocument(t *testing.T) {
	cases := map[string]string{
		"doctype":         `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`,
		"wrong root":      `<?xml version="1.0"?><rss></rss>`,
		"shift_jis":       `<?xml version="1.0" encoding="Shift_JIS"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`,
		"not closed":      jvndbDocHead,
		"empty":           ``,
		"html":            `<html><body>maintenance</body></html>`,
		"trailing root":   jvndbDocHead + `</rdf:RDF><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>`,
		"broken item":     jvndbDocHead + `<item><title>x</item></rdf:RDF>`,
		"no channel":      `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/" xmlns:sec="http://jvn.jp/rss/mod_sec/"><item><title>t</title><sec:identifier>JVNDB-2026-000001</sec:identifier></item></rdf:RDF>`,
		"undefined ent":   jvndbDocHead + `<item><title>&foo;</title></item></rdf:RDF>`,
		"trailing text":   jvndbDocHead + `</rdf:RDF>junk`,
		"pi inside":       jvndbDocHead + `<?evil x?></rdf:RDF>`,
		"non-rdf ns root": `<RDF></RDF>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseAll(t, []byte(doc))
			if !errors.Is(err, ErrJVNDBFeedMalformed) {
				t.Fatalf("err = %v, want ErrJVNDBFeedMalformed", err)
			}
		})
	}
}

// Codex R1 (Medium): a document without the RSS channel, or one whose every
// item is rejected, is not a feed.
func TestParseJVNDBRSS_NotAFeed(t *testing.T) {
	cases := map[string]string{
		"empty root":   `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>`,
		"all rejected": jvndbDocHead + jvndbItem("bad", "t", "", "2026-11-02T10:00+09:00") + jvndbItem("JVNDB-1", "t", "", "") + `</rdf:RDF>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseAll(t, []byte(doc))
			if !errors.Is(err, ErrJVNDBFeedMalformed) {
				t.Fatalf("err = %v, want ErrJVNDBFeedMalformed", err)
			}
		})
	}
	// A channel with no item is a valid (empty) feed: some early year feeds are.
	if _, st, err := parseAll(t, []byte(jvndbDocHead+`</rdf:RDF>`)); err != nil || st.Items != 0 {
		t.Fatalf("empty channel: %+v %v", st, err)
	}
}

// Codex R3 (Medium): nesting depth is bounded; an item without a usable
// modification time is rejected (its order against stored rows is unknown).
func TestParseJVNDBRSS_DepthAndUndated(t *testing.T) {
	deep := jvndbDocHead + `<channel>` + strings.Repeat("<x>", jvndbMaxDepth+5) + strings.Repeat("</x>", jvndbMaxDepth+5) + `</channel></rdf:RDF>`
	if _, _, err := parseAll(t, []byte(deep)); !errors.Is(err, ErrJVNDBFeedMalformed) {
		t.Fatalf("deep: err = %v", err)
	}
	deepItem := jvndbDocHead + `<item>` + strings.Repeat("<x>", jvndbMaxDepth+5) + strings.Repeat("</x>", jvndbMaxDepth+5) + `</item></rdf:RDF>`
	if _, _, err := parseAll(t, []byte(deepItem)); !errors.Is(err, ErrJVNDBFeedMalformed) {
		t.Fatalf("deep item: err = %v", err)
	}
	doc := jvndbDocHead +
		jvndbItem("JVNDB-2026-000001", "dated", "", "2026-11-02T10:00+09:00") +
		`<item><title>undated</title><sec:identifier>JVNDB-2026-000002</sec:identifier></item>` +
		`</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil || len(got) != 1 || st.Rejected != 1 || got[0].ID != "JVNDB-2026-000001" {
		t.Fatalf("got %+v stats %+v err %v: an undated item must be rejected", got, st, err)
	}
}

// Codex R1 (Medium): an item's title and references are bounded while they
// are read, not after.
func TestParseJVNDBRSS_ItemBounds(t *testing.T) {
	var refs strings.Builder
	for i := 0; i < jvndbMaxCVEsPerItem; i++ {
		fmt.Fprintf(&refs, `<sec:references source="CVE" id="CVE-2026-%06d"/>`, i)
	}
	doc := jvndbDocHead + jvndbItem("JVNDB-2026-000001", strings.Repeat("あ", 5000), refs.String(), "2026-11-02T10:00+09:00") + `</rdf:RDF>`
	got, _, err := parseAll(t, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0].CVEs) != jvndbMaxCVEsPerItem || len([]rune(got[0].Title)) != jvndbMaxTitleRunes {
		t.Fatalf("cves=%d title=%d", len(got[0].CVEs), len([]rune(got[0].Title)))
	}
	// An item over the per-item byte budget fails the feed.
	huge := jvndbDocHead + jvndbItem("JVNDB-2026-000002", strings.Repeat("x", jvndbMaxItemBytes+10), "", "2026-11-02T10:00+09:00") + `</rdf:RDF>`
	if _, _, err := parseAll(t, []byte(huge)); !errors.Is(err, ErrJVNDBFeedMalformed) {
		t.Fatalf("err = %v, want ErrJVNDBFeedMalformed for an oversized item", err)
	}
}

func TestParseJVNDBRSS_CallbackErrorStops(t *testing.T) {
	stop := errors.New("stop")
	n := 0
	_, err := ParseJVNDBRSS(bytes.NewReader(readJVNDBFixture(t)), func(repository.JVNDBAdvisoryRecord) error {
		n++
		return stop
	})
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err = %v after %d calls, want the callback error after 1", err, n)
	}
}

func TestCleanJVNDBTitle_Cap(t *testing.T) {
	long := strings.Repeat("あ", 1500)
	if got := []rune(cleanJVNDBTitle(long)); len(got) != jvndbMaxTitleRunes {
		t.Fatalf("len = %d, want %d", len(got), jvndbMaxTitleRunes)
	}
}

// --- sync service with a fake store ---------------------------------------

type fakeJVNDBStore struct {
	mu        sync.Mutex
	states    map[string]*repository.JVNDBFeedState
	finished  map[string]repository.JVNDBFeedResult
	upserted  []repository.JVNDBAdvisoryRecord
	upsertErr error
	finishErr error
}

func newFakeJVNDBStore() *fakeJVNDBStore {
	return &fakeJVNDBStore{states: map[string]*repository.JVNDBFeedState{}, finished: map[string]repository.JVNDBFeedResult{}}
}

func (f *fakeJVNDBStore) ClaimFeed(_ context.Context, feed string, minGap time.Duration) (*repository.JVNDBFeedState, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[feed]
	if !ok {
		st = &repository.JVNDBFeedState{Feed: feed, LastStatus: "never"}
		f.states[feed] = st
	}
	if st.LastAttemptAt != nil && time.Since(*st.LastAttemptAt) < minGap {
		return nil, false, nil
	}
	prev := *st
	now := time.Now()
	st.LastAttemptAt = &now
	st.LastStatus = "running"
	return &prev, true, nil
}

func (f *fakeJVNDBStore) FinishFeed(_ context.Context, feed, _ string, res repository.JVNDBFeedResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.finishErr != nil {
		return f.finishErr
	}
	st := f.states[feed]
	st.LastStatus = res.Status
	f.finished[feed] = res
	if res.Status == repository.JVNDBFeedStatusSuccess || res.Status == repository.JVNDBFeedStatusNotModified {
		st.ETag, st.LastModified, st.SourceURL = res.ETag, res.LastModified, res.SourceURL
		now := time.Now()
		st.LastSuccessAt = &now
		st.Completed = st.Completed || res.Completed
		if res.ContentModifiedAt != nil {
			st.ContentModifiedAt = res.ContentModifiedAt
		}
		if res.GapUntil != nil && (st.GapUntil == nil || res.GapUntil.After(*st.GapUntil)) {
			st.GapUntil = res.GapUntil
		}
	}
	return nil
}

func (f *fakeJVNDBStore) FeedStates(context.Context) (map[string]repository.JVNDBFeedState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]repository.JVNDBFeedState{}
	for k, v := range f.states {
		out[k] = *v
	}
	return out, nil
}

func (f *fakeJVNDBStore) UpsertAdvisories(_ context.Context, recs []repository.JVNDBAdvisoryRecord) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.upsertErr != nil {
		return 0, f.upsertErr
	}
	f.upserted = append(f.upserted, recs...)
	return len(recs), nil
}

func ageAllAttempts(store *fakeJVNDBStore) {
	past := time.Now().Add(-2 * time.Hour)
	for _, st := range store.states {
		st.LastAttemptAt = &past
	}
}

func TestJVNDBSync_OfflineMakesNoRequest(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	store := newFakeJVNDBStore()
	res, err := NewJVNDBRSSService(store, srv.URL, true, time.Hour, 2026).Sync(context.Background())
	if err != nil || res == nil || !res.Offline {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if hits != 0 || len(store.states) != 0 {
		t.Fatalf("offline made %d requests / touched %d feed states", hits, len(store.states))
	}
}

func TestJVNDBSync_FetchConditionalGETAndClaim(t *testing.T) {
	doc := readJVNDBFixture(t)
	var mu sync.Mutex
	var reqs []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.Clone(context.Background()))
		mu.Unlock()
		if r.URL.Path != "/ja/rss/jvndb.rdf" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Sat, 21 Nov 2026 08:00:05 GMT")
		_, _ = w.Write(doc)
	}))
	defer srv.Close()

	store := newFakeJVNDBStore()
	svc := NewJVNDBRSSService(store, srv.URL+"/ja/rss/", false, time.Hour, 0)
	res, err := svc.Sync(context.Background())
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(res.Feeds) != 1 || res.Feeds[0].Status != "success" || res.Feeds[0].Written != 7 {
		t.Fatalf("feeds = %+v", res.Feeds)
	}
	if ua := reqs[0].Header.Get("User-Agent"); ua != jvndbUserAgent || strings.Contains(ua, "@") {
		t.Errorf("User-Agent = %q", ua)
	}

	// Within the interval: claimed already, no request at all.
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("a second sync within the interval made a request (%d total)", len(reqs))
	}

	// After the interval: a conditional GET answered 304.
	past := time.Now().Add(-2 * time.Hour)
	store.states["recent"].LastAttemptAt = &past
	res, err = svc.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 || reqs[1].Header.Get("If-None-Match") != `"v1"` || reqs[1].Header.Get("If-Modified-Since") == "" {
		t.Fatalf("second fetch headers = %v", reqs[len(reqs)-1].Header)
	}
	if res.Feeds[0].Status != "not_modified" || len(store.upserted) != 7 {
		t.Fatalf("status = %s, upserted = %d", res.Feeds[0].Status, len(store.upserted))
	}
}

func TestJVNDBSync_ValidatorsOnlyForTheirURL(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("If-None-Match")+"|"+r.Header.Get("If-Modified-Since"))
		_, _ = w.Write(readJVNDBFixture(t))
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	past := time.Now().Add(-2 * time.Hour)
	store.states["recent"] = &repository.JVNDBFeedState{Feed: "recent", LastStatus: "success",
		SourceURL: "https://jvndb.jvn.jp/ja/rss/jvndb.rdf", ETag: `"real"`, LastModified: "Sat, 21 Nov 2026 08:00:05 GMT", LastAttemptAt: &past}
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "|" {
		t.Fatalf("validators of another URL were sent: %v", got)
	}
	if store.states["recent"].SourceURL != srv.URL+"/jvndb.rdf" {
		t.Fatalf("source url = %q", store.states["recent"].SourceURL)
	}
}

func TestJVNDBSync_FailuresKeepValidatorsAndReportGeneric(t *testing.T) {
	status := http.StatusNotFound
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("<html>secret upstream detail</html>"))
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	_, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background())
	if err == nil {
		t.Fatal("HTTP 404 must be an error")
	}
	fin := store.finished["recent"]
	if fin.Status != "failed" || strings.Contains(fin.ErrorMessage, "secret") || fin.ETag != "" {
		t.Fatalf("finish = %+v", fin)
	}
}

func TestJVNDBSync_OversizedBodyRefused(t *testing.T) {
	doc := readJVNDBFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"big"`)
		_, _ = w.Write(doc)
		_, _ = w.Write(bytes.Repeat([]byte(" "), 4096)) // valid XML whitespace after the root
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0)
	svc.recentMaxBody = int64(len(doc)) + 100
	if _, err := svc.Sync(context.Background()); err == nil {
		t.Fatal("a body over the limit must fail even when the part read is a complete document")
	}
	if fin := store.finished["recent"]; fin.Status == "success" || fin.ETag != "" {
		t.Fatalf("finish = %+v", fin)
	}

	// Exactly at the limit is fine.
	store = newFakeJVNDBStore()
	svc = NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0)
	svc.recentMaxBody = int64(len(doc)) + 4096
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatalf("body at the limit: %v", err)
	}
}

func TestJVNDBSync_BackfillOneYearPerRunNewestFirst(t *testing.T) {
	doc := readJVNDBFixture(t)
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2025)
	svc.now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }

	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(paths) != "[/jvndb.rdf /years/jvndb_2026.rdf]" {
		t.Fatalf("first run paths = %v", paths)
	}
	// Next interval: recent again plus the next year.
	past := time.Now().Add(-2 * time.Hour)
	for _, st := range store.states {
		st.LastAttemptAt = &past
	}
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(paths[2:]) != "[/jvndb.rdf /years/jvndb_2025.rdf]" {
		t.Fatalf("second run paths = %v", paths[2:])
	}
	for _, st := range store.states {
		st.LastAttemptAt = &past
	}
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(paths[4:]) != "[/jvndb.rdf]" {
		t.Fatalf("after the backfill finished, only the recent feed: %v", paths[4:])
	}
}

// Codex R1 (Medium): a gap keeps a year feed pending until a version of it
// generated after the gap has been read -- the weekly regeneration -- and
// the pending state is durable (it does not depend on the backfill setting at
// the time the gap was seen).
func TestJVNDBSync_GapKeepsYearPendingUntilRegenerated(t *testing.T) {
	doc := readJVNDBFixture(t)                // oldest modified 2026-11-18T08:24Z
	yearLM := "Sun, 15 Nov 2026 00:02:09 GMT" // generated before the gap
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path+"|"+r.Header.Get("If-None-Match"))
		lm := yearLM
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/years/") {
			etag := `"` + lm + `"`
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", lm)
		}
		_, _ = w.Write(doc)
	}))
	defer srv.Close()

	store := newFakeJVNDBStore()
	lastOK := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) // long before the feed's window
	cm := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	store.states["recent"] = &repository.JVNDBFeedState{Feed: "recent", LastStatus: "success", LastSuccessAt: &lastOK}
	store.states["year:2026"] = &repository.JVNDBFeedState{Feed: "year:2026", LastStatus: "success", Completed: true,
		SourceURL: srv.URL + "/years/jvndb_2026.rdf", LastSuccessAt: &lastOK, ContentModifiedAt: &cm}

	// The gap is seen while the backfill is OFF: it is still recorded.
	res, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Feeds[0].Gap || store.states["recent"].GapUntil == nil {
		t.Fatalf("gap not recorded: feeds=%+v state=%+v", res.Feeds, store.states["recent"])
	}

	// Backfill switched on later: the completed 2026 feed is read again.
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2026)
	svc.now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	ageAllAttempts(store)
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !containsPath(paths, "/years/jvndb_2026.rdf") {
		t.Fatalf("year feed not re-read after the gap: %v", paths)
	}
	// It was generated before the gap ended, so it stays pending: the next
	// interval asks again (conditional, answered 304).
	ageAllAttempts(store)
	n := len(paths)
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !containsPath(paths[n:], "/years/jvndb_2026.rdf") {
		t.Fatalf("stale year feed no longer pending: %v", paths[n:])
	}
	// After the weekly regeneration it is read in full and the gap is closed.
	mu.Lock()
	yearLM = "Fri, 20 Nov 2026 00:02:09 GMT" // after the gap, before the test's "now"
	mu.Unlock()
	ageAllAttempts(store)
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	ageAllAttempts(store)
	n = len(paths)
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if containsPath(paths[n:], "/years/jvndb_2026.rdf") {
		t.Fatalf("year feed still pending after a post-gap version was read: %v", paths[n:])
	}

	// No gap when the previous success is inside the window.
	store2 := newFakeJVNDBStore()
	recentOK := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	store2.states["recent"] = &repository.JVNDBFeedState{Feed: "recent", LastStatus: "success", LastSuccessAt: &recentOK}
	res, err = NewJVNDBRSSService(store2, srv.URL, false, time.Hour, 0).Sync(context.Background())
	if err != nil || res.Feeds[0].Gap {
		t.Fatalf("unexpected gap: %+v %v", res.Feeds, err)
	}
}

func containsPath(paths []string, p string) bool {
	for _, x := range paths {
		if strings.HasPrefix(x, p+"|") {
			return true
		}
	}
	return false
}

// Codex R1 (Medium): a year read from another source is not complete for
// the configured one.
func TestJVNDBSync_YearFromAnotherSourceIsReRead(t *testing.T) {
	doc := readJVNDBFixture(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	ok := time.Now().Add(-48 * time.Hour)
	store.states["year:2026"] = &repository.JVNDBFeedState{Feed: "year:2026", LastStatus: "success", Completed: true,
		SourceURL: "https://old-mirror.example/rss/years/jvndb_2026.rdf", LastSuccessAt: &ok, LastAttemptAt: &ok, ContentModifiedAt: &ok}
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2026)
	svc.now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(paths) != "[/jvndb.rdf /years/jvndb_2026.rdf]" {
		t.Fatalf("paths = %v", paths)
	}
}

// Codex R1 (Medium): pending years are taken least recently attempted first,
// so a year waiting for its weekly regeneration does not starve the others.
func TestJVNDBSync_PendingYearsRoundRobin(t *testing.T) {
	doc := readJVNDBFixture(t)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/years/jvndb_2026.rdf" {
			w.WriteHeader(http.StatusServiceUnavailable) // keeps failing
			return
		}
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2025)
	svc.now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	_, _ = svc.Sync(context.Background())
	ageAllAttempts(store)
	_, _ = svc.Sync(context.Background())
	if fmt.Sprint(paths) != "[/jvndb.rdf /years/jvndb_2026.rdf /jvndb.rdf /years/jvndb_2025.rdf]" {
		t.Fatalf("paths = %v (a failing year must not starve the next one)", paths)
	}
}

// Codex R1 (Medium): validators are kept only for an answer that came from
// the requested URL, and a 304 is accepted only for a conditional request.
func TestJVNDBSync_RedirectAndUnsolicited304(t *testing.T) {
	doc := readJVNDBFixture(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/moved/jvndb.rdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"moved"`)
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/jvndb.rdf", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved/jvndb.rdf", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newFakeJVNDBStore()
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fin := store.finished["recent"]; fin.Status != "success" || fin.ETag != "" || fin.LastModified != "" {
		t.Fatalf("validators of a redirected answer were kept: %+v", fin)
	}

	srv304 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv304.Close()
	store = newFakeJVNDBStore()
	if _, err := NewJVNDBRSSService(store, srv304.URL, false, time.Hour, 0).Sync(context.Background()); err == nil {
		t.Fatal("a 304 to an unconditional request must fail")
	}
	if fin := store.finished["recent"]; fin.Status != "failed" {
		t.Fatalf("finish = %+v", fin)
	}
}

// Codex R2 (Medium): only the replica that claimed the recent feed in this
// interval runs the backfill, so replicas never download several year feeds
// at once.
func TestJVNDBSync_OneBackfillAcrossReplicas(t *testing.T) {
	doc := readJVNDBFixture(t)
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore() // shared by both "replicas"
	now := func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	a := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2024)
	b := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2024)
	a.now, b.now = now, now
	if _, err := a.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(paths) != "[/jvndb.rdf /years/jvndb_2026.rdf]" {
		t.Fatalf("paths = %v: the second replica must not take another year in the same interval", paths)
	}
}

// Codex R2 (Medium / Low): without a Last-Modified the generation time is
// bounded by the weekly regeneration, not taken as the read time; a 304's
// Last-Modified counts as the generation time.
func TestJVNDBSync_ContentModifiedFromHeadersOnly(t *testing.T) {
	doc := readJVNDBFixture(t)
	lm := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lm != "" {
			w.Header().Set("Last-Modified", lm)
		}
		if r.Header.Get("If-None-Match") == `"y"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"y"`)
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	read := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2026)
	svc.now = func() time.Time { return read }
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cm := store.states["year:2026"].ContentModifiedAt
	if cm == nil || !cm.Equal(read.Add(-jvndbYearRegeneration)) {
		t.Fatalf("content modified = %v, want read time minus %v", cm, jvndbYearRegeneration)
	}
	// After a gap the year is pending again; a 304 carrying a newer
	// Last-Modified moves the generation time forward and closes it.
	gap := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	store.states["recent"].GapUntil = &gap
	lm = "Sat, 21 Nov 2026 00:02:09 GMT"
	ageAllAttempts(store)
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 11, 21, 0, 2, 9, 0, time.UTC)
	if fin := store.finished["year:2026"]; fin.Status != "not_modified" || store.states["year:2026"].ContentModifiedAt == nil || !store.states["year:2026"].ContentModifiedAt.Equal(want) {
		t.Fatalf("after 304: %+v / %v", fin, store.states["year:2026"].ContentModifiedAt)
	}
}

// Codex R2 (Low): conditional headers are not carried to a redirect target.
func TestJVNDBSync_ValidatorsNotSentAcrossRedirect(t *testing.T) {
	doc := readJVNDBFixture(t)
	var seen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/moved/jvndb.rdf", func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("If-None-Match")+"|"+r.Header.Get("If-Modified-Since"))
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/jvndb.rdf", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved/jvndb.rdf", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newFakeJVNDBStore()
	past := time.Now().Add(-2 * time.Hour)
	store.states["recent"] = &repository.JVNDBFeedState{Feed: "recent", LastStatus: "success", SourceURL: srv.URL + "/jvndb.rdf",
		ETag: `"a"`, LastModified: "Sat, 21 Nov 2026 08:00:05 GMT", LastAttemptAt: &past}
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != "|" {
		t.Fatalf("redirect target saw validators: %v", seen)
	}
}

// Codex R2 (Medium): one oversized token (text or attribute) anywhere in the
// document fails the parse while it is being read.
func TestParseJVNDBRSS_OversizedToken(t *testing.T) {
	big := strings.Repeat("x", jvndbMaxTokenBytes+64<<10) // beyond the decoder's 4 KiB read-ahead
	for name, doc := range map[string]string{
		"channel attribute": `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"><channel rdf:about="` + big + `"><title>t</title></channel></rdf:RDF>`,
		"channel text":      `<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"><channel><description>` + big + `</description></channel></rdf:RDF>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseAll(t, []byte(doc)); !errors.Is(err, ErrJVNDBFeedMalformed) {
				t.Fatalf("err = %v, want ErrJVNDBFeedMalformed", err)
			}
		})
	}
	g := &jvndbTokenGuard{r: strings.NewReader(big), limit: 1000}
	buf := make([]byte, 600)
	if n, err := g.Read(buf); err != nil || n != 600 {
		t.Fatal(n, err)
	}
	if n, err := g.Read(buf); err != nil || n != 400 {
		t.Fatalf("second read = %d, %v; want the 400 bytes left before the limit", n, err)
	}
	if _, err := g.Read(buf); err == nil {
		t.Fatal("the guard must refuse reading past its limit without a reset")
	}
	g.reset()
	if n, err := g.Read(buf); err != nil || n != 600 {
		t.Fatalf("after reset: %d, %v", n, err)
	}
}

// Codex R3 (Medium): an empty recent feed is not a successful read (it would
// move last_success_at and hide a later gap); an empty year feed is fine.
func TestJVNDBSync_EmptyRecentFeedFails(t *testing.T) {
	empty := jvndbDocHead + `</rdf:RDF>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"empty"`)
		_, _ = w.Write([]byte(empty))
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2026)
	svc.now = func() time.Time { return time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC) }
	_, err := svc.Sync(context.Background())
	if err == nil {
		t.Fatal("an empty recent feed must fail the round")
	}
	if fin := store.finished["recent"]; fin.Status != "failed" || fin.ETag != "" || store.states["recent"].LastSuccessAt != nil {
		t.Fatalf("recent = %+v / %+v", fin, store.states["recent"])
	}
	// The backfill still ran (the recent claim was held) and an empty year is accepted.
	if fin := store.finished["year:2026"]; fin.Status != "success" {
		t.Fatalf("year = %+v", fin)
	}
}

// Codex R3 (Low): a redirect chain back to the requested URL is still a
// redirect: no validators kept, and an unsolicited 304 is refused.
func TestJVNDBSync_RedirectBackToOrigin(t *testing.T) {
	doc := readJVNDBFixture(t)
	n := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jvndb.rdf", http.StatusFound)
	})
	mux.HandleFunc("/jvndb.rdf", func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			http.Redirect(w, r, "/hop", http.StatusFound)
			return
		}
		w.Header().Set("ETag", `"x"`)
		_, _ = w.Write(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	store := newFakeJVNDBStore()
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fin := store.finished["recent"]; fin.ETag != "" {
		t.Fatalf("validators kept after A->B->A: %+v", fin)
	}
}

// Codex R4 (Medium): a future modification time (beyond 24h of clock skew)
// is not a usable date, and a future Last-Modified does not close a gap.
func TestJVNDB_FutureDatesRejected(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).Format("2006-01-02T15:04Z07:00")
	soon := time.Now().Add(2 * time.Hour).Format("2006-01-02T15:04Z07:00")
	doc := jvndbDocHead + jvndbItem("JVNDB-2026-000001", "future", "", future) + jvndbItem("JVNDB-2026-000002", "skewed", "", soon) + `</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil || st.Rejected != 1 || len(got) != 1 || got[0].ID != "JVNDB-2026-000002" {
		t.Fatalf("got %+v stats %+v err %v", got, st, err)
	}

	fixture := readJVNDBFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", time.Now().Add(365*24*time.Hour).UTC().Format(http.TimeFormat))
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	read := time.Now().UTC()
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, read.Year())
	svc.now = func() time.Time { return read }
	if _, err := svc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	cm := store.states["year:"+fmt.Sprint(read.Year())].ContentModifiedAt
	if cm == nil || !cm.Equal(read.Add(-jvndbYearRegeneration)) {
		t.Fatalf("a future Last-Modified must fall back to the conservative bound, got %v", cm)
	}
}

// Codex R4 (Medium): an item whose CVE references cannot all be read is
// rejected, so it never replaces a stored mapping with a partial one.
func TestParseJVNDBRSS_IncompleteCVEReferencesRejected(t *testing.T) {
	var refs strings.Builder
	for i := 0; i < jvndbMaxCVEsPerItem+1; i++ {
		fmt.Fprintf(&refs, `<sec:references source="CVE" id="CVE-2026-%06d"/>`, i)
	}
	doc := jvndbDocHead +
		jvndbItem("JVNDB-2026-000001", "ok", `<sec:references source="CVE" id="CVE-2026-1234"/>`, "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000002", "bad cve", `<sec:references source="CVE" id="CVE-2026-1234"/><sec:references source="CVE" id="CVE-2026-12"/>`, "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000003", "too many", refs.String(), "2026-11-02T10:00+09:00") +
		`</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil || len(got) != 1 || st.Rejected != 2 {
		t.Fatalf("got %+v stats %+v err %v", got, st, err)
	}
}

// Codex R4 (Low): three redirects are allowed, a fourth is not, and every
// hop is checked for an https -> http downgrade; oversized validators are
// not stored.
func TestJVNDBCheckRedirectHops(t *testing.T) {
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	if err := jvndbCheckRedirect(mk("https://a/4"), []*http.Request{mk("https://a/0"), mk("https://a/1"), mk("https://a/2")}); err != nil {
		t.Errorf("the third redirect must be followed: %v", err)
	}
	if err := jvndbCheckRedirect(mk("https://a/5"), []*http.Request{mk("https://a/0"), mk("https://a/1"), mk("https://a/2"), mk("https://a/3")}); err == nil {
		t.Error("a fourth redirect must be refused")
	}
	if err := jvndbCheckRedirect(mk("http://a/x"), []*http.Request{mk("http://a/0"), mk("https://a/1")}); err == nil {
		t.Error("http -> https -> http must be refused at the downgrading hop")
	}
}

func TestJVNDBSync_OversizedValidatorsNotStored(t *testing.T) {
	doc := readJVNDBFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"`+strings.Repeat("e", 4096)+`"`)
		w.Header().Set("Last-Modified", "not a date")
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fin := store.finished["recent"]; fin.ETag != "" || fin.LastModified != "" {
		t.Fatalf("validators stored: etag %d bytes, last-modified %q", len(fin.ETag), fin.LastModified)
	}
}

// Codex R5 (Low): at the exact size limit a truncated transfer is still an
// error, not a clean end of body.
func TestJVNDBLimitedReader_BoundaryErrors(t *testing.T) {
	r := &jvndbLimitedReader{r: io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(io.ErrUnexpectedEOF)), remaining: 3}
	b, err := io.ReadAll(r)
	if string(b) != "abc" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %q, %v; want the transport error", b, err)
	}
	r = &jvndbLimitedReader{r: strings.NewReader("abc"), remaining: 3}
	if b, err := io.ReadAll(r); string(b) != "abc" || err != nil || r.exceeded {
		t.Fatalf("exact size: %q %v %v", b, err, r.exceeded)
	}
}

// Codex R1 (Low): a failed state write is reported, not swallowed.
func TestJVNDBSync_FinishFailureIsReported(t *testing.T) {
	doc := readJVNDBFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(doc) }))
	defer srv.Close()
	store := newFakeJVNDBStore()
	store.finishErr = errors.New("db down")
	if _, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background()); err == nil {
		t.Fatal("a failed feed-state write must make the sync fail")
	}
}

func TestJVNDBSync_StoreFailureIsPartialOrFailed(t *testing.T) {
	doc := readJVNDBFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v9"`)
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	store := newFakeJVNDBStore()
	store.upsertErr = errors.New("db down")
	_, err := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 0).Sync(context.Background())
	if err == nil {
		t.Fatal("a store failure must fail the sync")
	}
	if fin := store.finished["recent"]; fin.Status != "failed" || fin.ETag != "" {
		t.Fatalf("finish = %+v: validators must not be stored for an incomplete read", fin)
	}
}

func TestJVNDBCheckRedirect(t *testing.T) {
	mk := func(u string) *http.Request { r, _ := http.NewRequest("GET", u, nil); return r }
	if err := jvndbCheckRedirect(mk("http://a/x"), []*http.Request{mk("https://a/y")}); err == nil {
		t.Error("https -> http redirect must be refused")
	}
	if err := jvndbCheckRedirect(mk("https://a/x"), []*http.Request{mk("https://a/0"), mk("https://a/1"), mk("https://a/2"), mk("https://a/3")}); err == nil {
		t.Error("a 4th redirect must be refused")
	}
	if err := jvndbCheckRedirect(mk("https://b/x"), []*http.Request{mk("https://a/1")}); err != nil {
		t.Errorf("one https redirect must be followed: %v", err)
	}
}

// Codex M76 integration R1 Low: a supplied dcterms:modified that is not
// usable (here: more than 24h in the future) must reject the item, not fall
// back to dc:date — the fallback is only for an ABSENT modification time.
// A future dc:date or dcterms:issued rejects the item as well (§39.2).
func TestJVNDB_FutureDateIsNotReplacedByFallback(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).Format("2006-01-02T15:04Z07:00")
	item := func(id, issued, modified, date string) string {
		s := `<item rdf:about="x"><title>t</title><sec:identifier>` + id + `</sec:identifier>`
		if issued != "" {
			s += `<dcterms:issued>` + issued + `</dcterms:issued>`
		}
		if modified != "" {
			s += `<dcterms:modified>` + modified + `</dcterms:modified>`
		}
		if date != "" {
			s += `<dc:date>` + date + `</dc:date>`
		}
		return s + "</item>\n"
	}
	ok := "2026-11-02T10:00+09:00"
	doc := jvndbDocHead +
		item("JVNDB-2026-000001", ok, future, ok) + // future modified, valid dc:date
		item("JVNDB-2026-000002", future, ok, ok) + // future issued
		item("JVNDB-2026-000003", ok, ok, future) + // future dc:date
		item("JVNDB-2026-000004", ok, "", ok) + // absent modified: dc:date fallback
		`</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil || len(got) != 1 || got[0].ID != "JVNDB-2026-000004" || st.Rejected != 3 {
		t.Fatalf("got %+v stats %+v err %v; want only JVNDB-2026-000004 kept", got, st, err)
	}
}
