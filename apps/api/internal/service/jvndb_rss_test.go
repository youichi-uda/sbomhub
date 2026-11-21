package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
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
		jvndbItem("JVNDB-2026-000001", "ok", `<sec:references source="CVE" id="cve-2026-1234"/><sec:references source="CVE" id="CVE-2026-1234"/><sec:references source="CVE" id="CVE-26-1"/><sec:references source="JVN" id="CVE-2026-9999"/>`, "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-26-1", "bad id", "", "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000002", "   ", "", "2026-11-02T10:00+09:00") +
		jvndbItem("JVNDB-2026-000003", "a‮b\tc\n d", "", "not a date") +
		`</rdf:RDF>`
	got, st, err := parseAll(t, []byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if st.Items != 4 || st.Accepted != 2 || st.Rejected != 2 {
		t.Fatalf("stats = %+v, want 4 items, 2 accepted, 2 rejected", st)
	}
	if got[0].ID != "JVNDB-2026-000001" || len(got[0].CVEs) != 1 || got[0].CVEs[0] != "CVE-2026-1234" {
		t.Errorf("first = %+v: CVE ids are upper-cased, de-duplicated, malformed and non-CVE sources dropped", got[0])
	}
	if got[1].Title != "ab c d" {
		t.Errorf("title = %q, want bidi override removed and whitespace collapsed", got[1].Title)
	}
	if got[1].Modified != nil {
		t.Errorf("unparsable modified must be nil, got %v", got[1].Modified)
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
	attempted map[string]time.Time
	finished  map[string]repository.JVNDBFeedResult
	upserted  []repository.JVNDBAdvisoryRecord
	resets    int
	upsertErr error
}

func newFakeJVNDBStore() *fakeJVNDBStore {
	return &fakeJVNDBStore{states: map[string]*repository.JVNDBFeedState{}, attempted: map[string]time.Time{}, finished: map[string]repository.JVNDBFeedResult{}}
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

func (f *fakeJVNDBStore) FinishFeed(_ context.Context, feed string, res repository.JVNDBFeedResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.states[feed]
	st.LastStatus = res.Status
	f.finished[feed] = res
	if res.Status == repository.JVNDBFeedStatusSuccess || res.Status == repository.JVNDBFeedStatusNotModified {
		st.ETag, st.LastModified, st.SourceURL = res.ETag, res.LastModified, res.SourceURL
		now := time.Now()
		st.LastSuccessAt = &now
		st.Completed = st.Completed || res.Completed
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

func (f *fakeJVNDBStore) ResetBackfill(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets++
	for k, v := range f.states {
		if strings.HasPrefix(k, "year:") {
			v.Completed = false
			v.ETag, v.LastModified = "", ""
		}
	}
	return nil
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

func TestJVNDBSync_GapResetsBackfill(t *testing.T) {
	doc := readJVNDBFixture(t) // oldest modified 2026-11-18T08:24Z
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(doc) }))
	defer srv.Close()
	store := newFakeJVNDBStore()
	lastOK := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) // long before the feed's window
	store.states["recent"] = &repository.JVNDBFeedState{Feed: "recent", LastStatus: "success", LastSuccessAt: &lastOK}
	store.states["year:2026"] = &repository.JVNDBFeedState{Feed: "year:2026", LastStatus: "success", Completed: true, LastSuccessAt: &lastOK}
	svc := NewJVNDBRSSService(store, srv.URL, false, time.Hour, 2026)
	res, err := svc.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Feeds[0].Gap || store.resets != 1 || !store.finished["recent"].GapDetected {
		t.Fatalf("gap not detected/handled: feeds=%+v resets=%d", res.Feeds, store.resets)
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
	if err := jvndbCheckRedirect(mk("https://a/x"), []*http.Request{mk("https://a/1"), mk("https://a/2"), mk("https://a/3")}); err == nil {
		t.Error("a 4th redirect must be refused")
	}
	if err := jvndbCheckRedirect(mk("https://b/x"), []*http.Request{mk("https://a/1")}); err != nil {
		t.Errorf("one https redirect must be followed: %v", err)
	}
}
