package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func pagedOSV(t *testing.T, pages int, handler func(w http.ResponseWriter, page int, token string)) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		var q struct {
			Package struct {
				Name, Ecosystem string
			} `json:"package"`
			PageToken string `json:"page_token"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &q); err != nil || q.Package.Name != "openssl" || q.Package.Ecosystem != "Debian" {
			t.Errorf("request body %s", body)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		handler(w, int(n), q.PageToken)
	}))
	t.Cleanup(srv.Close)
	_ = pages
	return srv, &calls
}

func TestOSVQueryPackage_FollowsEveryPage(t *testing.T) {
	srv, calls := pagedOSV(t, 3, func(w http.ResponseWriter, page int, token string) {
		want := map[int]string{1: "", 2: "t1", 3: "t2"}[page]
		if token != want {
			t.Errorf("page %d token %q, want %q", page, token, want)
		}
		next := map[int]string{1: "t1", 2: "t2"}[page]
		// Page 2 is a token-only page (OSV documents these).
		vulns := `[{"id":"DSA-` + fmt.Sprint(page) + `","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Debian:11"}}]}]`
		if page == 2 {
			vulns = `[]`
		}
		fmt.Fprintf(w, `{"vulns":%s,"next_page_token":%q}`, vulns, next)
	})
	c := NewOSVClient().WithBaseURL(srv.URL + "/v1")
	paced := 0
	res, err := c.QueryPackage(context.Background(), "Debian", "openssl", 5, func(context.Context) error { paced++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Records[0].ID != "DSA-1" || res.Records[1].ID != "DSA-3" || res.Pages != 3 || *calls != 3 || paced != 3 {
		t.Errorf("records=%+v pages=%d calls=%d paced=%d", res.Records, res.Pages, *calls, paced)
	}
}

func TestOSVQueryPackage_EmptyObjectIsNoRecords(t *testing.T) {
	srv, _ := pagedOSV(t, 1, func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, `{}`) })
	res, err := NewOSVClient().WithBaseURL(srv.URL+"/v1").QueryPackage(context.Background(), "Debian", "openssl", 5, nil)
	if err != nil || len(res.Records) != 0 || res.Pages != 1 {
		t.Errorf("res=%+v err=%v", res, err)
	}
}

func TestOSVQueryPackage_NeverAShortAnswer(t *testing.T) {
	for _, c := range []struct {
		name    string
		handler func(w http.ResponseWriter, page int, token string)
		is      error
		pages   int
	}{
		{"budget exhausted", func(w http.ResponseWriter, page int, _ string) {
			fmt.Fprintf(w, `{"vulns":[{"id":"X-%d","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Debian:11"}}]}],"next_page_token":"t%d"}`, page, page)
		}, ErrOSVQueryTruncated, 2},
		{"repeated token", func(w http.ResponseWriter, _ int, _ string) {
			_, _ = io.WriteString(w, `{"vulns":[{"id":"X","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Debian:11"}}]}],"next_page_token":"same"}`)
		}, nil, 2},
		{"second page fails", func(w http.ResponseWriter, page int, _ string) {
			if page == 2 {
				http.Error(w, "boom", http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(w, `{"vulns":[{"id":"X","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"openssl","ecosystem":"Debian:11"}}]}],"next_page_token":"t"}`)
		}, nil, 2},
		{"rate limited", func(w http.ResponseWriter, _ int, _ string) { http.Error(w, "slow down", http.StatusTooManyRequests) }, nil, 1},
		{"html from a proxy", func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, "<html>gateway</html>") }, nil, 1},
		{"null body", func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, "null") }, nil, 1},
		{"empty body", func(w http.ResponseWriter, _ int, _ string) {}, nil, 1},
		{"truncated json", func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, `{"vulns":[{"id":"X"`) }, nil, 1},
		{"record without id", func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, `{"vulns":[{"id":""}]}`) }, nil, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := pagedOSV(t, 0, c.handler)
			res, err := NewOSVClient().WithBaseURL(srv.URL+"/v1").QueryPackage(context.Background(), "Debian", "openssl", 2, nil)
			if err == nil {
				t.Fatalf("no error; records=%+v", res.Records)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("error %v is not %v", err, c.is)
			}
			if res.Pages != c.pages {
				t.Errorf("pages = %d, want %d", res.Pages, c.pages)
			}
		})
	}
}

func TestOSVQueryPackage_OfflineMakesNoRequest(t *testing.T) {
	srv, calls := pagedOSV(t, 0, func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, `{}`) })
	_, err := NewOSVClient().WithBaseURL(srv.URL+"/v1").WithOffline(true).QueryPackage(context.Background(), "Debian", "openssl", 2, nil)
	if !errors.Is(err, ErrOSVOffline) || *calls != 0 {
		t.Errorf("err=%v calls=%d", err, *calls)
	}
}

func TestOSVQueryPackage_PacerErrorStopsTheWalk(t *testing.T) {
	srv, calls := pagedOSV(t, 0, func(w http.ResponseWriter, _ int, _ string) { _, _ = io.WriteString(w, `{}`) })
	stop := errors.New("deadline")
	_, err := NewOSVClient().WithBaseURL(srv.URL+"/v1").QueryPackage(context.Background(), "Debian", "openssl", 2,
		func(context.Context) error { return stop })
	if !errors.Is(err, stop) || *calls != 0 {
		t.Errorf("err=%v calls=%d", err, *calls)
	}
}

func TestOSVQueryPackage_RejectsEmptyArguments(t *testing.T) {
	for _, args := range [][2]string{{"", "openssl"}, {"Debian", " "}} {
		if _, err := NewOSVClient().QueryPackage(context.Background(), args[0], args[1], 1, nil); err == nil ||
			!strings.Contains(err.Error(), "needs") {
			t.Errorf("%q: err=%v", args, err)
		}
	}
}
