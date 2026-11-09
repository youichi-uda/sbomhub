package service

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// replayOSV serves the recorded OSV package answers (testdata/m70/osv) for
// POST /query, keyed by "<ecosystem>|<name>", and records every request.
// An unrecorded package gets OSV's real answer for a package it has nothing
// for (`{}`, measured for Debian "linux-signed-amd64").
type replayOSV struct {
	t      *testing.T
	routes map[string]string // "<ecosystem>|<name>" -> fixture name
	fail   map[string]int    // same keys -> HTTP status
	mu     sync.Mutex
	seen   []string
}

func (r *replayOSV) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/query" {
			http.Error(w, "unexpected "+req.Method+" "+req.URL.Path, http.StatusNotFound)
			return
		}
		var q struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			PageToken string `json:"page_token"`
		}
		if err := json.NewDecoder(req.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := q.Package.Ecosystem + "|" + q.Package.Name
		r.mu.Lock()
		r.seen = append(r.seen, key)
		r.mu.Unlock()
		if code, ok := r.fail[key]; ok {
			http.Error(w, "boom", code)
			return
		}
		name, ok := r.routes[key]
		if !ok {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		f, err := os.Open(filepath.Join("testdata", "m70", "osv", name+".json.gz"))
		if err != nil {
			r.t.Errorf("fixture %s: %v", name, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		zr, err := gzip.NewReader(f)
		if err != nil {
			r.t.Errorf("gunzip %s: %v", name, err)
			return
		}
		_, _ = io.Copy(w, zr)
	}))
	r.t.Cleanup(srv.Close)
	return srv
}

func (r *replayOSV) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}
