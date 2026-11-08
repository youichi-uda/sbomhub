package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

// blockingReader serves its prefix, then blocks forever (a chunked body that
// is never finished). Reads past the prefix are counted.
type blockingReader struct {
	prefix  io.Reader
	blocked chan struct{}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if n, err := r.prefix.Read(p); n > 0 || err != io.EOF {
		return n, err
	}
	select {
	case r.blocked <- struct{}{}:
	default:
	}
	select {} // never returns
}

func bindWithin(t *testing.T, method, target, ctype string, body io.Reader) (error, bool) {
	t.Helper()
	e := newProjectTestEcho()
	req := httptest.NewRequest(method, target, body)
	req.ContentLength = -1
	req.Header.Set(echo.HeaderContentType, ctype)
	c := e.NewContext(req, httptest.NewRecorder())
	done := make(chan error, 1)
	go func() {
		var v struct {
			Name string `json:"name"`
			N    int    `query:"n"`
		}
		done <- c.Bind(&v)
	}()
	select {
	case err := <-done:
		return err, true
	case <-time.After(2 * time.Second):
		return nil, false
	}
}

// Codex R5 (Medium): the guard read the whole body for any Content-Type that
// merely started with application/json, before path/query binding. A
// never-finished chunked body then pinned the handler (and its tenant
// transaction) where echo would have answered at once.
func TestTextGuard_DoesNotReadBodiesEchoWouldNotDecode(t *testing.T) {
	t.Run("json-patch media type is 415 without reading", func(t *testing.T) {
		br := &blockingReader{prefix: strings.NewReader(""), blocked: make(chan struct{}, 1)}
		err, ok := bindWithin(t, http.MethodPost, "/x", "application/json-patch+json", br)
		if !ok {
			t.Fatal("Bind blocked reading a body echo does not decode")
		}
		if he, isHE := err.(*echo.HTTPError); !isHE || he.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("err = %v, want 415", err)
		}
	})
	t.Run("query binding fails before the body is read", func(t *testing.T) {
		br := &blockingReader{prefix: strings.NewReader(""), blocked: make(chan struct{}, 1)}
		err, ok := bindWithin(t, http.MethodDelete, "/x?n=notanint", echo.MIMEApplicationJSON, br)
		if !ok {
			t.Fatal("Bind blocked on the body before failing query binding")
		}
		if he, isHE := err.(*echo.HTTPError); !isHE || he.Code != http.StatusBadRequest {
			t.Fatalf("err = %v, want 400", err)
		}
	})
	t.Run("a complete JSON value then a never-ending body still binds", func(t *testing.T) {
		br := &blockingReader{prefix: strings.NewReader(`{"name":"ok"}`), blocked: make(chan struct{}, 1)}
		err, ok := bindWithin(t, http.MethodPost, "/x", echo.MIMEApplicationJSON, br)
		if !ok {
			t.Fatal("Bind waited for the end of the body after a complete JSON value (echo's decoder does not)")
		}
		if err != nil {
			t.Fatalf("err = %v", err)
		}
	})
}
