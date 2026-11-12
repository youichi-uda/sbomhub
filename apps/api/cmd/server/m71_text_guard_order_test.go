package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	appmw "github.com/sbomhub/sbomhub/internal/middleware"
)

// Codex R2 (Low): TextGuardParams answers without calling next, so it must
// sit inside CORS. Outside it, an allowed cross-origin request refused for its
// query got no Access-Control-Allow-Origin, and the browser hid the 400 body
// behind a CORS error.
func TestM71TextGuardParamsRunsInsideCORS(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	cors := strings.Index(s, "e.Use(middleware.CORSWithConfig(")
	guard := strings.Index(s, "e.Use(appmw.TextGuardParams(")
	if cors < 0 || guard < 0 {
		t.Fatalf("could not find the e.Use lines (cors=%d guard=%d)", cors, guard)
	}
	if guard < cors {
		t.Fatal("appmw.TextGuardParams is installed before (outside) CORSWithConfig; its 400 would carry no CORS headers")
	}
}

// The behaviour the order buys, on the same two middleware.
func TestM71TextGuard400CarriesCORSHeaders(t *testing.T) {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{"http://localhost:3000"}}))
	e.Use(appmw.TextGuardParams())
	e.GET("/x", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/x?q=%00", nil)
	req.Header.Set(echo.HeaderOrigin, "http://localhost:3000")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get(echo.HeaderAccessControlAllowOrigin); got != "http://localhost:3000" {
		t.Fatalf("Access-Control-Allow-Origin = %q on the guard's 400", got)
	}
}

// The opaque share-link password names the two public routes by their full
// template; a route renamed without updating the exemption would silently
// refuse those passwords again.
func TestM71OpaquePasswordRoutesExist(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, want := range []string{
		`api.GET("/public/:token", publicLinkHandler.PublicGet`,
		`api.GET("/public/:token/download", publicLinkHandler.PublicDownload`,
		`api := e.Group("/api/v1")`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("main.go no longer contains %s", want)
		}
	}
	want := map[string]bool{"/api/v1/public/:token": true, "/api/v1/public/:token/download": true}
	if len(textGuardOpaqueParams()) != len(want) {
		t.Fatalf("textGuardOpaqueParams = %+v", textGuardOpaqueParams())
	}
	for _, o := range textGuardOpaqueParams() {
		if !want[o.Route] || o.Key != "password" {
			t.Errorf("unexpected opaque param %+v", o)
		}
	}
}
