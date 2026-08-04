// Package middleware — M51: `Authorization: Bearer ...` was parsed by two
// different rules in the same server.
//
// # The finding
//
// multiauth.go and apikey.go read the header through bearerAny +
// pickSingleCredential: the auth-scheme is matched case-insensitively (RFC 9110
// §11.1 makes it case-insensitive), more than one delimiting space is allowed,
// and a repeated Authorization header carrying two DIFFERENT credentials is
// refused rather than resolved by position. auth.go read the same header with
//
//	token := strings.TrimPrefix(authHeader, "Bearer ")
//	if token == authHeader { 401 }
//
// over `Header.Get`, which is case-sensitive, insists on exactly one space, and
// silently takes the FIRST of a repeated header.
//
// Measured on a throwaway stack (2026-08-04, api built from a85a0fb,
// SBOMHUB_AUTH_MODE=clerk), one API key, the two windows side by side:
//
//	credential                       Auth() GET /api/v1/me       MultiAuth GET .../sbom
//	Authorization: Bearer sbh_<k>    401 invalid token            200
//	Authorization: bearer sbh_<k>    401 invalid header format    200
//	Authorization: Bearer  sbh_<k>   401 invalid token            200
//	Authorization: bearer  sbh_<k>   401 invalid header format    200
//	[Authorization: ,                401 missing authorization    200
//	 Authorization: Bearer sbh_<k>]
//	[Authorization: Bearer <jwt>,    401 invalid token            401 invalid API key
//	 Authorization: Bearer sbh_<k>]
//
// The rows differ in what the two windows CONCLUDE about one header, which is
// the thing anti-pattern 107 is about: one credential, two rules, and the
// weaker rule decides on whichever route the caller picks. Here the split is
// fail-CLOSED rather than fail-open — a lowercased scheme is refused, not
// admitted — but the last two rows show it running in both directions: auth.go
// admits a duplicate-header request that MultiAuth refuses, and ignores a
// credential that MultiAuth honours.
//
// # What this file pins
//
// Not "auth.go now lowercases too". The two windows must not be able to
// disagree at all, so they consult ONE function — bearerFromRequest — and these
// tests assert the CLASSIFICATION each window reaches for a table of header
// shapes is the classification that function produces.
//
// Scan unit: every dimension of the header a caller controls —
// scheme case, delimiter (single space / multiple spaces / HTAB / none), token
// emptiness, a non-Bearer scheme, header repetition (identical, conflicting,
// empty-then-real, bearer-then-non-bearer), and header absence. Not covered
// here because Go's HTTP server strips it before any handler runs: trailing
// whitespace inside the field value.
package middleware

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/sbomhub/sbomhub/internal/config"
)

// bearerClass is what a window concluded about the header.
type bearerClass string

const (
	// classAbsent — no credential was presented at all.
	classAbsent bearerClass = "absent"
	// classMalformed — something was presented that is not a single usable
	// Bearer credential (wrong scheme, no delimiter, empty token, or two
	// conflicting values). Every window must REFUSE these; none may pick one.
	classMalformed bearerClass = "malformed"
	// classParsed — exactly one Bearer credential, extracted. Whether it then
	// validates is each window's own business; what must agree is that the
	// request got this far carrying THIS token.
	classParsed bearerClass = "parsed"
)

// bearerParityCase is one header shape and the classification every window owes
// it.
type bearerParityCase struct {
	name string
	// values is what the request carries under Authorization, in order. An
	// empty slice means the header is absent.
	values []string
	want   bearerClass
	// wantToken is the credential the request presents, for classParsed.
	wantToken string
	// wantIsAPIKey records, INDEPENDENTLY of any production function, whether
	// wantToken is an SBOMHub API key rather than a Clerk session token. It is
	// stated in the table on purpose: deciding it with looksLikeAPIKey would
	// make TestBearerParityWindowsAgreeOrDivergeExactlyOnce move with the bug it
	// exists to catch — measured, that version stayed green under a negative
	// control that reverted the case-insensitive prefix.
	wantIsAPIKey bool
	// why records what the shape is, so a failure reads as a statement about
	// HTTP rather than about this table.
	why string
}

// bearerParityCases is the closed table both windows are measured against.
//
// The token values are deliberately NOT `sbh_`-shaped except where the case is
// about the API-key branch: classification happens before any prefix test, and
// mixing the two would let a prefix bug pass as a parse bug.
func bearerParityCases() []bearerParityCase {
	const tok = "eyJhbGciOiJIUzI1NiJ9.e30.not-a-real-signature"
	const key = "sbh_ffffffffffffffffffffffffffffffff"
	return []bearerParityCase{
		{
			name: "absent", values: nil, want: classAbsent,
			why: "no Authorization header at all",
		},
		{
			name: "empty value", values: []string{""}, want: classAbsent,
			why: "a shell expanding an unset variable into -H 'Authorization: '",
		},
		{
			name: "canonical", values: []string{"Bearer " + tok},
			want: classParsed, wantToken: tok,
			why: "the spelling every client in this repo emits",
		},
		{
			name: "lowercase scheme", values: []string{"bearer " + tok},
			want: classParsed, wantToken: tok,
			why: "RFC 9110 §11.1: auth-scheme is case-insensitive",
		},
		{
			name: "uppercase scheme", values: []string{"BEARER " + tok},
			want: classParsed, wantToken: tok,
			why: "same rule, the other extreme",
		},
		{
			name: "mixed-case scheme", values: []string{"BeArEr " + tok},
			want: classParsed, wantToken: tok,
			why: "case-insensitive means every mixture, not two blessed spellings",
		},
		{
			name: "two delimiting spaces", values: []string{"Bearer  " + tok},
			want: classParsed, wantToken: tok,
			why: "RFC 9110 credentials = auth-scheme 1*SP token68",
		},
		{
			name: "lowercase + two spaces", values: []string{"bearer  " + key},
			want: classParsed, wantToken: key, wantIsAPIKey: true,
			why: "both relaxations at once, on an API-key-shaped credential",
		},
		{
			name: "scheme only", values: []string{"Bearer"},
			want: classMalformed,
			why:  "no delimiter, so `Bearer` is a token68-less scheme name",
		},
		{
			name: "scheme + delimiter, no token", values: []string{"Bearer "},
			want: classMalformed,
			why: "announcing a credential and supplying none must end the request, " +
				"not fall through to a default identity",
		},
		{
			name: "HTAB delimiter", values: []string{"Bearer\t" + tok},
			want: classMalformed,
			why: "the grammar says 1*SP; admitting HTAB authenticates a syntax " +
				"the Clerk SDK's own parser reads differently",
		},
		{
			name: "scheme is a prefix of a longer token", values: []string{"BearerX " + tok},
			want: classMalformed,
			why:  "`BearerX` is one scheme name, not Bearer",
		},
		{
			name: "different scheme", values: []string{"Basic YWJjOmRlZg=="},
			want: classMalformed,
			why:  "a credential this product does not accept",
		},
		{
			name:   "repeated, identical",
			values: []string{"Bearer " + tok, "Bearer " + tok},
			want:   classParsed, wantToken: tok,
			why: "one credential sent twice says nothing conflicting",
		},
		{
			name:   "repeated, conflicting",
			values: []string{"Bearer " + tok, "Bearer " + key},
			want:   classMalformed,
			why: "answering with either is a guess; `take the first` is the rule " +
				"that produced the M50 fall-through",
		},
		{
			name:   "empty first, real second",
			values: []string{"", "Bearer " + key},
			want:   classParsed, wantToken: key, wantIsAPIKey: true,
			why: "Header.Get returns only the first value, so this shape used to " +
				"look like no credential at all",
		},
		{
			name:   "non-bearer first, bearer second",
			values: []string{"Basic YWJjOmRlZg==", "Bearer " + tok},
			want:   classParsed, wantToken: tok,
			why: "only one Bearer candidate, so there is nothing to be ambiguous about",
		},
	}
}

// classify is the single rule, applied to the request. Every window's
// classification is compared against this.
func classify(t *testing.T, tc bearerParityCase) bearerClass {
	t.Helper()
	r := bearerParityRequest(tc.values)
	token, present, ambiguous := bearerFromRequest(r)
	switch {
	case ambiguous:
		return classMalformed
	case !present:
		if bearerParityHeaderAbsent(r) {
			return classAbsent
		}
		return classMalformed
	case token == "":
		return classMalformed
	default:
		if token != tc.wantToken {
			t.Errorf("%s: shared parser extracted %q, the table says %q",
				tc.name, token, tc.wantToken)
		}
		return classParsed
	}
}

func bearerParityRequest(values []string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	for _, v := range values {
		r.Header.Add("Authorization", v)
	}
	return r
}

// bearerParityHeaderAbsent reports whether the request carries no usable
// Authorization value, which is the "absent" case as opposed to "present and
// unusable". An empty value counts as absent: it is what a shell produces from
// an unset variable, and APIKeyAuth has always treated it that way.
func bearerParityHeaderAbsent(r *http.Request) bool {
	for _, v := range r.Header.Values("Authorization") {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

// TestBearerParityTableIsSelfConsistent guards the table itself: a case whose
// declared class disagrees with the shared parser would make every window test
// below assert the wrong thing.
func TestBearerParityTableIsSelfConsistent(t *testing.T) {
	for _, tc := range bearerParityCases() {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(t, tc); got != tc.want {
				t.Fatalf("shared parser classifies %q as %q, the table says %q (%s)",
					tc.values, got, tc.want, tc.why)
			}
		})
	}
}

// TestBearerParityAuthWindow drives the REAL Auth() middleware — the Clerk
// window, the one that had its own rule — and reads the classification back out
// of the 401 body it produces.
//
// The three bodies are distinguishable by construction:
//
//	{"error":"missing authorization header"}        -> absent
//	{"error":"invalid authorization header format"} -> malformed
//	{"error":"invalid token"}                       -> parsed, then failed to verify
//
// The third is what makes this a test of PARSING rather than of Clerk: reaching
// it means the middleware accepted the header's shape and handed the token on.
// No repository is touched on any of these paths, so the nil repos below are
// never dereferenced — a case that did reach them would panic, which is a
// louder failure than a wrong status.
func TestBearerParityAuthWindow(t *testing.T) {
	cfg := bearerParityClerkConfig(t)
	mw := Auth(cfg, nil, nil)

	for _, tc := range bearerParityCases() {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			reached := false
			h := mw(func(c echo.Context) error {
				reached = true
				return c.JSON(http.StatusOK, map[string]string{"reached": "handler"})
			})
			e.GET("/api/v1/me", h)

			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, bearerParityRequest(tc.values))
			if reached {
				t.Fatalf("the handler ran with an unverifiable token (status %d, body %s)",
					rec.Code, rec.Body.String())
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d body %s, want 401 for every case in this table",
					rec.Code, rec.Body.String())
			}
			got := bearerParityClassOfBody(t, rec.Body.String())
			if got != tc.want {
				t.Errorf("Auth() classifies %q as %q; the shared rule says %q (%s).\n"+
					"body: %s",
					tc.values, got, tc.want, tc.why, rec.Body.String())
			}
		})
	}
}

func bearerParityClassOfBody(t *testing.T, body string) bearerClass {
	t.Helper()
	switch {
	case strings.Contains(body, "missing authorization header"):
		return classAbsent
	case strings.Contains(body, "invalid authorization header format"):
		return classMalformed
	case strings.Contains(body, "invalid token"):
		return classParsed
	default:
		t.Fatalf("unrecognised 401 body %q — this test reads the classification "+
			"out of the body, so a new body needs a new arm here", body)
		return ""
	}
}

// TestBearerParityAPIKeyWindows drives the two API-key readers — MultiAuth's
// apiKeyCredential and APIKeyAuth's presentedAPIKey — over the same table.
//
// Their vocabulary differs from Auth()'s (they answer "is this an API-key
// attempt", not "is this a Bearer credential"), so the comparison is made where
// the two vocabularies coincide: for a token that IS `sbh_`-shaped, a shape the
// shared rule calls `parsed` must produce exactly that token here, and a shape
// it calls `malformed` must never produce a usable one.
func TestBearerParityAPIKeyWindows(t *testing.T) {
	for _, tc := range bearerParityCases() {
		t.Run(tc.name, func(t *testing.T) {
			r := bearerParityRequest(tc.values)

			multiRaw, multiPresented := apiKeyCredential(r)
			keyRaw, keyPresent, keyAmbiguous := presentedAPIKey(r)

			apiKeyShaped := strings.HasPrefix(tc.wantToken, apiKeyPrefix)
			switch {
			case tc.want == classParsed && apiKeyShaped:
				if !multiPresented || multiRaw != tc.wantToken {
					t.Errorf("MultiAuth: (%q, %v), want (%q, true) — the shared rule "+
						"parsed this shape (%s)", multiRaw, multiPresented, tc.wantToken, tc.why)
				}
				if keyAmbiguous || !keyPresent || keyRaw != tc.wantToken {
					t.Errorf("APIKeyAuth: (%q, present=%v, ambiguous=%v), want (%q, true, false)",
						keyRaw, keyPresent, keyAmbiguous, tc.wantToken)
				}
			case tc.want == classMalformed:
				// A malformed credential must never resolve to a usable key on
				// either window. It may be reported as presented-but-unusable
				// (which both windows answer 401 to) or, for a scheme this
				// product does not accept at all, as absent.
				if multiPresented && multiRaw != "" {
					t.Errorf("MultiAuth resolved malformed shape %q to the usable "+
						"credential %q (%s)", tc.values, multiRaw, tc.why)
				}
				if !keyAmbiguous && keyPresent && keyRaw != "" {
					t.Errorf("APIKeyAuth resolved malformed shape %q to the usable "+
						"credential %q (%s)", tc.values, keyRaw, tc.why)
				}
			case tc.want == classAbsent:
				if multiPresented {
					t.Errorf("MultiAuth reports a credential presented for %q", tc.values)
				}
				if keyPresent || keyAmbiguous {
					t.Errorf("APIKeyAuth reports a credential presented for %q", tc.values)
				}
			}
		})
	}
}

// TestBearerParityClerkRequestIsCanonicalised is the half that makes the
// relaxation real rather than cosmetic.
//
// The Clerk SDK (clerk-sdk-go/v2@v2.0.0, http/middleware.go:61) does its OWN
//
//	token := strings.TrimPrefix(authorization, "Bearer ")
//
// on the request we hand it. Teaching auth.go to accept `bearer <jwt>` while
// still passing the raw header through would therefore change the 401 body and
// nothing else: the SDK would strip nothing, decode `bearer <jwt>` as a JWT,
// fail, and answer 401 anyway. The credential set would still differ from the
// API-key window's — just less visibly.
//
// So the token is re-emitted in canonical form for the SDK, and the ORIGINAL
// request is left untouched (handlers and audit read it after us).
func TestBearerParityClerkRequestIsCanonicalised(t *testing.T) {
	const tok = "eyJhbGciOiJIUzI1NiJ9.e30.sig"
	for _, values := range [][]string{
		{"bearer " + tok},
		{"BEARER  " + tok},
		{"Bearer " + tok, "Bearer " + tok},
	} {
		r := bearerParityRequest(values)
		token, present, ambiguous := bearerFromRequest(r)
		if ambiguous || !present {
			t.Fatalf("%q: the shared parser refused a shape this test assumes it accepts", values)
		}
		got := clerkAuthorizationRequest(r, token)
		if diff := got.Header.Values("Authorization"); len(diff) != 1 || diff[0] != "Bearer "+tok {
			t.Errorf("%q: canonicalised header %q, want exactly [%q]",
				values, diff, "Bearer "+tok)
		}
		if orig := r.Header.Values("Authorization"); len(orig) != len(values) {
			t.Errorf("%q: the ORIGINAL request was mutated to %q", values, orig)
		}
	}
}

// bearerRuleViolations reports every place in one parsed file that applies its
// OWN Bearer prefix rule instead of calling the shared parser.
//
// It is a function rather than an inline loop so the sweep can be driven
// against a synthetic source as an anti-vacuity control — Codex round 3 (Low)
// added a forbidden reader to auth.go and watched the previous version of this
// test stay green, because that version only looked at string LITERALS and the
// reader it added spelled the prefix as the `BearerPrefix` constant.
//
// Two argument shapes therefore count: a string literal containing "bearer" in
// any casing, and an identifier ending in "BearerPrefix" (the package constant,
// qualified or not).
func bearerRuleViolations(fset *token.FileSet, file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "TrimPrefix", "HasPrefix", "TrimLeft", "CutPrefix", "EqualFold", "Cut", "Index", "Split":
		default:
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
			return true
		}
		for _, arg := range call.Args {
			var what string
			switch a := arg.(type) {
			case *ast.BasicLit:
				if a.Kind == token.STRING && strings.Contains(strings.ToLower(a.Value), "bearer") {
					what = a.Value
				}
			case *ast.Ident:
				if strings.HasSuffix(a.Name, "BearerPrefix") {
					what = a.Name
				}
			case *ast.SelectorExpr:
				if strings.HasSuffix(a.Sel.Name, "BearerPrefix") {
					what = a.Sel.Name
				}
			}
			if what == "" {
				continue
			}
			out = append(out, fmt.Sprintf("%s: strings.%s(..., %s)",
				fset.Position(arg.Pos()), sel.Sel.Name, what))
		}
		return true
	})
	return out
}

// TestBearerParityOneRuleInTheSource is the structural half: the behavioural
// tests above pass just as well if a fourth reader is added tomorrow with its
// own rule.
//
// Stripping a `Bearer` prefix off a header value is the exact shape of the
// defect, so no non-test file in this package may do it outside bearerAny.
//
// The sweep is over the AST, not the text: the doc comments in auth.go and
// multiauth.go quote the removed line verbatim (that is how the finding is
// recorded), and a substring search would report those quotations as the defect
// while missing a real call spelled across two lines.
func TestBearerParityOneRuleInTheSource(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if name == "multiauth.go" {
			continue // bearerAny lives here; it IS the rule
		}
		for _, v := range bearerRuleViolations(fset, file) {
			t.Errorf("%s applies its own Bearer rule. Use bearerFromRequest so the "+
				"windows cannot disagree.", v)
		}
	}
	if scanned == 0 {
		t.Fatal("swept no source files — the sweep would pass vacuously")
	}
}

// TestBearerRuleSweepRejectsASecondParser is the anti-vacuity control for the
// sweep, and it exists because the sweep failed one.
//
// Codex round 3 (Low) added `strings.TrimPrefix(v, BearerPrefix)` to auth.go and
// TestBearerParityOneRuleInTheSource stayed green: it inspected string literals
// only, and a constant is not a literal. A structural test that cannot be shown
// to reject the thing it forbids is a comment with a test's name on it.
//
// Each source below is a second parser spelled a different way. All must be
// rejected; the last one must NOT be, because it is the legitimate call every
// window makes.
func TestBearerRuleSweepRejectsASecondParser(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		wantFlag bool
	}{
		{"literal prefix", `func f(v string) string { return strings.TrimPrefix(v, "Bearer ") }`, true},
		{"lowercase literal", `func f(v string) string { return strings.TrimPrefix(v, "bearer ") }`, true},
		{"the package constant", `func f(v string) string { return strings.TrimPrefix(v, BearerPrefix) }`, true},
		{"a qualified constant", `func f(v string) string { return strings.TrimPrefix(v, mw.BearerPrefix) }`, true},
		{"HasPrefix test", `func f(v string) bool { return strings.HasPrefix(v, BearerPrefix) }`, true},
		{"CutPrefix", `func f(v string) (string, bool) { return strings.CutPrefix(v, "Bearer ") }`, true},
		{"the shared parser", `func f(r *http.Request) (string, bool, bool) { return bearerFromRequest(r) }`, false},
		{"an unrelated strings call", `func f(v string) string { return strings.TrimPrefix(v, "sbh_") }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			src := "package middleware\n\nimport \"strings\"\n\n" + tc.body + "\n"
			file, err := parser.ParseFile(fset, "synthetic.go", src, 0)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			got := bearerRuleViolations(fset, file)
			if tc.wantFlag && len(got) == 0 {
				t.Errorf("the sweep does NOT reject a second Bearer parser:\n\t%s", tc.body)
			}
			if !tc.wantFlag && len(got) != 0 {
				t.Errorf("the sweep rejects legitimate code %q: %v", tc.body, got)
			}
		})
	}
}

// bearerParityClerkConfig builds the config Auth() sees in a Clerk deployment,
// which is the only mode where its Authorization parsing runs at all: the
// self-hosted branch provisions a default identity without reading the header.
//
// Going through config.Load() rather than &config.Config{} is load-bearing —
// `mode` is unexported and a zero value resolves to SaaS for the wrong reason.
func bearerParityClerkConfig(t *testing.T) *config.Config {
	t.Helper()
	t.Setenv("CLERK_SECRET_KEY", "sk_test_bearer_parity_unit_test_key")
	cfg := config.Load()
	if cfg.IsSelfHosted() {
		t.Fatalf("expected a SaaS config, got mode %q", cfg.Mode())
	}
	return cfg
}

// apiKeyPrefixSpellings is every casing of `sbh_` a caller can send. The prefix
// is 4 ASCII characters, so 16 spellings; the table is generated rather than
// written out so a future longer prefix stays covered.
func apiKeyPrefixSpellings() []string {
	out := []string{""}
	for _, ch := range apiKeyPrefix {
		lo, hi := strings.ToLower(string(ch)), strings.ToUpper(string(ch))
		var next []string
		for _, p := range out {
			next = append(next, p+lo)
			if hi != lo {
				next = append(next, p+hi)
			}
		}
		out = next
	}
	return out
}

// TestAPIKeyPrefixRuleIsCaseInsensitive is the second half of the parity
// contract, and the one that carried real consequence.
//
// The Bearer SCHEME being case-insensitive is only half the header. The other
// half is the `sbh_` prefix that decides whether a Bearer value is an API-key
// attempt or a Clerk session token — and that test was
// `strings.HasPrefix(v, "sbh_")` in two files. Uppercasing those four
// characters made MultiAuth stop seeing a credential at all, so in
// SBOMHUB_AUTH_MODE=anonymous the request fell through to the self-hosted
// handler and ran as the DEFAULT tenant's Owner with api_keys.project_id
// discarded. Measured on a throwaway stack (2026-08-04) with a PROJECT-SCOPED
// key against a project in another tenant:
//
//	Authorization: Bearer sbh_<scoped key>   403 forbidden
//	Authorization: Bearer SBH_<same key>     200 + the project's SBOM
//	X-API-Key:            SBH_<same key>     401 invalid API key
//
// i.e. M50 W3's fall-through (docs/UPGRADE.md §7.1) reachable again by changing
// the case of a prefix, with the two channels disagreeing about one string.
func TestAPIKeyPrefixRuleIsCaseInsensitive(t *testing.T) {
	const bodyHex = "ffffffffffffffffffffffffffffffff"
	spellings := apiKeyPrefixSpellings()
	// One spelling per subset of the CASED characters in the prefix ("sbh_" has
	// three, so eight). Computed rather than hard-coded so the guard survives a
	// change to the prefix, and asserted so a generator that silently produced
	// only the canonical spelling cannot make this test vacuous.
	want := 1
	for _, ch := range apiKeyPrefix {
		if strings.ToLower(string(ch)) != strings.ToUpper(string(ch)) {
			want *= 2
		}
	}
	if len(spellings) != want {
		t.Fatalf("generated %d prefix spellings for %q, want %d",
			len(spellings), apiKeyPrefix, want)
	}
	if want < 2 {
		t.Fatalf("prefix %q has no cased characters — this test would be vacuous", apiKeyPrefix)
	}
	for _, prefix := range spellings {
		v := prefix + bodyHex
		t.Run(prefix, func(t *testing.T) {
			r := bearerParityRequest([]string{"Bearer " + v})

			multiRaw, multiPresented := apiKeyCredential(r)
			if !multiPresented {
				t.Errorf("MultiAuth does not see an API-key attempt in %q. It therefore "+
					"falls through to the Clerk / self-hosted path, and in anonymous mode "+
					"that serves the request as the DEFAULT tenant's Owner with the key — "+
					"and its project scope — discarded.", v)
			} else if multiRaw != v {
				t.Errorf("MultiAuth extracted %q, want the credential verbatim %q", multiRaw, v)
			}

			keyRaw, keyPresent, keyAmbiguous := presentedAPIKey(r)
			if keyAmbiguous || !keyPresent {
				t.Errorf("APIKeyAuth: present=%v ambiguous=%v for %q, want a presented credential",
					keyPresent, keyAmbiguous, v)
			} else if keyRaw != v {
				t.Errorf("APIKeyAuth extracted %q, want %q", keyRaw, v)
			}
		})
	}
}

// TestAPIKeyPrefixRuleDoesNotSwallowClerkTokens is the anti-vacuity control for
// the test above: a rule that answered "yes, an API key" to everything would
// pass it, and would route every web-UI session into the API-key table.
func TestAPIKeyPrefixRuleDoesNotSwallowClerkTokens(t *testing.T) {
	for _, v := range []string{
		// A Clerk JWT: the compact serialisation of {"alg":...} in base64url.
		"eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJzdWIiOiJ1c2VyXzEifQ.sig",
		"sbh", "sb", "s", "sbh-ffff", "xsbh_ffff", "SBH", "",
	} {
		if looksLikeAPIKey(v) {
			t.Errorf("looksLikeAPIKey(%q) = true; only a value beginning with %q in some "+
				"casing is an API-key attempt", v, apiKeyPrefix)
		}
	}
	// And the positive control, so a rule that answered "no" to everything is
	// caught too.
	for _, v := range []string{"sbh_x", "SBH_x", "Sbh_", "sBh_ffff"} {
		if !looksLikeAPIKey(v) {
			t.Errorf("looksLikeAPIKey(%q) = false, want true", v)
		}
	}
}

// TestBearerParityWindowsAgreeOrDivergeExactlyOnce closes the hole that let the
// prefix defect through review.
//
// TestBearerParityAPIKeyWindows checks each window against the shared rule
// SEPARATELY, so a shape both windows get wrong in DIFFERENT ways can satisfy it
// — which is what "`SBH_` is absent here and presented-unusable there" was. This
// asserts the two windows against EACH OTHER, and pins the single place they are
// allowed to differ.
//
// The permitted divergence, and why it exists: a non-empty Bearer value that is
// not API-key-shaped is a Clerk session token. MultiAuth has a Clerk path and
// must hand it on, so it reports "no API-key credential". APIKeyAuth's route
// groups have no Clerk path, so the same value is an API-key attempt it cannot
// use, and it reports "presented, unusable" — a 401 either way on its own
// routes. Any OTHER disagreement is the M51 bug class.
func TestBearerParityWindowsAgreeOrDivergeExactlyOnce(t *testing.T) {
	cases := bearerParityCases()
	for _, prefix := range apiKeyPrefixSpellings() {
		cases = append(cases, bearerParityCase{
			name:         "prefix spelling " + prefix,
			values:       []string{"Bearer " + prefix + "ffffffffffffffffffffffffffffffff"},
			want:         classParsed,
			wantToken:    prefix + "ffffffffffffffffffffffffffffffff",
			wantIsAPIKey: true,
			why:          "every casing of the API-key prefix is the same credential",
		})
	}

	divergences := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bearerParityRequest(tc.values)
			multiRaw, multiPresented := apiKeyCredential(r)
			keyRaw, keyPresent, keyAmbiguous := presentedAPIKey(r)

			// Stated by the table, never derived from the code under test.
			clerkCandidate := tc.want == classParsed && tc.wantToken != "" && !tc.wantIsAPIKey

			if clerkCandidate {
				divergences++
				// The one permitted disagreement, pinned exactly so it cannot
				// widen into "and also for these other shapes".
				if multiPresented {
					t.Errorf("MultiAuth claims an API-key credential in the Clerk token %q — "+
						"every web-UI session would be looked up in the API-key table", tc.wantToken)
				}
				if !keyPresent || keyRaw != "" || keyAmbiguous {
					t.Errorf("APIKeyAuth: (%q, present=%v, ambiguous=%v) for a Clerk token; "+
						"want presented-but-unusable (\"\", true, false) so its routes answer 401",
						keyRaw, keyPresent, keyAmbiguous)
				}
				return
			}

			if multiPresented != keyPresent {
				t.Errorf("the two windows disagree about %q: MultiAuth presented=%v, "+
					"APIKeyAuth present=%v. One request, two conclusions — and in "+
					"anonymous mode the window that says `absent` serves it as the "+
					"DEFAULT tenant's Owner. (%s)",
					tc.values, multiPresented, keyPresent, tc.why)
			}
			if multiPresented && keyPresent && multiRaw != keyRaw {
				t.Errorf("the two windows extract DIFFERENT credentials from %q: "+
					"MultiAuth %q, APIKeyAuth %q", tc.values, multiRaw, keyRaw)
			}
		})
	}
	if divergences == 0 {
		t.Error("no case in this table exercised the permitted Clerk-token divergence, " +
			"so the pin above is vacuous")
	}
}

// TestBearerAnnouncedButUnusableIsRefusedEverywhere is the third parity
// dimension, after the scheme's case and the key prefix's case: the DELIMITER
// and the credential's own character set.
//
// # The finding (M51 round 2)
//
// `bearerAny` reported "not a candidate" for anything after the scheme that was
// not `1*SP ...`, and its TrimLeft stripped SPACE only. So a tab made a
// perfectly recognisable credential look like the ABSENCE of one, and on a
// MultiAuth route in `anonymous` self-host absence means the DEFAULT tenant's
// Owner. Measured on a throwaway stack (2026-08-04) with a PROJECT-SCOPED key,
// against a project belonging to another tenant:
//
//	Authorization: Bearer<SP>sbh_<scoped>          403 forbidden
//	Authorization: Bearer<SP><HTAB>sbh_<scoped>    200 + that project's SBOM
//	Authorization: Bearer<HTAB>sbh_<scoped>        200 + that project's SBOM
//
// One tab, and api_keys.project_id is gone — the same fall-through the prefix
// casing produced (TestAPIKeyPrefixRuleIsCaseInsensitive), reached through the
// delimiter instead. `Bearer<SP><HTAB>...` additionally disagreed BETWEEN the
// windows: APIKeyAuth answered 401 while MultiAuth served it.
//
// # Why the earlier tests did not catch it
//
// TestBearerParityAPIKeyWindows' malformed branch asks only that no USABLE
// credential was produced, and `presented=false` satisfies that. The
// cross-window test compares the two windows to each other, and for
// `Bearer<HTAB>x` they agreed — both said absent. Agreeing on the fail-open
// answer is not the property that was wanted.
//
// So this asserts the fail-CLOSED contract directly: a header that ANNOUNCES
// Bearer and does not carry a usable credential must be presented-but-unusable
// at both windows, which is a 401 rather than a fall-through.
func TestBearerAnnouncedButUnusableIsRefusedEverywhere(t *testing.T) {
	const key = "sbh_ffffffffffffffffffffffffffffffff"
	for _, tc := range []struct{ name, value, why string }{
		{"SP then HTAB", "Bearer \t" + key,
			"TrimLeft stripped SPACE only, so the credential kept a leading tab"},
		{"HTAB delimiter", "Bearer\t" + key,
			"an auth-scheme is an HTTP token, so it ends at the tab: this announces Bearer"},
		{"bare scheme", "Bearer",
			"announced and supplied nothing"},
		{"two spaces then HTAB", "Bearer  \t" + key,
			"the relaxed multi-space delimiter must not smuggle a tab in behind it"},
		{"inner space in the token", "Bearer " + key + " x",
			"token68 admits no whitespace; this used to be forwarded verbatim"},
		{"control character in the token", "Bearer " + key + "\x01",
			"a credential is not a place for control characters"},
		{"non-ASCII in the token", "Bearer " + key + "é",
			"token68 is ASCII"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := bearerParityRequest([]string{tc.value})

			multiRaw, multiPresented := apiKeyCredential(r)
			if !multiPresented {
				t.Errorf("MultiAuth reports NO credential for %q (%s). It therefore falls "+
					"through to the Clerk / self-hosted path, and in anonymous mode that "+
					"serves the request as the DEFAULT tenant's Owner with the key — and "+
					"its project scope — discarded.", tc.value, tc.why)
			} else if multiRaw != "" {
				t.Errorf("MultiAuth resolved %q to the usable credential %q", tc.value, multiRaw)
			}

			keyRaw, keyPresent, keyAmbiguous := presentedAPIKey(r)
			if keyAmbiguous || !keyPresent || keyRaw != "" {
				t.Errorf("APIKeyAuth: (%q, present=%v, ambiguous=%v) for %q; want "+
					"presented-but-unusable (\"\", true, false)",
					keyRaw, keyPresent, keyAmbiguous, tc.value)
			}
		})
	}
}

// TestBearerSchemeAnnouncementIsBoundedByTheTokenGrammar is the anti-vacuity
// control for the test above: a rule that called EVERY Authorization value an
// announcement would satisfy it, and would then refuse credentials belonging to
// other schemes instead of leaving them alone.
func TestBearerSchemeAnnouncementIsBoundedByTheTokenGrammar(t *testing.T) {
	for _, v := range []string{
		"Basic YWJjOmRlZg==",                   // a different scheme
		"BearerX sbh_ffff",                     // a longer scheme NAME
		"Bearer-Token sbh_ffff",                // ditto: '-' is a tchar
		"",                                     // nothing
		"sbh_ffffffffffffffffffffffffffffffff", // a raw key, no scheme
	} {
		if _, ok := bearerAny(v); ok {
			t.Errorf("bearerAny(%q) reports a Bearer announcement; only the Bearer "+
				"auth-scheme is one, and refusing other schemes here would break "+
				"any future authenticator this product adds", v)
		}
	}
	// Positive control: the shapes that ARE announcements carrying a usable
	// credential must still come through verbatim.
	for _, tc := range []struct{ in, want string }{
		{"Bearer sbh_ffff", "sbh_ffff"},
		{"bearer   sbh_ffff", "sbh_ffff"},
		{"BEARER eyJhbGciOiJIUzI1NiJ9.e30.sig", "eyJhbGciOiJIUzI1NiJ9.e30.sig"},
		{"Bearer YWJjZGVm==", "YWJjZGVm=="},
	} {
		got, ok := bearerAny(tc.in)
		if !ok || got != tc.want {
			t.Errorf("bearerAny(%q) = (%q, %v), want (%q, true)", tc.in, got, ok, tc.want)
		}
	}
}
