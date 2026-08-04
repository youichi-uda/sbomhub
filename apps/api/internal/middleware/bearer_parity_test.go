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
			want: classParsed, wantToken: key,
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
			want:   classParsed, wantToken: key,
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

// TestBearerParityOneRuleInTheSource is the structural half: the behavioural
// tests above pass just as well if a fourth reader is added tomorrow with its
// own literal.
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
	scanned, checked := 0, 0
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
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "TrimPrefix" && sel.Sel.Name != "HasPrefix" &&
				sel.Sel.Name != "EqualFold" && sel.Sel.Name != "Cut" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "strings" {
				return true
			}
			checked++
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if !strings.Contains(strings.ToLower(lit.Value), "bearer") {
					continue
				}
				if name == "multiauth.go" {
					continue // bearerAny lives here; it IS the rule
				}
				t.Errorf("%s:%d applies its own Bearer rule (%s(..., %s)). "+
					"Use bearerFromRequest so the windows cannot disagree.",
					name, fset.Position(lit.Pos()).Line, sel.Sel.Name, lit.Value)
			}
			return true
		})
	}
	if scanned == 0 || checked == 0 {
		t.Fatalf("swept %d files and inspected %d strings.* prefix calls — "+
			"the sweep would pass vacuously", scanned, checked)
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
