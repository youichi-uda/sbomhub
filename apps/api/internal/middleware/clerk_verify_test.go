package middleware

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clerk/clerk-sdk-go/v2"
	"github.com/labstack/echo/v4"
)

// TestVerifyClerkJWT_Contract pins the token-acceptance contract of
// verifyClerkJWT independently of the Clerk SDK version, so an SDK bump that
// loosens verification (accepting an expired, forged, wrongly-issued or
// algorithm-confused token) fails here. Tokens are signed with the stdlib so
// the test does not depend on the SDK's own JOSE library; the JWKS is served
// from a fake Clerk backend.
//
// Not parallel: it swaps the process-global Clerk backend.
func TestVerifyClerkJWT_Contract(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// kid is unique per run: the SDK caches JWKs process-wide by kid.
	kid := "ins_contract_" + time.Now().Format("150405.000000000")

	b64 := base64.RawURLEncoding.EncodeToString
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64(key.N.Bytes()),
		"e": b64(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer srv.Close()

	prev := clerk.GetBackend()
	t.Cleanup(func() { clerk.SetBackend(prev) })
	clerk.SetBackend(clerk.NewBackend(&clerk.BackendConfig{
		HTTPClient: srv.Client(),
		URL:        clerk.String(srv.URL),
		Key:        clerk.String("sk_test_contract"),
	}))

	now := time.Now()
	baseClaims := func() map[string]any {
		return map[string]any{
			"iss":      "https://clerk.example.test",
			"sub":      "user_123",
			"sid":      "sess_123",
			"iat":      now.Add(-time.Minute).Unix(),
			"nbf":      now.Add(-time.Minute).Unix(),
			"exp":      now.Add(5 * time.Minute).Unix(),
			"org_id":   "org_abc",
			"org_role": "org:admin",
		}
	}
	sign := func(alg string, header map[string]any, claims map[string]any, signer func([]byte) []byte) string {
		h := map[string]any{"alg": alg, "typ": "JWT", "kid": kid}
		for k, v := range header {
			h[k] = v
		}
		hj, _ := json.Marshal(h)
		cj, _ := json.Marshal(claims)
		input := b64(hj) + "." + b64(cj)
		return input + "." + b64(signer([]byte(input)))
	}
	rs256 := func(k *rsa.PrivateKey) func([]byte) []byte {
		return func(in []byte) []byte {
			sum := sha256.Sum256(in)
			sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
	}

	verify := func(token string) (*ClerkClaims, error) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		c := echo.New().NewContext(req, httptest.NewRecorder())
		return verifyClerkJWT(c, token)
	}

	t.Run("valid token is accepted with claims mapped", func(t *testing.T) {
		got, err := verify(sign("RS256", nil, baseClaims(), rs256(key)))
		if err != nil {
			t.Fatalf("valid token rejected: %v", err)
		}
		if got.UserID != "user_123" || got.OrgID != "org_abc" || got.OrgRole != "org:admin" {
			t.Fatalf("unexpected claims: %+v", got)
		}
	})

	reject := map[string]string{}
	expired := baseClaims()
	expired["exp"] = now.Add(-10 * time.Minute).Unix()
	expired["iat"] = now.Add(-20 * time.Minute).Unix()
	expired["nbf"] = now.Add(-20 * time.Minute).Unix()
	reject["expired"] = sign("RS256", nil, expired, rs256(key))

	notYet := baseClaims()
	notYet["nbf"] = now.Add(10 * time.Minute).Unix()
	reject["not yet valid"] = sign("RS256", nil, notYet, rs256(key))

	badIss := baseClaims()
	badIss["iss"] = "https://evil.example.test"
	reject["foreign issuer"] = sign("RS256", nil, badIss, rs256(key))

	reject["signed by another key"] = sign("RS256", nil, baseClaims(), rs256(otherKey))

	// Algorithm confusion: HS256 keyed with the public modulus bytes.
	reject["HS256 alg confusion"] = sign("HS256", nil, baseClaims(), func(in []byte) []byte {
		m := hmac.New(sha256.New, key.N.Bytes())
		m.Write(in)
		return m.Sum(nil)
	})

	reject["alg none"] = sign("none", nil, baseClaims(), func([]byte) []byte { return nil })

	reject["unknown kid"] = sign("RS256", map[string]any{"kid": "ins_unknown"}, baseClaims(), rs256(key))

	tampered := sign("RS256", nil, baseClaims(), rs256(key))
	{
		escalated := baseClaims()
		escalated["sub"] = "user_admin"
		cj, _ := json.Marshal(escalated)
		parts := strings.Split(tampered, ".")
		tampered = parts[0] + "." + b64(cj) + "." + parts[2]
	}
	reject["tampered payload"] = tampered

	reject["empty"] = ""
	reject["garbage"] = "not.a.jwt"

	for name, tok := range reject {
		t.Run("rejects "+name, func(t *testing.T) {
			got, err := verify(tok)
			if err == nil {
				t.Fatalf("token accepted, claims %+v", got)
			}
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusUnauthorized {
				t.Fatalf("want 401 *echo.HTTPError, got %T %v", err, err)
			}
		})
	}
}
