package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GHSAClient is a client for the GitHub Security Advisory Database (Global Advisories)
// REST API.
//
// Reference: https://docs.github.com/en/rest/security-advisories/global-advisories
// API version: 2026-03-10 (latest stable as of 2026-06).
// Confirmed via web search on 2026-06-24 — endpoint `https://api.github.com/advisories`
// + `GET /advisories/{ghsa_id}`. Public read does not require authentication, but
// passing a token raises rate limit from 60/h to 5000/h.
type GHSAClient struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

const (
	ghsaAPIBase       = "https://api.github.com"
	ghsaAPIVersion    = "2026-03-10"
	ghsaUserAgent     = "sbomhub-advisory-fetch/1.0"
	ghsaDefaultLimit  = 30
	ghsaDefaultMaxAge = 30 * time.Second
)

// NewGHSAClient creates a new GHSA client. token may be empty for unauthenticated
// access (subject to GitHub's 60 req/h public rate limit). When a token is supplied
// it should be a fine-grained PAT with no special permissions or a classic PAT —
// global advisories do not require any specific scope.
func NewGHSAClient(token string) *GHSAClient {
	return &GHSAClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: ghsaAPIBase,
		token:   token,
	}
}

// WithBaseURL overrides the base URL — primarily used by tests to point the client
// at an httptest.Server. Returns the receiver for chaining.
func (c *GHSAClient) WithBaseURL(base string) *GHSAClient {
	c.baseURL = strings.TrimRight(base, "/")
	return c
}

// WithHTTPClient overrides the underlying http.Client — primarily used by tests
// for custom transports. Returns the receiver for chaining.
func (c *GHSAClient) WithHTTPClient(hc *http.Client) *GHSAClient {
	if hc != nil {
		c.httpClient = hc
	}
	return c
}

// GHSAAdvisory is a partial mapping of the GHSA global advisory schema, capturing
// only the fields the advisory parser needs. The full schema includes many more
// fields (credits, withdrawn_at, etc.) which we intentionally ignore for now.
type GHSAAdvisory struct {
	GHSAID          string              `json:"ghsa_id"`
	CVEID           string              `json:"cve_id"`
	URL             string              `json:"url"`
	HTMLURL         string              `json:"html_url"`
	Summary         string              `json:"summary"`
	Description     string              `json:"description"`
	Severity        string              `json:"severity"`
	Identifiers     []GHSAIdentifier    `json:"identifiers"`
	References      []string            `json:"references"`
	PublishedAt     string              `json:"published_at"`
	UpdatedAt       string              `json:"updated_at"`
	WithdrawnAt     string              `json:"withdrawn_at"`
	Vulnerabilities []GHSAVulnerability `json:"vulnerabilities"`
	CWEs            []GHSACWE           `json:"cwes"`
	CVSS            *GHSACVSS           `json:"cvss"`
	// VulnerableFunctions is a flat array of fully-qualified symbol names known
	// to be vulnerable. Present on a subset of advisories (Go ecosystem in
	// particular populates this from the GO-* CVE feed). ※要確認:
	// schema currently documents this at advisory top level; if GitHub later
	// nests it inside vulnerabilities[], the parser will simply see no values.
	VulnerableFunctions []string `json:"vulnerable_functions"`
}

// GHSAIdentifier is one of the alternate identifiers attached to an advisory.
type GHSAIdentifier struct {
	Type  string `json:"type"` // "CVE" or "GHSA"
	Value string `json:"value"`
}

// GHSAVulnerability is one affected package entry.
type GHSAVulnerability struct {
	Package                GHSAPackage `json:"package"`
	VulnerableVersionRange string      `json:"vulnerable_version_range"`
	FirstPatchedVersion    string      `json:"first_patched_version"`
	VulnerableFunctions    []string    `json:"vulnerable_functions"`
}

// GHSAPackage identifies the affected package in a specific ecosystem.
type GHSAPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// GHSACWE is a CWE classification attached to an advisory.
type GHSACWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

// GHSACVSS captures the CVSS score, if present.
type GHSACVSS struct {
	VectorString string  `json:"vector_string"`
	Score        float64 `json:"score"`
}

// GetByGHSAID fetches a single global advisory by its GHSA identifier.
// Returns nil, nil when the advisory does not exist (HTTP 404).
func (c *GHSAClient) GetByGHSAID(ctx context.Context, ghsaID string) (*GHSAAdvisory, error) {
	if ghsaID == "" {
		return nil, fmt.Errorf("ghsa: empty advisory id")
	}

	endpoint := fmt.Sprintf("%s/advisories/%s", c.baseURL, url.PathEscape(ghsaID))
	body, status, err := c.doGET(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("ghsa: get %s returned status %d: %s", ghsaID, status, truncate(string(body), 200))
	}

	var adv GHSAAdvisory
	if err := json.Unmarshal(body, &adv); err != nil {
		return nil, fmt.Errorf("ghsa: decode advisory %s: %w", ghsaID, err)
	}
	return &adv, nil
}

// GetByCVEID fetches global advisories matching the given CVE. The GHSA database
// can technically reference one CVE from multiple advisories (e.g. duplicates or
// disputed entries), so the API returns a list. Callers usually want the first
// non-withdrawn entry.
func (c *GHSAClient) GetByCVEID(ctx context.Context, cveID string) ([]GHSAAdvisory, error) {
	if cveID == "" {
		return nil, fmt.Errorf("ghsa: empty cve id")
	}

	q := url.Values{}
	q.Set("cve_id", cveID)
	q.Set("per_page", fmt.Sprintf("%d", ghsaDefaultLimit))
	return c.listAdvisories(ctx, q)
}

// ListByEcosystem lists advisories filtered by ecosystem (e.g. "go", "npm").
// limit caps the number of records returned (single page); pagination is not yet
// implemented because the MVP triage runner queries by CVE or GHSA ID directly.
// ※要確認: pagination via Link header should be added once the bulk ingester ships.
func (c *GHSAClient) ListByEcosystem(ctx context.Context, ecosystem string, limit int) ([]GHSAAdvisory, error) {
	if ecosystem == "" {
		return nil, fmt.Errorf("ghsa: empty ecosystem")
	}
	if limit <= 0 || limit > 100 {
		limit = ghsaDefaultLimit
	}
	q := url.Values{}
	q.Set("ecosystem", ecosystem)
	q.Set("per_page", fmt.Sprintf("%d", limit))
	return c.listAdvisories(ctx, q)
}

func (c *GHSAClient) listAdvisories(ctx context.Context, q url.Values) ([]GHSAAdvisory, error) {
	endpoint := fmt.Sprintf("%s/advisories?%s", c.baseURL, q.Encode())
	body, status, err := c.doGET(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("ghsa: list advisories returned status %d: %s", status, truncate(string(body), 200))
	}
	var advs []GHSAAdvisory
	if err := json.Unmarshal(body, &advs); err != nil {
		return nil, fmt.Errorf("ghsa: decode advisory list: %w", err)
	}
	return advs, nil
}

func (c *GHSAClient) doGET(ctx context.Context, endpoint string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("ghsa: build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", ghsaAPIVersion)
	req.Header.Set("User-Agent", ghsaUserAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ghsa: do request: %w", err)
	}
	defer resp.Body.Close()

	// F300 (M20-3): bound the response body read at maxErrorBodyBytes so a
	// hostile or misconfigured upstream that streams a multi-GB body under
	// the 30s client-side timeout cannot exhaust process memory. Every GHSA
	// advisory response fits comfortably under 64 KiB — the same bound also
	// caps 403 rate-limit bodies inspected via strings.Contains below and 4xx
	// / 5xx error bodies used in the "ghsa: get ... returned status" and
	// "ghsa: list advisories returned status" diagnostics. This mirrors the
	// jira.go / backlog.go hygiene apply and completes anti-pattern 48
	// universal closure across the three external HTTP clients that share
	// the rate_limit.go helper.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("ghsa: read response: %w", err)
	}

	// Surface rate-limit hits with a recognisable error so callers can backoff.
	if resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(body)), "rate limit") {
		return body, resp.StatusCode, fmt.Errorf("ghsa: rate limited (set GITHUB_TOKEN to raise the cap)")
	}
	return body, resp.StatusCode, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
