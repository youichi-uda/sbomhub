package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Package-level OSV query (M70): every OSV record for one (ecosystem, package),
// all pages. The distro step of a scan (service/distro_scan.go) uses it to read
// a distro's own fixed versions.
//
// Measured 2026-11-09 against the live api.osv.dev (no key, no rate limit
// published — the API documentation says "there are no limits on the API"):
//
//	Debian "openssl"            390 records,   799 KB, 1.9 s, one page
//	Debian "glibc"              189 records,   390 KB, 1.2 s, one page
//	Debian "linux"            3,000 records, 7.1 MB, 6.9 s, FIRST page of several
//	Debian "linux-signed-amd64"   0 records (`{}`), 0.35 s
//	Ubuntu:22.04:LTS "openssl"  100 records,   1.7 MB, 1.8 s
//	AlmaLinux:9 "openssl"        17 records,    60 KB, 0.5 s
//
// OSV pages a package query when it has more than 1,000 records or runs for
// more than 20 s; a page may even carry only a next_page_token. Every page is
// read; a walk that hits maxPages is an ERROR (ErrOSVQueryTruncated), not a
// short answer, because an unread page could hold the record that says the
// installed version is affected.

// maxOSVQueryPageBytes bounds one page. The largest measured page (Debian
// linux, 3,000 records) is 7.1 MB; OSV's own HTTP/1.1 response cap is 32 MiB.
const maxOSVQueryPageBytes = 32 << 20

// ErrOSVOffline is returned by QueryPackage in offline mode. Unlike
// GetVulnerability's (nil, nil), a package query never answers "no records"
// when it did not ask: an empty answer would read as "the distro has no data".
var ErrOSVOffline = errors.New("osv: offline mode, no query made")

// ErrOSVQueryTruncated: the walk hit its page budget with a next_page_token
// still pending.
var ErrOSVQueryTruncated = errors.New("osv: package query has more pages than the page budget")

// OSVPackageRecord is the part of an OSV record the distro step reads.
type OSVPackageRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Modified string   `json:"modified"`
	// Withdrawn is set (an RFC 3339 time) when the record was retracted.
	Withdrawn string        `json:"withdrawn"`
	Affected  []OSVAffected `json:"affected"`
}

// OSVPackageQueryResult is the whole answer of one package query.
type OSVPackageQueryResult struct {
	Records []OSVPackageRecord
	// Pages is how many HTTP requests the walk made (failed ones included).
	Pages int
}

type osvPackageQueryRequest struct {
	Package   OSVPackage `json:"package"`
	PageToken string     `json:"page_token,omitempty"`
}

type osvPackageQueryResponse struct {
	Vulns         []OSVPackageRecord `json:"vulns"`
	NextPageToken string             `json:"next_page_token"`
}

// PackageQueryLimits bound one package query.
type PackageQueryLimits struct {
	// MaxPages is the most requests the walk may make.
	MaxPages int
	// MaxTotalBytes bounds the response bytes of the whole walk (every page
	// together), so a package with a huge history cannot hold an unbounded
	// amount of memory (Codex M70 R2 High-3). 0 means maxOSVQueryPageBytes.
	MaxTotalBytes int64
}

// QueryPackage returns every OSV record for (ecosystem, name), following
// next_page_token for at most maxPages requests. before is called before every
// request (the caller's pacing); an error from it ends the walk with that
// error. Any HTTP status other than 200, an undecodable or oversized body, or a
// walk longer than maxPages is an error: there is no partial answer.
func (c *OSVClient) QueryPackage(ctx context.Context, ecosystem, name string, maxPages int, before func(context.Context) error) (OSVPackageQueryResult, error) {
	var out OSVPackageQueryResult
	pages, err := c.QueryPackageEach(ctx, ecosystem, name, PackageQueryLimits{MaxPages: maxPages, MaxTotalBytes: int64(maxPages) * maxOSVQueryPageBytes},
		before, func(recs []OSVPackageRecord) error {
			out.Records = append(out.Records, recs...)
			return nil
		})
	out.Pages = pages
	return out, err
}

// QueryPackageEach is QueryPackage that hands each page's records to onPage
// as it arrives (so the caller can reduce them at once) instead of holding the
// whole answer. An error from onPage ends the walk with it. pages counts the
// requests made, failed ones included. The walk is an error — never a short
// answer — when it would exceed lim.
func (c *OSVClient) QueryPackageEach(ctx context.Context, ecosystem, name string, lim PackageQueryLimits,
	before func(context.Context) error, onPage func([]OSVPackageRecord) error) (pages int, err error) {
	if c.offline {
		return 0, ErrOSVOffline
	}
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" {
		return 0, fmt.Errorf("osv: package query needs an ecosystem and a name")
	}
	if lim.MaxPages < 1 {
		lim.MaxPages = 1
	}
	if lim.MaxTotalBytes <= 0 {
		lim.MaxTotalBytes = maxOSVQueryPageBytes
	}
	token := ""
	seen := map[string]bool{}
	var spent int64
	for {
		if pages >= lim.MaxPages {
			return pages, fmt.Errorf("%w (%d pages, %s %q)", ErrOSVQueryTruncated, lim.MaxPages, ecosystem, name)
		}
		if before != nil {
			if err := before(ctx); err != nil {
				return pages, err
			}
		}
		pages++
		remaining := lim.MaxTotalBytes - spent
		page, n, err := c.queryPackagePage(ctx, osvPackageQueryRequest{
			Package:   OSVPackage{Name: name, Ecosystem: ecosystem},
			PageToken: token,
		}, remaining)
		spent += n
		if err != nil {
			return pages, err
		}
		if err := onPage(page.Vulns); err != nil {
			return pages, err
		}
		if page.NextPageToken == "" {
			return pages, nil
		}
		if seen[page.NextPageToken] {
			// A server handing back a token it already gave would loop until
			// the budget; say what it is instead.
			return pages, fmt.Errorf("osv: package query for %s %q repeated a page token", ecosystem, name)
		}
		seen[page.NextPageToken] = true
		token = page.NextPageToken
	}
}

// queryPackagePage fetches one page, reading at most min(budget, one page's
// cap) bytes; n is the bytes read.
func (c *OSVClient) queryPackagePage(ctx context.Context, q osvPackageQueryRequest, budget int64) (page osvPackageQueryResponse, n int64, err error) {
	limit := int64(maxOSVQueryPageBytes)
	if budget < limit {
		limit = budget
	}
	if limit <= 0 {
		return page, 0, fmt.Errorf("%w: byte budget spent", ErrOSVQueryTruncated)
	}
	body, err := json.Marshal(q)
	if err != nil {
		return page, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/query", bytes.NewReader(body))
	if err != nil {
		return page, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return page, 0, fmt.Errorf("osv: package query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return page, 0, fmt.Errorf("osv: package query returned status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	n = int64(len(raw))
	if err != nil {
		return page, n, fmt.Errorf("osv: read package query response: %w", err)
	}
	if n > limit {
		return page, n, fmt.Errorf("%w: response exceeds the remaining %d-byte budget", ErrOSVQueryTruncated, limit)
	}
	// The body must be a JSON object: `{}` (no records) or {"vulns": [...]}.
	// Anything else — an HTML error page from a proxy, `null`, an array — is
	// not an answer.
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return page, n, fmt.Errorf("osv: package query response is not a JSON object")
	}
	if err := json.Unmarshal(trimmed, &page); err != nil {
		return page, n, fmt.Errorf("osv: decode package query response: %w", err)
	}
	for i, r := range page.Vulns {
		if strings.TrimSpace(r.ID) == "" {
			return osvPackageQueryResponse{}, n, fmt.Errorf("osv: package query record %d has no id", i)
		}
	}
	return page, n, nil
}
