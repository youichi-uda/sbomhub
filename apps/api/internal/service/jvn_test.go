package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// cannedJVNFeed is a minimal but structurally faithful MyJVN getVulnOverviewList
// RSS/RDF response: one <channel> plus one <item> carrying a CVE reference and a
// CVSS v3.1 base score, matching the JVNRSSFeed / JVNItem parse structs.
// cannedJVNFeed models a real MyJVN getVulnOverviewList response.
//
// The <status:Status> element is REQUIRED here as of M54 (Codex R10,
// Critical): MyJVN sends it on both success and error responses, so its
// absence means the body is not a MyJVN answer at all, and parseJVNResponse
// now rejects that rather than reading it as "no vulnerabilities". This
// fixture omitted it, which is why it needed updating — a fixture that does
// not carry what the real contract carries stops the test from exercising the
// contract.
const cannedJVNFeed = `<?xml version="1.0" encoding="UTF-8"?>
<RDF>
  <Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd="" errMsg="" totalRes="1" totalResRet="1" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
  <channel>
    <title>JVNDB Vulnerability Overview</title>
    <description>test feed</description>
  </channel>
  <item>
    <title>libfoo における脆弱性</title>
    <link>https://jvndb.jvn.jp/ja/contents/2023/JVNDB-2023-000001.html</link>
    <description>libfoo に境界外書き込みの脆弱性が存在します。</description>
    <identifier>JVNDB-2023-000001</identifier>
    <references source="CVE" id="CVE-2023-1234">CVE-2023-1234</references>
    <cpe version="2.2" vendor="foo" product="libfoo">cpe:/a:foo:libfoo</cpe>
    <cvss version="3.1" type="Base" severity="High" score="7.5" vector="CVSS:3.1/AV:N/AC:L"/>
    <issued>2023-01-15T10:30:00+09:00</issued>
    <modified>2023-06-20T15:45:00+09:00</modified>
  </item>
</RDF>`

func TestNewJVNService_DefaultBaseURL(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	if svc.baseURL != jvnAPIBaseURL {
		t.Errorf("expected default baseURL %q, got %q", jvnAPIBaseURL, svc.baseURL)
	}
	if svc.offline {
		t.Error("expected offline false by default")
	}
	if svc.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

func TestJVNService_SearchByKeyword_HTTPMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The injected base URL should carry the MyJVN method + keyword params.
		if got := r.URL.Query().Get("method"); got != "getVulnOverviewList" {
			t.Errorf("expected method getVulnOverviewList, got %q", got)
		}
		if got := r.URL.Query().Get("keyword"); got != "libfoo" {
			t.Errorf("expected keyword libfoo, got %q", got)
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(cannedJVNFeed))
	}))
	defer server.Close()

	svc := NewJVNService(nil, nil, server.URL, false)
	svc.requestDelay = 0
	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("searchKeyword returned error: %v", err)
	}
	if len(res.Vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulns))
	}
	v := res.Vulns[0]
	if v.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", v.CVEID)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", v.Severity)
	}
	if v.CVSSScore == nil || *v.CVSSScore != 7.5 {
		t.Errorf("expected CVSS 7.5, got %v", v.CVSSScore)
	}
	if v.Source != "JVN" {
		t.Errorf("expected source JVN, got %s", v.Source)
	}
}

func TestJVNService_ParseJVNResponse(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	page, err := svc.parseJVNPage([]byte(cannedJVNFeed), jvnTestPageReq())
	if err != nil {
		t.Fatalf("parseJVNPage returned error: %v", err)
	}
	if len(page.vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(page.vulns))
	}
	if page.vulns[0].CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", page.vulns[0].CVEID)
	}
}

// TestJVNService_Offline_NoHTTP asserts offline mode short-circuits the
// keyword search to empty results with no network hit.
//
// M55: the GetVulnerabilitiesByJVNID half of this test went with the method
// itself — see the note in jvn.go for why it was removed rather than fixed.
func TestJVNService_Offline_NoHTTP(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewJVNService(nil, nil, server.URL, true)
	svc.requestDelay = 0

	res, err := svc.searchKeyword(context.Background(), "libfoo", nil)
	if err != nil {
		t.Fatalf("offline searchKeyword should not error, got %v", err)
	}
	if len(res.Vulns) != 0 {
		t.Errorf("offline searchKeyword should return empty, got %d", len(res.Vulns))
	}
	if res.Requests != 0 {
		t.Errorf("offline searchKeyword issued %d requests", res.Requests)
	}
	if res.Truncated {
		t.Error("offline mode must not report truncation; it reports nothing looked at")
	}

	if hit {
		t.Error("offline mode must not make any HTTP request")
	}
}

// TestM54JVN_ApplicationErrorIsNotZeroResults pins the MyJVN <status:Status>
// contract (Codex M54 R9, Critical).
//
// MyJVN reports application-level failures through retCd on that element,
// commonly WITH HTTP 200. The element was not modelled at all, so such a
// response unmarshalled into zero items, the component was counted as
// successfully checked, and even a total outage finished as a clean scan.
func TestM54JVN_ApplicationErrorIsNotZeroResults(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "retCd=1 application error",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
  <status:Status version="3.3" method="getVulnOverviewList" retCd="1" retMax="50" errCd="MYJVN-ERR-101" errMsg="parameter error" totalRes="0" totalResRet="0" firstRes="1"/>
</rdf:RDF>`,
			wantErr: true,
		},
		{
			name: "no status element at all",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/>`,
			wantErr: true,
		},
		{
			// M55: the paging attributes are the ones the live API
			// actually sends for a zero-match answer (measured:
			// totalRes="0" totalResRet="0" firstRes="1"). The earlier
			// fixture omitted totalResRet and wrote firstRes="0", i.e. it
			// did not carry what the real contract carries — the same
			// objection the M54 note above raises about the Status
			// element itself.
			name: "retCd=0 with no matches is a legitimate empty answer",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
  <status:Status version="3.3" method="getVulnOverviewList" lang="ja" retCd="0" retMax="50" errCd="" errMsg="" totalRes="0" totalResRet="0" firstRes="1" feed="hnd" keyword="libfoo" maxCountItem="50" startItem="1" rangeDatePublic="n" rangeDatePublished="n" rangeDateFirstPublished="n"/>
</rdf:RDF>`,
			wantErr: false,
		},
	}
	svc := NewJVNService(nil, nil, "", false)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.parseJVNPage([]byte(tc.body), jvnTestPageReq())
			if tc.wantErr && err == nil {
				t.Error("a MyJVN application error produced no error; the component would be " +
					"counted as successfully checked with zero findings")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("a legitimate empty answer must not error: %v", err)
			}
		})
	}
}

// TestM54JVN_ItemWithoutAnyIdentityIsDropped pins the identity requirement
// (Codex M54 R9, Critical). An item with neither a CVE reference nor an
// identifier used to become CVEID "" — a row the VARCHAR NOT NULL column
// accepts, that components then get linked to, and that every other such item
// collapses onto because cve_id is the ON CONFLICT key.
func TestM54JVN_ItemWithoutAnyIdentityIsDropped(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)

	if got := svc.convertJVNItemToVulnerability(JVNItem{Title: "no identity at all"}); got != nil {
		t.Errorf("an item with no CVE reference and no identifier produced %+v, want nil — "+
			"storing it creates an unidentifiable catalogue row", *got)
	}
	if got := svc.convertJVNItemToVulnerability(JVNItem{Identifier: "   "}); got != nil {
		t.Errorf("a whitespace-only identifier produced %+v, want nil", *got)
	}

	// A JVN advisory with no CVE is still legitimate and is keyed by its
	// JVNDB id.
	got := svc.convertJVNItemToVulnerability(JVNItem{Identifier: "JVNDB-2024-000123"})
	if got == nil {
		t.Fatal("an advisory identified only by its JVNDB id must be kept")
	}
	if got.CVEID != "JVNDB-2024-000123" {
		t.Errorf("CVEID = %q, want the JVNDB id", got.CVEID)
	}

	// A CVE reference is canonicalised, for the same uniqueness reason as NVD.
	got = svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2024-000124",
		References: []JVNRef{{ID: "cve-2021-44228", Source: "CVE"}},
	})
	if got == nil {
		t.Fatal("an advisory with a CVE reference must be kept")
	}
	if got.CVEID != "CVE-2021-44228" {
		t.Errorf("CVEID = %q, want the canonical upper-cased form", got.CVEID)
	}
}

// TestM54JVN_PublicationTimestampIsKept pins that JVN advisories carry their
// publication date (Codex M54 R10, Medium). JVNItem.Published was decoded and
// then never used, so every JVN row stored published_at = NULL and consumers
// could not display, sort or age those findings.
func TestM54JVN_PublicationTimestampIsKept(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	got := svc.convertJVNItemToVulnerability(JVNItem{
		Identifier: "JVNDB-2023-000001",
		Published:  "2023-01-15T10:30:00+09:00",
	})
	if got == nil {
		t.Fatal("item was dropped")
	}
	if got.PublishedAt == nil {
		t.Fatal("PublishedAt is nil; every JVN finding would store published_at = NULL")
	}
	want := time.Date(2023, 1, 15, 1, 30, 0, 0, time.UTC)
	if !got.PublishedAt.UTC().Equal(want) {
		t.Errorf("PublishedAt = %v, want %v", got.PublishedAt.UTC(), want)
	}
}
