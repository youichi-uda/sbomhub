package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// cannedJVNFeed is a minimal but structurally faithful MyJVN getVulnOverviewList
// RSS/RDF response: one <channel> plus one <item> carrying a CVE reference and a
// CVSS v3.1 base score, matching the JVNRSSFeed / JVNItem parse structs.
const cannedJVNFeed = `<?xml version="1.0" encoding="UTF-8"?>
<RDF>
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
	vulns, err := svc.searchByKeyword(context.Background(), "libfoo")
	if err != nil {
		t.Fatalf("searchByKeyword returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	v := vulns[0]
	if v.CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", v.CVEID)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected HIGH severity, got %s", v.Severity)
	}
	if v.CVSSScore != 7.5 {
		t.Errorf("expected CVSS 7.5, got %f", v.CVSSScore)
	}
	if v.Source != "JVN" {
		t.Errorf("expected source JVN, got %s", v.Source)
	}
}

func TestJVNService_ParseJVNResponse(t *testing.T) {
	svc := NewJVNService(nil, nil, "", false)
	vulns, err := svc.parseJVNResponse([]byte(cannedJVNFeed))
	if err != nil {
		t.Fatalf("parseJVNResponse returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if vulns[0].CVEID != "CVE-2023-1234" {
		t.Errorf("expected CVE-2023-1234, got %s", vulns[0].CVEID)
	}
}

// TestJVNService_Offline_NoHTTP asserts offline mode short-circuits searchByKeyword
// and GetVulnerabilitiesByJVNID to empty results with no network hit.
func TestJVNService_Offline_NoHTTP(t *testing.T) {
	hit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewJVNService(nil, nil, server.URL, true)

	vulns, err := svc.searchByKeyword(context.Background(), "libfoo")
	if err != nil {
		t.Fatalf("offline searchByKeyword should not error, got %v", err)
	}
	if len(vulns) != 0 {
		t.Errorf("offline searchByKeyword should return empty, got %d", len(vulns))
	}

	vuln, err := svc.GetVulnerabilitiesByJVNID(context.Background(), "JVNDB-2023-000001")
	if err != nil {
		t.Fatalf("offline GetVulnerabilitiesByJVNID should not error, got %v", err)
	}
	if vuln != nil {
		t.Errorf("offline GetVulnerabilitiesByJVNID should return nil, got %v", vuln)
	}

	if hit {
		t.Error("offline mode must not make any HTTP request")
	}
}
