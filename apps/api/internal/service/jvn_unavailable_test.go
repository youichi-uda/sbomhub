package service

// MyJVN unavailability (2026-11).
//
// Measured on 2026-11-13: every MyJVN API URL answers HTTP 404 ("Not Found",
// 9 bytes, Server: BigIP), and JPCERT/CC's notice of 2026-10-22
// (https://jvn.jp/nav/info2026102281.html) says JVN iPedia and MyJVN are
// suspended for system maintenance with no resumption date
// (「再開時期は未定です」). Until now that outage surfaced only as the generic
// "jvn: scan failed (fetch_failed)", indistinguishable from a component whose
// answer failed validation, and the sweep kept sending one request per
// component (2/s) to a service that was not there.
//
// These tests pin:
//   - a lookup that got no HTTP 200 answer at all (404, 5xx, 429, a transport
//     error) is classified as the SERVICE being unavailable, and only that: a
//     200 whose body fails validation is not, and neither is a 400;
//   - a sweep in which MyJVN is unavailable says so with its own reason code,
//     source_unavailable, IN ADDITION to fetch_failed (which callers already
//     key on), so the verdict — failed — is unchanged;
//   - the sweep stops asking after jvnUnavailableAbandonAfter consecutive
//     unavailable answers instead of issuing one request per component.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestJVNOutage_FetchPage_ClassifiesUnavailability(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		unavailable bool
	}{
		{"404 as measured on 2026-11-13", http.StatusNotFound, "Not Found", true},
		{"410 gone", http.StatusGone, "", true},
		{"403 blocked", http.StatusForbidden, "", true},
		{"429 rate limited", http.StatusTooManyRequests, "", true},
		{"500", http.StatusInternalServerError, "", true},
		{"502", http.StatusBadGateway, "", true},
		{"503 maintenance", http.StatusServiceUnavailable, "", true},
		{"504", http.StatusGatewayTimeout, "", true},
		{"400 is our request, not their outage", http.StatusBadRequest, "", false},
		{"200 with a body that is not MyJVN", http.StatusOK, "<html>maintenance</html>", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			svc := NewJVNService(nil, nil, srv.URL, false)
			_, err := svc.fetchPage(context.Background(), "openssl", 1)
			if err == nil {
				t.Fatal("fetchPage accepted a response that is not a MyJVN answer")
			}
			if got := isJVNUnavailable(err); got != tc.unavailable {
				t.Errorf("isJVNUnavailable(%v) = %t, want %t", err, got, tc.unavailable)
			}
		})
	}
}

func TestJVNOutage_FetchPage_TransportErrorIsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens there any more: connection refused
	svc := NewJVNService(nil, nil, url, false)
	_, err := svc.fetchPage(context.Background(), "openssl", 1)
	if err == nil || !isJVNUnavailable(err) {
		t.Fatalf("connection refused: err = %v, want an unavailability error", err)
	}
}

// A cancelled request is the sweep being cut off, not MyJVN being down: it
// must stay a context error so ScanComponentsReport counts it as Cancelled.
func TestJVNOutage_FetchPage_CancellationIsNotUnavailability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	svc := NewJVNService(nil, nil, srv.URL, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := svc.fetchPage(ctx, "openssl", 1)
	if err == nil {
		t.Fatal("a cancelled request returned no error")
	}
	if isJVNUnavailable(err) {
		t.Errorf("a cancelled request was classified as MyJVN unavailability: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}

func TestJVNOutage_Report_SourceUnavailableIsItsOwnReason(t *testing.T) {
	rep := JVNScanReport{Components: 10, Failed: 3, UnavailableFailures: 3, AbandonedUnavailable: 7,
		SourceUnavailable: true}
	err := rep.Err()
	want := []string{ScanReasonFetchFailed, ScanReasonSourceUnavailable}
	if got := ScanReasons(err); !slices.Equal(got, want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
	if !strings.Contains(err.Error(), "10 of 10") {
		t.Errorf("message %q does not say that all 10 components went unchecked", err)
	}
	if got := ScanFailureMarker("jvn", ScanReasons(err)); got != "jvn: scan failed (fetch_failed, source_unavailable)" {
		t.Errorf("marker = %q", got)
	}
}

// An ordinary partial failure keeps exactly the reasons it had.
func TestJVNOutage_Report_OrdinaryFailureIsNotSourceUnavailable(t *testing.T) {
	err := JVNScanReport{Components: 5, Scanned: 4, Failed: 1}.Err()
	if got := ScanReasons(err); !slices.Equal(got, []string{ScanReasonFetchFailed}) {
		t.Errorf("reasons = %v, want [fetch_failed]", got)
	}
}

// Components the sweep stopped asking about are missing coverage exactly like
// failed ones: the report must not read as complete on their account.
func TestJVNOutage_Report_AbandonedComponentsAreNotCoverage(t *testing.T) {
	err := JVNScanReport{Components: 6, Scanned: 2, Failed: 3, UnavailableFailures: 3,
		AbandonedUnavailable: 1, SourceUnavailable: true}.Err()
	if !errors.Is(err, ErrScanFetchFailed) || !errors.Is(err, ErrScanSourceUnavailable) {
		t.Fatalf("err = %v, want fetch_failed + source_unavailable", err)
	}
	if !strings.Contains(err.Error(), "4 of 6") {
		t.Errorf("message %q does not count the 3 failed + 1 abandoned components", err)
	}
}

func TestJVNOutage_ScanReasons_SourceUnavailableOrder(t *testing.T) {
	err := errors.Join(ErrScanSourceUnavailable, ErrScanDeadlineExceeded, ErrScanFetchFailed)
	want := []string{ScanReasonDeadlineExceeded, ScanReasonFetchFailed, ScanReasonSourceUnavailable}
	if got := ScanReasons(err); !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v", got, want)
	}
}
