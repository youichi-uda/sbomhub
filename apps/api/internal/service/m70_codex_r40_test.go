package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sbomhub/sbomhub/internal/client"
)

// Codex M70 R40 High-1: a transport failure never prints the configured URL
// (it may carry a credential).
func TestM70R40_TransportErrorRedactsURL(t *testing.T) {
	c := client.NewOSVClient().WithBaseURL("http://127.0.0.1:1/v1?api_key=SECRET-TOKEN")
	_, err := c.QueryPackage(context.Background(), "Debian", "p", 5, nil)
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("query error %v", err)
	}
	_, err = c.GetRecordState(context.Background(), "DSA-1")
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("lookup error %v", err)
	}
	_, err = c.GetVulnerability(context.Background(), "DSA-1")
	if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Errorf("get error %v", err)
	}
}

// Codex M70 R40 Medium-2 / Medium-3.
func TestM70R40_SkippedRowsAndSecondQuestionMark(t *testing.T) {
	if err := (DistroScanReport{LockedSkipped: 1}).incompleteErr(); !errors.Is(err, ErrScanWriteRefused) {
		t.Errorf("skipped rows reported as %v", err)
	}
	if err := r32Query(t, "AlmaLinux:9", "pkg:rpm/almalinux/p?distro=el9&note=x?arch=aarch64"); err == nil {
		t.Error("affected purl with a second '?' accepted")
	}
	if _, ok := parsePurl("pkg:deb/debian/openssl@1.1.1k-1?distro=debian-11&x=y?z=w"); ok {
		t.Error("component purl with a second '?' accepted")
	}
}
