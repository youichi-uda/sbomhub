package service

import (
	"regexp"
	"testing"
)

// Codex integration R1 Low: 64 random bits make a repeat between two scan
// groups of one SBOM improbable but possible, and web / MCP read equal
// scan_run as "no rescan". Use 128 bits.
func TestNewScanRunID_Has128RandomBits(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := newScanRunID()
		if !re.MatchString(id) {
			t.Fatalf("scan run %q, want 32 lowercase hex digits (128 bits)", id)
		}
		if seen[id] {
			t.Fatalf("scan run %q repeated", id)
		}
		seen[id] = true
	}
}
