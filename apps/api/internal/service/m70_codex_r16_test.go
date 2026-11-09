package service

import (
	"strings"
	"testing"
)

// Codex M70 R16 High-1: a continuation page with no records and no further
// token is a truncated walk, not the end.
func TestM70R16_EmptyContinuationArrayIsAnError(t *testing.T) {
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":"t1"}`, `{"vulns":[]}`); err == nil {
		t.Error("an empty continuation array ended the walk as complete")
	}
	// A token-only intermediate page is still fine.
	if err := r15Query(t, `{"vulns":[`+r15OK+`],"next_page_token":"t1"}`, `{"vulns":[],"next_page_token":"t2"}`, `{"vulns":[`+strings.Replace(r15OK, "DSA-1", "DSA-2", 1)+`]}`); err != nil {
		t.Errorf("token-only intermediate page refused: %v", err)
	}
}
