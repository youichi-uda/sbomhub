package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sbomhub/sbomhub/internal/model"
)

// fakeSearchRepo is a searchRepoAPI stub. A nil cveResult with a nil cveErr
// models a local-DB miss (the CVE is not cached locally), which forces
// SearchByCVE down its NVD-fallback / not-found branches.
type fakeSearchRepo struct {
	cveResult *model.CVESearchResult
	cveErr    error
}

func (f *fakeSearchRepo) SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error) {
	return f.cveResult, f.cveErr
}

func (f *fakeSearchRepo) SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error) {
	return nil, nil
}

// recordingSearchRepo captures the cveID SearchByCVE forwards to the repo so a
// test can assert the value was normalized (trimmed + upper-cased) before the
// lookup. It returns its canned result for the recorded call.
type recordingSearchRepo struct {
	result   *model.CVESearchResult
	gotCVEID string
}

func (r *recordingSearchRepo) SearchByCVE(ctx context.Context, cveID string) (*model.CVESearchResult, error) {
	r.gotCVEID = cveID
	return r.result, nil
}

func (r *recordingSearchRepo) SearchByComponent(ctx context.Context, name string, versionConstraint string) (*model.ComponentSearchResult, error) {
	return nil, nil
}

// fakeNVD is an nvdLookupAPI stub letting a test choose the NVD outcome:
// an operational error, or a successful-but-empty (nil, nil) result.
type fakeNVD struct {
	vuln *model.Vulnerability
	err  error
}

func (f *fakeNVD) SearchByCVEID(ctx context.Context, cveID string) (*model.Vulnerability, error) {
	return f.vuln, f.err
}

func (f *fakeNVD) SaveVulnerability(ctx context.Context, vuln *model.Vulnerability) error {
	return nil
}

// TestSearchByCVE_NVDOperationalError_NotClassifiedNotFound guards Bug 1: an
// NVD operational failure plus a local miss must NOT be reported as
// ErrCVENotFound (which the handler maps to 404 "CVE not found"). On the
// pre-fix code SearchByCVE wrapped this as ErrCVENotFound, so errors.Is
// below would be true and this test would fail.
func TestSearchByCVE_NVDOperationalError_NotClassifiedNotFound(t *testing.T) {
	svc := NewSearchServiceWithNVD(
		&fakeSearchRepo{}, // local miss
		&fakeNVD{err: errors.New("NVD API error: 500 - internal server error")},
	)

	_, err := svc.SearchByCVE(context.Background(), "CVE-2024-0001")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if errors.Is(err, ErrCVENotFound) {
		t.Fatalf("NVD operational failure must not be classified as ErrCVENotFound (would yield a false 404); got %v", err)
	}
}

// TestSearchByCVE_NVDEmptyResult_IsNotFound is a regression guard: a
// successful but empty NVD result (nil, nil) plus a local miss IS a genuine
// not-found and must stay ErrCVENotFound (404). Passes on both pre- and
// post-fix code; it pins the behaviour Bug 1's fix must not disturb.
func TestSearchByCVE_NVDEmptyResult_IsNotFound(t *testing.T) {
	svc := NewSearchServiceWithNVD(
		&fakeSearchRepo{}, // local miss
		&fakeNVD{},        // SearchByCVEID returns (nil, nil)
	)

	_, err := svc.SearchByCVE(context.Background(), "CVE-2024-0002")
	if !errors.Is(err, ErrCVENotFound) {
		t.Fatalf("empty NVD result must classify as ErrCVENotFound (404); got %v", err)
	}
}

// TestSearchByCVE_MalformedCVE_Rejected guards the M42 Wave 1 boundary
// validation: a malformed CVE ID must be rejected with ErrInvalidCVEID (→ 400)
// BEFORE any repository / NVD lookup runs. The fake repo below would panic-free
// return a nil result, but the point is the sentinel classification: each of
// these inputs is not a well-formed CVE ID and must never reach the DB.
func TestSearchByCVE_MalformedCVE_Rejected(t *testing.T) {
	svc := NewSearchService(&fakeSearchRepo{})

	for _, bad := range []string{
		"",
		"not-a-cve",
		"CVE-2021",              // no sequence
		"CVE-2021-123",          // 3-digit sequence, below \d{4,}
		"CVE-2021-44228 OR 1=1", // injection tail
		"CVE-2021-4&x",          // injection chars
		"library-name",          // a component name, not a CVE
	} {
		_, err := svc.SearchByCVE(context.Background(), bad)
		if !errors.Is(err, ErrInvalidCVEID) {
			t.Errorf("SearchByCVE(%q) err = %v, want ErrInvalidCVEID (400)", bad, err)
		}
	}
}

// TestSearchByCVE_ValidCVE_NormalizesAndPasses proves the validator does not
// reject real modern CVEs and that lowercase input is normalized through to the
// repository call. The fake records the cveID it is handed; we assert it is the
// upper-cased canonical form. A 5-digit (log4shell) and 7-digit ID both pass.
func TestSearchByCVE_ValidCVE_NormalizesAndPasses(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"cve-2021-44228", "CVE-2021-44228"},     // lowercase, 5-digit
		{"CVE-2023-1234567", "CVE-2023-1234567"}, // 7-digit sequence
		{" CVE-2014-0160 ", "CVE-2014-0160"},     // padded, 4-digit
	} {
		rec := &recordingSearchRepo{result: &model.CVESearchResult{CVEID: tc.want}}
		svc := NewSearchService(rec)
		if _, err := svc.SearchByCVE(context.Background(), tc.in); err != nil {
			t.Fatalf("SearchByCVE(%q) unexpected error: %v", tc.in, err)
		}
		if rec.gotCVEID != tc.want {
			t.Errorf("SearchByCVE(%q) passed %q to repo, want normalized %q", tc.in, rec.gotCVEID, tc.want)
		}
	}
}

// TestSearchByCVE_NilNVD_LocalMiss_IsNotFound guards Bug 2: with no NVD
// fallback wired and a local miss, the final fallback must wrap
// ErrCVENotFound so the handler returns 404, not a generic 500. On the
// pre-fix code this branch returned a plain fmt.Errorf without %w, so
// errors.Is would be false and this test would fail.
func TestSearchByCVE_NilNVD_LocalMiss_IsNotFound(t *testing.T) {
	svc := NewSearchService(&fakeSearchRepo{}) // nil NVD, local miss

	_, err := svc.SearchByCVE(context.Background(), "CVE-2024-0003")
	if !errors.Is(err, ErrCVENotFound) {
		t.Fatalf("nil-NVD local miss must classify as ErrCVENotFound (404); got %v", err)
	}
}
