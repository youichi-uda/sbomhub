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
