package repository

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// TestEcosystemFromPurl pins the frozen derivation rule: pkg:golang → "go",
// every other purl type maps to its type token verbatim, and a non-purl /
// empty string yields "". This is the single source of truth the handler
// response field and the ?ecosystem repo filter both depend on.
func TestEcosystemFromPurl(t *testing.T) {
	cases := []struct {
		name string
		purl string
		want string
	}{
		{"golang remaps to go", "pkg:golang/example.com/foo@v1.2.3", "go"},
		{"golang no path", "pkg:golang@v1.2.3", "go"},
		{"npm stays npm", "pkg:npm/lodash@4.17.21", "npm"},
		{"npm scoped", "pkg:npm/%40angular/core@17.0.0", "npm"},
		{"maven verbatim", "pkg:maven/org.apache.commons/commons-lang3@3.14.0", "maven"},
		{"pypi verbatim", "pkg:pypi/django@5.0", "pypi"},
		{"uppercase type lowercased", "pkg:GOLANG/x@v1", "go"},
		{"empty string", "", ""},
		{"non-purl string", "example.com/foo", ""},
		{"bare pkg prefix", "pkg:", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EcosystemFromPurl(tc.purl); got != tc.want {
				t.Errorf("EcosystemFromPurl(%q) = %q, want %q", tc.purl, got, tc.want)
			}
		})
	}
}

// TestVulnerabilityRepository_ListReachabilityTargets_JoinsComponents asserts
// the query is tenant-safe: component_vulnerabilities carries no tenant_id / no
// RLS, so the read MUST join through `components c` (FORCE RLS) and predicate
// on p.tenant_id. The assertion is structural on the SQL itself — a future
// revert that dropped the components join (re-introducing cross-tenant leakage)
// fails this expectation rather than merely changing the SQL text. It also
// verifies the (cve_id, component_id, purl, name, version) columns map through.
func TestVulnerabilityRepository_ListReachabilityTargets_JoinsComponents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVulnerabilityRepository(db)

	tenantID := uuid.New()
	projectID := uuid.New()
	comp1 := uuid.New()
	comp2 := uuid.New()

	// Require the tenant-safe join through components AND the tenant predicate.
	pattern := regexp.MustCompile(`(?is)FROM\s+components\s+c\s+JOIN\s+component_vulnerabilities\s+cv\s+ON\s+c\.id\s*=\s*cv\.component_id.*p\.tenant_id\s*=\s*\$1.*s\.project_id\s*=\s*\$2`)

	rows := sqlmock.NewRows([]string{"id", "name", "version", "purl", "cve_id"}).
		AddRow(comp1.String(), "foo", "v1.2.3", "pkg:golang/example.com/foo@v1.2.3", "CVE-2024-0001").
		AddRow(comp2.String(), "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "CVE-2024-0002")

	mock.ExpectQuery(pattern.String()).
		WithArgs(tenantID, projectID).
		WillReturnRows(rows)

	got, err := repo.ListReachabilityTargets(context.Background(), tenantID, projectID, "")
	if err != nil {
		t.Fatalf("ListReachabilityTargets: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2", len(got))
	}
	if got[0].ComponentID != comp1 {
		t.Errorf("got[0].ComponentID = %s, want %s", got[0].ComponentID, comp1)
	}
	if got[0].CVEID != "CVE-2024-0001" {
		t.Errorf("got[0].CVEID = %q, want CVE-2024-0001", got[0].CVEID)
	}
	if got[0].Purl != "pkg:golang/example.com/foo@v1.2.3" {
		t.Errorf("got[0].Purl = %q", got[0].Purl)
	}
	if got[0].ComponentName != "foo" || got[0].ComponentVersion != "v1.2.3" {
		t.Errorf("got[0] name/version = %q/%q", got[0].ComponentName, got[0].ComponentVersion)
	}
	if got[1].ComponentID != comp2 || got[1].CVEID != "CVE-2024-0002" {
		t.Errorf("got[1] = %+v", got[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestVulnerabilityRepository_ListReachabilityTargets_EcosystemFilter verifies
// the ?ecosystem filter is applied in Go over the derived ecosystem: the query
// returns both a golang and an npm row, and asking for "go" drops the npm one.
func TestVulnerabilityRepository_ListReachabilityTargets_EcosystemFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVulnerabilityRepository(db)

	tenantID := uuid.New()
	projectID := uuid.New()
	goComp := uuid.New()
	npmComp := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "name", "version", "purl", "cve_id"}).
		AddRow(goComp.String(), "foo", "v1", "pkg:golang/example.com/foo@v1", "CVE-2024-0001").
		AddRow(npmComp.String(), "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "CVE-2024-0002")

	mock.ExpectQuery(`(?is)component_vulnerabilities`).
		WithArgs(tenantID, projectID).
		WillReturnRows(rows)

	got, err := repo.ListReachabilityTargets(context.Background(), tenantID, projectID, "go")
	if err != nil {
		t.Fatalf("ListReachabilityTargets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1 (npm filtered out)", len(got))
	}
	if got[0].ComponentID != goComp {
		t.Errorf("got[0].ComponentID = %s, want the golang component %s", got[0].ComponentID, goComp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

// TestVulnerabilityRepository_ListReachabilityTargets_PropagatesError ensures a
// DB error is surfaced rather than swallowed.
func TestVulnerabilityRepository_ListReachabilityTargets_PropagatesError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	repo := NewVulnerabilityRepository(db)
	mock.ExpectQuery(`(?is)component_vulnerabilities`).WillReturnError(errors.New("boom"))

	if _, err := repo.ListReachabilityTargets(context.Background(), uuid.New(), uuid.New(), ""); err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
