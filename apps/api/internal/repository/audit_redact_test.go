package repository

import (
	"context"
	"database/sql/driver"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/model"
)

// captureDetailsArgMatcher records the marshalled audit_logs.details JSON
// (bound at $7 of the INSERT) so the M42 Wave 2 test below can assert on the
// exact bytes the choke point wrote, without a Postgres round-trip. Mirrors
// the captureStringArgMatcher style used in handler/evidence_pack_test.go.
type captureDetailsArgMatcher struct {
	target *string
}

func (m captureDetailsArgMatcher) Match(v driver.Value) bool {
	switch s := v.(type) {
	case string:
		*m.target = s
		return true
	case []byte:
		*m.target = string(s)
		return true
	}
	return false
}

// TestAuditRepository_Create_RedactsSecretsPreservesEvidence pins the M42
// Wave 2 audit choke point end-to-end from the repository side: a single
// Create with a Details map carrying BOTH secret-shaped strings AND
// compliance evidence must persist a details JSON where the secrets are
// redacted while every evidence field survives verbatim (§8.5 audit trail /
// over-redaction is the top hazard).
//
// The INSERT column order (see repository/audit.go Create) is:
//
//	id, tenant_id, user_id, action, resource_type, resource_id,
//	details, ip_address, user_agent, created_at   ($1..$10)
//
// We capture $7 (details) and accept anything for the other columns.
func TestAuditRepository_Create_RedactsSecretsPreservesEvidence(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	var capturedDetails string
	mock.ExpectExec(`INSERT INTO audit_logs`).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // action
			sqlmock.AnyArg(), // resource_type
			sqlmock.AnyArg(), // resource_id
			captureDetailsArgMatcher{target: &capturedDetails}, // details (JSON)
			sqlmock.AnyArg(), // ip_address
			sqlmock.AnyArg(), // user_agent
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	repo := NewAuditRepository(db)

	tenantID := uuid.New()
	userID := uuid.New()
	resourceID := uuid.New()
	// A resource UUID persisted INSIDE details (as evidence) — must survive.
	evidenceUUID := uuid.New().String()

	justification := "Not affected: the vulnerable sink is guarded by an " +
		"allow-list and never receives tainted input; reviewed 2026-07-01 " +
		"against advisory GHSA-jfh8-c2jp-5v3q."

	details := map[string]interface{}{
		// --- compliance evidence (MUST survive verbatim) ---
		"cve_id":          "CVE-2021-44228",
		"resource_uuid":   evidenceUUID,
		"provider":        "openai",
		"model":           "gemini-3.5-flash",
		"justification":   justification,
		"approved":        true,
		"vex_count":       7,
		"created_at_note": "2026-07-06T00:00:00Z",
		// --- co-located secrets (MUST be redacted) ---
		"dsn":   "postgres://appuser:S3cr3tDbPw@db.internal:5432/sbomhub",
		"error": "provider call failed: Authorization: Bearer eyJhbGciSECRETtoken",
		// --- the audit middleware's unfiltered query surface (url.Values) ---
		"query": url.Values{
			"q":        []string{"log4j"},
			"redirect": []string{"https://cb.example/oauth?access_token=LEAKED_AT_9f"},
		},
	}

	a := &model.AuditLog{
		ID:           uuid.New(),
		TenantID:     &tenantID,
		UserID:       &userID,
		Action:       model.ActionVEXDraftCreated,
		ResourceType: model.ResourceVEXDraft,
		ResourceID:   &resourceID,
		Details:      details,
		IPAddress:    net.ParseIP("203.0.113.7"),
		UserAgent:    "sbomhub-cli/1.0",
		CreatedAt:    time.Now().UTC(),
	}

	if err := repo.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sqlmock expectations: %v", err)
	}

	// --- secrets redacted ---
	for _, secret := range []string{
		"S3cr3tDbPw",
		"eyJhbGciSECRETtoken",
		"LEAKED_AT_9f",
	} {
		if strings.Contains(capturedDetails, secret) {
			t.Errorf("secret %q leaked into persisted details JSON:\n%s", secret, capturedDetails)
		}
	}
	// Positive markers for the shape-preserving redactions.
	for _, want := range []string{
		`postgres://appuser:[REDACTED]@db.internal:5432/sbomhub`,
		`Authorization: [REDACTED]`,
		`access_token=[REDACTED]`,
	} {
		if !strings.Contains(capturedDetails, want) {
			t.Errorf("expected redacted marker %q in details JSON:\n%s", want, capturedDetails)
		}
	}

	// --- evidence preserved verbatim (over-redaction guard, §8.5) ---
	for _, want := range []string{
		"CVE-2021-44228",
		evidenceUUID,
		`"provider":"openai"`,
		`"model":"gemini-3.5-flash"`,
		justification,
		`"approved":true`,
		`"vex_count":7`,
		"log4j",
	} {
		if !strings.Contains(capturedDetails, want) {
			t.Errorf("compliance evidence %q was corrupted/dropped from details JSON:\n%s", want, capturedDetails)
		}
	}
}
