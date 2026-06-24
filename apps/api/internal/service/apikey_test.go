package service

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/repository"
)

// TestCreateKey_InvalidPermissions_Rejected pins the F17 service-side
// fix (M1 Codex review round 7): APIKeyService.CreateKey must refuse
// permissions values outside the allowlist (read / write / admin /
// owner) with ErrInvalidPermissions and MUST NOT persist a row. The
// previous implementation accepted any string verbatim, and
// roleFromAPIKeyPermissions silently promoted unknown values to
// RoleMember (write-capable) at validation time — a fail-open default
// in a security product.
//
// The test uses sqlmock to assert two contracts at once:
//   - ErrInvalidPermissions is returned for every unrecognised value.
//   - No INSERT statement is ever issued (sqlmock.ExpectationsWereMet
//     would complain if any unexpected SQL ran).
func TestCreateKey_InvalidPermissions_Rejected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// Intentionally configure NO expectations — the service must not
	// reach the repository's INSERT at all.

	svc := NewAPIKeyService(repository.NewAPIKeyRepository(db))

	for _, perm := range []string{
		"garbage", "readonly", "none", "rw", "*",
		"delete", "write-only", "READ_ONLY", "x",
	} {
		t.Run(perm, func(t *testing.T) {
			_, err := svc.CreateKey(context.Background(), CreateAPIKeyInput{
				TenantID:    uuid.New(),
				Name:        "test key",
				Permissions: perm,
			})
			if !errors.Is(err, ErrInvalidPermissions) {
				t.Fatalf("F17: CreateKey(%q) returned %v, want ErrInvalidPermissions",
					perm, err)
			}
		})
	}

	// Sanity check — sqlmock would have complained loudly above if any
	// statement ran. Asserting expectations explicitly closes the loop
	// in case a future refactor adds a query before the validation.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("F17: no SQL must run for rejected permissions; got %v", err)
	}
}

// TestCreateProjectKey_InvalidPermissions_Rejected mirrors the above
// for the deprecated project-level path. Both surfaces must enforce
// the allowlist because, after the F14 MultiAuth integration, both
// key types feed the same TenantContext role mapping.
func TestCreateProjectKey_InvalidPermissions_Rejected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	svc := NewAPIKeyService(repository.NewAPIKeyRepository(db))

	for _, perm := range []string{"garbage", "readonly", "rw", "*"} {
		t.Run(perm, func(t *testing.T) {
			_, err := svc.CreateProjectKey(context.Background(), CreateProjectAPIKeyInput{
				TenantID:    uuid.New(),
				ProjectID:   uuid.New(),
				Name:        "test key",
				Permissions: perm,
			})
			if !errors.Is(err, ErrInvalidPermissions) {
				t.Fatalf("F17: CreateProjectKey(%q) returned %v, want ErrInvalidPermissions",
					perm, err)
			}
		})
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("F17: no SQL must run for rejected permissions; got %v", err)
	}
}

// TestCreateKey_KnownPermissions_Persisted is the positive-path
// companion: every documented allowlist value must reach the repository
// INSERT verbatim (after lowercasing). This pins the F17 contract that
// the validation only filters unknowns — it does not silently rewrite
// the persisted column for recognised inputs.
func TestCreateKey_KnownPermissions_Persisted(t *testing.T) {
	for _, perm := range []string{"read", "write", "admin", "owner"} {
		t.Run(perm, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()

			// The INSERT statement is constructed in
			// APIKeyRepository.Create. We match on the literal
			// permissions argument (lowercase, no surrounding ws) so a
			// future "normalise to uppercase" regression is caught.
			mock.ExpectExec(`INSERT INTO api_keys`).
				WithArgs(
					sqlmock.AnyArg(), // id
					sqlmock.AnyArg(), // tenant_id
					nil,              // project_id (tenant-level key)
					"test key",
					sqlmock.AnyArg(), // key_hash
					sqlmock.AnyArg(), // key_prefix
					perm,             // permissions — verbatim, lowercase
					sqlmock.AnyArg(), // expires_at
					sqlmock.AnyArg(), // created_at
				).
				WillReturnResult(sqlmock.NewResult(0, 1))

			svc := NewAPIKeyService(repository.NewAPIKeyRepository(db))
			_, err = svc.CreateKey(context.Background(), CreateAPIKeyInput{
				TenantID:    uuid.New(),
				Name:        "test key",
				Permissions: perm,
			})
			if err != nil {
				t.Fatalf("CreateKey(%q) returned %v, want nil", perm, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("expectations not met: %v", err)
			}
		})
	}
}

// TestCreateKey_EmptyPermissions_DefaultsToWrite preserves the
// historical short-hand: callers omitting permissions get the
// documented "write" default. F17 specifically prohibits silent
// PROMOTION of unknown values; the legacy empty-string default
// (substituted before validation) is retained for back-compat so
// existing CLI / web-UI flows that POST {"name":"..."} keep
// working.
func TestCreateKey_EmptyPermissions_DefaultsToWrite(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`INSERT INTO api_keys`).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // tenant_id
			nil,              // project_id
			"test key",
			sqlmock.AnyArg(), // key_hash
			sqlmock.AnyArg(), // key_prefix
			"write",          // empty → "write"
			sqlmock.AnyArg(), // expires_at
			sqlmock.AnyArg(), // created_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	svc := NewAPIKeyService(repository.NewAPIKeyRepository(db))
	_, err = svc.CreateKey(context.Background(), CreateAPIKeyInput{
		TenantID:    uuid.New(),
		Name:        "test key",
		Permissions: "",
	})
	if err != nil {
		t.Fatalf("CreateKey(empty) returned %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations not met: %v", err)
	}
}
