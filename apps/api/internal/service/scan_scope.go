package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/database"
	"github.com/sbomhub/sbomhub/internal/model"
)

// # Why scanners open their own transactions (M62)
//
// Until M62 every caller of NVDService/JVNService wrapped the WHOLE sweep in
// one tenant transaction: SbomHandler.runScan, VulnerabilityHandler.runScan
// and the scheduler (which wrapped every project of a tenant in one). The
// sweep is dominated by rate-limited network I/O — a cold scan of an SBOM with
// a Linux kernel took 68 NVD requests and 14 min 24 s without an API key
// (M60, 2026-11-08) — so for that whole time PostgreSQL held, per scan:
//
//   - one open transaction (pg_stat_activity: `idle in transaction`, with
//     xact_start set at the scan's start), which also pins a transaction id
//     once the first link is written and so holds back VACUUM's horizon;
//   - one connection out of the API's main pool (25), unusable by requests;
//   - the row locks of every link it had written (the inserted
//     component_vulnerabilities tuples — a second scan inserting the same
//     (component, vulnerability) key waits on them — and any row the
//     relabel UPDATE touched) and the FOR KEY SHARE locks the link's foreign
//     keys take on the referenced `components` and `vulnerabilities` rows;
//   - no advisory lock: nothing in the codebase took one before M62.
//
// The scanners now run in three phases and NO transaction is open during any
// network request:
//
//  1. read   — one short tenant transaction lists the SBOM's components
//     (components FORCE row-level security, so this read needs the tenant
//     GUC; outside a tenant transaction it silently returns zero rows);
//  2. fetch  — NVD/JVN requests with no transaction; the global catalogue
//     row a match needs is resolved right after each lookup on the pool
//     (GetByCVE autocommit, Create on the catalogue pool, M57), exactly
//     when it was resolved before, so cve_sync's 25 h replay-overlap
//     argument (scheduler.cveSyncReplayOverlap) is unchanged;
//  3. write  — one short tenant transaction, serialised per SBOM by a
//     transaction-level advisory lock, writes every link, one SAVEPOINT per
//     work item.
//
// The guarantee is structural rather than a convention: scanScopeFrom REFUSES
// a context that carries a transaction (ErrScanInTransaction), so a caller
// that wraps a scan in a transaction gets an error instead of a 15-minute
// transaction.

// ErrScanInTransaction is returned by a scanner handed a context that carries
// a *sql.Tx. Scanners must never run network I/O inside a transaction.
var ErrScanInTransaction = errors.New("scan: the context carries a database transaction; " +
	"scanners open their own short transactions and must not be called inside one")

// ErrScanNoScope is returned by a scanner whose context has no tenant scope
// (WithScanScope). Without it the component read would run outside any
// tenant transaction, where FORCE row-level security returns zero rows and
// the scan would "complete" having looked at nothing.
var ErrScanNoScope = errors.New("scan: no tenant scope on the context (service.WithScanScope)")

type scanScopeKey struct{}

// ScanScope is how a scanner reaches the database without holding a
// transaction across network I/O: the pool and the tenant whose GUC its
// short transactions bind.
type ScanScope struct {
	DB       *sql.DB
	TenantID uuid.UUID
}

// WithScanScope returns ctx carrying the tenant scope scanners need.
//
// It deliberately does NOT strip a transaction ctx carries (Codex M62 R1
// Medium): stripping the marker would not end the transaction — the caller
// would still be holding it open while the scanner talks to NVD — it would
// only hide it from the ErrScanInTransaction check. A caller must leave its
// transaction before building the scan context.
func WithScanScope(ctx context.Context, db *sql.DB, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, scanScopeKey{}, ScanScope{DB: db, TenantID: tenantID})
}

// CheckScanScope reports whether ctx is one a scanner accepts: a tenant scope
// and no transaction.
func CheckScanScope(ctx context.Context) error {
	_, err := scanScopeFrom(ctx)
	return err
}

// ScanScopeFrom returns the scope a scanner would use, or the error it would
// refuse ctx with. It lets a componentScanner other than NVD/JVN (and test
// probes) read through the same tenant transaction the real scanners use.
func ScanScopeFrom(ctx context.Context) (ScanScope, error) { return scanScopeFrom(ctx) }

// ReadTx runs fn in a short tenant transaction (see readTx).
func (s ScanScope) ReadTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	return s.readTx(ctx, fn)
}

func scanScopeFrom(ctx context.Context) (ScanScope, error) {
	if _, ok := database.TxFromContext(ctx); ok {
		return ScanScope{}, ErrScanInTransaction
	}
	s, ok := ctx.Value(scanScopeKey{}).(ScanScope)
	if !ok || s.DB == nil || s.TenantID == uuid.Nil {
		return ScanScope{}, ErrScanNoScope
	}
	return s, nil
}

// readTx runs fn in a short tenant transaction. If the scan's deadline (or
// another cancellation) is what failed it, the error says so (Codex M62 R1
// High): a read cut off by the deadline is reported as deadline_exceeded, not
// as a generic scan error.
func (s ScanScope) readTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	err := s.readTxRaw(ctx, fn)
	if err != nil {
		if cause := scanInterruption(ctx); cause != nil {
			return fmt.Errorf("%w: %w", cause, err)
		}
	}
	return err
}

func (s ScanScope) readTxRaw(ctx context.Context, fn func(txCtx context.Context) error) error {
	return database.WithTxFunc(ctx, s.DB, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx, `SELECT set_config('app.current_tenant_id', $1, true)`, s.TenantID.String()); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		return fn(txCtx)
	})
}

// scanLockNamespace prefixes the advisory-lock key so it cannot coincide with
// a key some other feature derives from the same UUID.
const scanLockNamespace = "sbomhub.scan.sbom:"

// ScanLockKey is the pg_advisory_xact_lock key that serialises the write
// phases of scans of one SBOM. Exported so tests can hold it.
func ScanLockKey(sbomID uuid.UUID) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(scanLockNamespace))
	_, _ = h.Write(sbomID[:])
	return int64(h.Sum64()) //nolint:gosec // a hash reinterpreted as a lock key; wrap-around is intended
}

// writeTx runs fn in a short tenant transaction holding the SBOM's
// transaction-level advisory lock.
//
// Why a lock at all: the link writes are idempotent and only ever relabel
// upward, so two scans of the same SBOM cannot produce a wrong row. What they
// CAN do is deadlock — each write phase inserts its links in its own order,
// and two transactions inserting overlapping (component, vulnerability) keys
// in opposite orders wait on each other's uncommitted tuples until PostgreSQL
// aborts one, which discards that scan's whole write phase. They can also
// interleave between another scan's before/after counts, which is what the
// scheduler's new_vulnerabilities is computed from. The lock makes write
// phases of one SBOM strictly sequential; it is per SBOM (the links written
// are those of the SBOM's components), so scans of different SBOMs — of the
// same project or not — never wait on each other. It is transaction-level, so
// it is released by COMMIT/ROLLBACK and cannot leak onto a pooled connection.
func (s ScanScope) writeTx(ctx context.Context, sbomID uuid.UUID, fn func(txCtx context.Context) error) error {
	return database.WithTxFunc(ctx, s.DB, func(txCtx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(txCtx, `SELECT set_config('app.current_tenant_id', $1, true)`, s.TenantID.String()); err != nil {
			return fmt.Errorf("set tenant context: %w", err)
		}
		if _, err := tx.ExecContext(txCtx, `SELECT pg_advisory_xact_lock($1)`, ScanLockKey(sbomID)); err != nil {
			return fmt.Errorf("scan write lock: %w", err)
		}
		return fn(txCtx)
	})
}

// scanWriteTimeout bounds the write phase. The write phase runs on a context
// detached from the scan's deadline (WithoutCancel): the deadline bounds
// FETCHING, and the findings already verified when it fires must still be
// committed (M60's "keep verified pages, report truncated" rule), which a
// context that has already expired could not do.
const scanWriteTimeout = 5 * time.Minute

// scanWriteContext is the context the write phase (and the per-match
// catalogue resolution) runs on: the scan's values without its cancellation,
// bounded by its own timeout.
func scanWriteContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), scanWriteTimeout)
}

// pendingLink is one component→vulnerability link the fetch phase decided on
// and the write phase records.
type pendingLink struct {
	componentID uuid.UUID
	vulnID      uuid.UUID
	method      model.MatchMethod
	// evidence is the match_evidence JSON written with a distro label (M70,
	// the distro step); nil for every other writer.
	evidence []byte
}

// linkWriter is the one repository call the write phase makes per link.
type linkWriter func(ctx context.Context, l pendingLink) error

// writeLinks records every group of links in ONE locked tenant transaction,
// one SAVEPOINT per group (a scanner's work item or component).
//
// A group whose statement is refused is rolled back to its savepoint and
// counted as refused in full — its links are not durable — while the other
// groups commit. Before M62 one refused statement aborted the transaction and
// discarded every link of the sweep (M50/M54); the savepoint confines the
// loss to the group that caused it.
//
// newVulns is the number of distinct vulnerabilities linked to the SBOM after
// the write minus before it, both counted inside the locked transaction, so a
// concurrent scan of the same SBOM cannot be attributed to this one. It is 0
// unless the transaction committed.
func (s ScanScope) writeLinks(ctx context.Context, sbomID uuid.UUID, groups [][]pendingLink, write linkWriter) (refused, newVulns int, err error) {
	total := 0
	for _, g := range groups {
		total += len(g)
	}
	if total == 0 {
		return 0, 0, nil
	}
	wctx, cancel := scanWriteContext(ctx)
	defer cancel()

	started := time.Now()
	var before, after int
	refusedInTx := 0
	err = s.writeTx(wctx, sbomID, func(txCtx context.Context) error {
		tx, _ := database.TxFromContext(txCtx)
		if err := tx.QueryRowContext(txCtx, sbomVulnCountSQL, sbomID).Scan(&before); err != nil {
			return fmt.Errorf("count links before write: %w", err)
		}
		for _, g := range groups {
			if len(g) == 0 {
				continue
			}
			if _, err := tx.ExecContext(txCtx, `SAVEPOINT scan_item`); err != nil {
				return fmt.Errorf("savepoint: %w", err)
			}
			var gerr error
			for _, l := range g {
				if gerr = write(txCtx, l); gerr != nil {
					break
				}
			}
			if gerr != nil {
				slog.Warn("scan: a link write was refused; rolling back that item only",
					"sbom_id", sbomID, "links_in_item", len(g), "error", gerr)
				refusedInTx += len(g)
				if _, err := tx.ExecContext(txCtx, `ROLLBACK TO SAVEPOINT scan_item`); err != nil {
					return fmt.Errorf("rollback to savepoint: %w", err)
				}
				continue
			}
			if _, err := tx.ExecContext(txCtx, `RELEASE SAVEPOINT scan_item`); err != nil {
				return fmt.Errorf("release savepoint: %w", err)
			}
		}
		if err := tx.QueryRowContext(txCtx, sbomVulnCountSQL, sbomID).Scan(&after); err != nil {
			return fmt.Errorf("count links after write: %w", err)
		}
		return nil
	})
	slog.Info("scan: write phase finished",
		"sbom_id", sbomID, "links", total, "refused", refusedInTx,
		"duration_ms", time.Since(started).Milliseconds(), "error", err)
	if err != nil {
		// Nothing committed: every link is lost.
		return total, 0, err
	}
	if after > before {
		newVulns = after - before
	}
	return refusedInTx, newVulns, nil
}

const sbomVulnCountSQL = `
	SELECT COUNT(DISTINCT cv.vulnerability_id)
	FROM component_vulnerabilities cv
	JOIN components c ON c.id = cv.component_id
	WHERE c.sbom_id = $1`
