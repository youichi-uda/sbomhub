package service

// The distro step of a scan (M70).
//
// # What it does
//
// After the NVD and JVN sweeps have linked an SBOM's components, this step
// reads, for every DISTRO package that has links, the distro's own
// fixed-version data (OSV's distro ecosystems) and relabels each link with
// what that data says about the installed version, compared with the distro's
// own ordering (internal/pkgversion):
//
//	distro_affected  fix released in the installed release, installed below it
//	distro_unfixed   installed release affected, no fix released
//	distro_fixed     installed version at or above the fix (kept, for review)
//
// It never adds or removes a link, and only ever relabels upward
// (model.MatchMethod.Rank). See distro_match.go for the rules and why a gap
// costs a label, never a finding.
//
// # Shape (M62)
//
// The three phases of every scanner: one short tenant READ transaction (the
// SBOM's components and links), fetching with NO transaction open (one OSV
// package query per distinct (ecosystem, package), cached in Redis, paced,
// bounded by the scan deadline), and one short locked WRITE transaction with
// a SAVEPOINT per component (ScanScope.writeLinks).
//
// # Failure reporting
//
//   - A package whose data could not be read: its links keep their labels,
//     and the scan reports distro_data_failed (ErrScanDistroDataFailed).
//   - The scan deadline / a cancellation before every package was read:
//     deadline_exceeded / cancelled, with what was decided committed.
//   - A refused write: write_refused.
//   - Offline mode (SBOMHUB_OFFLINE): no request at all, no relabel, no
//     failure — the links keep the M60 labels, exactly as before M70.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sbomhub/sbomhub/internal/cache"
	"github.com/sbomhub/sbomhub/internal/client"
	"github.com/sbomhub/sbomhub/internal/model"
	"github.com/sbomhub/sbomhub/internal/repository"
)

const (
	// distroMaxPages bounds one package query. The largest measured answer
	// (Debian "linux") is 3,000 records per page and several pages; 20 pages
	// is ~60,000 records. A query that needs more is a distro_data_failed
	// for that package, never a short answer.
	distroMaxPages = 20
	// distroRequestGap is the minimum gap between two OSV requests of one
	// scan. OSV publishes no rate limit; this keeps one scan's burst polite
	// (the fixture SBOM needs one request).
	distroRequestGap = 250 * time.Millisecond
	// distroWorkers is how many package queries run at once (sharing the
	// pacer, so the request RATE stays one per distroRequestGap).
	distroWorkers = 4
	// distroMaxBytesPerPackage bounds one package query's response bytes,
	// all pages together. The largest measured answer (Debian "linux") is
	// ~7 MB per 3,000-record page.
	distroMaxBytesPerPackage = 96 << 20
	// distroCachePayloadVersion is bumped with the distroRecord format
	// (2: Releases / Packages, Codex M70 R2; 3: Ubuntu binaries, R4;
	// 4: record modified, R8; 5: records validated as since R11, R12;
	// 6: no future timestamps, R14; 7: every affected element validated,
	// R15; 8: empty continuation pages refused (R16) and canonical identity
	// strings (R18); 9: canonical record identities, exact CVE matching (R19);
	// 10: unique record ids, OSV id character set (R21); 11: affected purl
	// agreement and field length bounds (R22); 12: purl namespace,
	// package-less GIT entries (R23); 13: strict affected purl, Ubuntu
	// binaries validated (R27); 14: purl distro / arch qualifiers (R31);
	// 15: rpm distro qualifier, strict subpath (R32); 16: every returned
	// record id (R34)).
	distroCachePayloadVersion = 16
)

// distroLinkStore is the repository surface the step uses.
// maxEvidenceBytes bounds one link's encoded evidence (Codex M70 R22
// High-3); field lengths are bounded at the source already.
const maxEvidenceBytes = 16 << 10

// recordState is what a lookup by id said about one record, for the
// queried package.
type recordState struct {
	withdrawn bool   // withdrawn (gone from every query)
	editedOut bool   // active, but no longer naming the package (Codex M70 R32 Medium-2)
	rev       string // the withdrawal's / the edit's normalised revision
	failed    bool   // the lookup failed, or contradicts the package query: unknown
}

// withdrawnClear decides whether a no-verdict link's distro label rests
// only on WITHDRAWN records. OSV's package query omits withdrawn records,
// so the package revision can go down, and the ordinary settlement (which
// needs data at least as new as the watermark) is then refused forever
// (Codex M70 R24 High-1). It applies only when the data's revision is below
// the link's watermark (same source), the label's evidence is of this
// source, and EVERY record of that evidence is absent from the data and,
// looked up by id, conclusively withdrawn at or after the evidence's
// revision (R25 High-1). The clear then claims no package revision: the
// withdrawal time of one record is not a snapshot of the package (R27
// High-2), so the watermark is kept as it is. It returns the clear's
// parameter, or nil; failed reports a lookup that failed.
func (d distroData) withdrawnClear(l repository.SbomLink, lookup func(id string) recordState) (p []byte, failed bool) {
	wmRev := l.RevFor(d.sourceID)
	// Resolved whatever the revisions (Codex M70 R31 High-1): even when the
	// package revision did not go down, a clear of a label whose records
	// were withdrawn must leave their tombstones, or a delayed scan that read
	// them before the withdrawal, at the same revision, brings it back.
	if !model.MatchMethod(l.Method).IsDistro() || l.LabelSource != d.sourceID ||
		lookup == nil || len(l.Records) == 0 {
		return nil, false
	}
	for _, id := range l.Records {
		if d.ids[id] {
			return nil, false // still in the data: not a withdrawal
		}
	}
	tombs := map[string]string{}
	for _, id := range l.Records {
		st := lookup(id)
		switch {
		case st.failed:
			return nil, true
		case st.editedOut && st.rev < l.LabelRev:
			// unchanged since the label, yet no longer naming the package:
			// contradictory data
			return nil, true
		case !st.withdrawn && !st.editedOut, st.rev < l.LabelRev:
			return nil, false
		}
		tombs[id] = st.rev
	}
	b, _ := json.Marshal(struct {
		SourceID     string            `json:"source_id"`
		Records      []string          `json:"records"`
		Tombstones   map[string]string `json:"tombstones"`
		WMRev        string            `json:"wm_rev"`
		DataModified string            `json:"data_modified"`
	}{d.sourceID, l.Records, tombs, wmRev, d.revision})
	return b, false
}

// settleNoVerdict is the one settlement of a no-verdict link.
// ok is false when nothing may be written: a lookup of the label's records
// failed, so whether it is a withdrawal is unknown; the label is kept and
// the failure reported (distro_data_failed).
func (d distroData) settleNoVerdict(l repository.SbomLink, wm []byte, lookup func(id string) recordState, counts *DistroScanReport) (pl pendingLink, ok bool) {
	p, failed := d.withdrawnClear(l, lookup)
	if failed {
		counts.LookupFailures++
		return pendingLink{}, false
	}
	// Clears are counted from what the write did, not predicted (Codex M70
	// R30 Low-3, R32 Low-4).
	was := model.MatchMethod(l.Method).IsDistro()
	if p != nil {
		return pendingLink{componentID: l.ComponentID, vulnID: l.VulnerabilityID, withdrawnClear: true, evidence: p, wasDistro: was}, true
	}
	return pendingLink{componentID: l.ComponentID, vulnID: l.VulnerabilityID, noVerdict: true, evidence: wm, wasDistro: was}, true
}

// withdrawalResolver looks records up by id, memoised and paced like the
// package queries; the returned function judges a record for the queried
// package (family, pkg).
func (s *DistroService) withdrawalResolver(ctx context.Context, pace func(context.Context) error) func(family, pkg string) func(string) recordState {
	type got struct {
		st  client.OSVRecordState
		err error
	}
	memo := map[string]got{}
	fetch := func(id string) got {
		if v, ok := memo[id]; ok {
			return v
		}
		g := got{err: fmt.Errorf("not looked up")}
		if err := pace(ctx); err == nil {
			st, err := s.osv.GetRecordState(ctx, id)
			g = got{st: st, err: err}
		}
		memo[id] = g
		return g
	}
	return func(family, pkg string) func(string) recordState {
		return func(id string) recordState {
			g := fetch(id)
			if g.err != nil {
				return recordState{failed: true}
			}
			if g.st.Withdrawn != "" {
				rev := normaliseModified(g.st.Withdrawn)
				if m := normaliseModified(g.st.Modified); m > rev {
					rev = m
				}
				return recordState{withdrawn: rev != "", rev: rev, failed: rev == ""}
			}
			if g.st.Names(family, pkg) {
				// active and still naming the package, yet absent from its
				// query: the query is incomplete
				return recordState{failed: true}
			}
			rev := normaliseModified(g.st.Modified)
			return recordState{editedOut: rev != "", rev: rev, failed: rev == ""}
		}
	}
}

// watermark is the evidence a clear or a no-verdict check leaves on a link:
// the source and revision of the data that was checked.
func watermark(d distroData) []byte {
	b, _ := json.Marshal(struct {
		Source       string `json:"source"`
		SourceID     string `json:"source_id"`
		DataModified string `json:"data_modified"`
	}{model.DistroSourceOSV, d.sourceID, d.revision})
	return b
}

type distroLinkStore interface {
	SettleDistroNoVerdictOutcome(ctx context.Context, componentID, vulnID uuid.UUID, watermark []byte) (changed, stillDistro bool, err error)
	ClearDistroWithdrawn(ctx context.Context, componentID, vulnID uuid.UUID, p []byte) (bool, error)
	ListScanTargetsBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error)
	ListSbomLinks(ctx context.Context, sbomID uuid.UUID) ([]repository.SbomLink, error)
	RelabelDistro(ctx context.Context, componentID, vulnID uuid.UUID, method model.MatchMethod, evidence []byte) (bool, error)
}

// distroFetcher is the OSV surface the step uses.
type distroFetcher interface {
	GetRecordState(ctx context.Context, id string) (client.OSVRecordState, error)
	QueryPackageEach(ctx context.Context, ecosystem, name string, lim client.PackageQueryLimits,
		before func(context.Context) error, onPage func([]client.OSVPackageRecord) error) (int, error)
}

// DistroService is the distro step. It satisfies the handlers'
// componentScanner (ScanComponents).
type DistroService struct {
	store distroLinkStore
	osv   distroFetcher
	// source is the endpoint as shown in evidence (no credentials);
	// sourceID identifies it exactly (cache keys, revision guards).
	source   string
	sourceID string
	cache    *cache.DistroCache
	offline  bool
	gap      time.Duration
	now      func() time.Time
}

// NewDistroService builds the step. osvBaseURL "" is OSV's public API;
// offline (SBOMHUB_OFFLINE) disables every request.
func NewDistroService(cr *repository.ComponentRepository, osvBaseURL string, distroCache *cache.DistroCache, offline bool) *DistroService {
	return &DistroService{
		store:    cr,
		osv:      client.NewOSVClient().WithBaseURL(osvBaseURL).WithOffline(offline),
		source:   distroSource(osvBaseURL),
		sourceID: distroSourceID(osvBaseURL),
		cache:    distroCache,
		offline:  offline,
		gap:      distroRequestGap,
		now:      time.Now,
	}
}

// DistroScanReport is the accounting of one distro step.
type DistroScanReport struct {
	// LinkedComponents: components with at least one link.
	LinkedComponents int
	// Targeted: linked distro components whose release and package were
	// identified; Untargeted counts the others by reason (not_distro is
	// not counted).
	Targeted   int
	Untargeted map[string]int
	// Packages: distinct (ecosystem, package) queries needed.
	Packages  int
	CacheHits int
	// Requests: OSV HTTP requests made (pages, failed ones included).
	Requests int
	// FetchFailures: packages whose data could not be read.
	FetchFailures int
	// Unfetched: packages never read because the scan's context ended.
	Unfetched int
	// Verdicts by label, and links with no verdict (by reason).
	Affected, Unfixed, Fixed int
	NoVerdict                map[string]int
	// Cleared: links whose stored distro label the current data no longer
	// supports, queued to go back to their earlier method.
	Cleared int
	// LookupFailures: record lookups by id (withdrawal checks) that failed;
	// reported as distro_data_failed.
	LookupFailures int
	// LinksKeptForFailure: links of a package whose data failed.
	LinksKeptForFailure int
	// Relabelled: relabel statements that changed a row (a group later
	// rolled back to its savepoint is not subtracted; 0 when the write
	// transaction failed). RefusedWrites as in NVDScanReport.
	Relabelled    int
	RefusedWrites int

	DeadlineExceeded bool
	Cancelled        bool
}

// ScanComponents runs the step for one SBOM (componentScanner).
func (s *DistroService) ScanComponents(ctx context.Context, sbomID uuid.UUID) error {
	_, err := s.ScanComponentsWithReport(ctx, sbomID)
	return err
}

// ScanComponentsWithReport is ScanComponents with the accounting.
func (s *DistroService) ScanComponentsWithReport(ctx context.Context, sbomID uuid.UUID) (DistroScanReport, error) {
	rep := DistroScanReport{Untargeted: map[string]int{}, NoVerdict: map[string]int{}}
	scope, err := scanScopeFrom(ctx)
	if err != nil {
		return rep, err
	}
	if s.offline {
		slog.Info("scan skipped: offline mode", "source", "distro")
		return rep, nil
	}

	// Phase 1 — read.
	var comps []model.Component
	var links []repository.SbomLink
	if err := scope.readTx(ctx, func(txCtx context.Context) error {
		var lerr error
		if comps, lerr = s.store.ListScanTargetsBySbom(txCtx, sbomID); lerr != nil {
			return lerr
		}
		links, lerr = s.store.ListSbomLinks(txCtx, sbomID)
		return lerr
	}); err != nil {
		return rep, fmt.Errorf("distro: read components and links: %w", err)
	}
	byComp := map[uuid.UUID][]repository.SbomLink{}
	for _, l := range links {
		byComp[l.ComponentID] = append(byComp[l.ComponentID], l)
	}
	os := sbomOperatingSystem(comps)

	var work []distroWork
	keys := map[distroFetchKey]bool{}
	for _, c := range comps {
		if len(byComp[c.ID]) == 0 {
			continue
		}
		rep.LinkedComponents++
		t, reason := distroTargetFor(c.Purl, c.Version, os)
		if reason == "" && !cpeVersionsAgree(c.CPEs, c.Version) {
			reason = "cpe_version_conflict"
		}
		if reason == "" && !purlNameAgrees(c.Purl, c.Name) {
			reason = "name_mismatch"
		}
		if reason != "" {
			if reason != "not_distro" && reason != "no_purl" {
				rep.Untargeted[reason]++
			}
			continue
		}
		rep.Targeted++
		work = append(work, distroWork{comp: c, target: t})
		keys[t.fetchKey()] = true
	}
	rep.Packages = len(keys)
	if len(work) == 0 {
		s.logSummary(sbomID, rep)
		return rep, nil
	}

	// Phase 2 — fetch and decide, no transaction.
	groups, err := s.fetchAndDecide(ctx, work, byComp, &rep)
	if err != nil {
		return rep, err
	}

	// Phase 3 — write, in one fixed row order (component, then
	// vulnerability) whatever order the fetches completed in (Codex M70 R32
	// Medium-3: concurrent writers lock rows in a consistent order).
	sortPendingGroups(groups)
	var tally writeTally
	refused, _, werr := scope.writeLinksReporting(ctx, sbomID, groups, func(txCtx context.Context, l pendingLink) error {
		var changed, stillDistro bool
		var err error
		switch {
		case l.withdrawnClear:
			changed, err = s.store.ClearDistroWithdrawn(txCtx, l.componentID, l.vulnID, l.evidence)
		case l.noVerdict:
			changed, stillDistro, err = s.store.SettleDistroNoVerdictOutcome(txCtx, l.componentID, l.vulnID, l.evidence)
		default:
			changed, err = s.store.RelabelDistro(txCtx, l.componentID, l.vulnID, l.method, l.evidence)
			stillDistro = true
		}
		if err == nil {
			tally.note(l, changed, stillDistro)
		}
		return err
	}, tally.groupDone)
	if werr != nil {
		slog.Warn("distro: write phase failed; no relabel of this step was committed", "sbom_id", sbomID, "error", werr)
		tally = writeTally{}
	}
	rep.RefusedWrites = refused
	rep.Relabelled = tally.relabelled
	rep.Cleared = tally.cleared
	s.logSummary(sbomID, rep)
	return rep, rep.incompleteErr()
}

// writeTally counts what the write phase did, per savepoint group: a
// group's counts are published only when its savepoint is released (and
// discarded by the caller if the transaction then fails).
type writeTally struct {
	relabelled, cleared int // published
	curR, curC          int // the current group's
}

// note records one successful write: changed rows count as relabelled;
// a settlement of a link read under a distro label that no longer carries
// one cleared it.
func (t *writeTally) note(l pendingLink, changed, stillDistro bool) {
	if !changed {
		return
	}
	t.curR++
	if (l.noVerdict || l.withdrawnClear) && l.wasDistro && !stillDistro {
		t.curC++
	}
}

func (t *writeTally) groupDone(released bool) {
	if released {
		t.relabelled += t.curR
		t.cleared += t.curC
	}
	t.curR, t.curC = 0, 0
}

// sortPendingGroups orders the groups by component id and each group's
// links by vulnerability id.
func sortPendingGroups(groups [][]pendingLink) {
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool { return bytes.Compare(g[i].vulnID[:], g[j].vulnID[:]) < 0 })
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if len(groups[i]) == 0 || len(groups[j]) == 0 {
			return len(groups[i]) > len(groups[j])
		}
		return bytes.Compare(groups[i][0].componentID[:], groups[j][0].componentID[:]) < 0
	})
}

// distroWork is one targeted component.
type distroWork struct {
	comp   model.Component
	target distroTarget
}

// fetchAndDecide loads each package's data (cache or OSV) and decides every
// component of that package AT ONCE, keeping only the pending relabels: the
// package's records are dropped before the next package is loaded by that
// worker, so retained memory is the relabels, not the data (Codex M70 R5
// High-2). The process-wide slot (distroQuerySlots) bounds the data held at
// any moment across all scans.
func (s *DistroService) fetchAndDecide(ctx context.Context, work []distroWork, byComp map[uuid.UUID][]repository.SbomLink,
	rep *DistroScanReport) ([][]pendingLink, error) {
	byKey := map[distroFetchKey][]distroWork{}
	for _, w := range work {
		k := w.target.fetchKey()
		byKey[k] = append(byKey[k], w)
	}
	ordered := make([]distroFetchKey, 0, len(byKey))
	for k := range byKey {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ecosystem != ordered[j].ecosystem {
			return ordered[i].ecosystem < ordered[j].ecosystem
		}
		return ordered[i].pkg < ordered[j].pkg
	})

	var groups [][]pendingLink
	var firstErr error
	pace := s.pacer()
	var mu sync.Mutex
	var wg sync.WaitGroup
	keyCh := make(chan distroFetchKey)
	for i := 0; i < distroWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range keyCh {
				if ctx.Err() != nil {
					mu.Lock()
					rep.Unfetched++
					mu.Unlock()
					continue
				}
				var g [][]pendingLink
				var counts DistroScanReport
				var derr error
				hit, pages, ferr := s.loadSlotted(ctx, k, pace, func(l distroLoad) error {
					d := l.data()
					d.source, d.sourceID = s.source, s.sourceID
					g, counts, derr = decideKey(ctx, d, l.fetchedAt, byKey[k], byComp, s.withdrawalResolver(ctx, pace))
					return nil
				})
				mu.Lock()
				rep.Requests += pages
				if hit {
					rep.CacheHits++
				}
				switch {
				case ferr != nil && scanInterruption(ctx) != nil:
					rep.Unfetched++
				case ferr != nil:
					slog.Warn("distro: could not read the distro's fixed-version data; its links keep their labels",
						"ecosystem", k.ecosystem, "package", k.pkg, "error", ferr)
					rep.FetchFailures++
					for _, w := range byKey[k] {
						rep.LinksKeptForFailure += len(byComp[w.comp.ID])
					}
				default:
					groups = append(groups, g...)
					rep.Affected += counts.Affected
					rep.LookupFailures += counts.LookupFailures
					rep.Unfixed += counts.Unfixed
					rep.Fixed += counts.Fixed
					for r, n := range counts.NoVerdict {
						rep.NoVerdict[r] += n
					}
					if derr != nil && firstErr == nil {
						firstErr = derr
					}
				}
				mu.Unlock()
			}
		}()
	}
	for _, k := range ordered {
		keyCh <- k
	}
	close(keyCh)
	wg.Wait()
	// Ended while fetching or deciding: what is decided is written, and the
	// step reports the interruption (Codex M70 R4 Medium-5).
	rep.noteInterruption(ctx)
	return groups, firstErr
}

// decideKey decides every link of the components of one package.
func decideKey(ctx context.Context, d distroData, fetchedAt time.Time, work []distroWork,
	byComp map[uuid.UUID][]repository.SbomLink, lookupFor func(family, pkg string) func(string) recordState) ([][]pendingLink, DistroScanReport, error) {
	counts := DistroScanReport{NoVerdict: map[string]int{}}
	var groups [][]pendingLink
	// One encoded watermark per package, one encoded evidence per (target,
	// CVE): links of duplicate components share the bytes (Codex M70 R22
	// High-3).
	wm := watermark(d)
	memo := map[string][]byte{}
	for _, w := range work {
		if ctx.Err() != nil {
			break
		}
		var g []pendingLink
		var lookup func(string) recordState
		if lookupFor != nil {
			lookup = lookupFor(w.target.query, w.target.pkg)
		}
		for _, l := range byComp[w.comp.ID] {
			if ctx.Err() != nil { // Codex M70 R26 Medium-2
				break
			}
			dec := d.decide(w.target, l.CVEID)
			if dec.verdict == verdictNone {
				counts.NoVerdict[dec.reason]++
				// Settled on the row as it is when written (clear a distro
				// label / leave the watermark): Codex M70 R22 High-1.
				if pl, ok := d.settleNoVerdict(l, wm, lookup, &counts); ok {
					g = append(g, pl)
				}
				continue
			}
			mk := w.target.release + "\x00" + w.target.pkg + "\x00" + w.target.version + "\x00" + w.target.binary + "\x00" + l.CVEID
			raw, seen := memo[mk]
			if !seen {
				dec.evidence.FetchedAt = fetchedAt.UTC()
				b, err := json.Marshal(dec.evidence)
				if err != nil {
					return groups, counts, fmt.Errorf("distro: encode evidence: %w", err)
				}
				if len(b) > maxEvidenceBytes {
					// Too large to store: settled as no verdict, which still
					// clears a stale label and advances the watermark (Codex
					// M70 R23 High-1).
					b = nil
				}
				raw, memo[mk] = b, b
			}
			if raw == nil {
				counts.NoVerdict["evidence_too_large"]++
				// The same settlement as any no verdict (Codex M70 R24 Low-4,
				// R26 High-1).
				if pl, ok := d.settleNoVerdict(l, wm, lookup, &counts); ok {
					g = append(g, pl)
				}
				continue
			}
			switch dec.verdict {
			case verdictAffected:
				counts.Affected++
			case verdictUnfixed:
				counts.Unfixed++
			case verdictFixed:
				counts.Fixed++
			}
			g = append(g, pendingLink{componentID: l.ComponentID, vulnID: l.VulnerabilityID, method: dec.verdict.method(), evidence: raw})
		}
		if len(g) > 0 {
			groups = append(groups, g)
		}
	}
	return groups, counts, nil
}

// noteInterruption records that the scan's context has ended (deadline or
// cancellation), whatever phase noticed it.
func (r *DistroScanReport) noteInterruption(ctx context.Context) {
	switch cause := scanInterruption(ctx); {
	case cause == nil:
	case errors.Is(cause, ErrScanDeadlineExceeded):
		r.DeadlineExceeded = true
	default:
		r.Cancelled = true
	}
}

// incompleteErr names every reason the step is incomplete.
func (r DistroScanReport) incompleteErr() error {
	var errs []error
	if r.RefusedWrites > 0 {
		errs = append(errs, fmt.Errorf("distro: database refused %d relabel(s): %w", r.RefusedWrites, ErrScanWriteRefused))
	}
	if r.DeadlineExceeded {
		errs = append(errs, fmt.Errorf("distro: the scan deadline fired with %d of %d package(s) unread: %w",
			r.Unfetched, r.Packages, ErrScanDeadlineExceeded))
	}
	if r.Cancelled {
		errs = append(errs, fmt.Errorf("distro: the scan was cancelled with %d of %d package(s) unread: %w",
			r.Unfetched, r.Packages, ErrScanCancelled))
	}
	if r.LookupFailures > 0 {
		errs = append(errs, fmt.Errorf("distro: %d record lookup(s) by id failed; the labels they would have cleared were kept: %w",
			r.LookupFailures, ErrScanDistroDataFailed))
	}
	if r.FetchFailures > 0 {
		errs = append(errs, fmt.Errorf("distro: the fixed-version data of %d of %d package(s) could not be read; "+
			"their %d link(s) keep their previous labels: %w", r.FetchFailures, r.Packages, r.LinksKeptForFailure,
			ErrScanDistroDataFailed))
	}
	return errors.Join(errs...)
}

func (s *DistroService) logSummary(sbomID uuid.UUID, r DistroScanReport) {
	args := []any{
		"sbom_id", sbomID, "linked_components", r.LinkedComponents, "targeted", r.Targeted,
		"untargeted", r.Untargeted, "packages", r.Packages, "cache_hits", r.CacheHits, "requests", r.Requests,
		"fetch_failures", r.FetchFailures, "unfetched", r.Unfetched,
		"affected", r.Affected, "unfixed", r.Unfixed, "fixed", r.Fixed, "no_verdict", r.NoVerdict,
		"cleared", r.Cleared, "relabelled", r.Relabelled, "refused_writes", r.RefusedWrites,
		"deadline_exceeded", r.DeadlineExceeded, "cancelled", r.Cancelled,
	}
	if r.FetchFailures > 0 || r.Unfetched > 0 || r.RefusedWrites > 0 {
		slog.Warn("distro: step completed with incomplete coverage", args...)
		return
	}
	slog.Info("distro: step completed", args...)
}

// pacer spaces the step's OSV requests by s.gap.
func (s *DistroService) pacer() func(context.Context) error {
	var mu sync.Mutex
	var last time.Time
	return func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if wait := s.gap - time.Since(last); !last.IsZero() && wait > 0 {
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
		last = time.Now()
		return ctx.Err()
	}
}

// distroQuerySlots bounds the package queries in flight across the WHOLE
// process (every scan, upload and manual alike), so overlapping scans cannot
// multiply the per-query memory bound (Codex M70 R2 High-3).
var distroQuerySlots = make(chan struct{}, 2)

// distroSourceID identifies the configured endpoint exactly, credentials and
// query included, as an opaque hash: two mirrors that differ only in their
// credentials share no cache entry and no revision order (Codex M70 R13
// Medium-5).
func distroSourceID(osvBaseURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(osvBaseURL), "/")
	if raw == "" {
		raw = client.DefaultOSVBaseURL
	}
	sum := sha256.Sum256([]byte("osv\x00" + raw))
	return hex.EncodeToString(sum[:16])
}

// notFuture: a revision no later than a day from now (Codex M70 R14 High-1).
func notFuture(rev string) bool {
	if rev == "" {
		return true
	}
	ts, err := time.Parse(time.RFC3339Nano, rev)
	return err == nil && !ts.After(time.Now().Add(24*time.Hour))
}

// distroSource is an OSV endpoint as SHOWN in evidence (source_url): its
// origin, scheme://host[:port], only — no credentials, path (which may carry
// a token), query or fragment ever reach a tenant through the API (Codex M70
// R12 High-4, R14 High-5).
func distroSource(osvBaseURL string) string {
	raw := strings.TrimSpace(osvBaseURL)
	if raw == "" {
		raw = client.DefaultOSVBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "configured-endpoint"
	}
	return u.Scheme + "://" + u.Host
}

// distroCachePayload is what the cache entry holds for one package.
type distroCachePayload struct {
	Version int            `json:"v"`
	Records []distroRecord `json:"records"`
	// IDs: every record id the query returned, reduced away or not (Codex
	// M70 R34 High-1).
	IDs []string `json:"ids"`
}

// distroLoad is one package's data as loaded.
type distroLoad struct {
	recs []distroRecord
	// ids: every record id the query returned, including records the
	// reduction dropped (no CVE identity, withdrawn, other packages only):
	// a record in the answer is not absent from it (Codex M70 R34 High-1).
	ids       []string
	fetchedAt time.Time
	// revision is the data's snapshot revision (rawRevision of the query).
	revision string
}

// data indexes the records under the load's revision.
func (l distroLoad) data() distroData {
	d := indexDistroRecords(l.recs)
	for _, id := range l.ids {
		d.ids[id] = true
	}
	if l.revision > d.revision {
		d.revision = l.revision
	}
	return d
}

// load returns one package's reduced records: from the cache, or from OSV
// (and then cached). It never returns a partial answer. It holds no slot
// itself; callers in a scan go through loadSlotted.
func (s *DistroService) load(ctx context.Context, k distroFetchKey, pace func(context.Context) error) (l distroLoad, hit bool, pages int, err error) {
	if c, ok := s.cachedLoad(ctx, k); ok {
		return c, true, 0, nil
	}
	return s.loadFetch(ctx, k, pace)
}

// cachedLoad returns the cached data of k when there is a usable entry.
func (s *DistroService) cachedLoad(ctx context.Context, k distroFetchKey) (distroLoad, bool) {
	e, cerr := s.cache.Get(ctx, s.sourceID, k.ecosystem, k.pkg)
	if cerr != nil {
		slog.Debug("distro cache get error", "ecosystem", k.ecosystem, "package", k.pkg, "error", cerr)
		return distroLoad{}, false
	}
	if e == nil {
		return distroLoad{}, false
	}
	var p distroCachePayload
	if json.Unmarshal(e.Payload, &p) != nil || p.Version != distroCachePayloadVersion || !validDistroRecords(p.Records) ||
		!validRecordIDs(p.IDs, p.Records) || !notFuture(e.DataModified) {
		return distroLoad{}, false
	}
	return distroLoad{recs: p.Records, ids: p.IDs, fetchedAt: e.FetchedAt, revision: e.DataModified}, true
}

// loadFetch fetches k from OSV and offers the answer to the cache. When the
// cache keeps a NEWER answer (another scan stored it meanwhile), that answer
// is used instead of this one; when it cannot then be read back, the package
// fails rather than decide on data known to be older (Codex M70 R21 High-1).
func (s *DistroService) loadFetch(ctx context.Context, k distroFetchKey, pace func(context.Context) error) (l distroLoad, hit bool, pages int, err error) {
	// The generation is taken BEFORE the request: a fetch that started later
	// saw the source at least as new, so it wins in the cache (Codex M70 R9
	// High-2).
	generation := s.cache.NextGeneration(ctx)
	// Each page is reduced as it arrives; only this package's entries are
	// kept, but the revision counts every record returned.
	walk := func() (w distroLoad, fp map[string]string, n int, err error) {
		fp = map[string]string{}
		n, err = s.osv.QueryPackageEach(ctx, k.ecosystem, k.pkg,
			client.PackageQueryLimits{MaxPages: distroMaxPages, MaxTotalBytes: distroMaxBytesPerPackage}, pace,
			func(page []client.OSVPackageRecord) error {
				w.recs = append(w.recs, reduceOSVRecords(page, k.pkg)...)
				if r := rawRevision(page); r > w.revision {
					w.revision = r
				}
				for _, r := range page {
					fp[r.ID] = r.Modified + "|" + r.Withdrawn
					w.ids = append(w.ids, r.ID)
				}
				return nil
			})
		return w, fp, n, err
	}
	l, fp, pages, err := walk()
	if err != nil {
		return distroLoad{}, false, pages, err
	}
	// OSV pages are separate queries resumed from a cursor, not one
	// snapshot: a record can change between pages, and the pages then mix
	// revisions (Codex M70 R30 High-1). A multi-page answer is accepted only
	// when two consecutive complete walks agree on every record's id,
	// modified and withdrawn.
	for walks := 1; pages > 1; walks++ {
		if walks >= distroConsistencyWalks {
			return distroLoad{}, false, pages, fmt.Errorf("distro: %s %q changed while its %d pages were read, %d times", k.ecosystem, k.pkg, pages, walks-1)
		}
		next, nfp, npages, nerr := walk()
		pages += npages
		if nerr != nil {
			return distroLoad{}, false, pages, nerr
		}
		same := len(nfp) == len(fp)
		for id, v := range nfp {
			same = same && fp[id] == v
		}
		l, fp = next, nfp
		if same {
			break
		}
	}
	l.fetchedAt = s.now().UTC()
	payload, merr := json.Marshal(distroCachePayload{Version: distroCachePayloadVersion, Records: l.recs, IDs: l.ids})
	if merr == nil && generation != "" {
		// No generation (Redis unreachable when the fetch started): not
		// cached, since its order against other writes is unknown (Codex
		// M70 R13 Medium-6).
		won, serr := s.cache.Set(ctx, s.sourceID, k.ecosystem, k.pkg, cache.DistroCacheEntry{FetchedAt: l.fetchedAt, Payload: payload,
			DataModified: l.revision, Generation: generation})
		switch {
		case serr != nil:
			slog.Debug("distro cache set error", "ecosystem", k.ecosystem, "package", k.pkg, "error", serr)
		case !won:
			winner, ok := s.cachedLoad(ctx, k)
			if !ok || winner.revision < l.revision {
				return distroLoad{}, false, pages, fmt.Errorf("distro: a newer cached answer for %s %q exists but could not be read", k.ecosystem, k.pkg)
			}
			return winner, false, pages, nil
		}
	}
	return l, false, pages, nil
}

// distroConsistencyWalks bounds the complete walks of one multi-page
// package answer (two must agree).
const distroConsistencyWalks = 3

// loadSlotted loads one package and hands it to use, holding one
// process-wide slot (distroQuerySlots) from before the cache read until use
// has returned: the slot bounds every package's data that is decoded or in
// use across all scans, not only the loading (Codex M70 R3 High-6, R6
// High-1). The data must not be retained past use.
func (s *DistroService) loadSlotted(ctx context.Context, k distroFetchKey, pace func(context.Context) error,
	use func(distroLoad) error) (hit bool, pages int, err error) {
	select {
	case distroQuerySlots <- struct{}{}:
	case <-ctx.Done():
		return false, 0, ctx.Err()
	}
	defer func() { <-distroQuerySlots }()
	l, hit, pages, err := s.load(ctx, k, pace)
	if err != nil {
		return hit, pages, err
	}
	return hit, pages, use(l)
}

// validRecordIDs: the cached id list is unique, bounded, canonical, and
// covers every cached record.
func validRecordIDs(ids []string, recs []distroRecord) bool {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] || !client.CanonicalOSVID(id) {
			return false
		}
		seen[id] = true
	}
	for _, r := range recs {
		if !seen[r.ID] {
			return false
		}
	}
	return true
}

// validDistroRecords rejects a cache entry that does not look like one this
// build wrote (the cache is shared and outlives builds).
func validDistroRecords(recs []distroRecord) bool {
	seen := map[string]bool{}
	for _, r := range recs {
		if seen[r.ID] {
			return false // ids are unique in an answer (Codex M70 R21 High-2)
		}
		seen[r.ID] = true
		if len(r.ID) > client.MaxOSVFieldBytes || !boundedEntries(r.Entries) {
			return false // the field bounds the client enforces (R22)
		}
		if strings.TrimSpace(r.ID) == "" || len(r.CVEs) == 0 || len(r.Entries) == 0 || r.Releases < 1 || r.Packages < 1 ||
			r.Modified == "" || normaliseModified(r.Modified) != r.Modified || !notFuture(r.Modified) {
			return false
		}
		for _, c := range r.CVEs {
			if !isCVEID(c) {
				return false
			}
		}
	}
	return true
}

// boundedEntries: every string of the entries within client.MaxOSVFieldBytes.
func boundedEntries(es []distroEntry) bool {
	ok := func(s string) bool { return len(s) <= client.MaxOSVFieldBytes }
	for _, e := range es {
		if !ok(e.Ecosystem) {
			return false
		}
		for _, v := range append(append([]string(nil), e.Versions...), e.Binaries...) {
			if !ok(v) {
				return false
			}
		}
		for _, r := range e.Ranges {
			for _, ev := range r.Events {
				if !ok(ev.Introduced) || !ok(ev.Fixed) || !ok(ev.LastAffected) || !ok(ev.Limit) {
					return false
				}
			}
		}
	}
	return true
}

// sbomOperatingSystem returns the SBOM's own operating system when it declares
// exactly one (Syft: type "operating-system", name "debian", version "11").
// Several, or none: nil — a package without a distro qualifier then has no
// release, rather than a guessed one.
func sbomOperatingSystem(comps []model.Component) *distroOS {
	var found *distroOS
	for _, c := range comps {
		if c.Type != "operating-system" {
			continue
		}
		if found != nil {
			return nil
		}
		// As stored: no trimming or case-folding (Codex M70 R19 Medium-3).
		if !cleanVersionText(c.Name) || !cleanVersionText(c.Version) || c.Name != strings.ToLower(c.Name) {
			return nil
		}
		found = &distroOS{id: c.Name, version: c.Version}
	}
	if found == nil || found.id == "" || found.version == "" {
		return nil
	}
	return found
}
