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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	// 4: record modified, R8).
	distroCachePayloadVersion = 4
)

// distroLinkStore is the repository surface the step uses.
type distroLinkStore interface {
	ListScanTargetsBySbom(ctx context.Context, sbomID uuid.UUID) ([]model.Component, error)
	ListSbomLinks(ctx context.Context, sbomID uuid.UUID) ([]repository.SbomLink, error)
	RelabelDistro(ctx context.Context, componentID, vulnID uuid.UUID, method model.MatchMethod, evidence []byte) (bool, error)
}

// distroFetcher is the OSV surface the step uses.
type distroFetcher interface {
	QueryPackageEach(ctx context.Context, ecosystem, name string, lim client.PackageQueryLimits,
		before func(context.Context) error, onPage func([]client.OSVPackageRecord) error) (int, error)
}

// DistroService is the distro step. It satisfies the handlers'
// componentScanner (ScanComponents).
type DistroService struct {
	store distroLinkStore
	osv   distroFetcher
	// source identifies the data source in cache keys (the OSV endpoint).
	source  string
	cache   *cache.DistroCache
	offline bool
	gap     time.Duration
	now     func() time.Time
}

// NewDistroService builds the step. osvBaseURL "" is OSV's public API;
// offline (SBOMHUB_OFFLINE) disables every request.
func NewDistroService(cr *repository.ComponentRepository, osvBaseURL string, distroCache *cache.DistroCache, offline bool) *DistroService {
	return &DistroService{
		store:   cr,
		osv:     client.NewOSVClient().WithBaseURL(osvBaseURL).WithOffline(offline),
		source:  distroSource(osvBaseURL),
		cache:   distroCache,
		offline: offline,
		gap:     distroRequestGap,
		now:     time.Now,
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

	// Phase 3 — write.
	relabelled := 0
	refused, _, werr := scope.writeLinks(ctx, sbomID, groups, func(txCtx context.Context, l pendingLink) error {
		changed, err := s.store.RelabelDistro(txCtx, l.componentID, l.vulnID, l.method, l.evidence)
		if changed {
			relabelled++
		}
		return err
	})
	if werr != nil {
		slog.Warn("distro: write phase failed; no relabel of this step was committed", "sbom_id", sbomID, "error", werr)
		relabelled = 0
	}
	rep.RefusedWrites = refused
	rep.Relabelled = relabelled
	s.logSummary(sbomID, rep)
	return rep, rep.incompleteErr()
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
					g, counts, derr = decideKey(ctx, l.data(), l.fetchedAt, byKey[k], byComp)
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
	byComp map[uuid.UUID][]repository.SbomLink) ([][]pendingLink, DistroScanReport, error) {
	counts := DistroScanReport{NoVerdict: map[string]int{}}
	var groups [][]pendingLink
	for _, w := range work {
		if ctx.Err() != nil {
			break
		}
		var g []pendingLink
		for _, l := range byComp[w.comp.ID] {
			dec := d.decide(w.target, l.CVEID)
			if dec.verdict == verdictNone {
				counts.NoVerdict[dec.reason]++
				continue
			}
			dec.evidence.FetchedAt = fetchedAt.UTC()
			raw, err := json.Marshal(dec.evidence)
			if err != nil {
				return groups, counts, fmt.Errorf("distro: encode evidence: %w", err)
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
		"relabelled", r.Relabelled, "refused_writes", r.RefusedWrites,
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

// distroSource is the cache identity of an OSV endpoint.
func distroSource(osvBaseURL string) string {
	if strings.TrimSpace(osvBaseURL) == "" {
		return client.DefaultOSVBaseURL
	}
	return strings.TrimRight(strings.TrimSpace(osvBaseURL), "/")
}

// distroCachePayload is what the cache entry holds for one package.
type distroCachePayload struct {
	Version int            `json:"v"`
	Records []distroRecord `json:"records"`
}

// distroLoad is one package's data as loaded.
type distroLoad struct {
	recs      []distroRecord
	fetchedAt time.Time
	// revision is the data's snapshot revision (rawRevision of the query).
	revision string
}

// data indexes the records under the load's revision.
func (l distroLoad) data() distroData {
	d := indexDistroRecords(l.recs)
	if l.revision > d.revision {
		d.revision = l.revision
	}
	return d
}

// load returns one package's reduced records: from the cache, or from OSV
// (and then cached). It never returns a partial answer. It holds no slot
// itself; callers in a scan go through loadSlotted.
func (s *DistroService) load(ctx context.Context, k distroFetchKey, pace func(context.Context) error) (l distroLoad, hit bool, pages int, err error) {
	if e, cerr := s.cache.Get(ctx, s.source, k.ecosystem, k.pkg); cerr != nil {
		slog.Debug("distro cache get error", "ecosystem", k.ecosystem, "package", k.pkg, "error", cerr)
	} else if e != nil {
		var p distroCachePayload
		if json.Unmarshal(e.Payload, &p) == nil && p.Version == distroCachePayloadVersion && validDistroRecords(p.Records) {
			return distroLoad{recs: p.Records, fetchedAt: e.FetchedAt, revision: e.DataModified}, true, 0, nil
		}
	}
	// The generation is taken BEFORE the request: a fetch that started later
	// saw the source at least as new, so it wins in the cache (Codex M70 R9
	// High-2).
	generation := s.cache.NextGeneration(ctx)
	// Each page is reduced as it arrives; only this package's entries are
	// kept, but the revision counts every record returned.
	pages, err = s.osv.QueryPackageEach(ctx, k.ecosystem, k.pkg,
		client.PackageQueryLimits{MaxPages: distroMaxPages, MaxTotalBytes: distroMaxBytesPerPackage}, pace,
		func(page []client.OSVPackageRecord) error {
			l.recs = append(l.recs, reduceOSVRecords(page, k.pkg)...)
			if r := rawRevision(page); r > l.revision {
				l.revision = r
			}
			return nil
		})
	if err != nil {
		return distroLoad{}, false, pages, err
	}
	l.fetchedAt = s.now().UTC()
	payload, merr := json.Marshal(distroCachePayload{Version: distroCachePayloadVersion, Records: l.recs})
	if merr == nil {
		if serr := s.cache.Set(ctx, s.source, k.ecosystem, k.pkg, cache.DistroCacheEntry{FetchedAt: l.fetchedAt, Payload: payload,
			DataModified: l.revision, Generation: generation}); serr != nil {
			slog.Debug("distro cache set error", "ecosystem", k.ecosystem, "package", k.pkg, "error", serr)
		}
	}
	return l, false, pages, nil
}

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

// validDistroRecords rejects a cache entry that does not look like one this
// build wrote (the cache is shared and outlives builds).
func validDistroRecords(recs []distroRecord) bool {
	for _, r := range recs {
		if strings.TrimSpace(r.ID) == "" || len(r.CVEs) == 0 || len(r.Entries) == 0 || r.Releases < 1 || r.Packages < 1 {
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

// sbomOperatingSystem returns the SBOM's own operating system when it declares
// exactly one (Syft: type "operating-system", name "debian", version "11").
// Several, or none: nil — a package without a distro qualifier then has no
// release, rather than a guessed one.
func sbomOperatingSystem(comps []model.Component) *distroOS {
	var found *distroOS
	for _, c := range comps {
		if !strings.EqualFold(strings.TrimSpace(c.Type), "operating-system") {
			continue
		}
		if found != nil {
			return nil
		}
		found = &distroOS{id: strings.ToLower(strings.TrimSpace(c.Name)), version: strings.TrimSpace(c.Version)}
	}
	if found == nil || found.id == "" || found.version == "" {
		return nil
	}
	return found
}
