package service

import (
	"slices"
)

// Scan coverage (2026-11): which data sources a scan actually checked.
//
// "completed" alone never proved coverage: offline mode (SBOMHUB_OFFLINE)
// turns the NVD, JVN and distro steps into no-ops that succeed, a manual
// `POST .../scan?sources=nvd` runs a subset, and SBOMHUB_JVN=off skips JVN.
// scan-status therefore names, for a terminal scan, each source of the
// vocabulary below as exactly one of:
//
//   - checked_sources: its step ran against the live data source (online,
//     switched on, requested) and finished without a failure. A step that had
//     nothing to look up for this SBOM (no components, no distro packages)
//     counts as checked: there was nothing it could have missed. So does a
//     lookup answered from the NVD / distro cache (24h): it is that
//     source's answer, and the findings have always been built from it.
//   - skipped_sources: its step made no request because of configuration or
//     the request — offline mode, SBOMHUB_JVN=off, not in `?sources=`, the
//     scheduled scan (NVD and distro only), or no scanner configured.
//   - neither: its step failed (it is in `error` / `reasons`), or nothing
//     reported its coverage (a run of an older replica, a legacy
//     MarkCompleted / MarkFailed, an interrupted run).
//
// Over a group of overlapping runs (M62) skipped is the union of the runs'
// skips and checked the INTERSECTION of the checks of the runs that reported
// coverage, minus anything skipped: a source is reported checked only when
// every run that said anything about it checked it.

// The scan source vocabulary, in the order checked_sources and
// skipped_sources list them.
const (
	ScanSourceNVD    = "nvd"
	ScanSourceJVN    = "jvn"
	ScanSourceDistro = "distro"
)

// ScanSources is every source an SBOM scan can consult, in report order.
var ScanSources = []string{ScanSourceNVD, ScanSourceJVN, ScanSourceDistro}

// ScanCoverage is what one run reports about its sources.
type ScanCoverage struct {
	// Checked: the sources the run checked (see the file comment). Meaningful
	// only when Reported.
	Checked []string
	// Skipped: the sources the run made no request to because of
	// configuration or the request.
	Skipped []string
	// Reported: the run states its checked sources. False for writers that
	// do not know (legacy Finish / FinishSkipped callers): their run then
	// neither adds to nor narrows the group's checked sources.
	Reported bool
}

// OrderScanSources returns the distinct non-empty names of in, the
// vocabulary first in ScanSources order, then any other name in lexical
// order (a newer replica's source). Never nil.
func OrderScanSources(in []string) []string {
	out := []string{}
	for _, s := range ScanSources {
		if slices.Contains(in, s) {
			out = append(out, s)
		}
	}
	var other []string
	for _, s := range in {
		if s != "" && !slices.Contains(ScanSources, s) && !slices.Contains(other, s) {
			other = append(other, s)
		}
	}
	slices.Sort(other)
	return append(out, other...)
}

// intersectScanSources keeps the names of a that are also in b, in a's order.
func intersectScanSources(a, b []string) []string {
	out := []string{}
	for _, s := range a {
		if slices.Contains(b, s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// withoutScanSources is a minus b, in a's order. Never nil.
func withoutScanSources(a, b []string) []string {
	out := []string{}
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

// normaliseCoverage puts a terminal detail's coverage in report form:
// skipped ordered (nil when empty, so the field stays absent as before);
// checked, when known, ordered, never nil, and without any skipped source
// (skipped wins: an older replica's skip has no matching narrowing of the
// checked sources).
func normaliseCoverage(d *ScanStatusDetail) {
	if len(d.Skipped) > 0 {
		d.Skipped = OrderScanSources(d.Skipped)
	} else {
		d.Skipped = nil
	}
	if d.CheckedKnown {
		d.Checked = OrderScanSources(withoutScanSources(d.Checked, d.Skipped))
	} else {
		d.Checked = nil
	}
}

// groupCoverage folds a finished run's coverage into a group's (the
// in-memory tracker and the coalesced shared writes use it; the Lua scripts
// implement the same rule): skipped is unioned; checked is intersected over
// the runs that reported it.
type groupCoverage struct {
	skipped      []string
	checked      []string
	checkedKnown bool
}

func (g *groupCoverage) add(c ScanCoverage) {
	g.skipped = MergeScanReasons(g.skipped, c.Skipped)
	if !c.Reported {
		return
	}
	if !g.checkedKnown {
		g.checked = intersectScanSources(c.Checked, c.Checked)
		g.checkedKnown = true
		return
	}
	g.checked = intersectScanSources(g.checked, c.Checked)
}
