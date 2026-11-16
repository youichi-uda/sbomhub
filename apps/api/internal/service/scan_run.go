package service

import (
	"crypto/rand"
	"encoding/hex"
)

// The scan run (2026-11): an opaque identifier of the scan whose state
// scan-status reports, returned as `scan_run`.
//
// A "scan" here is what scan-status already reports on: a GROUP of
// overlapping runs of one SBOM (M62) — runs that begin while another run of
// the SBOM is active join its group, and the status is terminal only once
// every run of the group has ended. scan_run identifies that group:
//
//   - it gets a NEW value whenever activity starts on the SBOM while no run
//     of it is active: a Begin that starts a new group, and, in the shared
//     store, also any other write that finds the SBOM idle and brings
//     activity — an intent, the rejoin or revival of a run that had lost its
//     identity or been swept as interrupted, a coalesced merge, a late finish
//     (the outcome of a run that was no longer active);
//   - runs that join an active group keep it; it never repeats (random, 64
//     bits, from the API process: no Redis clock, counter or key incarnation
//     is involved);
//   - absent means unknown: a legacy MarkRunning / MarkCompleted /
//     MarkFailed, an entry recreated after it was lost, an answer from this
//     process's memory standing in for the shared state (Redis unreadable,
//     writes pending, a run active here), and — with an older replica in a
//     rolling upgrade — any write by an older replica to the SBOM's key drops
//     it until the next group this version starts.
//
// So two answers that carry the SAME scan_run are about the same scan: no
// activity began on the SBOM between them. Different values, or either one
// absent, prove nothing either way (a client then decides as it did before).
//
// The name: not "generation", which the tracker already uses for ONE run
// (Begin's gen) and which suggests a number to compare by size; not
// "run_id", which would suggest one request's run. scan_run is opaque and
// only compared for equality.

// newScanRunIDFn is newScanRunID (a variable for tests).
var newScanRunIDFn = newScanRunID

// newScanRunID returns a fresh scan run: 16 lowercase hex digits.
func newScanRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("scan tracker: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
