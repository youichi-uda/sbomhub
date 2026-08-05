package handler

import "testing"

// TestM54ParseScanSources is the unit-level pin for the `?sources=` vocabulary
// (Codex M54 R4, Critical).
//
// The defect it guards against is not "a typo is accepted". It is that the
// vocabulary was written down TWICE — Scan accepted any non-empty string,
// runScan compared against four literals — so every value in the gap between
// the two produced a 202 "Vulnerability scan started" for a scan that then
// selected no scanner, invoked nothing, and (this route has no ScanTracker)
// reported that to nobody. One function is now the only definition, and Scan
// rejects what it does not recognise.
//
// The "rejected" rows below are the realistic near-misses: wrong case, an
// added space, a plausible synonym, a separator that is not a comma.
func TestM54ParseScanSources(t *testing.T) {
	accepted := map[string]struct{ nvd, jvn bool }{
		"nvd":     {true, false},
		"jvn":     {false, true},
		"nvd,jvn": {true, true},
		"jvn,nvd": {true, true},
	}
	for in, want := range accepted {
		gotNVD, gotJVN, ok := parseScanSources(in)
		if !ok {
			t.Errorf("parseScanSources(%q) rejected a documented value", in)
			continue
		}
		if gotNVD != want.nvd || gotJVN != want.jvn {
			t.Errorf("parseScanSources(%q) = (nvd=%v, jvn=%v), want (nvd=%v, jvn=%v)",
				in, gotNVD, gotJVN, want.nvd, want.jvn)
		}
	}

	rejected := []string{
		"", "NVD", "JVN", "Nvd,Jvn", "nvd, jvn", "nvd;jvn", "nvd,jvn,osv",
		"osv", "all", "both", " nvd", "nvd ", "nvd,nvd",
	}
	for _, in := range rejected {
		nvd, jvn, ok := parseScanSources(in)
		if ok {
			t.Errorf("parseScanSources(%q) was accepted; the documented vocabulary is "+
				"exactly nvd / jvn / nvd,jvn / jvn,nvd", in)
			continue
		}
		// The contract on the reject path matters as much as `ok`: a caller
		// that ignores ok must not be handed a selection that looks valid.
		if nvd || jvn {
			t.Errorf("parseScanSources(%q) returned ok=false but selected a scanner "+
				"(nvd=%v, jvn=%v)", in, nvd, jvn)
		}
	}

	// The default must itself be accepted — it is substituted before the check
	// in Scan, so a drift here would 400 every request that omits ?sources=.
	if _, _, ok := parseScanSources(scanSourcesDefault); !ok {
		t.Errorf("scanSourcesDefault (%q) is not accepted by parseScanSources; every request "+
			"that omits ?sources= would be rejected", scanSourcesDefault)
	}
}
