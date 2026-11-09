package service

import (
	"testing"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// Codex M70 R25 High-1: a regressed watermark is overridden only when EVERY
// absent evidence record is conclusively withdrawn; an active record or a
// failed lookup blocks it, and a failed lookup is reported.
func TestM70R25_AllAbsentRecordsMustBeWithdrawn(t *testing.T) {
	d := distroData{byCVE: map[string][]*distroRecord{}, ids: map[string]bool{}, sourceID: "S", revision: "2026-11-01T00:00:00.000000000Z"}
	l := repository.SbomLink{Method: "distro_affected", Records: []string{"R1", "R2"}, WMSource: "S", WMRev: "2026-11-05T00:00:00.000000000Z",
		LabelSource: "S", LabelRev: "2026-11-05T00:00:00.000000000Z"}
	wm := []byte(`{"data_modified":"2026-11-01T00:00:00.000000000Z"}`)
	states := map[string]recordState{
		"R1": {withdrawn: true, rev: "2026-11-08T00:00:00.000000000Z"},
	}
	for name, r2 := range map[string]recordState{
		"active": {},
		"error":  {failed: true},
	} {
		states["R2"] = r2
		got, failed := d.withdrawnClear(l, func(id string) recordState { return states[id] })
		if got != nil {
			t.Errorf("%s R2: withdrawn clear %s", name, got)
		}
		if failed != r2.failed {
			t.Errorf("%s R2: failed=%v", name, failed)
		}
	}
	states["R2"] = recordState{withdrawn: true, rev: "2026-11-07T00:00:00.000000000Z"}
	if got, failed := d.withdrawnClear(l, func(id string) recordState { return states[id] }); got == nil || failed {
		t.Errorf("both withdrawn: %s failed=%v, want a withdrawn clear", got, failed)
	}
	_ = wm
}
