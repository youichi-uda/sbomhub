package model

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The Go vocabulary and the CHECK of the newest migration that defines it
// must be the same set (the comment on MatchMethod: "the two lists must move
// together").
func TestMatchMethodVocabularyMatchesMigration070(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/070_component_vulnerabilities_distro_match.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	i := strings.Index(body, "CHECK ((match_method IS NULL OR match_method IN (")
	if i < 0 {
		t.Fatal("CHECK not found in 070")
	}
	end := strings.Index(body[i:], "))")
	var sqlSet []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(body[i:i+end], -1) {
		sqlSet = append(sqlSet, m[1])
	}
	var goSet []string
	for _, m := range allMatchMethods {
		goSet = append(goSet, string(m))
		if len(m) > 32 {
			t.Errorf("%q does not fit VARCHAR(32)", m)
		}
	}
	sort.Strings(sqlSet)
	sort.Strings(goSet)
	if strings.Join(sqlSet, ",") != strings.Join(goSet, ",") {
		t.Errorf("migration 070 CHECK %v != Go vocabulary %v", sqlSet, goSet)
	}
}

func TestMatchMethodRanksAndConfidence(t *testing.T) {
	for _, c := range []struct {
		m          MatchMethod
		rank, find int
		confidence string
		distro, ok bool
	}{
		{MatchDistroAffected, 6, 6, MatchConfidenceHigh, true, true},
		{MatchDistroUnfixed, 5, 5, MatchConfidenceHigh, true, true},
		{MatchDistroFixed, 4, -1, MatchConfidenceDistroFixed, true, true},
		{MatchNVDCPE, 3, 3, MatchConfidenceHigh, false, true},
		{MatchNVDCPEDistro, 2, 2, MatchConfidenceMedium, false, true},
		{MatchNVDCPEUnverified, 1, 1, MatchConfidenceLow, false, true},
		{MatchNVDKeyword, 1, 1, MatchConfidenceLow, false, true},
		{MatchJVNKeyword, 1, 1, MatchConfidenceLow, false, true},
		{MatchCVESyncKeyword, 1, 1, MatchConfidenceLow, false, true},
		{"", 0, 0, MatchConfidenceUnknown, false, false},
		{"distro_other", 0, 0, MatchConfidenceUnknown, false, false},
	} {
		if c.m.Rank() != c.rank || c.m.FindingRank() != c.find || c.m.Confidence() != c.confidence ||
			c.m.IsDistro() != c.distro || c.m.IsValid() != c.ok {
			t.Errorf("%q: rank=%d find=%d conf=%q distro=%v valid=%v", c.m, c.m.Rank(), c.m.FindingRank(),
				c.m.Confidence(), c.m.IsDistro(), c.m.IsValid())
		}
	}
}

// The relabel lattice: what each method may replace.
func TestWeakerMatchMethods_DistroLattice(t *testing.T) {
	has := func(m MatchMethod, w MatchMethod) bool {
		for _, x := range WeakerMatchMethods(m) {
			if x == string(w) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		writer, stored MatchMethod
		replaces       bool
	}{
		{MatchDistroFixed, MatchNVDCPEUnverified, true},
		{MatchDistroFixed, MatchNVDCPEDistro, true},   // a backport the upstream match cannot see
		{MatchDistroAffected, MatchDistroFixed, true}, // a data correction toward "affected"
		{MatchDistroUnfixed, MatchDistroFixed, true},
		{MatchDistroAffected, MatchDistroUnfixed, true}, // a fix was released since
		{MatchDistroFixed, MatchDistroAffected, false},  // never cleared automatically
		{MatchDistroFixed, MatchDistroUnfixed, false},
		{MatchDistroUnfixed, MatchDistroAffected, false},
		{MatchNVDCPEDistro, MatchDistroFixed, false}, // the NVD writer cannot undo a distro label
		{MatchNVDCPE, MatchDistroFixed, false},
		{MatchNVDCPEUnverified, MatchDistroFixed, false},
		{MatchJVNKeyword, MatchDistroAffected, false},
	} {
		if got := has(c.writer, c.stored); got != c.replaces {
			t.Errorf("%s replaces %s = %v, want %v", c.writer, c.stored, got, c.replaces)
		}
	}
}
