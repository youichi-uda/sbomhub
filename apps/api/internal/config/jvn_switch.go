package config

import (
	"fmt"
	"strings"
)

// JVNEnabled returns SBOMHUB_JVN: "on" (the default, also when unset) runs the
// JVN (MyJVN) lookup in every SBOM scan that includes it; "off" skips it.
//
// It exists because JPCERT/CC suspended MyJVN on 2026-10-22 with no
// resumption date (https://jvn.jp/nav/info2026102281.html): with JVN on, every
// scan that includes JVN is reported failed (fetch_failed,
// source_unavailable). "off" is the operator's explicit choice to scan without
// JVN; such scans read completed and name JVN in scan-status
// `skipped_sources`, so the narrower coverage is never silent.
//
// Like the M72 settings, any other value refuses startup rather than being
// read as a default the operator did not choose: "false", "0" or "disabled"
// would otherwise have to be guessed at.
func (c *Config) JVNEnabled() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(c.JVNRaw)) {
	case "", "on":
		return true, nil
	case "off":
		return false, nil
	}
	return false, fmt.Errorf("SBOMHUB_JVN=%q: want \"on\" or \"off\"", c.JVNRaw)
}
