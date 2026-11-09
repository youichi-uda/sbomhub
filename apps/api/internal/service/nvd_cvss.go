package service

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/sbomhub/sbomhub/internal/cvss"
)

// SelectNVDCVSS is the CVSS assessment SBOMHub stores for one NVD record. It
// is the NVD adapter onto cvss.Select (M67) and the ONLY place NVD metrics are
// turned into a score / severity / version: the scanner and search
// (convertEntries) and the CVE sync and catalogue reconcile
// (scheduler.extractCVSSFromMetrics) all call it, so a CVE's stored values no
// longer depend on which path wrote it.
//
// The version is the metrics LIST the assessment came from (cvssMetricV31 ->
// "3.1"), not cvssData.version: the list is how NVD classifies it, and the
// field inside is not reliably present on every mirror.
//
// A CVE without any CVSS metrics (NVD "Awaiting Analysis") yields a nil score
// and UNKNOWN — NOT 0.0, which is a real "None" score (M46 B2).
func SelectNVDCVSS(metrics NVDMetrics) cvss.Selection {
	var as []cvss.Assessment
	add := func(v cvss.Version, list []CvssMetric) {
		for _, m := range list {
			var score *float64
			if !m.CvssData.baseScoreMissing {
				s := m.CvssData.BaseScore
				score = &s
			}
			as = append(as, cvss.Assessment{
				Version:  v,
				Primary:  strings.EqualFold(strings.TrimSpace(m.Type), "Primary"),
				Score:    score,
				Severity: m.CvssData.BaseSeverity,
			})
		}
	}
	add(cvss.V31, metrics.CvssMetricV31)
	add(cvss.V30, metrics.CvssMetricV30)
	add(cvss.V40, metrics.CvssMetricV40)
	add(cvss.V2, metrics.CvssMetricV2)
	return cvss.Select(as)
}

// extractCvss is SelectNVDCVSS without the version, for the callers and tests
// that predate it.
func extractCvss(metrics NVDMetrics) (*float64, string) {
	s := SelectNVDCVSS(metrics)
	return s.Score, s.Severity
}

// scoreToCvss2Severity is cvss.Band on the v2 scale.
func scoreToCvss2Severity(score float64) string {
	return cvss.Band(cvss.V2, score)
}

// UnmarshalJSON records whether baseScore was on the wire (Codex M67 R3,
// High). A plain float64 decodes an absent or null baseScore as 0.0 — a real
// CVSS score ("None") — so an empty v3.1 entry beside a valid v4.0 9.8
// CRITICAL won on version precedence and was stored 0.0 / NONE. An absent
// score now reaches cvss.Select as nil: the entry keeps any rating it states,
// and with none it is not a candidate at all. A baseScore of the wrong type
// is still a decode error, as before.
func (d *CvssData) UnmarshalJSON(b []byte) error {
	type plain CvssData
	var aux struct {
		plain
		BaseScore json.RawMessage `json:"baseScore"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*d = CvssData(aux.plain)
	raw := bytes.TrimSpace(aux.BaseScore)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		d.BaseScore, d.baseScoreMissing = 0, true
		return nil
	}
	return json.Unmarshal(raw, &d.BaseScore)
}
