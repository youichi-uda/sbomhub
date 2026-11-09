package service

import (
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
			score := m.CvssData.BaseScore
			as = append(as, cvss.Assessment{
				Version:  v,
				Primary:  strings.EqualFold(strings.TrimSpace(m.Type), "Primary"),
				Score:    &score,
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
