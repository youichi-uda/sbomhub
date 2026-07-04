// F405 / M31 (issue #140): Evidence Pack v2 — machine-readable Zip.
//
// This file adds the FormatZip render target ALONGSIDE the pre-existing
// FormatMarkdown path in builder.go. The Markdown path is unchanged; a
// zip REUSES the exact Markdown builder output for its report.md entry
// (so the two formats can never drift) and additionally bundles the
// machine-readable, integrity-verifiable artefacts an auditor / customer
// / authority tool can ingest directly:
//
//	report.md            — the Markdown bundle, verbatim
//	vex.cdx.json         — CycloneDX VEX of the project's VEX statements
//	cra/<type>.<lang>.md — each approved CRA report body
//	meti-assessment.json — METI rows + achieved/total
//	manifest.json        — schema + provenance + per-file SHA-256 + disclaimer
//
// Determinism: the zip is byte-stable for a fixed input + injected
// timestamp — entries are path-sorted, every entry carries a fixed
// modtime, entries are Stored (uncompressed, so the bytes never depend
// on flate internals), and every emitted JSON document uses struct field
// order (stable keys). Every timestamp that lands in the bytes is derived
// from the injected BuildInput.Now, not a live clock: manifest.generated_at
// AND the bundled vex.cdx.json's metadata.timestamp (the VEX is exported via
// ExportCycloneDXVEXAt with z.now, NOT the standalone time.Now() export —
// F408). So two builds with identical project data + identical BuildInput.Now
// produce byte-identical zips, including vex.cdx.json.
package evidence_pack

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sbomhub/sbomhub/internal/repository"
)

// FormatZip bundles the Markdown report plus machine-readable,
// integrity-verifiable artefacts and a hash manifest into a single
// downloadable zip. Requested via BuildInput.Format; the handler maps it
// to Content-Type: application/zip.
const FormatZip = "zip"

// manifestSchema names the on-disk pack contract so a consumer can
// version-detect the layout.
const manifestSchema = "sbomhub.evidence-pack/v2"

// metiAssessmentSchema names the meti-assessment.json contract.
const metiAssessmentSchema = "sbomhub.meti-assessment/v1"

// generatorProvider / generatorModel identify the pack ASSEMBLER in the
// manifest's generated_by block. They describe SBOMHub (the software
// that assembled the pack), NOT an LLM: per-artefact LLM provenance is
// preserved verbatim inside each bundled artefact (report.md entries
// carry "LLM provenance: provider=... model=...", vex.cdx.json carries
// the CycloneDX tool metadata, meti-assessment.json carries each row's
// evaluator/override status + evidence). Surfacing an honest assembler
// identity here keeps the manifest from implying the pack itself was
// model-generated — the pack is a faithful aggregation of already-
// approved artefacts, nothing is inflated.
const (
	generatorProvider = "sbomhub"
	generatorModel    = "evidence-pack-v2"
)

// manifestDisclaimer is the fixed legal disclaimer the manifest carries,
// pinned verbatim by the F405 contract: the pack is submission SUPPORT,
// and the CRA reporting clock start is a human decision (the pack never
// auto-submits and never starts the 24h/72h clock).
const manifestDisclaimer = "This pack is submission support, not legal advice; the 24h/72h CRA reporting clock start is a human decision."

// zipEntryModTime is the fixed modification time stamped on every zip
// entry. A constant (not time.Now) is REQUIRED for byte-determinism:
// two builds of the same input must produce byte-identical zips so the
// golden/byte-equality test is stable and re-generated packs are
// diffable. The value is arbitrary but fixed.
var zipEntryModTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// VEXExporter renders the project's VEX statements as a CycloneDX VEX
// JSON document at a caller-supplied timestamp. Satisfied structurally by
// *service.VEXService via its ExportCycloneDXVEXAt method.
//
// The timestamp is passed in (rather than the exporter reading time.Now())
// so the pack's vex.cdx.json metadata.timestamp is derived from the pack's
// generation time (BuildInput.Now), keeping the zip byte-reproducible for a
// fixed input (F408, issue #140). The standalone VEX export endpoint keeps
// using service.VEXService.ExportCycloneDXVEX (live clock), which is
// unaffected.
//
// The interface is declared HERE (in evidence_pack) rather than importing
// the service package directly so that:
//   - the builder never imports service (which would create an import
//     cycle and drag the whole service graph into the builder's unit
//     tests), and
//   - the zip tests can inject a deterministic fake exporter.
type VEXExporter interface {
	ExportCycloneDXVEXAt(ctx context.Context, projectID uuid.UUID, ts time.Time) ([]byte, error)
}

// WithVEXExporter injects the CycloneDX VEX exporter used to render the
// zip's vex.cdx.json entry and returns the builder for chaining. It is a
// no-op for the Markdown path (FormatMarkdown never consults the
// exporter), so existing 5-arg NewBuilder callers keep working unchanged;
// only FormatZip with the VEX section enabled requires it.
func (b *Builder) WithVEXExporter(e VEXExporter) *Builder {
	b.vexExporter = e
	return b
}

// zipFile is one entry destined for the zip + its manifest row.
type zipFile struct {
	path string
	data []byte
}

// manifest is the manifest.json document. Field declaration order is the
// emitted JSON key order (encoding/json emits struct fields in order) so
// the manifest is byte-stable.
type manifest struct {
	Schema      string         `json:"schema"`
	GeneratedAt string         `json:"generated_at"`
	GeneratedBy manifestGenBy  `json:"generated_by"`
	TenantID    string         `json:"tenant_id"`
	ProjectID   string         `json:"project_id"`
	Files       []manifestFile `json:"files"`
	Disclaimer  string         `json:"disclaimer"`
}

type manifestGenBy struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}

// manifestFile is one row of manifest.files. SHA256 is the hex SHA-256
// over that FILE's bytes (NOT the zip); Bytes is the file's byte length.
type manifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

// metiAssessmentDoc is the meti-assessment.json document: every METI row
// (effective + evaluator status, override, evidence) plus the
// achieved/total tallies. Nothing is summarised away — the raw evidence
// travels with each row so the JSON faithfully reflects provenance.
type metiAssessmentDoc struct {
	Schema   string             `json:"schema"`
	Total    int                `json:"total"`
	Achieved int                `json:"achieved"`
	Criteria []metiCriterionRow `json:"criteria"`
}

type metiCriterionRow struct {
	CriterionID       string          `json:"criterion_id"`
	Phase             string          `json:"phase"`
	Status            string          `json:"status"` // effective status: override wins over evaluator
	EvaluatorStatus   string          `json:"evaluator_status"`
	OverrideStatus    string          `json:"override_status,omitempty"`
	ImprovementAction string          `json:"improvement_action,omitempty"`
	Evidence          json.RawMessage `json:"evidence,omitempty"`
}

// assembleZipInput carries everything the zip assembler needs. All rows
// are already fetched + sorted by Build so the assembler stays a pure
// transform (no repository access) and reuses the exact rows the Markdown
// report was rendered from.
type assembleZipInput struct {
	in                BuildInput
	now               time.Time
	reportMD          []byte
	craRows           []repository.CRAReport
	metiRows          []repository.MetiAssessment
	metiAchievedCount int
	vexCount          int
	craCount          int
}

// assembleZip builds the FormatZip BuildResult. It gathers the entry
// bytes, computes the manifest (per-file SHA-256), then writes a
// deterministic zip. It performs NO repository access — every row is
// supplied by Build.
func (b *Builder) assembleZip(ctx context.Context, z assembleZipInput) (*BuildResult, error) {
	files := make([]zipFile, 0, 8)

	// report.md — verbatim reuse of the Markdown builder output.
	files = append(files, zipFile{path: "report.md", data: z.reportMD})

	// vex.cdx.json — CycloneDX VEX via the injected exporter.
	if z.in.IncludeVEXApproved {
		if b.vexExporter == nil {
			return nil, fmt.Errorf("evidence_pack.Build: zip format requested with VEX section but VEX exporter not wired (server configuration error)")
		}
		// Thread the pack's generation timestamp (z.now / BuildInput.Now) into
		// the VEX export so vex.cdx.json's metadata.timestamp is pack-derived,
		// not a live time.Now() — required for the zip to be byte-reproducible
		// for a fixed input (F408, issue #140).
		vexJSON, err := b.vexExporter.ExportCycloneDXVEXAt(ctx, z.in.ProjectID, z.now)
		if err != nil {
			return nil, fmt.Errorf("evidence_pack.Build: export cyclonedx vex: %w", err)
		}
		files = append(files, zipFile{path: "vex.cdx.json", data: vexJSON})
	}

	// cra/<report_type>.<lang>.md — one file per approved CRA report.
	if z.in.IncludeCRAApproved {
		files = append(files, buildCRAFiles(z.craRows)...)
	}

	// meti-assessment.json — rows + achieved/total.
	if z.in.IncludeMETIAssessment {
		metiJSON, err := buildMETIAssessmentJSON(z.metiRows, z.metiAchievedCount)
		if err != nil {
			return nil, fmt.Errorf("evidence_pack.Build: encode meti assessment: %w", err)
		}
		files = append(files, zipFile{path: "meti-assessment.json", data: metiJSON})
	}

	// manifest.json — schema + provenance + per-file SHA-256 + disclaimer.
	// Built from the artefacts above (it does NOT list itself).
	manifestJSON, err := buildManifest(z, files)
	if err != nil {
		return nil, fmt.Errorf("evidence_pack.Build: encode manifest: %w", err)
	}
	files = append(files, zipFile{path: "manifest.json", data: manifestJSON})

	zipBytes, err := writeDeterministicZip(files)
	if err != nil {
		return nil, fmt.Errorf("evidence_pack.Build: assemble zip: %w", err)
	}

	return &BuildResult{
		Format:            FormatZip,
		Filename:          buildZipFilename(z.in.ProjectID, z.now),
		ContentBytes:      zipBytes,
		BuiltAt:           z.now,
		VEXApprovedCount:  z.vexCount,
		CRAApprovedCount:  z.craCount,
		METIIncluded:      z.in.IncludeMETIAssessment,
		METIRowCount:      len(z.metiRows),
		METIAchievedCount: z.metiAchievedCount,
	}, nil
}

// buildCRAFiles renders one zip entry per approved CRA report. The path
// is cra/<report_type>.<lang>.md. Multiple approved reports sharing the
// same (report_type, lang) are disambiguated by appending the 1-based
// occurrence index in the builder's stable row order (created_at DESC,
// id ASC) so the mapping is deterministic and no report is dropped. The
// file body is the report's DraftText verbatim.
func buildCRAFiles(rows []repository.CRAReport) []zipFile {
	out := make([]zipFile, 0, len(rows))
	seen := map[string]int{}
	for i := range rows {
		r := &rows[i]
		rt := sanitizePathSegment(r.ReportType)
		lang := sanitizePathSegment(r.Lang)
		base := fmt.Sprintf("cra/%s.%s.md", rt, lang)
		seen[base]++
		name := base
		if seen[base] > 1 {
			name = fmt.Sprintf("cra/%s.%s.%d.md", rt, lang, seen[base])
		}
		out = append(out, zipFile{path: name, data: []byte(r.DraftText)})
	}
	return out
}

// sanitizePathSegment reduces a report_type / lang value to a safe zip
// path segment: every character outside [A-Za-z0-9_-] becomes '_'. This
// keeps the enum values (early_warning, ja, ...) intact while defending
// against path traversal ('/', '..') and dots that would corrupt the
// <type>.<lang>.md naming. Empty input maps to "unknown".
func sanitizePathSegment(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// buildMETIAssessmentJSON renders meti-assessment.json. Rows are sorted
// by (phase, criterion_id) for a stable byte layout. achieved is the
// pre-computed effective-status tally from Build (override wins), so the
// JSON agrees with the Markdown footer and the audit row counts.
func buildMETIAssessmentJSON(rows []repository.MetiAssessment, achieved int) ([]byte, error) {
	sorted := append([]repository.MetiAssessment(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CriterionPhase != sorted[j].CriterionPhase {
			return sorted[i].CriterionPhase < sorted[j].CriterionPhase
		}
		return sorted[i].CriterionID < sorted[j].CriterionID
	})
	doc := metiAssessmentDoc{
		Schema:   metiAssessmentSchema,
		Total:    len(sorted),
		Achieved: achieved,
		Criteria: make([]metiCriterionRow, 0, len(sorted)),
	}
	for i := range sorted {
		r := &sorted[i]
		doc.Criteria = append(doc.Criteria, metiCriterionRow{
			CriterionID:       r.CriterionID,
			Phase:             r.CriterionPhase,
			Status:            effectiveStatus(r),
			EvaluatorStatus:   r.Status,
			OverrideStatus:    r.OverrideStatus,
			ImprovementAction: r.ImprovementAction,
			Evidence:          r.Evidence,
		})
	}
	return json.MarshalIndent(doc, "", "  ")
}

// buildManifest renders manifest.json for the supplied artefacts. Each
// files[] row carries the hex SHA-256 over that FILE's bytes (NOT the
// zip) so a consumer can verify integrity per artefact. Rows are sorted
// by path for a stable layout.
func buildManifest(z assembleZipInput, files []zipFile) ([]byte, error) {
	mf := manifest{
		Schema:      manifestSchema,
		GeneratedAt: z.now.UTC().Format(time.RFC3339),
		GeneratedBy: manifestGenBy{Provider: generatorProvider, Model: generatorModel},
		TenantID:    z.in.TenantID.String(),
		ProjectID:   z.in.ProjectID.String(),
		Files:       make([]manifestFile, 0, len(files)),
		Disclaimer:  manifestDisclaimer,
	}
	for _, f := range files {
		sum := sha256.Sum256(f.data)
		mf.Files = append(mf.Files, manifestFile{
			Path:   f.path,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  len(f.data),
		})
	}
	sort.SliceStable(mf.Files, func(i, j int) bool {
		return mf.Files[i].Path < mf.Files[j].Path
	})
	return json.MarshalIndent(mf, "", "  ")
}

// writeDeterministicZip serialises the entries into a byte-stable zip:
// entries are path-sorted, each carries the fixed zipEntryModTime, and
// each is Stored (uncompressed) so the output never depends on flate
// internals. Two calls with equal input return byte-identical output.
func writeDeterministicZip(files []zipFile) ([]byte, error) {
	ordered := append([]zipFile(nil), files...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].path < ordered[j].path
	})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range ordered {
		fh := &zip.FileHeader{
			Name:     f.path,
			Method:   zip.Store, // uncompressed → deterministic, no flate dependency
			Modified: zipEntryModTime,
		}
		fh.SetMode(0o644)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildZipFilename mirrors buildFilename but with the .zip extension:
// evidence-pack-<project_id-short>-<YYYYMMDD-HHMMSS>.zip.
func buildZipFilename(projectID uuid.UUID, now time.Time) string {
	short := projectID.String()
	if len(short) > 8 {
		short = short[:8]
	}
	return fmt.Sprintf("evidence-pack-%s-%s.zip", short, now.UTC().Format("20060102-150405"))
}
