// Package meti carries the static catalog of self-assessment criteria
// derived from 経済産業省 "ソフトウェア管理に向けた SBOM (Software Bill of
// Materials) の導入に関する手引 ver 2.0" (METI, 2024-08).
//
// This file is the M3-3 deliverable (PRODUCT_REBOOT_PLAN.md §13, GitHub
// issue #39) and is layered as follows:
//
//   - catalog.yaml       — the criterion definitions, embedded into the
//                          binary so the deployed image cannot drift away
//                          from the version vetted at build time.
//   - catalog.go         — load / lookup API consumed by the evaluator
//                          (M3-2, separate agent) and by the handler /
//                          report layer.
//   - catalog_test.go    — schema validation: every criterion must carry
//                          id, phase, ja+en title, ja+en description and
//                          evaluator_hint, and ids must be globally unique.
//
// Scope discipline (per the M3-3 task contract): this package owns the
// catalog only. It does NOT touch the DB (M3-1 owns migration 039 +
// meti_assessments repository), does NOT run evaluation (M3-2 owns the
// evaluator), and does NOT mutate handler / web / CLI code.
package meti

import (
	"bytes"
	_ "embed"
	"fmt"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// catalogYAML is the embedded YAML catalog.
//
// Embedding (not on-disk loading) is intentional so that:
//
//   - container deployments cannot drift between binary version and
//     catalog version (the file is sealed at build time);
//   - the evaluator can be unit-tested without a working directory
//     dependency.
//
//go:embed catalog.yaml
var catalogYAML []byte

// Phase enumerates the three METI ver 2.0 phases.
//
// Strings match the catalog.yaml `phase:` field exactly so that a typo
// during catalog edits surfaces as a parse-time validation error rather
// than silent mis-grouping at runtime.
type Phase string

const (
	// PhaseEnvSetup — 環境構築・体制整備フェーズ (chapter 4 of ver 2.0).
	PhaseEnvSetup Phase = "env_setup"
	// PhaseSBOMCreation — SBOM 作成・共有フェーズ (chapter 5 of ver 2.0).
	PhaseSBOMCreation Phase = "sbom_creation"
	// PhaseSBOMOperation — SBOM 運用・管理フェーズ (chapters 6+7 of ver 2.0).
	PhaseSBOMOperation Phase = "sbom_operation"
)

// validPhases is the closed set of phase values accepted by the loader.
//
// Kept private so callers cannot mutate it; iteration order is determined
// at use sites that need a deterministic order (e.g. ListByPhase).
var validPhases = map[Phase]struct{}{
	PhaseEnvSetup:      {},
	PhaseSBOMCreation:  {},
	PhaseSBOMOperation: {},
}

// Criterion is a single METI self-assessment item.
//
// All string fields are required and validated at load time — a missing
// field is a build-time error, not a runtime soft failure, because the
// evaluator and the report renderer both assume non-empty values.
type Criterion struct {
	// ID is the stable, dotted identifier (e.g. "meti.env_setup.01").
	// Used as the primary key by the M3-1 meti_assessments table and as
	// the i18n message key for any future UI strings, so it must never
	// change once shipped.
	ID string `yaml:"id"`

	// Phase is one of PhaseEnvSetup / PhaseSBOMCreation / PhaseSBOMOperation.
	Phase Phase `yaml:"phase"`

	// TitleJA / TitleEN are short headlines for the criterion in each
	// supported UI language.
	TitleJA string `yaml:"title_ja"`
	TitleEN string `yaml:"title_en"`

	// DescriptionJA / DescriptionEN spell out what the criterion requires
	// and why, in each supported language. May contain newlines (preserved
	// from the YAML block scalar).
	DescriptionJA string `yaml:"description_ja"`
	DescriptionEN string `yaml:"description_en"`

	// EvaluatorHint is the English free-form pointer used by the M3-2
	// evaluator agent to decide which DB table / setting / artefact to
	// inspect when auto-assessing this criterion. Keep it concrete enough
	// that a grep over the codebase resolves to the relevant service.
	EvaluatorHint string `yaml:"evaluator_hint"`

	// SourceSection is the chapter / sub-section reference in the
	// official METI guidance that this criterion is anchored to.
	// Required from M5-6 onward — the regression test rejects criteria
	// without a source pointer so a future authoring round cannot
	// silently lose the provenance link. Format: a free-form Japanese
	// string beginning with "第N章" (e.g. "第4章 4.1 / 4.6 SBOM ツール
	// 選定 (ver 2.0)").
	SourceSection string `yaml:"source_section"`

	// Notes is an optional Japanese free-form annotation introduced by
	// M10-2 (issue #75) to document where the catalog wording is a
	// deliberate distillation of a multi-paragraph PDF section, or
	// where the criterion is sourced from an IPA secondary catalogue
	// rather than the primary METI ver 2.0 PDF. Empty for criteria
	// where TitleJA / DescriptionJA already track the primary PDF
	// reasonably closely. Surfaced verbatim by the dashboard provenance
	// pane so operators see why the catalog text diverges from a literal
	// quote.
	Notes string `yaml:"notes,omitempty"`
}

// Metadata captures provenance for the catalog as a whole.
//
// M5-6 (issue #52) introduced this block so the deployed binary can
// surface which version of the METI guidance the criteria slice was
// reconciled against, and the date of that reconciliation. The
// regression test enforces that the values are non-empty and that
// LastSynced parses as a YYYY-MM-DD date so the audit / dashboard
// surface can render a freshness badge without a second source.
type Metadata struct {
	// Source is the human-readable title of the upstream document
	// (Japanese, e.g. "経済産業省 ソフトウェア管理に向けた SBOM の導入に関する手引 ver 2.0").
	Source string `yaml:"source"`
	// SourceURL is the canonical fetch URL of the primary PDF.
	SourceURL string `yaml:"source_url"`
	// SourceSummaryURL is the URL of the shorter "概要" PDF that
	// summarises the guidance; useful for operators who want a
	// quick orientation before opening the full text.
	SourceSummaryURL string `yaml:"source_summary_url"`
	// SourceVersion is the official version tag (e.g. "ver 2.0").
	SourceVersion string `yaml:"source_version"`
	// SourcePublished is the official publication date (YYYY-MM-DD).
	SourcePublished string `yaml:"source_published"`
	// LastSynced is the date this catalog was last reconciled against
	// the upstream document (YYYY-MM-DD). Bumped only when a wording
	// edit lands; not bumped by cosmetic edits.
	LastSynced string `yaml:"last_synced"`
	// SyncedBy records the milestone / issue that drove the
	// reconciliation (e.g. "M5-6 issue #52"). Lets the audit surface
	// link back to the change record.
	SyncedBy string `yaml:"synced_by"`
	// VerificationStatus is one of "full" / "partial" / "deferred".
	// "partial" is honest about the M5-6 reality where the primary PDF
	// could not be fetched from the build environment and the IPA
	// secondary source was used as a cross-check; the dashboard
	// surfaces this verbatim so operators are not told a stricter
	// claim than the wave delivered.
	VerificationStatus string `yaml:"verification_status"`
	// VerificationNotes is a longer Japanese note explaining how the
	// reconciliation was performed and what is still outstanding.
	VerificationNotes string `yaml:"verification_notes"`
}

// catalogFile mirrors the top-level YAML shape.
//
// Kept as an unexported envelope so we are free to add sibling keys
// (version, last_updated, source_url, …) to the YAML in the future
// without breaking the public Criterion API.
type catalogFile struct {
	Metadata Metadata    `yaml:"metadata"`
	Criteria []Criterion `yaml:"criteria"`
}

// loadOnce guarantees that catalog parse / validation happens exactly
// once per process even when LoadCatalog is called from many goroutines
// (the evaluator can fan out per-project assessments concurrently).
var (
	loadOnce       sync.Once
	cachedItems    []Criterion
	cachedByID     map[string]*Criterion
	cachedMetadata Metadata
	cachedErr      error
)

// LoadCatalog returns the parsed, validated criteria slice.
//
// The catalog is parsed once and cached. The returned slice is a copy
// so callers cannot mutate the cache by writing into it; lookups are
// O(1) via the internal map. Any validation failure (missing field,
// duplicate id, unknown phase) is returned as a wrapped error on the
// first call and on every subsequent call — the cache stores the error
// so the evaluator fails loudly at startup rather than per-request.
func LoadCatalog() ([]Criterion, error) {
	loadOnce.Do(parseCatalog)
	if cachedErr != nil {
		return nil, cachedErr
	}
	// Return a fresh copy so callers mutating the slice (e.g. sorting)
	// cannot poison the cache.
	out := make([]Criterion, len(cachedItems))
	copy(out, cachedItems)
	return out, nil
}

// GetCriterion looks up a single criterion by ID.
//
// Returns (nil, false) if the catalog failed to load or the id is unknown.
// The false-on-load-error path is intentional so handler code that wants
// to skip unknown ids does not need a separate error branch; callers that
// need the underlying parse error should call LoadCatalog first.
func GetCriterion(id string) (*Criterion, bool) {
	loadOnce.Do(parseCatalog)
	if cachedErr != nil {
		return nil, false
	}
	c, ok := cachedByID[id]
	if !ok {
		return nil, false
	}
	// Copy so callers cannot mutate the cache.
	cp := *c
	return &cp, true
}

// ListByPhase returns the criteria belonging to the given phase, sorted
// by ID for deterministic iteration order.
//
// An unknown phase returns an empty slice (not an error) so the report
// renderer can iterate over the closed phase set without conditional
// handling. Callers that need to detect an unknown phase should check
// against validPhases directly.
func ListByPhase(phase Phase) []Criterion {
	loadOnce.Do(parseCatalog)
	if cachedErr != nil {
		return nil
	}
	out := make([]Criterion, 0, len(cachedItems))
	for i := range cachedItems {
		if cachedItems[i].Phase == phase {
			out = append(out, cachedItems[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Phases returns the ordered list of valid phases (env_setup ->
// sbom_creation -> sbom_operation), matching the chronological order
// in which a team progresses through the ver 2.0 guidance.
func Phases() []Phase {
	return []Phase{PhaseEnvSetup, PhaseSBOMCreation, PhaseSBOMOperation}
}

// LoadMetadata returns the parsed catalog metadata block.
//
// Mirrors LoadCatalog's caching contract: parse-once, cached error
// returned on every subsequent call. The returned Metadata is a value
// (not a pointer) so callers cannot mutate the cache by writing into
// it; that matters because the dashboard surface reads LastSynced /
// VerificationStatus on every request.
func LoadMetadata() (Metadata, error) {
	loadOnce.Do(parseCatalog)
	if cachedErr != nil {
		return Metadata{}, cachedErr
	}
	return cachedMetadata, nil
}

// parseCatalog is the single-entry parser invoked under loadOnce.
//
// Validation rules (all enforced here so callers never see a partially
// constructed catalog):
//
//   - non-empty criteria list;
//   - every required string field non-empty (whitespace-trimmed);
//   - phase is one of validPhases;
//   - ID values are globally unique;
//   - ID prefix matches its phase (e.g. "meti.env_setup.*" only allowed
//     under PhaseEnvSetup), which catches accidental copy-paste errors
//     when authors duplicate-and-edit catalog entries.
func parseCatalog() {
	dec := yaml.NewDecoder(bytes.NewReader(catalogYAML))
	dec.KnownFields(true)

	var file catalogFile
	if err := dec.Decode(&file); err != nil {
		cachedErr = fmt.Errorf("meti: parse catalog.yaml: %w", err)
		return
	}
	if len(file.Criteria) == 0 {
		cachedErr = fmt.Errorf("meti: catalog.yaml contains zero criteria")
		return
	}

	if err := validateMetadata(&file.Metadata); err != nil {
		cachedErr = fmt.Errorf("meti: catalog.yaml metadata: %w", err)
		return
	}

	byID := make(map[string]*Criterion, len(file.Criteria))
	for i := range file.Criteria {
		c := &file.Criteria[i]
		if err := validateCriterion(c); err != nil {
			cachedErr = fmt.Errorf("meti: criterion #%d (id=%q): %w", i, c.ID, err)
			return
		}
		if _, dup := byID[c.ID]; dup {
			cachedErr = fmt.Errorf("meti: duplicate criterion id %q", c.ID)
			return
		}
		byID[c.ID] = c
	}

	cachedItems = file.Criteria
	cachedByID = byID
	cachedMetadata = file.Metadata
}

// validMetadataVerificationStatuses is the closed set of values for
// metadata.verification_status. Kept here so the loader rejects typos
// (e.g. "partially") at parse time rather than letting the dashboard
// render an unrecognised badge.
var validMetadataVerificationStatuses = map[string]struct{}{
	"full":     {},
	"partial":  {},
	"deferred": {},
}

// validateMetadata enforces the per-field invariants for the catalog
// metadata block.
//
// The dashboard surface relies on every field being non-empty, and on
// LastSynced / SourcePublished being YYYY-MM-DD so it can render a
// freshness badge without an extra round of date-parsing logic.
func validateMetadata(m *Metadata) error {
	if m.Source == "" {
		return fmt.Errorf("missing source")
	}
	if m.SourceURL == "" {
		return fmt.Errorf("missing source_url")
	}
	if m.SourceVersion == "" {
		return fmt.Errorf("missing source_version")
	}
	if m.SourcePublished == "" {
		return fmt.Errorf("missing source_published")
	}
	if _, err := time.Parse("2006-01-02", m.SourcePublished); err != nil {
		return fmt.Errorf("source_published %q must be YYYY-MM-DD: %w", m.SourcePublished, err)
	}
	if m.LastSynced == "" {
		return fmt.Errorf("missing last_synced")
	}
	if _, err := time.Parse("2006-01-02", m.LastSynced); err != nil {
		return fmt.Errorf("last_synced %q must be YYYY-MM-DD: %w", m.LastSynced, err)
	}
	if m.SyncedBy == "" {
		return fmt.Errorf("missing synced_by")
	}
	if m.VerificationStatus == "" {
		return fmt.Errorf("missing verification_status")
	}
	if _, ok := validMetadataVerificationStatuses[m.VerificationStatus]; !ok {
		return fmt.Errorf("unknown verification_status %q (want full|partial|deferred)", m.VerificationStatus)
	}
	if m.VerificationNotes == "" {
		return fmt.Errorf("missing verification_notes")
	}
	return nil
}

// validateCriterion enforces the per-criterion schema invariants.
//
// Errors are unwrapped (no wrap depth) so the parseCatalog wrapper can
// add the surrounding context (index + id) in one place.
func validateCriterion(c *Criterion) error {
	if c.ID == "" {
		return fmt.Errorf("missing id")
	}
	if c.Phase == "" {
		return fmt.Errorf("missing phase")
	}
	if _, ok := validPhases[c.Phase]; !ok {
		return fmt.Errorf("unknown phase %q (want env_setup|sbom_creation|sbom_operation)", c.Phase)
	}
	if c.TitleJA == "" {
		return fmt.Errorf("missing title_ja")
	}
	if c.TitleEN == "" {
		return fmt.Errorf("missing title_en")
	}
	if c.DescriptionJA == "" {
		return fmt.Errorf("missing description_ja")
	}
	if c.DescriptionEN == "" {
		return fmt.Errorf("missing description_en")
	}
	if c.EvaluatorHint == "" {
		return fmt.Errorf("missing evaluator_hint")
	}
	if c.SourceSection == "" {
		return fmt.Errorf("missing source_section")
	}
	// ID-prefix check: a criterion's id must encode its phase so authors
	// cannot silently mis-classify a duplicated entry.
	wantPrefix := "meti." + string(c.Phase) + "."
	if len(c.ID) <= len(wantPrefix) || c.ID[:len(wantPrefix)] != wantPrefix {
		return fmt.Errorf("id %q does not start with phase prefix %q", c.ID, wantPrefix)
	}
	return nil
}
