package cra

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestCRATemplateRegistryParity_F341 is the fourth horizontal replication
// of anti-pattern 58 (emit / registry parity in dual-list systems)
// outside the audit dimensions (F271 Action / F281 Resource), following
// F299 (M20-2, Plan feature registry ↔ SQL seed), F318 (M21-1, LLM
// provider registry) and F330 (M22-1, issue-tracker type registry — see
// handler/tracker_type_parity_test.go, the direct template for this
// test). The registry here is the CRA report template engine, and it has
// a shape none of the earlier replications had: one of its surfaces is a
// FILE SET — the embedded templates/*.tmpl directory — so "registry
// entry exists" means "a file with the derived name ships in the
// binary", not "a code entry exists". The surfaces that must agree:
//
//	(Go consts)   service/cra/templates.go `ReportType*` typed consts
//	              (currently early_warning / detailed_notification /
//	              final_report) and `Lang*` typed consts (ja / en) —
//	              the authoritative wire-value universe.
//
//	(Go registry) SupportedReportTypes() / SupportedLangs() in the same
//	              file — the allowlist the runner validates against
//	              (runner.go isValidReportType / isValidLang) and the
//	              set handlers surface to the UI.
//
//	(File set)    templatesFS (//go:embed templates/*.tmpl): exactly one
//	              {reporttype}_{lang}.tmpl file per (ReportType x Lang)
//	              cell, plus the hand-maintained key list inside the
//	              templateCache init closure.
//
//	(Web)         apps/web/src/lib/api.ts `CRAReportType` and
//	              `CRAReportLang` TS unions, and apps/web/src/app/
//	              [locale]/(dashboard)/projects/[id]/cra-reports/
//	              page.tsx REPORT_TYPE_OPTIONS / LANG_OPTIONS filter
//	              arrays (their "" member is the "all" filter sentinel,
//	              not a wire value, and stays outside the contract).
//
//	(i18n)        apps/web/messages/en.json AND ja.json: the
//	              CRAReports.ReportType and CRAReports.Lang label
//	              objects are KEYED by these wire values (next-intl
//	              looks the label up by the raw API value), so each
//	              catalog's key set is a parity surface — a report type
//	              added everywhere else renders as a missing-label
//	              fallback until both catalogs learn it (F358, M24-3).
//
//	(Prose)       templates.go's own docstrings ("six Markdown
//	              templates", "3 report types x 2 languages", "the
//	              three CRA Article 14 report types", the two "Stable
//	              order (...)" claims) plus two operator-facing
//	              enumerations elsewhere in apps/api:
//	              repository/cra_reports.go Insert's "report_type is
//	              required (one of ...)" / "lang is required (one of
//	              ...)" errors, and service/evidence_pack/builder.go's
//	              "- **Report type**: ... (one of ...)" line rendered
//	              into every evidence pack README.
//
// If any two drift, the breakage is silent in exactly the anti-pattern
// 58 way: a const added together with its templateCache key but without
// the .tmpl file panics the package init at runtime (the init closure
// only ReadFiles the hand-maintained keys list); a const added WITHOUT
// the cache key never panics — Render just returns ErrUnknownTemplate
// for the new type at runtime (and if SupportedReportTypes() also
// moved, requests can select a type that can never render) until
// direction 2b here flags the missing cache key (F351 factual reword —
// the pre-F351 text overstated init panic as covering the const-only
// drift); a .tmpl file added without a const is a
// dead artifact shipped in every binary; web surfaces extended without
// Go offer a report type the backend rejects; Go extended without the
// web leaves the new report type invisible to operators; and the prose
// enumerations quietly misinform operators about what they may send.
//
// Directions:
//
//	(1) Go consts ↔ Supported*() registries, bidirectionally: the const
//	    block is parsed out of templates.go source (declaration-shape
//	    anchors, no line numbers) and compared as a set against the
//	    runtime return values; duplicate wire values and duplicate
//	    registry entries fail loudly. (registry → const is additionally
//	    compiler-enforced, since Supported*() returns symbols.)
//	    Plus a universal Go census: every .go file under apps/api —
//	    test files INCLUDED, this file itself excluded (its pinned
//	    expected sets necessarily discuss the wire values; pinning
//	    oneself is circular) — that mentions a report-type wire value
//	    (bare-token prefix match, so comments, SQL fixtures and
//	    composite keys like early_warning_ja all count) must be in one
//	    of two hand-maintained file sets (non-test / test). A NEW file
//	    hardcoding a wire value fails this census until it is either
//	    switched to the consts or deliberately pinned here.
//
//	(2) (ReportType x Lang) cross product ↔ the embedded file set:
//	    templatesFS.ReadDir must contain exactly
//	    {reporttype}_{lang}.tmpl per cell — a missing cell AND an
//	    orphan .tmpl both fail. The templateCache key set must equal
//	    the same cross product (a stale entry in its hand-maintained
//	    key list panics package init before this test even runs, which
//	    is the loud-failure mode we want; a MISSING entry is caught
//	    here).
//
//	(3) Cross-language: the api.ts CRAReportType / CRAReportLang TS
//	    unions and the page.tsx REPORT_TYPE_OPTIONS / LANG_OPTIONS
//	    arrays must each equal the Go wire-value sets, and a duplicated
//	    entry within any single union / option array fails at parse
//	    time (F352: set comparison alone would collapse the duplicate
//	    and hide a doubled dropdown entry). All web parsing
//	    is read-only and anchor-terminated (F326 discipline: no
//	    byte-offset windows, no line numbers, identifier char class
//	    [A-Za-z0-9_-], widened by F347 so camelCase drift fails loudly;
//	    every anchor must occur exactly once). A web-side
//	    census pins which .ts/.tsx files under apps/web/src may mention
//	    a report-type wire value at all.
//
//	(4) Doc / prose factuality (F276 lineage): templates.go's numeric
//	    claims ("six" templates, "3 report types x 2 languages", "the
//	    three ... report types") are parsed and compared against the
//	    actual counts; the "Stable order (early -> detailed -> final)"
//	    and "(ja -> en)" claims are checked token-by-token (each token
//	    must be a prefix of the runtime value at that position, so the
//	    documented order tracks the real order). The two Insert error
//	    messages in repository/cra_reports.go and the evidence-pack
//	    README line in service/evidence_pack/builder.go must enumerate
//	    exactly the registered wire values — bidirectional (F337
//	    lineage): a registered value missing from the message AND a
//	    stale token no const declares both fail.
//
//	(5) i18n label catalogs (F358, M24-3): the CRAReports.ReportType
//	    and CRAReports.Lang objects in apps/web/messages/en.json AND
//	    ja.json must each have a key set equal to the Go wire-value
//	    sets. The objects are located structurally — an encoding/json
//	    token walk, not regex or json.Unmarshal — and anchored at
//	    their FULL key path (F362, M24 R2): the probe matches an
//	    object only at CRAReports.ReportType / CRAReports.Lang, not a
//	    same-named object anywhere in the document, so renaming the
//	    parent CRAReports namespace — which strands the labels
//	    next-intl resolves under CRAReports.* — fails loudly as a
//	    zero-match instead of the probe silently re-anchoring (the
//	    pre-F362 match-anywhere walk was R1-proven GREEN under exactly
//	    that rename). Exactly one object may exist at the pinned path
//	    (exactly-once, F326 spirit) and a duplicated key INSIDE the
//	    object fails at parse time (F352 lineage: map-decoding would
//	    silently collapse the duplicate). A messages census (5c)
//	    additionally pins which .json files under apps/web/messages
//	    may mention a report-type wire value at all, so a third locale
//	    catalog hardcoding the values must be brought under this
//	    contract deliberately.
//
// go-test-cache trap (F344 root cause; F348 rewrite, M23-2 #124):
// Direction 3 reads apps/web/src/lib/api.ts, the cra-reports page.tsx
// and (for the 3e census) every .ts/.tsx file under apps/web/src, and
// direction 5 reads every .json file under apps/web/messages (F358) —
// all OUTSIDE this Go module's root (apps/api). go's test cache folds
// opened files into the cache key ONLY when they are inside the
// module / GOPATH / GOROOT root (go1.26.4
// cmd/go/internal/test/test.go computeTestInputsID: "Do not recheck
// files outside the module, GOPATH, or GOROOT root"), so a bare
// `go test` after editing a web surface can return a stale
// "(cached) ok" false-pass. Empirically confirmed 2026-07-02 on THIS
// suite: with a warm cache, adding "incidentReport" to the api.ts
// CRAReportType union left `go test ./internal/service/cra/` reporting
// "(cached) ok"; the same run with -count=1 failed loudly (direction
// 3a). Run this suite with -count=1 whenever web-side surfaces OR the
// messages catalogs changed
// (and always for mutation verification). CI is unaffected — fresh
// runners have no warm cache. The in-module reads are cache-tracked
// normally: templates.go, repository/cra_reports.go,
// evidence_pack/builder.go and every other .go file the census walks
// are stat-tracked by (mtime,size) of the opened path; templatesFS and
// templateCache are compiled build inputs.
//
// What THIS test DOES catch:
//
//   - A ReportType* or Lang* const added/removed without updating
//     SupportedReportTypes() / SupportedLangs() (and vice versa), or
//     either registry returning duplicates.
//   - A (type, lang) cell with no embedded .tmpl file, an orphan .tmpl
//     file no cell claims, and a templateCache key list that lost an
//     entry (an extra bogus entry panics init — louder still).
//   - Any NEW Go file under apps/api (test or non-test) or .ts/.tsx
//     file under apps/web/src that hardcodes a report-type wire value
//     outside the pinned census sets, and any stale census pin.
//   - api.ts union or page.tsx filter-array drift from the Go registry,
//     in either direction, and a duplicated entry inside any one of
//     those four web surfaces (F352 parse-stage guard in
//     craParityQuotedSet — a duplicate would render twice in the UI
//     dropdown but survive a set-level comparison).
//   - templates.go's count and stable-order docstring claims going
//     stale, and the repository / evidence-pack operator-facing
//     enumerations advertising a set that differs from the registry.
//   - A messages catalog (en.json / ja.json) whose
//     CRAReports.ReportType or CRAReports.Lang label-object key set
//     drifts from the Go registry in either direction, a rename or
//     move of the parent CRAReports namespace that strands both label
//     objects (F362 full-path anchor), a duplicated key inside either
//     object, and any OTHER .json file under apps/web/messages
//     mentioning a report-type wire value outside the 5c census pin
//     (F358).
//
// What THIS test does NOT catch (documented factuality trade-off,
// mirrors the F276 note on F271 / F281 / F299 / F318 / F330):
//
//   - Wire-value stability. A coordinated rename ("early_warning" →
//     "earlyWarning") on every pinned surface in one PR passes this
//     test even though it breaks every persisted cra_reports.report_type
//     row AND the DB CHECK constraint. Out of scope, same trade-off as
//     the five earlier parity tests.
//   - The DB layer. migrations/038_cra_reports.up.sql declares CHECK
//     (report_type IN ('early_warning', 'detailed_notification',
//     'final_report')) — a NEW report type passes all four directions
//     here once the pinned surfaces move, yet every insert fails until
//     a migration extends that CHECK. Migrations are immutable history
//     and are not parsed here; the failure mode is at least loud (500
//     on insert), not silent.
//   - Template CONTENT. A blank, wrong-language, or legally stale
//     .tmpl body passes — only filename existence is pinned. Golden
//     tests (templates_test.go) own content.
//   - runner.go internals: buildCRASystemPrompt's ReportType switch
//     gained a loud default arm in F359 (M24-3) — an unregistered type
//     now embeds its raw wire value in the prompt instead of silently
//     truncating the sentence — but nothing HERE pins that each
//     registered type keeps its dedicated sentence; that lives in
//     runner_test.go's F359 unit test. The runner's validation path is
//     covered only indirectly (it delegates to SupportedReportTypes /
//     SupportedLangs).
//   - A Go or web lang-literal census. "ja" / "en" are locale tokens
//     used all over both trees for i18n (report.go, jvn.go, message
//     catalogs, next-intl) — pinning their file sets would couple this
//     test to unrelated churn. Lang parity is enforced only at the
//     typed surfaces (consts, SupportedLangs, tmpl filenames, TS union,
//     LANG_OPTIONS, the repository lang error message, and — since
//     F358 — the messages CRAReports.Lang label objects).
//   - i18n label TEXT. Direction 5 pins the label-object KEYS only —
//     a wrong, swapped, or stale label string ("24h" wording drift,
//     Japanese text pasted into the en catalog) passes; only key-set
//     parity is enforced.
//   - Comment-only mentions inside already-pinned files (e.g. the
//     repository struct-field comment, meti/criteria/sbom_operation.go's
//     doc comment): the census pins the FILE, not the comment content,
//     so those sentences can go stale without failing here.
//   - Anything outside apps/api *.go, apps/web/src *.ts/*.tsx and
//     apps/web/messages *.json (the catalogs graduated INTO the
//     contract as direction 5, F358): apps/web/e2e specs,
//     docker/seed/*.sql, and docs.
//
// Adding a new report type (or language) going forward — this test
// fails until ALL of the following move together, which is exactly the
// multi-way sync this replication exists to force: the ReportType*
// const, SupportedReportTypes(), the templateCache key list, one .tmpl
// file per supported language, the api.ts union, the page.tsx filter
// array, templates.go's count/order docstrings, the repository Insert
// error message, the evidence-pack README line, and the
// CRAReports.ReportType label objects in BOTH messages catalogs
// (direction 5) — plus (outside this test, see above) a DB migration
// extending the CHECK constraint. Add nothing to an allowlist (there
// is none). Do not silence this test. (F341, M23-1 #123; direction 5:
// F358, M24-3 #127)
func TestCRATemplateRegistryParity_F341(t *testing.T) {
	apiRoot, webSrcRoot, thisFile := craParityRoots(t)

	// ------- Set-up: read the Go tree once, parse the const universe -------

	goFiles := craParityScanTree(t, apiRoot, map[string]bool{".go": true}, thisFile)

	const templatesRel = "internal/service/cra/templates.go"
	templatesSrc, ok := goFiles[templatesRel]
	if !ok {
		t.Fatalf("F341 setup: %s not found under %s — the engine file "+
			"moved or the tree walk root is wrong; update this test.",
			templatesRel, apiRoot)
	}

	reportTypeConsts := craParityConsts(t, templatesSrc,
		craParityReportTypeConstRe, "model-level ReportType")
	langConsts := craParityConsts(t, templatesSrc,
		craParityLangConstRe, "model-level Lang")

	reportTypeValues := make(map[string]bool, len(reportTypeConsts))
	for _, v := range reportTypeConsts {
		reportTypeValues[v] = true
	}
	langValues := make(map[string]bool, len(langConsts))
	for _, v := range langConsts {
		langValues[v] = true
	}

	// ------- Direction 1: consts ↔ Supported*() + universal Go census -------

	// (1a) ReportType consts ↔ SupportedReportTypes(). The runtime
	// slice is also checked for duplicates: a duplicated entry would
	// otherwise survive a set-level comparison.
	supportedRT := SupportedReportTypes()
	gotRT := make(map[string]bool, len(supportedRT))
	for _, rt := range supportedRT {
		gotRT[string(rt)] = true
	}
	if len(gotRT) != len(supportedRT) {
		t.Errorf("F341 direction 1a: SupportedReportTypes() returned %d "+
			"entries but only %d distinct values — the registry contains "+
			"a duplicate; fix SupportedReportTypes().",
			len(supportedRT), len(gotRT))
	}
	craParityAssertSetEqual(t,
		"F341 direction 1a (templates.go ReportType consts ↔ SupportedReportTypes())",
		gotRT, reportTypeValues)

	// (1b) Lang consts ↔ SupportedLangs(), same shape.
	supportedLangs := SupportedLangs()
	gotLangs := make(map[string]bool, len(supportedLangs))
	for _, l := range supportedLangs {
		gotLangs[string(l)] = true
	}
	if len(gotLangs) != len(supportedLangs) {
		t.Errorf("F341 direction 1b: SupportedLangs() returned %d entries "+
			"but only %d distinct values — the registry contains a "+
			"duplicate; fix SupportedLangs().",
			len(supportedLangs), len(gotLangs))
	}
	craParityAssertSetEqual(t,
		"F341 direction 1b (templates.go Lang consts ↔ SupportedLangs())",
		gotLangs, langValues)

	// (1c) Universal Go census. Bare-token prefix matching (see
	// craParityLiteralRe) deliberately counts comments, SQL fixtures and
	// composite template keys, so a wire value smuggled into ANY new .go
	// file — including a test — surfaces here. Split non-test vs test so
	// the failure diff says which discipline applies (non-test files
	// should almost always use the consts instead).
	literalRe := craParityLiteralRe(reportTypeValues)
	wantGoNonTest := map[string]bool{
		"internal/repository/cra_reports.go":               true, // field comment + Insert error enumeration (probed in 4e)
		"internal/service/cra/templates.go":                true, // the const block + templateCache keys
		"internal/service/evidence_pack/builder.go":        true, // README enumeration line (probed in 4f)
		"internal/service/meti/criteria/sbom_operation.go": true, // doc comment naming the milestones
	}
	wantGoTest := map[string]bool{
		"internal/handler/cra_reports_test.go":            true,
		"internal/repository/cra_reports_rls_test.go":     true,
		"internal/repository/cra_reports_test.go":         true,
		"internal/service/evidence_pack/builder_test.go":  true,
		"internal/service/meti/criteria/criteria_test.go": true,
	}
	gotGoNonTest := make(map[string]bool)
	gotGoTest := make(map[string]bool)
	for rel, src := range goFiles {
		if !literalRe.MatchString(src) {
			continue
		}
		if strings.HasSuffix(rel, "_test.go") {
			gotGoTest[rel] = true
		} else {
			gotGoNonTest[rel] = true
		}
	}
	craParityAssertSetEqual(t,
		"F341 direction 1c (non-test Go files mentioning CRA report-type wire values)",
		gotGoNonTest, wantGoNonTest)
	craParityAssertSetEqual(t,
		"F341 direction 1c (test Go files mentioning CRA report-type wire values)",
		gotGoTest, wantGoTest)

	// ------- Direction 2: cross product ↔ embed.FS ↔ templateCache -------

	wantTmplFiles := make(map[string]bool, len(reportTypeValues)*len(langValues))
	wantCacheKeys := make(map[string]bool, len(reportTypeValues)*len(langValues))
	for rt := range reportTypeValues {
		for lang := range langValues {
			wantCacheKeys[rt+"_"+lang] = true
			wantTmplFiles[rt+"_"+lang+".tmpl"] = true
		}
	}

	entries, err := templatesFS.ReadDir("templates")
	if err != nil {
		t.Fatalf("F341 direction 2 setup: templatesFS.ReadDir(\"templates\") "+
			"failed: %v — the embed directive or directory moved; update "+
			"this test.", err)
	}
	gotTmplFiles := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			t.Fatalf("F341 direction 2: unexpected subdirectory %q inside "+
				"the embedded templates/ tree — the flat "+
				"{reporttype}_{lang}.tmpl layout changed; update this test "+
				"and the templateCache loader together.", e.Name())
		}
		gotTmplFiles[e.Name()] = true
	}
	craParityAssertSetEqual(t,
		"F341 direction 2a (ReportType x Lang cross product ↔ embedded templates/*.tmpl filenames)",
		gotTmplFiles, wantTmplFiles)

	gotCacheKeys := make(map[string]bool, len(templateCache))
	for k := range templateCache {
		gotCacheKeys[k] = true
	}
	craParityAssertSetEqual(t,
		"F341 direction 2b (ReportType x Lang cross product ↔ templateCache keys)",
		gotCacheKeys, wantCacheKeys)

	// ------- Direction 3: Go wire values ↔ web TS surfaces -------

	webFiles := craParityScanTree(t, webSrcRoot,
		map[string]bool{".ts": true, ".tsx": true}, "")

	const apiTSRel = "lib/api.ts"
	apiTS, ok := webFiles[apiTSRel]
	if !ok {
		t.Fatalf("F341 direction 3 setup: %s not found under %s — the web "+
			"API client moved; update this test.", apiTSRel, webSrcRoot)
	}
	rtUnion := craParityQuotedSet(t,
		craParityWindow(t, apiTS, apiTSRel, "export type CRAReportType =", ";"),
		apiTSRel+" CRAReportType union")
	craParityAssertSetEqual(t,
		"F341 direction 3a (api.ts CRAReportType union ↔ Go report-type wire values)",
		rtUnion, reportTypeValues)
	langUnion := craParityQuotedSet(t,
		craParityWindow(t, apiTS, apiTSRel, "export type CRAReportLang =", ";"),
		apiTSRel+" CRAReportLang union")
	craParityAssertSetEqual(t,
		"F341 direction 3b (api.ts CRAReportLang union ↔ Go lang wire values)",
		langUnion, langValues)

	const pageRel = "app/[locale]/(dashboard)/projects/[id]/cra-reports/page.tsx"
	pageTSX, ok := webFiles[pageRel]
	if !ok {
		t.Fatalf("F341 direction 3 setup: %s not found under %s — the CRA "+
			"reports page moved; update this test.", pageRel, webSrcRoot)
	}
	// The quoted-identifier regex requires at least one character, so
	// the arrays' "" all-filter sentinel stays outside the comparison by
	// construction.
	rtOptions := craParityQuotedSet(t,
		craParityWindow(t, pageTSX, pageRel,
			"const REPORT_TYPE_OPTIONS = [", "] as const"),
		pageRel+" REPORT_TYPE_OPTIONS")
	craParityAssertSetEqual(t,
		"F341 direction 3c (page.tsx REPORT_TYPE_OPTIONS ↔ Go report-type wire values)",
		rtOptions, reportTypeValues)
	langOptions := craParityQuotedSet(t,
		craParityWindow(t, pageTSX, pageRel,
			"const LANG_OPTIONS = [", "] as const"),
		pageRel+" LANG_OPTIONS")
	craParityAssertSetEqual(t,
		"F341 direction 3d (page.tsx LANG_OPTIONS ↔ Go lang wire values)",
		langOptions, langValues)

	// (3e) Web literal census: report-type wire values may appear only
	// in the two files above. A new .ts/.tsx file naming a wire value
	// must either use the CRAReportType union or be brought under this
	// parity contract deliberately.
	wantWebLiteralFiles := map[string]bool{
		apiTSRel: true,
		pageRel:  true,
	}
	gotWebLiteralFiles := make(map[string]bool)
	for rel, src := range webFiles {
		if literalRe.MatchString(src) {
			gotWebLiteralFiles[rel] = true
		}
	}
	craParityAssertSetEqual(t,
		"F341 direction 3e (web files mentioning CRA report-type wire values)",
		gotWebLiteralFiles, wantWebLiteralFiles)

	// ------- Direction 4: doc / prose factuality (F276 lineage) -------

	// (4a) "templatesFS embeds the six Markdown templates" — the word
	// must track the actual embedded-file count.
	embedsClaim := craParityExactlyOne(t, craParityEmbedsDocRe, templatesSrc,
		templatesRel, "templatesFS 'embeds the <N> Markdown templates' claim")
	if n := craParityNumber(t, embedsClaim[1],
		templatesRel+" templatesFS docstring"); n != len(gotTmplFiles) {
		t.Errorf("F341 direction 4a: templates.go claims templatesFS embeds "+
			"%q (=%d) Markdown templates but the embedded FS contains %d — "+
			"update the docstring alongside the registry.",
			embedsClaim[1], n, len(gotTmplFiles))
	}

	// (4b) "(3 report types x 2 languages)" — both factors must track
	// the const universe.
	dimsClaim := craParityExactlyOne(t, craParityDimsDocRe, templatesSrc,
		templatesRel, "'(<N> report types x <M> languages)' claim")
	if n, _ := strconv.Atoi(dimsClaim[1]); n != len(reportTypeValues) {
		t.Errorf("F341 direction 4b: templates.go claims %s report types "+
			"but %d ReportType consts are declared — update the docstring "+
			"alongside the registry.", dimsClaim[1], len(reportTypeValues))
	}
	if n, _ := strconv.Atoi(dimsClaim[2]); n != len(langValues) {
		t.Errorf("F341 direction 4b: templates.go claims %s languages but "+
			"%d Lang consts are declared — update the docstring alongside "+
			"the registry.", dimsClaim[2], len(langValues))
	}

	// (4c) "ReportType enumerates the three CRA Article 14 report types".
	enumClaim := craParityExactlyOne(t, craParityEnumDocRe, templatesSrc,
		templatesRel, "'ReportType enumerates the <N> ... report types' claim")
	if n := craParityNumber(t, enumClaim[1],
		templatesRel+" ReportType docstring"); n != len(reportTypeValues) {
		t.Errorf("F341 direction 4c: templates.go claims ReportType "+
			"enumerates %q (=%d) report types but %d consts are declared — "+
			"update the docstring alongside the registry.",
			enumClaim[1], n, len(reportTypeValues))
	}

	// (4d) The two "Stable order (...)" claims. Each doc token must be a
	// prefix of the runtime value at the same position, so the
	// documented order cannot silently diverge from the real one.
	rtOrderWindow := craParityWindow(t, templatesSrc, templatesRel,
		"// SupportedReportTypes returns", "func SupportedReportTypes(")
	rtOrder := craParityExactlyOne(t, craParityStableOrderRe, rtOrderWindow,
		templatesRel, "SupportedReportTypes 'Stable order (...)' claim")
	rtRuntime := make([]string, len(supportedRT))
	for i, v := range supportedRT {
		rtRuntime[i] = string(v)
	}
	craParityAssertDocOrder(t,
		"F341 direction 4d (SupportedReportTypes stable-order docstring)",
		rtOrder[1], rtRuntime)

	langOrderWindow := craParityWindow(t, templatesSrc, templatesRel,
		"// SupportedLangs returns", "func SupportedLangs(")
	langOrder := craParityExactlyOne(t, craParityStableOrderRe, langOrderWindow,
		templatesRel, "SupportedLangs 'Stable order (...)' claim")
	langRuntime := make([]string, len(supportedLangs))
	for i, v := range supportedLangs {
		langRuntime[i] = string(v)
	}
	craParityAssertDocOrder(t,
		"F341 direction 4d (SupportedLangs stable-order docstring)",
		langOrder[1], langRuntime)

	// (4e) repository/cra_reports.go Insert error enumerations — the
	// operator-facing "(one of ...)" lists for report_type AND lang must
	// each equal the registered set, bidirectionally (F337 lineage).
	const repoRel = "internal/repository/cra_reports.go"
	repoSrc, ok := goFiles[repoRel]
	if !ok {
		t.Fatalf("F341 direction 4e setup: %s not found under %s.",
			repoRel, apiRoot)
	}
	craParityAssertSetEqual(t,
		"F341 direction 4e (repository Insert report_type error enumeration ↔ Go wire values)",
		craParityTokenSet(t,
			craParityWindow(t, repoSrc, repoRel,
				"report_type is required (one of ", ")"),
			repoRel+" report_type enumeration"),
		reportTypeValues)
	craParityAssertSetEqual(t,
		"F341 direction 4e (repository Insert lang error enumeration ↔ Go lang wire values)",
		craParityTokenSet(t,
			craParityWindow(t, repoSrc, repoRel,
				"lang is required (one of ", ")"),
			repoRel+" lang enumeration"),
		langValues)

	// (4f) evidence_pack/builder.go README line: the "(one of ...)"
	// enumeration rendered into every evidence-pack README must equal
	// the registered report-type set. The line anchor is asserted first
	// so a second "one of" elsewhere in the file cannot hijack the
	// window.
	const builderRel = "internal/service/evidence_pack/builder.go"
	builderSrc, ok := goFiles[builderRel]
	if !ok {
		t.Fatalf("F341 direction 4f setup: %s not found under %s.",
			builderRel, apiRoot)
	}
	const builderLineAnchor = "- **Report type**:"
	if n := strings.Count(builderSrc, builderLineAnchor); n != 1 {
		t.Fatalf("F341 direction 4f setup: expected exactly one %q line in "+
			"%s, found %d — the evidence-pack README shape changed; "+
			"re-anchor this probe.", builderLineAnchor, builderRel, n)
	}
	builderTail := builderSrc[strings.Index(builderSrc, builderLineAnchor):]
	craParityAssertSetEqual(t,
		"F341 direction 4f (evidence-pack README report-type enumeration ↔ Go wire values)",
		craParityTokenSet(t,
			craParityWindow(t, builderTail, builderRel, "(one of ", ")"),
			builderRel+" report-type enumeration"),
		reportTypeValues)

	// ------- Direction 5: Go wire values ↔ i18n messages catalogs (F358) -------

	// The messages root sits BESIDE apps/web/src, so the 3e census can
	// never have seen it (that walk is rooted at webSrcRoot and filtered
	// to .ts/.tsx); direction 5 walks it explicitly.
	msgsRoot := filepath.Clean(filepath.Join(webSrcRoot, "..", "messages"))
	msgFiles := craParityScanTree(t, msgsRoot,
		map[string]bool{".json": true}, "")

	// (5a/5b) Per-catalog label-object key sets. Both locales are pinned
	// individually so a key missing from ja.json alone (the en-first
	// copy-paste failure mode) is named in the diff.
	msgCatalogs := []string{"en.json", "ja.json"}
	for _, rel := range msgCatalogs {
		src, ok := msgFiles[rel]
		if !ok {
			t.Fatalf("F358 direction 5 setup: %s not found under %s — the "+
				"i18n catalog moved or was renamed; update this test.",
				rel, msgsRoot)
		}
		craParityAssertSetEqual(t,
			"F358 direction 5a ("+rel+" CRAReports.ReportType label keys ↔ Go report-type wire values)",
			craParityMessagesObjectKeys(t, src, rel, "CRAReports.ReportType"),
			reportTypeValues)
		craParityAssertSetEqual(t,
			"F358 direction 5b ("+rel+" CRAReports.Lang label keys ↔ Go lang wire values)",
			craParityMessagesObjectKeys(t, src, rel, "CRAReports.Lang"),
			langValues)
	}

	// (5c) Messages census: report-type wire values may appear only in
	// the two pinned catalogs. A third locale file (or any other .json
	// under apps/web/messages) naming a wire value must be brought under
	// this parity contract deliberately — same discipline as 1c / 3e.
	wantMsgLiteralFiles := map[string]bool{
		"en.json": true,
		"ja.json": true,
	}
	gotMsgLiteralFiles := make(map[string]bool)
	for rel, src := range msgFiles {
		if literalRe.MatchString(src) {
			gotMsgLiteralFiles[rel] = true
		}
	}
	craParityAssertSetEqual(t,
		"F358 direction 5c (messages catalogs mentioning CRA report-type wire values)",
		gotMsgLiteralFiles, wantMsgLiteralFiles)
}

// -----------------------------------------------------------------------------
// Helpers (all craParity-prefixed; package cra has no other parity
// helpers, but the prefix keeps the F330-family naming convention)
// -----------------------------------------------------------------------------

// craParityReportTypeConstRe matches one typed const declaration line
//
//	ReportTypeEarlyWarning ReportType = "early_warning"
//
// in templates.go. The declaration shape itself is the anchor (no line
// numbers), so nothing else in the file can match. The value capture
// class is wider than snake_case (F347 parse-liberal / assert-strict):
// a camelCase wire value in a declaration still enters the parsed
// universe and fails direction 1a against SupportedReportTypes()
// instead of silently dropping out of the authoritative set.
var craParityReportTypeConstRe = regexp.MustCompile(
	`(?m)^\s*(ReportType[A-Za-z0-9]+)\s+ReportType\s*=\s*"([A-Za-z0-9_\-]+)"`)

// craParityLangConstRe matches one typed const declaration line
//
//	LangJA Lang = "ja"
//
// in templates.go, same technique (and the same F347-widened value
// capture class as craParityReportTypeConstRe).
var craParityLangConstRe = regexp.MustCompile(
	`(?m)^\s*(Lang[A-Za-z0-9]+)\s+Lang\s*=\s*"([A-Za-z0-9_\-]+)"`)

// craParityQuotedRe captures double-quoted wire-value identifiers. The
// capture class is deliberately WIDER than the snake_case wire-value
// shape (F347 parse-liberal / assert-strict): a camelCase member
// smuggled into a union or option array ("incidentReport") must be
// captured and fail the set comparison as an unexpected extra entry —
// the previous [a-z0-9_\-] class could not reach the closing quote of
// such a member and silently skipped it (latent false negative). The +
// still means the "" filter sentinel in the page.tsx option arrays can
// never be captured (F326).
var craParityQuotedRe = regexp.MustCompile(`"([A-Za-z0-9_\-]+)"`)

// craParityTokenRe captures bare wire-value-shaped tokens inside a
// prose enumeration window such as
//
//	early_warning|detailed_notification|final_report
//	early_warning [24h] | detailed_notification [72h] | final_report
//
// The leading [a-z] plus \b means bracketed annotations like [24h]
// cannot produce a token. The tail class is deliberately wider than
// snake_case (F347 parse-liberal / assert-strict): a camelCase drift
// token is captured whole and fails the set comparison loudly — the
// previous [a-z0-9_] tail truncated at the first uppercase letter, so
// a drift like "early_warningExtra" collapsed to the registered value
// "early_warning" and silently passed.
var craParityTokenRe = regexp.MustCompile(`\b[a-z][A-Za-z0-9_]*`)

// craParityEmbedsDocRe / craParityDimsDocRe / craParityEnumDocRe anchor
// the three numeric factuality claims in templates.go probed by
// direction 4a-4c.
var craParityEmbedsDocRe = regexp.MustCompile(
	`templatesFS embeds the ([a-z0-9]+) Markdown templates`)
var craParityDimsDocRe = regexp.MustCompile(
	`\((\d+) report types x (\d+) languages\)`)
var craParityEnumDocRe = regexp.MustCompile(
	`ReportType enumerates the ([a-z0-9]+) CRA Article 14 report types`)

// craParityStableOrderRe captures the parenthesised token list of a
// "Stable order (early -> detailed -> final)" docstring claim.
var craParityStableOrderRe = regexp.MustCompile(`Stable order \(([^)]+)\)`)

// craParityRoots resolves the apps/api and apps/web/src roots from this
// file's own location (runtime.Caller anchor, F318/F330 technique), so
// resolution is independent of the working directory. thisFile is
// returned so the census walk can exclude this test file itself.
func craParityRoots(t *testing.T) (apiRoot, webSrcRoot, thisFile string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("F341 setup: runtime.Caller failed")
	}
	// this file: apps/api/internal/service/cra/templates_parity_test.go
	craDir := filepath.Dir(thisFile)
	apiRoot = filepath.Clean(filepath.Join(craDir, "..", "..", ".."))
	webSrcRoot = filepath.Clean(filepath.Join(apiRoot, "..", "web", "src"))
	return apiRoot, webSrcRoot, thisFile
}

// craParityScanTree walks root and returns file contents keyed by
// slash-separated path relative to root, filtered to the given
// extensions. skipAbs (when non-empty) names one absolute path to
// exclude — this test file itself, whose docstring and pinned sets
// necessarily mention the wire values. Unlike the F330 walker, _test.go
// files are NOT skipped: the direction 1c census deliberately covers
// them. node_modules / testdata / .next / hidden directories are
// skipped defensively.
func craParityScanTree(
	t *testing.T,
	root string,
	exts map[string]bool,
	skipAbs string,
) map[string]string {
	t.Helper()
	out := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == "node_modules" || name == "testdata" ||
				name == ".next" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !exts[filepath.Ext(name)] {
			return nil
		}
		if skipAbs != "" && path == skipAbs {
			return nil
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("F341 setup: walking %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("F341 setup: tree walk of %s matched no files — wrong "+
			"root or extension filter; update this test.", root)
	}
	return out
}

// craParityConsts parses one typed const family out of templates.go
// source and returns symbol → wire value. Requires at least two
// declarations so a const-block reshape the regex can no longer see
// fails loudly instead of passing every direction vacuously, and fails
// on duplicate wire values (they would make the template filename
// registry ambiguous).
func craParityConsts(
	t *testing.T,
	src string,
	re *regexp.Regexp,
	kind string,
) map[string]string {
	t.Helper()
	matches := re.FindAllStringSubmatch(src, -1)
	if len(matches) < 2 {
		t.Fatalf("F341 setup: found %d %s const declarations in "+
			"templates.go (expected >= 2) — either the const block was "+
			"reshaped away from the `Name Type = \"value\"` form or "+
			"entries were removed; update this parser or the test.",
			len(matches), kind)
	}
	out := make(map[string]string, len(matches))
	valueToSym := make(map[string]string, len(matches))
	for _, m := range matches {
		sym, val := m[1], m[2]
		out[sym] = val
		if prev, dup := valueToSym[val]; dup {
			t.Fatalf("F341 setup: wire value %q is declared by both %s and "+
				"%s — duplicate wire values make the template filename "+
				"registry ambiguous; fix the const block.", val, prev, sym)
		}
		valueToSym[val] = sym
	}
	return out
}

// craParityLiteralRe builds the wire-value mention detector from the
// parsed const universe, so the censuses automatically track future
// report types. Prefix form (leading \b, no trailing \b) so composite
// tokens such as "early_warning_ja" and prose mentions in comments all
// count as mentions.
func craParityLiteralRe(valueSet map[string]bool) *regexp.Regexp {
	vals := make([]string, 0, len(valueSet))
	for v := range valueSet {
		vals = append(vals, regexp.QuoteMeta(v))
	}
	sort.Strings(vals)
	return regexp.MustCompile(`\b(?:` + strings.Join(vals, "|") + `)`)
}

// craParityWindow returns the text between startAnchor and the first
// endAnchor after it (both exclusive) — the anchor-terminated slice
// technique (F326: no byte offsets, no line numbers). The start anchor
// must occur exactly once; a miss or a duplicate fails loudly so the
// probe can never silently scan the wrong window.
func craParityWindow(t *testing.T, src, rel, startAnchor, endAnchor string) string {
	t.Helper()
	if n := strings.Count(src, startAnchor); n != 1 {
		t.Fatalf("F341 setup: expected exactly one occurrence of anchor %q "+
			"in %s, found %d — the anchored text was reworded, moved, or "+
			"duplicated; re-anchor this probe deliberately rather than "+
			"letting it pass (or scan) vacuously.", startAnchor, rel, n)
	}
	start := strings.Index(src, startAnchor) + len(startAnchor)
	end := strings.Index(src[start:], endAnchor)
	if end < 0 {
		t.Fatalf("F341 setup: no terminating %q found after anchor %q in "+
			"%s — the anchored block lost its terminator; update this "+
			"anchor pair.", endAnchor, startAnchor, rel)
	}
	return src[start : start+end]
}

// craParityQuotedSet extracts the double-quoted identifiers of a window
// as a set, failing loudly on an empty result (an emptied union or
// option array needs review, not a vacuous pass) and on a duplicated
// value (F352: the map collapse would otherwise let a doubled union
// member or option-array entry — which renders twice in the UI
// dropdown — pass the downstream set-equality untouched).
func craParityQuotedSet(t *testing.T, window, label string) map[string]bool {
	t.Helper()
	ms := craParityQuotedRe.FindAllStringSubmatch(window, -1)
	if len(ms) == 0 {
		t.Fatalf("F341 setup: no quoted identifiers found in %s — the "+
			"syntax changed or the list emptied; both need review.", label)
	}
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		if out[m[1]] {
			t.Fatalf("F341 setup (F352 duplicate guard): quoted value %q "+
				"appears more than once in %s — a duplicated entry renders "+
				"twice in the UI (or duplicates a TS union member) and "+
				"would be invisible to the set comparison; remove the "+
				"duplicate.", m[1], label)
		}
		out[m[1]] = true
	}
	return out
}

// craParityTokenSet extracts the bare wire-value-shaped tokens of a
// prose enumeration window as a set, failing loudly on an empty result.
func craParityTokenSet(t *testing.T, window, label string) map[string]bool {
	t.Helper()
	ms := craParityTokenRe.FindAllString(window, -1)
	if len(ms) == 0 {
		t.Fatalf("F341 setup: no enumeration tokens found in %s — the "+
			"message shape changed; update this probe deliberately rather "+
			"than letting it pass vacuously.", label)
	}
	out := make(map[string]bool, len(ms))
	for _, m := range ms {
		out[m] = true
	}
	return out
}

// craParityMessagesObjectKeys returns the key set of the JSON object
// stored at the exact dot-joined key path objPath (e.g.
// "CRAReports.ReportType") in the document src (direction 5, F358;
// full-path anchor: F362, M24 R2). The document is walked with an
// encoding/json token decoder — the frame stack carries each
// container's key path — rather than json.Unmarshal, so three failure
// modes stay loud that map-decoding (or the pre-F362 match-anywhere
// walk) would silently absorb:
//
//   - parent-namespace drift (F362): the pre-F362 walk matched a
//     "ReportType" / "Lang" object ANYWHERE in the document, so
//     renaming the parent CRAReports namespace — which strands the
//     labels next-intl resolves under CRAReports.* — kept the probe
//     GREEN (R1-proven). Matching only at objPath turns that rename
//     into a loud zero-match failure;
//   - exactly-once (F326 spirit): objPath resolving to more than one
//     object (possible only via duplicate parent keys, the same
//     decoder-collapse family as F352) would make the probe window
//     ambiguous — fatal, re-anchor deliberately;
//   - duplicate keys (F352 lineage): a doubled key inside the object is
//     last-wins-collapsed by every JSON map decoder (including
//     next-intl's), silently discarding one label — fatal here at parse
//     time instead.
//
// Containers reached through an array get a "[]" path segment, so an
// array-nested object can never satisfy a dot-joined key path. Only the
// matched object's OWN keys are collected (nested objects, if the
// catalog shape ever grows them, are not flattened in). An empty
// matched object is fatal: an emptied label catalog needs review, not a
// vacuous set comparison.
func craParityMessagesObjectKeys(
	t *testing.T,
	src, rel, objPath string,
) map[string]bool {
	t.Helper()
	type frame struct {
		obj       bool
		expectKey bool
		lastKey   string
		path      string // dot-joined key path of this container ("" = root)
		capture   bool
	}
	dec := json.NewDecoder(strings.NewReader(src))
	var stack []*frame
	matches := 0
	keys := make(map[string]bool)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("F358 direction 5 setup: %s is not parseable JSON: %v",
				rel, err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				childPath := ""
				if top != nil {
					if top.obj && !top.expectKey {
						// This delimiter is the value for top.lastKey; the
						// token after the block closes is the next key.
						childPath = craParityJoinPath(top.path, top.lastKey)
						top.expectKey = true
					} else {
						// Array element: "[]" can never appear in a
						// dot-joined key path, so array-nested objects
						// are unmatched by construction.
						childPath = craParityJoinPath(top.path, "[]")
					}
				}
				capture := d == '{' && childPath == objPath
				if capture {
					matches++
				}
				stack = append(stack, &frame{
					obj:       d == '{',
					expectKey: d == '{',
					path:      childPath,
					capture:   capture && matches == 1,
				})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top == nil {
			continue // top-level scalar document — nothing to track
		}
		if top.obj && top.expectKey {
			k, ok := tok.(string)
			if !ok {
				t.Fatalf("F358 direction 5 setup: %s: non-string object "+
					"key token %v — malformed catalog.", rel, tok)
			}
			if top.capture {
				if keys[k] {
					t.Fatalf("F358 direction 5 setup (F352 duplicate "+
						"guard): key %q appears more than once inside the "+
						"%s object of %s — JSON map decoding (including "+
						"next-intl's) silently keeps only the last one; "+
						"remove the duplicate.", k, objPath, rel)
				}
				keys[k] = true
			}
			top.lastKey = k
			top.expectKey = false
			continue
		}
		// Scalar value inside an object or array.
		if top.obj {
			top.expectKey = true
		}
	}
	if matches != 1 {
		t.Fatalf("F358 direction 5 setup (F362 full-path anchor): expected "+
			"exactly one object at key path %q in %s, found %d — the "+
			"catalog structure changed, the parent namespace was renamed, "+
			"or a duplicate parent key landed; move the catalogs and this "+
			"probe together deliberately rather than letting it scan the "+
			"wrong (or no) window.",
			objPath, rel, matches)
	}
	if len(keys) == 0 {
		t.Fatalf("F358 direction 5 setup: the %q object in %s is empty — "+
			"an emptied label catalog needs review, not a vacuous pass.",
			objPath, rel)
	}
	return keys
}

// craParityJoinPath dot-joins a container path with a child key; the
// root path is the empty string, so root-level keys join to themselves.
func craParityJoinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}

// craParityExactlyOne runs re over src and requires exactly one match,
// returning its submatches. Zero matches means the anchored doc claim
// was reworded (probe must be re-anchored deliberately); two or more
// means the window is ambiguous.
func craParityExactlyOne(
	t *testing.T,
	re *regexp.Regexp,
	src, rel, label string,
) []string {
	t.Helper()
	ms := re.FindAllStringSubmatch(src, -1)
	if len(ms) != 1 {
		t.Fatalf("F341 setup: expected exactly one match for the %s "+
			"(regexp %q) in %s, found %d — the docstring was reworded; "+
			"update this probe deliberately rather than letting it pass "+
			"vacuously.", label, re.String(), rel, len(ms))
	}
	return ms[0]
}

// craParityNumber converts a spelled-out ("six") or numeric ("6") count
// from a docstring into an int, failing loudly on anything it cannot
// parse.
func craParityNumber(t *testing.T, word, context string) int {
	t.Helper()
	words := map[string]int{
		"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
		"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
		"twelve": 12,
	}
	if n, ok := words[word]; ok {
		return n
	}
	if n, err := strconv.Atoi(word); err == nil {
		return n
	}
	t.Fatalf("F341 direction 4 setup: cannot parse %q as a count in %s — "+
		"the doc was reworded beyond this probe's vocabulary; update the "+
		"probe deliberately.", word, context)
	return 0
}

// craParityAssertDocOrder checks a "Stable order (a -> b -> c)"
// docstring claim against the runtime slice: same arity, and each doc
// token must be a prefix of the runtime value at the same position
// ("early" → "early_warning", "ja" → "ja").
func craParityAssertDocOrder(
	t *testing.T,
	label, docTokens string,
	runtimeVals []string,
) {
	t.Helper()
	tokens := strings.Split(docTokens, "->")
	if len(tokens) != len(runtimeVals) {
		t.Errorf("%s: doc claims a %d-step order %q but the runtime slice "+
			"has %d entries — update the docstring alongside the registry.",
			label, len(tokens), docTokens, len(runtimeVals))
		return
	}
	for i, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" || !strings.HasPrefix(runtimeVals[i], tok) {
			t.Errorf("%s: doc order token %q (position %d) is not a prefix "+
				"of the runtime value %q at that position — the documented "+
				"stable order went stale; update the docstring alongside "+
				"the registry.", label, tok, i, runtimeVals[i])
		}
	}
}

// craParityAssertSetEqual compares two string sets and fails with one
// stable, sorted diff line per divergence.
func craParityAssertSetEqual(t *testing.T, label string, got, want map[string]bool) {
	t.Helper()
	keys := make(map[string]bool, len(got)+len(want))
	for k := range got {
		keys[k] = true
	}
	for k := range want {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		switch {
		case got[k] && !want[k]:
			t.Errorf("%s: unexpected extra entry %q — either register it on "+
				"every surface of this parity contract or remove it, then "+
				"update this test deliberately.", label, k)
		case !got[k] && want[k]:
			t.Errorf("%s: missing entry %q — a surface lost a value the "+
				"registry still declares (or a hand-maintained pin went "+
				"stale); move all surfaces together.", label, k)
		}
	}
}
