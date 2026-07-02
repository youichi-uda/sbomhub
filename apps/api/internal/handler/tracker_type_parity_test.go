package handler

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestTrackerTypeRegistryParity_F330 is the third horizontal replication
// of anti-pattern 58 (emit / registry parity in dual-list systems)
// outside the audit dimension (F271 Action / F281 Resource), following
// F299 (M20-2, Plan feature registry ↔ SQL seed, first replication) and
// F318 (M21-1, LLM Provider registry, second replication — see
// settings_llm_parity_test.go, the direct template for this test). The
// dual (in fact three-way) list here is the issue-tracker type
// registry, which appears on the following surfaces that must all
// agree on the set of tracker identifiers:
//
//	(Go consts)    apps/api/internal/model/issue_tracker.go
//	               `model.TrackerType*` typed const block — the
//	               authoritative symbol + wire-value universe
//	               (currently TrackerTypeJira="jira",
//	               TrackerTypeBacklog="backlog").
//
//	(Go switches)  4 dispatch sites, hand-maintained in
//	               trackerParitySwitchSites below:
//	                 - service/issue_tracker.go testConnection,
//	                   CreateTicket, SyncTicket — `case
//	                   model.TrackerType*:` arms with a default arm
//	                   returning "unsupported tracker type".
//	                 - handler/issue_tracker.go CreateConnection —
//	                   `case "jira" / "backlog":` on the RAW request
//	                   string BEFORE it is mapped to the model const
//	                   (this 4th site was absent from the M22-1
//	                   kickoff draft and surfaced only in the
//	                   orchestrator survey; the universal switch-site
//	                   census below exists so the NEXT such site
//	                   cannot hide).
//
//	(Web surfaces) apps/web/src/lib/api.ts `export type TrackerType`
//	               TS union, and apps/web/src/app/[locale]/(dashboard)/
//	               settings/integrations/page.tsx SelectItem dropdown
//	               values (plus the useState default and the
//	               setTrackerType reset literal on the same page).
//
// (Plus two documentation touch-points probed in Direction 3:
//
//	(Go doc)  apps/api/internal/scheduler/ticket_sync.go's F274b
//	          comment, which names the model.TrackerType* switch arms
//	          of SyncTicket by symbol.
//	(Go doc)  handler/issue_tracker.go's 400 error message
//	          "Invalid tracker_type. Must be 'jira' or 'backlog'",
//	          which enumerates the wire values operators may send.)
//
// If any two of these drift, one of the following silent breakage
// shapes results:
//
//   - handler switch extended without the service switches: the API
//     accepts a tracker_type whose immediate testConnection call dies
//     in the default arm ("unsupported tracker type"), and any row
//     that still lands is undispatchable in CreateTicket / SyncTicket.
//   - service switches extended without the handler switch: the
//     backend can dispatch a tracker no request can ever select (dead
//     arm, 400 "Invalid tracker_type" on every create attempt).
//   - Go extended without the web surfaces: operators must hit the
//     API by hand because neither the dropdown nor the TS types
//     surface the new tracker.
//   - web surfaces extended without Go: the dropdown offers a tracker
//     the backend rejects on save (400).
//   - a model const added with no switch arm anywhere: dead registry
//     entry; every dispatch site errors at runtime.
//
// Directions (same 3-direction shape as F318):
//
//	(1) Direction 1 — Go const set ↔ the 4 switch sites. Case arms are
//	    parsed out of anchor-terminated per-function windows (F318's
//	    extractProviderCaseArms technique) and compared bidirectionally
//	    (F324 lesson: a const with no arm AND an arm with no const both
//	    fail). A universal switch-site census walks every non-test .go
//	    file under apps/api and requires the per-file count of
//	    `switch <expr>.TrackerType {` headers to exactly match the
//	    hand-maintained site list, so adding a 5th dispatch site
//	    anywhere fails this test until the list is updated. A second
//	    census requires tracker wire-value string literals in non-test
//	    Go files to appear ONLY in the model const block and the
//	    handler switch file (anti-pattern 48 universe pin).
//
//	(2) Direction 2 — cross-language 3-way: Go wire values ↔ the
//	    api.ts TS union ↔ the page.tsx SelectItem values, plus
//	    membership checks on the page's useState default and
//	    setTrackerType reset literals, plus a web-side literal census
//	    pinning which .ts/.tsx files may mention the wire values at
//	    all. All web parsing is read-only, anchored on syntactic
//	    markers and terminated by closing anchors (F326 discipline: no
//	    byte-offset windows, no hardcoded line numbers, identifier
//	    char class [a-z0-9_-]).
//
//	(3) Direction 3 — doc factuality (F276 lineage): every
//	    model.TrackerType* symbol the ticket_sync.go doc comment names
//	    must exist in the const block (referenced → real), and every
//	    const symbol must be named by that comment (real → referenced,
//	    so a new tracker's SyncTicket arm cannot leave the F274b
//	    HTTP-in-tx narrative silently incomplete). F339 (M22 R2): the
//	    mention scan runs over an anchor-terminated slice of the
//	    TicketSyncJob doc comment (F331 technique), NOT the whole
//	    file, so a future CODE-level model.TrackerType* reference in
//	    ticket_sync.go cannot vacuously satisfy the doc-completeness
//	    direction while the comment itself stays stale. The handler's
//	    400 message must enumerate exactly the registered wire-value
//	    set in single-quoted form — bidirectional (F337, M22 R2): a
//	    registered value missing from the message AND a stale
//	    single-quoted token in the message that no const declares both
//	    fail.
//
// What THIS test DOES catch:
//
//   - Any model.TrackerType* const added/removed without updating ALL
//     4 switch sites (both drift directions per site).
//   - Any new `switch <expr>.TrackerType` dispatch site added under
//     apps/api (non-test) without registering it in
//     trackerParitySwitchSites.
//   - Any new "jira"/"backlog" (or future wire-value) string literal
//     appearing in a non-test Go file, or a .ts/.tsx file, outside
//     the pinned file sets.
//   - TS union or SelectItem drift from the Go wire-value set, and a
//     useState default / setTrackerType reset naming a value the Go
//     registry does not contain.
//   - ticket_sync.go's doc comment naming a model.TrackerType* symbol
//     that does not exist, or omitting one that does (even if code in
//     the same file mentions it — F339 comment-window slice); the
//     handler 400 message not listing every registered wire value, or
//     listing a single-quoted token that is not a registered wire
//     value (F337 bidirectional).
//   - page.tsx losing (or duplicating) the useState<TrackerType>
//     default or the setTrackerType reset literal — both probes
//     require exactly one match, so a form reshape that silently
//     removes the hardcoded literal fails loudly instead of being
//     vacuously accepted (F339).
//
// What THIS test does NOT catch (documented factuality trade-off,
// mirrors the F276 note on F271 / F281 / F299 / F318):
//
//   - Wire-value stability. A coordinated rename ("jira" → "Jira") on
//     every surface in one PR passes this test even though it breaks
//     every persisted issue_tracker_connections.tracker_type row on
//     upgrade. Policing wire-value stability is out of scope (same
//     trade-off as the four earlier parity tests).
//   - A switch on a LOCAL variable of type model.TrackerType (e.g.
//     `tt := conn.TrackerType; switch tt {`) — the census matches
//     field-access headers (`switch ....TrackerType {`) only. No such
//     site exists today; introducing one is a review-required reshape.
//   - An if/else equality-chain dispatch (`if conn.TrackerType ==
//     model.TrackerTypeJira { ... } else { ... }`) — not a switch
//     header, so the direction 1a census cannot see it (F339). The
//     only non-test `.TrackerType ==` comparison today is the
//     handler's empty-string required-field check, which names no
//     tracker; a dispatch-shaped equality chain on a wire value or
//     const would land in the direction 1c literal census only if it
//     used a raw literal in a NEW file — a symbol-based equality
//     chain in an already-pinned file is invisible to this test and
//     is a review-required reshape.
//   - Two-member-universe assumptions in display ternaries:
//     page.tsx and create-ticket-button.tsx render labels via
//     `tracker_type === "jira" ? "Jira" : "Backlog"`, so a third
//     tracker would silently render the "Backlog" label. These are
//     equality comparisons, not dispatch switches; the web literal
//     census pins their FILE set but cannot see the binary
//     assumption inside them.
//   - The DB layer: migration 015_issue_tracker.up.sql declares
//     tracker_type VARCHAR(20) with NO CHECK constraint (any string
//     is storable) and its `-- 'jira', 'backlog'` comment is an
//     immutable historical record. Neither is parsed here.
//   - Human-readable display names ("Jira", "Backlog" capitalized
//     JSX labels, i18n catalogs) — only wire identifiers are pinned.
//
// Adding a new tracker (e.g. GitHub Issues) going forward — this test
// fails until ALL of the following move together, which is exactly the
// 3-way sync this replication exists to force:
//
//	model.TrackerTypeGitHub const in model/issue_tracker.go, case
//	arms in testConnection + CreateTicket + SyncTicket AND the
//	handler CreateConnection switch (updating its 400 message), the
//	api.ts TrackerType union, the page.tsx SelectItem list, and the
//	ticket_sync.go F274b comment. If a NEW dispatch switch site is
//	introduced, register it in trackerParitySwitchSites. Add nothing
//	to an allowlist (there is none). Do not silence this test.
func TestTrackerTypeRegistryParity_F330(t *testing.T) {
	apiRoot, webSrcRoot := trackerParityRoots(t)

	// ------- Set-up: read the Go tree once, parse the const universe -------

	goFiles := trackerParityScanTree(t, apiRoot,
		map[string]bool{".go": true}, true /* skip _test.go */)

	const modelRel = "internal/model/issue_tracker.go"
	modelSrc, ok := goFiles[modelRel]
	if !ok {
		t.Fatalf("F330 setup: %s not found under %s — the model file "+
			"moved or the tree walk root is wrong; update this test.",
			modelRel, apiRoot)
	}

	symToVal := trackerParityModelConsts(t, modelSrc)
	symbolSet := make(map[string]bool, len(symToVal))
	valueSet := make(map[string]bool, len(symToVal))
	for sym, val := range symToVal {
		symbolSet[sym] = true
		if valueSet[val] {
			t.Fatalf("F330 setup: wire value %q is declared by more than "+
				"one model.TrackerType* const — duplicate wire values make "+
				"every switch ambiguous; fix the const block.", val)
		}
		valueSet[val] = true
	}

	// ------- Direction 1: Go const set ↔ the 4 switch sites -------

	// Hand-maintained dispatch-site list. The census below fails this
	// test whenever the real per-file count of TrackerType switch
	// headers differs from this list, so future sites cannot be added
	// silently (the handler site below was itself missed in the M22-1
	// kickoff draft — that near-miss is why the census exists).
	trackerParitySwitchSites := []trackerParitySwitchSite{
		{
			rel:        "internal/service/issue_tracker.go",
			funcAnchor: "func (s *IssueTrackerService) testConnection",
			name:       "service testConnection",
			symbolArms: true,
		},
		{
			rel:        "internal/service/issue_tracker.go",
			funcAnchor: "func (s *IssueTrackerService) CreateTicket",
			name:       "service CreateTicket",
			symbolArms: true,
		},
		{
			rel:        "internal/service/issue_tracker.go",
			funcAnchor: "func (s *IssueTrackerService) SyncTicket",
			name:       "service SyncTicket",
			symbolArms: true,
		},
		{
			rel:        "internal/handler/issue_tracker.go",
			funcAnchor: "func (h *IssueTrackerHandler) CreateConnection",
			name:       "handler CreateConnection",
			symbolArms: false, // raw request string, literal case arms
		},
	}

	// (1a) Universal switch-site census: per-file header counts across
	// every non-test .go file under apps/api must equal the counts
	// implied by the hand-maintained list.
	wantSwitchCounts := make(map[string]int)
	for _, site := range trackerParitySwitchSites {
		wantSwitchCounts[site.rel]++
	}
	gotSwitchCounts := make(map[string]int)
	for rel, src := range goFiles {
		if n := len(trackerParitySwitchHeaderRe.FindAllStringIndex(src, -1)); n > 0 {
			gotSwitchCounts[rel] = n
		}
	}
	trackerParityAssertCountsEqual(t,
		"F330 direction 1a (universal TrackerType switch-site census)",
		gotSwitchCounts, wantSwitchCounts,
		"register the new dispatch site in trackerParitySwitchSites (or "+
			"remove the stale entry) so its case arms join the parity "+
			"contract")

	// (1b) Per-site case-arm parity, bidirectional.
	for _, site := range trackerParitySwitchSites {
		src, ok := goFiles[site.rel]
		if !ok {
			t.Fatalf("F330 direction 1b setup: %s not found under %s.",
				site.rel, apiRoot)
		}
		window := trackerParityFuncWindow(t, src, site.funcAnchor, site.name)
		got := trackerParityCaseArms(t, window, site)
		want := symbolSet
		if !site.symbolArms {
			want = valueSet
		}
		assertSetEqual(t,
			"F330 direction 1b ("+site.name+" case arms ↔ model.TrackerType* consts)",
			got, want)
	}

	// (1c) Universal Go literal census: tracker wire-value string
	// literals in non-test Go files may appear ONLY in the const block
	// itself and in the handler switch file (case arms + 400 message).
	literalRe := trackerParityLiteralRe(valueSet)
	wantGoLiteralFiles := map[string]bool{
		"internal/model/issue_tracker.go":   true,
		"internal/handler/issue_tracker.go": true,
	}
	gotGoLiteralFiles := make(map[string]bool)
	for rel, src := range goFiles {
		if literalRe.MatchString(src) {
			gotGoLiteralFiles[rel] = true
		}
	}
	assertSetEqual(t,
		"F330 direction 1c (Go files containing tracker wire-value literals)",
		gotGoLiteralFiles, wantGoLiteralFiles)

	// ------- Direction 2: Go wire values ↔ TS union ↔ UI dropdown -------

	webFiles := trackerParityScanTree(t, webSrcRoot,
		map[string]bool{".ts": true, ".tsx": true}, false)

	const apiTSRel = "lib/api.ts"
	apiTS, ok := webFiles[apiTSRel]
	if !ok {
		t.Fatalf("F330 direction 2 setup: %s not found under %s — the web "+
			"API client moved; update this test.", apiTSRel, webSrcRoot)
	}
	tsUnion := trackerParityTSUnion(t, apiTS, apiTSRel)
	assertSetEqual(t,
		"F330 direction 2 (api.ts TrackerType union ↔ Go wire values)",
		tsUnion, valueSet)

	const pageRel = "app/[locale]/(dashboard)/settings/integrations/page.tsx"
	pageTSX, ok := webFiles[pageRel]
	if !ok {
		t.Fatalf("F330 direction 2 setup: %s not found under %s — the "+
			"integrations settings page moved; update this test.",
			pageRel, webSrcRoot)
	}
	selectItems := trackerParitySelectItems(t, pageTSX, pageRel)
	assertSetEqual(t,
		"F330 direction 2 (page.tsx SelectItem values ↔ Go wire values)",
		selectItems, valueSet)

	// Default-value membership: the page hardcodes an initial and a
	// reset tracker value; both must name a registered wire value so a
	// tracker removal cannot leave the form defaulting to a value the
	// backend rejects.
	defaults := trackerParityUseStateRe.FindAllStringSubmatch(pageTSX, -1)
	if len(defaults) != 1 {
		t.Fatalf("F330 direction 2 setup: expected exactly one "+
			"useState<TrackerType>(\"...\") literal in %s, found %d — the "+
			"form state shape changed; update this parser.",
			pageRel, len(defaults))
	}
	// F339 (M22 R2): the reset literal is held to the same
	// exactly-one bar as the useState default. Pre-F339 a zero-match
	// scan was vacuously accepted, so removing (or reshaping) the
	// setTrackerType("...") reset call silently dropped the membership
	// probe instead of failing loudly.
	setters := trackerParitySetterRe.FindAllStringSubmatch(pageTSX, -1)
	if len(setters) != 1 {
		t.Fatalf("F330 direction 2 setup: expected exactly one "+
			"setTrackerType(\"...\") reset literal in %s, found %d — the "+
			"form reset shape changed; update this parser (and keep the "+
			"reset value inside the parity contract).",
			pageRel, len(setters))
	}
	for _, m := range append(defaults, setters...) {
		if !valueSet[m[1]] {
			t.Errorf("F330 direction 2: %s hardcodes tracker default/reset "+
				"value %q which is not a registered Go wire value — update "+
				"the hardcoded literal alongside the registry.", pageRel, m[1])
		}
	}

	// Web literal census: wire-value literals in .ts/.tsx may appear
	// only in the three known files (types, form page, display ternary
	// in the ticket button). A new file naming a wire value must be
	// either brought under this parity contract or use the TS union.
	wantWebLiteralFiles := map[string]bool{
		apiTSRel: true,
		pageRel:  true,
		"components/vulnerability/create-ticket-button.tsx": true,
	}
	gotWebLiteralFiles := make(map[string]bool)
	for rel, src := range webFiles {
		if literalRe.MatchString(src) {
			gotWebLiteralFiles[rel] = true
		}
	}
	assertSetEqual(t,
		"F330 direction 2 (web files containing tracker wire-value literals)",
		gotWebLiteralFiles, wantWebLiteralFiles)

	// ------- Direction 3: doc factuality (F276 lineage) -------

	// (3a) scheduler/ticket_sync.go F274b comment: every
	// model.TrackerType* symbol it names must exist, and every declared
	// const must be named, so the HTTP-in-tx narrative stays factually
	// complete when a tracker is added or removed.
	//
	// F339 (M22 R2): the scan window is the TicketSyncJob doc comment
	// only, located via an anchor-terminated slice (F331 technique:
	// doc-comment first line → the type declaration that terminates
	// it). Pre-F339 the scan ran over the WHOLE file, so a future
	// code-level model.TrackerType* reference (e.g. a dispatch added
	// to this scheduler) would have satisfied the "mentioned" set and
	// let the doc comment go stale without failing this direction.
	// Everything between the two anchors is comment text by
	// construction, so only prose can satisfy the probe.
	const schedRel = "internal/scheduler/ticket_sync.go"
	schedSrc, ok := goFiles[schedRel]
	if !ok {
		t.Fatalf("F330 direction 3 setup: %s not found under %s.",
			schedRel, apiRoot)
	}
	const schedDocStartAnchor = "// TicketSyncJob handles periodic ticket synchronization"
	const schedDocEndAnchor = "type TicketSyncJob struct"
	docStart := strings.Index(schedSrc, schedDocStartAnchor)
	if docStart < 0 {
		t.Fatalf("F330 direction 3 setup: cannot locate the TicketSyncJob "+
			"doc-comment start anchor %q in %s — the comment's first line "+
			"was rephrased; update this anchor deliberately rather than "+
			"letting the probe pass vacuously.", schedDocStartAnchor, schedRel)
	}
	docEnd := strings.Index(schedSrc[docStart:], schedDocEndAnchor)
	if docEnd < 0 {
		t.Fatalf("F330 direction 3 setup: cannot locate the %q end anchor "+
			"after the doc-comment start anchor in %s — the type was "+
			"renamed or the comment detached from it; update this anchor "+
			"pair.", schedDocEndAnchor, schedRel)
	}
	schedDocWindow := schedSrc[docStart : docStart+docEnd]
	mentioned := make(map[string]bool)
	for _, m := range trackerParityModelSymRe.FindAllStringSubmatch(schedDocWindow, -1) {
		mentioned[m[1]] = true
	}
	if len(mentioned) == 0 {
		t.Fatalf("F330 direction 3 setup: no model.TrackerType* symbol "+
			"mention found in the TicketSyncJob doc comment of %s — the "+
			"F274b comment was removed or reworded away from symbol "+
			"references; update this probe deliberately rather than "+
			"letting it pass vacuously.", schedRel)
	}
	assertSetEqual(t,
		"F330 direction 3 (ticket_sync.go doc-comment symbol mentions ↔ model.TrackerType* consts)",
		mentioned, symbolSet)

	// (3b) handler 400 message: the operator-facing "Must be ..." text
	// must enumerate exactly the registered wire-value set in single
	// quotes. F337 (M22 R2): the probe is bidirectional — pre-F337 it
	// only checked registered ⊆ message, so a tracker REMOVAL (or a
	// typo'd extra token) could leave the 400 message advertising a
	// wire value the handler switch no longer accepts. The message's
	// single-quoted tokens are extracted and compared as a full set.
	const handlerRel = "internal/handler/issue_tracker.go"
	handlerSrc := goFiles[handlerRel] // presence already asserted in 1b
	const msgAnchor = "Invalid tracker_type. Must be"
	msgStart := strings.Index(handlerSrc, msgAnchor)
	if msgStart < 0 {
		t.Fatalf("F330 direction 3 setup: cannot locate %q in %s — the "+
			"400 message was reworded; update this probe's anchor.",
			msgAnchor, handlerRel)
	}
	msgLine := handlerSrc[msgStart:]
	if nl := strings.IndexByte(msgLine, '\n'); nl >= 0 {
		msgLine = msgLine[:nl]
	}
	msgTokens := make(map[string]bool)
	for _, m := range trackerParityMsgTokenRe.FindAllStringSubmatch(msgLine, -1) {
		msgTokens[m[1]] = true
	}
	if len(msgTokens) == 0 {
		t.Fatalf("F330 direction 3 setup: no single-quoted wire-value "+
			"token found in the 400 message %q of %s — the message shape "+
			"changed; update this probe deliberately rather than letting "+
			"it pass vacuously.", msgLine, handlerRel)
	}
	assertSetEqual(t,
		"F330 direction 3 (handler 400-message single-quoted tokens ↔ Go wire values)",
		msgTokens, valueSet)
}

// -----------------------------------------------------------------------------
// Helpers (all trackerParity-prefixed to avoid collision with the F318
// helpers that share this package)
// -----------------------------------------------------------------------------

// trackerParitySwitchSite is one hand-maintained TrackerType dispatch
// site. symbolArms selects the case-arm style: true = `case
// model.TrackerType*:` (compared against the const SYMBOL set), false =
// `case "jira":` raw literals (compared against the WIRE-VALUE set).
type trackerParitySwitchSite struct {
	rel        string // path relative to apps/api, slash-separated
	funcAnchor string // start-of-function anchor for the scan window
	name       string // label used in failure messages
	symbolArms bool
}

// trackerParityConstRe matches one typed const declaration line
//
//	TrackerTypeJira    TrackerType = "jira"
//
// in model/issue_tracker.go. The declaration shape itself is the anchor
// (no line numbers, no sibling-type anchors), so AuthType / TicketStatus
// consts in the same file cannot match.
var trackerParityConstRe = regexp.MustCompile(
	`(?m)^\s*(TrackerType[A-Za-z0-9]+)\s+TrackerType\s*=\s*"([a-z0-9_\-]+)"`)

// trackerParitySwitchHeaderRe matches a switch statement header whose
// tag is a field access ending in .TrackerType, e.g.
//
//	switch conn.TrackerType {
//	switch req.TrackerType {
//	switch v := conn.TrackerType; v {
//
// Line-anchored so prose in comments (which always sits behind `//`)
// cannot match.
var trackerParitySwitchHeaderRe = regexp.MustCompile(
	`(?m)^\s*switch\b[^{\n]*\.TrackerType\b[^{\n]*\{`)

// trackerParityCaseLineRe captures the expression list of a `case ...:`
// line inside a scan window.
var trackerParityCaseLineRe = regexp.MustCompile(`(?m)^\s*case\s+([^:\n]+):`)

// trackerParityModelSymRe captures model.TrackerType* symbol references
// (in code or comments).
var trackerParityModelSymRe = regexp.MustCompile(`model\.(TrackerType[A-Za-z0-9]+)`)

// trackerParityQuotedRe captures quoted wire-value identifiers (F326
// identifier char class).
var trackerParityQuotedRe = regexp.MustCompile(`"([a-z0-9_\-]+)"`)

// trackerParityMsgTokenRe captures the SINGLE-quoted wire-value tokens
// of the handler's operator-facing 400 message ("Must be 'jira' or
// 'backlog'"), so direction 3b can compare the message's advertised
// set against the registry bidirectionally (F337, M22 R2).
var trackerParityMsgTokenRe = regexp.MustCompile(`'([a-z0-9_\-]+)'`)

// trackerParitySelectItemRe captures the value= attribute of a
// SelectItem inside the anchor-terminated SelectContent window.
var trackerParitySelectItemRe = regexp.MustCompile(
	`<SelectItem\s+value="([a-z0-9_\-]+)"`)

// trackerParityUseStateRe / trackerParitySetterRe capture the page's
// hardcoded initial and reset tracker values.
var trackerParityUseStateRe = regexp.MustCompile(
	`useState<TrackerType>\("([a-z0-9_\-]+)"\)`)
var trackerParitySetterRe = regexp.MustCompile(
	`setTrackerType\("([a-z0-9_\-]+)"\)`)

// trackerParityRoots resolves the apps/api and apps/web/src roots from
// this file's own location (runtime.Caller anchor, F318 technique), so
// resolution is independent of the working directory.
func trackerParityRoots(t *testing.T) (apiRoot, webSrcRoot string) {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("F330 setup: runtime.Caller failed")
	}
	// this file: apps/api/internal/handler/tracker_type_parity_test.go
	handlerDir := filepath.Dir(thisFile)
	apiRoot = filepath.Clean(filepath.Join(handlerDir, "..", ".."))
	webSrcRoot = filepath.Clean(filepath.Join(handlerDir,
		"..", "..", "..", "web", "src"))
	return apiRoot, webSrcRoot
}

// trackerParityScanTree walks root and returns file contents keyed by
// slash-separated path relative to root, filtered to the given
// extensions. skipTests drops *_test.go so test fixtures stay outside
// the parity universe. node_modules / hidden / testdata directories are
// skipped defensively.
func trackerParityScanTree(
	t *testing.T,
	root string,
	exts map[string]bool,
	skipTests bool,
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
		if skipTests && strings.HasSuffix(name, "_test.go") {
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
		t.Fatalf("F330 setup: walking %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("F330 setup: tree walk of %s matched no files — wrong "+
			"root or extension filter; update this test.", root)
	}
	return out
}

// trackerParityModelConsts parses the typed const declarations out of
// model/issue_tracker.go and returns symbol → wire value. Requires at
// least two declarations so a const-block reshape that the regex can no
// longer see fails loudly instead of passing every direction vacuously.
func trackerParityModelConsts(t *testing.T, modelSrc string) map[string]string {
	t.Helper()
	matches := trackerParityConstRe.FindAllStringSubmatch(modelSrc, -1)
	if len(matches) < 2 {
		t.Fatalf("F330 setup: found %d model.TrackerType* const "+
			"declarations (expected >= 2) — either the const block was "+
			"reshaped away from the `Name TrackerType = \"value\"` form "+
			"or trackers were removed; update this parser or the test.",
			len(matches))
	}
	out := make(map[string]string, len(matches))
	for _, m := range matches {
		out[m[1]] = m[2]
	}
	return out
}

// trackerParityFuncWindow slices src from the start of funcAnchor to
// the next top-level `func ` (or EOF) — the F318 "grep in a bounded
// window" technique. Not a Go parser by design; if the function is
// renamed the anchor misses and we fail loudly.
func trackerParityFuncWindow(t *testing.T, src, funcAnchor, name string) string {
	t.Helper()
	start := strings.Index(src, funcAnchor)
	if start < 0 {
		t.Fatalf("F330 direction 1b setup: cannot locate %s anchor %q — "+
			"the function may have been renamed; update "+
			"trackerParitySwitchSites.", name, funcAnchor)
	}
	body := src[start:]
	if end := strings.Index(body[len(funcAnchor):], "\nfunc "); end >= 0 {
		body = body[:len(funcAnchor)+end]
	}
	return body
}

// trackerParityCaseArms extracts the tracker identifiers from the case
// arms inside one function window. Symbol-style sites collect
// model.TrackerType* references (and flag a raw string literal arm as
// an explicit error, since `case "jira":` compiles fine in a typed
// switch but escapes symbol-level tooling); literal-style sites collect
// quoted wire values. Multi-value arms (`case a, b:`) are supported.
func trackerParityCaseArms(
	t *testing.T,
	window string,
	site trackerParitySwitchSite,
) map[string]bool {
	t.Helper()
	caseLines := trackerParityCaseLineRe.FindAllStringSubmatch(window, -1)
	if len(caseLines) == 0 {
		t.Fatalf("F330 direction 1b setup: no case arms found in the %s "+
			"window — the switch moved out of the anchored function; "+
			"update trackerParitySwitchSites.", site.name)
	}
	out := make(map[string]bool)
	for _, cl := range caseLines {
		exprs := cl[1]
		if site.symbolArms {
			syms := trackerParityModelSymRe.FindAllStringSubmatch(exprs, -1)
			if len(syms) == 0 {
				if lit := trackerParityQuotedRe.FindStringSubmatch(exprs); lit != nil {
					t.Errorf("F330 direction 1b: %s has raw literal case "+
						"arm %q — use the model.TrackerType* symbol so the "+
						"arm stays visible to symbol-level tooling. (The "+
						"literal is deliberately NOT counted as covering "+
						"the const, so the set diff below flags it too.)",
						site.name, lit[1])
				}
				continue
			}
			for _, s := range syms {
				out[s[1]] = true
			}
			continue
		}
		for _, q := range trackerParityQuotedRe.FindAllStringSubmatch(exprs, -1) {
			out[q[1]] = true
		}
	}
	return out
}

// trackerParityLiteralRe builds the wire-value literal detector from
// the parsed const universe, so the literal census automatically tracks
// future trackers. Note: a future wire value that collides with an
// unrelated quoted word elsewhere would surface as a census failure and
// force a deliberate review of the collision.
func trackerParityLiteralRe(valueSet map[string]bool) *regexp.Regexp {
	vals := make([]string, 0, len(valueSet))
	for v := range valueSet {
		vals = append(vals, regexp.QuoteMeta(v))
	}
	sort.Strings(vals)
	return regexp.MustCompile(`"(?:` + strings.Join(vals, "|") + `)"`)
}

// trackerParityTSUnion extracts the string members of
//
//	export type TrackerType = "jira" | "backlog";
//
// from api.ts via an anchor-terminated slice (start anchor → the first
// terminating semicolon).
func trackerParityTSUnion(t *testing.T, src, rel string) map[string]bool {
	t.Helper()
	const anchor = "export type TrackerType ="
	start := strings.Index(src, anchor)
	if start < 0 {
		t.Fatalf("F330 direction 2 setup: cannot locate %q in %s — the "+
			"union was renamed or moved; update this parser.", anchor, rel)
	}
	body := src[start:]
	end := strings.IndexByte(body, ';')
	if end < 0 {
		t.Fatalf("F330 direction 2 setup: no terminating ';' after the "+
			"TrackerType union in %s; update this parser.", rel)
	}
	quoted := trackerParityQuotedRe.FindAllStringSubmatch(body[:end], -1)
	if len(quoted) == 0 {
		t.Fatalf("F330 direction 2 setup: TrackerType union in %s "+
			"contained no quoted identifiers — syntax changed or union "+
			"emptied; both need review.", rel)
	}
	out := make(map[string]bool, len(quoted))
	for _, q := range quoted {
		out[q[1]] = true
	}
	return out
}

// trackerParitySelectItems extracts the SelectItem values from the
// tracker-type dropdown in the integrations settings page. The page
// currently contains exactly one Select; the count is asserted so that
// if a second dropdown is ever added, this parser must be re-anchored
// deliberately instead of silently scanning the wrong block.
func trackerParitySelectItems(t *testing.T, src, rel string) map[string]bool {
	t.Helper()
	const openAnchor = "<SelectContent"
	const closeAnchor = "</SelectContent>"
	if n := strings.Count(src, openAnchor); n != 1 {
		t.Fatalf("F330 direction 2 setup: expected exactly one "+
			"SelectContent block in %s, found %d — a new dropdown was "+
			"added; re-anchor this parser onto the tracker-type Select.",
			rel, n)
	}
	start := strings.Index(src, openAnchor)
	body := src[start:]
	end := strings.Index(body, closeAnchor)
	if end < 0 {
		t.Fatalf("F330 direction 2 setup: SelectContent block in %s has "+
			"no closing tag; update this parser.", rel)
	}
	items := trackerParitySelectItemRe.FindAllStringSubmatch(body[:end], -1)
	if len(items) == 0 {
		t.Fatalf("F330 direction 2 setup: no SelectItem value=\"...\" "+
			"entries found inside the SelectContent block of %s; the "+
			"dropdown syntax changed — update this parser.", rel)
	}
	out := make(map[string]bool, len(items))
	for _, m := range items {
		out[m[1]] = true
	}
	return out
}

// trackerParityAssertCountsEqual compares two per-file occurrence-count
// maps and fails with a stable, sorted diff plus a remediation hint.
func trackerParityAssertCountsEqual(
	t *testing.T,
	label string,
	got, want map[string]int,
	hint string,
) {
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
		if got[k] != want[k] {
			t.Errorf("%s: %s has %d TrackerType switch header(s), the "+
				"hand-maintained site list expects %d — %s.",
				label, k, got[k], want[k], hint)
		}
	}
}
