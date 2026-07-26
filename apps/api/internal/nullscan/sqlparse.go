package nullscan

// SQL mini-parser: just enough PostgreSQL syntax to decide, for each
// projection item of a SELECT / RETURNING list, whether the value can be
// NULL at runtime. This is intentionally NOT a general SQL parser — anything
// it cannot understand becomes an explicit "unanalyzable" result with a
// reason; it must never silently guess.

import (
	"fmt"
	"strings"
)

// DynMarker is substituted by the Go-side resolver for expression fragments
// whose value is not statically known (fmt.Sprintf verbs with non-constant
// args, appends of non-constant strings, ...). The SQL analyzer tolerates it
// in WHERE / ORDER BY / LIMIT tails but refuses to analyze a query whose
// projection list or FROM clause contains it.
const DynMarker = "__NULLSCAN_DYN__"

type tokKind int

const (
	tkIdent  tokKind = iota // bare or "quoted" identifier / keyword
	tkNumber                // numeric literal
	tkString                // 'string literal'
	tkParam                 // $1, $2, ...
	tkOp                    // operator or punctuation
)

type sqltok struct {
	kind   tokKind
	text   string // original text (identifiers keep case; compare via kw())
	quoted bool   // double-quoted identifier
}

// kw returns the uppercase form for keyword comparison ("" for non-idents
// and quoted identifiers, which can never be keywords).
func (t sqltok) kw() string {
	if t.kind != tkIdent || t.quoted {
		return ""
	}
	return strings.ToUpper(t.text)
}

func (t sqltok) isOp(s string) bool { return t.kind == tkOp && t.text == s }

type sqlError struct{ reason string }

func (e *sqlError) Error() string { return e.reason }

func errf(format string, args ...any) error {
	return &sqlError{reason: fmt.Sprintf(format, args...)}
}

// tokenizeSQL splits a SQL string into tokens. Comments are skipped.
// Dollar-quoted strings are supported minimally ($$...$$ / $tag$...$tag$).
func tokenizeSQL(s string) ([]sqltok, error) {
	var toks []sqltok
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < n && s[i+1] == '-':
			for i < n && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && s[i+1] == '*':
			depth := 1
			i += 2
			for i < n && depth > 0 {
				if i+1 < n && s[i] == '/' && s[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < n && s[i] == '*' && s[i+1] == '/' {
					depth--
					i += 2
				} else {
					i++
				}
			}
			if depth > 0 {
				return nil, errf("unterminated block comment")
			}
		case c == '\'':
			j := i + 1
			var sb strings.Builder
			for {
				if j >= n {
					return nil, errf("unterminated string literal")
				}
				if s[j] == '\'' {
					if j+1 < n && s[j+1] == '\'' { // '' escape
						sb.WriteByte('\'')
						j += 2
						continue
					}
					j++
					break
				}
				sb.WriteByte(s[j])
				j++
			}
			toks = append(toks, sqltok{kind: tkString, text: sb.String()})
			i = j
		case c == '"':
			j := i + 1
			var sb strings.Builder
			for {
				if j >= n {
					return nil, errf("unterminated quoted identifier")
				}
				if s[j] == '"' {
					if j+1 < n && s[j+1] == '"' {
						sb.WriteByte('"')
						j += 2
						continue
					}
					j++
					break
				}
				sb.WriteByte(s[j])
				j++
			}
			toks = append(toks, sqltok{kind: tkIdent, text: sb.String(), quoted: true})
			i = j
		case c == '$':
			// `$` + DynMarker arises from `fmt.Sprintf(" AND x = $%d", i)`
			// with a non-constant ordinal: keep it as a dynamic fragment
			// token (harmless in WHERE tails, poison in projections).
			if strings.HasPrefix(s[i+1:], DynMarker) {
				toks = append(toks, sqltok{kind: tkIdent, text: DynMarker})
				i += 1 + len(DynMarker)
				break
			}
			// $1 param, or dollar-quoted string $tag$...$tag$
			j := i + 1
			for j < n && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j > i+1 && (j >= n || !isIdentChar(s[j])) {
				toks = append(toks, sqltok{kind: tkParam, text: s[i:j]})
				i = j
				break
			}
			// dollar quote
			j = i + 1
			for j < n && s[j] != '$' && isIdentChar(s[j]) {
				j++
			}
			if j < n && s[j] == '$' {
				tag := s[i : j+1]
				end := strings.Index(s[j+1:], tag)
				if end < 0 {
					return nil, errf("unterminated dollar-quoted string")
				}
				toks = append(toks, sqltok{kind: tkString, text: s[j+1 : j+1+end]})
				i = j + 1 + end + len(tag)
				break
			}
			return nil, errf("stray '$' at offset %d", i)
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentChar(s[j]) {
				j++
			}
			toks = append(toks, sqltok{kind: tkIdent, text: s[i:j]})
			i = j
		case c >= '0' && c <= '9' || (c == '.' && i+1 < n && s[i+1] >= '0' && s[i+1] <= '9'):
			j := i
			seenDot := false
			for j < n && (s[j] >= '0' && s[j] <= '9' || (s[j] == '.' && !seenDot)) {
				if s[j] == '.' {
					// "1..2" would be weird; also avoid eating "1.col"? not valid SQL
					seenDot = true
				}
				j++
			}
			// exponent
			if j < n && (s[j] == 'e' || s[j] == 'E') {
				k := j + 1
				if k < n && (s[k] == '+' || s[k] == '-') {
					k++
				}
				for k < n && s[k] >= '0' && s[k] <= '9' {
					k++
					j = k
				}
			}
			toks = append(toks, sqltok{kind: tkNumber, text: s[i:j]})
			i = j
		default:
			// multi-char operators, longest first
			ops := []string{"::", "->>", "->", "#>>", "#>", "||", ">=", "<=", "<>", "!=", "~*", "!~*", "!~"}
			matched := ""
			for _, op := range ops {
				if strings.HasPrefix(s[i:], op) && len(op) > len(matched) {
					matched = op
				}
			}
			if matched != "" {
				toks = append(toks, sqltok{kind: tkOp, text: matched})
				i += len(matched)
				break
			}
			switch c {
			case '(', ')', '[', ']', ',', '.', ';', '=', '<', '>', '+', '-', '*', '/', '%', '~', '&', '|', '^', '#', '@', '!', '?', ':':
				toks = append(toks, sqltok{kind: tkOp, text: string(c)})
				i++
			default:
				return nil, errf("unexpected character %q at offset %d", c, i)
			}
		}
	}
	return toks, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

// ---------------------------------------------------------------------------
// scope: what tables/CTEs/subqueries are visible to a SELECT

// projCol is one output column of a SELECT (or CTE/subquery), as far as we
// could determine it.
type projCol struct {
	name     string // output name ("" if underivable)
	nullable bool
	known    bool   // false => nullability undeterminable
	reason   string // why unknown / why nullable (for reporting)
	// srcTable/srcCol identify the origin column when the projection item is
	// a plain (possibly qualified) column reference; used for baseline keys.
	srcTable string
	srcCol   string
	expr     string // normalized SQL snippet of the item
}

type tableRef struct {
	name     string // real table name, or CTE name, or "" for anonymous subquery
	alias    string // alias if given (else name)
	kind     string // "table", "cte", "subquery", "func", "opaque"
	cols     []projCol
	nullSide bool // on the nullable side of an outer join
	// table kind resolves columns via schema; others via cols.
}

func (tr *tableRef) refName() string {
	if tr.alias != "" {
		return tr.alias
	}
	return tr.name
}

type scope struct {
	schema *Schema
	ctes   map[string]*tableRef // lowercased CTE name -> pseudo table
	tables []*tableRef
}

// lookupColumn resolves a (qualifier, column) reference within the scope.
// Returns nullable/known plus origin table info.
func (sc *scope) lookupColumn(qualifier, col string) (res projCol) {
	res.name = col
	res.srcCol = col
	var candidates []*tableRef
	if qualifier != "" {
		for _, tr := range sc.tables {
			if strings.EqualFold(tr.refName(), qualifier) {
				candidates = append(candidates, tr)
			}
		}
		if len(candidates) == 0 {
			res.reason = fmt.Sprintf("qualifier %q not found in FROM clause", qualifier)
			return
		}
	} else {
		candidates = sc.tables
	}

	type hit struct {
		tr       *tableRef
		nullable bool
		known    bool
		reason   string
	}
	var hits []hit
	for _, tr := range candidates {
		switch tr.kind {
		case "table":
			cols, ok := sc.schema.Tables[strings.ToLower(tr.name)]
			if !ok {
				// opaque table (e.g. view or unknown) — only counts as a hit
				// when explicitly qualified.
				if qualifier != "" {
					hits = append(hits, hit{tr: tr, known: false,
						reason: fmt.Sprintf("table %q not in schema snapshot", tr.name)})
				}
				continue
			}
			c, ok := cols[strings.ToLower(col)]
			if !ok {
				continue
			}
			hits = append(hits, hit{tr: tr, nullable: c.Nullable || tr.nullSide, known: true,
				reason: nullReason(c.Nullable, tr)})
		case "cte", "subquery":
			found := false
			for _, pc := range tr.cols {
				if strings.EqualFold(pc.name, col) && pc.name != "" {
					found = true
					if !pc.known {
						hits = append(hits, hit{tr: tr, known: false,
							reason: fmt.Sprintf("column %q of %s %q: %s", col, tr.kind, tr.refName(), pc.reason)})
					} else {
						hits = append(hits, hit{tr: tr, nullable: pc.nullable || tr.nullSide, known: true,
							reason: nullReason(pc.nullable, tr)})
					}
					break
				}
			}
			if !found && qualifier != "" {
				hits = append(hits, hit{tr: tr, known: false,
					reason: fmt.Sprintf("column %q not found in %s %q", col, tr.kind, tr.refName())})
			}
		default: // opaque, func
			if qualifier != "" {
				hits = append(hits, hit{tr: tr, known: false,
					reason: fmt.Sprintf("%s source %q: column nullability unknown", tr.kind, tr.refName())})
			}
		}
	}

	switch len(hits) {
	case 0:
		if qualifier == "" {
			// A bare column that matched nothing: if any opaque source is in
			// scope it might come from there.
			for _, tr := range sc.tables {
				if tr.kind == "opaque" || tr.kind == "func" ||
					(tr.kind == "table" && sc.schema.Tables[strings.ToLower(tr.name)] == nil) {
					res.reason = fmt.Sprintf("bare column %q not resolvable: opaque source %q in scope", col, tr.refName())
					return
				}
				if tr.kind == "cte" || tr.kind == "subquery" {
					for _, pc := range tr.cols {
						if pc.name == "" {
							res.reason = fmt.Sprintf("bare column %q not resolvable: %s %q has unnamed columns", col, tr.kind, tr.refName())
							return
						}
					}
				}
			}
			res.reason = fmt.Sprintf("column %q not found in any FROM table", col)
			return
		}
		res.reason = fmt.Sprintf("column %q not found in %q", col, qualifier)
		return
	case 1:
		h := hits[0]
		// A bare column resolved against one table is only trustworthy if
		// no OTHER in-scope source is opaque (it might own the column too).
		if qualifier == "" {
			for _, tr := range sc.tables {
				if tr == h.tr {
					continue
				}
				if opaque, why := isOpaqueSource(sc, tr); opaque {
					res.known = false
					res.reason = fmt.Sprintf("bare column %q matches %q but %s", col, h.tr.refName(), why)
					return
				}
			}
		}
		res.known = h.known
		res.nullable = h.nullable
		res.reason = h.reason
		if h.tr.kind == "table" {
			res.srcTable = strings.ToLower(h.tr.name)
		} else {
			res.srcTable = h.tr.kind + ":" + h.tr.refName()
		}
		return
	default:
		// ambiguous bare column: acceptable only if all hits agree and are known
		allKnown := true
		allSame := true
		for _, h := range hits {
			if !h.known {
				allKnown = false
			}
			if h.nullable != hits[0].nullable {
				allSame = false
			}
		}
		if allKnown && allSame {
			h := hits[0]
			res.known = true
			res.nullable = h.nullable
			res.reason = h.reason + " (bare column matches multiple tables, all agree)"
			if h.tr.kind == "table" {
				res.srcTable = strings.ToLower(h.tr.name)
			} else {
				res.srcTable = h.tr.kind + ":" + h.tr.refName()
			}
			return
		}
		res.reason = fmt.Sprintf("bare column %q ambiguous across %d FROM tables with differing nullability", col, len(hits))
		return
	}
}

// isOpaqueSource reports whether a FROM item's column set is not fully
// known: unknown tables (views, pg_catalog), function sources, failed
// CTE/subquery analyses, or derived tables with unnamed output columns.
func isOpaqueSource(sc *scope, tr *tableRef) (bool, string) {
	switch tr.kind {
	case "opaque", "func":
		return true, fmt.Sprintf("%s source %q in scope has unknown columns", tr.kind, tr.refName())
	case "table":
		if sc.schema.Tables[strings.ToLower(tr.name)] == nil {
			return true, fmt.Sprintf("table %q in scope is not in the schema snapshot", tr.refName())
		}
	case "cte", "subquery":
		for _, pc := range tr.cols {
			if pc.name == "" {
				return true, fmt.Sprintf("%s %q in scope has unnamed columns", tr.kind, tr.refName())
			}
		}
	}
	return false, ""
}

func nullReason(ddlNullable bool, tr *tableRef) string {
	switch {
	case ddlNullable && tr.nullSide:
		return "column is DDL-nullable and on outer-join nullable side"
	case ddlNullable:
		return "column is DDL-nullable"
	case tr.nullSide:
		return fmt.Sprintf("column is NOT NULL in DDL but %q is on the nullable side of an outer join", tr.refName())
	default:
		return "column is NOT NULL"
	}
}

// ---------------------------------------------------------------------------
// statement-level parsing

// analyzeSQL is the entry point: returns the projection columns of the
// statement (SELECT list or RETURNING list), or an error describing why the
// statement is unanalyzable.
func analyzeSQL(sqlText string, schema *Schema) ([]projCol, error) {
	toks, err := tokenizeSQL(sqlText)
	if err != nil {
		return nil, err
	}
	// strip one trailing ';'
	for len(toks) > 0 && toks[len(toks)-1].isOp(";") {
		toks = toks[:len(toks)-1]
	}
	if len(toks) == 0 {
		return nil, errf("empty SQL")
	}
	ctes := map[string]*tableRef{}
	return analyzeStatement(toks, schema, ctes)
}

func analyzeStatement(toks []sqltok, schema *Schema, ctes map[string]*tableRef) ([]projCol, error) {
	p := 0
	if kwAt(toks, p) == "WITH" {
		var err error
		p, err = parseCTEs(toks, p, schema, ctes)
		if err != nil {
			return nil, err
		}
	}
	switch kwAt(toks, p) {
	case "SELECT":
		return analyzeSelect(toks[p:], schema, ctes)
	case "INSERT", "UPDATE", "DELETE":
		return analyzeReturning(toks[p:], schema, ctes)
	case DynMarker:
		return nil, errf("statement begins with a dynamic fragment (%s)", DynMarker)
	default:
		return nil, errf("unsupported statement kind %q", tokenText(toks, p))
	}
}

func kwAt(toks []sqltok, i int) string {
	if i >= 0 && i < len(toks) {
		return toks[i].kw()
	}
	return ""
}

func tokenText(toks []sqltok, i int) string {
	if i >= 0 && i < len(toks) {
		return toks[i].text
	}
	return "<eof>"
}

// parseCTEs consumes `WITH [RECURSIVE] name [(cols)] AS [[NOT] MATERIALIZED]
// ( body ) [, ...]` and registers each CTE in ctes. Returns the index of the
// token that follows the WITH clause.
func parseCTEs(toks []sqltok, p int, schema *Schema, ctes map[string]*tableRef) (int, error) {
	p++ // WITH
	if kwAt(toks, p) == "RECURSIVE" {
		p++
	}
	for {
		if p >= len(toks) || toks[p].kind != tkIdent {
			return 0, errf("expected CTE name, got %q", tokenText(toks, p))
		}
		name := toks[p].text
		p++
		var explicitCols []string
		if p < len(toks) && toks[p].isOp("(") {
			close, err := matchParen(toks, p)
			if err != nil {
				return 0, err
			}
			for i := p + 1; i < close; i++ {
				if toks[i].kind == tkIdent {
					explicitCols = append(explicitCols, toks[i].text)
				} else if !toks[i].isOp(",") {
					return 0, errf("unexpected token %q in CTE column list", toks[i].text)
				}
			}
			p = close + 1
		}
		if kwAt(toks, p) != "AS" {
			return 0, errf("expected AS in CTE definition of %q", name)
		}
		p++
		if kwAt(toks, p) == "NOT" {
			p++
		}
		if kwAt(toks, p) == "MATERIALIZED" {
			p++
		}
		if p >= len(toks) || !toks[p].isOp("(") {
			return 0, errf("expected ( after AS in CTE %q", name)
		}
		close, err := matchParen(toks, p)
		if err != nil {
			return 0, err
		}
		body := toks[p+1 : close]
		p = close + 1

		// Pre-register the CTE as opaque so a RECURSIVE self-reference
		// resolves (to "unknown") instead of failing the whole parse.
		ctes[strings.ToLower(name)] = &tableRef{name: name, kind: "opaque"}
		cols, err := analyzeStatement(body, schema, ctes)
		ref := &tableRef{name: name, kind: "cte"}
		if err != nil {
			// Keep it opaque; references to it will be unanalyzable with
			// this reason.
			ref.kind = "opaque"
			ref.cols = nil
		} else {
			if len(explicitCols) > 0 {
				if len(explicitCols) != len(cols) {
					return 0, errf("CTE %q declares %d columns but its body yields %d", name, len(explicitCols), len(cols))
				}
				for i := range cols {
					cols[i].name = explicitCols[i]
				}
			}
			ref.cols = cols
		}
		ctes[strings.ToLower(name)] = ref

		if p < len(toks) && toks[p].isOp(",") {
			p++
			continue
		}
		return p, nil
	}
}

// matchParen returns the index of the ')' matching the '(' at toks[open].
func matchParen(toks []sqltok, open int) (int, error) {
	depth := 0
	for i := open; i < len(toks); i++ {
		if toks[i].isOp("(") {
			depth++
		} else if toks[i].isOp(")") {
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errf("unbalanced parentheses")
}

// clause keywords that end the FROM clause at top level.
var fromEnders = map[string]bool{
	"WHERE": true, "GROUP": true, "HAVING": true, "WINDOW": true,
	"ORDER": true, "LIMIT": true, "OFFSET": true, "FOR": true,
	"UNION": true, "EXCEPT": true, "INTERSECT": true, "RETURNING": true,
	"FETCH": true, "ON": false, // ON belongs to JOIN
}

// analyzeSelect analyzes `SELECT ...` (toks[0] must be SELECT).
func analyzeSelect(toks []sqltok, schema *Schema, ctes map[string]*tableRef) ([]projCol, error) {
	p := 1 // skip SELECT
	if kwAt(toks, p) == "ALL" {
		p++
	}
	if kwAt(toks, p) == "DISTINCT" {
		p++
		if kwAt(toks, p) == "ON" {
			p++
			if p >= len(toks) || !toks[p].isOp("(") {
				return nil, errf("expected ( after DISTINCT ON")
			}
			close, err := matchParen(toks, p)
			if err != nil {
				return nil, err
			}
			p = close + 1
		}
	}

	// find top-level FROM (or end of projection region)
	projStart := p
	projEnd := -1
	depth := 0
	fromIdx := -1
	for i := p; i < len(toks); i++ {
		t := toks[i]
		if t.isOp("(") {
			depth++
		} else if t.isOp(")") {
			depth--
		}
		if depth == 0 {
			k := t.kw()
			if k == "FROM" {
				fromIdx = i
				projEnd = i
				break
			}
			if k == "UNION" || k == "EXCEPT" || k == "INTERSECT" {
				return nil, errf("set operation (%s) not supported by nullscan", k)
			}
			if fromEnders[k] && k != "" {
				projEnd = i
				break
			}
		}
	}
	if projEnd == -1 {
		projEnd = len(toks)
	}
	projToks := toks[projStart:projEnd]

	sc := &scope{schema: schema, ctes: ctes}
	hasGroupBy := false
	if fromIdx >= 0 {
		var rest int
		var err error
		rest, err = parseFromClause(toks, fromIdx+1, sc, schema, ctes)
		if err != nil {
			return nil, err
		}
		// Scan the tail for GROUP BY / set ops / dynamic fragments in
		// dangerous places.
		depth = 0
		for i := rest; i < len(toks); i++ {
			t := toks[i]
			if t.isOp("(") {
				depth++
			} else if t.isOp(")") {
				depth--
			}
			if depth == 0 {
				switch t.kw() {
				case "GROUP":
					hasGroupBy = true
				case "UNION", "EXCEPT", "INTERSECT":
					return nil, errf("set operation (%s) not supported by nullscan", t.kw())
				}
			}
		}
	}

	return analyzeProjection(projToks, sc, hasGroupBy)
}

func analyzeProjection(projToks []sqltok, sc *scope, hasGroupBy bool) ([]projCol, error) {
	items, err := splitTopLevel(projToks)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errf("empty projection list")
	}
	// `SELECT *` over a single subquery/CTE with a known column list
	// expands to that list (column order is preserved by construction).
	// Real tables cannot be expanded — the schema snapshot does not retain
	// DDL column order.
	if len(items) == 1 && len(items[0]) == 1 && items[0][0].isOp("*") {
		if len(sc.tables) == 1 {
			tr := sc.tables[0]
			if (tr.kind == "subquery" || tr.kind == "cte") && len(tr.cols) > 0 {
				out := make([]projCol, len(tr.cols))
				copy(out, tr.cols)
				if tr.nullSide {
					for i := range out {
						out[i].nullable = true
					}
				}
				return out, nil
			}
		}
		return nil, errf("SELECT * cannot be expanded (not a single subquery/CTE with known columns)")
	}

	var out []projCol
	for _, item := range items {
		if len(item) == 0 {
			return nil, errf("empty projection item (dangling comma?)")
		}
		// t.* — cannot pair with Scan args.
		if lastOpIsStar(item) {
			return nil, errf("projection contains '*' — column list unknown")
		}
		for _, t := range item {
			if t.kind == tkIdent && t.text == DynMarker {
				return nil, errf("projection list contains a dynamic fragment (%s)", DynMarker)
			}
		}
		expr, alias := stripAlias(item)
		pc := evalNullable(expr, sc, hasGroupBy)
		if alias != "" {
			pc.name = alias
		}
		pc.expr = renderTokens(item)
		out = append(out, pc)
	}
	return out, nil
}

func lastOpIsStar(item []sqltok) bool {
	// "*" alone or "t.*"
	if len(item) == 1 && item[0].isOp("*") {
		return true
	}
	if len(item) >= 2 && item[len(item)-1].isOp("*") && item[len(item)-2].isOp(".") {
		return true
	}
	return false
}

// analyzeReturning handles INSERT/UPDATE/DELETE ... RETURNING. For UPDATE
// the optional `FROM <tables>` (and for DELETE the `USING <tables>`) clause
// also enters the RETURNING scope.
func analyzeReturning(toks []sqltok, schema *Schema, ctes map[string]*tableRef) ([]projCol, error) {
	kind := kwAt(toks, 0)
	// target table (with optional schema qualifier and, for UPDATE/DELETE,
	// an optional [AS] alias)
	var tbl, alias string
	tblIdx := -1
	switch kind {
	case "INSERT":
		if kwAt(toks, 1) != "INTO" || len(toks) < 3 || toks[2].kind != tkIdent {
			return nil, errf("cannot find INSERT target table")
		}
		tbl = toks[2].text
		tblIdx = 2
	case "UPDATE":
		if len(toks) < 2 || toks[1].kind != tkIdent {
			return nil, errf("cannot find UPDATE target table")
		}
		tbl = toks[1].text
		tblIdx = 1
	case "DELETE":
		if kwAt(toks, 1) != "FROM" || len(toks) < 3 || toks[2].kind != tkIdent {
			return nil, errf("cannot find DELETE target table")
		}
		tbl = toks[2].text
		tblIdx = 2
	}
	// schema-qualified target: public.things (gemini-r2 #3)
	if tblIdx+2 < len(toks) && toks[tblIdx+1].isOp(".") && toks[tblIdx+2].kind == tkIdent {
		tbl = toks[tblIdx+2].text
		tblIdx += 2
	}
	if kind != "INSERT" {
		p := tblIdx + 1
		if kwAt(toks, p) == "AS" {
			p++
		}
		if p < len(toks) && toks[p].kind == tkIdent && kwAt(toks, p) != "SET" &&
			kwAt(toks, p) != "WHERE" && kwAt(toks, p) != "USING" && kwAt(toks, p) != "FROM" {
			alias = toks[p].text
		}
	}
	// top-level RETURNING (and, for UPDATE/DELETE, the FROM/USING clause)
	depth := 0
	retIdx := -1
	joinKW := "FROM"
	if kind == "DELETE" {
		joinKW = "USING"
	}
	joinIdx := -1
	for i := tblIdx + 1; i < len(toks); i++ {
		if toks[i].isOp("(") {
			depth++
		} else if toks[i].isOp(")") {
			depth--
		} else if depth == 0 {
			switch toks[i].kw() {
			case "RETURNING":
				if retIdx == -1 {
					retIdx = i
				}
			case joinKW:
				if joinIdx == -1 && kind != "INSERT" {
					joinIdx = i
				}
			}
		}
	}
	if retIdx == -1 {
		return nil, errf("%s statement has no RETURNING clause but its result is scanned", kind)
	}
	sc := &scope{schema: schema, ctes: ctes}
	tr := &tableRef{name: tbl, kind: "table", alias: alias}
	if cte, ok := ctes[strings.ToLower(tbl)]; ok {
		cp := *cte
		cp.alias = alias
		tr = &cp
	}
	sc.tables = []*tableRef{tr}
	if joinIdx != -1 && joinIdx < retIdx {
		if _, err := parseFromClause(toks, joinIdx+1, sc, schema, ctes); err != nil {
			return nil, errf("%s %s clause: %s", kind, joinKW, err.Error())
		}
	}
	return analyzeProjection(toks[retIdx+1:], sc, false)
}

// parseFromClause parses the FROM clause starting at toks[p] (just after the
// FROM keyword) and fills sc.tables. Returns the index just past the clause.
func parseFromClause(toks []sqltok, p int, sc *scope, schema *Schema, ctes map[string]*tableRef) (int, error) {
	for {
		ref, np, err := parseTableRef(toks, p, schema, ctes)
		if err != nil {
			return 0, err
		}
		p = np
		sc.tables = append(sc.tables, ref)

		// join chain
		for {
			joinKind := ""
			q := p
			switch kwAt(toks, q) {
			case "LEFT", "RIGHT", "FULL":
				joinKind = kwAt(toks, q)
				q++
				if kwAt(toks, q) == "OUTER" {
					q++
				}
				if kwAt(toks, q) != "JOIN" {
					return 0, errf("expected JOIN after %s", joinKind)
				}
				q++
			case "INNER":
				joinKind = "INNER"
				q++
				if kwAt(toks, q) != "JOIN" {
					return 0, errf("expected JOIN after INNER")
				}
				q++
			case "CROSS":
				joinKind = "CROSS"
				q++
				if kwAt(toks, q) != "JOIN" {
					return 0, errf("expected JOIN after CROSS")
				}
				q++
			case "JOIN":
				joinKind = "INNER"
				q++
			default:
				// not a join
			}
			if joinKind == "" {
				break
			}
			if kwAt(toks, q) == "LATERAL" {
				q++
			}
			right, nq, err := parseTableRef(toks, q, schema, ctes)
			if err != nil {
				return 0, err
			}
			q = nq
			switch joinKind {
			case "LEFT":
				right.nullSide = true
			case "RIGHT":
				for _, tr := range sc.tables {
					tr.nullSide = true
				}
			case "FULL":
				right.nullSide = true
				for _, tr := range sc.tables {
					tr.nullSide = true
				}
			}
			sc.tables = append(sc.tables, right)

			// ON <cond> or USING (...)
			if kwAt(toks, q) == "ON" {
				q++
				// consume condition tokens until next top-level join/clause keyword
				depth := 0
				for q < len(toks) {
					t := toks[q]
					if t.isOp("(") {
						depth++
					} else if t.isOp(")") {
						depth--
						if depth < 0 {
							break
						}
					}
					if depth == 0 {
						k := t.kw()
						if k == "JOIN" || k == "LEFT" || k == "RIGHT" || k == "FULL" ||
							k == "INNER" || k == "CROSS" || (fromEnders[k] && k != "") ||
							t.isOp(",") {
							break
						}
					}
					q++
				}
			} else if kwAt(toks, q) == "USING" {
				q++
				if q < len(toks) && toks[q].isOp("(") {
					close, err := matchParen(toks, q)
					if err != nil {
						return 0, err
					}
					q = close + 1
				}
			} else if joinKind != "CROSS" {
				return 0, errf("JOIN without ON/USING")
			}
			p = q
		}

		if p < len(toks) && toks[p].isOp(",") {
			p++
			continue
		}
		return p, nil
	}
}

// parseTableRef parses one table reference: name [AS alias], (subquery)
// [AS] alias, or func(...) [AS] alias.
func parseTableRef(toks []sqltok, p int, schema *Schema, ctes map[string]*tableRef) (*tableRef, int, error) {
	if p >= len(toks) {
		return nil, 0, errf("unexpected end of FROM clause")
	}
	if toks[p].kind == tkIdent && toks[p].text == DynMarker {
		return nil, 0, errf("FROM clause contains a dynamic fragment (%s)", DynMarker)
	}
	if toks[p].isOp("(") {
		close, err := matchParen(toks, p)
		if err != nil {
			return nil, 0, err
		}
		inner := toks[p+1 : close]
		ref := &tableRef{kind: "subquery"}
		if kwAt(inner, 0) == "SELECT" || kwAt(inner, 0) == "WITH" {
			cols, err := analyzeStatement(inner, schema, cloneCTEs(ctes))
			if err != nil {
				ref.kind = "opaque"
			} else {
				ref.cols = cols
			}
		} else {
			return nil, 0, errf("parenthesized FROM item is not a subquery")
		}
		p = close + 1
		p = parseAliasInto(toks, p, ref)
		if ref.alias == "" {
			return nil, 0, errf("subquery in FROM requires an alias")
		}
		return ref, p, nil
	}
	if toks[p].kind != tkIdent {
		return nil, 0, errf("unexpected token %q in FROM clause", toks[p].text)
	}
	name := toks[p].text
	p++
	// schema-qualified public.foo
	if p+1 < len(toks) && toks[p].isOp(".") && toks[p+1].kind == tkIdent {
		name = toks[p+1].text
		p += 2
	}
	// set-returning function: name(...)
	if p < len(toks) && toks[p].isOp("(") {
		close, err := matchParen(toks, p)
		if err != nil {
			return nil, 0, err
		}
		ref := &tableRef{name: name, kind: "func"}
		p = close + 1
		p = parseAliasInto(toks, p, ref)
		return ref, p, nil
	}
	var ref *tableRef
	if cte, ok := ctes[strings.ToLower(name)]; ok {
		cp := *cte // copy so per-query nullSide doesn't leak
		ref = &cp
		ref.alias = ""
	} else {
		ref = &tableRef{name: name, kind: "table"}
	}
	p = parseAliasInto(toks, p, ref)
	return ref, p, nil
}

func cloneCTEs(ctes map[string]*tableRef) map[string]*tableRef {
	out := make(map[string]*tableRef, len(ctes))
	for k, v := range ctes {
		out[k] = v
	}
	return out
}

var aliasStoppers = map[string]bool{
	"LEFT": true, "RIGHT": true, "FULL": true, "INNER": true, "CROSS": true,
	"JOIN": true, "ON": true, "USING": true, "WHERE": true, "GROUP": true,
	"HAVING": true, "WINDOW": true, "ORDER": true, "LIMIT": true,
	"OFFSET": true, "FOR": true, "UNION": true, "EXCEPT": true,
	"INTERSECT": true, "RETURNING": true, "FETCH": true, "LATERAL": true,
	"AND": true, "OR": true, "NATURAL": true, "TABLESAMPLE": true,
}

// parseAliasInto consumes an optional [AS] alias [(colnames)] after a table
// ref.
func parseAliasInto(toks []sqltok, p int, ref *tableRef) int {
	if kwAt(toks, p) == "AS" {
		p++
		if p < len(toks) && toks[p].kind == tkIdent {
			ref.alias = toks[p].text
			p++
		}
	} else if p < len(toks) && toks[p].kind == tkIdent && !aliasStoppers[toks[p].kw()] && toks[p].text != DynMarker {
		ref.alias = toks[p].text
		p++
	}
	// optional column alias list: alias(c1, c2)
	if ref.alias != "" && p < len(toks) && toks[p].isOp("(") {
		if close, err := matchParen(toks, p); err == nil {
			var names []string
			ok := true
			for i := p + 1; i < close; i++ {
				if toks[i].kind == tkIdent {
					names = append(names, toks[i].text)
				} else if !toks[i].isOp(",") {
					ok = false
					break
				}
			}
			if ok {
				if len(ref.cols) == len(names) && len(names) > 0 {
					for i := range ref.cols {
						ref.cols[i].name = names[i]
					}
				} else if ref.kind == "func" || ref.kind == "opaque" {
					// column names known but nullability not
					for _, n := range names {
						ref.cols = append(ref.cols, projCol{name: n, known: false,
							reason: "column of function/opaque FROM item"})
					}
				}
				p = close + 1
			}
		}
	}
	return p
}

// splitTopLevel splits toks on top-level commas (paren depth 0).
func splitTopLevel(toks []sqltok) ([][]sqltok, error) {
	var out [][]sqltok
	depth := 0
	start := 0
	for i, t := range toks {
		if t.isOp("(") || t.isOp("[") {
			depth++
		} else if t.isOp(")") || t.isOp("]") {
			depth--
			if depth < 0 {
				return nil, errf("unbalanced parentheses in list")
			}
		} else if depth == 0 && t.isOp(",") {
			out = append(out, toks[start:i])
			start = i + 1
		}
	}
	if depth != 0 {
		return nil, errf("unbalanced parentheses in list")
	}
	out = append(out, toks[start:])
	return out, nil
}

// stripAlias removes a trailing `AS alias` or bare-identifier alias from a
// projection item, returning the expression tokens and the alias ("" if
// none). For a plain column reference the column's own name doubles as the
// output name (handled by evalNullable).
func stripAlias(item []sqltok) ([]sqltok, string) {
	n := len(item)
	if n >= 2 && item[n-2].kw() == "AS" && item[n-1].kind == tkIdent {
		return item[:n-2], item[n-1].text
	}
	if n >= 2 && item[n-1].kind == tkIdent && !item[n-1].quoted {
		prev := item[n-2]
		// previous token must end an expression
		endsExpr := prev.kind == tkNumber || prev.kind == tkString ||
			prev.kind == tkParam || prev.isOp(")") || prev.isOp("]") ||
			(prev.kind == tkIdent && prev.kw() != "AS" && !isExprKeyword(prev.kw()))
		// ...and the pair must not be `tbl . col` (dot handled above via
		// prev != "."), an operator, or keyword pairs like IS NULL / NOT NULL.
		if endsExpr && !prev.isOp(".") && !isExprKeyword(item[n-1].kw()) {
			return item[:n-1], item[n-1].text
		}
	}
	if n >= 2 && item[n-1].quoted && item[n-1].kind == tkIdent {
		prev := item[n-2]
		if !prev.isOp(".") && (prev.kind != tkOp || prev.isOp(")") || prev.isOp("]")) {
			return item[:n-1], item[n-1].text
		}
	}
	return item, ""
}

// isExprKeyword: keywords that are part of an expression and therefore can
// be neither an implicit alias nor an "expression-ending" token for alias
// detection.
func isExprKeyword(k string) bool {
	switch k {
	case "NULL", "TRUE", "FALSE", "END", "CASE", "WHEN", "THEN", "ELSE",
		"AND", "OR", "NOT", "IS", "IN", "LIKE", "ILIKE", "BETWEEN",
		"DISTINCT", "FROM", "INTERVAL", "TIMESTAMP", "DATE", "TIME",
		"EXISTS", "ARRAY", "ROW", "COLLATE", "AT", "ZONE", "OVER",
		"FILTER", "SIMILAR", "TO", "ESCAPE", "ASC", "DESC", "BY":
		return true
	}
	// END/NULL etc can end an expression though — handled by callers where
	// needed.
	return false
}

func renderTokens(toks []sqltok) string {
	var sb strings.Builder
	for i, t := range toks {
		if i > 0 {
			prev := toks[i-1]
			// compact rendering: no space around '.', '(', ')', '::'
			if !prev.isOp(".") && !t.isOp(".") && !prev.isOp("::") && !t.isOp("::") &&
				!prev.isOp("(") && !t.isOp(")") && !t.isOp("(") && !t.isOp(",") {
				sb.WriteByte(' ')
			}
		}
		switch t.kind {
		case tkString:
			sb.WriteString("'" + t.text + "'")
		case tkIdent:
			if t.quoted {
				sb.WriteString("\"" + t.text + "\"")
			} else {
				sb.WriteString(t.text)
			}
		default:
			sb.WriteString(t.text)
		}
	}
	s := sb.String()
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
