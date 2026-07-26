package nullscan

// Expression-level nullability evaluation over token slices. The contract:
// every return is either {known: true} with a definite nullable verdict, or
// {known: false} with a reason — never a silent guess.

import (
	"strings"
)

func unknownCol(reason string) projCol {
	return projCol{known: false, reason: reason}
}

func nonNullCol(reason string) projCol {
	return projCol{known: true, nullable: false, reason: reason}
}

func nullableCol(reason string) projCol {
	return projCol{known: true, nullable: true, reason: reason}
}

// aggregate functions that yield NULL over an empty input set.
var nullableAggregates = map[string]bool{
	"SUM": true, "AVG": true, "MIN": true, "MAX": true,
	"STRING_AGG": true, "ARRAY_AGG": true, "JSON_AGG": true,
	"JSONB_AGG": true, "JSON_OBJECT_AGG": true, "JSONB_OBJECT_AGG": true,
	"BOOL_AND": true, "BOOL_OR": true, "EVERY": true,
	"PERCENTILE_CONT": true, "PERCENTILE_DISC": true, "MODE": true,
	"VARIANCE": true, "VAR_POP": true, "VAR_SAMP": true,
	"STDDEV": true, "STDDEV_POP": true, "STDDEV_SAMP": true,
}

var nonNullFuncs = map[string]bool{
	"COUNT": true, "NOW": true, "CURRENT_TIMESTAMP": true,
	"CURRENT_DATE": true, "CURRENT_TIME": true, "LOCALTIMESTAMP": true,
	"TRANSACTION_TIMESTAMP": true, "STATEMENT_TIMESTAMP": true,
	"CLOCK_TIMESTAMP": true, "GEN_RANDOM_UUID": true,
	"UUID_GENERATE_V4": true, "RANDOM": true, "PI": true,
	"ROW_NUMBER": true, "RANK": true, "DENSE_RANK": true, "NTILE": true,
	"CUME_DIST": true, "PERCENT_RANK": true, "EXISTS": true,
}

var nullableFuncs = map[string]bool{
	"NULLIF": true, "LAG": true, "LEAD": true, "FIRST_VALUE": true,
	"LAST_VALUE": true, "NTH_VALUE": true,
}

// evalNullable determines whether the expression can evaluate to NULL.
// grouped reports whether the enclosing SELECT has a GROUP BY clause (which
// guarantees aggregates never see an empty group).
func evalNullable(toks []sqltok, sc *scope, grouped bool) projCol {
	toks = stripCasts(toks)
	if len(toks) == 0 {
		return unknownCol("empty expression")
	}

	// dynamic fragment anywhere in the expression => unanalyzable
	for _, t := range toks {
		if t.kind == tkIdent && t.text == DynMarker {
			return unknownCol("expression contains a dynamic fragment (" + DynMarker + ")")
		}
	}

	// fully parenthesized
	if toks[0].isOp("(") {
		if close, err := matchParen(toks, 0); err == nil && close == len(toks)-1 {
			inner := toks[1 : len(toks)-1]
			if kwAt(inner, 0) == "SELECT" || kwAt(inner, 0) == "WITH" {
				// `(SELECT COUNT(...) FROM ...)` without GROUP BY always
				// yields exactly one non-NULL row.
				if isCountOnlySubquery(inner) {
					return nonNullCol("scalar COUNT(...) subquery always yields one non-NULL row")
				}
				return nullableCol("scalar subquery can return NULL (no rows or NULL value)")
			}
			return evalNullable(inner, sc, grouped)
		}
	}

	// Operator-level analysis MUST run before the CASE/ARRAY/ROW handlers:
	// `CASE ... END + nullable_col` would otherwise match the CASE handler,
	// which stops at END and silently drops the trailing operator chain
	// (gemini-r4 #1). evalBinary skips tokens inside CASE..END and
	// parens/brackets, so a plain CASE expression falls through unharmed.
	if pc, handled := evalBinary(toks, sc, grouped); handled {
		return pc
	}

	// CASE ... END
	if kwAt(toks, 0) == "CASE" {
		return evalCase(toks, sc, grouped)
	}

	// keyword-typed literals: INTERVAL '...', DATE '...', TIMESTAMP '...'
	if len(toks) == 2 && toks[1].kind == tkString {
		switch kwAt(toks, 0) {
		case "INTERVAL", "DATE", "TIMESTAMP", "TIME":
			return nonNullCol("typed literal")
		}
	}

	// ARRAY[...] constructor / ARRAY(SELECT ...)
	if kwAt(toks, 0) == "ARRAY" && len(toks) >= 2 && (toks[1].isOp("[") || toks[1].isOp("(")) {
		return nonNullCol("ARRAY constructor is never NULL")
	}
	if kwAt(toks, 0) == "ROW" && len(toks) >= 2 && toks[1].isOp("(") {
		return nonNullCol("ROW constructor is never NULL")
	}

	// NOT prefix
	if kwAt(toks, 0) == "NOT" {
		return evalNullable(toks[1:], sc, grouped)
	}

	// function call: ident ( ... ) [WITHIN GROUP (...)] [FILTER (...)] [OVER ...]
	if len(toks) >= 3 && toks[0].kind == tkIdent && toks[1].isOp("(") {
		if close, err := matchParen(toks, 1); err == nil {
			return evalFuncCall(toks, close, sc, grouped)
		}
	}

	// atoms
	if len(toks) == 1 {
		t := toks[0]
		switch t.kind {
		case tkNumber, tkString:
			return nonNullCol("literal")
		case tkParam:
			// Bind parameters are treated as non-NULL: the bug class this
			// analyzer targets is NULLs coming from the DATABASE, and the
			// codebase binds plain Go values (never nil pointers) as
			// parameters. Documented limitation.
			return nonNullCol("bind parameter " + t.text + " (assumed non-NULL; caller binds Go values)")
		case tkIdent:
			switch t.kw() {
			case "NULL":
				return nullableCol("literal NULL")
			case "TRUE", "FALSE":
				return nonNullCol("boolean literal")
			case "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME", "LOCALTIMESTAMP", "CURRENT_USER":
				return nonNullCol("non-null system value")
			}
			pc := sc.lookupColumn("", t.text)
			if pc.name == "" {
				pc.name = t.text
			}
			return pc
		}
	}

	// qualified column: ident . ident
	if len(toks) == 3 && toks[0].kind == tkIdent && toks[1].isOp(".") && toks[2].kind == tkIdent {
		pc := sc.lookupColumn(toks[0].text, toks[2].text)
		if pc.name == "" {
			pc.name = toks[2].text
		}
		return pc
	}

	// unary minus/plus
	if len(toks) >= 2 && (toks[0].isOp("-") || toks[0].isOp("+")) {
		return evalNullable(toks[1:], sc, grouped)
	}

	return unknownCol("unrecognized expression shape: " + renderTokens(toks))
}

// isCountOnlySubquery reports whether inner (the body of a scalar subquery,
// starting at SELECT) projects exactly one item that is a bare COUNT(...)
// call and cannot produce zero rows: no GROUP BY, and none of HAVING /
// LIMIT / OFFSET / FETCH / set operations, any of which can empty the
// result set and turn the scalar subquery into NULL (gemini-r2 #1).
func isCountOnlySubquery(inner []sqltok) bool {
	if kwAt(inner, 0) != "SELECT" {
		return false
	}
	depth := 0
	projEnd := len(inner)
	for i := 1; i < len(inner); i++ {
		t := inner[i]
		if t.isOp("(") {
			depth++
		} else if t.isOp(")") {
			depth--
		}
		if depth == 0 {
			switch t.kw() {
			case "GROUP", "HAVING", "LIMIT", "OFFSET", "FETCH",
				"UNION", "EXCEPT", "INTERSECT":
				return false
			case "FROM":
				if projEnd == len(inner) {
					projEnd = i
				}
			}
		}
	}
	item := inner[1:projEnd]
	items, err := splitTopLevel(item)
	if err != nil || len(items) != 1 {
		return false
	}
	it, _ := stripAlias(items[0])
	if len(it) < 3 || it[0].kw() != "COUNT" || !it[1].isOp("(") {
		return false
	}
	close, err := matchParen(it, 1)
	return err == nil && close == len(it)-1
}

// stripCasts removes top-level `::type` suffixes anywhere at paren depth 0.
// Casting never changes nullability.
func stripCasts(toks []sqltok) []sqltok {
	var out []sqltok
	depth := 0
	i := 0
	for i < len(toks) {
		t := toks[i]
		if t.isOp("(") || t.isOp("[") {
			depth++
		} else if t.isOp(")") || t.isOp("]") {
			depth--
		}
		if depth == 0 && t.isOp("::") {
			// consume :: [schema .] ident [more type words] [(nums)] [[]...]
			i++
			if i < len(toks) && toks[i].kind == tkIdent {
				i++
				// schema-qualified type: public.citext
				for i+1 < len(toks) && toks[i].isOp(".") && toks[i+1].kind == tkIdent {
					i += 2
				}
				for i < len(toks) && toks[i].kind == tkIdent {
					switch toks[i].kw() {
					case "PRECISION", "VARYING", "WITH", "WITHOUT", "TIME", "ZONE":
						i++
						continue
					}
					break
				}
				if i+1 < len(toks) && toks[i].isOp("(") {
					if close, err := matchParen(toks, i); err == nil {
						i = close + 1
					}
				}
				for i+1 < len(toks) && toks[i].isOp("[") && toks[i+1].isOp("]") {
					i += 2
				}
			}
			continue
		}
		out = append(out, t)
		i++
	}
	return out
}

// evalCase analyzes CASE [expr] WHEN ... THEN r1 [WHEN ... THEN rN] [ELSE rE]
// END: non-null iff an ELSE branch exists and every result branch is
// non-null.
func evalCase(toks []sqltok, sc *scope, grouped bool) projCol {
	type region struct {
		start int
		kind  string // "THEN" or "ELSE"
	}
	var regions []region
	depth := 0
	caseDepth := 0
	endIdx := -1
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.isOp("(") {
			depth++
		} else if t.isOp(")") {
			depth--
		}
		if depth != 0 {
			continue
		}
		switch t.kw() {
		case "CASE":
			caseDepth++
		case "END":
			caseDepth--
			if caseDepth == 0 {
				endIdx = i
			}
		case "THEN", "ELSE":
			if caseDepth == 1 {
				regions = append(regions, region{start: i, kind: t.kw()})
			}
		}
	}
	if endIdx == -1 {
		return unknownCol("CASE without matching END")
	}
	hasElse := false
	var results []projCol
	for ri, r := range regions {
		end := endIdx
		if ri+1 < len(regions) {
			end = regions[ri+1].start
		}
		// a THEN region runs until the next WHEN at caseDepth 1; find it
		if r.kind == "THEN" {
			depth = 0
			cd := 0
			for j := r.start + 1; j < end; j++ {
				t := toks[j]
				if t.isOp("(") {
					depth++
				} else if t.isOp(")") {
					depth--
				}
				if depth != 0 {
					continue
				}
				switch t.kw() {
				case "CASE":
					cd++
				case "END":
					cd--
				case "WHEN":
					if cd == 0 {
						end = j
					}
				}
				if end == j {
					break
				}
			}
		} else {
			hasElse = true
		}
		results = append(results, evalNullable(toks[r.start+1:end], sc, grouped))
	}
	if !hasElse {
		return nullableCol("CASE without ELSE yields NULL when no WHEN matches")
	}
	for _, r := range results {
		if !r.known {
			return unknownCol("CASE branch: " + r.reason)
		}
		if r.nullable {
			return nullableCol("CASE branch can be NULL: " + r.reason)
		}
	}
	return nonNullCol("CASE with ELSE and all branches non-null")
}

// binary/keyword operator handling. Returns handled=false when no top-level
// operator of any recognized class is present.
func evalBinary(toks []sqltok, sc *scope, grouped bool) (projCol, bool) {
	// locate top-level tokens (outside parens/brackets and outside CASE..END)
	type opHit struct {
		idx  int
		text string // uppercase kw or op text
		isKw bool
	}
	var hits []opHit
	depth := 0
	caseDepth := 0
	for i, t := range toks {
		if t.isOp("(") || t.isOp("[") {
			depth++
			continue
		}
		if t.isOp(")") || t.isOp("]") {
			depth--
			continue
		}
		if depth != 0 {
			continue
		}
		switch t.kw() {
		case "CASE":
			caseDepth++
			continue
		case "END":
			caseDepth--
			continue
		}
		if caseDepth != 0 {
			continue
		}
		if t.kind == tkOp {
			hits = append(hits, opHit{idx: i, text: t.text})
		} else if k := t.kw(); k != "" {
			hits = append(hits, opHit{idx: i, text: k, isKw: true})
		}
	}

	find := func(names ...string) int {
		for _, h := range hits {
			for _, n := range names {
				if h.text == n {
					return h.idx
				}
			}
		}
		return -1
	}

	// level 1/2: OR / AND — result NULL only if an operand is NULL
	for _, lvl := range [][]string{{"OR"}, {"AND"}} {
		if idx := find(lvl...); idx > 0 {
			left := evalNullable(toks[:idx], sc, grouped)
			right := evalNullable(toks[idx+1:], sc, grouped)
			return combineStrict("logical "+lvl[0], left, right), true
		}
	}

	// IS [NOT] NULL / IS [NOT] DISTINCT FROM / IS TRUE... — boolean, never NULL
	if idx := find("IS"); idx > 0 {
		return nonNullCol("IS predicate always yields TRUE/FALSE"), true
	}

	// IN / LIKE / ILIKE / BETWEEN / SIMILAR — strict over BOTH sides:
	// `x IN (nullable_col, 'v')` is NULL when x misses and the element is
	// NULL, so right-hand operands must be evaluated too (gemini-r1 #1).
	if idx := find("IN", "LIKE", "ILIKE", "BETWEEN", "SIMILAR"); idx > 0 {
		lhs := toks[:idx]
		// strip a trailing NOT (`x NOT IN (...)`)
		if len(lhs) > 0 && lhs[len(lhs)-1].kw() == "NOT" {
			lhs = lhs[:len(lhs)-1]
		}
		left := evalNullable(lhs, sc, grouped)
		rest := toks[idx+1:]
		// a subquery anywhere on the right => can be NULL
		depth := 0
		for _, t := range rest {
			if t.isOp("(") {
				depth++
			} else if t.isOp(")") {
				depth--
			}
			if t.kw() == "SELECT" {
				return nullableCol("predicate right side involves a subquery"), true
			}
		}
		var operands []projCol
		operands = append(operands, left)
		if len(rest) >= 2 && rest[0].isOp("(") {
			if close, err := matchParen(rest, 0); err == nil && close == len(rest)-1 {
				if elems, err := splitTopLevel(rest[1:close]); err == nil {
					for _, e := range elems {
						if len(e) > 0 {
							operands = append(operands, evalNullable(e, sc, grouped))
						}
					}
					return combineStrict("predicate", operands...), true
				}
			}
		}
		// LIKE pattern / BETWEEN bounds / non-parenthesized right side
		if len(rest) > 0 {
			operands = append(operands, evalNullable(rest, sc, grouped))
		}
		return combineStrict("predicate", operands...), true
	}

	// comparisons
	if idx := find("=", "<>", "!=", "<", ">", "<=", ">=", "~", "~*", "!~", "!~*"); idx > 0 {
		left := evalNullable(toks[:idx], sc, grouped)
		right := evalNullable(toks[idx+1:], sc, grouped)
		return combineStrict("comparison", left, right), true
	}

	// JSON extraction: nullable regardless of operands
	if idx := find("->", "->>", "#>", "#>>"); idx > 0 {
		return nullableCol("JSON extraction (->/->>) returns NULL for missing keys"), true
	}

	// concatenation and arithmetic (strict)
	if idx := find("||", "+", "-", "*", "/", "%"); idx > 0 {
		left := evalNullable(toks[:idx], sc, grouped)
		right := evalNullable(toks[idx+1:], sc, grouped)
		return combineStrict("operator", left, right), true
	}

	return projCol{}, false
}

func combineStrict(what string, operands ...projCol) projCol {
	for _, o := range operands {
		if !o.known {
			return unknownCol(what + " operand: " + o.reason)
		}
	}
	for _, o := range operands {
		if o.nullable {
			return nullableCol(what + " operand can be NULL: " + o.reason)
		}
	}
	return nonNullCol(what + " over non-null operands")
}

// evalFuncCall handles `name ( args ) [WITHIN GROUP (...)] [FILTER (...)]
// [OVER ...]`. close is the index of the ')' matching toks[1].
func evalFuncCall(toks []sqltok, close int, sc *scope, grouped bool) projCol {
	name := strings.ToUpper(toks[0].text)
	if toks[0].quoted {
		return unknownCol("quoted function name")
	}
	argToks := toks[2:close]

	// suffix clauses
	hasFilter := false
	hasOver := false
	p := close + 1
	for p < len(toks) {
		switch kwAt(toks, p) {
		case "WITHIN":
			p += 2 // WITHIN GROUP
			if p < len(toks) && toks[p].isOp("(") {
				if c, err := matchParen(toks, p); err == nil {
					p = c + 1
					continue
				}
			}
			return unknownCol("malformed WITHIN GROUP clause")
		case "FILTER":
			hasFilter = true
			p++
			if p < len(toks) && toks[p].isOp("(") {
				if c, err := matchParen(toks, p); err == nil {
					p = c + 1
					continue
				}
			}
			return unknownCol("malformed FILTER clause")
		case "OVER":
			hasOver = true
			p++
			if p < len(toks) && toks[p].isOp("(") {
				if c, err := matchParen(toks, p); err == nil {
					p = c + 1
					continue
				}
			} else if p < len(toks) && toks[p].kind == tkIdent {
				p++ // named window
				continue
			}
			return unknownCol("malformed OVER clause")
		default:
			// trailing tokens that are not a recognized suffix: this is not
			// a plain function-call expression (e.g. `f(x) + 1` — but that
			// is caught by evalBinary before we get here). Bail out.
			return unknownCol("unrecognized tokens after function call: " + renderTokens(toks[p:]))
		}
	}

	setName := func(pc projCol) projCol {
		if pc.name == "" {
			pc.name = strings.ToLower(name)
		}
		return pc
	}

	switch {
	case name == "EXISTS":
		return setName(nonNullCol("EXISTS always yields TRUE/FALSE"))
	case name == "COUNT":
		return setName(nonNullCol("COUNT never returns NULL"))
	case name == "COALESCE" || name == "GREATEST" || name == "LEAST":
		args, err := splitFuncArgs(argToks)
		if err != nil {
			return unknownCol(name + " args: " + err.Error())
		}
		anyUnknown := ""
		for _, a := range args {
			pc := evalNullable(a, sc, grouped)
			if pc.known && !pc.nullable {
				return setName(nonNullCol(name + " has a non-null fallback argument"))
			}
			if !pc.known && anyUnknown == "" {
				anyUnknown = pc.reason
			}
		}
		if anyUnknown != "" {
			return unknownCol(name + " argument: " + anyUnknown)
		}
		return setName(nullableCol(name + " with all-nullable arguments"))
	case nullableFuncs[name]:
		return setName(nullableCol(name + " can return NULL"))
	case nonNullFuncs[name]:
		return setName(nonNullCol(name + " never returns NULL"))
	case name == "CAST":
		// CAST(x AS type)
		cut := len(argToks)
		depth := 0
		for i, t := range argToks {
			if t.isOp("(") {
				depth++
			} else if t.isOp(")") {
				depth--
			} else if depth == 0 && t.kw() == "AS" {
				cut = i
				break
			}
		}
		return setName(evalNullable(argToks[:cut], sc, grouped))
	case name == "EXTRACT":
		// EXTRACT(field FROM expr): the field word (EPOCH/DAY/...) is not a
		// column — evaluate only the expr after the top-level FROM.
		depth := 0
		for i, t := range argToks {
			if t.isOp("(") {
				depth++
			} else if t.isOp(")") {
				depth--
			} else if depth == 0 && t.kw() == "FROM" {
				return setName(evalNullable(argToks[i+1:], sc, grouped))
			}
		}
		return unknownCol("EXTRACT without FROM")
	case nullableAggregates[name]:
		if hasFilter {
			return setName(nullableCol(name + " with FILTER yields NULL when the filtered set is empty"))
		}
		if !grouped && !hasOver {
			return setName(nullableCol(name + " over zero input rows yields NULL"))
		}
		// non-empty group / window frame: strictness on arguments
		return setName(evalFuncArgsStrict(name, argToks, sc, grouped))
	default:
		return setName(evalFuncArgsStrict(name, argToks, sc, grouped))
	}
}

// evalFuncArgsStrict applies the strict-function assumption: NULL in => NULL
// out, non-null args => non-null result. This is correct for the vast
// majority of scalar functions (LOWER, TO_CHAR, DATE_TRUNC, ...) but is an
// assumption — documented in the package limitations.
func evalFuncArgsStrict(name string, argToks []sqltok, sc *scope, grouped bool) projCol {
	args, err := splitFuncArgs(argToks)
	if err != nil {
		return unknownCol(name + " args: " + err.Error())
	}
	var evals []projCol
	for _, a := range args {
		if len(a) == 0 {
			continue
		}
		if len(a) == 1 && a[0].isOp("*") {
			continue // COUNT(*)-style; treated as non-null input
		}
		evals = append(evals, evalNullable(a, sc, grouped))
	}
	if len(evals) == 0 {
		return nonNullCol(name + "() with no nullable inputs (strict-function assumption)")
	}
	pc := combineStrict(name+" (strict-function assumption)", evals...)
	return pc
}

// splitFuncArgs splits a function argument token list on top-level commas,
// dropping a leading DISTINCT/ALL/VARIADIC and truncating at a top-level
// ORDER BY (aggregate ordering) or trailing FROM/FOR (EXTRACT/SUBSTRING
// style), which get normalized to commas.
func splitFuncArgs(argToks []sqltok) ([][]sqltok, error) {
	// normalize EXTRACT(x FROM y) / SUBSTRING(x FROM a FOR b) /
	// POSITION(a IN b) / TRIM(BOTH x FROM y)
	norm := make([]sqltok, 0, len(argToks))
	depth := 0
	for i := 0; i < len(argToks); i++ {
		t := argToks[i]
		if t.isOp("(") || t.isOp("[") {
			depth++
		} else if t.isOp(")") || t.isOp("]") {
			depth--
		}
		if depth == 0 {
			switch t.kw() {
			case "FROM", "FOR", "IN", "PLACING":
				norm = append(norm, sqltok{kind: tkOp, text: ","})
				continue
			case "BOTH", "LEADING", "TRAILING":
				continue
			case "ORDER":
				// ORDER BY ... — everything after belongs to ordering
				return splitTopLevel(norm)
			}
		}
		norm = append(norm, t)
	}
	if len(norm) == 0 {
		return nil, nil
	}
	if kwAt(norm, 0) == "DISTINCT" || kwAt(norm, 0) == "ALL" || kwAt(norm, 0) == "VARIADIC" {
		norm = norm[1:]
	}
	if len(norm) == 0 {
		return nil, nil
	}
	return splitTopLevel(norm)
}
