package nullscan

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// Finding is one analyzer result. Kind is one of:
//
//	violation    — a DDL-nullable (or outer-join-nullable, aggregate-NULL,
//	               ...) SQL value scanned into a NULL-intolerant Go type:
//	               a NULL row turns this read into a 500.
//	warning      — NULL scans succeed but silently leave the destination's
//	               zero/previous value (measured: uuid.UUID). Not a 500,
//	               but a data-integrity hazard.
//	unanalyzable — the analyzer could not decide and REFUSES to guess;
//	               reason explains why. Never silently skipped.
type Finding struct {
	Kind     string `json:"kind"`
	File     string `json:"file"` // relative to module root
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Pkg      string `json:"pkg"`
	Func     string `json:"func"`
	Table    string `json:"table,omitempty"` // source table (violations)
	Col      string `json:"column_name,omitempty"`
	SQLExpr  string `json:"sql_expr,omitempty"` // projection expression
	ArgIndex int    `json:"arg_index"`          // 0-based Scan argument
	ScanType string `json:"scan_type,omitempty"`
	Reason   string `json:"reason"`
	SQL      string `json:"sql,omitempty"` // resolved SQL (head, for context)
	Key      string `json:"key"`           // stable baseline key
}

// Report is the full analyzer output.
type Report struct {
	Violations   []Finding `json:"violations"`
	Warnings     []Finding `json:"warnings"`
	Unanalyzable []Finding `json:"unanalyzable"`
}

// Config controls an analysis run.
type Config struct {
	Dir          string   // module root (working directory for go/packages)
	Patterns     []string // package patterns, e.g. ./internal/...
	IncludeTests bool
	Schema       *Schema
}

type destClass int

const (
	destOK destClass = iota
	destNG
	destSilentZero
	destUnknown
)

// Analyze loads the packages and runs the scan-site analysis.
func Analyze(cfg Config) (*Report, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo |
		packages.NeedImports | packages.NeedDeps
	pkgs, err := packages.Load(&packages.Config{
		Mode:  mode,
		Dir:   cfg.Dir,
		Tests: cfg.IncludeTests,
	}, cfg.Patterns...)
	if err != nil {
		return nil, fmt.Errorf("load packages: %w", err)
	}
	var loadErrs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			loadErrs = append(loadErrs, fmt.Sprintf("%s: %s", p.PkgPath, e.Msg))
		}
	})
	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("package load errors (analysis needs a compiling tree):\n  %s",
			strings.Join(loadErrs, "\n  "))
	}

	rep := &Report{}
	seen := map[string]bool{} // dedupe (test variants load packages twice)
	for _, pkg := range pkgs {
		if strings.HasSuffix(pkg.PkgPath, ".test") {
			continue
		}
		a := &fileAnalyzer{
			cfg:  cfg,
			pkg:  pkg,
			res:  &resolver{info: pkg.TypesInfo, fset: pkg.Fset},
			rep:  rep,
			seen: seen,
		}
		for _, file := range pkg.Syntax {
			fname := pkg.Fset.Position(file.Pos()).Filename
			if !cfg.IncludeTests && strings.HasSuffix(fname, "_test.go") {
				continue
			}
			a.walkFile(file)
		}
	}

	sortFindings := func(fs []Finding) {
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].File != fs[j].File {
				return fs[i].File < fs[j].File
			}
			if fs[i].Line != fs[j].Line {
				return fs[i].Line < fs[j].Line
			}
			if fs[i].ArgIndex != fs[j].ArgIndex {
				return fs[i].ArgIndex < fs[j].ArgIndex
			}
			return fs[i].Key < fs[j].Key
		})
	}
	sortFindings(rep.Violations)
	sortFindings(rep.Warnings)
	sortFindings(rep.Unanalyzable)
	return rep, nil
}

type fileAnalyzer struct {
	cfg  Config
	pkg  *packages.Package
	res  *resolver
	rep  *Report
	seen map[string]bool
}

func (a *fileAnalyzer) walkFile(file *ast.File) {
	var funcStack []ast.Node // *ast.FuncDecl / *ast.FuncLit
	var visit func(n ast.Node) bool
	visit = func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			funcStack = append(funcStack, x)
			ast.Inspect(nodeBody(x), func(c ast.Node) bool { return visit(c) })
			funcStack = funcStack[:len(funcStack)-1]
			return false
		case *ast.CallExpr:
			a.checkCall(x, funcStack)
		}
		return true
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		funcStack = append(funcStack, fd)
		ast.Inspect(fd.Body, func(c ast.Node) bool { return visit(c) })
		funcStack = funcStack[:len(funcStack)-1]
	}
}

func nodeBody(n ast.Node) ast.Node {
	switch x := n.(type) {
	case *ast.FuncDecl:
		return x.Body
	case *ast.FuncLit:
		return x.Body
	}
	return n
}

// checkCall inspects one CallExpr; only `X.Scan(...)` where X is *sql.Row or
// *sql.Rows is interesting.
func (a *fileAnalyzer) checkCall(call *ast.CallExpr, funcStack []ast.Node) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Scan" {
		return
	}
	recvT := a.pkg.TypesInfo.TypeOf(sel.X)
	rowKind := sqlRowKind(recvT)
	if rowKind == "" {
		return
	}
	pos := a.pkg.Fset.Position(call.Lparen)
	fnDecl := enclosingFuncDecl(funcStack)
	funcName := a.funcDisplayName(funcStack)

	emitUnanalyzable := func(reasonClass, reason, sqlHead string) {
		a.emit(Finding{
			Kind:   "unanalyzable",
			Pkg:    a.pkg.PkgPath,
			Func:   funcName,
			Reason: reason,
			SQL:    sqlHead,
			Key:    baselineKey("U", a.pkg.PkgPath, funcName, reasonClass, sqlHead),
		}, pos)
	}

	if call.Ellipsis.IsValid() {
		emitUnanalyzable("variadic-dest", "Scan(dests...) with a spread destination slice cannot be checked statically", "")
		return
	}

	// locate the SQL string
	sqlCands, multiSource, partialErrs, queryErr := a.findQuerySQL(sel.X, fnDecl, call.Pos())
	if queryErr != "" {
		emitUnanalyzable("receiver", queryErr, "")
		return
	}
	for _, pe := range partialErrs {
		emitUnanalyzable("receiver", pe, "")
	}

	type candResult struct {
		sql  string
		cols []projCol
		err  error
	}
	var results []candResult
	for _, sqlText := range sqlCands {
		cols, err := analyzeSQL(sqlText, a.cfg.Schema)
		results = append(results, candResult{sql: sqlText, cols: cols, err: err})
	}

	// Pair candidates with this Scan by projection width. Two kinds of
	// non-matching candidates (gemini-r1 #2):
	//   - parse/dynamic failures: ALWAYS surfaced as unanalyzable, even when
	//     another candidate matched — a conditional branch whose SQL we
	//     cannot read must not vanish behind the readable branch.
	//   - count mismatches: silently pairable away ONLY when the rows
	//     variable is fed by multiple query calls (each query is analyzed at
	//     the Scan site whose arity it matches); otherwise surfaced.
	var matched []candResult
	var mismatched []candResult
	var parseFailed []candResult
	for _, r := range results {
		if r.err != nil {
			parseFailed = append(parseFailed, r)
			continue
		}
		if len(r.cols) == len(call.Args) {
			matched = append(matched, r)
		} else {
			mismatched = append(mismatched, candResult{sql: r.sql,
				err: errf("projection has %d columns but Scan has %d arguments", len(r.cols), len(call.Args))})
		}
	}
	for _, r := range parseFailed {
		emitUnanalyzable(classifySQLError(r.err), r.err.Error(), sqlHead(r.sql))
	}
	if len(matched) == 0 || !multiSource {
		for _, r := range mismatched {
			emitUnanalyzable(classifySQLError(r.err), r.err.Error(), sqlHead(r.sql))
		}
	}
	if len(matched) == 0 {
		return
	}

	// classify destinations once
	type destInfo struct {
		class destClass
		typ   string
		note  string
	}
	dests := make([]destInfo, len(call.Args))
	for i, arg := range call.Args {
		c, typ, note := a.classifyScanDest(arg)
		dests[i] = destInfo{class: c, typ: typ, note: note}
	}

	for _, r := range matched {
		for i, col := range r.cols {
			d := dests[i]
			switch d.class {
			case destOK:
				continue
			case destUnknown:
				a.emit(Finding{
					Kind: "unanalyzable", Pkg: a.pkg.PkgPath, Func: funcName,
					ArgIndex: i, ScanType: d.typ, SQLExpr: col.expr,
					Reason: "scan destination not classifiable: " + d.note,
					SQL:    sqlHead(r.sql),
					Key:    baselineKey("U", a.pkg.PkgPath, funcName, "dest", d.typ+"|"+col.expr),
				}, pos)
			case destNG, destSilentZero:
				if !col.known {
					a.emit(Finding{
						Kind: "unanalyzable", Pkg: a.pkg.PkgPath, Func: funcName,
						ArgIndex: i, ScanType: d.typ, SQLExpr: col.expr,
						Table: tableOf(col), Col: col.srcCol,
						Reason: "column nullability undeterminable: " + col.reason,
						SQL:    sqlHead(r.sql),
						Key:    baselineKey("U", a.pkg.PkgPath, funcName, "column", col.expr+"|"+d.typ),
					}, pos)
					continue
				}
				if !col.nullable {
					continue
				}
				kind := "violation"
				keyPfx := "V"
				reason := fmt.Sprintf("nullable SQL value scanned into NULL-intolerant %s: %s", d.typ, col.reason)
				if d.class == destSilentZero {
					kind = "warning"
					keyPfx = "W"
					reason = fmt.Sprintf("NULL scans into %s succeed but silently leave the zero value (measured): %s", d.typ, col.reason)
				}
				a.emit(Finding{
					Kind: kind, Pkg: a.pkg.PkgPath, Func: funcName,
					ArgIndex: i, ScanType: d.typ, SQLExpr: col.expr,
					Table: tableOf(col), Col: col.srcCol,
					Reason: reason,
					SQL:    sqlHead(r.sql),
					Key:    baselineKey(keyPfx, a.pkg.PkgPath, funcName, colIdentity(col), d.typ),
				}, pos)
			}
		}
	}
}

func tableOf(col projCol) string {
	return col.srcTable
}

// colIdentity is the line-number-independent identity of the flagged value.
func colIdentity(col projCol) string {
	if col.srcTable != "" && col.srcCol != "" {
		return col.srcTable + "." + col.srcCol
	}
	return "expr:" + col.expr
}

func baselineKey(parts ...string) string {
	return strings.Join(parts, "|")
}

func classifySQLError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, DynMarker):
		return "dynamic-sql"
	case strings.Contains(msg, "projection has"):
		return "count-mismatch"
	case strings.Contains(msg, "set operation"):
		return "set-op"
	default:
		return "sql-parse"
	}
}

func sqlHead(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		s = s[:97] + "..."
	}
	return s
}

func (a *fileAnalyzer) emit(f Finding, pos token.Position) {
	f.File = relPath(a.cfg.Dir, pos.Filename)
	f.Line = pos.Line
	f.Column = pos.Column
	dedupe := fmt.Sprintf("%s:%d:%d|%d|%s|%s", f.File, f.Line, f.Column, f.ArgIndex, f.Kind, f.Key)
	if a.seen[dedupe] {
		return
	}
	a.seen[dedupe] = true
	switch f.Kind {
	case "violation":
		a.rep.Violations = append(a.rep.Violations, f)
	case "warning":
		a.rep.Warnings = append(a.rep.Warnings, f)
	default:
		a.rep.Unanalyzable = append(a.rep.Unanalyzable, f)
	}
}

func relPath(dir, fname string) string {
	if dir == "" {
		return fname
	}
	abs, err1 := filepath.Abs(dir)
	if err1 != nil {
		return fname
	}
	if rel, err := filepath.Rel(abs, fname); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return fname
}

// findQuerySQL locates the SQL string for the Scan receiver expression:
// either a chained QueryRow[Context](...) call, or a rows variable assigned
// from Query[Context](...).
//
// Returns:
//   - cands: resolved candidate SQL strings
//   - multiSource: the rows variable is live from >1 query call at the Scan
//     site (conditional assignment); used by the caller to decide whether a
//     projection/arg count mismatch may be silently paired away
//   - partialErrs: sources that could NOT be resolved even though others
//     could — the caller must surface these (never silently dropped)
//   - errText: nothing resolved at all
func (a *fileAnalyzer) findQuerySQL(recv ast.Expr, fn *ast.FuncDecl, usePos token.Pos) (cands []string, multiSource bool, partialErrs []string, errText string) {
	recv = unparen(recv)
	if call, ok := recv.(*ast.CallExpr); ok {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return nil, false, nil, "Scan receiver is a call to a non-method"
		}
		switch sel.Sel.Name {
		case "QueryRow", "QueryRowContext":
			c, err := a.resolveQueryCall(call, fn, usePos)
			return c, false, nil, err
		default:
			return nil, false, nil, fmt.Sprintf("Scan receiver comes from helper call %s(...) — SQL not visible at this site", sel.Sel.Name)
		}
	}
	if id, ok := recv.(*ast.Ident); ok {
		obj := a.pkg.TypesInfo.ObjectOf(id)
		v, ok := obj.(*types.Var)
		if !ok {
			return nil, false, nil, fmt.Sprintf("Scan receiver %q is not a variable", id.Name)
		}
		if fn == nil || fn.Body == nil {
			return nil, false, nil, "no enclosing function to trace rows variable"
		}

		// Collect assignments to the rows variable in source order, tracking
		// whether each sits inside a conditional/loop relative to fn.Body.
		// Replay them with replace/fork semantics up to usePos so a reused
		// rows variable pairs each Scan with the query that actually feeds
		// it (a plain sequential reassignment REPLACES the candidate;
		// gemini-r1 #3), instead of unioning every query in the function.
		type rowsAssign struct {
			pos    token.Pos
			nested bool
			call   *ast.CallExpr
			bad    string // non-empty: unresolvable assignment
		}
		var assigns []rowsAssign
		var walk func(n ast.Node, nested bool)
		walk = func(n ast.Node, nested bool) {
			switch s := n.(type) {
			case nil:
				return
			case *ast.BlockStmt:
				for _, st := range s.List {
					walk(st, nested)
				}
			case *ast.IfStmt:
				if s.Init != nil {
					walk(s.Init, nested)
				}
				walk(s.Body, true)
				if s.Else != nil {
					walk(s.Else, true)
				}
			case *ast.ForStmt:
				if s.Init != nil {
					walk(s.Init, nested)
				}
				walk(s.Body, true)
			case *ast.RangeStmt:
				walk(s.Body, true)
			case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				ast.Inspect(n, func(c ast.Node) bool {
					if c == n {
						return true
					}
					walk(c, true)
					return false
				})
			case *ast.LabeledStmt:
				walk(s.Stmt, nested)
			case *ast.FuncLit:
				walk(s.Body, true)
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					lid, ok := lhs.(*ast.Ident)
					if !ok || a.pkg.TypesInfo.ObjectOf(lid) != v {
						continue
					}
					ra := rowsAssign{pos: s.Pos(), nested: nested}
					if len(s.Rhs) != 1 {
						ra.bad = "rows variable assigned from multi-value expression"
					} else if call, ok := unparen(s.Rhs[0]).(*ast.CallExpr); !ok {
						ra.bad = "rows variable not assigned from a method call"
					} else if csel, ok := call.Fun.(*ast.SelectorExpr); !ok ||
						(csel.Sel.Name != "Query" && csel.Sel.Name != "QueryContext" &&
							csel.Sel.Name != "QueryRow" && csel.Sel.Name != "QueryRowContext") {
						ra.bad = fmt.Sprintf("rows variable assigned from %s(...) — SQL not visible", renderExprHead(call.Fun))
					} else {
						ra.call = call
					}
					assigns = append(assigns, ra)
				}
			default:
				ast.Inspect(n, func(c ast.Node) bool {
					if c == n {
						return true
					}
					switch c.(type) {
					case *ast.BlockStmt, *ast.AssignStmt, *ast.IfStmt, *ast.ForStmt,
						*ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt,
						*ast.SelectStmt, *ast.FuncLit, *ast.LabeledStmt:
						walk(c, nested)
						return false
					}
					return true
				})
			}
		}
		walk(fn.Body, false)

		// replay: top-level assignment replaces the live set, nested forks it
		type liveEntry struct {
			call *ast.CallExpr
			bad  string
		}
		var live []liveEntry
		for _, ra := range assigns {
			if ra.pos >= usePos {
				continue
			}
			e := liveEntry{call: ra.call, bad: ra.bad}
			if ra.nested {
				live = append(live, e)
			} else {
				live = []liveEntry{e}
			}
		}
		if len(live) == 0 {
			return nil, false, nil, fmt.Sprintf("no Query/QueryContext assignment found for rows variable %q before its use", id.Name)
		}
		var cands []string
		var errs []string
		for _, e := range live {
			if e.bad != "" {
				errs = append(errs, e.bad)
				continue
			}
			c, errText := a.resolveQueryCall(e.call, fn, usePos)
			if errText != "" {
				errs = append(errs, errText)
				continue
			}
			cands = append(cands, c...)
		}
		if len(cands) > 0 {
			// partial resolution failures are surfaced by the caller, never
			// silently dropped (gemini-r1 #2)
			return dedupeStrings(cands), len(live) > 1, errs, ""
		}
		return nil, false, nil, errs[0]
	}
	return nil, false, nil, "Scan receiver expression is neither a Query call nor a rows variable"
}

// resolveQueryCall extracts and resolves the SQL argument of a
// Query/QueryRow[Context] call.
func (a *fileAnalyzer) resolveQueryCall(call *ast.CallExpr, fn *ast.FuncDecl, usePos token.Pos) ([]string, string) {
	var sqlArg ast.Expr
	for _, arg := range call.Args {
		t := a.pkg.TypesInfo.TypeOf(arg)
		if t == nil {
			continue
		}
		if b, ok := t.Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 {
			sqlArg = arg
			break
		}
	}
	if sqlArg == nil {
		return nil, "query call has no string argument (prepared statement?)"
	}
	cands, err := a.res.resolveSQLArg(sqlArg, fn, usePos)
	if err != nil {
		return nil, "cannot resolve SQL string: " + err.Error()
	}
	return cands, ""
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func enclosingFuncDecl(stack []ast.Node) *ast.FuncDecl {
	for i := len(stack) - 1; i >= 0; i-- {
		if fd, ok := stack[i].(*ast.FuncDecl); ok {
			return fd
		}
	}
	return nil
}

func (a *fileAnalyzer) funcDisplayName(stack []ast.Node) string {
	fd := enclosingFuncDecl(stack)
	if fd == nil {
		return "<toplevel>"
	}
	name := fd.Name.Name
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		t := fd.Recv.List[0].Type
		for {
			if star, ok := t.(*ast.StarExpr); ok {
				t = star.X
				continue
			}
			break
		}
		if id, ok := t.(*ast.Ident); ok {
			name = id.Name + "." + name
		}
	}
	// note closures
	depth := 0
	for _, n := range stack {
		if _, ok := n.(*ast.FuncLit); ok {
			depth++
		}
	}
	if depth > 0 {
		name += strings.Repeat(".func", depth)
	}
	return name
}

// sqlRowKind reports "Row"/"Rows" when t is *database/sql.Row / *database/sql.Rows.
func sqlRowKind(t types.Type) string {
	p, ok := t.(*types.Pointer)
	if !ok {
		return ""
	}
	n, ok := p.Elem().(*types.Named)
	if !ok {
		return ""
	}
	obj := n.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != "database/sql" {
		return ""
	}
	if obj.Name() == "Row" || obj.Name() == "Rows" {
		return obj.Name()
	}
	return ""
}

// classifyScanDest decides how the destination of one Scan argument reacts
// to a SQL NULL. The verdicts are backed by the measured decision table in
// nulltolerance_integration_test.go (2026-07-25, lib/pq 1.10.9,
// google/uuid 1.6.0, PostgreSQL 15).
func (a *fileAnalyzer) classifyScanDest(arg ast.Expr) (destClass, string, string) {
	arg = unparen(arg)
	info := a.pkg.TypesInfo

	// pq.Array(&x): measured NULL-tolerant for all element kinds
	if call, ok := arg.(*ast.CallExpr); ok {
		if isPkgFunc(info, call.Fun, "github.com/lib/pq", "Array") {
			return destOK, "pq.Array(...)", "measured NULL-tolerant"
		}
	}

	t := info.TypeOf(arg)
	if t == nil {
		return destUnknown, "?", "no type information"
	}
	if b, ok := t.(*types.Basic); ok && b.Kind() == types.UntypedNil {
		return destUnknown, "nil", "nil Scan destination"
	}
	ts := t.String()

	ptr, ok := t.Underlying().(*types.Pointer)
	if !ok {
		// non-pointer destination: only useful if it implements sql.Scanner
		if implementsScanner(t) {
			return classifyScannerType(t, ts)
		}
		if types.IsInterface(t) {
			return destUnknown, ts, "interface-typed destination; concrete type not visible"
		}
		return destUnknown, ts, "non-pointer Scan destination"
	}
	elem := ptr.Elem()
	elemStr := elem.String()

	// uuid.UUID: measured silent-zero
	if isNamed(elem, "github.com/google/uuid", "UUID") {
		return destSilentZero, elemStr, "uuid.UUID.Scan(nil) returns nil without setting the value (measured)"
	}
	// pointer-to-pointer (e.g. **string via &p): NULL-tolerant
	if _, ok := elem.Underlying().(*types.Pointer); ok {
		return destOK, elemStr, "pointer destination is NULL-tolerant"
	}
	// interface (any): tolerant
	if types.IsInterface(elem) {
		return destOK, elemStr, "interface destination accepts nil"
	}
	// sql.Scanner on *T or T
	if implementsScanner(types.NewPointer(elem)) || implementsScanner(elem) {
		return classifyScannerType(elem, elemStr)
	}
	// byte slices: exact []byte OK; named byte slices (json.RawMessage) NG (measured)
	if sl, ok := elem.Underlying().(*types.Slice); ok {
		if b, ok := sl.Elem().(*types.Basic); ok && b.Kind() == types.Uint8 {
			if _, named := elem.(*types.Named); !named {
				return destOK, elemStr, "[]byte accepts NULL as nil"
			}
			return destNG, elemStr, "named []byte type without Scanner rejects NULL (measured: json.RawMessage)"
		}
		return destNG, elemStr, "slice destination without Scanner rejects NULL"
	}
	return destNG, elemStr, "plain Go type has no NULL representation"
}

// classifyScannerType applies measured overrides for types implementing
// sql.Scanner; everything else is assumed tolerant (documented limitation —
// a Scanner whose Scan(nil) errors would be missed unless added here).
func classifyScannerType(t types.Type, ts string) (destClass, string, string) {
	base := t
	if p, ok := t.(*types.Pointer); ok {
		base = p.Elem()
	}
	if isNamed(base, "github.com/google/uuid", "UUID") {
		return destSilentZero, ts, "uuid.UUID.Scan(nil) returns nil without setting the value (measured)"
	}
	return destOK, ts, "implements sql.Scanner (assumed NULL-tolerant; sql.Null*/pq arrays measured)"
}

func isNamed(t types.Type, pkgPath, name string) bool {
	n, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := n.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == pkgPath && obj.Name() == name
}

// implementsScanner structurally checks for `Scan(any) error`, avoiding the
// need to locate the database/sql package object.
func implementsScanner(t types.Type) bool {
	ms := types.NewMethodSet(t)
	for i := 0; i < ms.Len(); i++ {
		m := ms.At(i)
		if m.Obj().Name() != "Scan" {
			continue
		}
		sig, ok := m.Obj().Type().(*types.Signature)
		if !ok || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		// NB: `any` is a *types.Alias since Go 1.23 (gotypesalias=1);
		// Unalias before asserting or every stdlib Scanner is missed.
		p, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Interface)
		if !ok || !p.Empty() {
			continue
		}
		if named, ok := sig.Results().At(0).Type().(*types.Named); ok &&
			named.Obj().Name() == "error" && named.Obj().Pkg() == nil {
			return true
		}
	}
	return false
}
