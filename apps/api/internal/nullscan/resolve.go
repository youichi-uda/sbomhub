package nullscan

// Go-AST-level resolution of the SQL string passed to Query/QueryRow/
// QueryContext/QueryRowContext. Handles: string literals and constants
// (via go/types constant folding, which also covers `+` concatenation of
// constants), local variables assigned literals, conditional reassignments
// and `+=` appends, and fmt.Sprintf with constant format strings. Fragments
// that cannot be resolved statically become DynMarker tokens; whether that
// poisons the analysis is decided later by where the marker lands in the SQL
// (projection/FROM => unanalyzable, WHERE/ORDER BY tail => harmless).

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// maxSQLCandidates bounds the conditional-assignment fan-out (audit's
// ListWithFilter builds 2^5 = 32 WHERE variants; all share one projection).
const maxSQLCandidates = 64

type resolver struct {
	info *types.Info
	fset *token.FileSet
}

// resolveSQLArg resolves the SQL argument expression used at usePos inside
// fn. It returns one or more candidate SQL strings (conditional assignment
// paths), or an error explaining why resolution failed.
func (r *resolver) resolveSQLArg(expr ast.Expr, fn *ast.FuncDecl, usePos token.Pos) ([]string, error) {
	cands, err := r.resolveExpr(expr, fn, usePos, 0, nil)
	if err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no resolvable SQL value")
	}
	if len(cands) > maxSQLCandidates {
		return nil, fmt.Errorf("too many dynamic SQL variants (%d > %d)", len(cands), maxSQLCandidates)
	}
	out := dedupeStrings(cands)
	// `var query string` + switch-case assignment leaves a phantom
	// empty-string candidate for the branch that early-returns before the
	// query call. Empty SQL has no projection, so it cannot hide a
	// NULL-scan bug — drop it when a real candidate exists (it would only
	// produce a noise "empty SQL" finding for an unreachable path).
	if len(out) > 1 {
		nonEmpty := out[:0]
		for _, c := range out {
			if strings.TrimSpace(c) != "" {
				nonEmpty = append(nonEmpty, c)
			}
		}
		if len(nonEmpty) > 0 {
			out = nonEmpty
		}
	}
	return out, nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// env maps variables to their already-accumulated candidate values; it is
// used to resolve self-references (`query = "..." + query + "..."`) against
// the value BEFORE the assignment instead of recursing forever.
func (r *resolver) resolveExpr(expr ast.Expr, fn *ast.FuncDecl, usePos token.Pos, depth int, env map[*types.Var][]string) ([]string, error) {
	if depth > 12 {
		return nil, fmt.Errorf("SQL resolution recursion too deep")
	}
	// constant folding first: literals, consts, constant concatenation
	if tv, ok := r.info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.String {
		return []string{constant.StringVal(tv.Value)}, nil
	}

	switch e := expr.(type) {
	case *ast.ParenExpr:
		return r.resolveExpr(e.X, fn, usePos, depth+1, env)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return nil, fmt.Errorf("non-concatenation operator %s in SQL expression", e.Op)
		}
		// An unresolvable operand degrades to a DynMarker fragment instead
		// of poisoning the whole concatenation: `constSQL + orderBy(x)`
		// stays analyzable because the marker lands in the ORDER BY tail.
		left, err := r.resolveExpr(e.X, fn, usePos, depth+1, env)
		if err != nil {
			left = []string{DynMarker}
		}
		right, err := r.resolveExpr(e.Y, fn, usePos, depth+1, env)
		if err != nil {
			right = []string{DynMarker}
		}
		var out []string
		for _, l := range left {
			for _, rr := range right {
				out = append(out, l+rr)
				if len(out) > maxSQLCandidates {
					return nil, fmt.Errorf("too many dynamic SQL variants")
				}
			}
		}
		return out, nil
	case *ast.Ident:
		obj := r.info.ObjectOf(e)
		v, ok := obj.(*types.Var)
		if !ok {
			return nil, fmt.Errorf("identifier %q is not a variable", e.Name)
		}
		if vals, ok := env[v]; ok {
			return vals, nil
		}
		if fn == nil || fn.Body == nil {
			return nil, fmt.Errorf("no enclosing function body to trace %q", e.Name)
		}
		return r.resolveVar(v, fn, usePos, depth, env)
	case *ast.CallExpr:
		if isPkgFunc(r.info, e.Fun, "fmt", "Sprintf") {
			return r.resolveSprintf(e, fn, usePos, depth, env)
		}
		return nil, fmt.Errorf("SQL built by function call %s", renderExprHead(e))
	case *ast.SelectorExpr:
		return nil, fmt.Errorf("SQL from field/selector %s is not traceable", renderExprHead(e))
	default:
		return nil, fmt.Errorf("unsupported SQL expression node %T", expr)
	}
}

// resolveVar reconstructs candidate values of local variable v at usePos by
// scanning assignments in source order. Assignments nested inside
// conditional/loop statements fork the candidate set (both with and without
// the assignment) instead of replacing it.
func (r *resolver) resolveVar(v *types.Var, fn *ast.FuncDecl, usePos token.Pos, depth int, env map[*types.Var][]string) ([]string, error) {
	type assign struct {
		pos    token.Pos
		rhs    ast.Expr
		opAdd  bool // += or self-append (v = v + x)
		nested bool // inside if/for/switch relative to fn.Body
		decl   bool // var v string (no init) => ""
	}
	var assigns []assign

	// conditional-nesting detection: walk with an explicit nesting counter.
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
			if s.Post != nil {
				walk(s.Post, true)
			}
			walk(s.Body, true)
		case *ast.RangeStmt:
			walk(s.Body, true)
		case *ast.SwitchStmt:
			if s.Init != nil {
				walk(s.Init, nested)
			}
			walk(s.Body, true)
		case *ast.TypeSwitchStmt:
			walk(s.Body, true)
		case *ast.SelectStmt:
			walk(s.Body, true)
		case *ast.CaseClause:
			for _, st := range s.Body {
				walk(st, true)
			}
		case *ast.CommClause:
			for _, st := range s.Body {
				walk(st, true)
			}
		case *ast.LabeledStmt:
			walk(s.Stmt, nested)
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || r.info.ObjectOf(id) != v {
					continue
				}
				a := assign{pos: s.Pos(), nested: nested}
				if i < len(s.Rhs) && len(s.Lhs) == len(s.Rhs) {
					a.rhs = s.Rhs[i]
				} // else: multi-value assignment; rhs stays nil => unresolvable
				switch s.Tok {
				case token.ADD_ASSIGN:
					a.opAdd = true
				case token.ASSIGN, token.DEFINE:
					// self-append: v = v + x
					if be, ok := a.rhs.(*ast.BinaryExpr); ok && be.Op == token.ADD {
						if xid, ok := be.X.(*ast.Ident); ok && r.info.ObjectOf(xid) == v {
							a.opAdd = true
							a.rhs = be.Y
						}
					}
				default:
					a.rhs = nil // other compound assignment: unresolvable
				}
				assigns = append(assigns, a)
			}
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok {
				return
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if r.info.ObjectOf(name) != v {
						continue
					}
					a := assign{pos: vs.Pos(), nested: nested}
					if i < len(vs.Values) {
						a.rhs = vs.Values[i]
					} else {
						a.decl = true
					}
					assigns = append(assigns, a)
				}
			}
		case *ast.FuncLit:
			// assignments inside closures still count (conservatively nested)
			walk(s.Body, true)
		default:
			// generic descent for statements that contain nested statements
			ast.Inspect(n, func(c ast.Node) bool {
				if c == n {
					return true
				}
				switch c.(type) {
				case *ast.BlockStmt, *ast.AssignStmt, *ast.DeclStmt, *ast.IfStmt,
					*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt,
					*ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit,
					*ast.LabeledStmt:
					walk(c, nested)
					return false
				}
				return true
			})
		}
	}
	walk(fn.Body, false)

	if len(assigns) == 0 {
		if v.IsField() {
			return nil, fmt.Errorf("variable %q is a struct field", v.Name())
		}
		return nil, fmt.Errorf("no assignment to %q found in function (parameter or captured variable?)", v.Name())
	}

	cands := []string{}
	for _, a := range assigns {
		if a.pos >= usePos {
			continue
		}
		var vals []string
		switch {
		case a.decl:
			vals = []string{""}
		case a.rhs == nil:
			vals = []string{DynMarker}
		default:
			// Resolve the rhs with the variable itself bound to its
			// candidates so far, so `v = "pre" + v + "post"` wraps the
			// current value instead of recursing.
			selfEnv := make(map[*types.Var][]string, len(env)+1)
			for k, vv := range env {
				selfEnv[k] = vv
			}
			cur := cands
			if len(cur) == 0 {
				cur = []string{""}
			}
			selfEnv[v] = cur
			var err error
			vals, err = r.resolveExpr(a.rhs, fn, usePos, depth+1, selfEnv)
			if err != nil {
				vals = []string{DynMarker}
			}
		}
		if a.opAdd {
			var next []string
			if a.nested {
				next = append(next, cands...) // path without the append
			}
			base := cands
			if len(base) == 0 {
				base = []string{""}
			}
			for _, c := range base {
				for _, val := range vals {
					next = append(next, c+val)
				}
			}
			cands = next
		} else {
			var next []string
			if a.nested {
				next = append(next, cands...) // path without the reassignment
			}
			next = append(next, vals...)
			cands = next
		}
		if len(cands) > maxSQLCandidates {
			return nil, fmt.Errorf("too many dynamic SQL variants while tracing %q", v.Name())
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no assignment to %q precedes its use", v.Name())
	}
	return dedupeStrings(cands), nil
}

// resolveSprintf substitutes constant args into a constant format string;
// non-constant verbs become DynMarker.
func (r *resolver) resolveSprintf(call *ast.CallExpr, fn *ast.FuncDecl, usePos token.Pos, depth int, env map[*types.Var][]string) ([]string, error) {
	if len(call.Args) == 0 {
		return nil, fmt.Errorf("fmt.Sprintf with no arguments")
	}
	formats, err := r.resolveExpr(call.Args[0], fn, usePos, depth+1, env)
	if err != nil {
		return nil, fmt.Errorf("fmt.Sprintf format string: %w", err)
	}
	if call.Ellipsis.IsValid() {
		return nil, fmt.Errorf("fmt.Sprintf with spread arguments")
	}

	// resolve each arg to candidate strings (DynMarker when unresolvable)
	argCands := make([][]string, 0, len(call.Args)-1)
	for _, a := range call.Args[1:] {
		if tv, ok := r.info.Types[a]; ok && tv.Value != nil {
			switch tv.Value.Kind() {
			case constant.String:
				argCands = append(argCands, []string{constant.StringVal(tv.Value)})
				continue
			case constant.Int, constant.Float, constant.Bool:
				argCands = append(argCands, []string{tv.Value.ExactString()})
				continue
			}
		}
		if cands, err := r.resolveExpr(a, fn, usePos, depth+1, env); err == nil && len(cands) > 0 {
			argCands = append(argCands, cands)
			continue
		}
		argCands = append(argCands, []string{DynMarker})
	}

	// cross-product of per-arg candidates, degrading multi-candidate args
	// to DynMarker if the fan-out would exceed the cap
	combos := [][]string{{}}
	for _, cands := range argCands {
		if len(combos)*len(cands) > maxSQLCandidates {
			cands = []string{DynMarker}
		}
		var next [][]string
		for _, c := range combos {
			for _, v := range cands {
				row := make([]string, len(c), len(c)+1)
				copy(row, c)
				next = append(next, append(row, v))
			}
		}
		combos = next
	}

	var out []string
	for _, f := range formats {
		for _, argVals := range combos {
			s, err := substituteVerbs(f, argVals)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
			if len(out) > maxSQLCandidates {
				return nil, fmt.Errorf("too many dynamic SQL variants from Sprintf")
			}
		}
	}
	return out, nil
}

func substituteVerbs(format string, args []string) (string, error) {
	var sb strings.Builder
	argIdx := 0
	i := 0
	for i < len(format) {
		c := format[i]
		if c != '%' {
			sb.WriteByte(c)
			i++
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			sb.WriteByte('%')
			i += 2
			continue
		}
		// consume flags/width/precision then the verb rune
		j := i + 1
		for j < len(format) && strings.ContainsRune("+-# 0123456789.", rune(format[j])) {
			j++
		}
		if j >= len(format) {
			return "", fmt.Errorf("trailing %% in format string")
		}
		if format[j] == '*' {
			return "", fmt.Errorf("dynamic width (%%*) in format string")
		}
		if format[j] == '[' {
			// positional verbs (%[2]s) would silently mis-map arguments —
			// refuse so the caller degrades to DynMarker/unanalyzable
			// instead of producing WRONG SQL (gemini-r2 #2)
			return "", fmt.Errorf("positional format verb (%%[n]) not supported")
		}
		if argIdx >= len(args) {
			return "", fmt.Errorf("format string has more verbs than arguments")
		}
		sb.WriteString(args[argIdx])
		argIdx++
		i = j + 1
	}
	return sb.String(), nil
}

// isPkgFunc reports whether fun is a reference to pkg.name (e.g. fmt.Sprintf).
func isPkgFunc(info *types.Info, fun ast.Expr, pkg, name string) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	if obj, ok := info.Uses[sel.Sel]; ok {
		if f, ok := obj.(*types.Func); ok && f.Pkg() != nil {
			return f.Pkg().Path() == pkg
		}
	}
	return false
}

func renderExprHead(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CallExpr:
		return renderExprHead(x.Fun) + "(...)"
	case *ast.SelectorExpr:
		return renderExprHead(x.X) + "." + x.Sel.Name
	case *ast.Ident:
		return x.Name
	default:
		return fmt.Sprintf("%T", e)
	}
}
