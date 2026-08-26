// Go -> JSON bridge for the command-injection ingest: per function, emit its params, assignments
// (lhs names <- rhs identifier/selector names), and calls (dotted callee + per-arg name lists).
// Uses the stdlib go/parser — native, exact. Mirrors the node+@babel bridge for JS.
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

type Arg struct {
	Names []string `json:"names"`
	Lit   string   `json:"lit"` // string-literal value (unquoted), else ""
}
type Call struct {
	Callee string `json:"callee"`
	Args   []Arg  `json:"args"`
	Local  bool   `json:"local,omitempty"`
}
type Assign struct {
	Lhs []string `json:"lhs"`
	Rhs []string `json:"rhs"`
}
type Func struct {
	Name          string     `json:"name"`
	Package       string     `json:"package"`
	QualifiedName string     `json:"qualified_name,omitempty"`
	Params        []string   `json:"params"`
	Calls         []Call     `json:"calls"`
	Assigns       []Assign   `json:"assigns"`
	Returns       [][]string `json:"returns"` // name footprint of each return expression (for return-taint summary)
}

// qualifiedTypeName preserves an imported package qualifier while stripping pointer/generic wrappers.
// That distinction is load-bearing for summary identity: “other.Type.Run“ must never be rewritten as
// a method on a same-spelled type in the current package.
func qualifiedTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return qualifiedTypeName(x.X)
	case *ast.SelectorExpr:
		base := qualifiedTypeName(x.X)
		if base != "" {
			return base + "." + x.Sel.Name
		}
		return x.Sel.Name
	case *ast.IndexExpr:
		return qualifiedTypeName(x.X)
	case *ast.IndexListExpr:
		return qualifiedTypeName(x.X)
	}
	return ""
}

// dotted name of a call's callee: exec.Command -> "exec.Command", r.FormValue -> "r.FormValue"
func dotted(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		base := dotted(x.X)
		if base != "" {
			return base + "." + x.Sel.Name
		}
		return x.Sel.Name
	case *ast.CallExpr:
		return dotted(x.Fun) // chained: r.URL.Query().Get -> resolves the receiver method
	}
	return ""
}

// Collision-prone source markers (Get/Form/Args/...) double as common config/std-lib method names.
// On a PROVABLY trusted config receiver (viper.Get, cfg.Get) the value is configuration, not attacker
// input — emitting the bare marker there caused a false positive (idiom-sweep ws6yh6pp7). We drop the
// marker ONLY for these receivers, so an unknown/HTTP receiver still emits it (no silent FN).
var collisionMarkers = map[string]bool{
	"Get": true, "Form": true, "Header": true, "Query": true, "URL": true,
	"Param": true, "Params": true, "Vars": true, "ReadAll": true, "Args": true,
}

// Deliberately NOT included: short names like `v` — `v := r.URL.Query(); v.Get("h")` is a REAL source, so
// trusting `v` would be a silent FN. Only names that are overwhelmingly config handles belong here.
var trustedReceivers = map[string]bool{
	"viper": true, "cfg": true, "config": true, "conf": true, "koanf": true, "settings": true,
}

// rootIdent: the leftmost identifier of a selector/call chain (viper.Get -> "viper", r.URL.Query() -> "r")
func rootIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return rootIdent(x.X)
	case *ast.CallExpr:
		return rootIdent(x.Fun)
	case *ast.IndexExpr:
		return rootIdent(x.X)
	case *ast.TypeAssertExpr:
		return rootIdent(x.X)
	}
	return ""
}

// every identifier + selector field name in an expression subtree (the taint footprint), EXCEPT a
// collision-prone source marker reached on a trusted config receiver (viper.Get -> emits "viper" only).
func names(e ast.Expr, out *[]string) {
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if !(collisionMarkers[x.Sel.Name] && trustedReceivers[rootIdent(x.X)]) {
				*out = append(*out, x.Sel.Name)
			}
			names(x.X, out) // walk the receiver ourselves so the trusted-skip applies all the way down
			return false    // and stop Inspect from re-visiting x.X / adding x.Sel as a bare Ident
		case *ast.Ident:
			*out = append(*out, x.Name)
		}
		return true
	})
}

// declaredExprType returns a concrete type only when the expression itself proves it.  It is used
// while collecting local declarations; calls to arbitrary constructors are intentionally not guessed.
func declaredExprType(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CompositeLit:
		return qualifiedTypeName(x.Type)
	case *ast.UnaryExpr:
		return declaredExprType(x.X) // &Clean{} retains Clean as the receiver type
	case *ast.ParenExpr:
		return declaredExprType(x.X)
	case *ast.CallExpr:
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
			return qualifiedTypeName(x.Args[0])
		}
	case *ast.TypeAssertExpr:
		return qualifiedTypeName(x.Type)
	}
	return ""
}

// localTypes conservatively records statically provable receiver types. If one spelling is shadowed
// with different concrete types, it is omitted entirely rather than assigning a method call to the
// wrong receiver and transferring a taint summary across unrelated methods.
func localTypes(fd *ast.FuncDecl) map[string]string {
	candidates := map[string]map[string]bool{}
	add := func(name, typ string) {
		if name == "" || typ == "" {
			return
		}
		if candidates[name] == nil {
			candidates[name] = map[string]bool{}
		}
		candidates[name][typ] = true
	}
	if fd.Recv != nil {
		for _, field := range fd.Recv.List {
			for _, name := range field.Names {
				add(name.Name, typeName(field.Type))
			}
		}
	}
	if fd.Type.Params != nil {
		for _, field := range fd.Type.Params.List {
			for _, name := range field.Names {
				add(name.Name, qualifiedTypeName(field.Type))
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ValueSpec:
			if typ := qualifiedTypeName(x.Type); typ != "" {
				for _, name := range x.Names {
					add(name.Name, typ)
				}
			} else if len(x.Names) == len(x.Values) {
				for i, name := range x.Names {
					add(name.Name, declaredExprType(x.Values[i]))
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE || len(x.Lhs) != len(x.Rhs) {
				break
			}
			for i, lhs := range x.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					add(id.Name, declaredExprType(x.Rhs[i]))
				}
			}
		}
		return true
	})
	out := map[string]string{}
	for name, types := range candidates {
		if len(types) == 1 {
			for typ := range types {
				out[name] = typ
			}
		}
	}
	return out
}

func receiverType(e ast.Expr, types map[string]string) string {
	switch x := e.(type) {
	case *ast.Ident:
		return types[x.Name]
	case *ast.CompositeLit:
		return qualifiedTypeName(x.Type)
	case *ast.UnaryExpr:
		return receiverType(x.X, types)
	case *ast.ParenExpr:
		return receiverType(x.X, types)
	case *ast.IndexExpr:
		return receiverType(x.X, types)
	case *ast.IndexListExpr:
		return receiverType(x.X, types)
	case *ast.TypeAssertExpr:
		return qualifiedTypeName(x.Type)
	}
	return ""
}

// qualifiedCallee retains a concrete receiver identity when syntax or a static local declaration
// proves it. Unknown dynamic or imported receivers keep their written spelling and are not treated
// as local package calls by the summary layer.
func qualifiedCallee(e ast.Expr, types map[string]string, pkg string) (string, bool) {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if typ := receiverType(sel.X, types); typ != "" {
			if strings.Contains(typ, ".") {
				return typ + "." + sel.Sel.Name, false
			}
			return pkg + "." + typ + "." + sel.Sel.Name, true
		}
	}
	if id, ok := e.(*ast.Ident); ok {
		return pkg + "." + id.Name, true
	}
	return dotted(e), false
}

func appendQualifiedCalls(e ast.Expr, types map[string]string, pkg string, out *[]string) {
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if q, local := qualifiedCallee(call.Fun, types, pkg); strings.Contains(q, ".") {
				if local {
					q = "__lattice_local_call__:" + q
				}
				*out = append(*out, q)
			}
		}
		return true
	})
}

// ---- graph mode (-mode graph <file>) ----------------------------------------
// Emits the structural facts the hypernetwork builder needs: symbols with lines,
// kinds, containers, export flags, stub flags, embedded-type inheritance; import
// specs; call sites with their line and bare callee name. Additive: the default
// (taint) output below is untouched.

type GraphSymbol struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Container  string   `json:"container,omitempty"`
	Start      int      `json:"start"`
	End        int      `json:"end"`
	Exported   bool     `json:"exported"`
	Stub       bool     `json:"stub"`
	Params     []string `json:"params"`
	Extends    []string `json:"extends"`
	Implements []string `json:"implements"`
}
type GraphImport struct {
	Path  string `json:"path"`
	Alias string `json:"alias,omitempty"`
	Line  int    `json:"line"`
}
type GraphCall struct {
	FromLine int    `json:"from_line"`
	Name     string `json:"name"`
	Callee   string `json:"callee"`
}
type GraphFile struct {
	Package string        `json:"package"`
	Entry   bool          `json:"entry"`
	Imports []GraphImport `json:"imports"`
	Symbols []GraphSymbol `json:"symbols"`
	Calls   []GraphCall   `json:"calls"`
}

// bare type name under pointers/generics/qualifiers: *pkg.T[K] -> T
func typeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return typeName(x.X)
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.IndexExpr:
		return typeName(x.X)
	case *ast.IndexListExpr:
		return typeName(x.X)
	}
	return ""
}

var stubMarkers = []string{"todo", "not implemented", "unimplemented", "not yet implemented", "implement me"}

func litIsStubMarker(lit string) bool {
	l := strings.ToLower(lit)
	for _, m := range stubMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// A stub body: absent, empty, or a lone panic("...TODO/not implemented...").
func isStubBody(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return true
	}
	if len(body.List) != 1 {
		return false
	}
	es, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "panic" {
		return false
	}
	if len(call.Args) != 1 {
		return false
	}
	bl, ok := call.Args[0].(*ast.BasicLit)
	if !ok {
		return false
	}
	v, err := strconv.Unquote(bl.Value)
	return err == nil && litIsStubMarker(v)
}

func graphMain(path string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		os.Stderr.WriteString("PARSE_ERROR: " + err.Error())
		os.Exit(2)
	}
	out := GraphFile{Package: f.Name.Name}
	line := func(p token.Pos) int { return fset.Position(p).Line }

	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		alias := ""
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		out.Imports = append(out.Imports, GraphImport{Path: p, Alias: alias, Line: line(imp.Pos())})
	}

	hasMain := false
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				sym := GraphSymbol{Name: ts.Name.Name, Start: line(ts.Pos()), End: line(ts.End()),
					Exported: ast.IsExported(ts.Name.Name),
					Params:   []string{}, Extends: []string{}, Implements: []string{}}
				switch t := ts.Type.(type) {
				case *ast.StructType:
					sym.Kind = "class"
					for _, fl := range t.Fields.List {
						if len(fl.Names) == 0 { // embedded type -> inheritance-like reuse
							if n := typeName(fl.Type); n != "" {
								sym.Extends = append(sym.Extends, n)
							}
						}
					}
				case *ast.InterfaceType:
					sym.Kind = "interface"
					for _, m := range t.Methods.List {
						if len(m.Names) == 0 { // embedded interface
							if n := typeName(m.Type); n != "" {
								sym.Extends = append(sym.Extends, n)
							}
						}
					}
				default:
					sym.Kind = "type"
				}
				out.Symbols = append(out.Symbols, sym)
			}
		case *ast.FuncDecl:
			sym := GraphSymbol{Name: d.Name.Name, Kind: "function",
				Start: line(d.Pos()), End: line(d.End()),
				Exported: ast.IsExported(d.Name.Name), Stub: isStubBody(d.Body),
				Params: []string{}, Extends: []string{}, Implements: []string{}}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				sym.Kind = "method"
				sym.Container = typeName(d.Recv.List[0].Type)
			}
			if d.Type.Params != nil {
				for _, p := range d.Type.Params.List {
					for _, nm := range p.Names {
						sym.Params = append(sym.Params, nm.Name)
					}
				}
			}
			out.Symbols = append(out.Symbols, sym)
			if d.Name.Name == "main" && d.Recv == nil {
				hasMain = true
			}
			if d.Body != nil {
				ast.Inspect(d.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						full := dotted(call.Fun)
						if full != "" {
							parts := strings.Split(full, ".")
							out.Calls = append(out.Calls, GraphCall{
								FromLine: line(call.Pos()), Name: parts[len(parts)-1], Callee: full})
						}
					}
					return true
				})
			}
		}
	}
	out.Entry = f.Name.Name == "main" && hasMain
	json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	args := os.Args[1:]
	if len(args) >= 3 && args[0] == "-mode" && args[1] == "graph" {
		graphMain(args[2])
		return
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, args[0], nil, 0)
	if err != nil {
		os.Stderr.WriteString("PARSE_ERROR: " + err.Error())
		os.Exit(2)
	}
	var funcs []Func
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		fn := Func{Name: fd.Name.Name, Package: f.Name.Name,
			QualifiedName: f.Name.Name + "." + fd.Name.Name}
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			if recv := typeName(fd.Recv.List[0].Type); recv != "" {
				fn.QualifiedName = f.Name.Name + "." + recv + "." + fd.Name.Name
			}
		}
		types := localTypes(fd)
		if fd.Type.Params != nil {
			for _, p := range fd.Type.Params.List {
				for _, nm := range p.Names {
					fn.Params = append(fn.Params, nm.Name)
				}
			}
		}
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			switch s := m.(type) {
			case *ast.CallExpr:
				callee, local := qualifiedCallee(s.Fun, types, f.Name.Name)
				c := Call{Callee: callee, Local: local}
				for _, a := range s.Args {
					arg := Arg{}
					names(a, &arg.Names)
					if bl, ok := a.(*ast.BasicLit); ok {
						if v, err := strconv.Unquote(bl.Value); err == nil {
							arg.Lit = v
						}
					}
					c.Args = append(c.Args, arg)
				}
				fn.Calls = append(fn.Calls, c)
			case *ast.AssignStmt:
				var asn Assign
				for _, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						asn.Lhs = append(asn.Lhs, id.Name)
					} else {
						// container/struct/pointer WRITE: m["c"]=x / q.Cmd=x / *p=x — taint the base
						// identifier so the container stays tainted (the LHS was previously dropped).
						switch l.(type) {
						case *ast.IndexExpr, *ast.SelectorExpr, *ast.StarExpr:
							if root := rootIdent(l); root != "" {
								asn.Lhs = append(asn.Lhs, root)
							}
						}
					}
				}
				for _, r := range s.Rhs {
					names(r, &asn.Rhs)
					appendQualifiedCalls(r, types, f.Name.Name, &asn.Rhs)
				}
				if len(asn.Lhs) > 0 {
					fn.Assigns = append(fn.Assigns, asn)
				}
			case *ast.ReturnStmt:
				for _, res := range s.Results {
					var rn []string
					names(res, &rn)
					appendQualifiedCalls(res, types, f.Name.Name, &rn)
					fn.Returns = append(fn.Returns, rn)
				}
			}
			return true
		})
		funcs = append(funcs, fn)
	}
	json.NewEncoder(os.Stdout).Encode(funcs)
}
