// Rust -> JSON bridge for the command-injection ingest. Uses `syn` (native Rust parser). Per function:
// name, params, calls (ExprCall path callee / ExprMethodCall method name + per-arg {names, lit}),
// assignments (let bindings + ExprAssign: lhs names <- rhs footprint), and returns (the name footprint of
// each explicit `return` expression AND the implicit trailing expression — for the return-taint summary).
// The Process::Command builder chain `Command::new("sh").arg("-c").arg(x)` surfaces as a Command::new
// call + .arg method calls; the Python ingest reconstructs the shell form from the per-function call list.
use serde::Serialize;
use syn::visit::Visit;

#[derive(Serialize, Default)]
struct Arg {
    names: Vec<String>,
    lit: String,
}
#[derive(Serialize, Default)]
struct Call {
    callee: String,
    args: Vec<Arg>,
}
#[derive(Serialize, Default)]
struct Assign {
    lhs: Vec<String>,
    rhs: Vec<String>,
}
#[derive(Serialize, Default)]
struct Func {
    name: String,
    qualified_name: String,
    params: Vec<String>,
    calls: Vec<Call>,
    assigns: Vec<Assign>,
    returns: Vec<Vec<String>>,
}

// All idents bound by a `let` pattern — Pat::Ident plus tuple/struct/slice/reference destructuring
// (`let (cmd, _f) = ...`), so a destructured binding still enters the dep graph.
fn collect_pat_idents(p: &syn::Pat, out: &mut Vec<String>) {
    match p {
        syn::Pat::Ident(pi) => out.push(pi.ident.to_string()),
        syn::Pat::Tuple(t) => {
            for e in &t.elems {
                collect_pat_idents(e, out);
            }
        }
        syn::Pat::TupleStruct(t) => {
            for e in &t.elems {
                collect_pat_idents(e, out);
            }
        }
        syn::Pat::Struct(s) => {
            for f in &s.fields {
                collect_pat_idents(&f.pat, out);
            }
        }
        syn::Pat::Slice(s) => {
            for e in &s.elems {
                collect_pat_idents(e, out);
            }
        }
        syn::Pat::Reference(r) => collect_pat_idents(&r.pat, out),
        syn::Pat::Type(t) => collect_pat_idents(&t.pat, out),
        syn::Pat::Or(o) => {
            for e in &o.cases {
                collect_pat_idents(e, out);
            }
        }
        _ => {}
    }
}

fn collect_tokens(ts: proc_macro2::TokenStream, out: &mut Vec<String>) {
    for tt in ts {
        match tt {
            proc_macro2::TokenTree::Ident(id) => out.push(id.to_string()),
            proc_macro2::TokenTree::Group(g) => collect_tokens(g.stream(), out),
            _ => {}
        }
    }
}

struct NameCollector {
    names: Vec<String>,
    module_path: Vec<String>,
    crate_path: Vec<String>,
}
impl<'ast> Visit<'ast> for NameCollector {
    fn visit_ident(&mut self, i: &'ast proc_macro2::Ident) {
        self.names.push(i.to_string());
    }
    // Keep the complete static call path as one footprint token as well as its individual identifiers.
    // Python can then distinguish `Dirty::load()` from `Clean::load()` when same-named impl methods exist.
    fn visit_expr_call(&mut self, n: &'ast syn::ExprCall) {
        let path = scoped_path(&callee_path(&n.func), &self.module_path, &self.crate_path);
        if !path.is_empty() {
            self.names.push(path);
        }
        syn::visit::visit_expr_call(self, n);
    }
    // `format!("ping {}", host)` hides its interpolated vars in an unparsed token stream — extract the
    // identifiers so the tainted `host` joins the footprint (format! IS how Rust builds command strings).
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        collect_tokens(m.tokens.clone(), &mut self.names);
    }
}
fn names_in(e: &syn::Expr, module_path: &[String], crate_path: &[String]) -> Vec<String> {
    let mut c = NameCollector {
        names: vec![],
        module_path: module_path.to_vec(),
        crate_path: crate_path.to_vec(),
    };
    c.visit_expr(e);
    c.names
}
fn lit_of(e: &syn::Expr) -> String {
    if let syn::Expr::Lit(el) = e {
        if let syn::Lit::Str(s) = &el.lit {
            return s.value();
        }
    }
    String::new()
}
fn callee_path(e: &syn::Expr) -> String {
    if let syn::Expr::Path(p) = e {
        let segs: Vec<String> = p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        return segs.join("::");
    }
    String::new()
}

fn scoped_path(path: &str, module_path: &[String], crate_path: &[String]) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = path.split("::").collect();
    let mut scope = module_path.to_vec();
    match parts.first().copied() {
        Some("crate") => {
            scope = crate_path.to_vec();
            parts.remove(0);
        }
        Some("self") => {
            parts.remove(0);
        }
        Some("super") => {
            while parts.first().copied() == Some("super") {
                scope.pop();
                parts.remove(0);
            }
        }
        _ => {}
    }
    scope.extend(parts.into_iter().map(str::to_string));
    scope.join("::")
}

struct FnBody {
    f: Func,
    module_path: Vec<String>,
    crate_path: Vec<String>,
}
impl<'ast> Visit<'ast> for FnBody {
    fn visit_expr_call(&mut self, n: &'ast syn::ExprCall) {
        let mut c = Call {
            callee: scoped_path(&callee_path(&n.func), &self.module_path, &self.crate_path),
            args: vec![],
        };
        for a in &n.args {
            c.args.push(Arg {
                names: names_in(a, &self.module_path, &self.crate_path),
                lit: lit_of(a),
            });
        }
        self.f.calls.push(c);
        syn::visit::visit_expr_call(self, n);
    }
    fn visit_expr_method_call(&mut self, n: &'ast syn::ExprMethodCall) {
        let m = n.method.to_string();
        let mut c = Call {
            callee: m.clone(),
            args: vec![],
        };
        for a in &n.args {
            c.args.push(Arg {
                names: names_in(a, &self.module_path, &self.crate_path),
                lit: lit_of(a),
            });
        }
        self.f.calls.push(c);
        // string/collection MUTATORS: the receiver accumulates taint from its args
        // (`let mut s=...; s.push_str(&u)` makes s tainted). Modelled as an augmenting assign.
        if matches!(
            m.as_str(),
            "push_str"
                | "push"
                | "insert_str"
                | "insert"
                | "extend"
                | "write_str"
                | "replace_range"
        ) {
            let recv = names_in(&n.receiver, &self.module_path, &self.crate_path);
            if !recv.is_empty() {
                let mut rhs = recv.clone();
                for a in &n.args {
                    rhs.extend(names_in(a, &self.module_path, &self.crate_path));
                }
                self.f.assigns.push(Assign { lhs: recv, rhs });
            }
        }
        syn::visit::visit_expr_method_call(self, n);
    }
    fn visit_local(&mut self, n: &'ast syn::Local) {
        let mut asn = Assign::default();
        collect_pat_idents(&n.pat, &mut asn.lhs); // Pat::Ident AND tuple/struct/slice destructuring
        if let Some(init) = &n.init {
            asn.rhs = names_in(&init.expr, &self.module_path, &self.crate_path);
        }
        if !asn.lhs.is_empty() {
            self.f.assigns.push(asn);
        }
        syn::visit::visit_local(self, n);
    }
    fn visit_expr_assign(&mut self, n: &'ast syn::ExprAssign) {
        let asn = Assign {
            lhs: names_in(&n.left, &self.module_path, &self.crate_path),
            rhs: names_in(&n.right, &self.module_path, &self.crate_path),
        };
        if !asn.lhs.is_empty() {
            self.f.assigns.push(asn);
        }
        syn::visit::visit_expr_assign(self, n);
    }
    // explicit `return X` — its name footprint feeds the return-taint summary (closure returns land in
    // the enclosing fn's list too: an over-approximation in the FIRE direction, never a dropped flow).
    fn visit_expr_return(&mut self, n: &'ast syn::ExprReturn) {
        if let Some(e) = &n.expr {
            self.f
                .returns
                .push(names_in(e, &self.module_path, &self.crate_path));
        }
        syn::visit::visit_expr_return(self, n);
    }
}

fn impl_type_name(ty: &syn::Type) -> String {
    if let syn::Type::Path(path) = ty {
        return path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
    }
    String::new()
}

struct Top {
    funcs: Vec<Func>,
    impl_type: Option<String>,
    module_path: Vec<String>,
    crate_path: Vec<String>,
}
impl Top {
    // shared emission for free fns AND impl methods (both expose sig + block). The typed-arg filter
    // skips the &self receiver, so a method's params line up with its call-site argument indices.
    fn add_func(&mut self, sig: &syn::Signature, block: &syn::Block, qualifier: Option<String>) {
        let mut f = Func::default();
        f.name = sig.ident.to_string();
        f.qualified_name = qualifier
            .filter(|value| !value.is_empty())
            .map(|value| format!("{}::{}", value, f.name))
            .unwrap_or_else(|| f.name.clone());
        for inp in &sig.inputs {
            if let syn::FnArg::Typed(pt) = inp {
                if let syn::Pat::Ident(pi) = &*pt.pat {
                    f.params.push(pi.ident.to_string());
                }
            }
        }
        let mut body = FnBody {
            f,
            module_path: self.module_path.clone(),
            crate_path: self.crate_path.clone(),
        };
        body.visit_block(block);
        // the IMPLICIT return — a trailing expression without `;` (THE Rust idiom for returning).
        if let Some(syn::Stmt::Expr(e, None)) = block.stmts.last() {
            body.f
                .returns
                .push(names_in(e, &self.module_path, &self.crate_path));
        }
        self.funcs.push(body.f);
    }
}
impl<'ast> Visit<'ast> for Top {
    fn visit_item_fn(&mut self, n: &'ast syn::ItemFn) {
        let qualifier = (!self.module_path.is_empty()).then(|| self.module_path.join("::"));
        self.add_func(&n.sig, &n.block, qualifier);
        syn::visit::visit_item_fn(self, n);
    }
    // methods inside `impl` blocks — previously NOT emitted at all (a silent FN for the dominant
    // Rust code-organization idiom; method calls already key by bare method name downstream).
    fn visit_impl_item_fn(&mut self, n: &'ast syn::ImplItemFn) {
        let qualifier = self
            .impl_type
            .as_deref()
            .map(|value| scoped_path(value, &self.module_path, &self.crate_path));
        self.add_func(&n.sig, &n.block, qualifier);
        syn::visit::visit_impl_item_fn(self, n);
    }
    fn visit_item_impl(&mut self, n: &'ast syn::ItemImpl) {
        let previous = self.impl_type.replace(impl_type_name(&n.self_ty));
        syn::visit::visit_item_impl(self, n);
        self.impl_type = previous;
    }
    fn visit_item_mod(&mut self, n: &'ast syn::ItemMod) {
        if n.content.is_none() {
            return;
        }
        self.module_path.push(n.ident.to_string());
        syn::visit::visit_item_mod(self, n);
        self.module_path.pop();
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: rust_ast <file.rs>");
        std::process::exit(2);
    });
    let module_path = args
        .next()
        .map(|value| {
            value
                .split("::")
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let crate_path = args
        .next()
        .map(|value| {
            value
                .split("::")
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("READ_ERROR: {e}");
        std::process::exit(2);
    });
    match syn::parse_file(&src) {
        Ok(file) => {
            let mut top = Top {
                funcs: vec![],
                impl_type: None,
                module_path,
                crate_path,
            };
            top.visit_file(&file);
            println!("{}", serde_json::to_string(&top.funcs).unwrap());
        }
        Err(e) => {
            eprintln!("PARSE_ERROR: {}", e);
            std::process::exit(2);
        }
    }
}
