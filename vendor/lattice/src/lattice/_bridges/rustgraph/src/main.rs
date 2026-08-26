// Rust -> JSON structural bridge (syn). One file per invocation:
//   rustgraph <file.rs>
// Emits symbols (functions, impl methods with their self type as container,
// structs/enums as classes, traits as interfaces with supertrait extends),
// trait-impl records, mod/use import specs, and call sites. Line numbers come
// from proc-macro2 span-locations.
use serde::Serialize;
use syn::spanned::Spanned;
use syn::visit::Visit;

#[derive(Serialize)]
struct GSym {
    name: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    container: Option<String>,
    start: usize,
    end: usize,
    exported: bool,
    stub: bool,
    params: Vec<String>,
    extends: Vec<String>,
    implements: Vec<String>,
}
#[derive(Serialize)]
struct GImp {
    path: String,
    line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
}
#[derive(Serialize)]
struct GCall {
    from_line: usize,
    name: String,
    path: String,
}
#[derive(Serialize)]
struct GTraitImpl {
    type_name: String,
    trait_name: String,
}
#[derive(Serialize)]
struct GFile {
    has_main: bool,
    imports: Vec<GImp>,
    symbols: Vec<GSym>,
    calls: Vec<GCall>,
    impls: Vec<GTraitImpl>,
}

fn is_pub(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

fn stub_macro(path: &syn::Path) -> bool {
    path.segments
        .last()
        .map(|s| s.ident == "todo" || s.ident == "unimplemented")
        .unwrap_or(false)
}

// A stub body: empty, or a lone todo!() / unimplemented!() statement or tail expr.
fn is_stub_block(block: &syn::Block) -> bool {
    if block.stmts.is_empty() {
        return true;
    }
    if block.stmts.len() != 1 {
        return false;
    }
    match &block.stmts[0] {
        syn::Stmt::Macro(m) => stub_macro(&m.mac.path),
        syn::Stmt::Expr(syn::Expr::Macro(m), _) => stub_macro(&m.mac.path),
        _ => false,
    }
}

fn param_names(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|a| match a {
            syn::FnArg::Typed(pt) => match pt.pat.as_ref() {
                syn::Pat::Ident(pi) => Some(pi.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn type_last_segment(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(tp) => tp.path.segments.last().map(|s| s.ident.to_string()),
        syn::Type::Reference(r) => type_last_segment(&r.elem),
        _ => None,
    }
}

fn namespace_name(namespace: &[String]) -> Option<String> {
    if namespace.is_empty() {
        None
    } else {
        Some(namespace.join("."))
    }
}

fn qualified_name(namespace: &[String], name: &str) -> String {
    match namespace_name(namespace) {
        Some(prefix) => format!("{prefix}.{name}"),
        None => name.to_owned(),
    }
}

struct CallVisitor<'a> {
    calls: &'a mut Vec<GCall>,
}
impl<'ast> Visit<'ast> for CallVisitor<'_> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = node.func.as_ref() {
            if let Some(seg) = p.path.segments.last() {
                self.calls.push(GCall {
                    from_line: node.span().start().line,
                    name: seg.ident.to_string(),
                    path: p
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                });
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.calls.push(GCall {
            from_line: node.span().start().line,
            name: node.method.to_string(),
            path: match node.receiver.as_ref() {
                syn::Expr::Path(p) => format!(
                    "{}.{}",
                    p.path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                    node.method
                ),
                _ => node.method.to_string(),
            },
        });
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn flatten_use(
    tree: &syn::UseTree,
    prefix: &str,
    line: usize,
    namespace: &[String],
    out: &mut Vec<GImp>,
) {
    match tree {
        syn::UseTree::Path(p) => {
            let next = if prefix.is_empty() {
                p.ident.to_string()
            } else {
                format!("{prefix}::{}", p.ident)
            };
            flatten_use(&p.tree, &next, line, namespace, out);
        }
        syn::UseTree::Name(n) => out.push(GImp {
            path: format!("use:{prefix}::{}", n.ident),
            line,
            scope: namespace_name(namespace),
            binding: Some(n.ident.to_string()),
        }),
        syn::UseTree::Rename(r) => out.push(GImp {
            path: format!("use:{prefix}::{}", r.ident),
            line,
            scope: namespace_name(namespace),
            binding: Some(r.rename.to_string()),
        }),
        syn::UseTree::Glob(_) => out.push(GImp {
            path: format!("use:{prefix}"),
            line,
            scope: namespace_name(namespace),
            binding: None,
        }),
        syn::UseTree::Group(g) => {
            for t in &g.items {
                flatten_use(t, prefix, line, namespace, out);
            }
        }
    }
}

fn walk_items(items: &[syn::Item], out: &mut GFile, namespace: &[String]) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                let span = f.span();
                if namespace.is_empty() && f.sig.ident == "main" {
                    out.has_main = true;
                }
                let mut calls = Vec::new();
                CallVisitor { calls: &mut calls }.visit_block(&f.block);
                out.calls.append(&mut calls);
                out.symbols.push(GSym {
                    name: f.sig.ident.to_string(),
                    kind: "function".into(),
                    container: namespace_name(namespace),
                    start: span.start().line,
                    end: span.end().line,
                    exported: is_pub(&f.vis),
                    stub: is_stub_block(&f.block),
                    params: param_names(&f.sig),
                    extends: vec![],
                    implements: vec![],
                });
            }
            syn::Item::Struct(s) => out.symbols.push(GSym {
                name: s.ident.to_string(),
                kind: "class".into(),
                container: namespace_name(namespace),
                start: s.span().start().line,
                end: s.span().end().line,
                exported: is_pub(&s.vis),
                stub: false,
                params: vec![],
                extends: vec![],
                implements: vec![],
            }),
            syn::Item::Enum(e) => out.symbols.push(GSym {
                name: e.ident.to_string(),
                kind: "class".into(),
                container: namespace_name(namespace),
                start: e.span().start().line,
                end: e.span().end().line,
                exported: is_pub(&e.vis),
                stub: false,
                params: vec![],
                extends: vec![],
                implements: vec![],
            }),
            syn::Item::Trait(t) => {
                let extends = t
                    .supertraits
                    .iter()
                    .filter_map(|b| match b {
                        syn::TypeParamBound::Trait(tb) => {
                            tb.path.segments.last().map(|s| s.ident.to_string())
                        }
                        _ => None,
                    })
                    .collect();
                out.symbols.push(GSym {
                    name: t.ident.to_string(),
                    kind: "interface".into(),
                    container: namespace_name(namespace),
                    start: t.span().start().line,
                    end: t.span().end().line,
                    exported: is_pub(&t.vis),
                    stub: false,
                    params: vec![],
                    extends,
                    implements: vec![],
                });
            }
            syn::Item::Impl(im) => {
                let self_name = type_last_segment(&im.self_ty);
                let self_container = self_name
                    .as_ref()
                    .map(|name| qualified_name(namespace, name));
                if let (Some(tn), Some((_, tp, _))) = (&self_container, &im.trait_) {
                    if let Some(seg) = tp.segments.last() {
                        out.impls.push(GTraitImpl {
                            type_name: tn.clone(),
                            trait_name: seg.ident.to_string(),
                        });
                    }
                }
                for it in &im.items {
                    if let syn::ImplItem::Fn(m) = it {
                        let span = m.span();
                        let mut calls = Vec::new();
                        CallVisitor { calls: &mut calls }.visit_block(&m.block);
                        out.calls.append(&mut calls);
                        out.symbols.push(GSym {
                            name: m.sig.ident.to_string(),
                            kind: "method".into(),
                            container: self_container.clone(),
                            start: span.start().line,
                            end: span.end().line,
                            exported: is_pub(&m.vis),
                            stub: is_stub_block(&m.block),
                            params: param_names(&m.sig),
                            extends: vec![],
                            implements: vec![],
                        });
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    let mut child_namespace = namespace.to_vec();
                    child_namespace.push(m.ident.to_string());
                    walk_items(items, out, &child_namespace); // inline module: recurse
                } else {
                    out.imports.push(GImp {
                        path: format!("mod:{}", m.ident),
                        line: m.span().start().line,
                        scope: namespace_name(namespace),
                        binding: Some(m.ident.to_string()),
                    });
                }
            }
            syn::Item::Use(u) => flatten_use(
                &u.tree,
                "",
                u.span().start().line,
                namespace,
                &mut out.imports,
            ),
            _ => {}
        }
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: rustgraph <file.rs>");
    let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        eprintln!("READ_ERROR: {e}");
        std::process::exit(2);
    });
    let ast = syn::parse_file(&src).unwrap_or_else(|e| {
        eprintln!("PARSE_ERROR: {e}");
        std::process::exit(2);
    });
    let mut out = GFile {
        has_main: false,
        imports: vec![],
        symbols: vec![],
        calls: vec![],
        impls: vec![],
    };
    walk_items(&ast.items, &mut out, &[]);
    println!("{}", serde_json::to_string(&out).expect("serialize"));
}
