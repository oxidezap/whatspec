//! Capture a locked retry syntax inventory. This is not an executable policy IR.
use anyhow::{Context, Result, ensure};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Function, IfStatement, ReturnStatement, ThrowStatement, YieldExpression};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType, Span};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

const MODULES: [&str; 4] = [
    "WAWebHandleRetryRequest",
    "WAWebUpdateLocalSignalSession",
    "WAWebSendRetryReceiptJob",
    "WAWebProcessRetryKeyBundle",
];

struct Inventory<'s> {
    source: &'s str,
    nodes: Vec<Value>,
    functions: Vec<Value>,
    guards: Vec<Span>,
}
impl Inventory<'_> {
    fn node(&mut self, kind: &str, span: Span) {
        self.nodes.push(json!({"kind":kind,"start":span.start,"end":span.end,
            "source":&self.source[span.start as usize..span.end as usize],
            "enclosingIfTests":self.guards.iter().map(|s| json!({"start":s.start,"end":s.end})).collect::<Vec<_>>()}));
    }
}
impl<'a> Visit<'a> for Inventory<'_> {
    fn visit_function(&mut self, it: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        // Nested callbacks execute in a different continuation, never inherit guards.
        let old = std::mem::take(&mut self.guards);
        if it.generator {
            self.functions.push(json!({"start":it.span.start,"end":it.span.end,"source":&self.source[it.span.start as usize..it.span.end as usize]}));
        }
        walk::walk_function(self, it, flags);
        self.guards = old;
    }
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.node("if", it.test.span());
        self.guards.push(it.test.span());
        walk::walk_if_statement(self, it);
        self.guards.pop();
    }
    fn visit_yield_expression(&mut self, it: &YieldExpression<'a>) {
        self.node("suspend", it.span);
        walk::walk_yield_expression(self, it);
    }
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.node("return", it.span);
        walk::walk_return_statement(self, it);
    }
    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.node("throw", it.span);
        walk::walk_throw_statement(self, it);
    }
}
fn inventory(source: &str) -> Result<Value> {
    let a = Allocator::default();
    let parsed = Parser::new(&a, source, SourceType::cjs()).parse();
    ensure!(
        !parsed.panicked && parsed.errors.is_empty(),
        "module parse failed"
    );
    let mut v = Inventory {
        source,
        nodes: vec![],
        functions: vec![],
        guards: vec![],
    };
    v.visit_program(&parsed.program);
    Ok(json!({"nodes":v.nodes,"generators":v.functions}))
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: retry_audit LOCK BUNDLES OUTPUT");
    let lock: wa_store::lock::BundleLock = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    lock.verify_self_consistent().map_err(anyhow::Error::msg)?;
    let mut files = std::fs::read_dir(&args[1])?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    files.retain(|p| p.extension().is_some_and(|e| e == "js"));
    files.sort();
    let mut actual = BTreeMap::new();
    let mut expected = BTreeMap::new();
    for b in &lock.bundles {
        *expected.entry((b.sha256.clone(), b.size)).or_insert(0usize) += 1;
    }
    let mut modules: BTreeMap<String, (String, Vec<Value>)> = BTreeMap::new();
    for file in files {
        let source = std::fs::read_to_string(&file)?;
        let hash = wa_text::sha256_hex(source.as_bytes());
        *actual
            .entry((hash.clone(), source.len() as u64))
            .or_insert(0usize) += 1;
        let definitions = wa_transform::extract_module_definitions_checked(&source)
            .map_err(|e| anyhow::anyhow!("{}: {e:?}", file.display()))?;
        for m in definitions
            .into_iter()
            .filter(|m| MODULES.contains(&m.name.as_str()))
        {
            let body = source[m.start..m.end].to_owned();
            let entry = modules
                .entry(m.name.clone())
                .or_insert_with(|| (body.clone(), vec![]));
            ensure!(entry.0 == body, "divergent duplicate {}", m.name);
            entry
                .1
                .push(json!({"bundleSha256":hash,"start":m.start,"end":m.end}));
        }
    }
    ensure!(actual == expected, "bundle multiset differs from lock");
    ensure!(modules.len() == MODULES.len(), "missing retry modules");
    let mut records = vec![];
    for (name, (source, mut definitions)) in modules {
        definitions.sort_by_key(Value::to_string);
        records.push(json!({"module":name,"sourceSha256":wa_text::sha256_hex(source.as_bytes()),"definitions":definitions,"inventory":inventory(&source)?,"source":source}));
    }
    let output = json!({"formatVersion":1,"waVersion":lock.wa_version,"setHash":lock.set_hash,"bundleCount":lock.bundle_count,
        "completeness":{"syntax":"complete-for-selected-node-kinds","policy":"partial-not-executable","continuations":"generator-yield-sites-only","excluded":["callee behavior","runtime flags","logical and conditional expression control flow","exception and cancellation semantics","queue scheduling","crypto","storage","transport"]},"modules":records});
    let out = Path::new(&args[2]);
    ensure!(!out.exists(), "output already exists");
    std::fs::create_dir_all(out)?;
    std::fs::write(
        out.join("audit.json"),
        serde_json::to_string_pretty(&output)? + "\n",
    )
    .context("write audit")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_policy_fails_closed() {
        assert!(inventory("function* f(){yield a; ").is_err());
    }
    #[test]
    fn detects_changed_order_and_guards() {
        let a = inventory("function* f(){if(x) yield a();yield b();return c;}").unwrap();
        let b = inventory("function* f(){yield b();if(x) yield a();return c;}").unwrap();
        assert_ne!(a, b);
        assert_eq!(a["nodes"][1]["kind"], "suspend");
        assert_eq!(
            a["nodes"][1]["enclosingIfTests"].as_array().unwrap().len(),
            1
        );
    }
}
