//! Native tooling: extract WhatsApp Web's binary-protocol token dictionaries.
//!
//! WA's binary XMPP encoding replaces frequently-sent strings with compact token
//! tags. The tables live in one self-contained module (`WAWapDict`) that exports:
//!
//! ```js
//! i.DICT_VERSION = e;                 // var e = 3
//! i.SINGLE_BYTE_TOKEN = l;            // ["xmlstreamstart", "xmlstreamend", …]
//! i.DICTIONARY_0_TOKEN = s;           // …DICTIONARY_1/2/3_TOKEN = u/c/d
//! i.DICTIONARIES = m;                 // [s, u, c, d]
//! ```
//!
//! The minified locals (`l`, `s`, …) are unstable across builds, so we resolve
//! everything through the **export names**, which are semantic and stable.
//!
//! The emitted [`TokensIr`] is canonicalized to the wire-indexable form every
//! known consumer uses (whatsmeow `SingleByteTokens`, Baileys `SINGLE_BYTE_TOKENS`,
//! whatsapp-rust `tokens.json`): `single_byte[0]` is the reserved empty token (WA's
//! raw list starts at tag 1), so `single_byte[tag]` / `double_byte[dict][i]` are
//! direct lookups with no offset.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::HashMap;

use oxc_allocator::Allocator;
use oxc_ast::ast::{ArrayExpression, AssignmentExpression, Expression, VariableDeclarator};
use oxc_ast_visit::{Visit, walk};
use wa_ir::TokensIr;
use wa_oxc::{as_identifier, as_int, as_string_lit, parse_cjs};
use wa_transform::ModuleDefinition;

/// Stable export names the `WAWapDict` module assigns onto its module object.
const SINGLE_BYTE_EXPORT: &str = "SINGLE_BYTE_TOKEN";
const DICTIONARIES_EXPORT: &str = "DICTIONARIES";
const DICT_VERSION_EXPORT: &str = "DICT_VERSION";

/// Convenience: split a whole bundle into modules, then extract the token tables.
/// Mirrors `extract_enums`; the pipeline uses [`extract_tokens_from_modules`] to
/// share one split with the other extractors.
pub fn extract_tokens(source: &str, wa_version: &str) -> TokensIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_tokens_from_modules(source, &defs, wa_version)
}

/// Extract the token dictionaries from an already-split module index.
///
/// Returns an empty IR (no single-byte tokens) when the token module isn't found,
/// which the CLI's zero-guard turns into a hard error rather than overwriting the
/// committed artifact with an empty one.
pub fn extract_tokens_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> TokensIr {
    for m in module_defs {
        let slice = &source[m.start..m.end];
        if !is_token_module(slice) {
            continue;
        }
        if let Some(ir) = build(slice, wa_version) {
            return ir;
        }
    }
    TokensIr {
        wa_version: wa_version.to_string(),
        dict_version: 0,
        single_byte: Vec::new(),
        double_byte: Vec::new(),
    }
}

/// A module is worth parsing only if it exports the single-byte table and at least
/// one dictionary. Cheap substring pre-filter; the AST parse confirms the real
/// shape, so a stray substring only costs one extra parse, never a missed module.
fn is_token_module(slice: &str) -> bool {
    // Accept either the `DICTIONARIES` aggregate or the numbered `DICTIONARY_<n>_TOKEN`
    // exports — the extraction path handles both, so the pre-filter must let both
    // through rather than depend on the numbered markers being present.
    slice.contains(SINGLE_BYTE_EXPORT)
        && (slice.contains(DICTIONARIES_EXPORT) || slice.contains("DICTIONARY_"))
}

/// The initializer of a top-level `var` in the module factory, in the forms this
/// module uses: an array of string literals (a token table), an array of
/// identifiers (the `DICTIONARIES` aggregate), or an integer (`DICT_VERSION`).
enum LocalInit {
    StringArray(Vec<String>),
    IdentArray(Vec<String>),
    Int(i64),
}

/// One `object.NAME = localIdent` assignment captured from the module factory.
struct Export {
    /// The assigned-onto object identifier (the factory's exports param).
    object: String,
    /// The exported property name (e.g. `SINGLE_BYTE_TOKEN`).
    name: String,
    /// The local identifier it aliases.
    local: String,
}

#[derive(Default)]
struct Collector {
    /// `var name = <init>` → parsed initializer.
    locals: HashMap<String, LocalInit>,
    /// `object.NAME = localIdent` assignments, anywhere in the factory. The object
    /// is captured so resolution can scope to the one module-export object and
    /// ignore any unrelated `x.PROP = y` elsewhere in the tree.
    exports: Vec<Export>,
}

impl<'a> Visit<'a> for Collector {
    fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
        if let (Some(name), Some(init)) = (decl.id.get_identifier_name(), decl.init.as_ref())
            && let Some(li) = parse_init(init)
        {
            self.locals.insert(name.to_string(), li);
        }
        walk::walk_variable_declarator(self, decl);
    }

    fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
        // Only `<ident>.NAME = <ident>` — a member assignment whose object is a
        // plain identifier (the module-export param). Nested/computed targets
        // (`a.b.NAME`, `a[x]`) are never how WAWapDict exports its tables.
        if let Some(member) = a.left.as_member_expression()
            && let Some(object) = as_identifier(member.object())
            && let Some(prop) = member.static_property_name()
            && let Some(id) = as_identifier(&a.right)
        {
            self.exports.push(Export {
                object: object.to_string(),
                name: prop.to_string(),
                local: id.to_string(),
            });
        }
        walk::walk_assignment_expression(self, a);
    }
}

fn parse_init(e: &Expression) -> Option<LocalInit> {
    match e {
        Expression::ArrayExpression(arr) => parse_array(arr),
        other => as_int(other).map(LocalInit::Int),
    }
}

/// Parse an array literal as either an all-string-literal table or an
/// all-identifier aggregate. Empty or mixed arrays yield `None`.
fn parse_array(arr: &ArrayExpression) -> Option<LocalInit> {
    if arr.elements.is_empty() {
        return None;
    }
    // All string literals → a token table.
    let strings: Option<Vec<String>> = arr
        .elements
        .iter()
        .map(|el| {
            el.as_expression()
                .and_then(as_string_lit)
                .map(str::to_string)
        })
        .collect();
    if let Some(v) = strings {
        return Some(LocalInit::StringArray(v));
    }
    // Otherwise, all identifiers → the `[s, u, c, d]` aggregate.
    let idents: Option<Vec<String>> = arr
        .elements
        .iter()
        .map(|el| {
            el.as_expression()
                .and_then(as_identifier)
                .map(str::to_string)
        })
        .collect();
    idents.map(LocalInit::IdentArray)
}

fn build(slice: &str, wa_version: &str) -> Option<TokensIr> {
    let alloc = Allocator::default();
    let ret = parse_cjs(&alloc, slice);
    let mut c = Collector::default();
    c.visit_program(&ret.program);

    // Single-byte table (WA's tag-1-based list) → canonicalize with a leading empty
    // token so `single_byte[tag]` is a direct lookup.
    let raw_single = c.string_array(SINGLE_BYTE_EXPORT)?;
    if raw_single.is_empty() {
        return None;
    }
    let mut single_byte = Vec::with_capacity(raw_single.len() + 1);
    single_byte.push(String::new());
    single_byte.extend(raw_single.iter().cloned());

    // Double-byte dictionaries, in order. No offset — indices are already 0-based.
    let double_byte = c.dictionaries()?;
    if double_byte.is_empty() || double_byte.iter().any(Vec::is_empty) {
        return None;
    }

    let dict_version = c
        .export_local(DICT_VERSION_EXPORT)
        .and_then(|id| match c.locals.get(id) {
            Some(LocalInit::Int(n)) => u32::try_from(*n).ok(),
            _ => None,
        })
        .unwrap_or(0);

    Some(TokensIr {
        wa_version: wa_version.to_string(),
        dict_version,
        single_byte,
        double_byte,
    })
}

impl Collector {
    /// The module-export object: the identifier that carries `SINGLE_BYTE_TOKEN`
    /// (the factory's exports param). Every real WAWapDict export lives on it, so
    /// scoping resolution to it ignores any unrelated `x.PROP = y` assignment
    /// elsewhere in the tree.
    ///
    /// Among objects that carry a `SINGLE_BYTE_TOKEN` export, pick the one with the
    /// most exports overall — the real module object holds the whole set, so a stray
    /// one-off `x.SINGLE_BYTE_TOKEN = …` can't win regardless of document order.
    fn export_object(&self) -> Option<&str> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for e in &self.exports {
            *counts.entry(e.object.as_str()).or_default() += 1;
        }
        self.exports
            .iter()
            .filter(|e| e.name == SINGLE_BYTE_EXPORT)
            .map(|e| e.object.as_str())
            .max_by_key(|obj| counts[obj])
    }

    /// The local identifier an export name aliases, scoped to the module-export
    /// object so a colliding property name on some other object can't shadow it.
    fn export_local(&self, name: &str) -> Option<&str> {
        let object = self.export_object()?;
        self.exports
            .iter()
            .find(|e| e.object == object && e.name == name)
            .map(|e| e.local.as_str())
    }

    /// The string-array table an export name resolves to.
    fn string_array(&self, export: &str) -> Option<&Vec<String>> {
        match self.locals.get(self.export_local(export)?) {
            Some(LocalInit::StringArray(v)) => Some(v),
            _ => None,
        }
    }

    /// The ordered double-byte dictionaries. Prefer the `DICTIONARIES` aggregate
    /// (`[s, u, c, d]`) for order and count; fall back to the numbered
    /// `DICTIONARY_<n>_TOKEN` exports sorted by `n` if the aggregate is absent.
    fn dictionaries(&self) -> Option<Vec<Vec<String>>> {
        if let Some(agg) = self.export_local(DICTIONARIES_EXPORT)
            && let Some(LocalInit::IdentArray(idents)) = self.locals.get(agg)
        {
            let dicts: Option<Vec<Vec<String>>> = idents
                .iter()
                .map(|id| match self.locals.get(id) {
                    Some(LocalInit::StringArray(v)) => Some(v.clone()),
                    _ => None,
                })
                .collect();
            if let Some(dicts) = dicts
                && !dicts.is_empty()
            {
                return Some(dicts);
            }
        }

        // Fallback: numbered `DICTIONARY_<n>_TOKEN` exports (scoped to the export
        // object), ordered by `n`.
        let object = self.export_object()?;
        let mut numbered: Vec<(u32, &str)> = self
            .exports
            .iter()
            .filter(|e| e.object == object)
            .filter_map(|e| {
                let n = e.name.strip_prefix("DICTIONARY_")?.strip_suffix("_TOKEN")?;
                Some((n.parse::<u32>().ok()?, e.local.as_str()))
            })
            .collect();
        numbered.sort_by_key(|(n, _)| *n);

        // The dictionary index IS the wire selector (tag `DICTIONARY_0` + n).
        // Compacting a gapped or duplicated set would silently misalign
        // `double_byte[dict]`, so require a contiguous `0..N` run and bail (→ empty
        // IR → the CLI's zero-guard) on any gap rather than emit a wrong mapping.
        if numbered
            .iter()
            .enumerate()
            .any(|(k, (n, _))| *n != k as u32)
        {
            return None;
        }

        let dicts: Option<Vec<Vec<String>>> = numbered
            .iter()
            .map(|(_, local)| match self.locals.get(*local) {
                Some(LocalInit::StringArray(v)) => Some(v.clone()),
                _ => None,
            })
            .collect();
        dicts.filter(|d| !d.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(src: &str) -> TokensIr {
        let defs = wa_transform::extract_module_definitions(src);
        extract_tokens_from_modules(src, &defs, "1.0")
    }

    #[test]
    fn extracts_and_canonicalizes_single_byte() {
        let src = r#"__d("WAWapDict",[],(function(t,n,r,o,a,i){"use strict";
            var e=3,l=["xmlstreamstart","xmlstreamend","s.whatsapp.net"],
                s=["read-self","active"],u=["reject"],c=["64"],d=["1724"],m=[s,u,c,d];
            i.DICT_VERSION=e,i.SINGLE_BYTE_TOKEN=l,i.DICTIONARY_0_TOKEN=s,i.DICTIONARY_1_TOKEN=u,
            i.DICTIONARY_2_TOKEN=c,i.DICTIONARY_3_TOKEN=d,i.DICTIONARIES=m}),66);"#;
        let ir = run(src);
        assert_eq!(ir.dict_version, 3);
        // Leading empty token prepended → `single_byte[tag]` is a direct lookup.
        assert_eq!(ir.single_byte[0], "");
        assert_eq!(ir.single_byte[1], "xmlstreamstart");
        assert_eq!(ir.single_byte.len(), 4, "3 raw tokens + the empty token");
        // Four dictionaries, in DICTIONARIES order, no prepend.
        assert_eq!(ir.double_byte.len(), 4);
        assert_eq!(ir.double_byte[0], vec!["read-self", "active"]);
        assert_eq!(ir.double_byte[3], vec!["1724"]);
    }

    #[test]
    fn falls_back_to_numbered_dictionaries_out_of_order() {
        // No DICTIONARIES aggregate; numbered exports (declared out of order) must
        // still resolve to dict 0..3 in numeric order.
        let src = r#"__d("WAWapDict",[],(function(t,n,r,o,a,i){
            var l=["only"],s=["d0"],u=["d1"],c=["d2"],d=["d3"];
            i.SINGLE_BYTE_TOKEN=l,i.DICTIONARY_2_TOKEN=c,i.DICTIONARY_0_TOKEN=s,
            i.DICTIONARY_3_TOKEN=d,i.DICTIONARY_1_TOKEN=u}),1);"#;
        let ir = run(src);
        assert_eq!(ir.double_byte.len(), 4);
        assert_eq!(ir.double_byte[0], vec!["d0"]);
        assert_eq!(ir.double_byte[1], vec!["d1"]);
        assert_eq!(ir.double_byte[2], vec!["d2"]);
        assert_eq!(ir.double_byte[3], vec!["d3"]);
    }

    #[test]
    fn aggregate_only_module_is_found_and_resolved() {
        // No numbered `DICTIONARY_<n>_TOKEN` exports at all — only the DICTIONARIES
        // aggregate. The pre-filter must still admit the module and the aggregate
        // path must resolve it.
        let src = r#"__d("WAWapDict",[],(function(t,n,r,o,a,i){
            var l=["x"],s=["d0"],u=["d1"],m=[s,u];
            i.SINGLE_BYTE_TOKEN=l,i.DICTIONARIES=m}),1);"#;
        let ir = run(src);
        assert_eq!(ir.single_byte, vec!["", "x"]);
        assert_eq!(ir.double_byte, vec![vec!["d0"], vec!["d1"]]);
    }

    #[test]
    fn gapped_numbered_fallback_bails_rather_than_misalign() {
        // Numbered fallback with a missing dict 1 (0, 2, 3) and no aggregate: silently
        // compacting to [d0, d2, d3] would map wire-dict 2 to index 1. Must bail to an
        // empty IR instead (the CLI's zero-guard turns that into a hard error).
        let src = r#"__d("WAWapDict",[],(function(t,n,r,o,a,i){
            var l=["x"],s=["d0"],c=["d2"],d=["d3"];
            i.SINGLE_BYTE_TOKEN=l,i.DICTIONARY_0_TOKEN=s,
            i.DICTIONARY_2_TOKEN=c,i.DICTIONARY_3_TOKEN=d}),1);"#;
        let ir = run(src);
        assert!(
            ir.double_byte.is_empty(),
            "gapped dict set must not compact"
        );
        assert!(ir.single_byte.is_empty(), "bail leaves the whole IR empty");
    }

    #[test]
    fn export_on_unrelated_object_is_ignored() {
        // A stray `x.SINGLE_BYTE_TOKEN = <bogus>` on a different object must not
        // shadow the real exports on the module param `i`.
        let src = r#"__d("WAWapDict",[],(function(t,n,r,o,a,i){
            var l=["real"],s=["d0"],u=["d1"],m=[s,u],bogus=["WRONG"];
            x.SINGLE_BYTE_TOKEN=bogus,
            i.SINGLE_BYTE_TOKEN=l,i.DICTIONARIES=m}),1);"#;
        let ir = run(src);
        // The real `i`-scoped single-byte table wins regardless of the stray export.
        assert_eq!(ir.single_byte, vec!["", "real"]);
        assert_eq!(ir.double_byte, vec![vec!["d0"], vec!["d1"]]);
    }

    #[test]
    fn missing_module_yields_empty_ir() {
        let src = r#"__d("Nope",[],(function(t,n,r,o,a,i){i.x=1}),1);"#;
        let ir = run(src);
        assert!(ir.single_byte.is_empty());
        assert!(ir.double_byte.is_empty());
    }
}
