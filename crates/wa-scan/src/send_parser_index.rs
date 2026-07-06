//! Cross-module index of legacy responses attached at the *send* site.
//!
//! A few legacy jobs build an `<iq>` and hand a sibling module's parser to
//! `deprecatedSendIq(iq, o("Mod").parser)` instead of constructing a
//! `WADeprecatedWapParser` inline. The per-module scanner only sees inline parsers,
//! so those responses would be lost (the request is captured with `parserName:
//! "unknown"`). This pass finds each send site whose parser reference is an external
//! `o("Mod").parser`, resolves the target module's single legacy parser to its typed
//! [`ParsedResponse`], and keys it by the *sending* module so the scanner can attach
//! it.
//!
//! Only the same-module case (the send site lives in the module that built the
//! `<iq>`) is resolved here — e.g. `WAWebQueryMediaConnsJob` sends its own `<iq>`
//! with `o("WAMediaConnParser").mediaConnParser`. A send site in a *different* module
//! from the one that built the `<iq>` (the iq expression is threaded across a module
//! boundary) is left for the scanner's `unknown` fallback.

use std::collections::{BTreeMap, HashMap};

use oxc_allocator::Allocator;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::{Visit, walk};
use wa_ir::ParsedResponse;
use wa_oxc::{arg_expr, as_call, as_identifier, as_member, callee_method, first_string_arg};
use wa_transform::ModuleDefinition;

use crate::response::parse_module_wap_parsers;

/// The name `deprecatedSendIq` is called under: the common member form
/// `o("WADeprecatedSendIq").deprecatedSendIq(...)`, or a bare identifier
/// `deprecatedSendIq(...)` when the export was hoisted into a local.
const SEND_IQ: &str = "deprecatedSendIq";

/// Sending module name → the typed response resolved from its `deprecatedSendIq`
/// parser reference. A `BTreeMap` keeps the build deterministic.
pub(crate) fn build_pass(
    defs: &[ModuleDefinition],
    source: &str,
) -> BTreeMap<String, ParsedResponse> {
    // module name → its source slice, for resolving a referenced target module.
    let slices: HashMap<&str, &str> = defs
        .iter()
        .map(|m| (m.name.as_str(), &source[m.start..m.end]))
        .collect();

    let mut out = BTreeMap::new();
    let mut seen = std::collections::HashSet::new();
    for m in defs {
        // Same module can appear in several bundle shards; resolve each name once.
        if !seen.insert(m.name.as_str()) {
            continue;
        }
        let slice = &source[m.start..m.end];
        // Cheap pre-filter: only re-parse modules that actually send an iq.
        if !slice.contains(SEND_IQ) {
            continue;
        }
        let Some(target) = find_send_parser_ref(slice) else {
            continue;
        };
        let Some(target_slice) = slices.get(target.as_str()) else {
            continue;
        };
        // Resolve the target's legacy parser, but only when it is unambiguous — a
        // module with two parsers can't be keyed by an export name we don't track,
        // so we leave it to the `unknown` fallback rather than guess.
        if let [only] = parse_module_wap_parsers(target_slice).as_slice() {
            out.insert(m.name.clone(), only.clone());
        }
    }
    out
}

/// The target module name in the first `deprecatedSendIq(iq, o("Mod").parser)` call
/// in `slice` whose parser argument is an external `o("Mod").member` reference.
fn find_send_parser_ref(slice: &str) -> Option<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, slice);
    if ret.panicked {
        return None;
    }
    let mut finder = SendFinder { target: None };
    finder.visit_program(&ret.program);
    finder.target
}

struct SendFinder {
    target: Option<String>,
}

impl<'a> Visit<'a> for SendFinder {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // Match both `o("…").deprecatedSendIq(…)` (member) and a bare
        // `deprecatedSendIq(…)` (identifier) callee.
        let is_send =
            callee_method(call) == Some(SEND_IQ) || as_identifier(&call.callee) == Some(SEND_IQ);
        if self.target.is_none()
            && is_send
            && let Some(arg1) = call.arguments.get(1).and_then(arg_expr)
            // The parser reference is a static member `o("Mod").parser`.
            && let Some((obj, _parser)) = as_member(arg1)
            // …whose object is a `require("Mod")` call.
            && let Some(require_call) = as_call(obj)
            && let Some(module) = first_string_arg(require_call)
        {
            self.target = Some(module.to_string());
        }
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(bundle: &str) -> BTreeMap<String, ParsedResponse> {
        let defs = wa_transform::extract_module_definitions(bundle);
        build_pass(&defs, bundle)
    }

    #[test]
    fn resolves_same_module_send_site_parser() {
        // `WAWebQueryMediaConnsJob` builds an `<iq>` and sends it with a sibling
        // module's parser; the response must be recovered from `WAMediaConnParser`.
        let bundle = r#"
            __d("WAWebQueryMediaConnsJob",["WADeprecatedSendIq","WAMediaConnParser"],(function(t,n,r,o,a,i,l){
                l.query=function(){
                    var m=o("WAWap").wap("iq",{xmlns:"w:m",type:"set"});
                    return o("WADeprecatedSendIq").deprecatedSendIq(m,o("WAMediaConnParser").mediaConnParser);
                };
            }),1);
            __d("WAMediaConnParser",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                l.mediaConnParser=new(r("WADeprecatedWapParser"))("mediaConnParser",function(e){
                    e.assertTag("iq");
                    return { auth: e.child("media_conn").attrString("auth") };
                });
            }),1);
        "#;
        let idx = index(bundle);
        let resp = idx
            .get("WAWebQueryMediaConnsJob")
            .expect("send-site parser resolved");
        assert_eq!(resp.parser_name, "mediaConnParser");
        // The `<media_conn>` child is recovered (its `auth` attr nests inside it).
        assert!(resp.fields.iter().any(|f| f.name == "media_conn"));
    }

    #[test]
    fn resolves_bare_identifier_send_site() {
        // `deprecatedSendIq` imported as a bare local of the same name and called
        // directly, not via `o("…").deprecatedSendIq(…)`.
        let bundle = r#"
            __d("Job",["WADeprecatedSendIq","P"],(function(t,n,r,o,a,i,l){
                var deprecatedSendIq=o("WADeprecatedSendIq").deprecatedSendIq;
                l.query=function(){ var m=o("WAWap").wap("iq",{}); return deprecatedSendIq(m,o("P").theParser); };
            }),1);
            __d("P",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                l.theParser=new(r("WADeprecatedWapParser"))("theParser",function(e){ return { id: e.attrString("id") }; });
            }),1);
        "#;
        let idx = index(bundle);
        assert_eq!(
            idx.get("Job").map(|r| r.parser_name.as_str()),
            Some("theParser"),
        );
    }

    #[test]
    fn send_site_without_module_ref_parser_is_ignored() {
        // A `deprecatedSendIq` whose parser argument is not an `o("Mod").parser`
        // reference (here: absent) yields no entry.
        let bundle = r#"__d("J",["WADeprecatedSendIq"],(function(t,n,r,o,a,i,l){
            l.q=function(){ var m=o("WAWap").wap("iq",{}); return o("WADeprecatedSendIq").deprecatedSendIq(m); };
        }),1);"#;
        assert!(!index(bundle).contains_key("J"));
    }

    #[test]
    fn ambiguous_target_module_is_not_guessed() {
        // The target module defines two parsers; without an export→parser mapping the
        // reference can't be resolved unambiguously, so nothing is attached.
        let bundle = r#"
            __d("J",["WADeprecatedSendIq","Two"],(function(t,n,r,o,a,i,l){
                l.q=function(){ var m=o("WAWap").wap("iq",{}); return o("WADeprecatedSendIq").deprecatedSendIq(m,o("Two").a); };
            }),1);
            __d("Two",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
                l.a=new(r("WADeprecatedWapParser"))("pa",function(e){ return { x: e.attrString("x") }; });
                l.b=new(r("WADeprecatedWapParser"))("pb",function(e){ return { y: e.attrString("y") }; });
            }),1);
        "#;
        assert!(!index(bundle).contains_key("J"));
    }
}
