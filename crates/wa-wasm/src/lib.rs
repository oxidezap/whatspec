//! Native tooling: extract WhatsApp Web's **WebAssembly surface** from the JS bundles.
//!
//! Two independent, fully static facts live here — together they say *which* wasm the
//! client runs and *how* it asks the server for the bytes:
//!
//! 1. **Emscripten binaries.** A compiled module ships its JS glue inline, and that glue
//!    names its payload in a string literal: `wasmBinaryFile="crypto_utils_v2.wasm"`.
//!    The name is the build-time identity of the binary (`liboqs_wasm_wrapper.wasm`,
//!    `dgwcppbridge.wasm`, …) — stable across rollouts, unlike the content-hashed URL.
//!    The *variable* it lands in is usually minified away (`var ae="dgwcppbridge.wasm"`),
//!    so the literal itself — not the assignment target — is what identifies it.
//! 2. **Bootloader resource handles.** The *URL* is never in the JS: the glue calls
//!    `r("bx").getURL(r("bx")("33861"))`, resolving a numeric `bx` id against the
//!    `bxData` map the server ships in the page (or via the bootloader endpoint). The
//!    ids, and the modules that consume them, are static; only the id→URI mapping is
//!    server-side.
//!
//! So this crate emits the **handles**, not the bytes: `wa-fetch` resolves the ids to
//! URIs at fetch time and the wasm lockfile records what they resolved to. A `bx` id
//! addresses *any* bootloader resource (most are images), so each one carries the
//! evidence that made it look wasm-related — see [`WasmResourceRef::wasm_hint`] — rather
//! than a guess the JS can't actually support.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{CallExpression, Expression, StringLiteral};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{WasmBinary, WasmIr, WasmResourceRef};
use wa_oxc::{first_string_arg, parse_cjs};
use wa_transform::ModuleDefinition;

/// The bootloader-resource module every `bx` handle is resolved through.
const BX_MODULE: &str = "bx";
/// Suffix of a payload name in the glue.
const BINARY_SUFFIX: &str = ".wasm";
/// Emscripten inlines small payloads as a base64 data URI in the *same* variable the
/// file name would occupy; those aren't fetchable resources, so they're excluded.
const DATA_URI_PREFIX: &str = "data:";
/// The runtime module wasm-loading WA modules depend on — one of the signals that a
/// `bx` handle in that module addresses a wasm payload.
const WASM_CACHE_DEP: &str = "WAWasmModuleCache";

/// Convenience: split a bundle and extract the wasm surface.
pub fn extract_wasm(source: &str, wa_version: &str) -> WasmIr {
    let defs = wa_transform::extract_module_definitions(source);
    extract_wasm_from_modules(source, &defs, wa_version)
}

/// Extract the wasm surface from an already-split module index.
///
/// Only modules that *mention* the two markers are parsed (a substring pre-filter over
/// the slice), so the AST cost is paid for a handful of modules out of tens of thousands.
pub fn extract_wasm_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> WasmIr {
    // binary file name → modules whose glue declares it.
    let mut binaries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // bx id → consuming modules.
    let mut refs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // bx id → the modules that gave it a wasm signal, and which signal.
    let mut hints: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();

    for m in module_defs {
        let slice = &source[m.start..m.end];
        let may_declare_binary = slice.contains(BINARY_SUFFIX);
        // A `bx` handle is `r("bx")("<id>")`, so the literal is always present; the dep
        // list is checked too because a build could inline the require differently.
        let may_use_bx = slice.contains("\"bx\"") || m.deps.iter().any(|d| d == BX_MODULE);
        if !(may_declare_binary || may_use_bx) {
            continue;
        }

        let allocator = Allocator::default();
        let ret = parse_cjs(&allocator, slice);
        let mut visitor = WasmVisitor::default();
        visitor.visit_program(&ret.program);

        for name in &visitor.binary_files {
            binaries
                .entry(name.clone())
                .or_default()
                .insert(m.name.clone());
        }
        // A module that declares an emscripten payload, is named `…Wasm…`, or depends on
        // the wasm module cache is asking `bx` for wasm bytes — record which of those it
        // was, so a consumer can judge the evidence instead of trusting a bare boolean.
        let module_hints: Vec<&'static str> = [
            (!visitor.binary_files.is_empty()).then_some("wasmBinaryLiteral"),
            m.name.contains("Wasm").then_some("moduleName"),
            m.deps
                .iter()
                .any(|d| d == WASM_CACHE_DEP)
                .then_some("wasmModuleCacheDep"),
        ]
        .into_iter()
        .flatten()
        .collect();
        for id in &visitor.bx_ids {
            refs.entry(id.clone()).or_default().insert(m.name.clone());
            if !module_hints.is_empty() {
                hints
                    .entry(id.clone())
                    .or_default()
                    .extend(module_hints.iter().copied());
            }
        }
    }

    WasmIr {
        wa_version: wa_version.to_string(),
        binaries: binaries
            .into_iter()
            .map(|(name, modules)| WasmBinary {
                name,
                modules: modules.into_iter().collect(),
            })
            .collect(),
        resources: refs
            .into_iter()
            .map(|(bx_id, consumers)| WasmResourceRef {
                wasm_hint: hints
                    .get(&bx_id)
                    .map(|h| h.iter().map(|s| (*s).to_string()).collect())
                    .unwrap_or_default(),
                bx_id,
                consumers: consumers.into_iter().collect(),
            })
            .collect(),
    }
}

/// Collects the two markers from one module's AST.
#[derive(Default)]
struct WasmVisitor {
    binary_files: Vec<String>,
    bx_ids: Vec<String>,
}

impl<'a> Visit<'a> for WasmVisitor {
    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        // Any `*.wasm` literal in the module: the glue's payload name, whatever
        // (minified) variable it is assigned to. Base64 data URIs are inlined payloads,
        // not fetchable resources.
        let value = lit.value.as_str();
        if value.ends_with(BINARY_SUFFIX) && !value.starts_with(DATA_URI_PREFIX) {
            self.binary_files.push(value.to_string());
        }
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        // `r("bx")("33861")` — the require alias is a minifier-chosen identifier, so the
        // shape (a call whose *callee* requires `bx`) is what identifies it, not the name.
        if let Expression::CallExpression(callee) = &call.callee
            && first_string_arg(callee) == Some(BX_MODULE)
            && let Some(id) = first_string_arg(call)
            && !id.is_empty()
            && id.bytes().all(|b| b.is_ascii_digit())
        {
            self.bx_ids.push(id.to_string());
        }
        // `getURL(r("bx")("…"))` nests the handle inside another call, so keep walking.
        walk::walk_call_expression(self, call);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap module bodies in the Metro `__d` shape the splitter expects.
    fn bundle(modules: &[(&str, &[&str], &str)]) -> String {
        modules
            .iter()
            .map(|(name, deps, body)| {
                let deps = deps
                    .iter()
                    .map(|d| format!("\"{d}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("__d(\"{name}\",[{deps}],(function(g,r,d,o,a,i,l){{{body}}}),42);\n")
            })
            .collect()
    }

    #[test]
    fn extracts_payload_names_whatever_variable_holds_them() {
        // Both the readable emscripten form and the minified one must be found, and a
        // base64-inlined payload must not be mistaken for a fetchable file.
        let src = bundle(&[
            (
                "ls_voprf_utils_v2",
                &[],
                "var wasmBinaryFile;wasmBinaryFile=\"crypto_utils_v2.wasm\";",
            ),
            ("DGWCppBridge", &[], "var ae=\"dgwcppbridge.wasm\";"),
            (
                "Inlined",
                &[],
                "var x=\"data:application/octet-stream;base64,AGFzbQ.wasm\";",
            ),
            // A metric/ODS name that merely *contains* `wasm` is not a payload.
            (
                "WAWebODS.consumer",
                &[],
                "r(\"WAWebODS\").incr(\"web.call.wasm_crash\");",
            ),
        ]);
        let ir = extract_wasm(&src, "2.3000.1");
        let names: Vec<&str> = ir.binaries.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["crypto_utils_v2.wasm", "dgwcppbridge.wasm"]);
        assert_eq!(ir.binaries[0].modules, ["ls_voprf_utils_v2"]);
        assert_eq!(ir.wa_version, "2.3000.1");
    }

    #[test]
    fn collects_bx_handles_with_consumers_and_hints() {
        let src = bundle(&[
            (
                "WAGetKaleidoscopeWasm",
                &["WAWasmModuleCache", "bx"],
                "var e=r(\"bx\").getURL(r(\"bx\")(\"33861\"));",
            ),
            // Same id from a second module: consumers merge, hints union.
            ("WAWebVoipInit", &["bx"], "var u=r(\"bx\")(\"32180\");"),
            (
                "WAWebVoipWebWasmLoader",
                &["bx"],
                "var u=r(\"bx\")(\"32180\");",
            ),
            // An image handle in a plain component: recorded, but no wasm evidence.
            ("WAWebThemeContext", &["bx"], "var i=r(\"bx\")(\"9547\");"),
        ]);
        let ir = extract_wasm(&src, "v");

        let ids: Vec<&str> = ir.resources.iter().map(|r| r.bx_id.as_str()).collect();
        assert_eq!(ids, ["32180", "33861", "9547"], "sorted by id (as strings)");

        let voip = &ir.resources[0];
        assert_eq!(voip.consumers, ["WAWebVoipInit", "WAWebVoipWebWasmLoader"]);
        assert_eq!(
            voip.wasm_hint,
            ["moduleName"],
            "hint unions across consumers"
        );

        let kaleido = &ir.resources[1];
        assert_eq!(kaleido.wasm_hint, ["moduleName", "wasmModuleCacheDep"]);

        let theme = &ir.resources[2];
        assert!(
            theme.wasm_hint.is_empty(),
            "an image handle carries no wasm evidence"
        );
    }

    #[test]
    fn ignores_non_numeric_and_non_bx_handles() {
        let src = bundle(&[(
            "Mixed",
            &["bx", "other"],
            // Not a bx handle (different module), not an id (non-numeric), and a bare
            // `bx` require with no id at all.
            "r(\"other\")(\"123\");r(\"bx\")(\"abc\");r(\"bx\").getURL(x);",
        )]);
        let ir = extract_wasm(&src, "v");
        assert!(ir.resources.is_empty(), "got {:?}", ir.resources);
    }

    #[test]
    fn payload_literal_is_its_own_hint() {
        // A module whose glue names a payload *and* asks bx for bytes: the literal alone
        // is evidence, even though the module isn't named `…Wasm…`.
        let src = bundle(&[(
            "WATheiaRaTls",
            &["bx"],
            "var he=\"theia_ratls_wasm.wasm\";var u=r(\"bx\")(\"47448\");",
        )]);
        let ir = extract_wasm(&src, "v");
        assert_eq!(ir.resources.len(), 1);
        assert_eq!(ir.resources[0].wasm_hint, ["wasmBinaryLiteral"]);
    }

    #[test]
    fn empty_and_wasm_free_bundles_yield_nothing() {
        assert!(extract_wasm("", "v").binaries.is_empty());
        let ir = extract_wasm(&bundle(&[("Plain", &[], "var x=1;")]), "v");
        assert!(ir.binaries.is_empty() && ir.resources.is_empty());
    }
}
