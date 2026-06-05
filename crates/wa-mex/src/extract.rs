//! Walk each `*.graphql` module's Relay operation literal
//! (`{kind:"Request", params:{id, operationKind, name}, operation:{argumentDefinitions, ...}}`)
//! and collect the persisted operation: docId, kind, and variable names.

use std::collections::{BTreeMap, HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentExpression, Expression, ObjectExpression, VariableDeclarator};
use oxc_ast_visit::{Visit, walk};
use wa_ir::{MexIr, MexOperation, MexOperationKind};
use wa_oxc::{arg_expr, as_identifier, as_object, as_string_lit, obj_prop};
use wa_transform::ModuleDefinition;

const MODULE_SUFFIX: &str = ".graphql";
const MEX_NAME_PREFIX: &str = "WAWebMex";
const NAME_PREFIX: &str = "WAWeb";
const QUERY_SUFFIX: &str = "Query";
const MUTATION_SUFFIX: &str = "Mutation";
const JOB_QUERY_SUFFIX: &str = "JobQuery";
const JOB_MUTATION_SUFFIX: &str = "JobMutation";

const REQUEST_KIND: &str = "Request";
const PROP_KIND: &str = "kind";
const PROP_PARAMS: &str = "params";
const PROP_OPERATION: &str = "operation";
const PROP_FRAGMENT: &str = "fragment";
const PROP_ID: &str = "id";
const PROP_OPERATION_KIND: &str = "operationKind";
const PROP_NAME: &str = "name";
const PROP_ARG_DEFS: &str = "argumentDefinitions";
const KIND_QUERY: &str = "query";
const KIND_MUTATION: &str = "mutation";
/// Sibling module that just exports a persisted id string for an operation.
const RELAY_OP_SUFFIX: &str = "_facebookRelayOperation";
const EXPORTS_PROP: &str = "exports";

/// Operation names containing any of these (case-insensitive) are ad/commerce/
/// platform noise, excluded to mirror the curated spec surface.
const NOISE: &[&str] = &[
    "bizad",
    "bizai",
    "bizcatalog",
    "bizpay",
    "bizbroadcast",
    "comet",
    "lwi",
    "mwchat",
    "mmlite",
    "bizmeta",
    "bizcommerce",
    "bizaccount",
    "bizdeli",
    "bizmass",
    "bizmcomm",
    "bizmessagetemplate",
    "bizorder",
    "bizplatform",
    "bizpostpaid",
    "bizsendoptin",
    "bizsetting",
    "bizshipping",
    "bizquickreplies",
    "bizlabel",
    "bizaway",
    "bizgreeting",
    "bizonboarding",
    "bizgroup",
    "bizhub",
    "bizinstall",
    "bizinterop",
    "bizlogin",
    "bizpnh",
    "bizqrcode",
    "bizquote",
    "bizrecurring",
    "bizrequest",
    "bizsubscribed",
    "bizupsell",
    "bizverify",
    "bizwa",
    "bizwam",
    "bizwelcome",
    "bizyou",
    "metaai",
    "metatransp",
    "saved",
    "telemetry",
    "subscribe",
    "galaxy",
    "hatch",
    "linkedaccounts",
    "provisioning",
    "rtcring",
    "xplatgen",
    "wallet",
    "transaction",
    "boost",
];

/// Extract all persisted Mex operations from a bundle's source.
pub fn extract_mex(bundle_source: &str, wa_version: &str) -> MexIr {
    let module_defs = wa_transform::extract_module_definitions(bundle_source);
    extract_mex_from_modules(bundle_source, &module_defs, wa_version)
}

/// Extract Mex operations from an already-split module index (shares one
/// whole-bundle parse with the other extractors; only `.graphql` and
/// relay-operation module slices are re-parsed here).
pub fn extract_mex_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> MexIr {
    // Map each `.graphql` module to its first caller (a module that depends on
    // it) — the caller's body holds the `fetchQuery(id, <expr>)` whose 2nd arg
    // reveals the input variable shape.
    let mut caller_by_graphql: HashMap<&str, &ModuleDefinition> = HashMap::new();
    for def in module_defs {
        for dep in &def.deps {
            if dep.ends_with(MODULE_SUFFIX) {
                caller_by_graphql.entry(dep.as_str()).or_insert(def);
            }
        }
    }

    // Pass 1: collect raw operations (first occurrence wins across concatenated
    // bundles) and the persisted-id strings exported by relay-operation siblings.
    let mut raw_ops: Vec<RawOp> = Vec::new();
    let mut exported_ids: HashMap<String, String> = HashMap::new();
    let mut seen_modules: HashSet<&str> = HashSet::new();
    for def in module_defs {
        let name = def.name.as_str();
        let slice = &source[def.start..def.end];
        if name.ends_with(RELAY_OP_SUFFIX) {
            if let Some(id) = module_exported_string(slice) {
                exported_ids.insert(name.to_string(), id);
            }
            continue;
        }
        if !name.ends_with(MODULE_SUFFIX) || !seen_modules.insert(name) {
            continue;
        }
        let alloc = Allocator::default();
        let ret = wa_oxc::parse_cjs(&alloc, slice);
        let mut collector = MexCollector::default();
        collector.visit_program(&ret.program);
        if let Some(mut raw) = collector.raw {
            raw.response = crate::shape::response_from_module(slice);
            let caller_body = caller_by_graphql.get(name).map(|d| &source[d.start..d.end]);
            raw.variables_shape = crate::shape::variables_shape(caller_body, &raw.variables);
            raw_ops.push(raw);
        }
    }

    // Pass 2: resolve doc ids, filter noise, re-key by short name (disambiguating
    // Query/Mutation collisions), into the sorted operation map.
    //
    // Sort by the full operation name first so collision disambiguation (which op
    // keeps the base key, which gets the suffix, which is dropped) is independent
    // of bundle/source order — otherwise the same WA version emits different keys.
    raw_ops.sort_by(|a, b| a.original_name.cmp(&b.original_name));
    let mut operations: BTreeMap<String, MexOperation> = BTreeMap::new();
    for raw in raw_ops {
        if is_noise(&raw.original_name) {
            continue;
        }
        let Some(kind) = raw.operation_kind else {
            continue;
        };
        let doc_id = raw
            .doc_id
            .or_else(|| raw.doc_id_ref.and_then(|m| exported_ids.get(&m).cloned()))
            .unwrap_or_else(|| raw.original_name.clone());

        let mut key = strip_op_name(&raw.original_name);
        if operations.contains_key(&key) {
            let alt = format!("{key}{}", kind_suffix(kind));
            if operations.contains_key(&alt) {
                continue;
            }
            key = alt;
        }
        operations.insert(
            key,
            MexOperation {
                original_name: raw.original_name,
                doc_id,
                operation_kind: kind,
                variables: raw.variables,
                variables_shape: raw.variables_shape,
                response: raw.response,
            },
        );
    }

    MexIr {
        wa_version: wa_version.to_string(),
        operations,
    }
}

fn is_noise(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    NOISE.iter().any(|t| lower.contains(t))
}

/// `WAWebFetchGroupInfoQuery` → `FetchGroupInfo`, `WAWebBizCreateOrderJobMutation`
/// → `BizCreateOrder`.
fn strip_op_name(name: &str) -> String {
    let n = name.strip_prefix(MEX_NAME_PREFIX).unwrap_or(name);
    let n = n.strip_prefix(NAME_PREFIX).unwrap_or(n);
    let n = n
        .strip_suffix(JOB_MUTATION_SUFFIX)
        .or_else(|| n.strip_suffix(JOB_QUERY_SUFFIX))
        .unwrap_or(n);
    let n = n
        .strip_suffix(MUTATION_SUFFIX)
        .or_else(|| n.strip_suffix(QUERY_SUFFIX))
        .unwrap_or(n);
    n.to_string()
}

fn kind_suffix(kind: MexOperationKind) -> &'static str {
    match kind {
        MexOperationKind::Query => QUERY_SUFFIX,
        MexOperationKind::Mutation => MUTATION_SUFFIX,
    }
}

struct RawOp {
    original_name: String,
    /// Inline string id, if persisted directly.
    doc_id: Option<String>,
    /// Module name from `id: require("X_facebookRelayOperation")`, resolved later.
    doc_id_ref: Option<String>,
    operation_kind: Option<MexOperationKind>,
    variables: Vec<String>,
    variables_shape: BTreeMap<String, wa_ir::TypeNode>,
    response: BTreeMap<String, wa_ir::TypeNode>,
}

#[derive(Default)]
struct MexCollector {
    /// Local array vars → the `name` fields of their object elements (Relay hoists
    /// `argumentDefinitions` either as a whole array...).
    array_var_names: HashMap<String, Vec<String>>,
    /// ...or as individual argument objects referenced by an inline array
    /// `[e, t, n]` — local object vars → their `name` field.
    object_var_names: HashMap<String, String>,
    raw: Option<RawOp>,
}

impl<'a> Visit<'a> for MexCollector {
    fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
        if let Some(name) = d.id.get_identifier_name() {
            match d.init.as_ref() {
                Some(Expression::ArrayExpression(arr)) => {
                    self.array_var_names
                        .insert(name.as_str().to_string(), object_name_fields(arr));
                }
                Some(Expression::ObjectExpression(o)) => {
                    if let Some(field) = obj_prop(o, PROP_NAME).and_then(as_string_lit) {
                        self.object_var_names
                            .insert(name.as_str().to_string(), field.to_string());
                    }
                }
                _ => {}
            }
        }
        walk::walk_variable_declarator(self, d);
    }

    fn visit_object_expression(&mut self, obj: &ObjectExpression<'a>) {
        if self.raw.is_none()
            && obj_prop(obj, PROP_KIND).and_then(as_string_lit) == Some(REQUEST_KIND)
        {
            self.raw = self.parse_request(obj);
        }
        walk::walk_object_expression(self, obj);
    }
}

impl MexCollector {
    fn parse_request(&self, obj: &ObjectExpression) -> Option<RawOp> {
        let params = obj_prop(obj, PROP_PARAMS).and_then(as_object)?;
        let original_name = obj_prop(params, PROP_NAME)
            .and_then(as_string_lit)?
            .to_string();
        let operation_kind = match obj_prop(params, PROP_OPERATION_KIND).and_then(as_string_lit) {
            Some(KIND_QUERY) => Some(MexOperationKind::Query),
            Some(KIND_MUTATION) => Some(MexOperationKind::Mutation),
            _ => None,
        };
        let id_expr = obj_prop(params, PROP_ID);
        let doc_id = id_expr.and_then(as_string_lit).map(str::to_string);
        // `id: require("X_facebookRelayOperation")` → capture X to resolve later.
        let doc_id_ref = match (doc_id.is_none(), id_expr) {
            (true, Some(Expression::CallExpression(c))) => c
                .arguments
                .first()
                .and_then(arg_expr)
                .and_then(as_string_lit)
                .map(str::to_string),
            _ => None,
        };

        // `argumentDefinitions` lives on `fragment` (preferred, for variable
        // order) or `operation` — an inline array or a hoisted-local reference.
        let arg_defs = obj_prop(obj, PROP_FRAGMENT)
            .and_then(as_object)
            .and_then(|o| obj_prop(o, PROP_ARG_DEFS))
            .or_else(|| {
                obj_prop(obj, PROP_OPERATION)
                    .and_then(as_object)
                    .and_then(|o| obj_prop(o, PROP_ARG_DEFS))
            });
        let variables = arg_defs
            .map(|e| self.resolve_arg_names(e))
            .unwrap_or_default();

        Some(RawOp {
            original_name,
            doc_id,
            doc_id_ref,
            operation_kind,
            variables,
            variables_shape: BTreeMap::new(),
            response: BTreeMap::new(),
        })
    }

    /// Resolve `argumentDefinitions` to ordered variable names, handling a whole
    /// hoisted array var, an inline array of object literals, or an inline array
    /// of identifiers referencing hoisted argument objects.
    fn resolve_arg_names(&self, expr: &Expression) -> Vec<String> {
        match expr {
            Expression::ArrayExpression(arr) => arr
                .elements
                .iter()
                .filter_map(|el| {
                    let e = el.as_expression()?;
                    if let Some(o) = as_object(e) {
                        obj_prop(o, PROP_NAME)
                            .and_then(as_string_lit)
                            .map(str::to_string)
                    } else {
                        as_identifier(e).and_then(|id| self.object_var_names.get(id).cloned())
                    }
                })
                .collect(),
            _ => as_identifier(expr)
                .and_then(|id| self.array_var_names.get(id).cloned())
                .unwrap_or_default(),
        }
    }
}

/// The `name` string field of each object element in an array literal.
fn object_name_fields(arr: &oxc_ast::ast::ArrayExpression) -> Vec<String> {
    arr.elements
        .iter()
        .filter_map(|el| el.as_expression().and_then(as_object))
        .filter_map(|o| obj_prop(o, PROP_NAME).and_then(as_string_lit))
        .map(str::to_string)
        .collect()
}

/// The string a tiny module exports via `X.exports = "..."` (relay-op id modules).
fn module_exported_string(module_src: &str) -> Option<String> {
    let alloc = Allocator::default();
    let ret = wa_oxc::parse_cjs(&alloc, module_src);
    let mut c = ExportsStringCollector { value: None };
    c.visit_program(&ret.program);
    c.value
}

struct ExportsStringCollector {
    value: Option<String>,
}

impl<'a> Visit<'a> for ExportsStringCollector {
    fn visit_assignment_expression(&mut self, n: &AssignmentExpression<'a>) {
        if self.value.is_none()
            && let Some(member) = n.left.as_member_expression()
            && member.static_property_name() == Some(EXPORTS_PROP)
            && let Some(s) = as_string_lit(&n.right)
        {
            self.value = Some(s.to_string());
        }
        walk::walk_assignment_expression(self, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE: &str = r#"__d("WAWebFetchFooBarQuery.graphql",["x"],(function(t,n,r,o,a,i){
        var e=[{defaultValue:null,kind:"LocalArgument",name:"project_name"},{kind:"LocalArgument",name:"limit"}],
            s=[{alias:null,kind:"LinkedField",name:"xwa_foo"}];
        i.exports=(function(){return{
            fragment:{argumentDefinitions:e,kind:"Fragment",name:"WAWebFetchFooBarQuery",selections:s,type:"Query"},
            kind:"Request",
            operation:{argumentDefinitions:e,kind:"Operation",name:"WAWebFetchFooBarQuery",selections:s},
            params:{id:"123456789",metadata:{},name:"WAWebFetchFooBarQuery",operationKind:"query",text:null}
        }})()
    }),null);"#;

    #[test]
    fn extracts_persisted_operation() {
        let ir = extract_mex(MODULE, "2.3000.1");
        assert_eq!(ir.operations.len(), 1);
        let op = ir.operations.get("FetchFooBar").expect("stripped name key");
        assert_eq!(op.original_name, "WAWebFetchFooBarQuery");
        assert_eq!(op.doc_id, "123456789");
        assert_eq!(op.operation_kind, MexOperationKind::Query);
        assert_eq!(op.variables, vec!["project_name", "limit"]);
    }

    #[test]
    fn mutation_with_inline_argdefs_and_null_id_falls_back_to_name() {
        let m = r#"__d("WAWebDoThingMutation.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",operation:{argumentDefinitions:[{kind:"LocalArgument",name:"input"}],name:"WAWebDoThingMutation"},params:{id:null,name:"WAWebDoThingMutation",operationKind:"mutation"}}
        }),null);"#;
        let ir = extract_mex(m, "2.3000.1");
        let op = ir.operations.get("DoThing").unwrap();
        assert_eq!(op.operation_kind, MexOperationKind::Mutation);
        assert_eq!(op.doc_id, "WAWebDoThingMutation"); // null id → name fallback
        assert_eq!(op.variables, vec!["input"]);
    }

    #[test]
    fn resolves_cross_module_doc_id() {
        // params.id is a require to a sibling that exports the persisted id string.
        let m = r#"
        __d("WAWebGetThingQuery_facebookRelayOperation",[],(function(t,n,r,o,a,i){a.exports="999111"}),null);
        __d("WAWebGetThingQuery.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",fragment:{argumentDefinitions:[{kind:"LocalArgument",name:"q"}],name:"WAWebGetThingQuery"},operation:{argumentDefinitions:[],name:"WAWebGetThingQuery"},params:{id:n("WAWebGetThingQuery_facebookRelayOperation"),name:"WAWebGetThingQuery",operationKind:"query"}}
        }),null);"#;
        let ir = extract_mex(m, "2.3000.1");
        let op = ir.operations.get("GetThing").unwrap();
        assert_eq!(op.doc_id, "999111"); // resolved from the sibling module
        assert_eq!(op.variables, vec!["q"]); // fragment argDefs preferred
    }

    #[test]
    fn noise_operations_are_skipped() {
        let m = r#"__d("WAWebBizAdSomethingQuery.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",operation:{argumentDefinitions:[],name:"WAWebBizAdSomethingQuery"},params:{id:"1",name:"WAWebBizAdSomethingQuery",operationKind:"query"}}
        }),null);"#;
        assert!(extract_mex(m, "2.3000.1").operations.is_empty());
    }

    #[test]
    fn short_key_strips_job_and_mex_affixes() {
        assert_eq!(strip_op_name("WAWebFetchGroupInfoQuery"), "FetchGroupInfo");
        assert_eq!(
            strip_op_name("WAWebBizCreateOrderJobMutation"),
            "BizCreateOrder"
        );
        assert_eq!(strip_op_name("WAWebMexSomethingQuery"), "Something");
        assert_eq!(strip_op_name("Plain"), "Plain");
    }

    #[test]
    fn non_graphql_modules_ignored() {
        let m = r#"__d("WAWebPlain",[],(function(t,n,r,o,a,i){ i.exports={x:1}; }),1);"#;
        assert!(extract_mex(m, "2.3000.1").operations.is_empty());
    }
}
