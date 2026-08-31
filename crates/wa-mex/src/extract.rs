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

/// Where an operation's persisted `docId` came from **in this run**, and how many
/// variable keys landed in each presence state.
///
/// The two halves answer questions a count of operations cannot. A `docId` is a
/// bare numeric string, so a stale one and a fresh one look alike; splitting the
/// total by origin makes "extracted from the operation literal" and "fell back to
/// the operation name" separately visible, and a fallback is a broken persisted
/// id rather than a cosmetic gap. The presence tallies are the residue of the
/// same rule the IR publishes: `undetermined` is a real state, and it belongs in
/// a counted diagnostic rather than in silence.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MexDiagnostics {
    /// Operations published.
    pub operations: usize,
    /// `params.id` read as a string literal in the operation's own module.
    pub doc_ids_inline: usize,
    /// `params.id: require("X_facebookRelayOperation")`, resolved against the
    /// sibling module that exports the id.
    pub doc_ids_from_sibling: usize,
    /// No id in the bundle at all: the operation name stands in for one, which is
    /// the only state in which `docId` is not a persisted id.
    pub doc_ids_from_name: usize,
    /// Variable keys carrying each verdict, counted over the whole published
    /// tree (nested object keys and list-element keys included).
    pub presence_always: usize,
    pub presence_conditional: usize,
    pub presence_undetermined: usize,
    /// Operations with at least one variable.
    pub operations_with_variables: usize,
    /// Operations where every variable is `always`.
    pub operations_fully_determined: usize,
    /// What the presence scan saw and could not read.
    pub presence: PresenceDiagnostics,
}

/// The forms the presence scan could not turn into a verdict, kept apart from
/// the verdicts themselves so a rise in "we could not read this" is not hidden by
/// a fall in "the client may omit this".
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PresenceDiagnostics {
    /// Operations for which no call site was recovered, so every one of their
    /// variables is `undetermined` for want of evidence rather than by judgement.
    pub operations_without_call_site: usize,
    /// A matched Relay call whose second argument is not an object literal and
    /// does not resolve to one.
    pub unreadable_call_arguments: usize,
    /// A spread whose source object the scan could not enumerate, so the keys it
    /// contributes are unknown - the one way a variable can look unwritten while
    /// the client writes it.
    pub unreadable_spreads: usize,
    /// A computed property key, which names no publishable variable.
    pub unreadable_keys: usize,
    /// Relay calls in a module that sends several operations whose handle names
    /// no module, so whether they belong to this operation is unknown. Kept
    /// apart from `unreadable_call_arguments`: there the call is known to be
    /// ours and its argument unreadable, here it is the other way round.
    pub ambiguous_call_sites: usize,
}

/// Extract all persisted Mex operations from a bundle's source.
pub fn extract_mex(bundle_source: &str, wa_version: &str) -> MexIr {
    extract_mex_with_diagnostics(bundle_source, wa_version).0
}

/// [`extract_mex`], plus the extraction-quality counts.
pub fn extract_mex_with_diagnostics(
    bundle_source: &str,
    wa_version: &str,
) -> (MexIr, MexDiagnostics) {
    let module_defs = wa_transform::extract_module_definitions(bundle_source);
    extract_mex_from_modules_with_diagnostics(bundle_source, &module_defs, wa_version)
}

/// Extract Mex operations from an already-split module index (shares one
/// whole-bundle parse with the other extractors; only `.graphql` and
/// relay-operation module slices are re-parsed here).
pub fn extract_mex_from_modules(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> MexIr {
    extract_mex_from_modules_with_diagnostics(source, module_defs, wa_version).0
}

/// [`extract_mex_from_modules`], plus the extraction-quality counts.
pub fn extract_mex_from_modules_with_diagnostics(
    source: &str,
    module_defs: &[ModuleDefinition],
    wa_version: &str,
) -> (MexIr, MexDiagnostics) {
    // Map each `.graphql` module to the callers (modules that depend on it) whose
    // bodies hold the `fetchQuery(id, <expr>)` the input variables are read from.
    //
    // All of them, not the first: presence only says `always` when every recovered
    // call site agrees, so a second job module sending the same operation is
    // evidence that has to reach the merge. No operation has two callers at the
    // waVersion this was written against, which is exactly why the single-caller
    // form looked sufficient and would have failed silently on the rollout that
    // added one, in the direction that matters (a key claimed unconditional
    // because the site contradicting it was never read).
    //
    // Deduplicated by module NAME, so the copies of one module that several
    // bundle files define are not merged with themselves; first occurrence wins,
    // the same rule the operation scan below follows.
    let mut caller_by_graphql: HashMap<&str, Vec<&ModuleDefinition>> = HashMap::new();
    let mut seen_callers: HashSet<(&str, &str)> = HashSet::new();
    for def in module_defs {
        for dep in &def.deps {
            if dep.ends_with(MODULE_SUFFIX) && seen_callers.insert((dep.as_str(), &def.name)) {
                caller_by_graphql.entry(dep.as_str()).or_default().push(def);
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
            let callers = caller_by_graphql
                .get(name)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let bodies: Vec<(&str, bool)> = callers
                .iter()
                .map(|d| {
                    // A caller that depends on exactly one `.graphql` module cannot
                    // be sending another operation, so a call whose handle argument
                    // the scan cannot tie back to a module is still unambiguously
                    // this one's. Asked per caller, since they need not agree.
                    let sole = d.deps.iter().filter(|x| x.ends_with(MODULE_SUFFIX)).count() == 1;
                    (&source[d.start..d.end], sole)
                })
                .collect();
            let shape_bodies: Vec<&str> = bodies.iter().map(|(src, _)| *src).collect();
            raw.variables_shape = crate::shape::variables_shape(&shape_bodies, &raw.variables);
            // Counted per operation and folded in below, so the totals describe
            // the operations the IR publishes rather than the raw scan - the noise
            // filter drops a third of them, and a diagnostic that counted those
            // would not add up against the document a consumer reads.
            raw.variables_presence = crate::presence::variables_presence(
                &bodies,
                name,
                &raw.variables,
                &mut raw.presence,
            );
            // The two maps are siblings a consumer reads together, so every key
            // the shape publishes has to carry a verdict. A key the presence scan
            // never reached - a list built by `.map(…)`, whose callback the shape
            // pass reads and this one does not judge - gets `undetermined` rather
            // than no entry, because an absent key and "we could not tell" are
            // exactly the two a reader must not have to guess between.
            align_with_shape(&raw.variables_shape, &mut raw.variables_presence);
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
    let mut diag = MexDiagnostics::default();
    let mut operations: BTreeMap<String, MexOperation> = BTreeMap::new();
    for raw in raw_ops {
        if is_noise(&raw.original_name) {
            continue;
        }
        let Some(kind) = raw.operation_kind else {
            continue;
        };
        // Split by origin so the manifest can say that every published `docId`
        // was read out of THIS bundle set rather than looking unchanged because
        // nothing re-derived it. Resolved here and counted below, after the
        // collision filter: an operation the filter drops is not published, and
        // counting it would report more ids than there are operations to carry
        // them.
        let (doc_id, origin) = match raw.doc_id {
            Some(id) => (id, DocIdOrigin::Inline),
            None => match raw.doc_id_ref.and_then(|m| exported_ids.get(&m).cloned()) {
                Some(id) => (id, DocIdOrigin::Sibling),
                None => (raw.original_name.clone(), DocIdOrigin::Name),
            },
        };

        let mut key = strip_op_name(&raw.original_name);
        if operations.contains_key(&key) {
            let alt = format!("{key}{}", kind_suffix(kind));
            if operations.contains_key(&alt) {
                continue;
            }
            key = alt;
        }
        match origin {
            DocIdOrigin::Inline => diag.doc_ids_inline += 1,
            DocIdOrigin::Sibling => diag.doc_ids_from_sibling += 1,
            DocIdOrigin::Name => diag.doc_ids_from_name += 1,
        }
        count_presence(&raw.variables_presence, &mut diag);
        let p = &raw.presence;
        diag.presence.operations_without_call_site += p.operations_without_call_site;
        diag.presence.unreadable_call_arguments += p.unreadable_call_arguments;
        diag.presence.unreadable_spreads += p.unreadable_spreads;
        diag.presence.unreadable_keys += p.unreadable_keys;
        diag.presence.ambiguous_call_sites += p.ambiguous_call_sites;
        if !raw.variables.is_empty() {
            diag.operations_with_variables += 1;
            if raw.variables_presence.values().all(all_always) {
                diag.operations_fully_determined += 1;
            }
        }
        operations.insert(
            key,
            MexOperation {
                original_name: raw.original_name,
                doc_id,
                operation_kind: kind,
                variables: raw.variables,
                variables_shape: raw.variables_shape,
                variables_presence: raw.variables_presence,
                response: raw.response,
            },
        );
    }

    diag.operations = operations.len();
    (
        MexIr {
            wa_version: wa_version.to_string(),
            operations,
        },
        diag,
    )
}

/// Publish a verdict for exactly the keys the shape types.
///
/// The two maps are siblings a consumer reads together, and `scripts/lint-ir.py`
/// rejects a document where one names a key the other does not - so this is what
/// makes that check unfailable rather than a hazard. A shape key the presence
/// scan never reached gets `undetermined`, because an absent key and "we could
/// not tell" must not look alike. A presence key the shape does not type is
/// dropped: the two passes read the call site differently (the shape's tracer
/// resolves a binding backwards from the call, presence also sees the module's
/// own later declarations), and a verdict for a key no consumer can generate a
/// field for is not worth an unpublishable document.
fn align_with_shape(
    shape: &BTreeMap<String, wa_ir::TypeNode>,
    presence: &mut BTreeMap<String, wa_ir::VariablePresenceNode>,
) {
    presence.retain(|key, _| shape.contains_key(key));
    for (key, node) in shape {
        let entry = presence.entry(key.clone()).or_insert_with(|| {
            wa_ir::VariablePresenceNode::leaf(wa_ir::VariablePresence::Undetermined)
        });
        align_node(node, entry);
    }
}

fn align_node(shape: &wa_ir::TypeNode, presence: &mut wa_ir::VariablePresenceNode) {
    // Each arm clears the children the shape does NOT have room for. The two
    // passes read a call site differently, so presence can resolve an object
    // where the shape emitted a leaf; keeping its fields there would publish
    // nested verdicts on a variable that is not an object, which the linter
    // rejects and which no consumer could generate against.
    match shape {
        wa_ir::TypeNode::Object(fields) => {
            presence.items = None;
            align_with_shape(fields, &mut presence.fields)
        }
        wa_ir::TypeNode::Array(items) => {
            presence.fields.clear();
            // Every layer, since a list of lists carries its keys one level
            // deeper (`[[{a}]]`) and stopping at the first would leave them with
            // no verdict at all rather than an undetermined one.
            if let Some(element @ (wa_ir::TypeNode::Object(_) | wa_ir::TypeNode::Array(_))) =
                items.first()
            {
                // A list element is not a key, so it carries no verdict of
                // its own - see `VariablePresenceNode::items`.
                let item = presence.items.get_or_insert_with(|| {
                    Box::new(wa_ir::VariablePresenceNode::leaf(
                        wa_ir::VariablePresence::Always,
                    ))
                });
                align_node(element, item);
            } else {
                presence.items = None;
            }
        }
        wa_ir::TypeNode::Leaf(_) => {
            presence.fields.clear();
            presence.items = None;
        }
    }
}

/// Where a resolved `docId` was read from, carried between resolution and the
/// collision filter so only a published operation is counted.
#[derive(Debug, Clone, Copy)]
enum DocIdOrigin {
    Inline,
    Sibling,
    Name,
}

/// Tally every key of a presence tree, nested keys included: the question is
/// asked of each key, so the count has to be of keys and not of variables.
fn count_presence(tree: &BTreeMap<String, wa_ir::VariablePresenceNode>, diag: &mut MexDiagnostics) {
    for node in tree.values() {
        match node.presence {
            wa_ir::VariablePresence::Always => diag.presence_always += 1,
            wa_ir::VariablePresence::Conditional => diag.presence_conditional += 1,
            wa_ir::VariablePresence::Undetermined => diag.presence_undetermined += 1,
        }
        count_keys_under(node, diag);
    }
}

/// The keys nested under one node, at every layer.
///
/// A list element is not a key and carries no verdict of its own, so it is
/// followed rather than counted - including through `items.items`, which a list
/// of lists carries and which stopping at the first layer left out of the totals
/// the floor guard reads.
fn count_keys_under(node: &wa_ir::VariablePresenceNode, diag: &mut MexDiagnostics) {
    count_presence(&node.fields, diag);
    if let Some(items) = &node.items {
        count_keys_under(items, diag);
    }
}

/// Whether a variable and everything nested under it is `always`.
fn all_always(node: &wa_ir::VariablePresenceNode) -> bool {
    node.presence == wa_ir::VariablePresence::Always
        && node.fields.values().all(all_always)
        && node.items.as_ref().is_none_or(|i| all_always(i))
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
    variables_presence: BTreeMap<String, wa_ir::VariablePresenceNode>,
    /// What the presence scan could not read for THIS operation, folded into the
    /// document-level totals only once the operation survives the noise filter.
    presence: PresenceDiagnostics,
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
            variables_presence: BTreeMap::new(),
            presence: PresenceDiagnostics::default(),
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
    fn doc_id_origin_is_counted_per_operation() {
        // A persisted id is a bare numeric string, so an id that did not change and
        // an id nothing re-derived are the same value. Splitting by origin is what
        // makes the second visible, and the name fallback is the state in which
        // `docId` is not a persisted id at all.
        let (_, diag) = extract_mex_with_diagnostics(MODULE, "2.3000.1");
        assert_eq!(diag.doc_ids_inline, 1, "read from this run's params.id");
        assert_eq!(diag.doc_ids_from_sibling, 0);
        assert_eq!(diag.doc_ids_from_name, 0);

        let m = r#"__d("WAWebNoIdQuery.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",operation:{argumentDefinitions:[],name:"WAWebNoIdQuery"},params:{id:null,name:"WAWebNoIdQuery",operationKind:"query"}}
        }),null);"#;
        let (_, diag) = extract_mex_with_diagnostics(m, "2.3000.1");
        assert_eq!(diag.doc_ids_from_name, 1);
        assert_eq!(diag.doc_ids_inline, 0);
    }

    #[test]
    fn presence_is_published_beside_the_shape() {
        let m = r#"
        __d("WAWebFlagQuery.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",fragment:{argumentDefinitions:[{kind:"LocalArgument",name:"fetch_x"},{kind:"LocalArgument",name:"fetch_y"}],name:"WAWebFlagQuery"},operation:{argumentDefinitions:[],name:"WAWebFlagQuery"},params:{id:"7",name:"WAWebFlagQuery",operationKind:"query"}}
        }),null);
        __d("WAWebFlagJob",["WAWebFlagQuery.graphql","WAWebMexClient"],(function(t,n,r,o,a,i,l){
            function u(e){return o("WAWebMexClient").fetchQuery(n("WAWebFlagQuery.graphql"),{fetch_x:(e==null?void 0:e.x)===!0,fetch_y:e.y})}
            l.job=u
        }),null);"#;
        let (ir, diag) = extract_mex_with_diagnostics(m, "2.3000.1");
        let op = ir.operations.get("Flag").unwrap();
        assert_eq!(
            op.variables_presence["fetch_x"].presence,
            wa_ir::VariablePresence::Always
        );
        assert_eq!(
            op.variables_presence["fetch_y"].presence,
            wa_ir::VariablePresence::Conditional
        );
        assert_eq!(diag.presence_always, 1);
        assert_eq!(diag.presence_conditional, 1);
        assert_eq!(diag.presence_undetermined, 0);
        assert_eq!(diag.operations_with_variables, 1);
        assert_eq!(diag.operations_fully_determined, 0);
    }

    #[test]
    fn two_callers_agree_on_shape_and_presence_keys() {
        // Presence merges every caller, so the shape has to as well: a nested key
        // only the second caller writes would otherwise carry a verdict the shape
        // does not type, which `scripts/lint-ir.py` rejects outright - the
        // operation would fail to publish rather than come out imprecise.
        let m = r#"
        __d("WAWebTwoQuery.graphql",[],(function(t,n,r,o,a,i){
            i.exports={kind:"Request",fragment:{argumentDefinitions:[{kind:"LocalArgument",name:"input"}],name:"WAWebTwoQuery"},operation:{argumentDefinitions:[],name:"WAWebTwoQuery"},params:{id:"5",name:"WAWebTwoQuery",operationKind:"query"}}
        }),null);
        __d("WAWebJobOne",["WAWebTwoQuery.graphql","WAWebMexClient"],(function(t,n,r,o,a,i,l){
            function u(e){return o("WAWebMexClient").fetchQuery(n("WAWebTwoQuery.graphql"),{input:{a:!0}})}
            l.one=u
        }),null);
        __d("WAWebJobTwo",["WAWebTwoQuery.graphql","WAWebMexClient"],(function(t,n,r,o,a,i,l){
            function u(e){return o("WAWebMexClient").fetchQuery(n("WAWebTwoQuery.graphql"),{input:{a:!0,b:e.b}})}
            l.two=u
        }),null);"#;
        let ir = extract_mex(m, "2.3000.1");
        let op = ir.operations.get("Two").expect("operation published");
        let wa_ir::TypeNode::Object(shape) = &op.variables_shape["input"] else {
            panic!("input shape is an object")
        };
        let presence = &op.variables_presence["input"];
        assert!(
            shape.contains_key("b") && presence.fields.contains_key("b"),
            "the second caller's key is typed and answered, not one or the other"
        );
        assert_eq!(
            presence.fields["a"].presence,
            wa_ir::VariablePresence::Always,
            "written by both callers"
        );
        assert_eq!(
            presence.fields["b"].presence,
            wa_ir::VariablePresence::Conditional,
            "one caller's input object does not carry it"
        );
        // The invariant the linter enforces, asserted here so a regression fails
        // in the crate rather than at publish time.
        for key in shape.keys() {
            assert!(
                presence.fields.contains_key(key),
                "{key} typed with no verdict"
            );
        }
        for key in presence.fields.keys() {
            assert!(shape.contains_key(key), "{key} answered but not typed");
        }
    }

    #[test]
    fn non_graphql_modules_ignored() {
        let m = r#"__d("WAWebPlain",[],(function(t,n,r,o,a,i){ i.exports={x:1}; }),1);"#;
        assert!(extract_mex(m, "2.3000.1").operations.is_empty());
    }
}
