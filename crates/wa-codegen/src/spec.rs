//! Generate one `IqSpec` impl (struct + constructor + response + build/parse).

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use wa_ir::{
    AssertionKind, IqStanzaDef, IqTarget, IqType, ResponseVariant, ResponseVariantKind,
    WapAttrKind, WapChildNode,
};

/// Two outcome variants are separable by a discriminator when both pin the SAME attr
/// to DIFFERENT literal values (`type:"result"` vs `type:"error"`): a response
/// satisfying one fails the other's guard, so neither can shadow the other.
pub(crate) fn assertions_conflict(a: &ResponseVariant, b: &ResponseVariant) -> bool {
    // BOTH sides must pin a literal, and to the same NAMED attribute. `Some("result")`
    // against a presence-only assertion (`value: None`) is not a conflict: a parser that
    // merely requires `type` to exist also accepts `type="result"`, so the variants are
    // not disjoint and the earlier arm shadows the later one in a first-success cascade.
    a.assertions.iter().any(|x| {
        x.kind == AssertionKind::Attr
            && x.name.is_some()
            && x.value.is_some()
            && b.assertions.iter().any(|y| {
                y.kind == AssertionKind::Attr
                    && y.name == x.name
                    && y.value.is_some()
                    && y.value != x.value
            })
    })
}

use crate::emit::{VariantCtx, emit_child_builder, emit_response_parser};
use crate::fields::{collect_response_fields, rust_attr_type};
use crate::naming::{pascal_case, rust_ident, rust_lit, rust_lit_inner};

/// Length of the common prefix shared by the variant tags, backed up to a word
/// boundary (next ASCII-uppercase char). Lets `GetBlockListResponseSuccessWithMatch`
/// / `…MigratedSuccessWithMatch` strip to `SuccessWithMatch` / `MigratedSuccessWithMatch`.
fn variant_tag_prefix(tags: &[String]) -> usize {
    let Some(first) = tags.first() else {
        return 0;
    };
    let mut len = first.len();
    for t in &tags[1..] {
        let common = first
            .bytes()
            .zip(t.bytes())
            .take_while(|(a, b)| a == b)
            .count();
        len = len.min(common);
    }
    let b = first.as_bytes();
    while len > 0 && len < b.len() && !(b[len] as char).is_ascii_uppercase() {
        len -= 1;
    }
    len
}

/// Whether `emit_response_parser` produces a parser that initializes every field of
/// the structs `collect_response_fields` derives for `fields` — the guard that keeps
/// codegen from emitting a parser that references non-existent fields (a shape
/// `emit_response_parser` mishandles, e.g. a repeated child under a `source_path`).
pub(crate) fn parser_is_valid(
    fields: &[wa_ir::ParsedField],
    response_type_name: &str,
    prefix: &str,
) -> bool {
    let (check_fields, check_child_structs, _) = collect_response_fields(fields, prefix);
    let names: Vec<&str> = check_fields.iter().map(|f| f.name.as_str()).collect();
    if names.iter().collect::<HashSet<_>>().len() != names.len() {
        return false;
    }
    let parser_code =
        emit_response_parser(fields, response_type_name, "        ", prefix).join("\n");
    for f in &check_fields {
        if !parser_code.contains(&format!("{},", f.name))
            && !parser_code.contains(&format!("{}:", f.name))
        {
            return false;
        }
    }
    if LET_KEYWORD.is_match(&parser_code) {
        return false;
    }
    for cs in &check_child_structs {
        let required: HashSet<&str> = cs.fields.iter().map(|f| f.name.as_str()).collect();
        for body in struct_init_bodies(&parser_code, &cs.name) {
            let inited: HashSet<&str> = INIT_FIELD
                .captures_iter(body)
                .map(|c| c.get(1).unwrap().as_str())
                .collect();
            if !required.iter().all(|r| inited.contains(r)) {
                return false;
            }
        }
    }
    true
}

/// The names of fields whose absence makes a generated variant parser return `Err`
/// (so they discriminate which variant a response matches): required attrs
/// (`attr…`, read with `?`) and required `child` nodes (read with `ok_or_else`).
/// Excludes optionals (`maybe…`), content reads (defaulted, never fail), and
/// untyped union/mixin placeholders (`method == ""`). Recursive.
fn fail_required_fields(fields: &[wa_ir::ParsedField]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    fn walk(fields: &[wa_ir::ParsedField], out: &mut std::collections::BTreeSet<String>) {
        for f in fields {
            if f.required && (f.method == "child" || f.method.starts_with("attr")) {
                out.insert(f.name.clone());
            }
            if let Some(kids) = &f.children {
                walk(kids, out);
            }
        }
    }
    walk(fields, &mut out);
    out
}

/// Emit, for an RPC outcome-union response, a `#[derive(Default)]` struct per
/// variant (and its child item structs) plus an `enum` wrapping them. Returns
/// `(variant_name, struct_name)` per variant for the parser — but only when EVERY
/// variant's parser validates ([`parser_is_valid`]); otherwise `None` (and nothing
/// emitted), so the caller falls back to the single-shape/`()` path rather than
/// generating an invalid parser. Models the IR's outcome wire shape, not domain types.
/// The attribute pins a response variant asserts, as `(name, value)` — the set that has to
/// pick this variant alone before a match may be treated as final.
fn variant_pins(v: &ResponseVariant) -> Vec<(&str, &str)> {
    v.assertions
        .iter()
        .filter(|a| a.kind == AssertionKind::Attr)
        .filter_map(|a| match (&a.name, &a.value) {
            (Some(name), Some(value)) => Some((name.as_str(), value.as_str())),
            _ => None,
        })
        .collect()
}

/// The same pins as generated conditions.
fn pin_conditions(v: &ResponseVariant, node: &str) -> Vec<String> {
    variant_pins(v)
        .into_iter()
        .map(|(name, value)| {
            format!(
                "{node}.get_attr({}).map(|x| x.as_str()).as_deref() == Some({})",
                rust_lit(name),
                rust_lit(value),
            )
        })
        .collect()
}

/// Whether a node satisfying `mine` could satisfy `other` as well.
///
/// Only a pin the two disagree on rules that out — anything `other` pins and `mine` does not is
/// a value the node is free to carry, and a pin `mine` has that `other` lacks constrains
/// nothing about `other`. So a variant pinning a SUPERSET of another's is still reachable
/// through it, and an unpinned variant is reachable through every one of them.
fn pins_can_coincide(mine: &[(&str, &str)], other: &[(&str, &str)]) -> bool {
    !mine.iter().any(|(name, value)| {
        other
            .iter()
            .any(|(o_name, o_value)| o_name == name && o_value != value)
    })
}

fn emit_outcome_types(
    op: &IqStanzaDef,
    spec_base: &str,
    enum_name: &str,
    doc: &str,
    out: &mut Vec<String>,
) -> Option<Vec<(String, String)>> {
    let tags: Vec<String> = op.response.variants.iter().map(|v| v.tag.clone()).collect();
    let plen = variant_tag_prefix(&tags);

    // Resolve variant names first, then bail unless all parsers validate.
    let mut names: Vec<(String, String)> = Vec::new();
    let mut used_vnames: HashSet<String> = HashSet::new();
    for v in &op.response.variants {
        let raw = if v.tag.len() > plen {
            &v.tag[plen..]
        } else {
            v.tag.as_str()
        };
        let mut vname = pascal_case(raw);
        if vname.is_empty() {
            vname = pascal_case(&v.tag);
        }
        let base = vname.clone();
        let mut n = 2;
        while !used_vnames.insert(vname.clone()) {
            vname = format!("{base}{n}");
            n += 1;
        }
        names.push((vname.clone(), format!("{spec_base}{vname}")));
    }
    let all_valid = op
        .response
        .variants
        .iter()
        .zip(&names)
        .all(|(v, (_, sname))| parser_is_valid(&v.fields, sname, sname));
    if !all_valid {
        return None;
    }

    // Bail if the try-each would still be ambiguous. A variant's parser accepts a
    // response iff it carries all the variant's *fail-on-absent* fields AND satisfies
    // its captured discriminator assertions (e.g. `type:"result"`). An earlier variant
    // shadows a later one only when its required fields are a subset AND no conflicting
    // assertion sets them apart — then a later-response would match the earlier arm
    // first (misclassification). When that can happen, fall back to the single-shape
    // path rather than emit a parser that lies. (Variants distinguished only by an
    // uncaptured discriminator — e.g. two errors differing by `<error>` code — stay
    // here; recovering those needs deeper child-discriminator capture.)
    let req: Vec<std::collections::BTreeSet<String>> = op
        .response
        .variants
        .iter()
        .map(|v| fail_required_fields(&v.fields))
        .collect();
    for i in 0..req.len() {
        for j in (i + 1)..req.len() {
            // i (earlier) shadows j only if j-responses also match i: their required
            // fields are a subset AND no captured discriminator (a conflicting attr
            // assertion, e.g. `type:"result"` vs `type:"error"`) sets them apart.
            if req[i].is_subset(&req[j])
                && !assertions_conflict(&op.response.variants[i], &op.response.variants[j])
            {
                return None;
            }
        }
    }

    let mut info: Vec<(String, String)> = Vec::new();
    let mut seen_struct: HashSet<String> = HashSet::new();
    for (v, (vname, struct_name)) in op.response.variants.iter().zip(names) {
        let (top, child_structs, enums) = collect_response_fields(&v.fields, &struct_name);
        let mut seen_f = HashSet::new();
        let top: Vec<_> = top
            .into_iter()
            .filter(|f| seen_f.insert(f.name.clone()))
            .collect();
        // A union nested in a variant's fields emits its enum inline (the module-level
        // shared-types pass skips outcome-union ops).
        for e in &enums {
            if seen_struct.insert(e.name.clone()) {
                out.extend(crate::fields::emit_enum_def(e));
            }
        }
        for cs in &child_structs {
            if !seen_struct.insert(cs.name.clone()) {
                continue;
            }
            out.push("#[derive(Debug, Clone, Default)]".to_string());
            out.push(format!("pub struct {} {{", cs.name));
            let mut sf = HashSet::new();
            for f in &cs.fields {
                if sf.insert(f.name.clone()) {
                    out.push(format!("    pub {}: {},", f.name, f.rust_type));
                }
            }
            out.push("}".to_string());
            out.push(String::new());
        }
        out.push("#[derive(Debug, Clone, Default)]".to_string());
        out.push(format!("pub struct {struct_name} {{"));
        for f in &top {
            out.push(format!("    pub {}: {},", f.name, f.rust_type));
        }
        out.push("}".to_string());
        out.push(String::new());
        info.push((vname, struct_name));
    }
    out.push(format!(
        "/// {doc} — RPC outcome union ({} variants).",
        info.len()
    ));
    out.push("#[derive(Debug, Clone)]".to_string());
    out.push(format!("pub enum {enum_name} {{"));
    for (vn, sn) in &info {
        out.push(format!("    {vn}({sn}),"));
    }
    out.push("}".to_string());
    out.push(String::new());
    Some(info)
}

/// Whether `op` actually generates an RPC outcome-union `enum` (vs falling back to the
/// single-shape struct). Single source of truth shared with [`generate_spec`]: a
/// fallback op still carries `response.variants` in the IR but emits the primary
/// mirror's struct/child-types/enums, which the module-level pass must then collect.
pub(crate) fn op_uses_outcome_union(op: &IqStanzaDef, child_prefix: &str) -> bool {
    if op.response.variants.is_empty() {
        return false;
    }
    let enum_name = format!("{child_prefix}Response");
    let mut sink = Vec::new();
    emit_outcome_types(op, child_prefix, &enum_name, "", &mut sink).is_some()
}

/// Emit the `parse_response` body for an outcome union: try each variant in order
/// (the RPC's own discrimination — first parser whose required fields all read wins)
/// and wrap the winner in its enum arm.
fn emit_outcome_parse(
    op: &IqStanzaDef,
    info: &[(String, String)],
    enum_name: &str,
    indent: &str,
) -> Vec<String> {
    let mut lines = Vec::new();
    for (i, (v, (vname, sname))) in op.response.variants.iter().zip(info).enumerate() {
        // The discriminator SELECTS; it does not bail. Spelled as a bail inside the payload
        // closure, a pin miss and a malformed payload were one `Err` and both moved on — so a
        // `type="result"` response whose success payload failed came back as the Error variant,
        // where the source dispatch takes the result path and rejects it. Review reported this
        // on the union cascade; this is the same emitter's twin on the response root, and
        // fixing one and not the other is the shape this branch keeps being caught for.
        //
        // A variant with NO pin is discriminated by its own required fields, exactly as an
        // unpinned union arm is, so there a failed parse IS the miss and it still falls through.
        let conds: Vec<String> = pin_conditions(v, "response");
        // A pin set is a discriminator only when it picks this variant ALONE. The committed
        // `WASmaxOutGroupsCreateRequest` pins both `CreateResponseSuccess` and
        // `CreateResponseGroupAlreadyExists` to `type="result"` and tells them apart by
        // disjoint required fields — `emit_outcome_types` admitted the pair for exactly that
        // reason — so making the first match terminal turned a group-already-exists response
        // into an error.
        //
        // Asked as "could a node that satisfies these conditions reach a LATER variant", not as
        // equality of the condition lists. Equality missed two shapes at once: the same pins
        // written in a different order, and a later variant pinning a SUPERSET, whose responses
        // this arm's own condition also matches. Later only — an earlier variant is tried first,
        // so a node it would take never reaches this one.
        let mine = variant_pins(v);
        let unique = !mine.is_empty()
            && !op.response.variants[i + 1..]
                .iter()
                .any(|o| pins_can_coincide(&mine, &variant_pins(o)));
        let pinned = unique;
        let body = if pinned {
            lines.push(format!("{indent}if {} {{", conds.join(" && ")));
            format!("{indent}    ")
        } else {
            indent.to_string()
        };
        lines.push(format!(
            "{body}let __r: Result<{sname}, anyhow::Error> = (|| -> Result<{sname}, anyhow::Error> {{"
        ));
        lines.extend(emit_response_parser(
            &v.fields,
            sname,
            &format!("{body}    "),
            sname,
        ));
        lines.push(format!("{body}}})();"));
        if pinned {
            lines.push(format!("{body}return Ok({enum_name}::{vname}(__r?));"));
            lines.push(format!("{indent}}}"));
        } else {
            lines.push(format!(
                "{body}if let Ok(__v) = __r {{ return Ok({enum_name}::{vname}(__v)); }}"
            ));
        }
    }
    lines.push(format!(
        "{indent}anyhow::bail!(\"{enum_name}: no response variant matched\")"
    ));
    lines
}

/// Discriminator guards the SUCCESS variant asserts on the response root
/// (`type:"result"` and any other fixed attr/content pins). Emitted at the top of a
/// single-shape FALLBACK parser — an op that carries `response.variants` but whose
/// outcomes couldn't be separated into an enum, so it mirrors the success shape.
/// Without the guard a non-success response (e.g. `<iq type="error">`) would decode
/// to an all-default struct; the guard makes it fail the success-shaped parse instead.
/// Empty for a pure single-shape op (no variants) — nothing to discriminate.
fn emit_success_guards(op: &IqStanzaDef, indent: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let Some(success) = op
        .response
        .variants
        .iter()
        .find(|v| v.kind == ResponseVariantKind::Success)
    else {
        return lines;
    };
    for a in &success.assertions {
        match a.kind {
            AssertionKind::Attr => {
                if let (Some(name), Some(value)) = (&a.name, &a.value) {
                    lines.push(format!(
                        "{indent}if response.get_attr({}).map(|x| x.as_str()).as_deref() != Some({}) {{ anyhow::bail!(\"not a success response: {} != {}\"); }}",
                        rust_lit(name),
                        rust_lit(value),
                        rust_lit_inner(name),
                        rust_lit_inner(value),
                    ));
                }
            }
            AssertionKind::Content => {
                if let Some(value) = &a.value {
                    lines.push(format!(
                        "{indent}if response.content_str() != Some({}) {{ anyhow::bail!(\"not a success response: content != {}\"); }}",
                        rust_lit(value),
                        rust_lit_inner(value),
                    ));
                }
            }
            // Tag (the `<iq>` root) / FromServer are not success-vs-error discriminators.
            // Neither is a Reference echo (`from` == the request's `to`): every outcome
            // of the same request satisfies it identically, so it separates nothing —
            // it is a request-correlation rule, enforced by whoever holds the request.
            AssertionKind::Tag | AssertionKind::FromServer | AssertionKind::Reference => {}
        }
    }
    lines
}

fn iq_type_str(t: IqType) -> &'static str {
    match t {
        IqType::Get => "get",
        IqType::Set => "set",
    }
}

static LET_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\blet (type|fn|loop|match|mod|pub|use|struct|impl|trait|enum)\b").unwrap()
});
// Captures struct-init field KEYS, including raw identifiers (`r#type`). Matches the
// identifier before `:` (explicit `key: value,`) OR `,` (field shorthand) — a nested
// repeated grandchild is emitted as `tag: tag_items,`, where the old `,`-only pattern
// captured the VALUE (`tag_items`) instead of the KEY (`tag`) and wrongly rejected an
// otherwise-valid parser. The acceptance check is one-directional (required ⊆ inited),
// so the extra value/`Default` matches the broader pattern admits are harmless.
static INIT_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(r#\w+|\w+)\s*[:,]").unwrap());
static LET_BINDING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\blet\s+(mut\s+)?(\w+)\b").unwrap());

/// Generate the Rust source for a single IQ stanza's spec.
/// The base (pre-dedup) `…Spec` struct name for an op: from its exported
/// function, falling back to the module name. The caller is responsible for
/// disambiguating collisions within a namespace (see [`generate_spec`]).
pub(crate) fn spec_base_name(op: &IqStanzaDef) -> String {
    let base = match &op.exported_function {
        // Skip `default` and the minifier's `$N` locals (e.g. usync's `$3`,
        // upload-prekeys' `$4`) — neither is a usable name; fall back to the
        // module name (`WAWebUsync` → `Usync`).
        Some(e) if e != "default" && !e.starts_with('$') => e.clone(),
        _ => op
            .module_name
            .strip_prefix("WAWeb")
            .unwrap_or(&op.module_name)
            .to_string(),
    };
    format!("{}Spec", pascal_case(&base))
}

/// Generate one `IqSpec` impl. `spec_name` is the (possibly disambiguated) struct
/// name chosen by the caller, so two ops in the same namespace never collide.
pub(crate) fn generate_spec(op: &IqStanzaDef, ns_const: &str, spec_name: &str) -> String {
    let mut lines: Vec<String> = Vec::new();

    let is_confirmation = op.response.fields.is_empty();
    let iq = iq_type_str(op.iq_type);

    // Spec fields from request-children attrs (skip const + generated id).
    let mut spec_fields: Vec<(String, &'static str, WapAttrKind)> = Vec::new();
    let mut seen_spec = HashSet::new();
    collect_attrs(&op.request.children, &mut spec_fields, &mut seen_spec);

    // Generate `build_iq`'s body first: it discovers each node's variant groups
    // (smax MixinGroup disjunctions), emitting the enum types and the extra spec
    // fields they require — both needed before the struct below.
    let spec_base = spec_name.trim_end_matches("Spec").to_string();
    let mut variant_enums: Vec<String> = Vec::new();
    let mut variant_fields: Vec<(String, String, bool)> = Vec::new();
    let build_iq_lines = emit_build_iq(
        op,
        ns_const,
        iq,
        &spec_base,
        &mut variant_enums,
        &mut variant_fields,
    );

    // ── Variant enums (top-level, before the struct that references them) ──
    lines.extend(variant_enums);

    let has_fields = !spec_fields.is_empty() || !variant_fields.is_empty();

    // ── Spec struct ──
    let doc_owner = op.exported_function.as_deref().unwrap_or(&op.namespace);
    lines.push(format!("/// {doc_owner}:{iq} IQ spec."));
    lines.push("///".to_string());
    lines.push(format!("/// Source: `{}`", op.module_name));
    if has_fields {
        lines.push("#[derive(Debug, Clone)]".to_string());
        lines.push(format!("pub struct {spec_name} {{"));
        for (name, ty, _) in &spec_fields {
            lines.push(format!("    pub {name}: {ty},"));
        }
        for (name, ty, _) in &variant_fields {
            lines.push(format!("    pub {name}: {ty},"));
        }
        lines.push("}".to_string());
    } else {
        lines.push("#[derive(Debug, Clone, Default)]".to_string());
        lines.push(format!("pub struct {spec_name};"));
    }
    lines.push(String::new());

    // ── Constructor ──
    if has_fields {
        lines.push(format!("impl {spec_name} {{"));
        let mut params: Vec<String> = spec_fields
            .iter()
            .map(|(name, ty, _)| match *ty {
                "String" => format!("{name}: impl Into<String>"),
                "Jid" => format!("{name}: &Jid"),
                _ => format!("{name}: {ty}"),
            })
            .collect();
        params.extend(
            variant_fields
                .iter()
                .map(|(name, ty, _)| format!("{name}: {ty}")),
        );
        lines.push(format!("    pub fn new({}) -> Self {{", params.join(", ")));
        lines.push("        Self {".to_string());
        for (name, ty, _) in &spec_fields {
            match *ty {
                "String" => lines.push(format!("            {name}: {name}.into(),")),
                "Jid" => lines.push(format!("            {name}: {name}.clone(),")),
                _ => lines.push(format!("            {name},")),
            }
        }
        for (name, _, _) in &variant_fields {
            lines.push(format!("            {name},"));
        }
        lines.push("        }".to_string());
        lines.push("    }".to_string());
        lines.push("}".to_string());
        lines.push(String::new());
    }

    // ── Response type ──
    // Child item structs are prefixed with the spec's base name so two specs in one
    // namespace can carry same-tagged children with incompatible shapes without a
    // struct-name collision (e.g. `tos` `<notice>` differs across specs).
    let child_prefix = spec_name.trim_end_matches("Spec");
    // An RPC outcome union (`response.variants`) becomes an `enum` over per-variant
    // structs — the wire-shape outcomes (success/error) the IR records, which the
    // single-struct path below can't express. Falls through to that path when any
    // variant's parser can't be generated cleanly (`emit_outcome_types` → None).
    let mut outcome_info: Vec<(String, String)> = Vec::new();
    let mut use_union = false;
    let mut response_type_name: String = "()".to_string();
    if !op.response.variants.is_empty() {
        let enum_name = format!("{child_prefix}Response");
        if let Some(info) = emit_outcome_types(
            op,
            child_prefix,
            &enum_name,
            &format!("{doc_owner}:{iq}"),
            &mut lines,
        ) {
            response_type_name = enum_name;
            outcome_info = info;
            use_union = true;
        }
    }
    if !use_union {
        if is_confirmation {
            response_type_name = "()".to_string();
        } else {
            let (mut top_fields, _, _) = collect_response_fields(&op.response.fields, child_prefix);
            let mut seen = HashSet::new();
            top_fields.retain(|f| seen.insert(f.name.clone()));
            if top_fields.is_empty() {
                response_type_name = "()".to_string();
            } else {
                response_type_name = format!("{}Response", spec_name.trim_end_matches("Spec"));
                lines.push(format!("/// Response from {doc_owner}:{iq}."));
                lines.push("#[derive(Debug, Clone, Default)]".to_string());
                lines.push(format!("pub struct {response_type_name} {{"));
                for f in &top_fields {
                    lines.push(format!("    pub {}: {},", f.name, f.rust_type));
                }
                lines.push("}".to_string());
                lines.push(String::new());
            }
        }
    }
    let effectively_confirmation = response_type_name == "()";

    // ── IqSpec impl ──
    lines.push(format!("impl IqSpec for {spec_name} {{"));
    lines.push(format!("    type Response = {response_type_name};"));
    lines.push(String::new());
    lines.extend(build_iq_lines);
    lines.push(String::new());

    // parse_response — validate the parser can produce all struct fields. Skipped
    // for outcome unions, which generate their own per-variant try-each parser.
    let mut can_generate = !effectively_confirmation && !use_union;
    if can_generate {
        let (check_fields, check_child_structs, _) =
            collect_response_fields(&op.response.fields, child_prefix);
        let names: Vec<&str> = check_fields.iter().map(|f| f.name.as_str()).collect();
        if names.iter().collect::<HashSet<_>>().len() != names.len() {
            can_generate = false;
        }
        if can_generate {
            let parser_code = emit_response_parser(
                &op.response.fields,
                &response_type_name,
                "        ",
                child_prefix,
            )
            .join("\n");
            for f in &check_fields {
                if !parser_code.contains(&format!("{},", f.name))
                    && !parser_code.contains(&format!("{}:", f.name))
                {
                    can_generate = false;
                    break;
                }
            }
            if can_generate && LET_KEYWORD.is_match(&parser_code) {
                can_generate = false;
            }
            if can_generate {
                'outer: for cs in &check_child_structs {
                    let required: HashSet<&str> =
                        cs.fields.iter().map(|f| f.name.as_str()).collect();
                    for body in struct_init_bodies(&parser_code, &cs.name) {
                        let inited: HashSet<&str> = INIT_FIELD
                            .captures_iter(body)
                            .map(|c| c.get(1).unwrap().as_str())
                            .collect();
                        if !required.iter().all(|r| inited.contains(r)) {
                            can_generate = false;
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    // Fall back to () if the parser can't be generated cleanly (non-union path).
    if !can_generate && !effectively_confirmation && !use_union {
        let marker = format!("/// Response from {doc_owner}:{iq}.");
        if let Some(start) = lines.iter().rposition(|l| *l == marker) {
            let mut end = start;
            while end < lines.len() && lines[end] != "}" {
                end += 1;
            }
            let remove_to = (end + 2).min(lines.len());
            lines.drain(start..remove_to);
        }
        response_type_name = "()".to_string();
        if let Some(idx) = lines.iter().position(|l| l.contains("type Response =")) {
            lines[idx] = "    type Response = ();".to_string();
        }
    }

    let resp_param = if effectively_confirmation || response_type_name == "()" {
        "_response"
    } else {
        "response"
    };
    if use_union {
        lines.push(
            "    #[allow(clippy::needless_update, unused_variables, clippy::redundant_closure_call)]"
                .to_string(),
        );
        lines.push(
            "    fn parse_response(&self, response: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {".to_string()
        );
        lines.extend(emit_outcome_parse(
            op,
            &outcome_info,
            &response_type_name,
            "        ",
        ));
    } else if effectively_confirmation || response_type_name == "()" {
        lines.push(format!(
            "    fn parse_response(&self, {resp_param}: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {{"
        ));
        lines.push("        Ok(())".to_string());
    } else {
        lines.push("    #[allow(clippy::needless_update, unused_variables)]".to_string());
        lines.push(format!(
            "    fn parse_response(&self, {resp_param}: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {{"
        ));
        // A single-shape FALLBACK (op had variants the outcome union couldn't separate)
        // mirrors the success shape; guard it so a non-success response fails rather
        // than decoding to all-defaults. A pure single-shape op adds nothing here.
        lines.extend(emit_success_guards(op, "        "));
        lines.extend(emit_response_parser(
            &op.response.fields,
            &response_type_name,
            "        ",
            child_prefix,
        ));
    }
    lines.push("    }".to_string());
    lines.push("}".to_string());

    fix_unused_vars(lines.join("\n"))
}

/// Emit the `fn build_iq` method (request builder), threading a [`VariantCtx`] so a
/// node's variant groups contribute their enums (`variant_enums`) and spec fields
/// (`variant_fields`) back to the caller.
#[allow(clippy::too_many_arguments)]
fn emit_build_iq(
    op: &IqStanzaDef,
    ns_const: &str,
    iq: &str,
    spec_base: &str,
    variant_enums: &mut Vec<String>,
    variant_fields: &mut Vec<(String, String, bool)>,
) -> Vec<String> {
    let mut lines = vec!["    fn build_iq(&self) -> InfoQuery<'static> {".to_string()];
    let target = if matches!(op.target, IqTarget::Group) {
        "Jid::new(\"\", Server::Group)"
    } else {
        "Jid::new(\"\", Server::Pn)"
    };
    if !op.request.children.is_empty() {
        let mut ctx = VariantCtx {
            spec_base,
            enum_defs: variant_enums,
            fields: variant_fields,
        };
        let mut top_var_names: Vec<String> = Vec::new();
        let mut used_names = std::collections::HashMap::new();
        for child in &op.request.children {
            let (child_lines, child_var) =
                emit_child_builder(child, "        ", &mut used_names, &mut ctx);
            lines.extend(child_lines);
            top_var_names.push(child_var);
        }
        lines.push(String::new());
        lines.push(format!("        InfoQuery::{iq}("));
        lines.push(format!("            {ns_const},"));
        lines.push(format!("            {target},"));
        lines.push(format!(
            "            Some(NodeContent::Nodes(vec![{}])),",
            top_var_names.join(", ")
        ));
        lines.push("        )".to_string());
    } else {
        lines.push(format!(
            "        InfoQuery::{iq}({ns_const}, {target}, None)"
        ));
    }
    lines.push("    }".to_string());
    lines
}

fn collect_attrs(
    children: &[WapChildNode],
    out: &mut Vec<(String, &'static str, WapAttrKind)>,
    seen: &mut HashSet<String>,
) {
    for child in children {
        for attr in &child.attrs {
            if !matches!(attr.kind, WapAttrKind::Const | WapAttrKind::GeneratedId) {
                let ident = rust_ident(&attr.name);
                if seen.insert(ident.clone()) {
                    out.push((ident, rust_attr_type(&attr.kind), attr.kind.clone()));
                }
            }
        }
        collect_attrs(&child.children, out, seen);
    }
}

/// Prefix single-use `let` bindings with `_` to silence unused-variable lints.
fn fix_unused_vars(mut code: String) -> String {
    let vars: Vec<String> = LET_BINDING
        .captures_iter(&code)
        .filter_map(|c| c.get(2).map(|m| m.as_str().to_string()))
        .collect();
    for var in vars {
        if var.starts_with('_') {
            continue;
        }
        // A whole-code occurrence count of 1 means the name appears only in its
        // own `let` binding (and no superstring contains it), so a single literal
        // replacement of that binding is exact — no regex needed.
        if code.matches(&var).count() <= 1 {
            let with_mut = format!("let mut {var}");
            if code.contains(&with_mut) {
                code = code.replacen(&with_mut, &format!("let mut _{var}"), 1);
            } else {
                code = code.replacen(&format!("let {var}"), &format!("let _{var}"), 1);
            }
        }
    }
    code
}

/// Bodies of `name { ... }` struct-init blocks in `code` (everything between each
/// `name`-prefixed `{` and the next `}`). Mirrors the old `(?s)name\s*\{([^}]*)\}`
/// scan without compiling a per-name regex.
fn struct_init_bodies<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(rel) = code[from..].find(name) {
        let after = from + rel + name.len();
        let rest = &code[after..];
        let trimmed = rest.trim_start();
        if !trimmed.starts_with('{') {
            from = after;
            continue;
        }
        let body_start = after + (rest.len() - trimmed.len()) + 1;
        match code[body_start..].find('}') {
            Some(end_rel) => {
                out.push(&code[body_start..body_start + end_rel]);
                from = body_start + end_rel + 1;
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{IqRequestDef, ParsedResponse};

    fn conflict_attr(name: &str, value: Option<&str>) -> wa_ir::ResponseAssertion {
        wa_ir::ResponseAssertion {
            kind: AssertionKind::Attr,
            name: Some(name.to_string()),
            value: value.map(str::to_string),
            reference_path: None,
        }
    }

    fn conflict_variant(assertions: Vec<wa_ir::ResponseAssertion>) -> wa_ir::ResponseVariant {
        wa_ir::ResponseVariant {
            assertions,
            ..Default::default()
        }
    }

    #[test]
    fn a_presence_only_assertion_does_not_conflict_with_a_pin() {
        // A parser that merely requires `type` to EXIST also accepts `type="result"`, so
        // the two variants are not disjoint. Treating `Some("result") != None` as a
        // conflict let the separability gate emit a first-success cascade whose earlier
        // arm shadows the later one.
        let pinned = conflict_variant(vec![conflict_attr("type", Some("result"))]);
        let present = conflict_variant(vec![conflict_attr("type", None)]);
        assert!(!assertions_conflict(&pinned, &present));
        assert!(!assertions_conflict(&present, &pinned));
        // Two different pins on the same attribute still conflict.
        let other = conflict_variant(vec![conflict_attr("type", Some("error"))]);
        assert!(assertions_conflict(&pinned, &other));
    }

    fn stanza(module: &str, exported: Option<&str>) -> IqStanzaDef {
        IqStanzaDef {
            module_name: module.into(),
            namespace: "w:test".into(),
            iq_type: IqType::Get,
            target: IqTarget::Server,
            parser_name: "p".into(),
            exported_function: exported.map(str::to_string),
            all_exports: vec![],
            request: IqRequestDef {
                namespace: "w:test".into(),
                iq_type: IqType::Get,
                target: IqTarget::Server,
                children: vec![],
            },
            response: ParsedResponse {
                parser_name: "unknown".into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn spec_base_name_falls_back_to_module_for_minified_exports() {
        // A real exported name is used as-is.
        assert_eq!(
            spec_base_name(&stanza("WAWebGetThing", Some("queryThing"))),
            "QueryThingSpec"
        );
        // Minifier `$N` locals (usync `$3`, upload-prekeys `$4`) and `default`
        // fall back to the module name (sans the `WAWeb` prefix).
        assert_eq!(
            spec_base_name(&stanza("WAWebUsync", Some("$3"))),
            "UsyncSpec"
        );
        assert_eq!(
            spec_base_name(&stanza("WAWebUploadPrekeysForRegTask", Some("$4"))),
            "UploadPrekeysForRegTaskSpec"
        );
        assert_eq!(
            spec_base_name(&stanza("WAWebFoo", Some("default"))),
            "FooSpec"
        );
    }

    #[test]
    fn struct_init_bodies_extracts_each_block() {
        let code = "EntryItem {\n    a,\n    b,\n}\nnoise EntryItem { c }";
        let bodies = struct_init_bodies(code, "EntryItem");
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("a,") && bodies[0].contains("b,"));
        assert_eq!(bodies[1].trim(), "c");
    }

    #[test]
    fn struct_init_bodies_ignores_name_not_followed_by_brace() {
        assert!(struct_init_bodies("let EntryItem = 1;", "EntryItem").is_empty());
    }

    #[test]
    fn success_guards_discriminate_fallback_single_shape() {
        // A success variant pinned to `type:"result"` produces a top-of-parser guard,
        // so a single-shape fallback rejects a non-success (`type:"error"`) response.
        let mut s = stanza("WASmaxOutThing", Some("getThing"));
        s.response.variants = vec![ResponseVariant {
            tag: "GetThingResponseSuccess".into(),
            module_name: "WASmaxInThingGetThingResponseSuccess".into(),
            kind: ResponseVariantKind::Success,
            assertions: vec![wa_ir::ResponseAssertion {
                kind: AssertionKind::Attr,
                name: Some("type".into()),
                value: Some("result".into()),
                reference_path: None,
            }],
            fields: vec![],
            ..Default::default()
        }];
        let guards = emit_success_guards(&s, "    ");
        assert_eq!(guards.len(), 1);
        assert!(
            guards[0].contains(
                "response.get_attr(\"type\").map(|x| x.as_str()).as_deref() != Some(\"result\")"
            ) && guards[0].contains("anyhow::bail!"),
            "{}",
            guards[0]
        );
        // A pure single-shape op (no variants) adds no guard.
        assert!(emit_success_guards(&stanza("WAWebThing", Some("getThing")), "    ").is_empty());
    }

    #[test]
    fn outcome_union_generates_enum_and_try_each_parse() {
        use wa_ir::{ParsedField, ParsedFieldType, ResponseVariant, ResponseVariantKind};
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                required: true,
                ..Default::default()
            }
        }
        let mut op = stanza("WASmaxOutFooGetThingRequest", Some("makeGetThingRequest"));
        op.response = ParsedResponse {
            parser_name: "FooGetThingRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "GetThingResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![],
                    fields: vec![attr("token")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "GetThingResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    assertions: vec![],
                    fields: vec![attr("code")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeGetThingRequestSpec");
        // One enum over per-variant structs (prefix stripped to the discriminating tail).
        assert!(
            code.contains("pub enum MakeGetThingRequestResponse {"),
            "{code}"
        );
        assert!(
            code.contains("Success(MakeGetThingRequestSuccess)"),
            "{code}"
        );
        assert!(code.contains("Error(MakeGetThingRequestError)"), "{code}");
        assert!(
            code.contains("type Response = MakeGetThingRequestResponse;"),
            "{code}"
        );
        // Try-each parse: first variant whose required fields all read wins.
        assert!(
            code.contains("return Ok(MakeGetThingRequestResponse::Success(__v));"),
            "{code}"
        );
        assert!(
            code.contains("MakeGetThingRequestResponse: no response variant matched"),
            "{code}"
        );
    }

    #[test]
    fn a_variant_a_later_superset_can_also_take_is_not_unique() {
        use wa_ir::{
            ParsedField, ParsedFieldType, ResponseAssertion, ResponseVariant, ResponseVariantKind,
        };
        // Equality of the pin lists is the wrong question. A variant pinning `type="result"`
        // followed by one pinning `type="result"` AND `kind="special"` has a DIFFERENT list, so
        // ordered equality called it unique — but every response the second takes, the first's
        // own condition also matches, so making it terminal means the second is never tried.
        // The question is whether a node satisfying these conditions can reach a later variant.
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                required: true,
                ..Default::default()
            }
        }
        fn pin(name: &str, value: &str) -> ResponseAssertion {
            ResponseAssertion {
                kind: AssertionKind::Attr,
                name: Some(name.into()),
                value: Some(value.into()),
                reference_path: None,
            }
        }
        let mut op = stanza("WASmaxOutFooWideRequest", Some("makeWideRequest"));
        op.response = ParsedResponse {
            parser_name: "FooWideRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "WideResponsePlain".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![pin("type", "result")],
                    fields: vec![attr("plainOnly")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "WideResponseSpecial".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![pin("type", "result"), pin("kind", "special")],
                    fields: vec![attr("specialOnly")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeWideRequestSpec");
        assert!(
            code.contains(
                "if let Ok(__v) = __r { return Ok(MakeWideRequestResponse::Plain(__v)); }"
            ),
            "the wider pin cannot be terminal:\n{code}"
        );
        // The bound: pins that CONTRADICT rule each other out, so a node matching one cannot
        // reach the other and the first is a discriminator after all.
        op.response.variants[1].assertions = vec![pin("type", "error")];
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeWideRequestSpec");
        assert!(
            code.contains("return Ok(MakeWideRequestResponse::Plain(__r?));"),
            "disagreeing pins separate the two:\n{code}"
        );
    }

    #[test]
    fn variants_sharing_a_pin_still_cascade() {
        use wa_ir::{
            ParsedField, ParsedFieldType, ResponseAssertion, ResponseVariant, ResponseVariantKind,
        };
        // A pin set is a discriminator only when it picks ONE variant. The committed
        // `WASmaxOutGroupsCreateRequest` pins both its success and its group-already-exists
        // outcomes to `type="result"` and tells them apart by disjoint required fields — which
        // is exactly why `emit_outcome_types` admits the pair — so making the first match
        // terminal turned a real response into an error. Sharing a pin puts a variant back on
        // the first-success side, where its own payload is the only thing that can select it.
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                required: true,
                ..Default::default()
            }
        }
        fn type_assert(value: &str) -> ResponseAssertion {
            ResponseAssertion {
                kind: AssertionKind::Attr,
                name: Some("type".into()),
                value: Some(value.into()),
                reference_path: None,
            }
        }
        let mut op = stanza("WASmaxOutFooCreateRequest", Some("makeCreateRequest"));
        op.response = ParsedResponse {
            parser_name: "FooCreateRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "CreateResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![type_assert("result")],
                    fields: vec![attr("groupId")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "CreateResponseGroupAlreadyExists".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![type_assert("result")],
                    fields: vec![attr("existingId")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeCreateRequestSpec");
        // The EARLIER of the pair must fall through: its pin does not tell it from the one
        // below, so a failed payload is still a miss.
        assert!(
            code.contains(
                "if let Ok(__v) = __r { return Ok(MakeCreateRequestResponse::Success(__v)); }"
            ),
            "a shared pin is not a discriminator:\n{code}"
        );
        // The LAST one may be terminal, and should be: nothing below it could have taken the
        // node, so its payload error is the only answer left — and the tail below it bails
        // anyway, with a less precise message.
        assert!(
            code.contains("return Ok(MakeCreateRequestResponse::GroupAlreadyExists(__r?));"),
            "the last matching variant has nothing to fall through to:\n{code}"
        );
    }

    #[test]
    fn conflicting_assertions_separate_subset_variants_into_enum() {
        use wa_ir::{
            ParsedField, ParsedFieldType, ResponseAssertion, ResponseVariant, ResponseVariantKind,
        };
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                required: true,
                ..Default::default()
            }
        }
        fn type_assert(value: &str) -> ResponseAssertion {
            ResponseAssertion {
                kind: AssertionKind::Attr,
                name: Some("type".into()),
                value: Some(value.into()),
                reference_path: None,
            }
        }
        // Success and error read the same field (`type`) — a bare subset that WOULD be
        // ambiguous — but their captured `type` discriminators differ, so the guard
        // must emit a (correctly-discriminated) enum, with a guard per arm.
        let mut op = stanza("WASmaxOutFooGetThingRequest", Some("makeGetThingRequest"));
        op.response = ParsedResponse {
            parser_name: "FooGetThingRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "GetThingResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![type_assert("result")],
                    fields: vec![attr("type")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "GetThingResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    assertions: vec![type_assert("error")],
                    fields: vec![attr("type")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeGetThingRequestSpec");
        assert!(
            code.contains("pub enum MakeGetThingRequestResponse"),
            "{code}"
        );
        // Each arm guards on its pin — as a SELECTOR now rather than as a bail inside the
        // payload closure, which is what separates a discriminator miss from a payload that
        // failed. Spelled the other way, a `type="result"` response whose success payload failed
        // came back as the Error variant.
        assert!(
            code.contains(
                "if response.get_attr(\"type\").map(|x| x.as_str()).as_deref() == Some(\"result\") {"
            ),
            "success arm must select on type==result: {code}"
        );
        assert!(
            code.contains(
                "if response.get_attr(\"type\").map(|x| x.as_str()).as_deref() == Some(\"error\") {"
            ),
            "error arm must select on type==error: {code}"
        );
        // And its payload error is the answer, rather than the next variant's parse.
        assert!(
            code.contains("return Ok(MakeGetThingRequestResponse::Success(__r?));"),
            "the selected arm's payload error is propagated: {code}"
        );
    }

    #[test]
    fn ambiguous_outcome_union_falls_back_not_misclassifies() {
        use wa_ir::{ParsedField, ParsedFieldType, ResponseVariant, ResponseVariantKind};
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                required: true,
                ..Default::default()
            }
        }
        // A type-only success precedes type-only errors (their real discriminators —
        // type value, <error> child — aren't captured): the success would shadow the
        // errors. The codegen must NOT emit a (misclassifying) enum.
        let mut op = stanza("WASmaxOutFooGetThingRequest", Some("makeGetThingRequest"));
        op.response = ParsedResponse {
            parser_name: "FooGetThingRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "GetThingResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    assertions: vec![],
                    fields: vec![attr("type")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "GetThingResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    assertions: vec![],
                    fields: vec![attr("type")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeGetThingRequestSpec");
        assert!(
            !code.contains("pub enum MakeGetThingRequestResponse"),
            "ambiguous union must not generate an enum: {code}"
        );
    }

    #[test]
    fn fix_unused_vars_underscores_single_use_bindings() {
        // `x` is used; `y`/`z` are not.
        let code = "let x = 1;\nlet mut y = Vec::new();\nlet z = foo();\nuse_it(x);".to_string();
        let out = fix_unused_vars(code);
        assert!(out.contains("let x = 1;"), "used binding untouched");
        assert!(
            out.contains("let mut _y = Vec::new();"),
            "unused mut binding"
        );
        assert!(out.contains("let _z = foo();"), "unused binding");
    }
}
