//! Generate one `IqSpec` impl (struct + constructor + response + build/parse).

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use wa_ir::{
    AssertionKind, IqStanzaDef, IqTarget, IqType, ResponseVariant, ResponseVariantKind,
    WapAttrKind, WapChildNode,
};

/// Two outcome variants are separable by a discriminator when a response satisfying one fails
/// the other's guard, so neither can shadow the other.
///
/// The exact complement of [`pins_can_coincide`], and it is spelled as one. This was a second
/// copy of that relation restricted to attributes, so the round that taught the SELECTOR about
/// content pins left the ADMISSION gate behind it: two outcomes separated by `literalContent`
/// were still judged to shadow each other, the union was refused, and the guard emitted for
/// them was never reached. A rule fixed at one end and not the other, which is the shape this
/// branch keeps being caught for — so there is one end now.
///
/// A presence-only assertion (`value: None`) is not a pin and never conflicts: a parser that
/// merely requires `type` to exist also accepts `type="result"`, so the variants are not
/// disjoint. [`variant_pins`] drops it for that reason, and this inherits the answer.
pub(crate) fn assertions_conflict(a: &ResponseVariant, b: &ResponseVariant) -> bool {
    !pins_can_coincide(&variant_pins(a), &variant_pins(b))
}

use crate::emit::{VariantCtx, emit_child_builder, emit_response_parser};
use crate::fields::{collect_response_fields, rust_attr_type};
use crate::naming::{fmt_lit_inner, pascal_case, rust_ident, rust_lit};

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

/// The reads whose absence makes a generated variant parser return `Err`
/// (so they discriminate which variant a response matches): required attrs
/// (`attr…`, read with `?`) and required `child` nodes (read with `ok_or_else`).
/// Excludes optionals (`maybe…`) and untyped union/mixin placeholders (`method == ""`).
/// Recursive.
///
/// A REQUIRED content read belongs here too, and did not while every content decoder ended in
/// `unwrap_or_default` — a read that cannot fail cannot discriminate. It fails now: an absent or
/// undecodable payload is an error, so a variant that requires its node's content really does
/// bail where a fallback variant would not. Leaving it out left two such outcomes looking like
/// empty signatures, which the union gate reads as indistinguishable, so a discriminable pair
/// was rejected and only the fallback shape emitted.
///
/// Keyed by what the parser READS, not by the struct field it writes: the descent path,
/// then the wire attribute name or the child tag. Two variants can name the same wire
/// attribute differently — `{name: "success_code", wire_name: "code"}` against
/// `{name: "error_code", wire_name: "code"}` — and by output name those sets look disjoint,
/// so the shadowing gate below admitted a union whose first parser accepts every response
/// the second could and left the second unreachable. The `attr`/`child` marker keeps an
/// attribute and a child tag of the same spelling apart, and the path keeps a nested `code`
/// from standing in for a top-level one.
fn fail_required_fields(fields: &[wa_ir::ParsedField]) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    fn walk(
        fields: &[wa_ir::ParsedField],
        base: &[String],
        reached: bool,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        for f in fields {
            let mut path = base.to_vec();
            path.extend(f.source_path.iter().flatten().cloned());
            // `f.required` alongside the method test is belt and braces: the accessor
            // vocabulary already carries optionality, so an optional attribute reads
            // `maybeAttrString` — which does not start with `attr` — and an optional child
            // reads `maybeChild`. No well-formed IR separates the two conditions, and the
            // mutation dropping `f.required` changes no answer. Kept because the alternative is
            // code that depends on that invariant without saying so.
            // Content has no NAME — it is the node's own payload — so the descent path is the
            // whole of its identity, which is exactly what distinguishes one node's content
            // from another's.
            if reached && f.parser_required && wa_ir::wap::is_content_method(&f.method) {
                out.insert(format!("{}/content", path.join("/")));
            }
            // …and a REPEATED child fails on nothing. Its parser iterates `get_children_by_tag`
            // and succeeds with an empty vector where the child is absent, so recording it as
            // fail-on-absent gave two variants a difference their parsers do not have — and the
            // gate then admitted a union whose first arm accepts the later arm's response.
            let repeated = f.repeats == Some(true);
            if reached
                && f.parser_required
                && !repeated
                && (f.method == "child" || f.method.starts_with("attr"))
            {
                let (kind, wire) = if f.method == "child" {
                    ("child", f.tag.as_deref().unwrap_or(&f.name))
                } else {
                    ("attr", f.wire_name.as_deref().unwrap_or(&f.name))
                };
                out.insert(format!("{}/{kind}:{wire}", path.join("/")));
            }
            if let Some(kids) = &f.children {
                let mut inner = path;
                if f.method == "child" || f.method == "maybeChild" {
                    inner.push(f.tag.as_deref().unwrap_or(&f.name).to_string());
                }
                // Under an OPTIONAL child nothing is fail-on-absent: the emitter defaults the
                // whole subtree when that child is missing, so a required attribute inside it
                // does not make the parser bail and cannot discriminate a variant. The walk
                // recorded it anyway, and once round forty-six qualified these keys by path
                // that false requirement could differ from a later variant's real one — so the
                // subset gate admitted a union whose first arm then took the later response.
                walk(kids, &inner, reached && f.parser_required, out);
            }
        }
    }
    walk(fields, &[], true, &mut out);
    out
}

/// Emit, for an RPC outcome-union response, a `#[derive(Default)]` struct per
/// variant (and its child item structs) plus an `enum` wrapping them. Returns
/// `(variant_name, struct_name)` per variant for the parser — but only when EVERY
/// variant's parser validates ([`parser_is_valid`]); otherwise an error identifies
/// the variant and nothing is emitted. The caller retains legacy response types
/// but emits a diagnostic error instead of silently dropping outcomes.
/// A value a response variant pins before it will accept a node.
///
/// Two kinds, because an outcome root has two things to pin: an ATTRIBUTE by name, and the
/// node's own text CONTENT, which `literalContent` writes and which has no name at all.
/// Modelling the set as `(name, value)` pairs kept the first and dropped the second, so a
/// content-discriminated arm emitted no selector and took every response whose required fields
/// happened to parse — whichever content value made the source parser select a later one.
#[derive(PartialEq, Eq)]
enum Pin<'a> {
    Attr(&'a str, &'a str),
    Content(&'a str),
}

/// The pins a response variant asserts — the set that has to pick this variant alone before a
/// match may be treated as final.
fn variant_pins(v: &ResponseVariant) -> Vec<Pin<'_>> {
    v.assertions
        .iter()
        .filter_map(|a| match a.kind {
            AssertionKind::Attr => match (&a.name, &a.value) {
                (Some(name), Some(value)) => Some(Pin::Attr(name.as_str(), value.as_str())),
                _ => None,
            },
            // `name` is unused for a content pin; the value is the whole of it.
            AssertionKind::Content => a.value.as_deref().map(Pin::Content),
            _ => None,
        })
        .collect()
}

/// The same pins as generated conditions.
fn pin_conditions(v: &ResponseVariant, node: &str) -> Vec<String> {
    let mut conditions: Vec<String> = variant_pins(v)
        .into_iter()
        .map(|pin| match pin {
            Pin::Attr(name, value) => format!(
                "{node}.get_attr({}).map(|x| x.as_str()).as_deref() == Some({})",
                rust_lit(name),
                rust_lit(value),
            ),
            Pin::Content(value) => format!(
                "{node}.content_str().as_deref() == Some({})",
                rust_lit(value),
            ),
        })
        .collect();
    // flattenedChildWithTag is a presence guard even when no payload is read.
    // Keep it in both the admission signature and the emitted selector.
    conditions.extend(v.assertions.iter().filter_map(|a| {
        (a.kind == AssertionKind::Child)
            .then_some(a.name.as_deref())
            .flatten()
            .map(|name| {
                format!(
                    "{node}.get_children_by_tag({}).count() == 1",
                    rust_lit(name)
                )
            })
    }));
    conditions.extend(v.assertions.iter().filter_map(|a| {
        if a.kind == AssertionKind::Tag {
            a.name
                .as_ref()
                .map(|name| format!("{node}.tag == {}", rust_lit(name)))
        } else {
            None
        }
    }));
    if let Some(error) = error_selection(v, node) {
        conditions.push(error);
    }
    conditions
}

/// Whether a node satisfying `mine` could satisfy `other` as well.
///
/// Only a pin the two disagree on rules that out — anything `other` pins and `mine` does not is
/// a value the node is free to carry, and a pin `mine` has that `other` lacks constrains
/// nothing about `other`. So a variant pinning a SUPERSET of another's is still reachable
/// through it, and an unpinned variant is reachable through every one of them.
fn pins_can_coincide(mine: &[Pin<'_>], other: &[Pin<'_>]) -> bool {
    !mine.iter().any(|m| {
        other.iter().any(|o| match (m, o) {
            (Pin::Attr(name, value), Pin::Attr(o_name, o_value)) => {
                name == o_name && value != o_value
            }
            // A node has ONE text content, so two variants pinning it to different values are
            // as exclusive as two disagreeing on an attribute.
            (Pin::Content(value), Pin::Content(o_value)) => value != o_value,
            _ => false,
        })
    })
}

/// Error predicates are sets of (integer code, optional text pin). Compare unions
/// of intervals only; this does not model arbitrary parser control flow.
fn error_arms_cover(earlier: &[wa_ir::ErrorArm], later: &[wa_ir::ErrorArm]) -> bool {
    fn band(arm: &wa_ir::ErrorArm) -> (i128, i128) {
        let min = arm.code.or(arm.code_min).unwrap_or(i64::MIN);
        let max = arm.code.or(arm.code_max).unwrap_or(i64::MAX);
        (i128::from(min), i128::from(max))
    }
    later.iter().all(|arm| {
        let (mut cursor, end) = band(arm);
        let mut bands: Vec<_> = earlier
            .iter()
            .filter(|a| a.text.is_none() || (arm.text.is_some() && a.text == arm.text))
            .map(band)
            .collect();
        bands.sort_unstable();
        for (lo, hi) in bands {
            if lo > cursor {
                break;
            }
            cursor = cursor.max(hi + 1);
            if cursor > end {
                return true;
            }
        }
        cursor > end
    })
}

/// The direct, bounded code/text error union observed in the pilots. Unknown
/// payload structures use the ordinary admission path, never this specialization.
fn direct_error_payload(v: &ResponseVariant) -> Option<&wa_ir::ParsedField> {
    use wa_ir::ParsedFieldType;
    if v.error_arms.is_empty() || v.error_envelope.is_some() || v.fields.len() != 2 {
        return None;
    }
    let payload = v.fields.iter().find(|f| {
        f.parser_required
            && f.source_path.as_deref() == Some(&["error".to_string()])
            && f.field_type == ParsedFieldType::Union
    })?;
    if !v.fields.iter().any(|f| {
        f.method == "attrString"
            && f.parser_required
            && f.wire_name.as_deref().unwrap_or(&f.name) == "type"
            && f.literal_value.as_deref() == Some("error")
    }) {
        return None;
    }
    let variants = payload.union_variants.as_ref()?;
    if crate::union::classify_union(payload).is_none() || variants.len() != v.error_arms.len() {
        return None;
    }
    for (variant, arm) in variants.iter().zip(&v.error_arms) {
        let lo = arm.code.or(arm.code_min)?;
        let hi = arm.code.or(arm.code_max)?;
        // This decoder only needs exact small integers. Values outside the band
        // cannot round into it under the source's JS parseInt/Number semantics.
        if lo < 0
            || hi > i64::from(i32::MAX)
            || lo > hi
            || arm.name.as_deref() != Some(&variant.name)
        {
            return None;
        }
        let code = variant
            .fields
            .iter()
            .find(|f| f.wire_name.as_deref().unwrap_or(&f.name) == "code")?;
        let text = variant
            .fields
            .iter()
            .find(|f| f.wire_name.as_deref().unwrap_or(&f.name) == "text")?;
        if code.method != "attrInt"
            || !code.parser_required
            || code.field_type != ParsedFieldType::Integer
            || code
                .literal_value
                .as_ref()
                .and_then(|s| s.parse::<i64>().ok())
                != arm.code
            || code.int_min != arm.code_min
            || code.int_max != arm.code_max
            || text.method != "attrString"
            || !text.parser_required
            || text.literal_value != arm.text
        {
            return None;
        }
        // Apart from code/text, the pilot has optional <field name=… reason=…>.
        // No unbounded coercion, repeated tree or opaque union is inferred here.
        if variant.fields.iter().any(|f| {
            let wire = f.wire_name.as_deref().unwrap_or(&f.name);
            if wire == "code" || wire == "text" {
                return false;
            }
            !(f.method == "child"
                && !f.parser_required
                && f.repeats != Some(true)
                && f.source_path.is_none()
                && f.children.as_ref().is_some_and(|children| {
                    children.iter().all(|c| {
                        c.method == "attrString" && c.source_path.is_none() && c.children.is_none()
                    })
                }))
        }) {
            return None;
        }
    }
    Some(payload)
}

fn error_arm_condition(arm: &wa_ir::ErrorArm) -> String {
    let mut terms = Vec::new();
    if let Some(code) = arm.code {
        terms.push(format!("code == {code}i64"));
    }
    if let Some(min) = arm.code_min {
        terms.push(format!("code >= {min}i64"));
    }
    if let Some(max) = arm.code_max {
        terms.push(format!("code <= {max}i64"));
    }
    if let Some(text) = &arm.text {
        terms.push(format!(
            "error.get_attr(\"text\").map(|v| v.as_str()).as_deref() == Some({})",
            rust_lit(text)
        ));
    }
    format!("({})", terms.join(" && "))
}

fn error_selection(v: &ResponseVariant, node: &str) -> Option<String> {
    direct_error_payload(v)?;
    let arms: Vec<_> = v.error_arms.iter().map(error_arm_condition).collect();
    Some(format!(
        "({node}.get_children_by_tag(\"error\").count() == 1 && {node}.get_optional_child(\"error\").is_some_and(|error| error.get_attr(\"text\").is_some() && error.get_attr(\"code\").and_then(|v| __iq_error_code(v.as_str())).is_some_and(|code| {})))",
        arms.join(" || ")
    ))
}

/// Source WASmaxParseUtils uses parseInt(value, 10), not Rust's whole-string
/// integer parse. Overflow is outside every admitted error-code band.
fn emit_error_code_decoder(indent: &str) -> Vec<String> {
    r#"fn __iq_error_code(value: &str) -> Option<i64> {
    let value = value.trim_start_matches(|c| matches!(c, '\u{0009}'..='\u{000d}' | ' ' | '\u{00a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'));
    let offset = usize::from(matches!(value.as_bytes().first(), Some(b'+') | Some(b'-')));
    let end = offset + value.bytes().skip(offset).take_while(u8::is_ascii_digit).count();
    if end == offset { None } else { value[..end].parse().ok() }
}"#.lines().map(|line| format!("{indent}{line}")).collect()
}

fn emit_direct_error_parser(
    v: &ResponseVariant,
    payload: &wa_ir::ParsedField,
    sname: &str,
    indent: &str,
) -> Vec<String> {
    let ename = crate::union::enum_name(payload, sname);
    let mut lines = vec![
        format!(
            "{indent}let error = response.get_optional_child(\"error\").ok_or_else(|| anyhow::anyhow!(\"missing error\"))?;"
        ),
        format!(
            "{indent}let code = error.get_attr(\"code\").and_then(|v| __iq_error_code(v.as_str())).ok_or_else(|| anyhow::anyhow!(\"invalid error code\"))?;"
        ),
        format!("{indent}let payload = (|| -> Result<{ename}, anyhow::Error> {{"),
    ];
    for (variant, arm) in payload
        .union_variants
        .as_ref()
        .unwrap()
        .iter()
        .zip(&v.error_arms)
    {
        let vname = pascal_case(&variant.name);
        let struct_name = format!("{ename}{vname}");
        let code_field = variant
            .fields
            .iter()
            .find(|f| f.wire_name.as_deref().unwrap_or(&f.name) == "code")
            .unwrap();
        let fields: Vec<_> = variant
            .fields
            .iter()
            .filter(|f| f.wire_name.as_deref().unwrap_or(&f.name) != "code")
            .cloned()
            .collect();
        let mut conditions = vec![error_arm_condition(arm)];
        for child in fields.iter().filter(|f| f.method == "child") {
            conditions.push(format!(
                "error.get_children_by_tag({}).count() <= 1",
                rust_lit(child.tag.as_deref().unwrap_or(&child.name))
            ));
        }
        lines.push(format!("{indent}    if {} {{", conditions.join(" && ")));
        lines.push(format!(
            "{indent}        let parsed = (|| -> Result<{struct_name}, anyhow::Error> {{"
        ));
        lines.extend(crate::emit::emit_struct_parser(
            &fields,
            "error",
            &struct_name,
            &format!("{indent}            "),
            &struct_name,
        ));
        lines.push(format!("{indent}        }})();"));
        // The source disjunction tries the next parser after *any* failure,
        // including a malformed specific payload. Do not commit on code/text:
        // SetSubject 406/not-acceptable can still reach the 400..499 fallback.
        lines.push(format!("{indent}        if let Ok(mut value) = parsed {{ value.{} = code as {}; return Ok({ename}::{vname}(value)); }}", rust_ident(&code_field.name), crate::fields::integer_width(code_field)));
        lines.push(format!("{indent}    }}"));
    }
    lines.push(format!(
        "{indent}    anyhow::bail!(\"no error payload matched\")"
    ));
    lines.push(format!("{indent}}})()?;"));
    let header = v
        .fields
        .iter()
        .find(|f| f.field_type != wa_ir::ParsedFieldType::Union)
        .unwrap();
    lines.push(format!(
        "{indent}Ok({sname} {{ {}: \"error\".to_string(), {}: Some(payload) }})",
        rust_ident(&header.name),
        rust_ident(&payload.name)
    ));
    lines
}

/// The context entry point currently supports the two direct wire echoes proven
/// by the pilots. Other reference paths are diagnosed rather than guessed.
fn correlation_requirements(op: &IqStanzaDef) -> Result<Vec<(&str, &str)>, String> {
    fn references(assertions: &[wa_ir::ResponseAssertion]) -> Result<Vec<(&str, &str)>, String> {
        let mut out = Vec::new();
        for a in assertions
            .iter()
            .filter(|a| a.kind == AssertionKind::Reference)
        {
            match (a.name.as_deref(), a.reference_path.as_deref()) {
                (Some("id"), Some(path)) if path == ["id"] => out.push(("id", "request_id")),
                (Some("from"), Some(path)) if path == ["to"] => out.push(("from", "request_to")),
                _ => {
                    return Err(
                        "guards.reference_unsupported: expected id=request.id or from=request.to"
                            .into(),
                    );
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }
    let mut common = references(&op.response.assertions)?;
    if let Some(first) = op.response.variants.first() {
        let required = references(&first.assertions)?;
        for variant in &op.response.variants[1..] {
            if references(&variant.assertions)? != required {
                return Err(
                    "guards.reference_nonuniform: outcome references require distinct contexts"
                        .into(),
                );
            }
        }
        common.extend(required);
    }
    common.sort_unstable();
    common.dedup();
    Ok(common)
}

fn emit_outcome_types(
    op: &IqStanzaDef,
    spec_base: &str,
    enum_name: &str,
    doc: &str,
    out: &mut Vec<String>,
) -> Result<Vec<(String, String)>, String> {
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
    for (index, (variant, (_, name))) in op.response.variants.iter().zip(&names).enumerate() {
        if variant.fields.iter().any(|field| {
            field.field_type == wa_ir::ParsedFieldType::Union
                && crate::union::classify_union(field).is_none()
        }) {
            return Err(format!(
                "outcomes.unemittable: response.variants[{index}] {} has an unsupported payload union",
                variant.tag
            ));
        }
        if !parser_is_valid(&variant.fields, name, name) {
            return Err(format!(
                "outcomes.unemittable: response.variants[{index}] {} has an unemittable payload parser",
                variant.tag
            ));
        }
    }

    // Bail if the try-each would still be ambiguous. A variant's parser accepts a
    // response iff it carries all the variant's *fail-on-absent* fields AND satisfies
    // its captured discriminator assertions (e.g. `type:"result"`). An earlier variant
    // shadows a later one only when its required fields are a subset AND no conflicting
    // assertion sets them apart — then a later-response would match the earlier arm
    // first (misclassification). Reject fully covered later outcomes. The bounded
    // direct error payload admits demonstrated code/text discrimination; other
    // overlapping payload shapes remain unsupported.
    let req: Vec<std::collections::BTreeSet<String>> = op
        .response
        .variants
        .iter()
        .map(|v| {
            let mut required = fail_required_fields(&v.fields);
            for assertion in &v.assertions {
                if assertion.kind == AssertionKind::Child
                    && let Some(name) = &assertion.name
                {
                    required.insert(format!("/child:{name}"));
                }
            }
            required
        })
        .collect();
    for i in 0..req.len() {
        for j in (i + 1)..req.len() {
            // i (earlier) shadows j only if j-responses also match i: their required
            // fields are a subset AND no captured discriminator (a conflicting attr
            // assertion, e.g. `type:"result"` vs `type:"error"`) sets them apart.
            if req[i].is_subset(&req[j])
                && !assertions_conflict(&op.response.variants[i], &op.response.variants[j])
                && !(error_selection(&op.response.variants[i], "response").is_some()
                    && error_selection(&op.response.variants[j], "response").is_some()
                    && !error_arms_cover(
                        &op.response.variants[i].error_arms,
                        &op.response.variants[j].error_arms,
                    ))
            {
                return Err(format!(
                    "outcomes.unemittable: response.variants[{i}] {} can shadow response.variants[{j}] {}",
                    op.response.variants[i].tag, op.response.variants[j].tag
                ));
            }
        }
    }

    // Several preceding error outcomes can collectively cover a later one even
    // when no single outcome does. Only combine roots with the same assertions.
    for j in 1..op.response.variants.len() {
        let later = &op.response.variants[j];
        if error_selection(later, "response").is_none() {
            continue;
        }
        let preceding: Vec<_> = op.response.variants[..j]
            .iter()
            .enumerate()
            .filter(|(i, earlier)| {
                req[*i].is_subset(&req[j])
                    && earlier.assertions == later.assertions
                    && error_selection(earlier, "response").is_some()
            })
            .flat_map(|(_, earlier)| earlier.error_arms.iter().cloned())
            .collect();
        if !preceding.is_empty() && error_arms_cover(&preceding, &later.error_arms) {
            return Err(format!(
                "outcomes.unemittable: preceding error outcomes cover response.variants[{j}] {}",
                later.tag
            ));
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
    Ok(info)
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
    emit_outcome_types(op, child_prefix, &enum_name, "", &mut sink).is_ok()
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
    if op
        .response
        .variants
        .iter()
        .any(|v| direct_error_payload(v).is_some())
    {
        lines.extend(emit_error_code_decoder(indent));
    }
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
        // The pin guards whenever there is one; uniqueness decides only whether a payload error
        // inside that guard is terminal. Reading one flag for both dropped the condition
        // entirely from every shared-pin arm, so a response this variant's pin excludes could
        // still be returned as it whenever its required fields happened to parse.
        let guarded = !conds.is_empty();
        let body = if guarded {
            lines.push(format!("{indent}if {} {{", conds.join(" && ")));
            format!("{indent}    ")
        } else {
            indent.to_string()
        };
        lines.push(format!(
            "{body}let __r: Result<{sname}, anyhow::Error> = (|| -> Result<{sname}, anyhow::Error> {{"
        ));
        if let Some(payload) = direct_error_payload(v) {
            lines.extend(emit_direct_error_parser(
                v,
                payload,
                sname,
                &format!("{body}    "),
            ));
        } else {
            lines.extend(emit_response_parser(
                &v.fields,
                sname,
                &format!("{body}    "),
                sname,
            ));
        }
        lines.push(format!("{body}}})();"));
        for field in v
            .fields
            .iter()
            .filter(|f| f.parser_required && f.field_type == wa_ir::ParsedFieldType::Union)
        {
            lines.push(format!("{body}let __r = __r.and_then(|value| {{ if value.{}.is_none() {{ anyhow::bail!({}); }} Ok(value) }});", rust_ident(&field.name), rust_lit(&format!("{}: required payload {} did not match", v.tag, field.name))));
        }
        if unique {
            lines.push(format!("{body}return Ok({enum_name}::{vname}(__r?));"));
        } else {
            lines.push(format!(
                "{body}if let Ok(__v) = __r {{ return Ok({enum_name}::{vname}(__v)); }}"
            ));
        }
        if guarded {
            lines.push(format!("{indent}}}"));
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
                        fmt_lit_inner(name),
                        fmt_lit_inner(value),
                    ));
                }
            }
            AssertionKind::Content => {
                if let Some(value) = &a.value {
                    lines.push(format!(
                        "{indent}if response.content_str() != Some({}) {{ anyhow::bail!(\"not a success response: content != {}\"); }}",
                        rust_lit(value),
                        fmt_lit_inner(value),
                    ));
                }
            }
            AssertionKind::Child => {
                if let Some(name) = &a.name {
                    // Union semantics: this parser mirrors the whole success set, not
                    // one variant, so it accepts whatever ANY success variant accepts.
                    // A child gate belongs here only when every success variant
                    // requires that child; otherwise (e.g. a bare `<iq type="result">`
                    // success beside a gated one) emitting it rejects a legitimate
                    // response.
                    let required_by_all = op
                        .response
                        .variants
                        .iter()
                        .filter(|v| v.kind == ResponseVariantKind::Success)
                        .all(|v| {
                            v.assertions.iter().any(|o| {
                                o.kind == AssertionKind::Child
                                    && o.name.as_deref() == Some(name.as_str())
                            })
                        });
                    if required_by_all {
                        lines.push(format!(
                            "{indent}if response.get_optional_child({}).is_none() {{ anyhow::bail!(\"not a success response: missing <{}>\"); }}",
                            rust_lit(name),
                            fmt_lit_inner(name),
                        ));
                    }
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
    let mut attr_fields: AttrFieldMap = HashMap::new();
    collect_attrs(
        &op.request.children,
        &mut spec_fields,
        &mut seen_spec,
        &[],
        &mut attr_fields,
    );

    // Generate `build_iq`'s body first: it discovers each node's variant groups
    // (smax MixinGroup disjunctions), emitting the enum types and the extra spec
    // fields they require — both needed before the struct below.
    let spec_base = spec_name.trim_end_matches("Spec").to_string();
    let mut variant_enums: Vec<String> = Vec::new();
    let mut variant_fields: Vec<(String, String, bool)> = Vec::new();
    // The attribute field names, so a synthesized content field cannot collide with one.
    let reserved: HashSet<String> = spec_fields.iter().map(|(n, _, _)| n.clone()).collect();
    let build_iq_lines = emit_build_iq(
        op,
        ns_const,
        iq,
        &spec_base,
        &mut variant_enums,
        &mut variant_fields,
        &reserved,
        &attr_fields,
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
    // single-struct path below can't express. When any variant cannot be emitted,
    // retain the old fallback type but refuse parsing with a generation diagnostic.
    let mut outcome_info: Vec<(String, String)> = Vec::new();
    let mut use_union = false;
    let mut outcome_error = None;
    let mut response_type_name: String = "()".to_string();
    if !op.response.variants.is_empty() {
        let enum_name = format!("{child_prefix}Response");
        match emit_outcome_types(
            op,
            child_prefix,
            &enum_name,
            &format!("{doc_owner}:{iq}"),
            &mut lines,
        ) {
            Ok(info) => {
                response_type_name = enum_name;
                outcome_info = info;
                use_union = true;
            }
            Err(reason) => outcome_error = Some(reason),
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
    let can_generate = !effectively_confirmation
        && !use_union
        && parser_is_valid(&op.response.fields, &response_type_name, child_prefix);

    // Retain the legacy associated type when no parser can be emitted. The parse
    // method below returns an explicit generation error instead of confirming success.
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

    // A missing shape is not evidence of an empty successful result. Preserve the
    // existing associated type for source compatibility, but make degradation an
    // explicit error. An explicit empty outcome still uses its admitted union.
    let correlation = correlation_requirements(op);
    let rejection = if let Err(reason) = &correlation {
        Some(reason.as_str())
    } else if let Some(reason) = outcome_error.as_deref() {
        Some(reason)
    } else if !use_union && op.response.fields.is_empty() {
        Some("response.contract_missing: no recovered response fields or outcomes")
    } else if !use_union && effectively_confirmation {
        Some("response.payload_unemittable: recovered fields produced no response payload")
    } else if !use_union && !can_generate {
        Some("response.parser_unemittable: parser cannot initialize the recovered payload")
    } else {
        None
    };

    let resp_param =
        if rejection.is_some() || effectively_confirmation || response_type_name == "()" {
            "_response"
        } else {
            "response"
        };
    let needs_context = correlation.as_ref().is_ok_and(|refs| !refs.is_empty());
    if needs_context && rejection.is_none() {
        lines.push("    fn parse_response(&self, _response: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {".to_string());
        lines.push(format!(
            "        anyhow::bail!({})",
            rust_lit(&format!(
                "{}: guards.request_context_required: use parse_response_with_request",
                op.module_name
            ))
        ));
        lines.push("    }".into());
        lines.push("}".into());
        lines.push(format!("impl {spec_name} {{"));
        lines.push(format!("    pub fn parse_response_with_request(&self, response: &wacore_binary::NodeRef<'_>, request_id: &str, request_to: &str) -> Result<{response_type_name}, anyhow::Error> {{"));
        for (wire, value) in correlation.as_ref().unwrap() {
            lines.push(format!("        if response.get_attr({}).map(|v| v.as_str()).as_deref() != Some({value}) {{ anyhow::bail!({}); }}", rust_lit(wire), rust_lit(&format!("{}: response.{wire} does not match {value}", op.module_name))));
        }
        if use_union {
            lines.extend(emit_outcome_parse(
                op,
                &outcome_info,
                &response_type_name,
                "        ",
            ));
        } else {
            lines.extend(emit_response_parser(
                &op.response.fields,
                &response_type_name,
                "        ",
                child_prefix,
            ));
        }
    } else if let Some(reason) = rejection {
        lines.push("    fn parse_response(&self, _response: &wacore_binary::NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {".to_string());
        lines.push(format!(
            "        anyhow::bail!({})",
            rust_lit(&format!("{}: {reason}", op.module_name)),
        ));
    } else if use_union {
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

    if let Some(reason) = rejection {
        lines.push(String::new());
        lines.push(format!("impl {spec_name} {{"));
        lines.push("    /// Why this reference parser always returns an error. This is a codegen limitation, not a wire rejection policy.".to_string());
        lines.push(format!(
            "    pub const RESPONSE_GENERATION_ERROR: &'static str = {};",
            rust_lit(reason)
        ));
        lines.push("}".to_string());
    }

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
    reserved: &HashSet<String>,
    attr_fields: &AttrFieldMap,
) -> Vec<String> {
    let mut lines = vec!["    fn build_iq(&self) -> InfoQuery<'static> {".to_string()];
    let target = match op.target {
        // The two literal addressees, the only ones the builder can write on its own.
        IqTarget::GroupServer => "Jid::new(\"\", Server::Group)".to_string(),
        IqTarget::Server => "Jid::new(\"\", Server::Pn)".to_string(),
        // Everything else needs the caller. `GroupJid` is the case that matters: 26 of
        // the 33 `w:g2` requests address one group's own `<group>@g.us`, and emitting the
        // bare `g.us` for them would send a subject change to the group server. `Unknown`
        // is the same shape with less known about it. `Unset` is here for a different
        // reason — there is nothing to send — but `InfoQuery` has no way to omit `to`, so
        // the caller is asked rather than a server silently substituted; the generated
        // comment says which of the three it is.
        IqTarget::GroupJid | IqTarget::Unset | IqTarget::Unknown => {
            let name = if reserved.contains("target") {
                "iq_target"
            } else {
                "target"
            };
            variant_fields.push((name.to_string(), "Jid".to_string(), true));
            lines.push(format!(
                "        // `{name}` is {}",
                match op.target {
                    IqTarget::GroupJid =>
                        "the group's own JID (`<group>@g.us`) — not the bare `g.us` server.",
                    IqTarget::Unset =>
                        "`unset`: the client writes no `to` at all, and `InfoQuery` \
                         cannot omit it — yours to decide.",
                    _ => "`unknown`: a runtime JID the IR could not name.",
                }
            ));
            format!("self.{name}.clone()")
        }
    };
    let target = target.as_str();
    if !op.request.children.is_empty() {
        let mut ctx = VariantCtx {
            spec_base,
            enum_defs: variant_enums,
            fields: variant_fields,
            reserved,
            attr_fields,
        };
        let mut top_var_names: Vec<(String, bool)> = Vec::new();
        let mut used_names = std::collections::HashMap::new();
        for child in &op.request.children {
            let (child_lines, child_var, is_list) =
                emit_child_builder(child, "        ", &mut used_names, &mut ctx, &[]);
            lines.extend(child_lines);
            top_var_names.push((child_var, is_list));
        }
        lines.push(String::new());
        lines.push(format!("        InfoQuery::{iq}("));
        lines.push(format!("            {ns_const},"));
        lines.push(format!("            {target},"));
        // A top-level child that repeats yields a LIST of nodes, which the `vec![a, b]` spelling
        // cannot hold — those are spread in, and the rest pushed one by one.
        if top_var_names.iter().any(|(_, is_list)| *is_list) {
            lines.push("            Some(NodeContent::Nodes({".to_string());
            lines.push("                let mut __children = Vec::new();".to_string());
            for (v, is_list) in &top_var_names {
                lines.push(if *is_list {
                    format!("                __children.extend({v});")
                } else {
                    format!("                __children.push({v});")
                });
            }
            lines.push("                __children".to_string());
            lines.push("            })),".to_string());
        } else {
            lines.push(format!(
                "            Some(NodeContent::Nodes(vec![{}])),",
                top_var_names
                    .iter()
                    .map(|(v, _)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        lines.push("        )".to_string());
    } else {
        lines.push(format!(
            "        InfoQuery::{iq}({ns_const}, {target}, None)"
        ));
    }
    lines.push("    }".to_string());
    lines
}

/// Collect the spec fields a request's attributes need, and record which field each attribute
/// SITE reads — keyed by the path of tags down to it, since two nodes may spell an attribute the
/// same way and mean different things.
///
/// One `seen` set across the whole tree collapsed them into a single field: the committed group
/// create request carries `jid` on its repeated `<participant>` nodes and on `<linked_parent>`,
/// a user JID and a group JID, and the spec exposed one `jid` written to both — a request the
/// caller cannot construct at all. Deduplication is right only for the SAME node's attribute,
/// which really is one input; across nodes it is two inputs sharing a name.
///
/// The first site keeps the plain spelling, so nothing that never collided moves. A later site
/// takes its owning tag as a prefix, and a numeric suffix past that.
pub(crate) type AttrFieldMap = HashMap<(Vec<String>, String), String>;

fn collect_attrs(
    children: &[WapChildNode],
    out: &mut Vec<(String, &'static str, WapAttrKind)>,
    seen: &mut HashSet<String>,
    path: &[String],
    map: &mut AttrFieldMap,
) {
    for child in children {
        let mut here = path.to_vec();
        here.push(child.tag.clone());
        for attr in &child.attrs {
            if matches!(attr.kind, WapAttrKind::Const | WapAttrKind::GeneratedId) {
                continue;
            }
            let ident = rust_ident(&attr.name);
            let key = (here.clone(), attr.name.clone());
            // The same node's attribute is one input however many times the tree repeats it.
            if let Some(existing) = map.get(&key) {
                let _ = existing;
                continue;
            }
            let field = if seen.insert(ident.clone()) {
                ident
            } else {
                let prefixed = rust_ident(&format!("{}_{}", child.tag, attr.name));
                if seen.insert(prefixed.clone()) {
                    prefixed
                } else {
                    (2..)
                        .map(|n| format!("{prefixed}_{n}"))
                        .find(|n| seen.insert(n.clone()))
                        .expect("an unused suffix exists")
                }
            };
            map.insert(key, field.clone());
            out.push((field, rust_attr_type(&attr.kind), attr.kind.clone()));
        }
        collect_attrs(&child.children, out, seen, &here, map);
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

    fn conflict_content(value: &str) -> wa_ir::ResponseAssertion {
        wa_ir::ResponseAssertion {
            kind: AssertionKind::Content,
            name: None,
            value: Some(value.to_string()),
            reference_path: None,
        }
    }

    /// A required content read fails on an absent payload, so it separates outcomes exactly as
    /// a required attribute does — and while every content decoder ended in `unwrap_or_default`
    /// it could not, which is why the signature left it out. It fails now, and leaving it out
    /// made two distinguishable outcomes look like a pair of empty signatures.
    #[test]
    fn a_required_content_read_counts_toward_a_variants_signature() {
        let field = |json: serde_json::Value| -> wa_ir::ParsedField {
            serde_json::from_value(json).expect("field")
        };
        let content = field(serde_json::json!({
            "method": "contentString", "name": "elementValue", "type": "string",
            "parserRequired": true
        }));
        assert!(
            !fail_required_fields(std::slice::from_ref(&content)).is_empty(),
            "a required content read is fail-on-absent",
        );
        // …and it is keyed by the DESCENT, since content has no name of its own: one node's
        // content must not stand in for another's. Both shapes below require the same child, so
        // the child entry cannot be what tells them apart — only where the content sits can.
        let content_inside = vec![field(serde_json::json!({
            "method": "child", "name": "detail", "type": "string", "parserRequired": true,
            "children": [{
                "method": "contentString", "name": "elementValue", "type": "string",
                "parserRequired": true
            }]
        }))];
        let content_outside = vec![
            field(serde_json::json!({
                "method": "child", "name": "detail", "type": "string", "parserRequired": true
            })),
            content.clone(),
        ];
        assert_ne!(
            fail_required_fields(&content_inside),
            fail_required_fields(&content_outside),
            "content under a child is a different requirement from content at the root",
        );
        // A REPEATED child fails on nothing: its parser iterates and succeeds with an empty
        // vector where the child is absent, so it cannot tell one variant from another.
        let repeated = field(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "parserRequired": true, "repeats": true,
            "children": [{"method": "attrString", "name": "v", "wireName": "v",
                          "type": "string", "parserRequired": true}]
        }));
        assert!(
            !fail_required_fields(std::slice::from_ref(&repeated))
                .iter()
                .any(|k| k.contains("child:item")),
            "a repeated child is not fail-on-absent",
        );
        // …and a child that does NOT repeat still is, which is what makes the exclusion about
        // repetition rather than about children.
        let single = field(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "parserRequired": true,
            "children": [{"method": "attrString", "name": "v", "wireName": "v",
                          "type": "string", "parserRequired": true}]
        }));
        assert!(
            fail_required_fields(std::slice::from_ref(&single))
                .iter()
                .any(|k| k.contains("child:item")),
            "a single required child bails on absence",
        );
        // The bound: an OPTIONAL content read still fails on nothing, because the emitter hands
        // back a `None` the field holds rather than an error.
        let optional = field(serde_json::json!({
            "method": "contentString", "name": "elementValue", "type": "string",
            "parserRequired": false
        }));
        assert!(
            fail_required_fields(std::slice::from_ref(&optional)).is_empty(),
            "an optional content read discriminates nothing",
        );
    }

    /// Two nodes may spell an attribute the same way and mean different things, so one `seen`
    /// set across the tree collapsed them into a single field written to both.
    #[test]
    fn same_named_attributes_on_different_nodes_stay_apart() {
        let node = |tag: &str, kind: WapAttrKind| wa_ir::WapChildNode {
            tag: tag.into(),
            attrs: vec![wa_ir::WapAttrDef {
                name: "jid".into(),
                kind,
                value: None,
                required: true,
                enum_ref: None,
                arg_path: None,
            }],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
            ..Default::default()
        };
        let children = vec![
            node("participant", WapAttrKind::UserJid),
            node("linked_parent", WapAttrKind::GroupJid),
        ];
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut map = HashMap::new();
        collect_attrs(&children, &mut out, &mut seen, &[], &mut map);
        let names: Vec<&str> = out.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            vec!["jid", "linked_parent_jid"],
            "the second site takes its own field: {out:?}"
        );
        // …and each SITE is told which field it reads, or the builder would write both to
        // whichever name won.
        assert_eq!(
            map.get(&(vec!["participant".to_string()], "jid".to_string()))
                .map(String::as_str),
            Some("jid")
        );
        assert_eq!(
            map.get(&(vec!["linked_parent".to_string()], "jid".to_string()))
                .map(String::as_str),
            Some("linked_parent_jid")
        );
        // The bound: the SAME node's attribute is one input however often the tree spells it.
        // Two sibling `<participant>` nodes are one repeated shape, not two fields.
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut map = HashMap::new();
        collect_attrs(
            &[
                node("participant", WapAttrKind::UserJid),
                node("participant", WapAttrKind::UserJid),
            ],
            &mut out,
            &mut seen,
            &[],
            &mut map,
        );
        assert_eq!(
            out.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>(),
            vec!["jid"],
            "one node, one input, whatever the repetition: {out:?}"
        );
    }

    #[test]
    fn a_content_pin_selects_a_variant_as_much_as_an_attribute_one() {
        // An outcome root has two things to pin, and the pin set modelled only one. A variant
        // discriminated by `literalContent` emitted no selector at all, so a response carrying
        // both variants' required fields came back as the first regardless of which content
        // value made the source parser choose the second.
        let v = conflict_variant(vec![conflict_content("admin_add")]);
        let conds = pin_conditions(&v, "response");
        assert_eq!(
            conds,
            vec![r#"response.content_str().as_deref() == Some("admin_add")"#.to_string()],
            "the content is compared"
        );
        // …and it discriminates: a node has ONE text content, so two variants pinning it to
        // different values are as exclusive as two disagreeing on an attribute.
        let other = conflict_variant(vec![conflict_content("admin_remove")]);
        assert!(
            !pins_can_coincide(&variant_pins(&v), &variant_pins(&other)),
            "different content values cannot both match"
        );
        // The bounds. The same value still coincides; a content pin and an ATTRIBUTE pin
        // constrain different things and never conflict; and an unpinned variant is still
        // reachable through every one of them.
        assert!(pins_can_coincide(
            &variant_pins(&v),
            &variant_pins(&conflict_variant(vec![conflict_content("admin_add")]))
        ));
        assert!(pins_can_coincide(
            &variant_pins(&v),
            &variant_pins(&conflict_variant(vec![conflict_attr(
                "type",
                Some("result")
            )]))
        ));
        assert!(pins_can_coincide(
            &variant_pins(&v),
            &variant_pins(&conflict_variant(vec![]))
        ));
        // …and it has to reach the ADMISSION gate as well as the selector. `assertions_conflict`
        // was a second copy of this relation restricted to attributes, so two outcomes separated
        // by `literalContent` were judged to shadow each other, the union was refused, and the
        // guard emitted for them was never reached — the rule fixed at one end and not the
        // other. The two are one function now, so this cannot drift again.
        assert!(
            assertions_conflict(&v, &other),
            "content pins separate the outcomes"
        );
        assert!(
            !assertions_conflict(&v, &conflict_variant(vec![conflict_content("admin_add")])),
            "the same value does not"
        );
        assert!(
            !assertions_conflict(
                &v,
                &conflict_variant(vec![conflict_attr("type", Some("result"))])
            ),
            "and a pin on something else does not"
        );

        // And an attribute pin still reads as one — the enum did not swallow the old shape.
        let a = conflict_variant(vec![conflict_attr("type", Some("result"))]);
        assert_eq!(
            pin_conditions(&a, "response"),
            vec![
                r#"response.get_attr("type").map(|x| x.as_str()).as_deref() == Some("result")"#
                    .to_string()
            ]
        );
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
                target_arg_path: None,
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

    fn success_variant(tag: &str, assertions: Vec<wa_ir::ResponseAssertion>) -> ResponseVariant {
        ResponseVariant {
            tag: tag.into(),
            module_name: format!("M{tag}"),
            kind: ResponseVariantKind::Success,
            assertions,
            fields: vec![],
            ..Default::default()
        }
    }

    fn child_assert(tag: &str) -> wa_ir::ResponseAssertion {
        wa_ir::ResponseAssertion {
            kind: AssertionKind::Child,
            name: Some(tag.into()),
            value: None,
            reference_path: None,
        }
    }

    #[test]
    fn success_guard_requires_a_child_only_when_every_success_does() {
        // The fallback parser mirrors the whole success SET, so it accepts whatever
        // any success variant accepts. A gate beside a childless success (the
        // AcceptGroupAdd shape) must not be emitted, or the fallback rejects the
        // legitimate bare response.
        let mut s = stanza("WASmaxOutThing", Some("getThing"));
        s.response.variants = vec![
            success_variant(
                "GetThingResponseGatedSuccess",
                vec![child_assert("m_child")],
            ),
            success_variant("GetThingResponseSuccess", vec![]),
        ];
        assert!(
            !emit_success_guards(&s, "    ")
                .iter()
                .any(|g| g.contains("m_child")),
            "a childless sibling keeps the fallback open"
        );
        // …while a gate every success variant carries is enforced.
        let mut s = stanza("WASmaxOutThing", Some("getThing"));
        s.response.variants = vec![success_variant(
            "GetThingResponseGatedSuccess",
            vec![child_assert("m_child")],
        )];
        let guards = emit_success_guards(&s, "    ");
        assert!(
            guards
                .iter()
                .any(|g| g.contains("get_optional_child(\"m_child\")")),
            "unanimous gate enforced: {guards:?}"
        );
    }
    #[test]
    fn ordered_child_guard_keeps_both_success_outcomes_reachable() {
        // The gated success must be tried before the bare success. Flattening the
        // two loses the approval outcome even though both stanzas still parse.
        use wa_ir::ResponseAssertion;
        use wa_ir::{ParsedField, ParsedFieldType};
        fn typ() -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: "typ".into(),
                field_type: ParsedFieldType::String,
                parser_required: true,
                ..Default::default()
            }
        }
        fn gated() -> ResponseVariant {
            ResponseVariant {
                tag: "AcceptGroupAddResponseGroupJoinRequestSuccess".into(),
                module_name: "m".into(),
                kind: ResponseVariantKind::Success,
                assertions: vec![
                    ResponseAssertion {
                        kind: AssertionKind::Attr,
                        name: Some("type".into()),
                        value: Some("result".into()),
                        reference_path: None,
                    },
                    ResponseAssertion {
                        kind: AssertionKind::Child,
                        name: Some("membership_approval_request".into()),
                        value: None,
                        reference_path: None,
                    },
                ],
                fields: vec![typ()],
                ..Default::default()
            }
        }
        fn bare() -> ResponseVariant {
            let mut v = gated();
            v.tag = "AcceptGroupAddResponseSuccess".into();
            v.assertions.pop();
            v
        }
        let mut op = stanza(
            "WASmaxOutGroupsAcceptGroupAddRequest",
            Some("makeAcceptGroupAddRequest"),
        );
        op.response = ParsedResponse {
            parser_name: "GroupsAcceptGroupAddRPC".into(),
            variants: vec![gated(), bare()],
            fields: vec![typ()],
            ..Default::default()
        };
        let code = generate_spec(&op, "W_G2_NAMESPACE", "MakeAcceptGroupAddRequestSpec");
        assert!(
            code.contains("pub enum MakeAcceptGroupAddRequestResponse"),
            "the two success outcomes must remain distinguishable: {code}"
        );
        assert!(
            code.contains(
                "response.get_children_by_tag(\"membership_approval_request\").count() == 1"
            ),
            "{code}"
        );
        assert!(
            code.find("::GroupJoinRequestSuccess(").unwrap() < code.find("::Success(").unwrap()
        );
        op.response.variants.reverse();
        let reversed = generate_spec(&op, "W_G2_NAMESPACE", "MakeAcceptGroupAddRequestSpec");
        assert!(
            reversed.contains("outcomes.unemittable"),
            "a broad first arm shadows the gated one: {reversed}"
        );
    }

    #[test]
    fn outcome_union_generates_enum_and_try_each_parse() {
        use wa_ir::{ParsedField, ParsedFieldType, ResponseVariant, ResponseVariantKind};
        fn attr(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                parser_required: true,
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
                parser_required: true,
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
                parser_required: true,
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
        // …and both are still GUARDED on the pin they share. What uniqueness decides is whether
        // a payload error inside the guard is terminal, not whether the pin is tested at all: a
        // shared `type="result"` still excludes a `type="error"` response. Reading one flag for
        // both dropped the condition from every shared-pin variant.
        assert_eq!(
            code.matches("get_attr(\"type\").map(|x| x.as_str()).as_deref() == Some(\"result\")")
                .count(),
            2,
            "a shared pin still guards its own variant:\n{code}"
        );
    }

    #[test]
    fn a_requirement_under_an_optional_child_discriminates_nothing() {
        use wa_ir::{ParsedField, ParsedFieldType, ResponseVariant, ResponseVariantKind};
        // The emitter defaults a whole subtree when its optional child is missing, so a
        // required attribute INSIDE one never makes the parser bail and cannot tell a variant
        // from its sibling. The signature walk recorded it anyway — and once round forty-six
        // qualified these keys by path, that false requirement could differ from a later
        // variant's real one, so the subset gate admitted a union whose first arm then took
        // every response the second could.
        fn attr(name: &str, required: bool) -> ParsedField {
            ParsedField {
                method: if required {
                    "attrString"
                } else {
                    "maybeAttrString"
                }
                .into(),
                name: name.into(),
                field_type: ParsedFieldType::String,
                parser_required: required,
                ..Default::default()
            }
        }
        fn optional_child(tag: &str, kids: Vec<ParsedField>) -> ParsedField {
            ParsedField {
                method: "maybeChild".into(),
                name: tag.into(),
                tag: Some(tag.into()),
                field_type: ParsedFieldType::String,
                parser_required: false,
                children: Some(kids),
                ..Default::default()
            }
        }
        let mut op = stanza("WASmaxOutFooOptRequest", Some("makeOptRequest"));
        op.response = ParsedResponse {
            parser_name: "FooOptRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "OptResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![optional_child("detail", vec![attr("code", true)])],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "OptResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![attr("reason", true)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeOptRequestSpec");
        assert!(
            !code.contains("enum MakeOptRequestResponse"),
            "the first variant requires nothing, so it shadows the second:\n{code}"
        );
        // The bound: the same attribute under a REQUIRED child is fail-on-absent, so it does
        // separate them and the union stands.
        let mut op = stanza("WASmaxOutFooOptRequest", Some("makeOptRequest"));
        let mut required_child = optional_child("detail", vec![attr("code", true)]);
        required_child.method = "child".into();
        required_child.parser_required = true;
        op.response = ParsedResponse {
            parser_name: "FooOptRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "OptResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![required_child],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "OptResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![attr("reason", true)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeOptRequestSpec");
        assert!(
            code.contains("enum MakeOptRequestResponse"),
            "a required child really does discriminate:\n{code}"
        );
        // And the other bound, which is the rule this walk had right all along: an OPTIONAL
        // field of the variant's own is not fail-on-absent either, so two variants told apart
        // only by one are not separable. Recording every field regardless is the over-broad
        // mutation.
        let mut op = stanza("WASmaxOutFooOptRequest", Some("makeOptRequest"));
        op.response = ParsedResponse {
            parser_name: "FooOptRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "OptResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![attr("hint", false)],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "OptResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![attr("reason", true)],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeOptRequestSpec");
        assert!(
            !code.contains("enum MakeOptRequestResponse"),
            "an optional field discriminates nothing:\n{code}"
        );
    }

    #[test]
    fn two_variants_reading_one_wire_attribute_are_not_disjoint() {
        use wa_ir::{ParsedField, ParsedFieldType, ResponseVariant, ResponseVariantKind};
        // The shadowing gate asks whether an earlier variant's required reads are a subset of a
        // later one's, and it asked that of the OUTPUT field names. Two variants may bind one
        // wire attribute under different result names — `success_code` and `error_code`, both
        // reading `code` — and by output name those sets look disjoint, so the union was
        // admitted with two parsers of identical acceptance and the second unreachable. Keyed by
        // what the parser reads, the sets are equal and the gate declines to the single-shape
        // path.
        fn coded(name: &str) -> ParsedField {
            ParsedField {
                method: "attrString".into(),
                name: name.into(),
                wire_name: Some("code".into()),
                field_type: ParsedFieldType::String,
                parser_required: true,
                ..Default::default()
            }
        }
        let mut op = stanza("WASmaxOutFooCodeRequest", Some("makeCodeRequest"));
        op.response = ParsedResponse {
            parser_name: "FooCodeRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "CodeResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![coded("successCode")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "CodeResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![coded("errorCode")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeCodeRequestSpec");
        assert!(
            !code.contains("enum MakeCodeRequestResponse"),
            "one wire read cannot separate two variants:\n{code}"
        );
        // The bounds, both of them things the key must NOT conflate. First: the same wire name
        // read at a different DESCENT is a different read. A `code` on the response and a `code`
        // inside an `<error>` wrapper are told apart by whether that wrapper exists, so keying
        // on the name alone would decline a union that is perfectly separable — a loss of typing
        // rather than a wrong parser, and still not the answer.
        let mut op = stanza("WASmaxOutFooCodeRequest", Some("makeCodeRequest"));
        let mut nested = coded("errorCode");
        nested.source_path = Some(vec!["error".into()]);
        op.response = ParsedResponse {
            parser_name: "FooCodeRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "CodeResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![coded("successCode")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "CodeResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![nested],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeCodeRequestSpec");
        assert!(
            code.contains("enum MakeCodeRequestResponse"),
            "the same name at a different descent is a different read:\n{code}"
        );
        // Second: two variants reading different wire attributes are separable exactly as
        // before, so the key change narrows nothing it should not.
        let mut op = stanza("WASmaxOutFooCodeRequest", Some("makeCodeRequest"));
        let mut distinct = coded("errorCode");
        distinct.wire_name = Some("reason".into());
        op.response = ParsedResponse {
            parser_name: "FooCodeRPC".into(),
            variants: vec![
                ResponseVariant {
                    tag: "CodeResponseSuccess".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Success,
                    fields: vec![coded("successCode")],
                    ..Default::default()
                },
                ResponseVariant {
                    tag: "CodeResponseError".into(),
                    module_name: "m".into(),
                    kind: ResponseVariantKind::Error,
                    fields: vec![distinct],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let code = generate_spec(&op, "FOO_NAMESPACE", "MakeCodeRequestSpec");
        assert!(
            code.contains("enum MakeCodeRequestResponse"),
            "different wire reads still separate them:\n{code}"
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
                parser_required: true,
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
                parser_required: true,
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
    fn error_admission_preserves_text_pairs_ranges_and_fallback_order() {
        fn exact(code: i64, text: &str) -> wa_ir::ErrorArm {
            wa_ir::ErrorArm {
                code: Some(code),
                text: Some(text.into()),
                ..Default::default()
            }
        }
        fn range(lo: i64, hi: i64) -> wa_ir::ErrorArm {
            wa_ir::ErrorArm {
                code_min: Some(lo),
                code_max: Some(hi),
                ..Default::default()
            }
        }
        let client = vec![
            exact(304, "already-exists"),
            exact(500, "resource-constraint"),
            range(400, 499),
        ];
        let server = vec![exact(500, "internal-server-error"), range(500, 599)];
        assert!(!error_arms_cover(&client, &server));
        assert!(!error_arms_cover(&server, &client));
        assert!(error_arms_cover(
            &[range(500, 599)],
            &[exact(500, "resource-constraint")]
        ));
        assert!(!error_arms_cover(
            &[exact(500, "resource-constraint")],
            &[range(500, 599)]
        ));
        assert!(error_arms_cover(
            &[range(400, 449), range(450, 499)],
            &[range(400, 499)]
        ));
        assert!(!error_arms_cover(
            &[range(400, 449), range(451, 499)],
            &[range(400, 499)]
        ));
        assert!(error_arms_cover(
            &[range(i64::MIN, i64::MAX)],
            &[range(i64::MIN, i64::MAX)]
        ));
    }

    #[test]
    fn unknown_reference_paths_are_diagnosed_not_ignored() {
        let mut op = stanza("UnknownReference", None);
        op.response.assertions.push(wa_ir::ResponseAssertion {
            kind: AssertionKind::Reference,
            name: Some("from".into()),
            value: None,
            reference_path: Some(vec!["account".into(), "to".into()]),
        });
        let code = generate_spec(&op, "TEST_NAMESPACE", "UnknownReferenceSpec");
        assert!(code.contains("guards.reference_unsupported"));
        assert!(!code.contains("pub fn parse_response_with_request"));
    }

    #[test]
    fn missing_response_contract_is_not_a_confirmation() {
        let op = stanza("MissingResponse", None);
        let code = generate_spec(&op, "TEST_NAMESPACE", "MissingResponseSpec");
        assert!(
            !code.contains("Ok(())"),
            "unrecovered response must fail: {code}"
        );
        assert!(code.contains("response.contract_missing"), "{code}");
    }

    #[test]
    fn discarded_response_payload_is_not_a_confirmation() {
        let mut op = stanza("DiscardedPayload", None);
        op.response.fields = vec![wa_ir::ParsedField {
            name: "unresolvedPayload".into(),
            ..Default::default()
        }];
        let code = generate_spec(&op, "TEST_NAMESPACE", "DiscardedPayloadSpec");
        assert!(
            !code.contains("Ok(())"),
            "discarded payload must fail: {code}"
        );
        assert!(code.contains("response.payload_unemittable"), "{code}");
    }

    #[test]
    fn invalid_response_parser_is_not_a_confirmation() {
        // Real nested optional/repeated shape whose emitted initializer is incomplete.
        let ir: wa_ir::IqIr =
            serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
        let op = ir
            .stanzas
            .iter()
            .find(|op| op.module_name == "WAWebQueryBusinessCategoriesJob")
            .unwrap();
        assert!(!parser_is_valid(
            &op.response.fields,
            "CategoriesResponse",
            "Categories"
        ));
        let code = generate_spec(op, "TEST_NAMESPACE", "CategoriesSpec");
        assert!(!code.contains("Ok(())"), "invalid parser must fail: {code}");
        assert!(code.contains("response.parser_unemittable"), "{code}");
    }

    #[test]
    fn real_pilots_emit_ordered_outcomes_with_required_request_context() {
        let ir: wa_ir::IqIr =
            serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
        for pilot in ["SetSubject", "AcceptGroupAdd"] {
            let module = format!("WASmaxOutGroups{pilot}Request");
            let op = ir
                .stanzas
                .iter()
                .find(|op| op.module_name == module)
                .unwrap();
            assert_eq!(op.request.target, IqTarget::GroupJid);
            assert_eq!(op.request.target_arg_path.as_ref().unwrap()[0].key, "iqTo");
            for variant in &op.response.variants {
                for (wire, request) in [("id", "id"), ("from", "to")] {
                    assert!(
                        variant
                            .assertions
                            .iter()
                            .any(|a| a.kind == AssertionKind::Reference
                                && a.name.as_deref() == Some(wire)
                                && a.reference_path.as_deref() == Some(&[request.to_string()]))
                    );
                }
            }
            let code = generate_spec(op, "W_G2_NAMESPACE", &format!("{pilot}Spec"));
            assert!(code.contains("self.target.clone()"));
            assert!(!code.contains("outcomes.unemittable"), "{code}");
            assert!(code.contains("pub fn parse_response_with_request"));
            assert!(code.contains("guards.request_context_required"));
            assert!(code.contains("Some(request_id)"));
            assert!(code.contains("Some(request_to)"));
            assert!(code.contains("::ClientError("));
            assert!(code.contains("::ServerError("));
            if pilot == "SetSubject" {
                assert_eq!(
                    op.request.children[0]
                        .content
                        .as_ref()
                        .unwrap()
                        .arg_path
                        .as_ref()
                        .unwrap()[0]
                        .key,
                    "subjectElementValue"
                );
                assert!(code.contains("subject_node.bytes(self.subject_content.clone())"));
            } else {
                assert!(
                    op.response.variants[0]
                        .tag
                        .ends_with("GroupJoinRequestSuccess")
                );
                assert!(op.response.variants[1].tag.ends_with("ResponseSuccess"));
                assert!(
                    op.response.variants[0]
                        .assertions
                        .iter()
                        .any(|a| a.kind == AssertionKind::Child
                            && a.name.as_deref() == Some("membership_approval_request"))
                );
                for wire in ["code", "expiration", "admin"] {
                    assert!(code.contains(&format!("accept_node.attr(\"{wire}\"")));
                }
            }
        }
    }

    #[test]
    fn explicit_empty_outcome_remains_a_success() {
        let mut op = stanza("EmptyOutcome", None);
        op.response.variants = vec![success_variant(
            "EmptySuccess",
            vec![conflict_attr("type", Some("result"))],
        )];
        op.response.variants[0].fields.clear();
        let code = generate_spec(&op, "TEST_NAMESPACE", "EmptyOutcomeSpec");
        assert!(code.contains("pub enum EmptyOutcomeResponse"), "{code}");
        assert!(code.contains("return Ok(EmptyOutcomeResponse::"), "{code}");
        assert!(code.contains("Some(\"result\")"), "{code}");
        assert!(!code.contains("response.contract_missing"), "{code}");
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
