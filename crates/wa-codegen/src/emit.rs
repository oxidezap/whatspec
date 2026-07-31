//! Emit Rust source fragments: response parsers and request builders.

use std::collections::HashMap;

use wa_ir::wap;
use wa_ir::{ParsedField, ParsedFieldType, WapAttrKind, WapChildNode, WapContentKind};

use crate::fields::{
    child_content_type, flatten_same_node, is_attr_field, is_child_field, is_jid_kind,
};
use crate::naming::{fmt_lit_inner, pascal_case, rust_ident, rust_lit, snake_case};

fn tag_or_name(f: &ParsedField) -> &str {
    f.tag.as_deref().unwrap_or(&f.name)
}

fn children_of(f: &ParsedField) -> &[ParsedField] {
    f.children.as_deref().unwrap_or(&[])
}

fn repeats(f: &ParsedField) -> bool {
    f.repeats == Some(true)
}

/// Emit the `let <name> = ...;` lines that read a single field off `node_var`.
///
/// Content accessors read the node body; attribute accessors derive their shape
/// from the canonical [`wap::method_field_type`] + optionality, so a newly-added
/// accessor in `wap` flows through here instead of being swallowed by a silent
/// `_ => Vec::new()` catch-all. Non-field methods (child accessors, `hasAttr`,
/// `contentInt`) are materialized elsewhere and emit nothing here.
pub(crate) fn emit_field_parse(f: &ParsedField, node_var: &str, indent: &str) -> Vec<String> {
    let name = rust_ident(&f.name);
    // The attribute is read by its WIRE name (snake_case), not the camelCase
    // struct field name; smax responses name the field by the makeResult key.
    let wire = f.wire_name.as_deref().unwrap_or(&f.name);
    let flit = rust_lit(wire);
    let fmsg = fmt_lit_inner(wire);
    let method = f.method.as_str();

    // Every remaining content spelling reads the node body and is typed by the canonical
    // classifier, so a newly-recognized one (`contentUint`, `contentEnum`,
    // `contentBytesRange`, `contentLiteralBytes`) is parsed rather than silently skipped.
    if wap::is_content_method(method) {
        // The byte count a `contentUint(N)` leaf pins, checked on the RAW payload and BEFORE the
        // decode, because folding N big-endian bytes into a `u64` loses it. The flattened
        // child-content path has asked this since the round it was added and the ordinary read
        // did not — the committed corpus has a repeated `mapChildren` item with
        // `contentUint(3)`, whose one-, two- and four-byte payloads this accepted and the source
        // accessor turns away. One rule, two places, one copy missing it, on the third kind of
        // constraint this branch has needed it for.
        // The IR's `required` is a source of optionality for a CONTENT leaf exactly as it is
        // for an attribute — `rust_field_type` reads it and declares `Option<T>` — and this
        // branch emitted the required decoder unconditionally, so an optional content leaf was
        // declared `Option<String>` and initialized with a `String`. Emitted Rust that does not
        // type-check, which nothing on this branch compiles: the third defect of that kind here,
        // and the first that the committed IR already carries the shape for.
        //
        // The attribute path below has read the same flag since the round it was written; this
        // one asked only the accessor spelling, and no content accessor spells optionality.
        let optional_leaf = !f.required;
        let mut out = raw_length_check(Some(f), &name, &fmsg, indent, node_var);
        out.push(if optional_leaf {
            format!(
                "{indent}let {name} = {node_var}.{};",
                content_decoder_opt(method)
            )
        } else {
            format!(
                "{indent}let {name} = {};",
                content_read_required(f, node_var, &fmsg)
            )
        });
        // The same band the attribute path enforces. A content leaf declaring `intMin: -10`
        // decoded the number and checked nothing, and the moment its width could be signed a
        // `-20` materialized where the unsigned parse had been refusing every negative value by
        // accident. The union's content guard already tests this band; the ordinary read did
        // not, which is one rule spelled in two places with one copy missing it — again.
        // …and a constraint is asked of a value that IS there. An absent optional payload is a
        // value the field holds, not one the accessor rejects — the same reading the optional
        // attribute path takes, and the same one the flattened-child path was given two rounds
        // ago.
        // The REQUIRED spelling is left exactly as it was, message and all — an optional leaf is
        // the only thing that moves here, and a diff on every required one would say this
        // touched them.
        // …and HOW an absent one is skipped depends on what the payload is. An integer is
        // `Option<i64>`, which is `Copy`: `is_none_or` takes it by value, binds the number and
        // leaves the field readable for the message afterwards. Bytes are not — `as_ref()` keeps
        // the `Vec` where it is and `len()` reads straight through the reference.
        //
        // One `as_ref()` served both, which bound `&i64` under the integer band: `weight >=
        // -10i64` does not compile against a reference, and neither does the two-sided
        // `contains(&&i64)`. Emitted Rust that does not type-check, from the branch that has
        // now produced four of them — every one found by reading rather than by building,
        // because nothing in this workspace compiles the module it writes.
        let checked_value = |test: String| format!("{name}.is_none_or(|{name}| {test})");
        let checked_ref = |test: String| format!("{name}.as_ref().is_none_or(|{name}| {test})");
        if let Some(test) = super::fields::int_band(f, &name) {
            out.push(if optional_leaf {
                format!(
                    "{indent}anyhow::ensure!({}, \"{fmsg} out of range: {{:?}}\", {name});",
                    checked_value(test)
                )
            } else {
                format!("{indent}anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});")
            });
        }
        // And the length a bytes accessor pins, which this path decoded and ignored entirely:
        // `contentBytes(32)` and `contentBytesRange(1, 128)` both record what they will accept,
        // and the generated parser took a body of any length. The union's leaf guard has
        // checked it all along — the same one-rule-two-places asymmetry as the integer band,
        // on the other kind of constraint, so it reads the same shared predicate.
        //
        // Only where the decoded value IS bytes. `contentUint(N)` records a byte length too and
        // folds those bytes into a `u64`, which has no `len()`; the classifier calls it an
        // integer, so asking it here keeps the two apart.
        if wap::method_field_type(method) == ParsedFieldType::Bytes
            && let Some(test) = super::fields::byte_band(f, &name)
        {
            out.push(if optional_leaf {
                format!(
                    "{indent}anyhow::ensure!({}, \"{fmsg} wrong length: {{:?}}\", {name});",
                    checked_ref(test)
                )
            } else {
                format!(
                    "{indent}anyhow::ensure!({test}, \"{fmsg} wrong length: {{}}\", {name}.len());"
                )
            });
        }
        // `contentEnum(TABLE)` records its vocabulary exactly as an attribute enum does, and
        // this branch returned after the numeric and byte constraints without ever asking for
        // it — the enum check added one round ago reached the attribute path and stopped there.
        // …and the two constraint helpers that already spell both shapes are told which one
        // this is. "A content decoder never yields an `Option`" was true of the decoder and not
        // of the FIELD, which is the distinction this whole branch had missed.
        out.extend(enum_membership(f, &name, &fmsg, indent, optional_leaf));
        out.extend(literal_pin(f, &name, &fmsg, indent, optional_leaf));
        return out;
    }
    if !wap::is_attr_method(method) {
        return Vec::new();
    }

    // See `rust_field_type`: the accessor spelling and the IR's `required` are both
    // sources of optionality, and the two must agree or the initializer will not match the
    // declared field type.
    let optional = wap::is_optional_method(method) || !f.required;
    // A declared band is part of what the accessor accepts, and this path decoded the number and
    // enforced nothing — so `attrIntRange("weight", -10000, 10000)` took a `-20000` the source
    // turns away. Harmless while every integer was `u64`, because the parse itself refused every
    // negative value; the moment the width could be signed it became an over-acceptance, and it
    // is the union guard's own `int_band`, read from one place now.
    let band = super::fields::int_band(f, &name);
    match wap::method_field_type(method) {
        ParsedFieldType::Integer if optional => {
            let width = super::fields::integer_width(f);
            // Which of the two sources the optionality came from decides what an UNPARSEABLE
            // value means. A `maybeAttrInt` tolerates the attribute's absence by design, and
            // what it does with a present non-number is a question about that accessor this
            // cannot answer from here — so its reading is left exactly as it was.
            //
            // A relaxed `attrInt` is a different thing: the accessor is a required one that
            // runs on some paths only, and when it runs it rejects a value it cannot parse.
            // Folding the parse failure into `None` stored "absent" for `expiration="invalid"`
            // — a response the source turns away, filed as one where the field simply is not
            // there. Four attributes in the committed artifacts are relaxed this way.
            let mut out = if tolerates_a_failed_decode(f) {
                let read = format!(
                    "{node_var}.get_attr({flit}).and_then(|v| v.as_str().parse::<{width}>().ok())"
                );
                match &band {
                    // Out of band is not the same as absent: the source accessor THROWS on a
                    // value outside its range, so mapping it to `None` would accept a response
                    // the parser rejects — quietly, and with the field simply missing.
                    Some(test) => vec![
                        format!("{indent}let {name} = match {read} {{"),
                        format!("{indent}    Some({name}) => {{"),
                        format!(
                            "{indent}        anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
                        ),
                        format!("{indent}        Some({name})"),
                        format!("{indent}    }}"),
                        format!("{indent}    None => None,"),
                        format!("{indent}}};"),
                    ],
                    None => vec![format!("{indent}let {name} = {read};")],
                }
            } else {
                let mut lines = vec![
                    format!("{indent}let {name} = match {node_var}.get_attr({flit}) {{"),
                    format!("{indent}    Some({name}) => {{"),
                    format!("{indent}        let {name}: {width} = {name}.as_str().parse()"),
                    format!(
                        "{indent}            .map_err(|_| anyhow::anyhow!(\"{fmsg} not a number\"))?;"
                    ),
                ];
                if let Some(test) = &band {
                    lines.push(format!(
                        "{indent}        anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
                    ));
                }
                lines.push(format!("{indent}        Some({name})"));
                lines.push(format!("{indent}    }}"));
                lines.push(format!("{indent}    None => None,"));
                lines.push(format!("{indent}}};"));
                lines
            };
            out.extend(literal_pin(f, &name, &fmsg, indent, true));
            out
        }
        ParsedFieldType::Integer => {
            let mut out = vec![
                format!(
                    "{indent}let {name}: {} = {node_var}.get_attr({flit})",
                    super::fields::integer_width(f)
                ),
                format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
                format!("{indent}    .as_str()"),
                format!("{indent}    .parse()?;"),
            ];
            if let Some(test) = &band {
                out.push(format!(
                    "{indent}anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {name});"
                ));
            }
            out.extend(literal_pin(f, &name, &fmsg, indent, false));
            out
        }
        // An OPTIONAL JID must come first: `rust_field_type` declares `Option<Jid>` for a
        // `maybeAttr…Jid`, and falling into the branch below both mis-typed the
        // initializer and rejected the absence the accessor exists to permit.
        t if t.is_jid() && optional => {
            // …and a JID that fails to CONVERT is not an absent attribute. `to_jid()` answers
            // `None` for both, so a malformed `attrUserJid` relaxed to `required: false` was
            // stored as though the attribute were not there — the same collapse the relaxed
            // integer had, on the branch directly below it, missed in the very commit that
            // taught the integer. Read from one predicate now.
            let mut out = if tolerates_a_failed_decode(f) {
                vec![format!(
                    "{indent}let {name} = {node_var}.get_attr({flit}).and_then(|v| v.to_jid());"
                )]
            } else {
                vec![
                    format!("{indent}let {name} = match {node_var}.get_attr({flit}) {{"),
                    format!(
                        "{indent}    Some({name}) => Some({name}.to_jid().ok_or_else(|| anyhow::anyhow!(\"{fmsg} not a JID\"))?),"
                    ),
                    format!("{indent}    None => None,"),
                    format!("{indent}}};"),
                ]
            };
            out.extend(jid_literal_pin(f, node_var, &flit, &fmsg, indent, true));
            out
        }
        // Every JID flavor materializes as one `Jid`; switch on `is_jid()` so a newly
        // preserved flavor (UserJid/LidUserJid/…) is parsed as a JID, not a String.
        t if t.is_jid() => {
            let mut out = vec![format!(
                "{indent}let {name} = {node_var}.get_attr({flit}).and_then(|v| v.to_jid()).ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?;"
            )];
            out.extend(jid_literal_pin(f, node_var, &flit, &fmsg, indent, false));
            out
        }
        _ if optional => {
            let mut out = vec![format!(
                "{indent}let {name} = {node_var}.get_attr({flit}).map(|v| v.as_str().to_string());"
            )];
            out.extend(enum_membership(f, &name, &fmsg, indent, true));
            out.extend(literal_pin(f, &name, &fmsg, indent, true));
            out
        }
        _ => {
            let mut out = vec![
                format!("{indent}let {name} = {node_var}.get_attr({flit})"),
                format!("{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?"),
                format!("{indent}    .as_str()"),
                format!("{indent}    .to_string();"),
            ];
            out.extend(enum_membership(f, &name, &fmsg, indent, false));
            out.extend(literal_pin(f, &name, &fmsg, indent, false));
            out
        }
    }
}

/// The read for a content leaf whose accessor must DECODE what is there, absence aside.
///
/// The optional decoders end their integer spelling in `parse().ok()`, which merges "no content"
/// with "content that is not a number" — so a `contentInt` relaxed to `required: false` stored
/// `<participant_count>invalid</participant_count>` as an absence. Absence really is absence for
/// such a leaf; a payload that is THERE still has to decode, because the accessor rejects it
/// whenever its path runs.
///
/// Only the integer-from-text spelling can fail: bytes are bytes, a `contentUint` fold cannot
/// fail once the payload is there, and a string is already a string. The rest are the optional
/// decoders unchanged, which keeps one function rather than a fork per kind.
fn content_read_relaxed(f: &ParsedField, node_var: &str, fmsg: &str) -> String {
    let method = f.method.as_str();
    if method == "contentUint" {
        return format!(
            "{node_var}.content_bytes().map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))"
        );
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => format!("{node_var}.content_bytes().map(|b| b.to_vec())"),
        ParsedFieldType::Integer => format!(
            "{node_var}.content_str().map(|s| s.parse::<{}>().map_err(|_| anyhow::anyhow!(\"{fmsg} not a number\"))).transpose()?",
            super::fields::integer_width(f)
        ),
        _ => format!("{node_var}.content_str().map(|s| s.to_string())"),
    }
}

/// Whether a read that fails to DECODE may quietly become `None`.
///
/// Only where the accessor itself spells the optionality. A `maybeAttr…`/`maybeChild` tolerates
/// absence by design, and what it does with a present value it cannot decode is a question about
/// that accessor which this cannot answer from here. A required accessor relaxed by the IR's own
/// `required` flag is a different thing: it runs on some paths only, and when it runs it rejects
/// what it cannot decode — so folding the failure into `None` files a response the source turns
/// away as one where the field is simply absent.
///
/// One predicate, because this is the third round the same question has been answered
/// separately per branch and the third time a branch was missed. The integer read learned it,
/// the JID read beside it did not; both read this now, and the next kind of value has one place
/// to look.
fn tolerates_a_failed_decode(f: &ParsedField) -> bool {
    wap::is_optional_method(&f.method)
}

/// The pin on a JID attribute, compared on the RAW wire text.
///
/// `literal(attrDomainJid, node, "from", "s.whatsapp.net")` accepts one value and one only, and
/// the two JID branches emitted no check at all — the generated parser took any JID that parses
/// where the source takes exactly that one. The round that gave every other kind its pin did not
/// reach these two, which return before [`literal_pin`] is ever called.
///
/// Compared BEFORE the conversion rather than after. The pin is wire text and `Jid` is what that
/// text becomes, so the text is the thing the source actually names; it also keeps the check to
/// accessors the emitted modules already demonstrate — `get_attr` and `as_str` — rather than
/// assuming an equality `Jid` may or may not offer. Nothing in the committed artifacts carries a
/// pinned JID today; the scan preserves both halves, so the shape is reachable and the branch
/// silently accepting everything is the wrong thing to leave behind.
fn jid_literal_pin(
    f: &ParsedField,
    node_var: &str,
    flit: &str,
    fmsg: &str,
    indent: &str,
    optional: bool,
) -> Vec<String> {
    let Some(lit) = f.literal_value.as_deref() else {
        return Vec::new();
    };
    let pin = rust_lit(lit);
    let raw = format!("{node_var}.get_attr({flit}).map(|v| v.as_str())");
    // An ABSENT attribute is not a pin violation where the read admits absence: the field holds
    // the absence, exactly as the optional string pin reads it.
    let test = if optional {
        format!("matches!({raw}, None | Some({pin}))")
    } else {
        format!("{raw} == Some({pin})")
    };
    vec![format!(
        "{indent}anyhow::ensure!({test}, \"{fmsg} not accepted: {{:?}}\", {raw});"
    )]
}

/// The value a `literal(...)` accessor pins the field to, as a check on the decoded read.
///
/// `literal(attrString, node, "type", "result")` rejects `type="error"` at the source. The union
/// arm's `leaf_guard` has compared that pin since the round it was added — it is how an arm is
/// told apart from its siblings — while the ordinary read took any string and stored it. The same
/// asymmetry as the vocabulary, one constraint over.
///
/// Only the string spelling. The IR records the pin as text, and comparing a decoded number or a
/// byte payload against it needs the same care `leaf_guard` takes over an integer pin that does
/// not fit the field's width; those keep the reading they have until there is a case to measure.
fn literal_pin(
    f: &ParsedField,
    name: &str,
    fmsg: &str,
    indent: &str,
    optional: bool,
) -> Vec<String> {
    let Some(lit) = f.literal_value.as_deref() else {
        return Vec::new();
    };
    // Per decoded type, not string alone. The IR records every pin as TEXT, and the committed
    // corpus has `attrInt` pins such as `code = 500` and byte-content ones — for those the
    // decoder took any value the source `literal(...)` accessor turns away. An integer pin is
    // compared AFTER decoding, the same reading `leaf_guard` takes: `"0429"` is a value the
    // source accepts and a raw text compare against `"429"` would reject.
    let width = super::fields::integer_width(f);
    let test = match wap::method_field_type(&f.method) {
        ParsedFieldType::String => {
            let pin = rust_lit(lit);
            if optional {
                format!("matches!({name}.as_deref(), None | Some({pin}))")
            } else {
                format!("{name}.as_str() == {pin}")
            }
        }
        // A pin no value of the field's width can equal is not a pin this can compare — the
        // same `representable` question the union arm asks, answered by the parse itself.
        ParsedFieldType::Integer => {
            let Some(n) = lit.parse::<i128>().ok().filter(|n| match width {
                "i64" => i64::try_from(*n).is_ok(),
                _ => u64::try_from(*n).is_ok(),
            }) else {
                return Vec::new();
            };
            if optional {
                format!("{name}.is_none_or(|n| n == {n}{width})")
            } else {
                format!("{name} == {n}{width}")
            }
        }
        // A byte pin IS comparable: the scan records it as the payload's bytes in lowercase
        // hex, two digits each, and that is a spelling this can decode — `decode_hex` is the
        // same reader the const-content builder uses. Declining it left four live
        // `contentBytes` pins in the committed corpus unenforced, so a `<type>` carrying `06`
        // was stored where the source accessor takes `05` alone. A pin whose text is not that
        // spelling still declines, which is what the decode answering `None` says.
        ParsedFieldType::Bytes => {
            let Some(bytes) = decode_hex(lit) else {
                return Vec::new();
            };
            // An empty pin has no typed literal to compare against — `[]` infers nothing — and
            // "the payload is empty" is the whole of what it says.
            if bytes.is_empty() {
                return match optional {
                    true => vec![format!(
                        "{indent}anyhow::ensure!({name}.as_deref().is_none_or(<[u8]>::is_empty), \"{fmsg} is pinned to an empty payload: {{:?}}\", {name});"
                    )],
                    false => vec![format!(
                        "{indent}anyhow::ensure!({name}.is_empty(), \"{fmsg} is pinned to an empty payload: {{:?}}\", {name});"
                    )],
                };
            }
            // The width is spelled on every element, not just the last: `[0x05, 0x06u8]`
            // infers, and so does `[0x05u8, 0x06u8]`, but only the second says what it means
            // at a glance and neither costs anything.
            let arr = bytes
                .iter()
                .map(|b| format!("0x{b:02x}u8"))
                .collect::<Vec<_>>()
                .join(", ");
            if optional {
                format!("{name}.as_deref().is_none_or(|b| b == [{arr}].as_slice())")
            } else {
                format!("{name}.as_slice() == [{arr}].as_slice()")
            }
        }
        _ => return Vec::new(),
    };
    vec![format!(
        "{indent}anyhow::ensure!({test}, \"{fmsg} is pinned to {}: {{:?}}\", {name});",
        fmt_lit_inner(lit)
    )]
}

/// The byte length a `contentUint(N)` leaf pins, checked on the RAW payload.
///
/// `contentUint` folds N big-endian bytes into a `u64`, so by the time the value exists its
/// length is gone — and the committed IQ IR carries `contentUint(4)`, `(1)` and `(3)`, where
/// that count is part of what the source accessor accepts. The band helper cannot ask this,
/// because it tests the decoded value and the decoded value is a number.
fn raw_length_check(
    leaf: Option<&ParsedField>,
    id: &str,
    fmsg: &str,
    indent: &str,
    node: &str,
) -> Vec<String> {
    let Some(leaf) = leaf else { return Vec::new() };
    if leaf.method != "contentUint" {
        return Vec::new();
    }
    let Some(n) = leaf.byte_length else {
        return Vec::new();
    };
    let _ = id;
    // A REQUIRED read has to reject an absent payload as firmly as a wrong-length one: an
    // existing but empty `<registration/>` yields no bytes at all, and the decoder behind this
    // check ends in `unwrap_or_default`, so letting absence through stores a fabricated zero
    // for a node the source accessor turns away. The optional shape is the other answer —
    // there absence is a value the field can hold, and the read yields `None` on its own.
    //
    // The LEAF's requiredness, which is the only one this question is about. The flattened
    // child path handed it the CHILD's optionality instead, and the two are different facts:
    // `get_optional_child` has already answered whether the element is there, so every check
    // below it judges a node that IS present. For `maybeChild("registration").contentUint(4)`
    // an empty `<registration/>` was flattened to `None` where the source accessor turns that
    // present node away for having no payload — the child's absence and the payload's absence
    // read as one thing. Round twenty-five settled that a wrong length is not an absence; this
    // is the same sentence about whose absence is being asked.
    let present = if leaf.required {
        "is_some_and"
    } else {
        "is_none_or"
    };
    vec![format!(
        "{indent}anyhow::ensure!({node}.content_bytes().{present}(|b| b.len() == {n}), \"{fmsg} wrong length: {{}}\", {node}.content_bytes().map_or(0, |b| b.len()));"
    )]
}

/// The membership check an enum accessor enforces, for a field this path decoded as a plain
/// string and did not validate at all.
///
/// The union arm's selection guard has applied this vocabulary all along; the ordinary read
/// copied whatever text was there, so a `reason="invalid"` became `Some("invalid")` for a field
/// whose accessor takes seven values. One rule, two places, one copy missing it — the fourth
/// constraint to be found that way on this branch, after the integer band, the byte length and
/// the optional-leaf guard.
///
/// Absence is untouched in both shapes. An optional accessor takes a missing attribute, and
/// whether a REQUIRED one tolerates one is a separate question this path already answers its own
/// way; only a value that IS there has to be one the accessor accepts.
fn enum_membership(
    f: &ParsedField,
    name: &str,
    fmsg: &str,
    indent: &str,
    optional: bool,
) -> Vec<String> {
    let Some(values) = super::fields::enum_values(f) else {
        return Vec::new();
    };
    // Two spellings, because the two shapes hand back different types and neither should be
    // bent to the other: the optional read yields an `Option<String>`, whose `None` is a value
    // the accessor takes, and the required read yields a `String` that is always there.
    let lits = |wrap: fn(&str) -> String| {
        values
            .iter()
            .map(|v| wrap(&rust_lit(v)))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let test = if optional {
        format!(
            "matches!({name}.as_deref(), None | {})",
            lits(|l| format!("Some({l})"))
        )
    } else {
        format!("matches!({name}.as_str(), {})", lits(str::to_string))
    };
    vec![format!(
        "{indent}anyhow::ensure!({test}, \"{fmsg} not accepted: {{:?}}\", {name});"
    )]
}

/// How to read a content leaf off a node, as a full expression yielding the field's type.
///
/// `contentInt()` and `contentUint(N)` are BOTH integers and are decoded completely
/// differently: `contentInt` is decimal text (a follower count), while `contentUint(N)`
/// is N big-endian bytes (a 3-byte prekey id, a 4-byte registration id). Reading the
/// latter as text makes every one of them silently `0`, which is what grouping them by
/// `method_field_type` alone did.
pub(crate) fn content_decoder(method: &str) -> &'static str {
    if method == "contentUint" {
        return "content_bytes()\n        .map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))\n        .unwrap_or_default()";
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => "content_bytes().map(|b| b.to_vec()).unwrap_or_default()",
        ParsedFieldType::Integer => {
            "content_str().and_then(|s| s.parse().ok()).unwrap_or_default()"
        }
        _ => "content_str().unwrap_or_default().to_string()",
    }
}

/// The read for a REQUIRED content leaf, which demands the content it is required to carry.
///
/// [`content_decoder`] ends every spelling in `unwrap_or_default`, so `<count></count>` decoded
/// to `0` and `<count>abc</count>` decoded to `0` beside it — both values the source accessor
/// turns away, materialized as an ordinary reading of the response. The union's `leaf_guard` has
/// required content that is present AND parses since it was written, and selects no arm without
/// it; the ordinary struct read accepted everything. One rule, two places, one copy missing it.
///
/// The union ARM keeps `content_decoder`: by the time an arm's members are built its guard has
/// already established both facts, so defaulting there can only be reached where the default is
/// the right answer.
fn content_read_required(f: &ParsedField, node_var: &str, fmsg: &str) -> String {
    let method = f.method.as_str();
    let absent = format!("ok_or_else(|| anyhow::anyhow!(\"missing {fmsg}\"))?");
    // `contentUint(N)` is N big-endian BYTES, not text, which is why it is asked before the
    // classifier — folding them into a `u64` cannot fail once the payload is there.
    if method == "contentUint" {
        return format!(
            "{node_var}.content_bytes().{absent}.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)"
        );
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => format!("{node_var}.content_bytes().{absent}.to_vec()"),
        // The one spelling where PRESENT is not enough: text that does not parse is a value the
        // accessor rejects, and the width is written out so the parse has a type to reach for.
        ParsedFieldType::Integer => format!(
            "{node_var}.content_str().{absent}.parse::<{}>().map_err(|_| anyhow::anyhow!(\"{fmsg} not a number\"))?",
            super::fields::integer_width(f)
        ),
        _ => format!("{node_var}.content_str().{absent}.to_string()"),
    }
}

/// The same read for a leaf the parser only takes sometimes — yielding `Option<T>` where
/// [`content_decoder`] yields `T`.
///
/// A union variant's member is typed from the IR's `required`, so an arm reading its
/// content behind a guard is declared `Option<String>`; defaulting the read instead
/// produced a `String` for that member and the generated module did not compile.
pub(crate) fn content_decoder_opt(method: &str) -> &'static str {
    if method == "contentUint" {
        return "content_bytes().map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))";
    }
    match wap::method_field_type(method) {
        ParsedFieldType::Bytes => "content_bytes().map(|b| b.to_vec())",
        ParsedFieldType::Integer => "content_str().and_then(|s| s.parse().ok())",
        _ => "content_str().map(|s| s.to_string())",
    }
}

/// Emit the body of `parse_response`, ending with `Ok(<ResponseType> {{ ... }})`.
pub(crate) fn emit_response_parser(
    fields: &[ParsedField],
    response_type_name: &str,
    indent: &str,
    prefix: &str,
) -> Vec<String> {
    // lines[0] is reserved for the deferred `use` import, lines[1] is a blank; the
    // body reads off the `response` node and ends in `Ok(<ResponseType> { … })`.
    let mut lines: Vec<String> = vec![String::new(), String::new()];
    lines.extend(emit_struct_parser(
        fields,
        "response",
        response_type_name,
        indent,
        prefix,
    ));
    lines
}

/// Emit the reads for `fields` off `node_var` followed by `Ok(<struct_name> { … })`.
/// Mirrors [`emit_response_parser`] but for an arbitrary node var and struct — reused
/// to build a tag-discriminated union variant's per-arm parser (see [`crate::union`]).
pub(crate) fn emit_struct_parser(
    fields: &[ParsedField],
    node_var: &str,
    struct_name: &str,
    indent: &str,
    prefix: &str,
) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    // Recursively emit the reads off `node_var`, mirroring `collect_response_fields`:
    // attrs/content leaves become fields, repeated children become `Vec<Item>` loops,
    // and a non-repeated child is descended and its fields flattened into the parent
    // (so the parser inits exactly the struct `collect_response_fields` derived).
    let mut wrapper_vars: HashMap<(String, Vec<String>), String> = HashMap::new();
    let mut init_fields: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    emit_struct_reads(
        fields,
        node_var,
        prefix,
        indent,
        &mut lines,
        &mut wrapper_vars,
        &mut init_fields,
        &mut seen,
    );

    lines.push(format!("{indent}Ok({struct_name} {{"));
    lines.extend(init_fields);
    lines.push(format!("{indent}    ..Default::default()"));
    lines.push(format!("{indent}}})"));
    lines
}

/// Descend `path` (a field's `source_path` wrapper tags) from `base`, returning the
/// node var to read off. `source_path` is relative to the enclosing node, so the
/// descent is keyed by `(base, path)` (memoized per base — the same wrapper under two
/// different parents must descend each). Each segment is read as required (a missing
/// wrapper is a parse error), mirroring a required `child`.
/// Descend a RELAXED field's source path without failing when a wrapper is absent.
///
/// [`descend_from`] binds each wrapper with `ok_or_else(missing)?`, which is right for a path the
/// parser always takes. A field flattened out of an OPTIONAL same-node wrapper carries
/// `required: false` — that is how the flattening records it — and the wrapper is no more present
/// than the field: a `<message>` without its `<meta>` is one the source accepts, and descending
/// with the fail-on-absence helper turned it away. That is a rejection the previous round
/// introduced by giving these reads a descent at all; they had none before, and read the item's
/// own attributes instead.
///
/// The field's own read goes inside the arm and yields the `Option<T>` its relaxed type already
/// declares, so an absent wrapper and an absent value are the same answer — which for a field the
/// parser may skip is the right one.
fn emit_relaxed_path_field(cf: &ParsedField, base: &str, indent: &str) -> Vec<String> {
    let path = cf.source_path.as_deref().unwrap_or_default();
    let name = rust_ident(&cf.name);
    let wrap = format!("{name}__wrap");
    let mut chain = format!("{base}.get_optional_child({})", rust_lit(&path[0]));
    for seg in &path[1..] {
        chain = format!(
            "{chain}.and_then(|w| w.get_optional_child({}))",
            rust_lit(seg)
        );
    }
    let inner = format!("{indent}        ");
    let mut out = vec![
        format!("{indent}let {name} = match {chain} {{"),
        format!("{indent}    Some({wrap}) => {{"),
    ];
    out.extend(emit_field_parse(cf, &wrap, &inner));
    out.push(format!("{inner}{name}"));
    out.push(format!("{indent}    }}"));
    out.push(format!("{indent}    None => None,"));
    out.push(format!("{indent}}};"));
    out
}

/// Whether this field's source path must be descended without failing on an absent wrapper.
fn path_is_optional(cf: &ParsedField) -> bool {
    !cf.required && cf.source_path.as_deref().is_some_and(|p| !p.is_empty())
}

fn descend_from(
    base: &str,
    path: Option<&[String]>,
    vars: &mut HashMap<(String, Vec<String>), String>,
    lines: &mut Vec<String>,
    indent: &str,
) -> String {
    let Some(path) = path.filter(|p| !p.is_empty()) else {
        return base.to_string();
    };
    let mut parent = base.to_string();
    let mut acc: Vec<String> = Vec::new();
    for seg in path {
        acc.push(seg.clone());
        let key = (base.to_string(), acc.clone());
        if let Some(var) = vars.get(&key) {
            parent = var.clone();
            continue;
        }
        let segs = acc
            .iter()
            .map(|s| snake_case(s))
            .collect::<Vec<_>>()
            .join("_");
        // The common top-level descent stays `<path>_wrap`; nested descents prefix the
        // base node so the same wrapper tag under different parents can't collide.
        let var = if base == "response" {
            format!("{segs}_wrap")
        } else {
            format!("{}__{segs}_wrap", snake_case(base))
        };
        lines.push(format!(
            "{indent}let {var} = {parent}.get_optional_child({})",
            rust_lit(seg)
        ));
        lines.push(format!(
            "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
            fmt_lit_inner(seg)
        ));
        vars.insert(key, var.clone());
        parent = var;
    }
    parent
}

/// Recursively emit the reads for `fields` off `node_var`, appending each resulting
/// struct field to `inits` (deduped via `seen`). Mirrors `collect_response_fields`
/// branch-for-branch so the parser inits exactly the fields that function derives:
/// attrs/content-leaves become fields read off the (source-path-descended) node; a
/// repeated child becomes a `Vec<Item>` loop (with one level of repeated grandchild
/// item vecs, as collect models); a non-repeated child is descended and its fields
/// flattened into the SAME struct (collect inlines single children).
#[allow(clippy::too_many_arguments)]
fn emit_struct_reads(
    fields: &[ParsedField],
    node_var: &str,
    prefix: &str,
    indent: &str,
    lines: &mut Vec<String>,
    wrapper_vars: &mut HashMap<(String, Vec<String>), String>,
    inits: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    let fields = flatten_same_node(fields);
    for f in &fields {
        // ── discriminated union (`type=union`) → enum read ──
        // Gated on the same `classify_union` that `collect_response_fields` uses, so a
        // codegen-able union inits the `Option<Enum>` field collect derived, and an
        // unsupported one is skipped by both (the rest of the struct stays typed).
        if f.field_type == ParsedFieldType::Union {
            let id = rust_ident(&f.name);
            if !seen.insert(id.clone()) {
                continue;
            }
            // `emit_union_read` handles its own (optional) `source_path` descent — a
            // union is `Option<Enum>`, so an absent wrapper must yield `None`, not the
            // required `?` descent `descend_from` would emit.
            if let Some((union_lines, init)) =
                crate::union::emit_union_read(f, node_var, prefix, indent)
            {
                lines.extend(union_lines);
                inits.push(init);
            } else {
                seen.remove(&id);
            }
            continue;
        }
        // ── attribute / content-leaf-via-method field ──
        if is_attr_field(f) && f.method != "hasAttr" {
            let id = rust_ident(&f.name);
            if !seen.insert(id.clone()) {
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            lines.extend(emit_field_parse(f, &base, indent));
            inits.push(format!("{indent}    {id},"));
            continue;
        }
        if !is_child_field(f) {
            continue;
        }
        let tag = tag_or_name(f);

        // ── child whose content is the value (`child("x").contentString()`) ──
        if let Some(ct) = f.content_type.or_else(|| child_content_type(f)) {
            let id = rust_ident(tag);
            if !seen.insert(id.clone()) {
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            let lit = rust_lit(tag);
            // Two spellings per kind: one that yields an `Option` for the `maybeChild`
            // chain, one that unwraps for the required branch. Kept as literal text per
            // kind so adding the integer reading leaves the existing bytes/string output
            // byte-for-byte unchanged.
            //
            // The child's OWN accessor decides when it has one, because `ContentType`
            // cannot tell decimal text from big-endian bytes: `contentInt` and
            // `contentUint` are both `Integer` and decode oppositely.
            let leaf = children_of(f)
                .iter()
                .find(|c| wap::is_content_method(&c.method));
            let leaf_method = leaf.map(|c| c.method.as_str());
            let (opt_read, req_read) = match leaf_method {
                Some("contentUint") => (
                    "content_bytes().map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))",
                    "content_bytes()\n        .map(|b| b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64))\n        .unwrap_or_default()",
                ),
                _ => match ct {
                    wa_ir::ContentType::Bytes => (
                        "content_bytes().map(|b| b.to_vec())",
                        "content_bytes().map(|b| b.to_vec()).unwrap_or_default()",
                    ),
                    wa_ir::ContentType::Integer => (
                        "content_str().and_then(|s| s.parse().ok())",
                        "content_str().and_then(|s| s.parse().ok()).unwrap_or_default()",
                    ),
                    _ => (
                        "content_str().map(|s| s.to_string())",
                        "content_str().unwrap_or_default().to_string()",
                    ),
                },
            };
            // The leaf's declared band, which THIS path was not applying. A relaxed
            // `child("weight")` over a `contentInt` leaf bounded to `-10..=10` bypasses
            // `emit_field_parse` entirely and parsed a `-20` straight into the field. That is
            // the third site for one rule — the attribute read, the ordinary content read, and
            // here — so it is `int_band` again rather than a third spelling, and it is asked of
            // the LEAF, which is also where `collect_response_fields` took the width from.
            let fmsg = fmt_lit_inner(tag);
            // The leaf's declared band, and its declared LENGTH — this path was given the
            // integer one and the byte one reached the two other content paths without reaching
            // here, so `child("blob")` over a `contentBytes(32)` leaf stored a vector of any
            // length. The length is gated on the decoded value being bytes, so a `contentUint`
            // fold into a `u64` is not asked for its `len()`. Each keeps its own message,
            // because a value out of range and a payload of the wrong length are not the same
            // report and the value they name is not the same expression.
            // A LIST of checks, not one. A leaf can carry both a constraint and a pin —
            // `contentLiteralBytes` records the payload's length and its exact bytes — and a
            // single slot could only ever emit whichever was asked for first. That is how the
            // four committed `contentBytes` pins reached the emitter with their length checked
            // and their value not.
            let band = leaf.map_or_else(Vec::new, |c| {
                let mut out = Vec::new();
                if let Some(test) = super::fields::int_band(c, &id) {
                    out.push(format!(
                        "anyhow::ensure!({test}, \"{fmsg} out of range: {{}}\", {id});"
                    ));
                }
                // The leaf's vocabulary, which the two other content paths enforce and this one
                // did not: the committed `token_type` child carries a `contentEnum` limited to
                // two values and stored any string at all. Fourth site for that rule, the same
                // count the integer band and the byte length each took to close.
                else if let Some(values) = super::fields::enum_values(c) {
                    let arms = values
                        .iter()
                        .map(|v| rust_lit(v))
                        .collect::<Vec<_>>()
                        .join(" | ");
                    out.push(format!(
                        "anyhow::ensure!(matches!({id}.as_str(), {arms}), \"{fmsg} not accepted: {{:?}}\", {id});"
                    ));
                } else if wap::method_field_type(&c.method) == ParsedFieldType::Bytes
                    && let Some(test) = super::fields::byte_band(c, &id)
                {
                    out.push(format!(
                        "anyhow::ensure!({test}, \"{fmsg} wrong length: {{}}\", {id}.len());"
                    ));
                }
                // …and the exact value the accessor pins, which the two other content paths
                // compare and this one never did. Additive, not exclusive: a pinned payload has
                // a length as well, and both are part of what the source accepts. The value
                // inside the arm below is unwrapped, so the pin is asked of a present one.
                out.extend(literal_pin(c, &id, &fmsg, "", false));
                out
            });
            // Same two sources as the declared type, or the initializer will not match it.
            if f.method == "maybeChild" || !f.required {
                // The child lookup and the leaf decode are two questions, and chaining them
                // into `get_optional_child(…).and_then(|n| n.read())` folds a PRESENT element
                // with no payload into the same `None` as an absent element. Round sixty drew
                // that distinction for the raw-length check and round twenty-five for the band;
                // both wrote it as a branch taken only when the leaf declared something, so an
                // UNCONSTRAINED leaf kept the chain — and the committed optional
                // `device-identity` and `verified_name` byte children, and the notification
                // body strings, are exactly that shape. An empty `<device-identity/>` read as
                // an absent one.
                //
                // One shape for all of them now, whatever the leaf declares. What a leaf
                // declares decides which checks go INSIDE the arm, never whether the element's
                // presence is distinguished from its payload's.
                let inner = format!("{indent}        ");
                lines.push(format!(
                    "{indent}let {id} = match {base}.get_optional_child({lit}) {{"
                ));
                lines.push(format!("{indent}    Some({id}_node) => {{"));
                lines.extend(raw_length_check(
                    leaf,
                    &id,
                    &fmsg,
                    &inner,
                    &format!("{id}_node"),
                ));
                // …and the leaf must decode what is THERE, whether or not it is required:
                // absence stays absence, a present payload it cannot read is a rejection. The
                // committed `participant_count` is a relaxed `contentInt`, and `parse().ok()`
                // filed `invalid` as a missing value.
                //
                // Asked of every content leaf, with no optionality test beside it. No content
                // accessor spells optionality — `is_content_method` lists eight names and not one
                // begins with `maybe`, the same fact round seventy-four leaned on from the other
                // side — so a `tolerates_a_failed_decode` gate here could never answer anything
                // but "must decode", and a gate no input can move is worse than no gate. Whether
                // ABSENCE is an error is the separate question the arms below hold.
                let leaf_read = match leaf {
                    Some(c) => content_read_relaxed(c, &format!("{id}_node"), &fmsg),
                    None => format!("{id}_node.{opt_read}"),
                };
                if leaf.is_some_and(|c| c.required) {
                    // A required leaf makes an absent payload a REJECTION, not an absence: the
                    // accessor throws, and folding it to `None` would leave the field simply
                    // missing from a response the parser turns away.
                    lines.push(format!("{inner}let {id} = {leaf_read}"));
                    lines.push(format!(
                        "{inner}    .ok_or_else(|| anyhow::anyhow!(\"<{fmsg}> has no content\"))?;"
                    ));
                    lines.extend(band.iter().map(|c| format!("{inner}{c}")));
                    lines.push(format!("{inner}Some({id})"));
                } else {
                    // An optional leaf really may be absent, and only a value that IS there has
                    // to satisfy what the leaf declares.
                    lines.push(format!("{inner}match {leaf_read} {{"));
                    lines.push(format!("{inner}    Some({id}) => {{"));
                    lines.extend(band.iter().map(|c| format!("{inner}        {c}")));
                    lines.push(format!("{inner}        Some({id})"));
                    lines.push(format!("{inner}    }}"));
                    lines.push(format!("{inner}    None => None,"));
                    lines.push(format!("{inner}}}"));
                }
                lines.push(format!("{indent}    }}"));
                lines.push(format!("{indent}    None => None,"));
                lines.push(format!("{indent}}};"));
            } else {
                lines.push(format!(
                    "{indent}let {id}_node = {base}.get_optional_child({lit})"
                ));
                lines.push(format!(
                    "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
                    fmt_lit_inner(tag)
                ));
                lines.extend(raw_length_check(
                    leaf,
                    &id,
                    &fmsg,
                    indent,
                    &format!("{id}_node"),
                ));
                // …and it DEMANDS the content when the leaf is required, which is the same
                // question `emit_field_parse` was taught two rounds ago and this path was not.
                // `req_read` ends every spelling in `unwrap_or_default`, so an empty `<detail/>`
                // read as the type's default — and once a required content read counted toward
                // a variant's discriminator signature, that signature was claiming a failure
                // this parser does not perform. Two arms could then look disjoint while the
                // first accepted everything the second wanted, which is exactly the shadowing
                // the gate exists to refuse. I added the signature entry last round without
                // checking every emitter path honoured it; this is the path that did not.
                let demands = leaf.is_some_and(|c| c.required);
                lines.push(match leaf.filter(|_| demands) {
                    Some(c) => format!(
                        "{indent}let {id} = {};",
                        content_read_required(c, &format!("{id}_node"), &fmsg)
                    ),
                    None => format!("{indent}let {id} = {id}_node.{req_read};"),
                });
                lines.extend(band.iter().map(|c| format!("{indent}{c}")));
            }
            inits.push(format!("{indent}    {id},"));
            continue;
        }

        let kids = children_of(f);
        if kids.is_empty() {
            continue;
        }

        if repeats(f) {
            // Repeated child → `Vec<Item>`. The Item carries this child's own attrs
            // and one level of repeated grandchild vecs (matching collect).
            let id = rust_ident(tag);
            if !seen.insert(id.clone()) {
                continue;
            }
            // Use `kids` as-is (no same-node flatten) so the Item's read set matches
            // what `collect_response_fields` puts in the `<Tag>Item` struct exactly.
            let item_attrs = dedup_attrs(kids);
            let nested_repeats: Vec<&ParsedField> = kids
                .iter()
                .filter(|n| is_child_field(n) && repeats(n) && !children_of(n).is_empty())
                .filter(|n| !dedup_attrs(children_of(n)).is_empty())
                .collect();
            let union_kids: Vec<&ParsedField> = kids
                .iter()
                .filter(|n| n.field_type == ParsedFieldType::Union)
                .collect();
            if item_attrs.is_empty() && nested_repeats.is_empty() && union_kids.is_empty() {
                seen.remove(&id);
                continue;
            }
            let struct_name = format!("{prefix}{}Item", pascal_case(tag));
            let vec_var = format!("{}_items", snake_case(tag));
            let loop_var = format!("{}_item", snake_case(tag));
            let inner = format!("{indent}    ");
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            lines.push(format!("{indent}let mut {vec_var} = Vec::new();"));
            lines.push(format!(
                "{indent}for {loop_var} in {base}.get_children_by_tag({}) {{",
                rust_lit(tag)
            ));
            // A repeated item's field can sit BELOW it: `sourcePath: ["background"]` puts the
            // value in a `<background>` inside the item, and reading it off the item itself
            // decoded the parent's own content — so a valid item was rejected as missing the
            // field. Eighteen reads in the committed IR are shaped this way.
            //
            // Its own cache, because these wrappers are bound INSIDE the loop body: an entry
            // escaping into the code after the loop would name a binding that is gone. The
            // outer map is keyed by base, so nothing here could have collided with it anyway —
            // the scoping is what matters.
            let mut item_wrappers: HashMap<(String, Vec<String>), String> = HashMap::new();
            for cf in &item_attrs {
                if path_is_optional(cf) {
                    lines.extend(emit_relaxed_path_field(cf, &loop_var, &inner));
                    continue;
                }
                let cbase = descend_from(
                    &loop_var,
                    cf.source_path.as_deref(),
                    &mut item_wrappers,
                    lines,
                    &inner,
                );
                lines.extend(emit_field_parse(cf, &cbase, &inner));
            }
            // `type=union` columns on the Item: read each off the item node (prefixed by
            // the Item struct so the generated enum/variant structs match collect).
            let mut union_init: Vec<String> = Vec::new();
            for uf in &union_kids {
                if let Some((ulines, uinit)) =
                    crate::union::emit_union_read(uf, &loop_var, &struct_name, &inner)
                {
                    lines.extend(ulines);
                    union_init.push(uinit);
                }
            }
            let mut nested_init: Vec<String> = Vec::new();
            for nf in &nested_repeats {
                let n_tag = tag_or_name(nf);
                // collect names the nested item `<prefix><Tag>Item` (spec-prefixed).
                let n_struct = format!("{prefix}{}Item", pascal_case(n_tag));
                let n_vec = format!("{}_items", snake_case(n_tag));
                let n_loop = format!("{}_item", snake_case(n_tag));
                let n_inner = format!("{inner}    ");
                let n_attrs = dedup_attrs(children_of(nf));
                let n_base = descend_from(
                    &loop_var,
                    nf.source_path.as_deref(),
                    wrapper_vars,
                    lines,
                    &inner,
                );
                lines.push(format!("{inner}let mut {n_vec} = Vec::new();"));
                lines.push(format!(
                    "{inner}for {n_loop} in {n_base}.get_children_by_tag({}) {{",
                    rust_lit(n_tag)
                ));
                // …and the nested repeated loop, which reads its fields the same way.
                let mut n_wrappers: HashMap<(String, Vec<String>), String> = HashMap::new();
                for ncf in &n_attrs {
                    if path_is_optional(ncf) {
                        lines.extend(emit_relaxed_path_field(ncf, &n_loop, &n_inner));
                        continue;
                    }
                    let nbase = descend_from(
                        &n_loop,
                        ncf.source_path.as_deref(),
                        &mut n_wrappers,
                        lines,
                        &n_inner,
                    );
                    lines.extend(emit_field_parse(ncf, &nbase, &n_inner));
                }
                lines.push(format!("{n_inner}{n_vec}.push({n_struct} {{"));
                for ncf in &n_attrs {
                    lines.push(format!("{n_inner}    {},", rust_ident(&ncf.name)));
                }
                lines.push(format!("{n_inner}    ..Default::default()"));
                lines.push(format!("{n_inner}}});"));
                lines.push(format!("{inner}}}"));
                nested_init.push(format!("{inner}    {}: {n_vec},", rust_ident(n_tag)));
            }
            lines.push(format!("{inner}{vec_var}.push({struct_name} {{"));
            for cf in &item_attrs {
                lines.push(format!("{inner}    {},", rust_ident(&cf.name)));
            }
            lines.extend(union_init);
            lines.extend(nested_init);
            lines.push(format!("{inner}    ..Default::default()"));
            lines.push(format!("{inner}}});"));
            lines.push(format!("{indent}}}"));
            inits.push(format!("{indent}    {id}: {vec_var},"));
        } else {
            // Non-repeated child → descend and flatten its fields into the current
            // struct, mirroring collect's single-child inlining. The descent is
            // emitted as a required (`?`) binding ONLY when the subtree actually reads
            // a field: a childless wrapper (e.g. a bare `<appeal_status/>` marker that
            // contributes nothing to the struct) would otherwise create a dead binding
            // whose required `ok_or_else` makes the whole parse fail whenever that
            // optional marker is simply absent. Decide via a scratch run over clones
            // (so a discarded subtree pollutes neither `seen` nor `wrapper_vars`), then
            // re-run against the real buffers to commit consistently.
            let cvar = rust_ident(tag);
            let mut scratch_lines: Vec<String> = Vec::new();
            let mut scratch_inits: Vec<String> = Vec::new();
            let mut scratch_seen = seen.clone();
            let mut scratch_vars = wrapper_vars.clone();
            emit_struct_reads(
                kids,
                &cvar,
                prefix,
                indent,
                &mut scratch_lines,
                &mut scratch_vars,
                &mut scratch_inits,
                &mut scratch_seen,
            );
            if scratch_inits.is_empty() {
                // Childless wrapper — descending would read nothing, so skip it
                // entirely rather than emit a dead, fragile required binding.
                continue;
            }
            let base = descend_from(
                node_var,
                f.source_path.as_deref(),
                wrapper_vars,
                lines,
                indent,
            );
            if f.required {
                // Required child: a missing `<tag>` is a parse error.
                lines.push(format!(
                    "{indent}let {cvar} = {base}.get_optional_child({})",
                    rust_lit(tag)
                ));
                lines.push(format!(
                    "{indent}    .ok_or_else(|| anyhow::anyhow!(\"missing <{}>\"))?;",
                    fmt_lit_inner(tag)
                ));
                emit_struct_reads(
                    kids,
                    &cvar,
                    prefix,
                    indent,
                    lines,
                    wrapper_vars,
                    inits,
                    seen,
                );
            } else {
                // Optional child (`optionalChildWithTag` in smax): when absent, its
                // fields default rather than failing the whole parse. Read the subtree
                // inside `if let Some(<tag>)` and bind every contributed field through a
                // tuple, defaulting each in the `else`. Field TYPES are unchanged (the
                // `else` defaults each element), so `collect_response_fields` needs no
                // weakening — required leaves INSIDE a present child still fail-fast.
                let inner = format!("{indent}    ");
                let mut body_lines: Vec<String> = Vec::new();
                let mut body_inits: Vec<String> = Vec::new();
                // A wrapper bound INSIDE this `if let` is not in scope after it, so the cache
                // must not carry it out. Two optional siblings sharing a tag and a nested source
                // path had the second suppress its own declaration and emit a reference to the
                // first's binding — a generated module that does not compile. A clone goes in,
                // so the outer entries (still in scope) are reused, and nothing comes back out.
                let mut branch_wrappers = wrapper_vars.clone();
                emit_struct_reads(
                    kids,
                    &cvar,
                    prefix,
                    &inner,
                    &mut body_lines,
                    &mut branch_wrappers,
                    &mut body_inits,
                    seen,
                );
                // Map each init `name,` / `name: value,` to (outer binding, inner value).
                let pairs: Vec<(String, String)> = body_inits
                    .iter()
                    .map(|l| {
                        let t = l.trim().trim_end_matches(',');
                        match t.split_once(": ") {
                            Some((name, value)) => (name.to_string(), value.to_string()),
                            None => (t.to_string(), t.to_string()),
                        }
                    })
                    .collect();
                let names = pairs.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
                let values = pairs.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
                let defaults = vec!["Default::default()".to_string(); pairs.len()];
                // A 1-tuple needs the trailing comma; >1 don't (and reads cleaner).
                let tuple = |items: &[String]| {
                    if items.len() == 1 {
                        format!("({},)", items[0])
                    } else {
                        format!("({})", items.join(", "))
                    }
                };
                lines.push(format!(
                    "{indent}let {} = if let Some({cvar}) = {base}.get_optional_child({}) {{",
                    tuple(&names),
                    rust_lit(tag)
                ));
                lines.extend(body_lines);
                lines.push(format!("{inner}{}", tuple(&values)));
                lines.push(format!("{indent}}} else {{"));
                lines.push(format!("{inner}{}", tuple(&defaults)));
                lines.push(format!("{indent}}};"));
                for n in names {
                    inits.push(format!("{indent}    {n},"));
                }
            }
        }
    }
}

/// Dedup attribute children by name, dropping `hasAttr`.
fn dedup_attrs(kids: &[ParsedField]) -> Vec<&ParsedField> {
    let mut seen = std::collections::HashSet::new();
    kids.iter()
        .filter(|f| is_attr_field(f) && f.method != "hasAttr")
        .filter(|f| seen.insert(f.name.clone()))
        .collect()
}

/// Accumulators threaded through [`emit_child_builder`] for a node's variant groups
/// (smax MixinGroup disjunctions): `enum_defs` collects the top-level `enum` types,
/// `fields` the `(struct_field, type, optional)` triples the spec struct must carry.
/// `spec_base` prefixes generated enum names so two specs don't collide.
pub(crate) struct VariantCtx<'a> {
    pub spec_base: &'a str,
    pub enum_defs: &'a mut Vec<String>,
    pub fields: &'a mut Vec<(String, String, bool)>,
    /// Field names the spec already declares from the request's ATTRIBUTES, collected before
    /// this walk begins and so invisible to `fields`.
    ///
    /// A content field is synthesized from the node's var name, and a node may carry an
    /// attribute that spells the same thing: `<website website_content="…">payload</website>`
    /// declared `website_content` twice, with two types and two constructor parameters, and the
    /// generated module did not compile.
    pub reserved: &'a std::collections::HashSet<String>,
    /// Which spec field each attribute SITE reads, keyed by the path of tags down to its node.
    ///
    /// Two nodes may spell an attribute the same way and mean different things, so the field a
    /// site writes is not derivable from the attribute name alone — the collection pass resolved
    /// it and this is where the builder reads that answer back.
    pub attr_fields: &'a crate::spec::AttrFieldMap,
}

/// A field name this spec does not already use, from either source.
fn unique_field(ctx: &VariantCtx, base: &str) -> String {
    let taken = |n: &str| ctx.reserved.contains(n) || ctx.fields.iter().any(|(f, _, _)| f == n);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}_{n}"))
        .find(|n| !taken(n))
        .expect("an unused suffix exists")
}

/// Emit the `let <tag>_node = NodeBuilder::new("tag")…build();` statements for a
/// request child, recursing into nested children first. `used_names` dedups
/// repeated tags. Returns `(lines, var_name)` — the caller takes the returned
/// var name rather than reconstructing it from the shared counter (which is
/// bumped further by sibling/grandchild recursion).
///
/// The node is built through a rebindable `let mut` so optional attributes can be
/// added conditionally (`if let Some(v) = &self.x`), which a fluent chain can't.
/// A node's variant groups (mutually-exclusive MixinGroup alternatives) generate an
/// `enum` per group and a `match` in the build; see [`emit_variant_groups`].
pub(crate) fn emit_child_builder(
    child: &WapChildNode,
    indent: &str,
    used_names: &mut HashMap<String, usize>,
    ctx: &mut VariantCtx,
    path: &[String],
) -> (Vec<String>, String, bool) {
    let mut lines: Vec<String> = Vec::new();
    let here: Vec<String> = path.iter().cloned().chain([child.tag.clone()]).collect();
    let base_name = format!("{}_node", snake_case(&child.tag));
    let count = *used_names.get(&base_name).unwrap_or(&0);
    used_names.insert(base_name.clone(), count + 1);
    let var_name = if count == 0 {
        base_name.clone()
    } else {
        format!("{base_name}_{}", count + 1)
    };

    let mut nested_var_names: Vec<(String, bool)> = Vec::new();
    for nested in &child.children {
        let (nested_lines, nested_var, nested_is_list) =
            emit_child_builder(nested, indent, used_names, ctx, &here);
        lines.extend(nested_lines);
        nested_var_names.push((nested_var, nested_is_list));
    }
    // A child that REPEATS and carries opaque content is as many nodes as the caller has
    // payloads. It was one field and one node, so a request with two `<area_description>`
    // entries — which the committed business profile sends — could not be reproduced at all.
    // Only this shape: no attributes, no children of its own, nothing but the payload, which is
    // what the committed node is and all this can build one-per-entry without guessing which
    // parts vary between them.
    if child.repeats
        && child.children.is_empty()
        && child.variant_groups.is_empty()
        && child.attrs.is_empty()
        && child
            .content
            .as_ref()
            .is_some_and(|c| c.kind == WapContentKind::Dynamic && c.const_bytes.is_none())
    {
        let field = unique_field(ctx, &content_field_name(&var_name));
        let element = child
            .content
            .as_ref()
            .map_or_else(|| "Vec<u8>".to_string(), payload_type);
        ctx.fields
            .push((field.clone(), format!("Vec<{element}>"), false));
        let list = format!("{var_name}s");
        lines.push(format!("{indent}let mut {list} = Vec::new();"));
        lines.push(format!("{indent}for payload in &self.{field} {{"));
        lines.push(format!(
            "{indent}    {list}.push(NodeBuilder::new({}).bytes({}).build());",
            rust_lit(&child.tag),
            child.content.as_ref().map_or_else(
                || "payload.clone()".to_string(),
                |c| payload_expr(c, "payload")
            )
        ));
        lines.push(format!("{indent}}}"));
        return (lines, list, true);
    }

    // Collect the attr/children mutations; the node only needs `mut` if there's
    // at least one (otherwise `unused_mut` would warn in the consumer).
    let mut body: Vec<String> = Vec::new();
    // `.children(…)` SETS a node's children, so the static list and a variant's cannot each
    // call it — the second would erase the first. Where a variant contributes children they
    // share one accumulator, seeded with the static ones so those keep their leading position,
    // and it is attached once at the end. Where none does, the array spelling is left exactly
    // as it was so every other node's emission is unchanged.
    let variant_children = child
        .variant_groups
        .iter()
        .flat_map(|g| &g.variants)
        .any(|v| !v.children.is_empty());
    // A list of nodes cannot sit inside the `[a, b]` array spelling, so any nested child that
    // yields one puts every sibling through the same accumulator the variant children use.
    let nested_list = nested_var_names.iter().any(|(_, is_list)| *is_list);
    if variant_children || nested_list {
        body.push(format!(
            "{indent}let mut {var_name}_children: Vec<wacore_binary::node::Node> = Vec::new();"
        ));
        for (v, is_list) in &nested_var_names {
            body.push(if *is_list {
                format!("{indent}{var_name}_children.extend({v});")
            } else {
                format!("{indent}{var_name}_children.push({v});")
            });
        }
    }
    for attr in &child.attrs {
        let alit = rust_lit(&attr.name);
        // The field this SITE reads, which the collection pass resolved: a name shared with
        // another node's attribute was given a distinct field there, and deriving it from the
        // attribute name here would write both sites to whichever one won.
        let ident = ctx
            .attr_fields
            .get(&(here.clone(), attr.name.clone()))
            .cloned()
            .unwrap_or_else(|| rust_ident(&attr.name));
        match &attr.kind {
            WapAttrKind::Const => {
                if let Some(value) = &attr.value {
                    body.push(format!(
                        "{indent}{var_name} = {var_name}.attr({alit}, {});",
                        rust_lit(value)
                    ));
                }
            }
            WapAttrKind::String | WapAttrKind::Dynamic => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, &*self.{ident});"
                ));
            }
            WapAttrKind::Integer => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, self.{ident}.to_string());"
                ));
            }
            k if is_jid_kind(k) => {
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, self.{ident}.clone());"
                ));
            }
            WapAttrKind::Optional => {
                body.push(format!(
                    "{indent}if let Some(v) = &self.{ident} {{ {var_name} = {var_name}.attr({alit}, v.as_str()); }}"
                ));
            }
            // A GENERATED id is an attribute the request carries, not one it lacks. It reached
            // the catch-all and was dropped, so the committed `<usync sid>` and the nested
            // `<iq id>` of `updateCartEnabled` were built without them — requests the source
            // cannot send. Threaded as a caller-supplied `String`: what generates it is the
            // consumer's business (a counter, a random id, a session sequence), and this cannot
            // call a generator it has never seen. `collect_attrs` skips this kind, so the field
            // is declared here and reserved against the names that pass already exposed.
            WapAttrKind::GeneratedId => {
                let field = unique_field(ctx, &ident);
                ctx.fields
                    .push((field.clone(), "String".to_string(), false));
                body.push(format!(
                    "{indent}{var_name} = {var_name}.attr({alit}, self.{field}.as_str());"
                ));
            }
            _ => {}
        }
    }
    body.extend(emit_variant_groups(child, &var_name, indent, ctx));
    body.extend(emit_node_content(child, &var_name, indent, ctx));
    if variant_children || nested_list {
        body.push(format!(
            "{indent}{var_name} = {var_name}.children({var_name}_children);"
        ));
    } else if !nested_var_names.is_empty() {
        body.push(format!(
            "{indent}{var_name} = {var_name}.children([{}]);",
            nested_var_names
                .iter()
                .map(|(v, _)| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if body.is_empty() {
        lines.push(format!(
            "{indent}let {var_name} = NodeBuilder::new({}).build();",
            rust_lit(&child.tag)
        ));
    } else {
        lines.push(format!(
            "{indent}let mut {var_name} = NodeBuilder::new({});",
            rust_lit(&child.tag)
        ));
        lines.extend(body);
        lines.push(format!("{indent}let {var_name} = {var_name}.build();"));
    }
    (lines, var_name, false)
}

/// Emit, for each of a node's variant groups, a top-level `enum` (pushed to
/// `ctx.enum_defs`), a spec-struct field (pushed to `ctx.fields`), and the build
/// `match` that applies the chosen variant's attrs to `var_name`. A group is a smax
/// MixinGroup disjunction: exactly one variant applies (or none, when optional).
fn emit_variant_groups(
    node: &WapChildNode,
    var_name: &str,
    indent: &str,
    ctx: &mut VariantCtx,
) -> Vec<String> {
    let mut build = Vec::new();
    let multi = node.variant_groups.len() > 1;
    for (gi, group) in node.variant_groups.iter().enumerate() {
        let base = format!("{}{}", ctx.spec_base, pascal_case(&node.tag));
        let enum_name = if multi {
            format!("{base}Variant{}", gi + 1)
        } else {
            format!("{base}Variant")
        };
        // Through `rust_ident`, and the `_vN` suffix on the PLAIN spelling first: a node tagged
        // `<type>` produced `pub type`, a `type` parameter and `self.type`, none of which
        // compile, and `r#type_v2` would be no better. The variant CHILD member learned this two
        // rounds ago and the group's own field was left on `snake_case` beside it.
        let field = {
            let f = snake_case(&node.tag);
            rust_ident(&if multi { format!("{f}_v{}", gi + 1) } else { f })
        };
        let disc = variant_discriminator(group);
        // Deduped variant names: when the discriminator can't tell variants apart
        // (e.g. six `<config>` alternatives that all lead with a dynamic `platform`
        // attr → all named `Platform`), suffix collisions so the enum has distinct
        // variants. Computed once and indexed by both the def and the match below so
        // the arm always names the same variant the def declared.
        let vnames = dedup_variant_names(group, disc.as_deref());

        // enum definition
        let mut def = vec![
            "#[derive(Debug, Clone)]".to_string(),
            format!("pub enum {enum_name} {{"),
        ];
        for (vi, v) in group.variants.iter().enumerate() {
            let vname = &vnames[vi];
            let mut payload: Vec<String> = v
                .attrs
                .iter()
                .filter(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
                .map(|a| {
                    format!(
                        "{}: {}",
                        rust_ident(&a.name),
                        crate::fields::rust_attr_type(&a.kind)
                    )
                })
                .collect();
            // …and the CHILDREN the variant contributes, which this enum carried none of. A
            // variant is "the attrs and children this alternative adds to the node", and the
            // payload was built from half of it — so choosing the `<config>` variant whose
            // shape is a repeated `<item>` list emitted a `<config>` with no items, a request
            // the source cannot produce and the caller has no way to complete.
            for c in &v.children {
                let (member, ty, def) = variant_child_member(&enum_name, vname, c, &v.attrs);
                payload.push(format!("{member}: {ty}"));
                ctx.enum_defs.extend(def);
            }
            if payload.is_empty() {
                def.push(format!("    {vname},"));
            } else {
                def.push(format!("    {vname} {{ {} }},", payload.join(", ")));
            }
        }
        def.push("}".to_string());
        ctx.enum_defs.extend(def);
        ctx.enum_defs.push(String::new());

        let ty = if group.optional {
            format!("Option<{enum_name}>")
        } else {
            enum_name.clone()
        };
        ctx.fields.push((field.clone(), ty, group.optional));

        // build match
        let (matchee, inner_indent) = if group.optional {
            build.push(format!("{indent}if let Some(__v) = &self.{field} {{"));
            ("__v".to_string(), format!("{indent}    "))
        } else {
            (format!("&self.{field}"), indent.to_string())
        };
        build.push(format!("{inner_indent}match {matchee} {{"));
        for (vi, v) in group.variants.iter().enumerate() {
            let vname = &vnames[vi];
            build.extend(variant_arm(
                &enum_name,
                vname,
                v,
                var_name,
                &format!("{inner_indent}    "),
            ));
        }
        build.push(format!("{inner_indent}}}"));
        if group.optional {
            build.push(format!("{indent}}}"));
        }
    }
    build
}

/// Emit the leaf element content of a request node (`<value>`, `<signature>`, the
/// prekey `<link_code_pairing_nonce>`) — the byte payload the node carries between
/// its tags. Without this a key-material node builds empty and is unusable on the
/// wire. Two shapes, both `bytes`:
/// - a compile-time constant ([`WapContent::const_bytes`], e.g. the one-byte `00`
///   nonce) → a literal `.bytes(vec![0x00])`;
/// - a caller-supplied buffer (a bare `bytes` content, e.g. a prekey `signature`)
///   → a `Vec<u8>` spec field pushed to `ctx.fields` (mirroring
///   [`emit_variant_groups`]) and threaded in as `.bytes(self.<field>.clone())`.
///
/// The field name derives from the caller's collision-free `var_name` (`id_node` →
/// `id_content`, `id_node_2` → `id_content_2`) so repeated leaf tags across a
/// stanza (the three `<value>`/`<id>` nodes in a prekey `<skey>` tree) each get a
/// distinct field.
fn emit_node_content(
    child: &WapChildNode,
    var_name: &str,
    indent: &str,
    ctx: &mut VariantCtx,
) -> Vec<String> {
    let Some(content) = &child.content else {
        return Vec::new();
    };
    // A fixed byte constant: emit the literal buffer, no caller input needed. Handled
    // in isolation — a `const_bytes` that fails to decode degrades to no content, and
    // must never fall through to the caller-supplied-field branch below (that would
    // turn a fixed constant into an unwanted `Vec<u8>` builder argument).
    if let Some(hex) = &content.const_bytes {
        return decode_hex(hex)
            .map(|bytes| {
                let lits = bytes
                    .iter()
                    .map(|b| format!("0x{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![format!(
                    "{indent}{var_name} = {var_name}.bytes(vec![{lits}]);"
                )]
            })
            .unwrap_or_default();
    }
    // A caller-supplied byte buffer: thread a `Vec<u8>` spec field. Rename the
    // *terminal* `_node` segment (the var is `{tag}_node` or `{tag}_node_{n}`) so a
    // tag that itself contains `_node` isn't corrupted (`node_id_node` → `node_id_content`).
    if content.kind == WapContentKind::Bytes {
        let field = unique_field(ctx, &content_field_name(var_name));
        ctx.fields
            .push((field.clone(), payload_type(content), false));
        return vec![format!(
            "{indent}{var_name} = {var_name}.bytes({});",
            payload_expr(content, &format!("self.{field}"))
        )];
    }
    // A fixed STRING is the const_bytes case in the other spelling: the value is known, so it is
    // written out rather than asked of the caller. Nothing in the committed corpus carries one,
    // and the branch fell through to no content beside the dynamic one — the same empty element,
    // for the one kind whose value this already has in hand.
    if content.kind == WapContentKind::Const
        && let Some(value) = &content.value
    {
        let lits = value
            .as_bytes()
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        return vec![format!(
            "{indent}{var_name} = {var_name}.bytes(vec![{lits}]);"
        )];
    }
    // Opaque content the scan could not resolve to bytes or to a constant is still CONTENT: the
    // node carries a value the caller supplies. Falling through to nothing turned three
    // committed nodes — a business profile's `<website>` and its repeated `<area_description>`
    // — into empty elements, discarding exactly the value the request exists to send.
    //
    // `Vec<u8>`, the same shape a declared `bytes` payload takes. `Dynamic` means the scan could
    // not resolve the value, NOT that the value is text: `content_of_expr` records a member
    // reference this way whether it holds a URL or a signature, and typing it `String` made the
    // spec unable to express the bytes the source builder accepts. A caller holding text writes
    // `.into_bytes()` and loses nothing; one holding bytes had no spelling at all.
    if content.kind == WapContentKind::Dynamic {
        let field = unique_field(ctx, &content_field_name(var_name));
        ctx.fields
            .push((field.clone(), payload_type(content), false));
        return vec![format!(
            "{indent}{var_name} = {var_name}.bytes({});",
            payload_expr(content, &format!("self.{field}"))
        )];
    }
    Vec::new()
}

/// The type a caller-supplied payload takes: a fixed-size array where the node declares a
/// length, and an unbounded `Vec<u8>` where it does not.
///
/// `BIG_ENDIAN_CONTENT(x, 3)` accepts three bytes and nothing else, and a `Vec<u8>` let a caller
/// hand over one or four — a request the source builder cannot produce. `build_iq` returns an
/// `InfoQuery` rather than a `Result`, so there is no runtime check to add here; the array says
/// the same thing where it cannot be said later, and says it at compile time.
fn payload_type(content: &wa_ir::WapContent) -> String {
    match content.byte_length {
        Some(n) => format!("[u8; {n}]"),
        None => "Vec<u8>".to_string(),
    }
}

/// The same payload as the `Vec<u8>` the builder takes, however it was declared.
fn payload_expr(content: &wa_ir::WapContent, field: &str) -> String {
    match content.byte_length {
        Some(_) => format!("{field}.to_vec()"),
        None => format!("{field}.clone()"),
    }
}

/// The spec-struct field a node's caller-supplied content is threaded through.
///
/// Renames the TERMINAL `_node` segment of the caller's collision-free var name (`id_node` →
/// `id_content`, `id_node_2` → `id_content_2`) so repeated leaf tags each get a distinct field,
/// and so a tag that itself contains `_node` is not corrupted (`node_id_node` → `node_id_content`).
fn content_field_name(var_name: &str) -> String {
    match var_name.rfind("_node") {
        Some(pos) => format!(
            "{}_content{}",
            &var_name[..pos],
            &var_name[pos + "_node".len()..]
        ),
        None => format!("{var_name}_content"),
    }
}

/// Decode an even-length hex string (`"00"`, `"0a1b"`) to its bytes. Returns `None`
/// for malformed input (odd length, non-ASCII, or a non-hex digit) so a bad
/// `const_bytes` degrades to no content rather than panicking codegen. The
/// `is_ascii` gate also keeps the byte-index slicing below on char boundaries.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// A const attr present in every variant of a group with DISTINCT values is the
/// discriminator (e.g. `type` = `jid`/`invite`); variants are named by its value.
fn variant_discriminator(group: &wa_ir::WapVariantGroup) -> Option<String> {
    let first = group.variants.first()?;
    'attr: for a in &first.attrs {
        if a.kind != WapAttrKind::Const {
            continue;
        }
        let mut values = Vec::new();
        for v in &group.variants {
            match v
                .attrs
                .iter()
                .find(|x| x.name == a.name && x.kind == WapAttrKind::Const)
            {
                Some(found) => values.push(found.value.clone().unwrap_or_default()),
                None => continue 'attr,
            }
        }
        // distinct across variants → a usable discriminator
        let mut sorted = values.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() == group.variants.len() {
            return Some(a.name.clone());
        }
    }
    None
}

/// Variant name: the discriminator value (`Jid`/`Invite`), else the first non-const
/// attr name (`Before`/`After`), else `VariantN`.
fn variant_name(v: &wa_ir::WapVariant, disc: Option<&str>, idx: usize) -> String {
    if let Some(d) = disc
        && let Some(a) = v.attrs.iter().find(|x| x.name == d)
        && let Some(val) = &a.value
    {
        return pascal_case(val);
    }
    if let Some(a) = v
        .attrs
        .iter()
        .find(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
    {
        return pascal_case(&a.name);
    }
    format!("Variant{}", idx + 1)
}

/// Variant names for a whole group, deduped: two alternatives that resolve to the
/// same [`variant_name`] (e.g. several `platform`-led `<config>` variants → all
/// `Platform`) would otherwise collide into one enum variant with mismatched fields.
/// The first keeps the base name; later collisions get a `2`/`3`/… suffix, stable in
/// declaration order so the def and the match agree.
fn dedup_variant_names(group: &wa_ir::WapVariantGroup, disc: Option<&str>) -> Vec<String> {
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(group.variants.len());
    for (vi, v) in group.variants.iter().enumerate() {
        let base = variant_name(v, disc, vi);
        let mut name = base.clone();
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}{n}");
            n += 1;
        }
        out.push(name);
    }
    out
}

/// One `match` arm: destructure the variant's non-const attrs and apply each attr
/// (const literal, bound dynamic, or optional) to the node `var_name`.
fn variant_arm(
    enum_name: &str,
    vname: &str,
    v: &wa_ir::WapVariant,
    var_name: &str,
    indent: &str,
) -> Vec<String> {
    let mut binds: Vec<String> = v
        .attrs
        .iter()
        .filter(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
        .map(|a| rust_ident(&a.name))
        .collect();
    binds.extend(
        v.children
            .iter()
            .map(|c| variant_child_member(enum_name, vname, c, &v.attrs).0),
    );
    let pat = if binds.is_empty() {
        format!("{enum_name}::{vname}")
    } else {
        format!("{enum_name}::{vname} {{ {} }}", binds.join(", "))
    };
    let mut lines = vec![format!("{indent}{pat} => {{")];
    let body_indent = format!("{indent}    ");
    for a in &v.attrs {
        let alit = rust_lit(&a.name);
        let ident = rust_ident(&a.name);
        match &a.kind {
            WapAttrKind::Const => {
                if let Some(value) = &a.value {
                    lines.push(format!(
                        "{body_indent}{var_name} = {var_name}.attr({alit}, {});",
                        rust_lit(value)
                    ));
                }
            }
            WapAttrKind::Optional => lines.push(format!(
                "{body_indent}if let Some(x) = {ident} {{ {var_name} = {var_name}.attr({alit}, x.as_str()); }}"
            )),
            WapAttrKind::Integer => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.to_string());"
            )),
            k if is_jid_kind(k) => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.clone());"
            )),
            WapAttrKind::String | WapAttrKind::Dynamic => lines.push(format!(
                "{body_indent}{var_name} = {var_name}.attr({alit}, {ident}.as_str());"
            )),
            _ => {}
        }
    }
    // …and the children the variant contributes, built from the payload the enum now carries.
    for c in &v.children {
        let (member, _, _) = variant_child_member(enum_name, vname, c, &v.attrs);
        lines.extend(variant_child_build(c, &member, var_name, &body_indent));
    }
    lines.push(format!("{indent}}}"));
    lines
}

/// The enum-payload member a variant's child contributes: `(binding, type, struct defs)`.
///
/// A child this can express as a TYPE is one that is attributes and nothing else — no nested
/// children of its own, no element content, no variant groups. That is every variant child in
/// the committed corpus (two `<config>` alternatives, each a repeated `<item>` of plain attrs),
/// and it becomes a struct the caller fills in, `Vec<_>` where the child repeats.
///
/// Anything richer falls back to `Vec<Node>` — the caller hands the nodes over ready-made. Not
/// an ideal shape, and better than the two alternatives: emitting a node with the children
/// silently missing produces a request the source cannot send, and skipping the variant group
/// drops the attrs with them. Whatever this cannot describe, the caller can still supply.
fn variant_child_member(
    enum_name: &str,
    vname: &str,
    c: &WapChildNode,
    siblings: &[wa_ir::WapAttrDef],
) -> (String, String, Vec<String>) {
    // The binding lives in the same pattern as the variant's attrs, so a child tag that spells
    // one of them would shadow it. Rare enough to have no example here and cheap to rule out.
    //
    // Sanitized LAST, and through `rust_ident` like every other name this file emits: a tag is
    // wire text, and `snake_case` alone leaves `type` and `2fa` as they are — neither of which
    // is a Rust identifier, so the generated module would not compile. Suffixing after the
    // escape would be no better, since `r#type_children` is not one either; the collision test
    // therefore compares escaped forms and the suffix goes on the plain one.
    let mut member = snake_case(&c.tag);
    if siblings
        .iter()
        .any(|a| rust_ident(&a.name) == rust_ident(&member))
    {
        member.push_str("_children");
    }
    let member = rust_ident(&member);
    // …and cardinality survives the fallback. A child that does not repeat is exactly one node,
    // and declaring `Vec<Node>` for it let a caller supply none or several — a request the
    // source cannot send, from the very branch that exists so no request is silently wrong.
    let opaque = (
        member.clone(),
        if c.repeats {
            "Vec<wacore_binary::node::Node>".to_string()
        } else {
            "wacore_binary::node::Node".to_string()
        },
        Vec::new(),
    );
    if !c.children.is_empty() || c.content.is_some() || !c.variant_groups.is_empty() {
        return opaque;
    }
    let fields: Vec<String> = c
        .attrs
        .iter()
        .filter(|a| !matches!(a.kind, WapAttrKind::Const | WapAttrKind::GeneratedId))
        .map(|a| {
            format!(
                "    pub {}: {},",
                rust_ident(&a.name),
                crate::fields::rust_attr_type(&a.kind)
            )
        })
        .collect();
    let sname = format!("{enum_name}{vname}{}", pascal_case(&c.tag));
    let mut def = vec![
        "#[derive(Debug, Clone)]".to_string(),
        format!("pub struct {sname} {{"),
    ];
    def.extend(fields);
    def.push("}".to_string());
    def.push(String::new());
    let ty = if c.repeats {
        format!("Vec<{sname}>")
    } else {
        sname
    };
    (member, ty, def)
}

/// The build statements for one variant child, from the payload [`variant_child_member`] named.
///
/// Every node goes into the arm's shared `{var}_children` accumulator rather than into a
/// `.children(…)` call of its own: that call SETS the list, so two of them — a variant's and the
/// node's static children, or two children of one variant — would leave only the last.
fn variant_child_build(
    c: &WapChildNode,
    member: &str,
    var_name: &str,
    indent: &str,
) -> Vec<String> {
    // The opaque fallback: the caller built the nodes, so they are taken as they are — one for
    // a child that does not repeat, however many for one that does.
    if !c.children.is_empty() || c.content.is_some() || !c.variant_groups.is_empty() {
        return vec![if c.repeats {
            format!("{indent}{var_name}_children.extend({member}.iter().cloned());")
        } else {
            format!("{indent}{var_name}_children.push({member}.clone());")
        }];
    }
    let node = format!("{member}_node");
    let attrs = |src: &str, ind: &str| -> Vec<String> {
        c.attrs
            .iter()
            .filter_map(|a| {
                let alit = rust_lit(&a.name);
                let ident = rust_ident(&a.name);
                Some(match &a.kind {
                    WapAttrKind::Const => format!(
                        "{ind}{node} = {node}.attr({alit}, {});",
                        rust_lit(a.value.as_deref()?)
                    ),
                    WapAttrKind::Optional => format!(
                        "{ind}if let Some(x) = &{src}.{ident} {{ {node} = {node}.attr({alit}, x.as_str()); }}"
                    ),
                    WapAttrKind::Integer => {
                        format!("{ind}{node} = {node}.attr({alit}, {src}.{ident}.to_string());")
                    }
                    k if crate::fields::is_jid_kind(k) => {
                        format!("{ind}{node} = {node}.attr({alit}, {src}.{ident}.clone());")
                    }
                    WapAttrKind::String | WapAttrKind::Dynamic => {
                        format!("{ind}{node} = {node}.attr({alit}, {src}.{ident}.as_str());")
                    }
                    _ => return None,
                })
            })
            .collect()
    };
    let tag = rust_lit(&c.tag);
    if !c.repeats {
        let mut out = vec![format!("{indent}let mut {node} = NodeBuilder::new({tag});")];
        out.extend(attrs(member, indent));
        out.push(format!("{indent}{var_name}_children.push({node}.build());"));
        return out;
    }
    let inner = format!("{indent}    ");
    let mut out = vec![
        format!("{indent}for item in {member} {{"),
        format!("{inner}let mut {node} = NodeBuilder::new({tag});"),
    ];
    out.extend(attrs("item", &inner));
    out.push(format!("{inner}{var_name}_children.push({node}.build());"));
    out.push(format!("{indent}}}"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::collect_response_fields;
    use wa_ir::{WapAttrDef, WapChildNode};

    /// A bounded integer attribute, as `attrIntRange` records one.
    fn ranged(name: &str, lo: Option<i64>, hi: Option<i64>, required: bool) -> ParsedField {
        ParsedField {
            method: "attrIntRange".into(),
            name: name.into(),
            wire_name: Some(name.into()),
            field_type: ParsedFieldType::Integer,
            required,
            int_min: lo,
            int_max: hi,
            ..Default::default()
        }
    }

    #[test]
    fn an_optional_content_leaf_decodes_into_its_declared_type() {
        // The IR's `required` is a source of optionality for a CONTENT leaf exactly as it is for
        // an attribute — `rust_field_type` reads it and declares `Option<T>` — and this branch
        // emitted the required decoder unconditionally. The field was declared `Option<String>`
        // and initialized with a `String`: emitted Rust that does not type-check, which nothing
        // on this branch compiles.
        for (m, ty, want) in [
            (
                "contentString",
                "string",
                "n.content_str().map(|s| s.to_string());",
            ),
            (
                "contentInt",
                "integer",
                "n.content_str().and_then(|s| s.parse().ok());",
            ),
            (
                "contentBytes",
                "bytes",
                "n.content_bytes().map(|b| b.to_vec());",
            ),
        ] {
            let f: ParsedField = serde_json::from_value(serde_json::json!({
                "method": m, "name": "elementValue", "type": ty, "required": false
            }))
            .expect("field");
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(src.contains(want), "{m} decodes into an Option: {src}");
        }
        // …and a constraint is asked of a value that IS there: an absent optional payload is a
        // value the field holds, not one the accessor rejects.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "contentBytes", "name": "elementValue", "type": "bytes",
            "required": false, "byteLength": 32
        }))
        .expect("field");
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(
                "element_value.as_ref().is_none_or(|element_value| element_value.len() == 32)"
            ),
            "absence is not a rejection: {src}"
        );
        // …and the bands the other payload kinds carry. An integer is `Copy`, so the closure
        // binds the NUMBER — `as_ref()` here would compare `&i64` against `-10i64` and the
        // emitted module would not compile.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "contentInt", "name": "weight", "type": "integer",
            "required": false, "intMin": -10
        }))
        .expect("field");
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("weight.is_none_or(|weight| weight >= -10i64)"),
            "an optional integer band binds by value: {src}"
        );
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "contentInt", "name": "weight", "type": "integer",
            "required": false, "intMin": -10, "intMax": 10
        }))
        .expect("field");
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("weight.is_none_or(|weight| (-10i64..=10i64).contains(&weight))"),
            "and so does a two-sided one: {src}"
        );
        // A REQUIRED content leaf demands its content, which is what the union's own guard has
        // required all along — the shape moved deliberately and this is the new spelling.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "contentBytes", "name": "elementValue", "type": "bytes",
            "required": true, "byteLength": 32
        }))
        .expect("field");
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(
                r#"n.content_bytes().ok_or_else(|| anyhow::anyhow!("missing elementValue"))?.to_vec();"#
            ) && src.contains(
                r#"anyhow::ensure!(element_value.len() == 32, "elementValue wrong length: {}", element_value.len());"#
            ),
            "a required leaf demands its content: {src}"
        );
    }

    /// A required content leaf that cannot be decoded is a response the source rejects, and
    /// every decoder used to end in `unwrap_or_default` — so a missing body and an unparseable
    /// one both materialized as the type's default.
    #[test]
    fn a_required_content_leaf_demands_something_it_can_decode() {
        let src = |m: &str, ty: &str| {
            let f: ParsedField = serde_json::from_value(serde_json::json!({
                "method": m, "name": "elementValue", "type": ty, "required": true
            }))
            .expect("field");
            emit_field_parse(&f, "n", "").join("\n")
        };
        // Text that does not parse is the sharper half: present content, and still a value the
        // accessor turns away.
        let int = src("contentInt", "integer");
        assert!(
            int.contains(
                r#"content_str().ok_or_else(|| anyhow::anyhow!("missing elementValue"))?"#
            ) && int.contains(
                r#".parse::<u64>().map_err(|_| anyhow::anyhow!("elementValue not a number"))?"#
            ),
            "a required integer must be present and parse: {int}"
        );
        assert!(
            !src("contentString", "string").contains("unwrap_or_default"),
            "nor does a required string default",
        );
        assert!(
            !src("contentBytes", "bytes").contains("unwrap_or_default"),
            "nor do required bytes",
        );
        // `contentUint` is N big-endian bytes, so presence is the whole question — folding them
        // cannot fail once the payload is there.
        let uint = src("contentUint", "integer");
        assert!(
            uint.contains(
                r#"content_bytes().ok_or_else(|| anyhow::anyhow!("missing elementValue"))?"#
            ) && uint.contains("fold(0u64"),
            "a required uint demands its bytes and folds them: {uint}"
        );
        // The bound: an OPTIONAL leaf still hands back an `Option` and demands nothing.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "contentInt", "name": "elementValue", "type": "integer",
            "required": false
        }))
        .expect("field");
        let opt = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            opt.contains("n.content_str().and_then(|s| s.parse().ok());"),
            "an optional leaf is untouched: {opt}"
        );
    }

    #[test]
    fn a_bounded_integer_read_enforces_its_band() {
        // The accessor rejects a value outside its range, and this path decoded the number and
        // checked nothing — so `attrIntRange("weight", -10000, 10000)` took a `-20000` the source
        // turns away. Harmless while every integer was `u64`, because the parse itself refused
        // every negative value; signed, it is an over-acceptance. The union arm's selection guard
        // has applied the same band all along, and both read it from one place now.
        let src = emit_field_parse(&ranged("weight", Some(-10000), Some(10000), true), "n", "")
            .join("\n");
        assert!(
            src.contains("let weight: i64"),
            "signed by its range: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!((-10000i64..=10000i64).contains(&weight)"#),
            "and the band is enforced after decoding: {src}"
        );
    }

    #[test]
    fn a_bounded_content_read_enforces_its_band_as_well() {
        // The same accessor promise on the content path. A `contentInt` leaf declaring a range
        // decoded the number and checked nothing, and the moment its width could be signed a
        // `-20` materialized where the unsigned parse had been refusing every negative value by
        // accident. The union's content guard has tested this band all along — one rule spelled
        // in two places with one copy missing it, which is most of this branch's review.
        let mut f = ranged("weight", Some(-10), Some(10), true);
        f.method = "contentInt".into();
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("content_str()"),
            "still the content decoder: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!((-10i64..=10i64).contains(&weight)"#),
            "and the band is enforced after decoding: {src}"
        );
    }

    /// A required accessor relaxed to `required: false` still rejects what it cannot parse when
    /// its branch runs — folding that into `None` filed a response the source turns away as one
    /// where the field is simply absent.
    #[test]
    fn a_relaxed_integer_attribute_still_rejects_what_it_cannot_parse() {
        let read = |method: &str| {
            let mut f = ranged("expiration", None, None, false);
            f.method = method.into();
            emit_field_parse(&f, "n", "").join("\n")
        };
        let strict = read("attrInt");
        assert!(
            strict.contains(r#".map_err(|_| anyhow::anyhow!("expiration not a number"))?;"#),
            "a present value must parse: {strict}"
        );
        assert!(
            strict.contains("None => None,"),
            "and an absent one is still absent: {strict}"
        );
        assert!(
            !strict.contains("parse::<u64>().ok()"),
            "the lenient parse is gone from this spelling: {strict}"
        );
        // The bound: a `maybe…` accessor tolerates absence by design, and what it does with a
        // present non-number is a question about that accessor — its reading is untouched.
        let lenient = read("maybeAttrInt");
        assert!(
            lenient.contains(
                r#"let expiration = n.get_attr("expiration").and_then(|v| v.as_str().parse::<u64>().ok());"#
            ),
            "the optional accessor is unchanged: {lenient}"
        );
        // …and a band on the relaxed spelling is still enforced, inside the arm that parsed.
        let mut f = ranged("expiration", Some(1), Some(10), false);
        f.method = "attrIntRange".into();
        let banded = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            banded.contains(r#".map_err(|_| anyhow::anyhow!("expiration not a number"))?;"#)
                && banded.contains("(1u64..=10u64).contains(&expiration)"),
            "parse then band: {banded}"
        );
    }

    /// A `literal(...)` wrapping a JID accessor pins it to one value, and the two JID branches
    /// emitted no check at all — so the parser took any JID that parses.
    #[test]
    fn a_pinned_jid_attribute_is_compared_to_its_pin() {
        let src = |method: &str, required: bool| {
            let f: ParsedField = serde_json::from_value(serde_json::json!({
                "method": method, "name": "from", "wireName": "from", "type": "user_jid",
                "required": required, "literalValue": "s.whatsapp.net"
            }))
            .expect("field");
            emit_field_parse(&f, "n", "").join("\n")
        };
        // Compared on the RAW wire text, before the conversion: the pin is text, and `Jid` is
        // what that text becomes.
        let required = src("attrUserJid", true);
        assert!(
            required.contains(
                r#"anyhow::ensure!(n.get_attr("from").map(|v| v.as_str()) == Some("s.whatsapp.net")"#
            ),
            "the required read is pinned: {required}"
        );
        // Absence is not a pin violation where the read admits absence.
        let optional = src("maybeAttrUserJid", false);
        assert!(
            optional.contains(
                r#"matches!(n.get_attr("from").map(|v| v.as_str()), None | Some("s.whatsapp.net"))"#
            ),
            "and the optional read admits absence: {optional}"
        );
        // …and a JID that fails to CONVERT is not an absent attribute. `to_jid()` answers `None`
        // for both, so a relaxed required accessor stored a malformed value as though the
        // attribute were not there — the collapse the relaxed integer had, one branch over.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "attrUserJid", "name": "from", "wireName": "from", "type": "user_jid",
            "required": false
        }))
        .expect("field");
        let relaxed = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            relaxed.contains(r#".to_jid().ok_or_else(|| anyhow::anyhow!("from not a JID"))?"#)
                && relaxed.contains("None => None,"),
            "a present value must convert, and an absent one stays absent: {relaxed}"
        );
        // The bound: a `maybe…` accessor tolerates absence by design and is untouched.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "maybeAttrUserJid", "name": "from", "wireName": "from",
            "type": "user_jid", "required": false
        }))
        .expect("field");
        let lenient = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            lenient.contains(r#"let from = n.get_attr("from").and_then(|v| v.to_jid());"#),
            "the optional accessor is unchanged: {lenient}"
        );
        // The bound: an unpinned JID is read exactly as before.
        let f: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "attrUserJid", "name": "from", "wireName": "from", "type": "user_jid",
            "required": true
        }))
        .expect("field");
        let unpinned = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            !unpinned.contains("ensure!"),
            "nothing pinned, nothing checked: {unpinned}"
        );
    }

    #[test]
    fn an_unbounded_content_read_checks_nothing_extra() {
        // The bound: a content leaf with no declared range is read exactly as before. The check
        // follows the band, not the accessor.
        let mut f = ranged("weight", None, None, true);
        f.method = "contentInt".into();
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            !src.contains("ensure!"),
            "nothing declared, nothing enforced: {src}"
        );
    }

    #[test]
    fn an_optional_bounded_integer_read_enforces_it_too() {
        // Out of band is not the same as absent: the source THROWS on a value outside the range,
        // so filtering it to `None` would accept a response the parser rejects, quietly and with
        // the field missing. Absent stays absent.
        let src = emit_field_parse(&ranged("weight", Some(0), Some(10), false), "n", "").join("\n");
        assert!(
            src.contains("None => None,"),
            "absence is still absence: {src}"
        );
        assert!(
            src.contains(r#"anyhow::ensure!(weight <= 10u64"#),
            "and a present value is checked: {src}"
        );
        assert!(
            !src.contains(">= 0u64"),
            "a floor no u64 can fail is not a check: {src}"
        );
    }

    #[test]
    fn an_unbounded_integer_read_checks_nothing_extra() {
        // The bounds. No declared band is nothing to enforce, and a bound no value of the emitted
        // width can fail says nothing either — a floor of zero on a `u64` is not a check, it is
        // noise the consumer's linter would flag. (A NEGATIVE floor is a different matter: it is
        // what makes the field signed, and then it constrains something.)
        for f in [
            ranged("count", None, None, true),
            ranged("count", Some(0), None, true),
        ] {
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(!src.contains("ensure!"), "nothing to enforce: {src}");
        }
    }

    fn attr(name: &str, kind: WapAttrKind, value: Option<&str>) -> WapAttrDef {
        WapAttrDef {
            name: name.into(),
            kind,
            value: value.map(|v| v.into()),
            required: false,
            enum_ref: None,
        }
    }
    fn leaf(tag: &str) -> WapChildNode {
        WapChildNode {
            tag: tag.into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
        }
    }

    /// Build a child node with a throwaway variant context (for the tests that don't
    /// exercise variant groups).
    fn build1(child: &WapChildNode) -> (Vec<String>, String, bool) {
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        emit_child_builder(child, "", &mut HashMap::new(), &mut ctx, &[])
    }

    /// Flattening removes an optional same-node wrapper, and with it the only record that its
    /// descendants are read only when the wrapper is there — so every one of them is no longer
    /// required. Only three attribute spellings were weakened, and the rest kept `required:
    /// true`: a JID, a content leaf and a child were all emitted as mandatory reads of a node
    /// that may be absent, and the generated parser rejected the branch flattening exists for.
    #[test]
    fn an_optional_same_node_wrapper_weakens_every_descendant() {
        let wrapper: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "result", "type": "string",
            "required": false, "sameNode": true,
            "children": [
                {"method": "attrString", "name": "label", "type": "string", "required": true},
                {"method": "attrUserJid", "name": "jid", "type": "user_jid", "required": true},
                {"method": "contentString", "name": "elementValue", "type": "string",
                 "required": true},
                {"method": "child", "name": "detail", "type": "string", "required": true,
                 "children": [
                     {"method": "attrInt", "name": "count", "type": "integer",
                      "required": true}
                 ]}
            ]
        }))
        .expect("wrapper");
        let flat = crate::fields::flatten_same_node(std::slice::from_ref(&wrapper));
        for f in &flat {
            assert!(
                !f.required,
                "every lifted leaf is optional, not just the ones with a `maybe…` spelling: {f:?}"
            );
        }
        // …and the ones that HAVE a `maybe…` accessor take it, which is the half that already
        // worked and must keep working.
        let by = |n: &str| flat.iter().find(|f| f.name == n).expect(n).clone();
        assert_eq!(by("label").method, "maybeAttrString");
        // The rest keep their accessor — there is no `maybe` form — and the flag carries it.
        assert_eq!(by("jid").method, "attrUserJid");
        assert_eq!(by("elementValue").method, "contentString");
        // …and the weakening reaches through a nested child, not just the top level.
        let detail = by("detail");
        let kids = detail.children.as_deref().unwrap_or(&[]);
        assert!(
            kids.iter().all(|c| !c.required),
            "a grandchild of the wrapper is no more required than a child: {kids:?}"
        );
        // The bound: a REQUIRED same-node wrapper lifts its descendants unchanged.
        let mut required_wrapper = wrapper.clone();
        required_wrapper.required = true;
        let flat = crate::fields::flatten_same_node(std::slice::from_ref(&required_wrapper));
        assert!(
            flat.iter().all(|f| f.required),
            "nothing is weakened under a wrapper that is always there: {flat:?}"
        );
    }

    /// A variant is the attrs AND children its alternative adds to the node, and the enum
    /// carried only the attrs — so choosing a variant emitted a node the source cannot send.
    #[test]
    fn a_variant_carries_the_children_it_contributes() {
        use wa_ir::{WapVariant, WapVariantGroup};
        let item = WapChildNode {
            tag: "item".into(),
            attrs: vec![
                attr("jid", WapAttrKind::GroupJid, None),
                attr("mute", WapAttrKind::Integer, None),
            ],
            children: vec![],
            content: None,
            repeats: true,
            variant_groups: vec![],
        };
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![leaf("static")],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("platform", WapAttrKind::String, None)],
                    children: vec![item],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let src = lines.join("\n");
        let defs = enums.join("\n");
        // The item's own struct, and the payload member that carries a list of them.
        assert!(
            defs.contains("pub struct TConfigVariantPlatformItem {")
                && defs.contains("pub jid: Jid,")
                && defs.contains("pub mute: u64,"),
            "the child becomes a struct the caller fills: {defs}"
        );
        assert!(
            defs.contains("item: Vec<TConfigVariantPlatformItem>"),
            "and the variant carries a list of them: {defs}"
        );
        // The arm builds them, attr by attr.
        assert!(
            src.contains("for item in item {")
                && src.contains(r#"item_node = item_node.attr("jid", item.jid.clone());"#)
                && src.contains(r#"item_node = item_node.attr("mute", item.mute.to_string());"#),
            "and the arm builds each one: {src}"
        );
        // `.children(…)` SETS the list, so the static child and the variant's share one
        // accumulator — attaching them separately would leave only whichever ran last.
        assert!(
            src.contains(
                "let mut config_node_children: Vec<wacore_binary::node::Node> = Vec::new();"
            ) && src.contains("config_node_children.push(static_node);")
                && src.contains("config_node_children.push(item_node.build());")
                && src.contains("config_node = config_node.children(config_node_children);"),
            "one accumulator, attached once: {src}"
        );
        assert_eq!(
            src.matches(".children(").count(),
            1,
            "and exactly one call sets them: {src}"
        );
    }

    /// A relaxed content leaf must decode what is THERE. `parse().ok()` merged "no content"
    /// with "content that is not a number", so the committed `participant_count` filed an
    /// unparseable payload as an absence.
    #[test]
    fn a_relaxed_child_content_leaf_still_rejects_what_it_cannot_decode() {
        let child = |method: &str, required: bool| -> ParsedField {
            serde_json::from_value(serde_json::json!({
                "method": "maybeChild", "name": "participant_count", "tag": "participant_count",
                "type": "string", "required": false,
                "children": [{
                    "method": method, "name": "content", "type": "integer",
                    "required": required
                }]
            }))
            .expect("child")
        };
        let src = emit_struct_parser(&[child("contentInt", false)], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(
                r#".map(|s| s.parse::<u64>().map_err(|_| anyhow::anyhow!("participant_count not a number"))).transpose()?"#
            ),
            "a present payload must decode: {src}"
        );
        assert!(
            src.contains("None => None,"),
            "and an absent one stays absent: {src}"
        );
        // The bound: a payload that cannot FAIL to decode is emitted as it always was — bytes
        // are bytes, and only the integer-from-text spelling can be rejected.
        let src = emit_struct_parser(&[child("contentBytes", false)], "n", "R", "", "P").join("\n");
        assert!(
            src.contains("content_bytes().map(|b| b.to_vec())") && !src.contains("map_err"),
            "bytes decode or are absent, never malformed: {src}"
        );
    }

    /// A repeated item's field can sit BELOW it, and reading it off the item itself decoded the
    /// parent's own content — so a valid item was rejected as missing the field.
    #[test]
    fn a_repeated_items_field_is_read_through_its_source_path() {
        let leaf: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "attrString", "name": "label", "wireName": "label", "type": "string",
            "required": true, "sourcePath": ["background"]
        }))
        .expect("leaf");
        let item: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "required": true, "repeats": true, "children": [leaf]
        }))
        .expect("item");
        let src = emit_struct_parser(&[item], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(r#"item_item.get_optional_child("background")"#)
                && src.contains("missing <background>"),
            "the path is descended, and a REQUIRED field fails on an absent wrapper: {src}"
        );
        assert!(
            !src.contains(r#"item_item.get_attr("label")"#),
            "and the field is not read off the item itself: {src}"
        );
        // …and the nested repeated loop reads its fields the same way.
        let inner_leaf: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "attrString", "name": "label", "wireName": "label", "type": "string",
            "required": true, "sourcePath": ["background"]
        }))
        .expect("leaf");
        let inner_item: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "part", "tag": "part", "type": "string",
            "required": true, "repeats": true, "children": [inner_leaf]
        }))
        .expect("inner");
        let outer: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "required": true, "repeats": true, "children": [inner_item]
        }))
        .expect("outer");
        let src = emit_struct_parser(&[outer], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(r#"part_item.get_optional_child("background")"#)
                && src.contains("missing <background>"),
            "the nested loop descends too, and a REQUIRED field still fails on absence: {src}"
        );
        // …and a RELAXED field's wrapper is no more present than the field itself: descending
        // it with the fail-on-absence helper turned away an item the source accepts. That
        // rejection is one the descent introduced, since these reads had no descent before.
        let leaf: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "maybeAttrString", "name": "label", "wireName": "label",
            "type": "string", "required": false, "sourcePath": ["meta"]
        }))
        .expect("leaf");
        let item: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "required": true, "repeats": true, "children": [leaf]
        }))
        .expect("item");
        let src = emit_struct_parser(&[item], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(r#"match item_item.get_optional_child("meta") {"#)
                && src.contains("None => None,"),
            "an absent wrapper leaves the field absent: {src}"
        );
        assert!(
            !src.contains(r#"missing <meta>"#),
            "and does not fail the parse: {src}"
        );
        // …and the nested repeated loop reads a relaxed path the same way.
        let leaf: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "maybeAttrString", "name": "label", "wireName": "label",
            "type": "string", "required": false, "sourcePath": ["meta"]
        }))
        .expect("leaf");
        let inner_item: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "part", "tag": "part", "type": "string",
            "required": true, "repeats": true, "children": [leaf]
        }))
        .expect("inner");
        let outer: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "required": true, "repeats": true, "children": [inner_item]
        }))
        .expect("outer");
        let src = emit_struct_parser(&[outer], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(r#"match part_item.get_optional_child("meta") {"#)
                && !src.contains("missing <meta>"),
            "the nested loop leaves a relaxed field absent too: {src}"
        );
        // The bound: a field with no source path is still read straight off the item.
        let leaf: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "attrString", "name": "label", "wireName": "label", "type": "string",
            "required": true
        }))
        .expect("leaf");
        let item: ParsedField = serde_json::from_value(serde_json::json!({
            "method": "child", "name": "item", "tag": "item", "type": "string",
            "required": true, "repeats": true, "children": [leaf]
        }))
        .expect("item");
        let src = emit_struct_parser(&[item], "n", "R", "", "P").join("\n");
        assert!(
            src.contains(r#"item_item.get_attr("label")"#),
            "no path, no descent: {src}"
        );
    }

    /// A wrapper bound inside an optional child's `if let` is gone after it, so two siblings
    /// sharing a tag and a nested path must each declare their own.
    #[test]
    fn two_optional_siblings_do_not_share_a_wrapper_binding() {
        // The same TAG in both, which is what makes them share a cache key at all — two
        // different tags key differently and could never have collided.
        let optional_child = |field: &str| -> ParsedField {
            serde_json::from_value(serde_json::json!({
                "method": "maybeChild", "name": "item", "tag": "item", "type": "string",
                "required": false,
                "children": [{
                    "method": "attrString", "name": field, "wireName": field, "type": "string",
                    "required": true, "sourcePath": ["meta"]
                }]
            }))
            .expect("child")
        };
        let src = emit_struct_parser(
            &[optional_child("a"), optional_child("b")],
            "n",
            "R",
            "",
            "P",
        )
        .join("\n");
        assert_eq!(
            src.matches("_meta_wrap = ").count(),
            2,
            "each branch declares its own wrapper: {src}"
        );
    }

    /// A child that repeats and carries opaque content is as many nodes as the caller has
    /// payloads — one field and one node could not reproduce a request that sends two.
    #[test]
    fn repeated_dynamic_content_is_one_node_per_payload() {
        let mut node = leaf("area_description");
        node.repeats = true;
        node.content = Some(wa_ir::WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, var, is_list) =
            emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(is_list, "the child yields a list of nodes");
        assert_eq!(var, "area_description_nodes");
        assert!(
            fields.contains(&(
                "area_description_content".to_string(),
                "Vec<Vec<u8>>".to_string(),
                false
            )),
            "one payload per node: {fields:?}"
        );
        assert!(
            lines
                .join("\n")
                .contains("for payload in &self.area_description_content {"),
            "and a node is built for each: {}",
            lines.join("\n")
        );
        // The bound: the same content on a child that does NOT repeat is still one node and one
        // payload.
        let mut node = leaf("website");
        node.content = Some(wa_ir::WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (_, var, is_list) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(!is_list && var == "website_node", "one node: {var}");
        assert!(
            fields.contains(&("website_content".to_string(), "Vec<u8>".to_string(), false)),
            "one payload: {fields:?}"
        );
    }

    /// A variant group's own spec field is a name the module has to bind, and a wire tag is
    /// only sometimes one. The variant CHILD member learned this two rounds ago; this did not.
    #[test]
    fn a_variant_group_field_becomes_a_usable_identifier() {
        use wa_ir::{WapVariant, WapVariantGroup};
        let group = || WapVariantGroup {
            optional: false,
            variants: vec![WapVariant {
                attrs: vec![attr("platform", WapAttrKind::String, None)],
                children: vec![],
            }],
        };
        let build = |groups: Vec<WapVariantGroup>| {
            let node = WapChildNode {
                tag: "type".into(),
                attrs: vec![],
                children: vec![],
                content: None,
                repeats: false,
                variant_groups: groups,
            };
            let (mut enums, mut fields) = (Vec::new(), Vec::new());
            let reserved = std::collections::HashSet::new();
            let attr_fields = crate::spec::AttrFieldMap::new();
            let mut ctx = VariantCtx {
                spec_base: "T",
                enum_defs: &mut enums,
                fields: &mut fields,
                reserved: &reserved,
                attr_fields: &attr_fields,
            };
            emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
            fields
        };
        assert_eq!(
            build(vec![group()])[0].0,
            "r#type",
            "a keyword tag is escaped"
        );
        // …and the `_vN` suffix goes on the PLAIN spelling, since `r#type_v2` is no identifier.
        let multi = build(vec![group(), group()]);
        assert_eq!(multi[0].0, "type_v1");
        assert_eq!(multi[1].0, "type_v2");
    }

    /// A generated id is an attribute the request CARRIES. It reached the catch-all and was
    /// dropped, so `<usync sid>` was built without one — a request the source cannot send.
    #[test]
    fn a_generated_id_attribute_is_carried_not_dropped() {
        let mut node = leaf("usync");
        node.attrs = vec![attr("sid", WapAttrKind::GeneratedId, None)];
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            fields.contains(&("sid".to_string(), "String".to_string(), false)),
            "the caller supplies it: {fields:?}"
        );
        assert!(
            lines
                .join("\n")
                .contains(r#"usync_node = usync_node.attr("sid", self.sid.as_str());"#),
            "and the node carries it: {}",
            lines.join("\n")
        );
    }

    /// An attribute SITE writes the field the collection pass gave it, which is not derivable
    /// from the attribute's own name: another node may spell it the same and mean something
    /// else, and deriving it here would write both sites to whichever name won.
    #[test]
    fn an_attribute_site_writes_the_field_it_was_assigned() {
        let mut node = leaf("linked_parent");
        node.attrs = vec![attr("jid", WapAttrKind::GroupJid, None)];
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let mut attr_fields = crate::spec::AttrFieldMap::new();
        attr_fields.insert(
            (vec!["linked_parent".to_string()], "jid".to_string()),
            "linked_parent_jid".to_string(),
        );
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            lines
                .join("\n")
                .contains(r#"attr("jid", self.linked_parent_jid.clone());"#),
            "the assigned field, not the derived one: {}",
            lines.join("\n")
        );
        // The bound: with nothing assigned the plain derivation stands, so a request whose
        // attribute names never collided is emitted exactly as before.
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let empty = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &empty,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            lines
                .join("\n")
                .contains(r#"attr("jid", self.jid.clone());"#),
            "nothing assigned, nothing renamed: {}",
            lines.join("\n")
        );
    }

    /// A wire tag is text, and only some of it spells a Rust identifier. `type` and `2fa` are
    /// valid tags and neither is a name the generated module can bind, so the payload member and
    /// the match binding go through the same escape every other emitted name does.
    #[test]
    fn a_variant_child_tag_becomes_a_usable_identifier() {
        use wa_ir::{WapVariant, WapVariantGroup};
        let kid = |tag: &str| WapChildNode {
            tag: tag.into(),
            attrs: vec![attr("v", WapAttrKind::String, None)],
            children: vec![],
            content: None,
            repeats: true,
            variant_groups: vec![],
        };
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("platform", WapAttrKind::String, None)],
                    children: vec![kid("type"), kid("2fa")],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let defs = enums.join("\n");
        let src = lines.join("\n");
        assert!(
            defs.contains("r#type: Vec<") && src.contains("for item in r#type {"),
            "a keyword tag is escaped: {defs}\n{src}"
        );
        assert!(
            defs.contains("_2fa: Vec<") && src.contains("for item in _2fa {"),
            "and a digit-led one is not left digit-led: {defs}\n{src}"
        );
        // …and a tag that collides with one of the variant's own attrs is suffixed on the PLAIN
        // spelling, since `r#platform_children` would not be an identifier either.
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("type", WapAttrKind::String, None)],
                    children: vec![kid("type")],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (_, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let defs = enums.join("\n");
        assert!(
            defs.contains("type_children: Vec<") && !defs.contains("r#type_children"),
            "the suffix goes on the plain spelling: {defs}"
        );
        // …and the collision is judged on the ESCAPED spellings, because that is what the
        // pattern binds. `myTag` and `my-tag` are different wire names and one identifier, so
        // comparing the raw text would declare the member twice.
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("myTag", WapAttrKind::String, None)],
                    children: vec![kid("my-tag")],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (_, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let defs = enums.join("\n");
        assert!(
            defs.contains("my_tag: String") && defs.contains("my_tag_children: Vec<"),
            "two wire names, one identifier, two members: {defs}"
        );
    }

    /// A child shape richer than attributes has no struct this can describe, so the caller hands
    /// the nodes over ready-made — never a node with the children silently missing.
    #[test]
    fn a_variant_child_this_cannot_type_is_caller_supplied() {
        use wa_ir::{WapVariant, WapVariantGroup};
        let mut nested = leaf("wrapper");
        nested.children = vec![leaf("inner")];
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("platform", WapAttrKind::String, None)],
                    children: vec![nested],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        // A child that does not repeat is exactly ONE node, and its cardinality survives the
        // fallback: `Vec<Node>` would let a caller supply none or several.
        assert!(
            enums
                .join("\n")
                .contains("wrapper: wacore_binary::node::Node"),
            "one node for a child that does not repeat: {}",
            enums.join("\n")
        );
        assert!(
            lines
                .join("\n")
                .contains("config_node_children.push(wrapper.clone());"),
            "and the arm attaches it once: {}",
            lines.join("\n")
        );
        // …and a REPEATING one takes as many as the caller has.
        let mut nested = leaf("wrapper");
        nested.children = vec![leaf("inner")];
        nested.repeats = true;
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![WapVariant {
                    attrs: vec![attr("platform", WapAttrKind::String, None)],
                    children: vec![nested],
                }],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            enums
                .join("\n")
                .contains("wrapper: Vec<wacore_binary::node::Node>"),
            "a list for a child that repeats: {}",
            enums.join("\n")
        );
        assert!(
            lines
                .join("\n")
                .contains("config_node_children.extend(wrapper.iter().cloned());"),
            "and the arm attaches all of them: {}",
            lines.join("\n")
        );
    }

    /// Opaque content is still content: the node carries a value the caller supplies, and
    /// emitting nothing turned it into an empty element that discards the caller's data.
    #[test]
    fn dynamic_node_content_is_caller_supplied() {
        let mut node = leaf("website");
        node.content = Some(wa_ir::WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        // `Dynamic` says the scan could not resolve the value, not that the value is text —
        // the same record covers a URL and a signature — so the payload has to preserve bytes.
        assert!(
            fields.contains(&("website_content".to_string(), "Vec<u8>".to_string(), false)),
            "the caller supplies the payload, bytes and all: {fields:?}"
        );
        assert!(
            lines
                .join("\n")
                .contains("website_node = website_node.bytes(self.website_content.clone());"),
            "and it is written as the node's content: {}",
            lines.join("\n")
        );
        // …and the synthesized name must not collide with an attribute the spec already
        // declares: `<website website_content="…">payload</website>` declared the field twice,
        // with two types and two constructor parameters.
        let mut node = leaf("website");
        node.content = Some(wa_ir::WapContent {
            kind: WapContentKind::Dynamic,
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved: std::collections::HashSet<String> =
            ["website_content".to_string()].into_iter().collect();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            fields.contains(&(
                "website_content_2".to_string(),
                "Vec<u8>".to_string(),
                false
            )),
            "the content field steps around the attribute: {fields:?}"
        );
        assert!(
            lines.join("\n").contains("self.website_content_2.clone()"),
            "and the build reads the name it declared: {}",
            lines.join("\n")
        );
        // The bound: a node with no content declared still builds empty.
        let (lines, _, _) = build1(&leaf("website"));
        assert!(
            !lines.join("\n").contains("bytes("),
            "no content, no payload: {}",
            lines.join("\n")
        );
        // …and a CONST value is known, so it is written out rather than asked of the caller.
        let mut node = leaf("website");
        node.content = Some(wa_ir::WapContent {
            kind: WapContentKind::Const,
            value: Some("hi".into()),
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            lines
                .join("\n")
                .contains("website_node = website_node.bytes(vec![0x68, 0x69]);"),
            "a known value is a literal: {}",
            lines.join("\n")
        );
        assert!(
            fields.is_empty(),
            "and asks the caller for nothing: {fields:?}"
        );
    }

    #[test]
    fn variant_group_emits_enum_field_and_match() {
        use wa_ir::{WapVariant, WapVariantGroup};
        // `messages{count}` with a required query-params disjunction (jid/invite,
        // discriminated by `type`) and an optional directions disjunction.
        let node = WapChildNode {
            tag: "messages".into(),
            attrs: vec![attr("count", WapAttrKind::Integer, None)],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![
                WapVariantGroup {
                    optional: false,
                    variants: vec![
                        WapVariant {
                            attrs: vec![
                                attr("type", WapAttrKind::Const, Some("jid")),
                                attr("jid", WapAttrKind::UserJid, None),
                            ],
                            children: vec![],
                        },
                        WapVariant {
                            attrs: vec![
                                attr("type", WapAttrKind::Const, Some("invite")),
                                attr("key", WapAttrKind::String, None),
                            ],
                            children: vec![],
                        },
                    ],
                },
                WapVariantGroup {
                    optional: true,
                    variants: vec![
                        WapVariant {
                            attrs: vec![attr("before", WapAttrKind::Integer, None)],
                            children: vec![],
                        },
                        WapVariant {
                            attrs: vec![attr("after", WapAttrKind::Integer, None)],
                            children: vec![],
                        },
                    ],
                },
            ],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "Foo",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let enum_src = enums.join("\n");
        let code = lines.join("\n");

        // Discriminated enum for the query-params group (named by `type`).
        assert!(
            enum_src.contains("pub enum FooMessagesVariant1 {"),
            "{enum_src}"
        );
        assert!(enum_src.contains("Jid { jid: Jid }"), "{enum_src}");
        assert!(enum_src.contains("Invite { key: String }"), "{enum_src}");
        // Directions group named by its distinguishing attr.
        assert!(
            enum_src.contains("pub enum FooMessagesVariant2 {"),
            "{enum_src}"
        );
        assert!(enum_src.contains("Before { before: u64 }"), "{enum_src}");

        // Spec fields: required enum + optional enum.
        assert!(
            fields
                .iter()
                .any(|(n, t, opt)| n == "messages_v1" && t == "FooMessagesVariant1" && !opt)
        );
        assert!(
            fields.iter().any(|(n, t, opt)| n == "messages_v2"
                && t == "Option<FooMessagesVariant2>"
                && *opt)
        );

        // Build match applies the const discriminator + bound payload.
        assert!(code.contains("match &self.messages_v1 {"), "{code}");
        assert!(
            code.contains("messages_node = messages_node.attr(\"type\", \"jid\");"),
            "{code}"
        );
        assert!(
            code.contains("messages_node = messages_node.attr(\"jid\", jid.clone());"),
            "{code}"
        );
        assert!(
            code.contains("if let Some(__v) = &self.messages_v2 {"),
            "{code}"
        );
    }

    #[test]
    fn same_named_variants_are_deduped() {
        use wa_ir::{WapVariant, WapVariantGroup};
        // Several `<config>` alternatives that all lead with a dynamic `platform` attr
        // resolve to the same `variant_name` (`Platform`); they must become distinct
        // enum variants (Platform / Platform2 / Platform3), and the build match must
        // name the same deduped variants so the generated code compiles.
        let mk = |extra: &str| WapVariant {
            attrs: vec![
                attr("platform", WapAttrKind::String, None),
                attr(extra, WapAttrKind::String, None),
            ],
            children: vec![],
        };
        let node = WapChildNode {
            tag: "config".into(),
            attrs: vec![],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![WapVariantGroup {
                optional: false,
                variants: vec![mk("appid"), mk("voip"), mk("endpoint")],
            }],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "Foo",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let enum_src = enums.join("\n");
        // Three distinct variants, no duplicate `Platform`.
        assert_eq!(
            enum_src.matches("Platform").count(),
            3,
            "expected Platform/Platform2/Platform3:\n{enum_src}"
        );
        assert!(
            enum_src.contains("Platform {")
                && enum_src.contains("Platform2 {")
                && enum_src.contains("Platform3 {"),
            "{enum_src}"
        );
        // The match arms reference the same deduped names.
        let code = lines.join("\n");
        assert!(
            code.contains("Platform2 {") && code.contains("Platform3 {"),
            "{code}"
        );
    }

    #[test]
    fn source_path_attr_is_read_off_descended_wrapper() {
        // `protocol` carries sourcePath=["props"]: it lives on <props>, not the
        // <iq> root. The parser must descend the wrapper, and optional siblings
        // sharing the wrapper must read off it too, while a plain root attr stays
        // on `response`.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"attrString","name":"propsProtocol","wireName":"protocol","type":"string","required":true,"sourcePath":["props"]},
            {"method":"maybeAttrString","name":"propsHash","wireName":"hash","type":"string","required":false,"sourcePath":["props"]},
            {"method":"attrString","name":"type","wireName":"type","type":"string","required":true}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let props_wrap = response.get_optional_child(\"props\")"),
            "no <props> wrapper descent:\n{code}"
        );
        assert!(
            code.contains("let props_protocol = props_wrap.get_attr(\"protocol\")"),
            "required attr not read off the wrapper:\n{code}"
        );
        assert!(
            code.contains("let props_hash = props_wrap.get_attr(\"hash\")"),
            "optional sibling not read off the wrapper:\n{code}"
        );
        assert!(
            code.contains("response.get_attr(\"type\")"),
            "root attr should still read off response:\n{code}"
        );
    }

    #[test]
    fn source_path_child_is_read_off_descended_wrapper() {
        // A child with sourcePath=["detail"] (smax flattenedChildWithTag): the
        // <request> child lives under <detail>, not the <iq> root, and its attrs
        // are read off that descended child.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"detailRequest","tag":"request","type":"string","required":false,"sourcePath":["detail"],
             "children":[{"method":"attrString","name":"foo","wireName":"foo","type":"string","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let detail_wrap = response.get_optional_child(\"detail\")"),
            "{code}"
        );
        // The child is optional (`required:false`), so it reads inside `if let Some` —
        // but still off the descended <detail> wrapper, not the response root.
        assert!(
            code.contains("if let Some(request) = detail_wrap.get_optional_child(\"request\")"),
            "child not read off the <detail> wrapper:\n{code}"
        );
        assert!(
            !code.contains("response.get_optional_child(\"request\")"),
            "child STILL read off the response root:\n{code}"
        );
    }

    #[test]
    fn optional_child_defaults_when_absent_instead_of_failing() {
        // A `required:false` child (smax `optionalChildWithTag`) must not bail the whole
        // parse when absent: its fields read inside `if let Some` and default otherwise.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"suspended","tag":"suspended","type":"string","required":false,
             "children":[{"method":"attrInt","name":"value","wireName":"value","type":"integer","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("if let Some(suspended) = response.get_optional_child(\"suspended\")"),
            "optional child should read inside `if let Some`:\n{code}"
        );
        assert!(
            code.contains("} else {") && code.contains("(Default::default(),)"),
            "absent optional child should default its fields:\n{code}"
        );
        assert!(
            !code.contains(".ok_or_else(|| anyhow::anyhow!(\"missing <suspended>\"))"),
            "optional child must NOT bail when absent:\n{code}"
        );
    }

    #[test]
    fn required_child_still_bails_when_absent() {
        // A `required:true` child keeps the fail-fast descent.
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"child","name":"group","tag":"group","type":"string","required":true,
             "children":[{"method":"attrString","name":"id","wireName":"id","type":"string","required":true}]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let group = response.get_optional_child(\"group\")")
                && code.contains(".ok_or_else(|| anyhow::anyhow!(\"missing <group>\"))?"),
            "required child must fail-fast when absent:\n{code}"
        );
    }

    #[test]
    fn nested_source_path_descends_each_segment() {
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"attrString","name":"nonceValue","wireName":"value","type":"string","required":true,"sourcePath":["detail","nonce"]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let detail_wrap = response.get_optional_child(\"detail\")"),
            "{code}"
        );
        assert!(
            code.contains("let detail_nonce_wrap = detail_wrap.get_optional_child(\"nonce\")"),
            "{code}"
        );
        assert!(
            code.contains("let nonce_value = detail_nonce_wrap.get_attr(\"value\")"),
            "{code}"
        );
    }

    #[test]
    fn optional_only_wrapper_is_still_descended() {
        // Every attr under <props> is optional → the wrapper node is still required
        // (smax `flattenedChildWithTag`), so it must be descended, not read off the
        // <iq> root (else the attrs would always parse as None).
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"maybeAttrString","name":"propsAbKey","wireName":"ab_key","type":"string","required":false,"sourcePath":["props"]},
            {"method":"maybeAttrString","name":"propsHash","wireName":"hash","type":"string","required":false,"sourcePath":["props"]}
        ]))
        .unwrap();
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let props_wrap = response.get_optional_child(\"props\")"),
            "optional-only wrapper not descended:\n{code}"
        );
        assert!(
            code.contains("let props_ab_key = props_wrap.get_attr(\"ab_key\")"),
            "optional attr not read off the wrapper:\n{code}"
        );
        assert!(
            !code.contains("response.get_attr(\"ab_key\")"),
            "optional attr STILL read off the root:\n{code}"
        );
    }

    #[test]
    fn optional_same_node_wrapper_weakens_attr_children() {
        // `{displayNameMixin: m.success ? m.value : null}` → an OPTIONAL same-node
        // wrapper. When flattened the wrapper disappears, so its required attr child
        // must be weakened to an optional read (the wrapper may be absent).
        let fields: Vec<ParsedField> = serde_json::from_value(serde_json::json!([
            {"method":"","name":"displayNameMixin","type":"string","required":false,"sameNode":true,
             "children":[{"method":"attrString","name":"displayName","wireName":"display_name","type":"string","required":true}]}
        ]))
        .unwrap();
        // Struct field is Option<…>.
        let (struct_fields, _, _) = collect_response_fields(&fields, "Foo");
        let df = struct_fields
            .iter()
            .find(|f| f.name == "display_name")
            .expect("display_name field");
        assert_eq!(
            df.rust_type, "Option<String>",
            "weakened field should be Option"
        );
        // Parser reads it optionally (no `missing` error).
        let code = emit_response_parser(&fields, "Resp", "    ", "Foo").join("\n");
        assert!(
            code.contains("let display_name = response.get_attr(\"display_name\").map("),
            "optional same_node child not read optionally:\n{code}"
        );
        assert!(
            !code.contains("missing display_name"),
            "optional same_node child still read as required:\n{code}"
        );
    }

    #[test]
    fn optional_request_attr_is_emitted_conditionally() {
        let child = WapChildNode {
            tag: "query".into(),
            attrs: vec![
                attr("opt", WapAttrKind::Optional, None),
                attr("xmlns", WapAttrKind::Const, Some("w:x")),
            ],
            children: vec![],
            content: None,
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, var, _) = build1(&child);
        let code = lines.join("\n");
        assert_eq!(var, "query_node");
        assert!(code.contains("let mut query_node = NodeBuilder::new(\"query\");"));
        assert!(
            code.contains(
                "if let Some(v) = &self.opt { query_node = query_node.attr(\"opt\", v.as_str()); }"
            ),
            "{code}"
        );
        assert!(code.contains("query_node = query_node.attr(\"xmlns\", \"w:x\");"));
        assert!(code.contains("let query_node = query_node.build();"));
    }

    #[test]
    fn empty_node_avoids_unused_mut() {
        let (lines, _, _) = build1(&leaf("ping"));
        let code = lines.join("\n");
        assert!(code.contains("let ping_node = NodeBuilder::new(\"ping\").build();"));
        assert!(!code.contains("let mut ping_node"));
    }

    #[test]
    fn same_tag_nested_siblings_get_distinct_var_names() {
        let parent = WapChildNode {
            tag: "list".into(),
            attrs: vec![],
            children: vec![leaf("item"), leaf("item")],
            content: None,
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, _, _) = build1(&parent);
        let code = lines.join("\n");
        assert!(code.contains("let item_node = NodeBuilder::new(\"item\").build();"));
        assert!(code.contains("let item_node_2 = NodeBuilder::new(\"item\").build();"));
        // Both wired into the parent in order — the bug reconstructed wrong names here.
        assert!(
            code.contains("list_node = list_node.children([item_node, item_node_2]);"),
            "{code}"
        );
    }

    #[test]
    fn const_bytes_content_emits_literal_byte_buffer() {
        use wa_ir::{WapContent, WapContentKind};
        // The one-byte `00` link-code pairing nonce: a compile-time constant, so the
        // builder writes the literal buffer directly (no caller input). Previously the
        // node was built empty, making the request unusable on the wire.
        let node = WapChildNode {
            tag: "link_code_pairing_nonce".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(1),
                const_bytes: Some("00".into()),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (lines, _, _) = build1(&node);
        let code = lines.join("\n");
        assert!(
            code.contains(
                "link_code_pairing_nonce_node = link_code_pairing_nonce_node.bytes(vec![0x00]);"
            ),
            "{code}"
        );
    }

    #[test]
    fn dynamic_bytes_content_threads_a_vec_u8_spec_field() {
        use wa_ir::{WapContent, WapContentKind};
        // A prekey `<signature>` carries caller-supplied key material, so the builder
        // threads a `Vec<u8>` spec field named after the (collision-free) var and
        // writes it as the node content.
        let node = WapChildNode {
            tag: "signature".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(64),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        let code = lines.join("\n");
        // A declared LENGTH is part of what the node accepts, and `build_iq` returns no
        // `Result` to check it in — so the type says it: 64 bytes and nothing else.
        assert!(
            code.contains(
                "signature_node = signature_node.bytes(self.signature_content.to_vec());"
            ),
            "{code}"
        );
        assert_eq!(
            fields,
            vec![(
                "signature_content".to_string(),
                "[u8; 64]".to_string(),
                false
            )]
        );
        // The bound: with no length declared the payload is unbounded, exactly as before.
        let mut node = leaf("signature");
        node.content = Some(WapContent {
            kind: WapContentKind::Bytes,
            ..Default::default()
        });
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(
            lines
                .join("\n")
                .contains("bytes(self.signature_content.clone());"),
            "no length, no array: {}",
            lines.join("\n")
        );
        assert_eq!(
            fields[0].1, "Vec<u8>",
            "and an unbounded payload: {fields:?}"
        );
    }

    #[test]
    fn dynamic_content_field_renames_only_the_terminal_node_segment() {
        use wa_ir::{WapContent, WapContentKind};
        // A tag whose own name contains `_node` must not corrupt the field name: the
        // var `node_id_node` yields `node_id_content`, not `node_content_node`.
        let node = WapChildNode {
            tag: "node_id".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                byte_length: Some(8),
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert_eq!(fields[0].0, "node_id_content");
    }

    #[test]
    fn malformed_const_bytes_emits_nothing_and_adds_no_field() {
        use wa_ir::{WapContent, WapContentKind};
        // A `const_bytes` that can't be decoded degrades to no content — it must not
        // fall through and be turned into a caller-supplied `Vec<u8>` field.
        let node = WapChildNode {
            tag: "nonce".into(),
            attrs: vec![],
            children: vec![],
            content: Some(WapContent {
                kind: WapContentKind::Bytes,
                const_bytes: Some("zz".into()), // not hex
                ..Default::default()
            }),
            repeats: false,
            variant_groups: vec![],
        };
        let (mut enums, mut fields) = (Vec::new(), Vec::new());
        let reserved = std::collections::HashSet::new();
        let attr_fields = crate::spec::AttrFieldMap::new();
        let mut ctx = VariantCtx {
            spec_base: "T",
            enum_defs: &mut enums,
            fields: &mut fields,
            reserved: &reserved,
            attr_fields: &attr_fields,
        };
        let (lines, _, _) = emit_child_builder(&node, "", &mut HashMap::new(), &mut ctx, &[]);
        assert!(fields.is_empty(), "no spec field for a malformed constant");
        assert!(
            !lines.join("\n").contains(".bytes("),
            "no content emitted for a malformed constant"
        );
    }

    /// A `child("weight")` whose only body is a bounded `contentInt` leaf.
    fn child_over(leaf: ParsedField, required: bool) -> ParsedField {
        ParsedField {
            method: if required { "child" } else { "maybeChild" }.into(),
            name: "weight".into(),
            wire_name: Some("weight".into()),
            required,
            children: Some(vec![leaf]),
            ..Default::default()
        }
    }

    fn bounded_leaf(lo: Option<i64>, hi: Option<i64>) -> ParsedField {
        let mut leaf = ranged("weight", lo, hi, true);
        leaf.method = "contentInt".into();
        leaf
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_band() {
        // A child collapsed to its content leaf is emitted HERE, not through
        // `emit_field_parse`, so the band the other two paths apply reached neither shape: a
        // `contentInt` leaf bounded to `-10..=10` parsed a `-20` straight into the field. The
        // band is the leaf's, which is also where the declared width comes from.
        for required in [true, false] {
            let src = emit_struct_parser(
                &[child_over(bounded_leaf(Some(-10), Some(10)), required)],
                "n",
                "R",
                "",
                "P",
            )
            .join("\n");
            assert!(
                src.contains(
                    r#"anyhow::ensure!((-10i64..=10i64).contains(&weight), "weight out of range"#
                ),
                "the leaf's band is enforced (required={required}): {src}"
            );
        }
    }

    #[test]
    fn an_out_of_band_flattened_child_content_value_is_an_error_not_an_absence() {
        // The optional shape keeps absence and rejection apart: the source accessor THROWS on a
        // value outside its range, so mapping it to `None` would accept a response the parser
        // turns away and leave the field quietly missing.
        let src = emit_struct_parser(
            &[child_over(bounded_leaf(Some(-10), Some(10)), false)],
            "n",
            "R",
            "",
            "P",
        )
        .join("\n");
        assert!(
            src.contains("None => None,"),
            "an absent CHILD stays absent: {src}"
        );
        assert!(
            src.contains("anyhow::ensure!((-10i64..=10i64).contains(&weight)"),
            "a value outside the band is an error: {src}"
        );
        // …and a present child with no payload is a third case, which the chained
        // `get_optional_child(…).and_then(|n| n.read())` folded into the first. The leaf here is
        // required, so an empty element is a rejection and not an absence — the committed `erid`
        // child is that shape and was being accepted.
        assert!(
            src.contains(r#"anyhow::anyhow!("<weight> has no content")"#),
            "a present child with no payload is an error: {src}"
        );
    }

    #[test]
    fn an_optional_leaf_under_an_optional_child_may_still_be_absent() {
        // The bound on that third case: when the LEAF itself is optional, an empty element is a
        // value the field can hold and only a payload that IS there has to satisfy the band.
        let mut leaf = bounded_leaf(Some(-10), Some(10));
        leaf.required = false;
        let src = emit_struct_parser(&[child_over(leaf, false)], "n", "R", "", "P").join("\n");
        assert!(
            !src.contains("has no content"),
            "an absent payload is allowed: {src}"
        );
        assert!(
            src.contains("anyhow::ensure!((-10i64..=10i64).contains(&weight)"),
            "a present one is still checked: {src}"
        );
    }

    /// What a leaf DECLARES decides which checks go inside the arm, never whether a present
    /// element is told apart from an absent one.
    ///
    /// Splitting on that gave an unconstrained leaf a chained `and_then`, so an empty
    /// `<weight/>` read as a missing one — the same collapse the declared-band branch beside it
    /// existed to prevent, on the shape that declares nothing.
    #[test]
    fn an_unconstrained_child_still_tells_an_empty_element_from_a_missing_one() {
        for required in [true, false] {
            let src = emit_struct_parser(
                &[child_over(bounded_leaf(None, None), required)],
                "n",
                "R",
                "",
                "P",
            )
            .join("\n");
            assert!(
                !src.contains("ensure!"),
                "nothing declared, nothing enforced (required={required}): {src}"
            );
            assert!(
                !src.contains(".and_then(|n| n."),
                "the two questions stay apart (required={required}): {src}"
            );
        }
        // The optional child descends first, and a REQUIRED leaf inside it then demands its
        // payload — an element that is there with nothing in it is a rejection, not an absence.
        let src = emit_struct_parser(
            &[child_over(bounded_leaf(None, None), false)],
            "n",
            "R",
            "",
            "P",
        )
        .join("\n");
        assert!(
            src.contains(r#"match n.get_optional_child("weight") {"#)
                && src.contains(r#".ok_or_else(|| anyhow::anyhow!("<weight> has no content"))?;"#),
            "a present element must carry its required payload: {src}"
        );
    }

    #[test]
    fn a_length_pinned_content_read_enforces_it() {
        // `contentBytes(32)` and `contentBytesRange(1, 128)` both record what the accessor will
        // accept, and this path decoded the payload and checked nothing — so the generated
        // parser took a body of any length. The union's leaf guard has checked it all along;
        // one rule, two places, one copy missing it, on the byte side this time.
        for (method, len, lo, hi, want) in [
            (
                "contentBytes",
                Some(32),
                None,
                None,
                "element_value.len() == 32",
            ),
            (
                "contentBytesRange",
                None,
                Some(1),
                Some(128),
                "(1..=128).contains(&element_value.len())",
            ),
            (
                "contentBytesRange",
                None,
                Some(4),
                None,
                "element_value.len() >= 4",
            ),
        ] {
            let f = ParsedField {
                method: method.into(),
                name: "elementValue".into(),
                wire_name: Some("elementValue".into()),
                field_type: ParsedFieldType::Bytes,
                required: true,
                byte_length: len,
                byte_min: lo,
                byte_max: hi,
                ..Default::default()
            };
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(
                src.contains(&format!(
                    "anyhow::ensure!({want}, \"elementValue wrong length"
                )),
                "the declared length is enforced: {src}"
            );
        }
    }

    #[test]
    fn a_content_read_with_no_pinned_length_checks_nothing_extra() {
        // The paired bound: nothing declared means nothing enforced, whichever spelling asks.
        for (method, len) in [("contentBytes", None), ("contentUint", None)] {
            let f = ParsedField {
                method: method.into(),
                name: "elementValue".into(),
                wire_name: Some("elementValue".into()),
                required: true,
                byte_length: len,
                ..Default::default()
            };
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(
                !src.contains("wrong length"),
                "no length check here ({method}): {src}"
            );
        }
    }

    #[test]
    fn an_ordinary_content_uint_measures_the_raw_payload() {
        // `contentUint(N)` pins a byte count, and folding N big-endian bytes into a `u64` loses
        // it — so the check is on the RAW payload, before the decode. I had this test asserting
        // that no check belongs here at all, on the grounds that a `u64` has no `len()`. That is
        // true of the decoded value and beside the point: the flattened child path has measured
        // the payload since the round that added it, and review was right that this one had
        // never been given the same rule. The corpus has a repeated `mapChildren` item with
        // `contentUint(3)`, whose one-, two- and four-byte payloads this accepted.
        let f = ParsedField {
            method: "contentUint".into(),
            name: "elementValue".into(),
            wire_name: Some("elementValue".into()),
            required: true,
            byte_length: Some(8),
            ..Default::default()
        };
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"n.content_bytes().is_some_and(|b| b.len() == 8)"#),
            "the payload is measured: {src}"
        );
        // And before the fold, not after: the decoded value is a number and has no length to
        // take. Ordering it the other way round emits code that does not compile.
        assert!(
            src.find("wrong length").unwrap() < src.find("let element_value").unwrap(),
            "the check precedes the decode: {src}"
        );
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_length() {
        // The third site for the byte band, and the last: this path was given the INTEGER band
        // five rounds ago and the byte one reached the attribute read and the ordinary content
        // read without reaching here, so `child("blob")` over a `contentBytes(32)` leaf stored
        // a vector of any length in both shapes.
        for required in [true, false] {
            let mut leaf = ranged("blob", None, None, true);
            leaf.method = "contentBytes".into();
            leaf.byte_length = Some(32);
            let src =
                emit_struct_parser(&[child_over(leaf, required)], "n", "R", "", "P").join("\n");
            assert!(
                src.contains(r#"anyhow::ensure!(weight.len() == 32, "weight wrong length"#),
                "the leaf's length is enforced (required={required}): {src}"
            );
        }
    }

    #[test]
    fn a_flattened_child_content_read_asks_the_classifier_for_its_length() {
        // Nothing declared is nothing enforced.
        let mut leaf = ranged("blob", None, None, true);
        leaf.method = "contentBytes".into();
        let src = emit_struct_parser(&[child_over(leaf, true)], "n", "R", "", "P").join("\n");
        assert!(!src.contains("wrong length"), "nothing declared: {src}");
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_pin() {
        // A leaf can carry BOTH a constraint and a pin — `contentLiteralBytes` records the
        // payload's length and its exact bytes — and this path had a single check slot, so
        // whichever was asked for first was the only one emitted. The committed
        // `FetchKeyBundlesUserSuccess` carries such a leaf.
        let mut leaf = ranged("nonce", None, None, true);
        leaf.method = "contentBytes".into();
        leaf.byte_length = Some(1);
        leaf.literal_value = Some("05".into());
        for required in [true, false] {
            let src = emit_struct_parser(&[child_over(leaf.clone(), required)], "n", "R", "", "P")
                .join("\n");
            assert!(
                src.contains("weight.len() == 1"),
                "the length is still checked (required={required}): {src}"
            );
            assert!(
                src.contains("weight.as_slice() == [0x05u8].as_slice()"),
                "and so is the value (required={required}): {src}"
            );
        }
        // The bound: a leaf with no pin emits only its length, exactly as before.
        leaf.literal_value = None;
        let src = emit_struct_parser(&[child_over(leaf, true)], "n", "R", "", "P").join("\n");
        assert!(src.contains("weight.len() == 1"), "length: {src}");
        assert!(!src.contains("is pinned to"), "nothing pinned: {src}");
    }

    #[test]
    fn a_flattened_child_content_read_enforces_its_vocabulary() {
        // Fourth site for the enum rule — the same count the integer band and the byte length
        // each took to close. The committed `token_type` child carries a `contentEnum` limited
        // to two values and this path stored any string at all.
        let mut leaf = ranged("mode", None, None, true);
        leaf.method = "contentEnum".into();
        leaf.enum_keys = Some(vec!["Strong".into(), "Weak".into()]);
        for required in [true, false] {
            let src = emit_struct_parser(&[child_over(leaf.clone(), required)], "n", "R", "", "P")
                .join("\n");
            assert!(
                src.contains(r#"matches!(weight.as_str(), "Strong" | "Weak")"#),
                "the leaf's vocabulary is enforced (required={required}): {src}"
            );
        }
    }

    #[test]
    fn a_content_uint_length_is_checked_on_the_raw_payload() {
        // `contentUint(N)` folds N big-endian bytes into a `u64`, so by the time the value
        // exists its length is gone — and the committed IR carries `contentUint(4)`, `(1)` and
        // `(3)`, where that count is part of what the accessor takes. I had asserted this leaf
        // gets no length check at all, which was right about the DECODED value (a `u64` has no
        // `len()`, and asking for one is code that does not compile) and wrong about the
        // payload. Review was right; the bound now says which of the two it is about.
        let leaf = |required| {
            let mut leaf = ranged("blob", None, None, required);
            leaf.method = "contentUint".into();
            leaf.byte_length = Some(3);
            leaf
        };
        // And absence is judged per shape — the LEAF's shape. A required accessor has to turn
        // an empty element away as firmly as a wrong-length one, because the decoder behind it
        // ends in `unwrap_or_default` and letting absence through stores a fabricated zero. An
        // optional one is the other answer: absence is a value that field holds.
        //
        // Asked of the leaf at every child optionality, because the child's is a different
        // fact. `get_optional_child` has already decided whether the ELEMENT is there, so the
        // check below it judges a node that is present either way; taking the child's answer
        // had `maybeChild("registration").contentUint(4)` flatten a present, empty
        // `<registration/>` to `None` where the source accessor turns it away. The eighth test
        // of mine review has had to correct, and the second written to bound a rule that in
        // fact says something else.
        for (leaf_required, expect) in [
            (true, "content_bytes().is_some_and(|b| b.len() == 3)"),
            (false, "content_bytes().is_none_or(|b| b.len() == 3)"),
        ] {
            for child_required in [true, false] {
                let src = emit_struct_parser(
                    &[child_over(leaf(leaf_required), child_required)],
                    "n",
                    "R",
                    "",
                    "P",
                )
                .join("\n");
                assert!(
                    src.contains(expect),
                    "the raw payload is measured (leaf={leaf_required} child={child_required}): {src}"
                );
                assert!(
                    !src.contains("weight.len()"),
                    "and never the folded number (leaf={leaf_required} child={child_required}): {src}"
                );
            }
        }
    }

    #[test]
    fn a_band_that_admits_nothing_accepts_nothing() {
        // Filtering the two bounds independently could turn an EMPTY range into a permissive
        // one. A bound is dropped when no value of the emitted width can fail it — `>= 0` under
        // a `u64`; a negative ceiling under that same width is the opposite, a bound no value
        // can pass, and dropping it read `intMin: 5, intMax: -1` as "at least five" and `0, -1`
        // as no check at all. Both accept every value the source accessor turns away.
        for (lo, hi) in [(Some(5), Some(-1)), (Some(0), Some(-1)), (Some(5), Some(3))] {
            let src = emit_field_parse(&ranged("weight", lo, hi, true), "n", "").join("\n");
            assert!(
                src.contains(r#"anyhow::ensure!(false, "weight out of range"#),
                "nothing satisfies {lo:?}..={hi:?}: {src}"
            );
        }
        // The bounds. An ordinary band is still a band at either width, a ceiling alone still
        // makes the field signed and is a real test there, a floor a `u64` cannot fail is still
        // dropped, and no declared range still means no check.
        for (lo, hi, expect) in [
            (Some(5), Some(10), "(5u64..=10u64).contains(&weight)"),
            (Some(-5), Some(10), "(-5i64..=10i64).contains(&weight)"),
            (None, Some(-1), "weight <= -1i64"),
            (Some(5), None, "weight >= 5u64"),
        ] {
            let src = emit_field_parse(&ranged("weight", lo, hi, true), "n", "").join("\n");
            assert!(
                src.contains(expect) && !src.contains("ensure!(false"),
                "an ordinary band {lo:?}..={hi:?}: {src}"
            );
        }
        let src = emit_field_parse(&ranged("weight", None, None, true), "n", "").join("\n");
        assert!(!src.contains("ensure!"), "nothing declared: {src}");
    }

    #[test]
    fn an_enum_field_enforces_its_vocabulary() {
        // The union arm's selection guard has applied this vocabulary all along; the ordinary
        // read copied whatever text was there, so `reason="invalid"` became `Some("invalid")`
        // for a field whose accessor takes seven values. Both shapes, and absence untouched:
        // an optional accessor takes a missing attribute.
        let mut f = ranged("reason", None, None, false);
        f.method = "maybeAttrEnum".into();
        f.field_type = ParsedFieldType::String;
        f.enum_keys = Some(vec!["a".into(), "b".into()]);
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"matches!(reason.as_deref(), None | Some("a") | Some("b"))"#),
            "absent, or one of the accessor's values: {src}"
        );

        f.method = "attrEnum".into();
        f.required = true;
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"matches!(reason.as_str(), "a" | "b")"#),
            "the required read yields a String, so it is tested as one: {src}"
        );
    }

    #[test]
    fn a_field_with_no_vocabulary_checks_nothing_extra() {
        // The bound: the check follows the declared values, not the accessor's name, so a field
        // with none is read exactly as before.
        let mut f = ranged("reason", None, None, false);
        f.method = "maybeAttrString".into();
        f.field_type = ParsedFieldType::String;
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(!src.contains("not accepted"), "nothing declared: {src}");
    }

    #[test]
    fn a_content_enum_enforces_its_vocabulary_too() {
        // `contentEnum(TABLE)` records its values exactly as an attribute enum does, and the
        // content branch returned after the numeric and byte constraints without asking.
        let mut f = ranged("state", None, None, true);
        f.method = "contentEnum".into();
        f.enum_keys = Some(vec!["on".into(), "off".into()]);
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"matches!(state.as_str(), "on" | "off")"#),
            "a content decoder always yields a value, so it is tested as one: {src}"
        );
    }

    #[test]
    fn a_pinned_field_enforces_its_pin() {
        // `literal(attrString, node, "type", "result")` rejects `type="error"` at the source.
        // The union arm's guard has compared that pin all along — it is how an arm is told
        // apart from its siblings — while the ordinary read took any string and stored it.
        let mut f = ranged("type", None, None, true);
        f.method = "attrString".into();
        f.literal_value = Some("result".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"r#type.as_str() == "result""#),
            "the pin is compared: {src}"
        );

        f.method = "maybeAttrString".into();
        f.required = false;
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"matches!(r#type.as_deref(), None | Some("result"))"#),
            "and absence is still allowed for an optional accessor: {src}"
        );
    }

    #[test]
    fn a_diagnostic_never_borrows_a_brace_from_the_wire() {
        // Every message the emitter writes is the first argument of `anyhow!`, `ensure!` or
        // `bail!` — a FORMAT string whether or not it takes arguments. A pinned value, a wire
        // attribute name or a child tag holding `{` or `}` therefore became a placeholder in
        // the generated Rust: this pin produced a message with two extra placeholders and one
        // argument, and the emitted module stopped compiling. Nothing in CI compiles that
        // module, so an otherwise valid IR would have shipped a broken consumer.
        let mut f = ranged("type", None, None, true);
        f.method = "attrString".into();
        f.literal_value = Some("{}".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"is pinned to {{}}: {:?}"#),
            "the pin's braces are doubled, not left as placeholders: {src}"
        );
        // Exactly the one placeholder the message passes an argument for.
        let msg = src
            .lines()
            .find(|l| l.contains("is pinned to"))
            .expect("the ensure line");
        // From the message literal's own opening quote — the line also carries the COMPARISON,
        // whose `"{}"` is the pin itself and not part of the format string. My first draft of
        // this bound took the first quote on the line and counted that one too.
        let start = msg
            .find("\"type is pinned to")
            .expect("the message literal")
            + 1;
        let body = &msg[start..start + msg[start..].find('"').expect("close quote")];
        assert_eq!(
            body.replace("{{", "")
                .replace("}}", "")
                .matches('{')
                .count(),
            1,
            "one placeholder, one argument: {msg}"
        );

        // The same for the WIRE name, which reaches the message by a different route.
        let mut f = ranged("od{d}", None, None, true);
        f.method = "attrString".into();
        f.wire_name = Some("od{d}".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("missing od{{d}}"),
            "the wire name's braces are doubled too: {src}"
        );

        // The bound: a name with no braces is embedded exactly as before, so the escaping
        // narrows nothing it should not.
        let mut f = ranged("plain", None, None, true);
        f.method = "attrString".into();
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains(r#"missing plain"#) && !src.contains("{{"),
            "an ordinary name is untouched: {src}"
        );
    }

    #[test]
    fn a_pin_this_cannot_compare_is_left_alone() {
        // The bound: the IR records a pin as TEXT, and comparing it against a decoded number or
        // a byte payload needs the care `leaf_guard` takes over a pin that does not fit the
        // field's width. Those keep the reading they have until there is a case to measure.
        // An integer pin IS compared, after decoding — which is what review corrected here,
        // and the corpus has `code = 500` among others. I had asserted the opposite.
        let mut f = ranged("count", None, None, true);
        f.method = "attrInt".into();
        f.literal_value = Some("7".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(src.contains("count == 7u64"), "compared as a number: {src}");

        // What is still left alone: a pin no value of the field's width can equal, which is not
        // a comparison at all — the same `representable` question the union arm asks.
        f.literal_value = Some("-7".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(!src.contains("is pinned to"), "unrepresentable: {src}");

        // A BYTES pin used to be listed here too, as "text this does not decode". The scan
        // writes it as the payload's bytes in lowercase hex, two digits each — a spelling
        // `decode_hex` reads and the const-content builder already relies on — so declining it
        // was a claim about my own recorder that was not true of it. Four live pins in the
        // committed corpus went unenforced behind that claim. Another of the reversals the PR
        // lists, and the second in this one test.
        f.method = "contentBytes".into();
        f.literal_value = Some("05".into());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(
            src.contains("count.as_slice() == [0x05u8].as_slice()"),
            "bytes are compared: {src}"
        );

        // What stays left alone is a pin whose text is NOT that spelling — an odd digit count
        // or a non-hex character is not a payload this recorded, and guessing at one would
        // reject responses the parser takes.
        for text in ["5", "zz"] {
            f.literal_value = Some(text.into());
            let src = emit_field_parse(&f, "n", "").join("\n");
            assert!(
                !src.contains("is pinned to"),
                "unreadable pin {text}: {src}"
            );
        }

        // An empty pin says the payload is empty, which needs no literal to compare against.
        f.literal_value = Some(String::new());
        let src = emit_field_parse(&f, "n", "").join("\n");
        assert!(src.contains("count.is_empty()"), "empty pin: {src}");
    }
}
