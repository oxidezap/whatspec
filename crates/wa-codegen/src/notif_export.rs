//! IR -> Rust for the incoming-notification dispatch catalog.
//!
//! Emits a drift-free replacement for the hand-maintained `match notification_type`
//! a client otherwise writes: a `NotificationType` enum (with wire<->variant
//! conversions), the `<notification>`-tag → handler-module table, the top-level
//! `StanzaTag` enum, and — for every notification whose handler exposes a legacy
//! parser — a typed content struct (reusing the IQ response field-tree emitter).

use wa_ir::{NotifIr, NotificationDef, StanzaTagDef};

use crate::fields::{RustChildStruct, RustField, collect_response_fields, emit_enum_def};
use crate::naming::{pascal_case, rust_lit, snake_case};

/// Generate the reference Rust catalog from the notification IR.
pub fn generate_notif(ir: &NotifIr) -> String {
    let mut body = String::new();
    body.push_str(&emit_notification_type_enum(&ir.notifications));
    body.push_str(&emit_stanza_tag_enum(&ir.stanza_tags));
    body.push_str(&emit_handler_table(&ir.notifications));
    body.push_str(&emit_action_tables(&ir.notifications));
    let (content, uses_jid) = emit_content_module(&ir.notifications);

    let mut out = String::new();
    let dispatchers = if ir.dispatcher_modules.is_empty() {
        "<none>".to_string()
    } else {
        ir.dispatcher_modules.join(", ")
    };
    out.push_str(&format!(
        "//! Auto-generated incoming-notification dispatch catalog (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! Dispatcher modules: {}. Regenerated from the notif IR by wa-codegen.\n\
         //! A generated catalog — a consumer uses a subset, so unused items are expected.\n\
         #![allow(clippy::all, dead_code, non_snake_case)]\n\n",
        ir.wa_version, dispatchers,
    ));
    // The typed content structs may reference `Jid`; import it only when a field
    // actually decodes to one, so the file has no dead import.
    if uses_jid {
        out.push_str("use wacore_binary::jid::Jid;\n\n");
    }
    out.push_str(&body);
    out.push_str(&content);
    out
}

/// `pub enum NotificationType` + wire<->variant conversions + `ALL`.
fn emit_notification_type_enum(notifications: &[NotificationDef]) -> String {
    let mut l = String::new();
    l.push_str("/// Every `<notification type=\"…\">` kind WA Web dispatches.\n");
    l.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n");
    l.push_str("pub enum NotificationType {\n");
    for n in notifications {
        l.push_str(&format!("    {},\n", variant_name(&n.notif_type)));
    }
    l.push_str("}\n\n");

    l.push_str("impl NotificationType {\n");
    l.push_str("    /// The wire `type` attribute value.\n");
    l.push_str("    pub const fn as_wire(&self) -> &'static str {\n        match self {\n");
    for n in notifications {
        l.push_str(&format!(
            "            Self::{} => {:?},\n",
            variant_name(&n.notif_type),
            n.notif_type
        ));
    }
    l.push_str("        }\n    }\n\n");
    l.push_str("    /// Parse a wire `type` value into a variant.\n");
    l.push_str("    pub fn from_wire(s: &str) -> Option<Self> {\n        Some(match s {\n");
    for n in notifications {
        l.push_str(&format!(
            "            {:?} => Self::{},\n",
            n.notif_type,
            variant_name(&n.notif_type)
        ));
    }
    l.push_str("            _ => return None,\n        })\n    }\n\n");
    l.push_str("    /// Every variant, in catalog order.\n");
    l.push_str("    pub const ALL: &'static [NotificationType] = &[\n");
    for n in notifications {
        l.push_str(&format!("        Self::{},\n", variant_name(&n.notif_type)));
    }
    l.push_str("    ];\n}\n\n");
    l
}

/// `pub enum StanzaTag` + wire<->variant conversions.
fn emit_stanza_tag_enum(tags: &[StanzaTagDef]) -> String {
    let mut l = String::new();
    l.push_str("/// Top-level stanza tags handled on an authenticated connection.\n");
    l.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n");
    l.push_str("pub enum StanzaTag {\n");
    for t in tags {
        l.push_str(&format!("    {},\n", variant_name(&t.tag)));
    }
    l.push_str("}\n\n");
    l.push_str("impl StanzaTag {\n");
    l.push_str("    pub const fn as_wire(&self) -> &'static str {\n        match self {\n");
    for t in tags {
        l.push_str(&format!(
            "            Self::{} => {:?},\n",
            variant_name(&t.tag),
            t.tag
        ));
    }
    l.push_str("        }\n    }\n\n");
    l.push_str("    pub fn from_wire(s: &str) -> Option<Self> {\n        Some(match s {\n");
    for t in tags {
        l.push_str(&format!(
            "            {:?} => Self::{},\n",
            t.tag,
            variant_name(&t.tag)
        ));
    }
    l.push_str("            _ => return None,\n        })\n    }\n}\n\n");
    l
}

/// `pub const NOTIFICATION_HANDLERS: &[NotificationHandler]` — the dispatch table.
/// Sub-discriminants (e.g. `encrypt` → `count`/`digest`) ride along as a doc line.
fn emit_handler_table(notifications: &[NotificationDef]) -> String {
    let mut l = String::new();
    l.push_str(
        "/// A dispatch entry: a notification type and the WA Web handler it forwards to.\n",
    );
    l.push_str("#[derive(Debug, Clone, Copy)]\n");
    l.push_str("pub struct NotificationHandler {\n");
    l.push_str("    pub notif_type: NotificationType,\n");
    l.push_str("    /// The WA Web handler module, when the arm forwards to one.\n");
    l.push_str("    pub handler_module: Option<&'static str>,\n");
    l.push_str("    /// The method invoked on the handler module, when applicable.\n");
    l.push_str("    pub handler_function: Option<&'static str>,\n");
    l.push_str("}\n\n");
    l.push_str("/// The `<notification>` dispatch table, mirroring WA Web's `switch(type)`.\n");
    l.push_str("pub const NOTIFICATION_HANDLERS: &[NotificationHandler] = &[\n");
    for n in notifications {
        for sd in &n.sub_discriminants {
            let cases: Vec<String> = sd
                .cases
                .iter()
                .map(|c| match &c.handler_module {
                    Some(m) => format!("{} -> {m}", c.value),
                    None => c.value.clone(),
                })
                .collect();
            l.push_str(&format!(
                "    // `{}` sub-dispatch on {:?}: {}\n",
                n.notif_type,
                sd.on,
                cases.join(", ")
            ));
        }
        l.push_str(&format!(
            "    NotificationHandler {{ notif_type: NotificationType::{}, handler_module: {}, handler_function: {} }},\n",
            variant_name(&n.notif_type),
            opt_str(&n.handler_module),
            opt_str(&n.handler_function),
        ));
    }
    l.push_str("];\n\n");
    l
}

/// `pub mod content { … }` — one typed struct per notification with a recovered
/// content shape, plus the nested child structs / enums those fields need.
///
/// Returns `(module_source, uses_jid)`. `uses_jid` is derived from the generated
/// fields' Rust types (which come from the type-aware [`crate::fields`] emitter),
/// not by grepping the rendered text — so it can't misfire on a `Jid` substring in
/// a doc comment or parser name.
fn emit_content_module(notifications: &[NotificationDef]) -> (String, bool) {
    let typed: Vec<&NotificationDef> = notifications
        .iter()
        .filter(|n| n.content.is_some())
        .collect();
    if typed.is_empty() {
        return (String::new(), false);
    }

    let mut inner = String::new();
    let mut uses_jid = false;
    for n in &typed {
        let content = n.content.as_ref().unwrap();
        let struct_name = pascal_case(&n.notif_type);
        let (fields, child_structs, enums) = collect_response_fields(&content.fields, &struct_name);

        uses_jid |= fields_use_jid(&fields)
            || child_structs.iter().any(|cs| fields_use_jid(&cs.fields))
            || enums
                .iter()
                .any(|e| e.variants.iter().any(|v| fields_use_jid(&v.fields)));

        inner.push_str(&format!(
            "/// Content of `<notification type={:?}>` (parser `{}`).\n",
            n.notif_type, content.parser_name
        ));
        inner.push_str(&emit_struct(&struct_name, &fields));
        for cs in &child_structs {
            inner.push_str(&emit_child_struct(cs));
        }
        for e in &enums {
            for line in emit_enum_def(e) {
                inner.push_str(&line);
                inner.push('\n');
            }
        }
    }

    let mut l = String::new();
    l.push_str("/// Typed content shapes for notifications whose handler exposes a parser.\n");
    l.push_str("pub mod content {\n");
    if uses_jid {
        l.push_str("    use super::Jid;\n\n");
    }
    for line in inner.trim_end().split('\n') {
        if line.is_empty() {
            l.push('\n');
        } else {
            l.push_str("    ");
            l.push_str(line);
            l.push('\n');
        }
    }
    l.push_str("}\n");
    (l, uses_jid)
}

/// Whether any generated field decodes to a `Jid` (`Jid` / `Option<Jid>`). Read off
/// the field's Rust type, which the field emitter derives from `ParsedFieldType`.
fn fields_use_jid(fields: &[RustField]) -> bool {
    fields.iter().any(|f| f.rust_type.contains("Jid"))
}

/// A plain data struct: `pub struct Name { pub f: T, … }` (empty → unit-like `{}`).
fn emit_struct(name: &str, fields: &[RustField]) -> String {
    let mut l = String::new();
    l.push_str("#[derive(Debug, Clone, Default)]\n");
    l.push_str(&format!("pub struct {name} {{\n"));
    for f in fields {
        l.push_str(&format!("    pub {}: {},\n", f.name, f.rust_type));
    }
    l.push_str("}\n\n");
    l
}

fn emit_child_struct(cs: &RustChildStruct) -> String {
    emit_struct(&cs.name, &cs.fields)
}

/// A Rust enum-variant / stanza-variant identifier from a wire token
/// (`account_sync` → `AccountSync`, `w:gp2` → `WGp2`, `fb:update` → `FbUpdate`).
fn variant_name(wire: &str) -> String {
    let p = pascal_case(wire);
    // pascal_case can yield an empty/leading-digit ident for exotic tokens; guard it.
    if p.is_empty() || p.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("N{}", snake_case(wire))
    } else {
        p
    }
}

/// `Some("x")` / `None` for an optional string, as a Rust literal.
fn opt_str(v: &Option<String>) -> String {
    match v {
        Some(s) => format!("Some({s:?})"),
        None => "None".to_string(),
    }
}

/// The `NotifFieldType` variants, in IR order.
///
/// Paired with [`field_type_variant`]'s exhaustive match: adding a variant to
/// [`wa_ir::ParsedFieldType`] fails to compile the generator rather than silently
/// widening a generated enum that a consumer has already matched on.
const FIELD_TYPE_VARIANTS: &[&str] = &[
    "String",
    "Integer",
    "Timestamp",
    "TimestampMillis",
    "Enum",
    "Bytes",
    "Jid",
    "UserJid",
    "LidUserJid",
    "DeviceJid",
    "LidDeviceJid",
    "GroupJid",
    "NewsletterJid",
    "CallJid",
    "BroadcastJid",
    "StatusJid",
    "JidTyped",
    "Bool",
    "Union",
    "Node",
];

/// The out-of-set policy as the generated table spells it.
///
/// A `bool` rather than a mirrored enum: the reference table only has to answer "may I
/// close this enum", and `Reject` vs `Null` is exactly that question. `Unclassified`
/// answers it with `None` — the same as "no table" — because a policy nobody judged is
/// not a licence to close anything.
///
/// `has_values` is the other half, and it is not a detail: this field's whole meaning is
/// "what happens to a value outside `enum_values`", so with that table empty there is no
/// set for the answer to be about. The one action it applies to is `create.reason`, whose
/// handler recognizes several reasons the action extractor could not name — publishing
/// `Some(false)` there described every possible reason as outside an empty set. Same rule
/// as `attrJidEnum` in `wa_ir::wap`: no policy without the set it judges.
fn rejects_unknown_value(p: Option<wa_ir::UnknownValuePolicy>, has_values: bool) -> &'static str {
    if !has_values {
        return "None";
    }
    match p {
        Some(wa_ir::UnknownValuePolicy::Reject) => "Some(true)",
        Some(wa_ir::UnknownValuePolicy::Null) => "Some(false)",
        Some(wa_ir::UnknownValuePolicy::Unclassified) | None => "None",
    }
}

/// The generated variant name for an IR field type. Exhaustive on purpose; see
/// [`FIELD_TYPE_VARIANTS`].
fn field_type_variant(t: wa_ir::ParsedFieldType) -> &'static str {
    use wa_ir::ParsedFieldType as T;
    match t {
        T::String => "String",
        T::Integer => "Integer",
        T::Timestamp => "Timestamp",
        T::TimestampMillis => "TimestampMillis",
        T::Enum => "Enum",
        T::Bytes => "Bytes",
        T::Jid => "Jid",
        T::UserJid => "UserJid",
        T::LidUserJid => "LidUserJid",
        T::DeviceJid => "DeviceJid",
        T::LidDeviceJid => "LidDeviceJid",
        T::GroupJid => "GroupJid",
        T::NewsletterJid => "NewsletterJid",
        T::CallJid => "CallJid",
        T::BroadcastJid => "BroadcastJid",
        T::StatusJid => "StatusJid",
        T::JidTyped => "JidTyped",
        T::Bool => "Bool",
        T::Union => "Union",
        T::Node => "Node",
    }
}

/// The payload action unions (`notifications[].actions`) as a const table.
///
/// The envelope structs above describe what wraps the payload; this is the layer INSIDE
/// it — `w:gp2`'s 47 group-action arms and their normalization. Without it a consumer
/// reading the reference `notif.rs` instead of the JSON sees none of it, which is the
/// whole point of shipping a reference consumer.
///
/// Emitted as data rather than a generated enum per notification type: the arms are a
/// many-to-one wire-tag → action-type map with heterogeneous payloads, and a table keeps
/// the mapping and the per-arm shape addressable without inventing 47 struct names.
fn emit_action_tables(notifications: &[NotificationDef]) -> String {
    if notifications.iter().all(|n| n.actions.is_empty()) {
        return String::new();
    }
    let mut l = String::new();
    l.push_str(
        "/// How an action field decodes. Mirrors the IR's own vocabulary rather than\n\
         /// collapsing to a Rust type, because the JID flavours must stay distinct: a PN\n\
         /// user JID and a LID user JID are different identities for the same person.\n",
    );
    l.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    l.push_str("pub enum NotifFieldType {\n");
    for v in FIELD_TYPE_VARIANTS {
        l.push_str(&format!("    {v},\n"));
    }
    l.push_str("}\n\n");
    l.push_str("/// One field an action arm reads off its child element.\n");
    l.push_str("#[derive(Debug, Clone, Copy)]\n");
    l.push_str("pub struct NotifActionField {\n");
    l.push_str("    /// Output field name.\n");
    l.push_str("    pub name: &'static str,\n");
    l.push_str("    /// The wire attribute (or child tag, for a content read) it comes from.\n");
    l.push_str("    pub wire_name: &'static str,\n");
    l.push_str("    /// How the value decodes.\n");
    l.push_str("    pub field_type: NotifFieldType,\n");
    l.push_str("    /// Whether the arm reads it unconditionally.\n");
    l.push_str("    pub required: bool,\n");
    l.push_str("    /// The element body is read instead of an attribute.\n");
    l.push_str("    pub content: bool,\n");
    l.push_str(
        "    /// The wire enum the handler validates this value against, when the\n\
         \x20   /// extractor could name it. A `field_type` of `Enum` says the value is\n\
         \x20   /// constrained; this says to WHAT.\n",
    );
    l.push_str("    pub enum_values: &'static [&'static str],\n");
    l.push_str(
        "    /// What the handler does with a value outside `enum_values`: `Some(true)`\n\
         \x20   /// rejects the notification, `Some(false)` yields null and parses on.\n\
         \x20   /// `None` means no usable policy — the accessor checks no table, one was\n\
         \x20   /// checked and this build has not judged which it does, or `enum_values`\n\
         \x20   /// is empty, leaving no set for the answer to be about.\n\
         \x20   /// A consumer may close a generated enum only on `Some(true)`.\n",
    );
    l.push_str("    pub rejects_unknown_value: Option<bool>,\n");
    l.push_str("}\n\n");
    l.push_str(
        "/// A value an arm stamps rather than reading. Typed, because `false` and the\n\
         /// string `\"false\"` are different values and a stringified table cannot say which.\n",
    );
    l.push_str("#[derive(Debug, Clone, Copy)]\n");
    l.push_str("pub enum NotifConstValue {\n");
    l.push_str("    Bool(bool),\n");
    l.push_str("    Int(i64),\n");
    l.push_str("    Str(&'static str),\n");
    l.push_str("}\n\n");
    l.push_str("/// A repeated sub-element an arm maps over (`participants`).\n");
    l.push_str("#[derive(Debug, Clone, Copy)]\n");
    l.push_str("pub struct NotifActionChild {\n");
    l.push_str("    pub name: &'static str,\n");
    l.push_str("    pub wire_tag: &'static str,\n");
    l.push_str("    pub fields: &'static [NotifActionField],\n");
    l.push_str("    /// Whether every branch producing this action carries the list.\n");
    l.push_str("    pub required: bool,\n");
    l.push_str("}\n\n");
    l.push_str("/// One arm of a notification's payload action union.\n");
    l.push_str("#[derive(Debug, Clone, Copy)]\n");
    l.push_str("pub struct NotifAction {\n");
    l.push_str("    pub notif_type: NotificationType,\n");
    l.push_str("    /// The child element's tag — what the handler switches on.\n");
    l.push_str("    pub wire_tag: &'static str,\n");
    l.push_str(
        "    /// The normalized identity. NOT always the wire tag (`not_ephemeral` →\n\
         \x20   /// `ephemeral`); `None` when the arm computes it.\n",
    );
    l.push_str("    pub action_type: Option<&'static str>,\n");
    l.push_str("    pub fields: &'static [NotifActionField],\n");
    l.push_str(
        "    /// Fields the arm stamps to a constant rather than reading — the\n\
         \x20   /// normalization that is invisible from the wire alone.\n",
    );
    l.push_str("    pub constants: &'static [(&'static str, NotifConstValue)],\n");
    l.push_str("    pub children: &'static [NotifActionChild],\n");
    l.push_str("}\n\n");

    let field_list = |fields: &[wa_ir::NotifActionField]| -> String {
        let items: Vec<String> = fields
            .iter()
            .map(|f| {
                let values: Vec<String> = f
                    .enum_ref
                    .as_ref()
                    .map(|e| e.variants.iter().map(|v| rust_lit(&v.value)).collect())
                    .unwrap_or_default();
                format!(
                    "NotifActionField {{ name: {}, wire_name: {}, field_type: NotifFieldType::{}, required: {}, content: {}, enum_values: &[{}], rejects_unknown_value: {} }}",
                    rust_lit(&f.name),
                    rust_lit(&f.wire_name),
                    field_type_variant(f.field_type),
                    f.required,
                    f.content,
                    values.join(", "),
                    rejects_unknown_value(f.unknown_value, !values.is_empty()),
                )
            })
            .collect();
        format!("&[{}]", items.join(", "))
    };

    l.push_str("/// Every payload action arm, by notification type then wire tag.\n");
    l.push_str("pub const NOTIF_ACTIONS: &[NotifAction] = &[\n");
    for n in notifications {
        for a in &n.actions {
            let constants: Vec<String> = a
                .constant_fields
                .iter()
                .map(|c| {
                    let v = match &c.value {
                        wa_ir::NotifConstValue::Bool(b) => format!("NotifConstValue::Bool({b})"),
                        wa_ir::NotifConstValue::Int(i) => format!("NotifConstValue::Int({i})"),
                        wa_ir::NotifConstValue::Str(s) => {
                            format!("NotifConstValue::Str({})", rust_lit(s))
                        }
                    };
                    format!("({}, {v})", rust_lit(&c.name))
                })
                .collect();
            let children: Vec<String> = a
                .children
                .iter()
                .map(|c| {
                    format!(
                        "NotifActionChild {{ name: {}, wire_tag: {}, fields: {}, required: {} }}",
                        rust_lit(&c.name),
                        rust_lit(&c.wire_tag),
                        field_list(&c.fields),
                        c.required
                    )
                })
                .collect();
            l.push_str(&format!(
                "    NotifAction {{ notif_type: NotificationType::{}, wire_tag: {}, \
                 action_type: {}, fields: {}, constants: &[{}], children: &[{}] }},\n",
                pascal_case(&n.notif_type),
                rust_lit(&a.wire_tag),
                match &a.action_type {
                    Some(t) => format!("Some({})", rust_lit(t)),
                    None => "None".to_string(),
                },
                field_list(&a.fields),
                constants.join(", "),
                children.join(", ")
            ));
        }
    }
    l.push_str("];\n\n");
    l.push_str(
        "/// The arms a notification type's payload can carry.\n\
         pub fn actions_for(t: NotificationType) -> impl Iterator<Item = &'static NotifAction> {\n\
         \x20   NOTIF_ACTIONS.iter().filter(move |a| a.notif_type == t)\n\
         }\n\n",
    );
    l
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{
        AssertionKind, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion, SubCase,
        SubDiscriminant, SubDiscriminantOn,
    };

    #[test]
    fn a_policy_needs_the_set_it_judges() {
        // `rejects_unknown_value` answers "what happens to a value outside
        // `enum_values`". With that table empty there is no set for it to be about, and
        // `Some(false)` there described every possible value as outside an empty one —
        // the live case being `create.reason`, whose handler recognizes several reasons
        // the action extractor could not name.
        let field = |name: &str, enum_ref: Option<wa_ir::AttrEnumRef>| wa_ir::NotifActionField {
            name: name.into(),
            wire_name: name.into(),
            field_type: ParsedFieldType::Enum,
            required: false,
            content: false,
            enum_ref,
            unknown_value: Some(wa_ir::UnknownValuePolicy::Null),
        };
        let mut ir = ir();
        ir.notifications[0].actions = vec![wa_ir::NotifActionDef {
            wire_tag: "add".into(),
            action_type: None,
            fields: vec![
                field("reason", None),
                field(
                    "kind",
                    Some(wa_ir::AttrEnumRef {
                        name: "K".into(),
                        module: "M".into(),
                        variants: vec![wa_ir::AttrEnumVariant {
                            name: "INVITE".into(),
                            value: "invite".into(),
                        }],
                    }),
                ),
            ],
            constant_fields: vec![],
            children: vec![],
        }];
        let src = generate_notif(&ir);
        assert!(
            src.contains(r#"name: "reason", wire_name: "reason", field_type: NotifFieldType::Enum, required: false, content: false, enum_values: &[], rejects_unknown_value: None"#),
            "no set, so no policy:\n{src}"
        );
        assert!(
            src.contains(r#"enum_values: &["invite"], rejects_unknown_value: Some(false)"#),
            "the set is published, so the policy is usable:\n{src}"
        );
    }

    #[test]
    fn the_payload_action_union_reaches_generated_rust() {
        // The envelope structs describe what WRAPS the payload; the arms inside it are a
        // whole protocol layer, and a consumer reading this file instead of the JSON saw
        // none of it. The many-to-one normalization is the part that cannot be guessed
        // from the wire, so it is what the assertion pins.
        let mut ir = ir();
        ir.notifications[0].actions = vec![wa_ir::NotifActionDef {
            wire_tag: "not_ephemeral".into(),
            action_type: Some("ephemeral".into()),
            fields: vec![],
            constant_fields: vec![wa_ir::NotifActionConstant {
                name: "duration".into(),
                value: wa_ir::NotifConstValue::Int(0),
            }],
            children: vec![],
        }];
        let src = generate_notif(&ir);
        assert!(src.contains("pub const NOTIF_ACTIONS"), "the table exists");
        assert!(
            src.contains(r#"wire_tag: "not_ephemeral""#)
                && src.contains(r#"action_type: Some("ephemeral")"#),
            "the many-to-one mapping survives:\n{src}"
        );
        // Typed, not stringified: `false` and the string `"false"` are different values,
        // and a `(&str, &str)` table cannot say which one the arm stamps.
        assert!(
            src.contains(r#"("duration", NotifConstValue::Int(0))"#),
            "and the constant the arm stamps, with its type:\n{src}"
        );
        syn::parse_file(&src).expect("generated notif.rs is valid Rust");
    }

    fn ir() -> NotifIr {
        NotifIr {
            wa_version: "2.3000.test".into(),
            dispatcher_modules: vec!["WAWebCommsHandleLoggedInStanza".into()],
            stanza_tags: vec![StanzaTagDef {
                tag: "presence".into(),
                handler_module: Some("WAWebHandlePresence".into()),
                handler_function: None,
            }],
            notifications: vec![
                NotificationDef {
                    notif_type: "devices".into(),
                    handler_module: Some("WAWebHandleDeviceNotification".into()),
                    handler_function: Some("handleDevicesNotification".into()),
                    sub_discriminants: vec![],
                    content: Some(ParsedResponse {
                        parser_name: "incomingDevicesNotification".into(),
                        assertions: vec![ResponseAssertion {
                            kind: AssertionKind::Tag,
                            name: Some("notification".into()),
                            value: None,
                            reference_path: None,
                        }],
                        fields: vec![ParsedField {
                            method: "attrString".into(),
                            name: "id".into(),
                            field_type: ParsedFieldType::String,
                            parser_required: true,
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    actions: Vec::new(),
                },
                NotificationDef {
                    notif_type: "encrypt".into(),
                    handler_module: None,
                    handler_function: None,
                    sub_discriminants: vec![SubDiscriminant {
                        on: SubDiscriminantOn::FirstChildTag,
                        cases: vec![SubCase {
                            value: "count".into(),
                            handler_module: Some("WAWebHandlePreKeyLow".into()),
                            handler_function: None,
                        }],
                    }],
                    content: None,
                    actions: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn generates_parseable_rust() {
        let src = generate_notif(&ir());
        syn::parse_file(&src)
            .unwrap_or_else(|e| panic!("generated notif.rs is invalid: {e}\n{src}"));
    }

    #[test]
    fn emits_wire_conversions_and_handler_table() {
        let src = generate_notif(&ir());
        assert!(src.contains("pub enum NotificationType"));
        assert!(src.contains("Devices,"));
        assert!(src.contains("Self::Devices => \"devices\""));
        assert!(src.contains("\"devices\" => Self::Devices"));
        assert!(src.contains("handler_module: Some(\"WAWebHandleDeviceNotification\")"));
        // encrypt has no primary handler but a sub-dispatch comment.
        assert!(src.contains("handler_module: None"));
        assert!(src.contains("sub-dispatch"));
    }

    #[test]
    fn emits_typed_content_struct() {
        let src = generate_notif(&ir());
        assert!(src.contains("pub mod content"));
        assert!(src.contains("pub struct Devices"));
        assert!(src.contains("pub id: String"));
    }
}
