//! IR -> Rust for the incoming-notification dispatch catalog.
//!
//! Emits a drift-free replacement for the hand-maintained `match notification_type`
//! a client otherwise writes: a `NotificationType` enum (with wire<->variant
//! conversions), the `<notification>`-tag → handler-module table, the top-level
//! `StanzaTag` enum, and — for every notification whose handler exposes a legacy
//! parser — a typed content struct (reusing the IQ response field-tree emitter).

use wa_ir::{NotifIr, NotificationDef, StanzaTagDef};

use crate::fields::{RustChildStruct, RustField, collect_response_fields, emit_enum_def};
use crate::naming::{pascal_case, snake_case};

/// Generate the reference Rust catalog from the notification IR.
pub fn generate_notif(ir: &NotifIr) -> String {
    let mut body = String::new();
    body.push_str(&emit_notification_type_enum(&ir.notifications));
    body.push_str(&emit_stanza_tag_enum(&ir.stanza_tags));
    body.push_str(&emit_handler_table(&ir.notifications));
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

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{
        AssertionKind, ParsedField, ParsedFieldType, ParsedResponse, ResponseAssertion, SubCase,
        SubDiscriminant, SubDiscriminantOn,
    };

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
                        }],
                        fields: vec![ParsedField {
                            method: "attrString".into(),
                            name: "id".into(),
                            field_type: ParsedFieldType::String,
                            required: true,
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
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
