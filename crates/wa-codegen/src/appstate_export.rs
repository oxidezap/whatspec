//! Generate a self-contained, typed Rust registry of AppState (syncd) action
//! schemas from the appstate IR — the Rust analog of zapo's
//! `spec/appstate/index.{js,d.ts}`.
//!
//! Emits `Collection`/`Scope`/`IndexPart` enums, a `Schema` struct, one
//! `pub const <ACTION>: Schema` per action, plus `COLLECTIONS`, `ALL`, and a
//! `by_name` lookup. Everything is `const` / `&'static`, dependency-free, so a
//! consumer can drive typed syncd mutation building/indexing without the library
//! exposing a per-action API.

use std::collections::{BTreeSet, HashSet};

use wa_ir::{AppstateIr, IndexPart};

use crate::naming::{pascal_case, rust_lit, snake_case, unique_ident};

/// Render the full `schemas.rs` artifact.
pub fn generate_appstate_schemas(ir: &AppstateIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated AppState (syncd) action schemas (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! Typed registry of syncd actions: collection, version, scope, value proto type,\n\
         //! enum fields, and the mutation-index parts. `const`/`&'static`, no deps.\n\n\
         #![allow(clippy::all)]\n\n",
        ir.wa_version
    ));

    out.push_str(&render_collection_enum(&ir.collections));
    let scopes: BTreeSet<&str> = ir.actions.values().map(|a| a.scope.as_str()).collect();
    out.push_str(&render_scope_enum(&scopes));
    out.push_str(INDEX_PART_AND_SCHEMA);

    // COLLECTIONS list.
    let coll_variants: Vec<String> = ir
        .collections
        .iter()
        .map(|c| format!("Collection::{}", pascal_case(c)))
        .collect();
    out.push_str(&format!(
        "/// All syncd collections, in dependency order.\npub const COLLECTIONS: &[Collection] = &[{}];\n\n",
        coll_variants.join(", ")
    ));

    // One const per action + the ALL table.
    let mut all_entries: Vec<String> = Vec::new();
    let mut used_consts = HashSet::new();
    for (key, action) in &ir.actions {
        // Disambiguate/sanitize so two keys that upper-case to the same ident (or
        // an empty/digit-led key) can't emit a duplicate or invalid `pub const`.
        let const_name = unique_ident(&snake_case(key).to_uppercase(), &mut used_consts, "ACTION");
        let collection = action
            .collection
            .as_deref()
            .map(|c| format!("Collection::{}", pascal_case(c)))
            .unwrap_or_else(|| "Collection::Regular".to_string());
        let scope = format!("Scope::{}", pascal_case(&action.scope));
        let version = action.version.unwrap_or(0);
        let value_field = opt_lit(action.value_field.as_deref());
        let value_proto = opt_lit(action.value_proto_type.as_deref());
        let enum_fields = match &action.value_enum_fields {
            Some(m) if !m.is_empty() => format!(
                "&[{}]",
                m.iter()
                    .map(|(k, v)| format!("({}, {})", rust_lit(k), rust_lit(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => "&[]".to_string(),
        };
        let chat_jid_index = match action.chat_jid_index {
            Some(i) => format!("Some({i})"),
            None => "None".to_string(),
        };
        let index_parts = action
            .index_parts
            .iter()
            .map(render_index_part)
            .collect::<Vec<_>>()
            .join(", ");

        out.push_str(&format!(
            "/// `{key}` — module `{}`.\npub const {const_name}: Schema = Schema {{\n\
             \x20   key: {},\n    name: {},\n    module: {},\n    collection: {collection},\n\
             \x20   version: {version},\n    scope: {scope},\n    value_field: {value_field},\n\
             \x20   value_proto_type: {value_proto},\n    value_enum_fields: {enum_fields},\n\
             \x20   chat_jid_index: {chat_jid_index},\n    index_parts: &[{index_parts}],\n}};\n\n",
            action.module,
            rust_lit(key),
            rust_lit(&action.name),
            rust_lit(&action.module),
        ));
        all_entries.push(const_name);
    }

    out.push_str("/// Every action schema, keyed-sorted.\npub const ALL: &[Schema] = &[\n");
    for name in &all_entries {
        out.push_str(&format!("    {name},\n"));
    }
    out.push_str("];\n\n");
    out.push_str(
        "/// Look up a schema by its action key (the registry key, e.g. `\"Agent\"`).\n\
         pub fn by_name(key: &str) -> Option<&'static Schema> {\n\
         \x20   ALL.iter().find(|s| s.key == key)\n}\n",
    );
    out
}

fn opt_lit(v: Option<&str>) -> String {
    match v {
        Some(s) => format!("Some({})", rust_lit(s)),
        None => "None".to_string(),
    }
}

fn render_index_part(part: &IndexPart) -> String {
    match part {
        IndexPart::Literal { value } => {
            format!("IndexPart::Literal {{ value: {} }}", rust_lit(value))
        }
        IndexPart::Jid { name } => format!("IndexPart::Jid {{ name: {} }}", rust_lit(name)),
        IndexPart::BoolString { name } => {
            format!("IndexPart::BoolString {{ name: {} }}", rust_lit(name))
        }
        IndexPart::JidOrZero { name } => {
            format!("IndexPart::JidOrZero {{ name: {} }}", rust_lit(name))
        }
        IndexPart::Enum { name, proto_enum } => format!(
            "IndexPart::Enum {{ name: {}, proto_enum: {} }}",
            rust_lit(name),
            rust_lit(proto_enum)
        ),
        IndexPart::StringPart { name } => {
            format!("IndexPart::StringPart {{ name: {} }}", rust_lit(name))
        }
        IndexPart::Unknown { name } => format!("IndexPart::Unknown {{ name: {} }}", rust_lit(name)),
    }
}

fn render_collection_enum(collections: &[String]) -> String {
    let mut s = String::from(
        "/// A syncd collection (mutation bucket / priority).\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Collection {\n",
    );
    for c in collections {
        s.push_str(&format!("    {},\n", pascal_case(c)));
    }
    s.push_str("}\n\nimpl Collection {\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for c in collections {
        s.push_str(&format!(
            "            Collection::{} => {},\n",
            pascal_case(c),
            rust_lit(c)
        ));
    }
    s.push_str("        }\n    }\n}\n\n");
    s
}

fn render_scope_enum(scopes: &BTreeSet<&str>) -> String {
    let mut s = String::from(
        "/// The index scope an action applies to.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Scope {\n",
    );
    for sc in scopes {
        s.push_str(&format!("    {},\n", pascal_case(sc)));
    }
    s.push_str("}\n\nimpl Scope {\n    pub const fn as_str(self) -> &'static str {\n        match self {\n");
    for sc in scopes {
        s.push_str(&format!(
            "            Scope::{} => {},\n",
            pascal_case(sc),
            rust_lit(sc)
        ));
    }
    s.push_str("        }\n    }\n}\n\n");
    s
}

/// The fixed `IndexPart` discriminated union + `Schema` struct.
const INDEX_PART_AND_SCHEMA: &str = "\
/// One component of a mutation index key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexPart {
    /// Fixed wire name at position 0.
    Literal { value: &'static str },
    /// A WhatsApp JID (legacy-encoded).
    Jid { name: &'static str },
    /// '0' or '1' bool encoding.
    BoolString { name: &'static str },
    /// Participant slot: a JID, or '0' when fromMe/null.
    JidOrZero { name: &'static str },
    /// Stringified protobuf-enum integer; `proto_enum` is the dotted enum path.
    Enum { name: &'static str, proto_enum: &'static str },
    /// Opaque identifier (msg/label/agent id, etc.).
    StringPart { name: &'static str },
    /// Unrecognized slot.
    Unknown { name: &'static str },
}

/// A syncd action schema.
#[derive(Debug, Clone, Copy)]
pub struct Schema {
    /// Registry key (e.g. \"Agent\").
    pub key: &'static str,
    /// On-wire action name (e.g. \"deviceAgent\").
    pub name: &'static str,
    /// Source WA Web module.
    pub module: &'static str,
    pub collection: Collection,
    pub version: u32,
    pub scope: Scope,
    /// Field on `SyncActionValue` carrying the payload.
    pub value_field: Option<&'static str>,
    /// Dotted protobuf type of the value (in `waproto`).
    pub value_proto_type: Option<&'static str>,
    /// `(field, dotted enum path)` for enum-typed value fields.
    pub value_enum_fields: &'static [(&'static str, &'static str)],
    /// Index position holding the chat JID, if any.
    pub chat_jid_index: Option<i64>,
    pub index_parts: &'static [IndexPart],
}

";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wa_ir::AppstateAction;

    fn ir() -> AppstateIr {
        let mut actions = BTreeMap::new();
        actions.insert(
            "Agent".to_string(),
            AppstateAction {
                module: "WAWebAgentSync".into(),
                name: "deviceAgent".into(),
                collection: Some("regular".into()),
                version: Some(7),
                scope: "account".into(),
                base_class: "AccountSyncdActionBase".into(),
                value_field: Some("agentAction".into()),
                value_proto_type: Some("SyncActionValue.AgentAction".into()),
                value_enum_fields: None,
                chat_jid_index: None,
                index_parts: vec![
                    IndexPart::Literal {
                        value: "deviceAgent".into(),
                    },
                    IndexPart::StringPart {
                        name: "agentId".into(),
                    },
                ],
            },
        );
        actions.insert(
            "AvatarUpdated".to_string(),
            AppstateAction {
                module: "WAWebStickersAvatarUpdatedSyncAction".into(),
                name: "avatar_updated_action".into(),
                collection: Some("regular".into()),
                version: Some(7),
                scope: "account".into(),
                base_class: "AccountSyncdActionBase".into(),
                value_field: Some("avatarUpdatedAction".into()),
                value_proto_type: Some("SyncActionValue.AvatarUpdatedAction".into()),
                value_enum_fields: Some(
                    [(
                        "eventType".to_string(),
                        "AvatarUpdatedAction.AvatarEventType".to_string(),
                    )]
                    .into_iter()
                    .collect(),
                ),
                chat_jid_index: None,
                index_parts: vec![IndexPart::Literal {
                    value: "avatar_updated_action".into(),
                }],
            },
        );
        AppstateIr {
            wa_version: "2.3000.1".into(),
            collections: vec![
                "regular".into(),
                "regular_low".into(),
                "critical_block".into(),
            ],
            actions,
        }
    }

    #[test]
    fn emits_typed_registry() {
        let code = generate_appstate_schemas(&ir());
        assert!(code.contains("pub enum Collection {"));
        assert!(code.contains("Regular,") && code.contains("CriticalBlock,"));
        assert!(code.contains("pub enum Scope {") && code.contains("Account,"));
        assert!(code.contains("pub const COLLECTIONS: &[Collection] = &[Collection::Regular, Collection::RegularLow, Collection::CriticalBlock];"));
        // Agent const.
        assert!(code.contains("pub const AGENT: Schema = Schema {"));
        assert!(code.contains("name: \"deviceAgent\","));
        assert!(code.contains("collection: Collection::Regular,"));
        assert!(code.contains("version: 7,"));
        assert!(code.contains("scope: Scope::Account,"));
        assert!(code.contains("value_proto_type: Some(\"SyncActionValue.AgentAction\"),"));
        assert!(code.contains("IndexPart::Literal { value: \"deviceAgent\" }"));
        assert!(code.contains("IndexPart::StringPart { name: \"agentId\" }"));
        // Enum fields.
        assert!(code.contains(
            "value_enum_fields: &[(\"eventType\", \"AvatarUpdatedAction.AvatarEventType\")],"
        ));
        // Table + lookup.
        assert!(code.contains("pub const ALL: &[Schema] = &["));
        assert!(code.contains("    AGENT,") && code.contains("    AVATAR_UPDATED,"));
        assert!(code.contains("pub fn by_name(key: &str) -> Option<&'static Schema>"));
    }
}
