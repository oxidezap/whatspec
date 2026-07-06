//! Render a [`ProtoFile`] to `.proto` text: 2-space indent,
//! `flags type name = id [packed = true];`, top-level entities sorted by name, a
//! blank line after each message (none after an enum), and the
//! `syntax`/`package`/version header. Output is `buf format`-canonical (empty
//! blank lines, no blank before a closing brace, empty messages collapsed to
//! `{}`), so running `buf` over it is a no-op.

use wa_ir::{ProtoEntity, ProtoEnum, ProtoField, ProtoFile, ProtoMember, ProtoMessage};

const INDENT: &str = "  ";

/// Render a full `.proto` file.
pub fn stringify(file: &ProtoFile) -> String {
    let mut entities: Vec<&ProtoEntity> = file.entities.iter().collect();
    entities.sort_by(|a, b| a.name().cmp(b.name()));

    let body = entities
        .iter()
        .map(|e| entity_lines(e).join("\n"))
        .collect::<Vec<_>>()
        .join("\n");

    // proto2, not proto3: WhatsApp's schemas use `required` fields, explicit
    // `optional`/`repeated` labels, and enums whose first value is not zero — all
    // of which protoc rejects under proto3. The `whatsapp` package matches the
    // upstream reference, so consumers (e.g. whatsapp-rust) drop the file in as-is.
    format!(
        "syntax = \"proto2\";\npackage whatsapp;\n\n/// WhatsApp Version: {}\n\n{}",
        file.wa_version, body
    )
}

fn entity_lines(e: &ProtoEntity) -> Vec<String> {
    match e {
        ProtoEntity::Enum(en) => enum_lines(en),
        ProtoEntity::Message(m) => message_lines(m),
    }
}

fn enum_lines(e: &ProtoEnum) -> Vec<String> {
    let mut out = vec![format!("enum {} {{", e.name)];
    for v in &e.values {
        out.push(format!("{INDENT}{} = {};", v.name, v.id));
    }
    out.push("}".to_string());
    out
}

fn message_lines(m: &ProtoMessage) -> Vec<String> {
    // An empty message collapses onto a single line, matching `buf format`.
    if m.members.is_empty() && m.nested.is_empty() {
        return vec![format!("message {} {{}}", m.name), String::new()];
    }
    let mut out = vec![format!("message {} {{", m.name)];
    for member in &m.members {
        out.extend(indent(member_lines(member)));
    }
    for nested in &m.nested {
        out.extend(indent(entity_lines(nested)));
    }
    // A nested message carries its own trailing blank (the separator between
    // siblings); drop it here so there is no blank line before the closing brace.
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.push("}".to_string());
    out.push(String::new()); // blank line separating this message from the next

    out
}

fn member_lines(member: &ProtoMember) -> Vec<String> {
    match member {
        ProtoMember::Field(f) => vec![field_line(f)],
        ProtoMember::OneOf(o) => {
            let mut out = vec![format!("oneof {} {{", o.name)];
            for f in &o.fields {
                out.push(format!("{INDENT}{}", field_line(f)));
            }
            out.push("}".to_string());
            out
        }
    }
}

fn field_line(f: &ProtoField) -> String {
    let flags = f.flags.join(" ");
    let sep = if f.flags.is_empty() { "" } else { " " };
    let mut opts: Vec<String> = Vec::new();
    if f.packed {
        opts.push("packed = true".to_string());
    }
    if let Some(d) = &f.default {
        // A proto2 `string`/`bytes` default is a quoted string literal; enum/bool/numeric
        // defaults are bare. (No WA field currently has a bytes default, but quoting it
        // keeps a future one valid rather than emitting `[default = x]` that protoc rejects.)
        // (packed and default never co-occur — packed is for repeated scalars, defaults
        // for singular optionals — but the joined-options form handles either alone.)
        if f.type_name == "string" || f.type_name == "bytes" {
            opts.push(format!("default = \"{d}\""));
        } else {
            opts.push(format!("default = {d}"));
        }
    }
    let options = if opts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", opts.join(", "))
    };
    format!(
        "{flags}{sep}{} {} = {}{options};",
        f.type_name, f.name, f.id
    )
}

/// Prefix every non-empty line with one indent level. Blank lines stay empty
/// (no trailing whitespace), matching `buf format`.
fn indent(lines: Vec<String>) -> Vec<String> {
    lines
        .into_iter()
        .map(|l| {
            if l.is_empty() {
                l
            } else {
                format!("{INDENT}{l}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{ProtoEnumValue, ProtoOneOf};

    fn field(name: &str, ftype: &str, id: i64, flags: &[&str], packed: bool) -> ProtoMember {
        ProtoMember::Field(ProtoField {
            name: name.to_string(),
            id,
            type_name: ftype.to_string(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
            packed,
            default: None,
        })
    }

    #[test]
    fn emits_proto2_defaults() {
        fn defaulted(name: &str, ftype: &str, id: i64, default: &str) -> ProtoMember {
            ProtoMember::Field(ProtoField {
                name: name.to_string(),
                id,
                type_name: ftype.to_string(),
                flags: vec!["optional".to_string()],
                packed: false,
                default: Some(default.to_string()),
            })
        }
        let file = ProtoFile {
            wa_version: "1".to_string(),
            entities: vec![ProtoEntity::Message(ProtoMessage {
                name: "M".to_string(),
                members: vec![
                    defaulted("accountType", "ADVEncryptionType", 1, "E2EE"),
                    defaulted("count", "int32", 2, "1"),
                    defaulted("flag", "bool", 3, "false"),
                    defaulted("label", "string", 4, "hi"),
                ],
                nested: vec![],
            })],
        };
        let out = stringify(&file);
        // enum / int / bool defaults are bare; a `string` default is quoted.
        assert!(
            out.contains("optional ADVEncryptionType accountType = 1 [default = E2EE];"),
            "{out}"
        );
        assert!(
            out.contains("optional int32 count = 2 [default = 1];"),
            "{out}"
        );
        assert!(
            out.contains("optional bool flag = 3 [default = false];"),
            "{out}"
        );
        assert!(
            out.contains(r#"optional string label = 4 [default = "hi"];"#),
            "{out}"
        );
    }

    #[test]
    fn matches_adv_snippet() {
        // Hand-built IR for the ADV* head of a real WAProto.proto.
        let file = ProtoFile {
            wa_version: "2.3000.1040225260".to_string(),
            entities: vec![
                ProtoEntity::Message(ProtoMessage {
                    name: "ADVDeviceIdentity".to_string(),
                    members: vec![
                        field("rawId", "uint32", 1, &["optional"], false),
                        field("timestamp", "uint64", 2, &["optional"], false),
                        field("keyIndex", "uint32", 3, &["optional"], false),
                        field("accountType", "ADVEncryptionType", 4, &["optional"], false),
                        field("deviceType", "ADVEncryptionType", 5, &["optional"], false),
                    ],
                    nested: vec![],
                }),
                ProtoEntity::Enum(ProtoEnum {
                    name: "ADVEncryptionType".to_string(),
                    values: vec![
                        ProtoEnumValue {
                            name: "E2EE".to_string(),
                            id: 0,
                        },
                        ProtoEnumValue {
                            name: "HOSTED".to_string(),
                            id: 1,
                        },
                        ProtoEnumValue {
                            name: "NON_E2EE".to_string(),
                            id: 2,
                        },
                    ],
                }),
                ProtoEntity::Message(ProtoMessage {
                    name: "ADVKeyIndexList".to_string(),
                    members: vec![
                        field("rawId", "uint32", 1, &["optional"], false),
                        field("timestamp", "uint64", 2, &["optional"], false),
                        field("currentIndex", "uint32", 3, &["optional"], false),
                        field("validIndexes", "uint32", 4, &["repeated"], true),
                        field("accountType", "ADVEncryptionType", 5, &["optional"], false),
                    ],
                    nested: vec![],
                }),
            ],
        };

        let expected = "syntax = \"proto2\";\npackage whatsapp;\n\n/// WhatsApp Version: 2.3000.1040225260\n\n\
message ADVDeviceIdentity {\n\
\x20 optional uint32 rawId = 1;\n\
\x20 optional uint64 timestamp = 2;\n\
\x20 optional uint32 keyIndex = 3;\n\
\x20 optional ADVEncryptionType accountType = 4;\n\
\x20 optional ADVEncryptionType deviceType = 5;\n\
}\n\
\n\
enum ADVEncryptionType {\n\
\x20 E2EE = 0;\n\
\x20 HOSTED = 1;\n\
\x20 NON_E2EE = 2;\n\
}\n\
message ADVKeyIndexList {\n\
\x20 optional uint32 rawId = 1;\n\
\x20 optional uint64 timestamp = 2;\n\
\x20 optional uint32 currentIndex = 3;\n\
\x20 repeated uint32 validIndexes = 4 [packed = true];\n\
\x20 optional ADVEncryptionType accountType = 5;\n\
}\n";

        assert_eq!(stringify(&file), expected);
    }

    #[test]
    fn oneof_and_nested_and_map() {
        let file = ProtoFile {
            wa_version: "2.3000.1".to_string(),
            entities: vec![ProtoEntity::Message(ProtoMessage {
                name: "Outer".to_string(),
                members: vec![
                    ProtoMember::OneOf(ProtoOneOf {
                        name: "body".to_string(),
                        fields: vec![
                            ProtoField {
                                name: "text".to_string(),
                                id: 1,
                                type_name: "string".to_string(),
                                flags: vec![],
                                packed: false,
                                default: None,
                            },
                            ProtoField {
                                name: "num".to_string(),
                                id: 2,
                                type_name: "int32".to_string(),
                                flags: vec![],
                                packed: false,
                                default: None,
                            },
                        ],
                    }),
                    field("labels", "map<string, string>", 3, &[], false),
                    field("inner", "Outer.Inner", 4, &["optional"], false),
                ],
                nested: vec![ProtoEntity::Message(ProtoMessage {
                    name: "Inner".to_string(),
                    members: vec![field("x", "uint32", 1, &["optional"], false)],
                    nested: vec![],
                })],
            })],
        };

        let out = stringify(&file);
        assert!(out.contains("  oneof body {\n    string text = 1;\n    int32 num = 2;\n  }\n"));
        assert!(out.contains("  map<string, string> labels = 3;\n"));
        assert!(out.contains("  optional Outer.Inner inner = 4;\n"));
        // Nested message is indented one level inside Outer.
        assert!(out.contains("  message Inner {\n    optional uint32 x = 1;\n  }\n"));
    }

    #[test]
    fn buf_canonical_blank_lines_and_empty_messages() {
        let file = ProtoFile {
            wa_version: "2.3000.1".to_string(),
            entities: vec![ProtoEntity::Message(ProtoMessage {
                name: "Outer".to_string(),
                members: vec![field("id", "uint32", 1, &["optional"], false)],
                nested: vec![
                    ProtoEntity::Message(ProtoMessage {
                        name: "Empty".to_string(),
                        members: vec![],
                        nested: vec![],
                    }),
                    ProtoEntity::Message(ProtoMessage {
                        name: "Inner".to_string(),
                        members: vec![field("x", "uint32", 1, &["optional"], false)],
                        nested: vec![],
                    }),
                ],
            })],
        };
        let out = stringify(&file);
        // Empty message collapses onto one line.
        assert!(out.contains("  message Empty {}\n"));
        // No indented "blank" line (trailing whitespace) anywhere.
        assert!(!out.contains("\n  \n"));
        // No blank line immediately before a closing brace.
        assert!(!out.contains("\n\n}"));
        // Sibling nested messages are still separated by a (truly empty) blank line.
        assert!(out.contains("  message Empty {}\n\n  message Inner {"));
    }
}
