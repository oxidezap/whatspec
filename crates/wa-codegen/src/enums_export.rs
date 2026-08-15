//! Generate a reference Rust catalog of `$InternalEnum`s from the enums IR.
//!
//! One `pub mod <module>` per source module; within it, each enum is a
//! `pub const <NAME>: &[(&str, V)]` slice of `(variant, value)` pairs (`V` =
//! `i64` for code enums, `&str` for wire-string enums). A const table — rather
//! than a typed enum — is used because the catalog is large and auto-derived, so
//! arbitrary variant names can't produce invalid/ colliding Rust idents. The
//! cross-language contract is `enums/index.json`; this is the Rust reference.

use std::collections::{BTreeMap, HashSet};

use wa_ir::{EnumValueKind, EnumsIr, InternalEnumDef, Scalar};

use crate::naming::{snake_case, unique_ident};

/// Render the full `enums.rs` artifact.
pub fn generate_enums(ir: &EnumsIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated $InternalEnum catalog (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! One module per source module; each enum is a `(variant, value)` table.\n\n\
         #![allow(clippy::all)]\n",
        ir.wa_version
    ));

    // Group by source module (BTreeMap → deterministic module order).
    let mut by_mod: BTreeMap<&str, Vec<&InternalEnumDef>> = BTreeMap::new();
    for e in &ir.enums {
        by_mod.entry(e.module.as_str()).or_default().push(e);
    }

    let mut used_mods: HashSet<String> = HashSet::new();
    for (module, defs) in &by_mod {
        let mod_name = unique_ident(&snake_case(module), &mut used_mods, "m");
        out.push_str(&format!("\npub mod {mod_name} {{\n"));
        let mut used_consts: HashSet<String> = HashSet::new();
        for d in defs {
            let const_name =
                unique_ident(&snake_case(&d.name).to_uppercase(), &mut used_consts, "E");
            emit_enum(&mut out, d, &const_name);
        }
        out.push_str("}\n");
    }
    out
}

fn emit_enum(out: &mut String, d: &InternalEnumDef, const_name: &str) {
    // The value type (`i64` vs `&'static str`) already signals int-code vs
    // wire-string, so the const needs no doc comment beyond its name — except for the two
    // things the type cannot say.
    let ty = match d.value_kind {
        EnumValueKind::Int => "i64",
        EnumValueKind::String => "&'static str",
    };
    // A bit-position table looks exactly like a code table here: three `i64`s. Emitting
    // the raw value with nothing said would put back the ambiguity the IR flag removes —
    // `HID_FAILED_DECRYPT` is position 2 and reaches the wire as 4. The position is what
    // is published (shifting it here would contradict `enums/index.json`), so the note
    // carries the shift and a `_BITS` companion applies it.
    if d.bit_position {
        out.push_str(
            "    /// **Bit positions, not wire values**: a variant's value is the shift\n\
             \x20   /// distance, so what goes on the wire is `1 << value`. See the\n\
             \x20   /// `_BITS` table below for the masks.\n",
        );
    }
    if d.synthetic_name {
        out.push_str(
            "    /// The name is WA's build-generated one, spelled from the variants\n\
             \x20   /// themselves — not descriptive, and not unique across modules.\n",
        );
    }
    out.push_str(&format!(
        "    pub const {const_name}: &[(&str, {ty})] = &[\n"
    ));
    for v in &d.variants {
        let value = match (&d.value_kind, &v.value) {
            (EnumValueKind::Int, Scalar::Int(i)) => i.to_string(),
            (EnumValueKind::String, Scalar::Str(s)) => format!("{s:?}"),
            // Kind/value mismatch shouldn't occur (extractor guarantees it); skip.
            _ => continue,
        };
        out.push_str(&format!("        ({:?}, {value}),\n", v.name));
    }
    out.push_str("    ];\n");
    if d.bit_position {
        out.push_str(&format!(
            "    /// The same variants as `{const_name}`, with the shift applied — the\n\
             \x20   /// values that actually go on the wire. The client computes these with\n\
             \x20   /// JavaScript's 32-bit `1 << n`, so a position outside `0..=30` has no\n\
             \x20   /// distinct positive mask and is listed as a comment instead of a\n\
             \x20   /// number; `{const_name}` above still carries its position.\n\
             \x20   pub const {const_name}_BITS: &[(&str, i64)] = &[\n"
        ));
        for v in &d.variants {
            // The mask is whatever the CLIENT computes, and the client computes it in
            // JavaScript: `t |= 1 << ReceiptModeBitPosition.ORPHAN`, where `<<` is a
            // 32-bit SIGNED operation. So the arithmetic to mirror is not `1i64 << i`.
            // Past 30 that shift stops describing the client at all — JS gives
            // `1 << 31 === -2147483648` and `1 << 32 === 1`, wrapping the count mod 32,
            // so an i64 shift would publish a mask for a bit the client never sets (and
            // at 63 would hand back `i64::MIN`, a negative "mask", which `checked_shl`
            // does not catch because the shift COUNT is in range).
            //
            // The position comes from the bundle as a bare `i64` and nothing upstream
            // bounds it, so anything outside 0..=30 gets the note rather than a number.
            // The positions table above still carries the raw value: the fact is not
            // hidden, only the mask this generator cannot honestly derive.
            let Scalar::Int(i) = v.value else { continue };
            match i {
                0..=30 => out.push_str(&format!("        ({:?}, {}),\n", v.name, 1i64 << i)),
                _ => out.push_str(&format!(
                    "        // {:?}: position {i} is outside the 0..=30 a 32-bit `1 << n` \
                     gives a distinct positive mask for — see enums/index.json.\n",
                    v.name
                )),
            }
        }
        out.push_str("    ];\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::EnumVariant;

    fn def(
        module: &str,
        name: &str,
        kind: EnumValueKind,
        vs: &[(&str, Scalar)],
    ) -> InternalEnumDef {
        InternalEnumDef::new(
            name.into(),
            module.into(),
            kind,
            vs.iter()
                .map(|(n, v)| EnumVariant {
                    name: (*n).into(),
                    value: v.clone(),
                })
                .collect(),
        )
    }

    #[test]
    fn emits_module_grouped_const_tables() {
        let ir = EnumsIr {
            wa_version: "1.0".into(),
            enums: vec![
                def(
                    "WAWebChatType",
                    "ChatType",
                    EnumValueKind::String,
                    &[("INDIVIDUAL", Scalar::Str("individual".into()))],
                ),
                def(
                    "WAWebChatType",
                    "Codes",
                    EnumValueKind::Int,
                    &[("STALE", Scalar::Int(421))],
                ),
            ],
        };
        let code = generate_enums(&ir);
        assert!(code.contains("pub mod wa_web_chat_type {"));
        assert!(code.contains("pub const CHAT_TYPE: &[(&str, &'static str)]"));
        assert!(code.contains("(\"INDIVIDUAL\", \"individual\")"));
        assert!(code.contains("pub const CODES: &[(&str, i64)]"));
        assert!(code.contains("(\"STALE\", 421)"));
    }

    #[test]
    fn a_bit_position_table_carries_only_masks_the_client_computes() {
        let mut d = def(
            "M",
            "Bits",
            EnumValueKind::Int,
            &[
                ("LOW", Scalar::Int(0)),
                ("TOP", Scalar::Int(30)),
                // JS `1 << 31` is -2147483648 and `1 << 32` is 1: past 30 the client's
                // 32-bit shift stops producing a distinct positive mask, and 63 is where
                // an i64 shift silently hands back `i64::MIN` — a negative "mask" that
                // `checked_shl` accepts because the shift count itself is in range.
                ("SIGN", Scalar::Int(31)),
                ("WRAPS", Scalar::Int(32)),
                ("I64_SIGN", Scalar::Int(63)),
                ("ABSURD", Scalar::Int(9999)),
            ],
        );
        d.bit_position = true;
        let code = generate_enums(&EnumsIr {
            wa_version: "1.0".into(),
            enums: vec![d],
        });
        // The positions themselves are published either way — the bundle said them.
        for name in ["LOW", "TOP", "SIGN", "WRAPS", "I64_SIGN", "ABSURD"] {
            assert!(
                code.contains(&format!("({name:?}, ")) || code.contains(&format!("// {name:?}"))
            );
        }
        assert!(code.contains("pub const BITS_BITS: &[(&str, i64)]"));
        assert!(code.contains("(\"LOW\", 1),"));
        assert!(code.contains("(\"TOP\", 1073741824),"));
        // …but no mask is invented for a position the client's `<<` cannot express.
        for name in ["SIGN", "WRAPS", "I64_SIGN", "ABSURD"] {
            assert!(
                code.contains(&format!("// {name:?}: position")),
                "{name} must get the note, not a number"
            );
        }
        assert!(
            !code.contains("-2147483648") && !code.contains("-9223372036854775808"),
            "a negative mask is never published"
        );
    }

    #[test]
    fn dedups_colliding_const_names() {
        let ir = EnumsIr {
            wa_version: "1.0".into(),
            enums: vec![
                def("M", "Foo", EnumValueKind::Int, &[("A", Scalar::Int(1))]),
                def("M", "foo", EnumValueKind::Int, &[("B", Scalar::Int(2))]),
            ],
        };
        let code = generate_enums(&ir);
        assert!(code.contains("pub const FOO:"));
        assert!(code.contains("pub const FOO_2:"));
    }
}
