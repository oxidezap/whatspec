//! Emit the consumer-ready `tokens.json` from the token dictionary IR.
//!
//! This is the shape every known binary-protocol consumer reads — whatsapp-rust's
//! `build.rs` (`single_byte` / `double_byte`), matching the canonical whatsmeow /
//! Baileys layout. The IR is already canonicalized (leading empty single-byte
//! token, no dictionary offsets), so this is a straight re-serialization under the
//! consumer's `snake_case` keys.

use wa_ir::TokensIr;

/// Render `tokens.json`: `{ "single_byte": [...], "double_byte": [[...], ...] }`.
pub fn generate_tokens_json(ir: &TokensIr) -> String {
    let doc = serde_json::json!({
        "single_byte": ir.single_byte,
        "double_byte": ir.double_byte,
    });
    serde_json::to_string_pretty(&doc).expect("tokens.json serializes") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_single_and_double_byte_keys() {
        let ir = TokensIr {
            wa_version: "1.0".into(),
            dict_version: 3,
            single_byte: vec!["".into(), "xmlstreamstart".into()],
            double_byte: vec![vec!["read-self".into()], vec!["reject".into()]],
        };
        let out = generate_tokens_json(&ir);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        // Consumer keys are snake_case; dict_version is intentionally not emitted
        // (the consumer format carries only the two tables).
        assert_eq!(v["single_byte"][0], "");
        assert_eq!(v["single_byte"][1], "xmlstreamstart");
        assert_eq!(v["double_byte"][0][0], "read-self");
        assert_eq!(v["double_byte"][1][0], "reject");
        assert!(v.get("dict_version").is_none());
        assert!(out.ends_with('\n'));
    }
}
