//! In-place refresh of a hand-curated `mex_ids.rs` registry.
//!
//! whatsapp-rust keeps `MexDoc { name, id }` constants with human-chosen const
//! names and module grouping; only the numeric `id` rotates with each WA Web
//! release. This rewrites those ids by matching the stable `name` against the
//! freshly-extracted mex index, preserving every other byte (names, grouping,
//! comments, tests), and reports stale entries whose `name` no longer exists in
//! the bundle (upstream renamed/removed them).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use wa_ir::MexIr;

/// `name: "...", id: "..."` inside a `MexDoc` literal (whitespace/newline
/// tolerant, so `buf fmt`-style reflow doesn't matter).
static MEX_DOC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"name:\s*"(?P<name>[^"]+)"\s*,\s*id:\s*"(?P<id>[^"]+)""#).unwrap()
});

/// Outcome of refreshing a `mex_ids.rs` against a fresh [`MexIr`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MexIdRefresh {
    /// The rewritten file content.
    pub updated_source: String,
    /// `(name, old_id, new_id)` for entries whose id changed.
    pub changed: Vec<(String, String, String)>,
    /// Names already current.
    pub unchanged: Vec<String>,
    /// Names present in the file but absent from the current bundle (stale —
    /// the operation was renamed or removed upstream; a human must remap them).
    pub stale: Vec<String>,
    /// Count of operations in the bundle not referenced by the registry.
    pub available_unused: usize,
}

/// Rewrite the `id` of every `MexDoc` in `existing` from `ir`, matching by the
/// stable `name`. Unknown names are left untouched and reported as `stale`.
pub fn refresh_mex_ids(existing: &str, ir: &MexIr) -> MexIdRefresh {
    // originalName → docId for the current bundle.
    let by_name: BTreeMap<&str, &str> = ir
        .operations
        .values()
        .map(|op| (op.original_name.as_str(), op.doc_id.as_str()))
        .collect();

    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    let mut stale = Vec::new();
    let mut referenced: Vec<String> = Vec::new();

    let updated_source = MEX_DOC
        .replace_all(existing, |caps: &regex::Captures| {
            let name = caps.name("name").unwrap().as_str();
            let old_id = caps.name("id").unwrap().as_str();
            referenced.push(name.to_string());
            match by_name.get(name) {
                Some(&new_id) => {
                    if new_id == old_id {
                        unchanged.push(name.to_string());
                    } else {
                        changed.push((name.to_string(), old_id.to_string(), new_id.to_string()));
                    }
                    rebuild_doc(&caps[0], old_id, new_id)
                }
                None => {
                    stale.push(name.to_string());
                    caps[0].to_string()
                }
            }
        })
        .into_owned();

    let available_unused = by_name
        .keys()
        .filter(|n| !referenced.iter().any(|r| r == *n))
        .count();

    MexIdRefresh {
        updated_source,
        changed,
        unchanged,
        stale,
        available_unused,
    }
}

/// Swap only the quoted `id` value inside a captured `name:.., id:".."` slice,
/// preserving every other byte (spacing included).
fn rebuild_doc(matched: &str, old_id: &str, new_id: &str) -> String {
    let id_pos = matched.rfind("id:").expect("matched contains id:");
    let (head, tail) = matched.split_at(id_pos);
    let new_tail = tail.replacen(&format!("\"{old_id}\""), &format!("\"{new_id}\""), 1);
    format!("{head}{new_tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wa_ir::{MexOperation, MexOperationKind};

    fn ir(pairs: &[(&str, &str)]) -> MexIr {
        let mut operations = BTreeMap::new();
        for (i, (orig, id)) in pairs.iter().enumerate() {
            operations.insert(
                format!("k{i}"),
                MexOperation {
                    original_name: (*orig).to_string(),
                    doc_id: (*id).to_string(),
                    operation_kind: MexOperationKind::Query,
                    variables: vec![],
                    variables_shape: Default::default(),
                    response: Default::default(),
                },
            );
        }
        MexIr {
            wa_version: "2.3000.1".into(),
            operations,
        }
    }

    const SRC: &str = r#"
    pub const A: MexDoc = MexDoc {
        name: "WAWebMexAJobQuery",
        id: "111",
    };
    pub const B: MexDoc = MexDoc { name: "WAWebMexBJobMutation", id: "222" };
"#;

    #[test]
    fn refreshes_changed_keeps_unchanged_flags_stale() {
        // A's id rotated; B is gone from the bundle; a third op is unused.
        let ir = ir(&[("WAWebMexAJobQuery", "999"), ("WAWebMexCJobQuery", "333")]);
        let r = refresh_mex_ids(SRC, &ir);

        assert_eq!(
            r.changed,
            vec![("WAWebMexAJobQuery".into(), "111".into(), "999".into())]
        );
        assert_eq!(r.stale, vec!["WAWebMexBJobMutation".to_string()]);
        assert!(r.unchanged.is_empty());
        assert_eq!(r.available_unused, 1); // C is in the bundle but unreferenced

        // A's id rewritten, B left intact, multi-line + single-line both handled.
        assert!(r.updated_source.contains("id: \"999\""));
        assert!(
            r.updated_source
                .contains(r#"name: "WAWebMexBJobMutation", id: "222""#)
        );
        assert!(!r.updated_source.contains("\"111\""));
        // Const names / structure preserved.
        assert!(r.updated_source.contains("pub const A: MexDoc"));
    }

    #[test]
    fn unchanged_id_is_byte_identical() {
        let ir = ir(&[
            ("WAWebMexAJobQuery", "111"),
            ("WAWebMexBJobMutation", "222"),
        ]);
        let r = refresh_mex_ids(SRC, &ir);
        assert_eq!(r.updated_source, SRC, "no rotation → no rewrite");
        assert_eq!(r.unchanged.len(), 2);
        assert!(r.changed.is_empty() && r.stale.is_empty());
    }
}
