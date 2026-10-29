use std::{fs, process::Command};
mod support;

const MODULES: &[&str] = &[
    "WASmaxOutGroupsSetSubjectRequest",
    "WASmaxOutGroupsAcceptGroupAddRequest",
    "WASmaxOutGroupsJoinLinkedGroupRequest",
    "WASmaxOutGroupsDeleteParentGroupRequest",
    "WASmaxOutPassiveModeActiveIQRequest",
    "WASmaxOutMdGetCountryCodeRequest",
];

#[test]
fn isolated_web_parser_fixture_is_reproducible() {
    let result = Command::new("node")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/conformance/contextual/active-oracle.mjs"
        ))
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

fn selected() -> wa_ir::IqIr {
    let mut ir: wa_ir::IqIr =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    ir.stanzas
        .retain(|s| MODULES.contains(&s.module_name.as_str()));
    assert_eq!(ir.stanzas.len(), MODULES.len());
    ir
}

#[test]
fn checked_generation_rejects_lost_context_request_inputs_and_missing_outcomes() {
    let original = selected();
    assert!(wa_codegen::generate_iq_checked(&original).is_ok());
    for mutation in 0..6 {
        let mut ir = original.clone();
        let op = ir
            .stanzas
            .iter_mut()
            .find(|s| s.module_name.ends_with("SetSubjectRequest"))
            .unwrap();
        match mutation {
            0 => op.request.children[0].content.as_mut().unwrap().arg_path = None,
            1 => op.response.variants.clear(),
            2 => {
                op.response.variants[0]
                    .assertions
                    .iter_mut()
                    .find(|a| a.kind == wa_ir::AssertionKind::Reference)
                    .unwrap()
                    .reference_path = Some(vec!["unknown".into()])
            }
            3 => op.request.children[0].repeats = true,
            4 => op.request.target_arg_path = None,
            _ => op.request.children[0].attrs.push(serde_json::from_value(serde_json::json!({"name":"delete", "kind":"optional", "required":false, "value":"true", "argPath":[{"key":"deleteFlag"}]})).unwrap()),
        }
        let errors = wa_codegen::generate_iq_checked(&ir).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|d| d.module == op_name() && !d.reasons.is_empty())
        );
    }
    fn op_name() -> &'static str {
        "WASmaxOutGroupsSetSubjectRequest"
    }
    let all: wa_ir::IqIr =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    assert_eq!(wa_codegen::diagnose_iq_generation(&all).len(), 142);
    assert!(wa_codegen::generate_iq_checked(&all).is_err());
}

#[test]
fn contextual_trait_compiles_and_executes_representative_families() {
    let dir = std::env::temp_dir().join(format!("whatspec-contextual-iq-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("generated.rs"),
        wa_codegen::generate_iq_checked(&selected()).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("active-oracle.tsv"),
        include_str!("../../../tests/conformance/contextual/active-oracle.tsv"),
    )
    .unwrap();
    let adapter = include_str!("fixtures/iq_runtime.rs")
        .split_once("\nfn main() {")
        .unwrap()
        .0;
    fs::write(
        dir.join("main.rs"),
        format!(
            "{adapter}\n{}",
            include_str!("fixtures/contextual_iq_cases.rs")
        ),
    )
    .unwrap();
    let compiler = support::FixtureCompiler::build(&dir);
    let result = compiler.command(&dir, true).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(dir.join("run")).output().unwrap();
    assert!(
        result.status.success(),
        "{} {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    fs::remove_dir_all(dir).unwrap();
}
