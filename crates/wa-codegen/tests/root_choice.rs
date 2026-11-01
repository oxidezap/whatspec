use std::{fs, process::Command};
mod support;
#[test]
fn root_choice_emits_exactly_one_payload_child() {
    let ir: wa_ir::IqIr = serde_json::from_value(serde_json::json!({
        "schemaVersion":"4.5.0","waVersion":"test","unparseable":[],"stanzas":[{
            "moduleName":"WASmaxRootRPC","namespace":"w:g2","iqType":"set","target":"s.whatsapp.net","parserName":"probe","exportedFunction":"makeRootRequest","allExports":[],
            "request":{"namespace":"w:g2","iqType":"set","target":"s.whatsapp.net","children":[],"variantGroups":[{"optional":false,"variants":[{"attrs":[],"children":[{"tag":"config","attrs":[],"children":[],"repeats":false}]},{"attrs":[],"children":[{"tag":"clear","attrs":[],"children":[],"repeats":false}]}]}]},
            "response":{"parserName":"probe","assertions":[],"fields":[]}
        }]
    })).unwrap();
    let dir = std::env::temp_dir().join(format!("whatspec-root-choice-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("generated.rs"), wa_codegen::generate_iq(&ir)).unwrap();
    let adapter = include_str!("fixtures/iq_runtime.rs")
        .split_once("\nfn main() {")
        .unwrap()
        .0;
    fs::write(dir.join("main.rs"), format!("{adapter}\n{}", r#"
fn main() {
    let cases = [
        (MakeRootRequestIqPayloadVariant::Variant1 { config: MakeRootRequestIqPayloadVariantVariant1Config {} }, "config"),
        (MakeRootRequestIqPayloadVariant::Variant2 { clear: MakeRootRequestIqPayloadVariantVariant2Clear {} }, "clear"),
    ];
    let mut checked = 0;
    for (choice, expected) in cases {
        let query = MakeRootRequestSpec::new(choice).build_iq();
        let node::NodeContent::Nodes(children) = query.content.unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, expected);
        checked += 1;
    }
    println!("root-choice cases: {checked}");
}
"#)).unwrap();
    let compiler = support::FixtureCompiler::build(&dir);
    let compile = compiler.command(&dir, false).output().unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(dir.join("run")).output().unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        String::from_utf8(run.stdout).unwrap(),
        "root-choice cases: 2\n"
    );
    fs::remove_dir_all(dir).unwrap();
}
