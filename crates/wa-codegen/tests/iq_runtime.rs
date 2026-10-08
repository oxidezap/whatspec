//! Compile and execute the emitted pilot parsers against a small in-memory node
//! adapter. This checks generated Rust, not a binary codec or external client API.
use std::{fs, process::Command};

#[test]
fn generated_pilot_requests_and_responses_execute() {
    let mut ir: wa_ir::IqIr =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    ir.stanzas.retain(|op| {
        matches!(
            op.module_name.as_str(),
            "WASmaxOutGroupsSetSubjectRequest" | "WASmaxOutGroupsAcceptGroupAddRequest"
        )
    });
    assert_eq!(ir.stanzas.len(), 2);
    let subject = ir
        .stanzas
        .iter()
        .find(|o| o.module_name.contains("SetSubject"))
        .unwrap()
        .clone();
    // Constructed guard probes use the real pilot's fields and request shape;
    // they do not claim additional recovered protocol operations.
    for (name, context, content) in [
        ("GuardedPayload", true, false),
        ("GuardedPlain", false, false),
        ("GuardedContent", true, true),
    ] {
        let mut op = subject.clone();
        op.module_name = name.into();
        op.exported_function = Some(format!("make{name}"));
        op.response.fields = subject.response.variants[0].fields.clone();
        op.response.assertions = subject.response.variants[0].assertions.clone();
        if !context {
            op.response
                .assertions
                .retain(|a| a.kind != wa_ir::AssertionKind::Reference);
        }
        let guard = |kind, name: Option<&str>, value: Option<&str>| wa_ir::ResponseAssertion {
            kind,
            name: name.map(str::to_string),
            value: value.map(str::to_string),
            reference_path: None,
        };
        op.response
            .assertions
            .push(guard(wa_ir::AssertionKind::Attr, Some("marker"), None));
        op.response.assertions.push(guard(
            wa_ir::AssertionKind::Attr,
            Some("scope"),
            Some("group"),
        ));
        op.response.assertions.push(if content {
            guard(wa_ir::AssertionKind::Content, None, Some("accepted"))
        } else {
            guard(wa_ir::AssertionKind::Child, Some("proof"), None)
        });
        op.response.variants.clear();
        ir.stanzas.push(op);
    }
    let mut op = subject.clone();
    op.module_name = "PayloadCoverage".into();
    op.exported_function = Some("makePayloadCoverage".into());
    let original = &subject.response.variants[1];
    let original_payload = original
        .fields
        .iter()
        .find(|f| f.field_type == wa_ir::ParsedFieldType::Union)
        .unwrap();
    let optional_field = original_payload
        .union_variants
        .as_ref()
        .unwrap()
        .iter()
        .flat_map(|v| &v.fields)
        .find(|f| f.method == "child")
        .unwrap();
    op.response.variants = [
        ("LowError", 400, 449, true),
        ("HighError", 450, 499, true),
        ("FallbackError", 400, 499, false),
    ]
    .into_iter()
    .map(|(name, lo, hi, child)| {
        let mut v = original.clone();
        v.tag = name.into();
        let mut exact = v.error_arms[0].clone();
        exact.code = Some(lo);
        let mut range = v.error_arms.last().unwrap().clone();
        range.code_min = Some(lo);
        range.code_max = Some(hi);
        v.error_arms = vec![exact, range];
        let payload = v
            .fields
            .iter_mut()
            .find(|f| f.field_type == wa_ir::ParsedFieldType::Union)
            .unwrap();
        let variants = payload.union_variants.as_ref().unwrap();
        let mut exact = variants[0].clone();
        exact
            .fields
            .iter_mut()
            .find(|f| f.name == "code")
            .unwrap()
            .literal_value = Some(lo.to_string());
        exact
            .assertions
            .iter_mut()
            .find(|a| a.name.as_deref() == Some("code"))
            .unwrap()
            .value = Some(lo.to_string());
        let mut range = variants.last().unwrap().clone();
        let code = range.fields.iter_mut().find(|f| f.name == "code").unwrap();
        code.int_min = Some(lo);
        code.int_max = Some(hi);
        if child {
            exact.fields.push(optional_field.clone());
            range.fields.push(optional_field.clone());
        }
        payload.union_variants = Some(vec![exact, range]);
        v
    })
    .collect();
    ir.stanzas.push(op);

    let dir = std::env::temp_dir().join(format!("whatspec-iq-runtime-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("generated.rs"), wa_codegen::generate_iq(&ir)).unwrap();
    fs::write(dir.join("main.rs"), include_str!("fixtures/iq_runtime.rs")).unwrap();
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let anyhow = fs::read_dir(&deps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libanyhow-")
                && p.extension().is_some_and(|ext| ext == "rlib")
        })
        .expect("anyhow dev dependency rlib");
    let compile = Command::new("rustc")
        .arg("--edition=2024")
        .arg(dir.join("main.rs"))
        .arg("--extern")
        .arg(format!("anyhow={}", anyhow.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("-o")
        .arg(dir.join("run"))
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "generated pilot compilation failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(dir.join("run")).output().unwrap();
    assert!(
        run.status.success(),
        "generated pilot execution failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    fs::remove_dir_all(dir).unwrap();
}
