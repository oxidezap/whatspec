//! Compile and execute the emitted pilot parsers against a small in-memory node
//! adapter. This checks generated Rust, not a binary codec or external client API.
use std::{fs, process::Command};
mod support;

/// Compile and execute generated request and response contracts against wire assertions.
#[test]
fn generated_pilot_requests_and_responses_execute() {
    let mut ir: wa_ir::IqIr =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    let upstream_create = ir
        .stanzas
        .iter()
        .find(|s| s.module_name == "WASmaxOutGroupsCreateRequest")
        .unwrap()
        .request
        .children[0]
        .clone();
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

    // A nullability choice is independent of the constant's wire value. Two
    // attributes supplied by one mixin must share its presence argument.
    let mut op = subject.clone();
    op.module_name = "NullableParent".into();
    op.exported_function = Some("makeNullableParent".into());
    op.target = wa_ir::IqTarget::GroupServer;
    op.request.target = wa_ir::IqTarget::GroupServer;
    op.request.target_arg_path = None;
    op.response = Default::default();
    op.request.children = serde_json::from_value(serde_json::json!([{
        "tag":"create", "repeats":false,
        "attrs":[{"name":"subject","kind":"const","required":true,"value":"Fixture community"}],
        "children":[]
    }]))
    .unwrap();
    op.request.children[0]
        .attrs
        .extend(upstream_create.attrs.clone());
    op.request.children[0].children.push(
        upstream_create
            .children
            .iter()
            .find(|c| c.tag == "parent")
            .cloned()
            .unwrap(),
    );
    ir.stanzas.push(op);

    let mut op = subject.clone();
    op.module_name = "OptionalChildren".into();
    op.exported_function = Some("makeOptionalChildren".into());
    op.response = Default::default();
    op.target = wa_ir::IqTarget::GroupServer;
    op.request.target = wa_ir::IqTarget::GroupServer;
    op.request.target_arg_path = None;
    let children = ["privacy", "member_add_mode", "locked"].map(|tag| {
        upstream_create
            .children
            .iter()
            .chain(upstream_create.children.iter().flat_map(|c| &c.children))
            .find(|c| c.tag == tag)
            .unwrap()
            .clone()
    });
    op.request.children = vec![wa_ir::WapChildNode {
        tag: "create".into(),
        children: children.into(),
        ..Default::default()
    }];
    ir.stanzas.push(op);

    let dir = std::env::temp_dir().join(format!("whatspec-iq-runtime-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let generated = wa_codegen::generate_iq(&ir);
    assert!(generated.contains(
        "pub parent_args_has_parent_group_default_membership_approval_mode_present: Option<bool>"
    ));
    assert_eq!(
        generated
            .matches("pub dedup_attrs_mixin_args_present: Option<bool>")
            .count(),
        1
    );
    fs::write(dir.join("generated.rs"), generated).unwrap();
    fs::write(dir.join("main.rs"), include_str!("fixtures/iq_runtime.rs")).unwrap();
    let compiler = support::FixtureCompiler::build(&dir);
    let compile = compiler.command(&dir, false).output().unwrap();
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
