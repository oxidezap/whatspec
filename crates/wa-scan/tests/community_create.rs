//! Minimal synthetic forms from WA 2.3000.1047483476, not session captures.
//! Original bundle 7783a694b3a8bc3a379585817de0e477c75729c73b21adbffbf060f5f0ac2860:
//! CreateRequest [28556,33576), parent approval mixin [28194,28554).
//! WASmaxMixins.optionalMerge tests `input != null`, not truthiness.
use wa_scan::extract_iq;

const SOURCE: &str = r#"
__d("WASmaxOutParentModeMixin",["WASmaxJsx","WASmaxMixins"],function(t,n,r,o,a,i,l){
 function e(){var e=o("WASmaxJsx").smax("parent",{default_membership_approval_mode:"request_required"});return e}
 function s(t){var n=e();return o("WASmaxMixins").mergeStanzas(t,n)}l.mergeParentModeMixin=s;
});
__d("WASmaxOutGroupsCreateRequest",["WASmaxJsx","WASmaxChildren","WASmaxMixins","WASmaxOutParentModeMixin"],function(t,n,r,o,a,i,l){
 function description(e){var t=e.bodyElementValue,n=o("WASmaxJsx").smax("description",null,o("WASmaxJsx").smax("body",null,t));return n}
 function parent(e){var t=e.hasMode,n=o("WASmaxMixins").optionalMerge(o("WASmaxOutParentModeMixin").mergeParentModeMixin,o("WASmaxJsx").smax("parent",null),t);return n}
 function unrelated(){var t=o("WASmaxJsx").smax("wrong",null);return t}
 function create(e){var n=e.parentArgs,r=e.descriptionArgs;return o("WASmaxJsx").smax("iq",{xmlns:"w:g2",type:"set",to:"g.us"},o("WASmaxJsx").smax("create",null,o("WASmaxChildren").OPTIONAL_CHILD(description,r),o("WASmaxChildren").OPTIONAL_CHILD(parent,n)))}l.makeCreateRequest=create;
});
"#;

/// Keep sibling locals out of Create while retaining nested optional-merge metadata.
#[test]
fn scoped_values_and_nested_optional_mixins_survive_extraction() {
    let ir = extract_iq(SOURCE, "test");
    let request = &ir
        .stanzas
        .iter()
        .find(|s| s.module_name == "WASmaxOutGroupsCreateRequest")
        .unwrap()
        .request;
    let children = &request.children[0].children;
    assert_eq!(
        children.iter().map(|c| c.tag.as_str()).collect::<Vec<_>>(),
        ["description", "parent"]
    );
    let body = &children[0].children[0];
    assert!(
        body.children.is_empty(),
        "a sibling's t must never become body content"
    );
    assert_eq!(
        body.content
            .as_ref()
            .unwrap()
            .arg_path
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.key.as_str())
            .collect::<Vec<_>>(),
        ["descriptionArgs", "bodyElementValue"]
    );
    let mode = &children[1].attrs[0];
    assert_eq!(mode.name, "default_membership_approval_mode");
    assert_eq!(mode.value.as_deref(), Some("request_required"));
    assert!(!mode.required);
    assert_eq!(
        serde_json::to_value(mode).unwrap()["presenceArgPath"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["parentArgs", "hasMode"]
    );
}

/// An inner guard rebased through its outer argument names both nullability checks.
#[test]
fn nested_optional_merge_preserves_the_rebased_inner_guard() {
    let source = r#"
__d("WASmaxOutInnerMixin",["WASmaxJsx"],function(t,n,r,o,a,i,l){
function merge(dst){return o("WASmaxMixins").mergeStanzas(dst,o("WASmaxJsx").smax("parent",{mode:"request_required"}))}l.mergeInnerMixin=merge;
});
__d("WASmaxOutOuterMixin",["WASmaxMixins","WASmaxJsx","WASmaxOutInnerMixin"],function(t,n,r,o,a,i,l){
function merge(dst,args){return o("WASmaxMixins").optionalMerge(o("WASmaxOutInnerMixin").mergeInnerMixin,dst,args.inner)}l.mergeOuterMixin=merge;
});
__d("WASmaxOutGroupsCreateRequest",["WASmaxJsx","WASmaxMixins","WASmaxOutOuterMixin"],function(t,n,r,o,a,i,l){
function create(args){return o("WASmaxJsx").smax("iq",{xmlns:"w:g2",type:"set"},o("WASmaxMixins").optionalMerge(o("WASmaxOutOuterMixin").mergeOuterMixin,o("WASmaxJsx").smax("parent",null),args.outer))}l.makeCreateRequest=create;
});"#;
    for (guard, expected) in [
        ("args.outer", vec!["outer", "inner"]),
        ("args", vec!["inner"]),
    ] {
        let source = source.replace("args.outer", guard);
        let ir = extract_iq(&source, "test");
        let attr = &ir
            .stanzas
            .iter()
            .find(|s| s.module_name == "WASmaxOutGroupsCreateRequest")
            .unwrap()
            .request
            .children[0]
            .attrs[0];
        assert!(!attr.required);
        assert_eq!(attr.name, "mode");
        let path = attr.presence_arg_path.as_ref().unwrap();
        assert_eq!(
            path.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(),
            expected
        );
    }
}

/// A module-wide alias collision must not erase the selected IQ's root target.
#[test]
fn root_attributes_use_the_selected_functions_aliases() {
    let source = r#"__d("WASmaxOutGroupsCreateRequest",["WAWap","Other"],function(t,n,r,o,a,i,l){
function unrelated(){var w=o("Other");return w.call()}
function create(args){var w=o("WAWap");return w.wap("iq",{xmlns:"w:g2",type:"set",to:w.S_WHATSAPP_NET})}l.makeCreateRequest=create;
});"#;
    let ir = extract_iq(source, "test");
    assert_eq!(ir.stanzas.len(), 1);
    assert_eq!(ir.stanzas[0].target, wa_ir::IqTarget::Server);
}

/// Paths of the three unqualified requests stay at merge-base 587a514's contract.
#[test]
fn shared_mixin_index_preserves_non_create_argument_paths() {
    /// Retain argument paths and their exact tree locations for baseline comparison.
    fn paths(value: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        let entries: Vec<_> = match value {
            Value::Object(map) => map
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if matches!(k.as_str(), "argPath" | "presenceArgPath" | "targetArgPath") {
                            v.clone()
                        } else {
                            paths(v)
                        },
                    )
                })
                .collect(),
            Value::Array(array) => array
                .iter()
                .enumerate()
                .map(|(i, v)| (i.to_string(), paths(v)))
                .collect(),
            _ => Vec::new(),
        };
        Value::Object(
            entries
                .into_iter()
                .filter(|(_, v)| v.as_object().is_none_or(|o| !o.is_empty()))
                .collect(),
        )
    }
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/non_create_argument_paths.json")).unwrap();
    let ir: serde_json::Value =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    for (module, baseline) in expected.as_object().unwrap() {
        let stanza = ir["stanzas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["moduleName"] == module.as_str())
            .unwrap();
        assert_eq!(
            paths(&stanza["request"]),
            *baseline,
            "unqualified contract changed: {module}"
        );
    }
}
