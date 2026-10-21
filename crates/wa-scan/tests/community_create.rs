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
