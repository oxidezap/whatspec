//! End to end over the two operations from `oxidezap/whatsapp-rust#1372`.
//!
//! Both came back `400 Bad Request` from a consumer that had the right variable
//! names and the right types and sent a subset of the keys. The `.graphql`
//! modules here carry the real `argumentDefinitions` and the real persisted ids;
//! the job modules are the bundle's own call sites, copied as WA ships them
//! (`waVersion` 2.3000.1045368834) with only the logging tail trimmed. The point
//! of using the real text is that the verdicts below are a reading of WA Web
//! rather than of a fixture written to produce them.

use wa_ir::VariablePresence;

/// `WAWebMexFetchAllNewslettersMetadataJobQuery`, docId 25399611239711790, and
/// the job that sends it. Both variables are written through `=== !0`, which
/// coerces `undefined` to `false`: there is no path on which either key is
/// absent from the request.
const FETCH_ALL: &str = r#"
__d("WAWebMexFetchAllNewslettersMetadataJobQuery.graphql",[],(function(t,n,r,o,a,i){"use strict";var e=(function(){var e={defaultValue:null,kind:"LocalArgument",name:"fetch_status_metadata"},t={defaultValue:null,kind:"LocalArgument",name:"fetch_wamo_sub"},l=[{alias:null,args:null,concreteType:"XWA2Newsletter",kind:"LinkedField",name:"xwa2_newsletter_subscribed",plural:!0,selections:[{alias:null,args:null,kind:"ScalarField",name:"id",storageKey:null}],storageKey:null}];return{fragment:{argumentDefinitions:[e,t],kind:"Fragment",name:"WAWebMexFetchAllNewslettersMetadataJobQuery",selections:l,type:"Query"},kind:"Request",operation:{argumentDefinitions:[t,e],kind:"Operation",name:"WAWebMexFetchAllNewslettersMetadataJobQuery",selections:l},params:{id:"25399611239711790",metadata:{},name:"WAWebMexFetchAllNewslettersMetadataJobQuery",operationKind:"query",text:null}}})();a.exports=e}),null);
__d("WAWebMexFetchAllNewslettersMetadataJob",["WALogger","WAWebBackendErrors","WAWebMexClient","WAWebMexFetchAllNewslettersMetadataJobQuery.graphql","WAWebMexNewsletterParseUtils","WAWebNewsletterGatingUtils","asyncToGeneratorRuntime"],(function(t,n,r,o,a,i,l){var e,s;function u(e){return c.apply(this,arguments)}function c(){return c=n("asyncToGeneratorRuntime").asyncToGenerator(function*(t){var r=e!==void 0?e:e=n("WAWebMexFetchAllNewslettersMetadataJobQuery.graphql"),a=yield o("WAWebMexClient").fetchQuery(r,{fetch_wamo_sub:(t==null?void 0:t.fetchWamoSub)===!0,fetch_status_metadata:(t==null?void 0:t.fetchStatusMetadata)===!0});return a}),c.apply(this,arguments)}l.mexFetchAllNewsletters=u}),98);
"#;

/// `WAWebMexFetchNewsletterJobQuery`, docId 27456920720571478, and its job. Same
/// coercion on three of the flags, a local bound to a comparison on a fourth, a
/// bare property read on a fifth, and a gate read through a function call on the
/// sixth - one operation carrying every verdict the IR can give.
const FETCH_ONE: &str = r#"
__d("WAWebMexFetchNewsletterJobQuery.graphql",[],(function(t,n,r,o,a,i){"use strict";var e=(function(){var e={defaultValue:null,kind:"LocalArgument",name:"fetch_creation_time"},t={defaultValue:null,kind:"LocalArgument",name:"fetch_full_image"},n={defaultValue:null,kind:"LocalArgument",name:"fetch_pinned_messages"},r={defaultValue:null,kind:"LocalArgument",name:"fetch_status_metadata"},o={defaultValue:null,kind:"LocalArgument",name:"fetch_viewer_metadata"},a={defaultValue:null,kind:"LocalArgument",name:"fetch_wamo_sub"},i={defaultValue:null,kind:"LocalArgument",name:"input"},m=[{alias:null,args:null,concreteType:"XWA2Newsletter",kind:"LinkedField",name:"xwa2_newsletter",plural:!1,selections:[{alias:null,args:null,kind:"ScalarField",name:"id",storageKey:null}],storageKey:null}];return{fragment:{argumentDefinitions:[i,o,t,e,a,r,n],kind:"Fragment",name:"WAWebMexFetchNewsletterJobQuery",selections:m,type:"Query"},kind:"Request",operation:{argumentDefinitions:[i,o,t,e,a,r,n],kind:"Operation",name:"WAWebMexFetchNewsletterJobQuery",selections:m},params:{id:"27456920720571478",metadata:{},name:"WAWebMexFetchNewsletterJobQuery",operationKind:"query",text:null}}})();a.exports=e}),null);
__d("WAWebMexFetchNewsletterJob",["WALogger","WAWebMexClient","WAWebMexFetchNewsletterJobQuery.graphql","WAWebNewsletterPinGatingUtils","WAWebWid","asyncToGeneratorRuntime"],(function(t,n,r,o,a,i,l){var e,s;function u(e,t,n){return c.apply(this,arguments)}function c(){return c=n("asyncToGeneratorRuntime").asyncToGenerator(function*(t,a,i){var l=e!==void 0?e:e=n("WAWebMexFetchNewsletterJobQuery.graphql"),u=r("WAWebWid").isNewsletter(t)?"JID":"INVITE",c=u!=="INVITE",d={input:{key:t,type:u,view_role:a},fetch_viewer_metadata:i.fetchViewerMetadata,fetch_full_image:c,fetch_creation_time:i.fetchCreationTime===!0,fetch_wamo_sub:i.fetchWamoSub===!0,fetch_status_metadata:i.fetchStatusMetadata===!0,fetch_pinned_messages:o("WAWebNewsletterPinGatingUtils").isChannelMessagePinReadEnabled()},m=yield o("WAWebMexClient").fetchQuery(l,d);return m}),c.apply(this,arguments)}l.mexGetNewsletter=u}),98);
"#;

fn presence(source: &str, op: &str, key: &str) -> VariablePresence {
    let ir = wa_mex::extract_mex(source, "2.3000.1045368834");
    let operation = ir
        .operations
        .get(op)
        .unwrap_or_else(|| panic!("{op} not extracted from {:?}", ir.operations.keys()));
    operation
        .variables_presence
        .get(key)
        .unwrap_or_else(|| panic!("{op}.{key} carries no presence verdict"))
        .presence
}

#[test]
fn fetch_all_newsletters_metadata_always_sends_both_flags() {
    for key in ["fetch_wamo_sub", "fetch_status_metadata"] {
        assert_eq!(
            presence(FETCH_ALL, "FetchAllNewslettersMetadata", key),
            VariablePresence::Always,
            "{key} is written as `x === !0`, which coerces undefined to false"
        );
    }
    let ir = wa_mex::extract_mex(FETCH_ALL, "2.3000.1045368834");
    let op = &ir.operations["FetchAllNewslettersMetadata"];
    assert_eq!(op.doc_id, "25399611239711790");
    assert_eq!(op.variables_presence.len(), op.variables.len());
}

#[test]
fn fetch_newsletter_separates_the_three_verdicts() {
    let ir = wa_mex::extract_mex(FETCH_ONE, "2.3000.1045368834");
    let op = &ir.operations["FetchNewsletter"];
    assert_eq!(op.doc_id, "27456920720571478");

    for key in [
        "fetch_wamo_sub",
        "fetch_status_metadata",
        "fetch_creation_time",
    ] {
        assert_eq!(
            op.variables_presence[key].presence,
            VariablePresence::Always,
            "{key} is coerced with `=== !0`"
        );
    }
    assert_eq!(
        op.variables_presence["fetch_full_image"].presence,
        VariablePresence::Always,
        "bound to `u !== \"INVITE\"`, a comparison, which is always a boolean"
    );
    assert_eq!(
        op.variables_presence["fetch_viewer_metadata"].presence,
        VariablePresence::Conditional,
        "a bare read of `i.fetchViewerMetadata`, which JSON drops when undefined"
    );
    assert_eq!(
        op.variables_presence["fetch_pinned_messages"].presence,
        VariablePresence::Undetermined,
        "isChannelMessagePinReadEnabled() is a call - not read, and not evidence \
         that the client omits the key"
    );
}

#[test]
fn fetch_newsletter_answers_the_nested_input_keys() {
    let ir = wa_mex::extract_mex(FETCH_ONE, "2.3000.1045368834");
    let input = &ir.operations["FetchNewsletter"].variables_presence["input"];
    assert_eq!(
        input.presence,
        VariablePresence::Always,
        "the object literal itself is always written"
    );
    // Not all three: WA writes `{key: t, type: u, view_role: a}`, and only `type`
    // is bound to something that cannot be undefined.
    assert_eq!(
        input.fields["type"].presence,
        VariablePresence::Always,
        "bound to a ternary of two string literals"
    );
    assert_eq!(
        input.fields["key"].presence,
        VariablePresence::Conditional,
        "the job function's first parameter, passed straight through"
    );
    assert_eq!(
        input.fields["view_role"].presence,
        VariablePresence::Conditional,
        "the job function's second parameter, passed straight through"
    );
}

#[test]
fn every_typed_variable_carries_a_verdict() {
    // The two maps are siblings: a key with a type and no verdict is the silence
    // this whole dimension exists to remove.
    for source in [FETCH_ALL, FETCH_ONE] {
        let ir = wa_mex::extract_mex(source, "2.3000.1045368834");
        for (name, op) in &ir.operations {
            for key in op.variables_shape.keys() {
                assert!(
                    op.variables_presence.contains_key(key),
                    "{name}.{key} is typed but carries no presence verdict"
                );
            }
        }
    }
}
