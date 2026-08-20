use super::*;
use wa_ir::{WamCallSiteValue, WamFieldWrite};

fn run(src: &str) -> WamIr {
    run_full(src).0
}

fn run_full(src: &str) -> (WamIr, WamDiagnostics) {
    let defs = wa_transform::extract_module_definitions(src);
    extract_wam_from_modules(src, &defs, "1.0")
}

#[test]
fn extracts_event_with_base_and_enum_fields() {
    // Mirrors the real AppLaunch shape: code, fields {name:[id,type]}, weights, channel.
    let src = r#"
__d("WAWebWamEnumAppLaunchType",[],(function(t,n,r,o,a,i){var e=Object.freeze({COLD:1,WARM:2,LUKEWARM:3});i.APP_LAUNCH_TYPE=e}),66);
__d("WAWebAppLaunchWamEvent",["WAWebWamCodegenUtils","WAWebWamEnumAppLaunchType"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils"),s=e.defineEvents({AppLaunch:[1094,{
    appContext:[22,e.TYPES.STRING],
    appLaunchT:[1,e.TYPES.TIMER],
    dbReadsCount:[8,e.TYPES.INTEGER],
    lowPowerModeEnabled:[12,e.TYPES.BOOLEAN],
    appLaunchTypeT:[5,o("WAWebWamEnumAppLaunchType").APP_LAUNCH_TYPE]
  },[1,1,1],"regular"]},{AppLaunch:[]});
  l.AppLaunchWamEvent=s
}),98);
__d("WAWebWamAppLaunchReporter",["WAWebAppLaunchWamEvent"],(function(t,n,r,o,a,i,l){}),1);
"#;
    let ir = run(src);
    assert_eq!(ir.events.len(), 1);
    let ev = &ir.events[0];
    assert_eq!(ev.name, "AppLaunch");
    assert_eq!(ev.code, 1094);
    assert_eq!(ev.channel, "regular");
    assert_eq!(ev.weights, vec![1, 1, 1]);
    assert_eq!(ev.private_stats_id, None);
    assert_eq!(ev.module, "WAWebAppLaunchWamEvent");

    // Fields in source order, ids + types resolved.
    let f = |n: &str| ev.fields.iter().find(|f| f.name == n).unwrap();
    assert_eq!(f("appContext").id, 22);
    assert_eq!(f("appContext").field_type, WamFieldType::String);
    assert_eq!(f("appLaunchT").field_type, WamFieldType::Timer);
    assert_eq!(f("dbReadsCount").field_type, WamFieldType::Integer);
    assert_eq!(f("lowPowerModeEnabled").field_type, WamFieldType::Boolean);
    assert_eq!(
        f("appLaunchTypeT").field_type,
        WamFieldType::Enum {
            module: "WAWebWamEnumAppLaunchType".into()
        }
    );

    // The referenced enum is resolved (and only that one).
    assert_eq!(ir.enums.len(), 1);
    let en = &ir.enums[0];
    assert_eq!(en.module, "WAWebWamEnumAppLaunchType");
    assert_eq!(en.name, "APP_LAUNCH_TYPE");
    assert_eq!(en.variants.len(), 3);
    assert_eq!(en.variants[0].key, "COLD");
    assert_eq!(en.variants[0].value, 1);

    // The dep graph: the reporter module that imports the event module. It says
    // nothing about emission, which is what `call_sites` is for.
    assert_eq!(ev.consumers, vec!["WAWebWamAppLaunchReporter".to_string()]);
    assert!(
        ev.call_sites.is_empty(),
        "a module that only imports the event constructs nothing"
    );
}

#[test]
fn channel_and_private_stats_id_defaults_and_overrides() {
    let src = r#"
__d("WAWebPrivXWamEvent",["WAWebWamCodegenUtils"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.X=e.defineEvents({PrivX:[7,{a:[1,e.TYPES.INTEGER]},[1,1,1],"private",42]},{PrivX:[]})
}),1);
__d("WAWebDefXWamEvent",["WAWebWamCodegenUtils"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.X=e.defineEvents({DefX:[8,{b:[1,e.TYPES.STRING]},[1,1,1]]},{DefX:[]})
}),2);
"#;
    let ir = run(src);
    let priv_x = ir.events.iter().find(|e| e.name == "PrivX").unwrap();
    assert_eq!(priv_x.channel, "private");
    assert_eq!(priv_x.private_stats_id, Some(42));
    let def_x = ir.events.iter().find(|e| e.name == "DefX").unwrap();
    assert_eq!(def_x.channel, "regular"); // default
    assert_eq!(def_x.private_stats_id, None);
}

#[test]
fn non_wam_module_and_unreferenced_enum_ignored() {
    // A WamEvent without the codegen dep is skipped; an enum no field references
    // is NOT emitted (the IR carries only referenced enums).
    let src = r#"
__d("WAWebWamEnumUnused",[],(function(t,n,r,o,a,i){i.UNUSED=Object.freeze({A:1})}),1);
__d("WAWebFakeWamEvent",["SomethingElse"],(function(t,n,r,o,a,i,l){
  var e=o("SomethingElse");l.X=e.defineEvents({Fake:[1,{a:[1,e.TYPES.INTEGER]},[1]]},{})
}),2);
"#;
    let ir = run(src);
    assert!(ir.events.is_empty(), "no codegen dep → not a WAM event");
    assert!(ir.enums.is_empty(), "unreferenced enum not emitted");
}

/// The real `WAWebWamGlobals` shape, trimmed to the two globals whose channel lists
/// disagree, plus one that omits the list entirely.
const GLOBALS_SRC: &str = r#"
__d("WAWebWamEnumAppBuildType",[],(function(t,n,r,o,a,i){i.APP_BUILD_TYPE=Object.freeze({RELEASE:1})}),1);
__d("WAWebWamGlobals",["WAWebWamCodegenUtils","WAWebWamEnumAppBuildType"],(function(t,n,r,o,a,i,l){
  var e,s=(e=o("WAWebWamCodegenUtils")).defineGlobal({
    abKey2:[4473,e.TYPES.STRING,["regular"]],
    appBuild:[1657,o("WAWebWamEnumAppBuildType").APP_BUILD_TYPE,["regular","private"]],
    psId:[6005,e.TYPES.STRING,["private"]],
    legacyKey:[99,e.TYPES.INTEGER]
  }),u=[{key:"DefaultPsId",keyHashInt:113760892,rotationPeriodDays:-1},
        {key:"IdTtlDaily",keyHashInt:248614979,rotationPeriodDays:1}];
  l.Global=s,l.PrivateStatsAllIds=u
}),98);
__d("WAWebWamConstants",[],(function(t,n,r,o,a,i){var e=5e4,l=5,d=120;
  i.WAM_MAX_BUFFER_SIZE=e,i.WAM_PROTOCOL_VERSION=l,i.WAM_BUFFER_ROTATE_INTERVAL_IN_SECS=d}),66);
"#;

#[test]
fn globals_carry_id_type_and_the_channels_they_are_legal_on() {
    let ir = run(GLOBALS_SRC);
    let g = |n: &str| ir.globals.iter().find(|g| g.name == n).unwrap();
    // The axis an event field does not have: writing `abKey2` into a `private` buffer
    // produces one the client never sends.
    assert_eq!(g("psId").channels, vec!["private".to_string()]);
    assert_eq!(g("psId").id, 6005);
    assert_eq!(g("psId").field_type, WamFieldType::String);
    assert_eq!(g("abKey2").channels, vec!["regular".to_string()]);
    assert_eq!(
        g("appBuild").channels,
        vec!["regular".to_string(), "private".to_string()]
    );
    assert_eq!(
        g("appBuild").field_type,
        WamFieldType::Enum {
            module: "WAWebWamEnumAppBuildType".into()
        }
    );
    // An omitted list is `["regular"]`, resolved here rather than left empty, because
    // that is what `defineGlobal` does with it.
    assert_eq!(g("legacyKey").channels, vec!["regular".to_string()]);
    // A global's enum resolves into the same catalog an event field's does.
    assert!(
        ir.enums
            .iter()
            .any(|e| e.module == "WAWebWamEnumAppBuildType"),
        "an enum only a global references is still resolved"
    );
}

#[test]
fn private_stats_table_keeps_the_never_rotates_sentinel() {
    let ir = run(GLOBALS_SRC);
    let p = |k: &str| ir.private_stats_ids.iter().find(|p| p.key == k).unwrap();
    // Both in one test: it is the `-1` beside a real period that a consumer gets wrong,
    // reading "rotates every -1 days" or normalizing it into 0.
    assert_eq!(p("DefaultPsId").rotation_period_days, -1);
    assert_eq!(p("DefaultPsId").id, 113760892);
    assert_eq!(p("IdTtlDaily").rotation_period_days, 1);
    assert_eq!(p("IdTtlDaily").id, 248614979);
    assert_eq!(p("DefaultPsId").module, "WAWebWamGlobals");
}

#[test]
fn the_runtimes_extra_private_stats_group_is_carried_too() {
    // `WAWebWamPrivateStats` adds a group the published table does not list, and it is
    // the one 21 private events name. Without it a `privateStatsId` of 0 resolves
    // against nothing.
    let src = format!(
        "{GLOBALS_SRC}\n__d(\"WAWebWamPrivateStats\",[\"WAWebWamGlobals\"],(function(t,n,r,o,a,i,l){{\
         var c={{}},d={{}},m={{}};o(\"WAWebWamGlobals\").PrivateStatsAllIds.map(function(e){{\
         c[e.keyHashInt]=e.key,d[e.key]=e.keyHashInt,m[e.key]={{value:e.keyHashInt,rotationPeriodDays:e.rotationPeriodDays}}}}),\
         c[0]=\"none\",d.none=0,m.none={{value:\"none\",rotationPeriodDays:-1}}}}),98);"
    );
    let ir = run(&src);
    let none = ir.private_stats_ids.iter().find(|p| p.id == 0).unwrap();
    assert_eq!(none.key, "none");
    assert_eq!(none.rotation_period_days, -1);
    // Provenance, because it is not part of the table WA publishes.
    assert_eq!(none.module, "WAWebWamPrivateStats");
}

#[test]
fn buffer_constants_are_carried_with_their_module() {
    let ir = run(GLOBALS_SRC);
    let c = |n: &str| ir.constants.iter().find(|c| c.name == n).unwrap();
    assert_eq!(c("WAM_PROTOCOL_VERSION").value, 5);
    assert_eq!(c("WAM_PROTOCOL_VERSION").module, "WAWebWamConstants");
    assert_eq!(c("WAM_MAX_BUFFER_SIZE").value, 50000);
    assert_eq!(c("WAM_BUFFER_ROTATE_INTERVAL_IN_SECS").value, 120);
}

/// The two-form emission shape of `WAWebMessageSendReporter`: an object literal in the
/// constructor, and property writes from other methods of the same class.
const REPORTER_SRC: &str = r#"
__d("WAWebWamEnumMessageType",[],(function(t,n,r,o,a,i){i.MESSAGE_TYPE=Object.freeze({TEXT:1})}),1);
__d("WAWebMessageSendWamEvent",["WAWebWamCodegenUtils","WAWebWamEnumMessageType"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.MessageSendWamEvent=e.defineEvents({MessageSend:[321,{
    messageType:[1,o("WAWebWamEnumMessageType").MESSAGE_TYPE],
    fastForwardEnabled:[2,e.TYPES.BOOLEAN],
    deviceCount:[3,e.TYPES.INTEGER],
    retryCount:[4,e.TYPES.INTEGER]
  },[1,1,1]]},{MessageSend:[]})
}),98);
__d("WAWebMessageSendReporter",["WAWebMessageSendWamEvent","WAWebWamEnumMessageType"],(function(t,n,r,o,a,i,l){
  var _=(function(){function t(t){
    this.$2=new(o("WAWebMessageSendWamEvent")).MessageSendWamEvent({
      messageType:o("WAWebWamEnumMessageType").MESSAGE_TYPE.TEXT,
      fastForwardEnabled:!0,
      retryCount:c(t)
    })}
    var n=t.prototype;
    n.setDeviceCount=function(e){this.$2.deviceCount=e};
    return t})();
  l.MessageSendReporter=_
}),99);
__d("WAWebMessageSendImporter",["WAWebMessageSendWamEvent"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebMessageSendWamEvent");l.type=e
}),100);
"#;

#[test]
fn call_site_carries_constructor_literals_and_later_writes() {
    let (ir, diag) = run_full(REPORTER_SRC);
    let ev = ir.events.iter().find(|e| e.name == "MessageSend").unwrap();
    // Both modules import the event; only one constructs it.
    assert_eq!(
        ev.consumers,
        vec![
            "WAWebMessageSendImporter".to_string(),
            "WAWebMessageSendReporter".to_string()
        ]
    );
    assert_eq!(ev.call_sites.len(), 1);
    let site = &ev.call_sites[0];
    assert_eq!(site.module, "WAWebMessageSendReporter");
    let f = |n: &str| site.fields.iter().find(|f| f.name == n).unwrap();

    // The constructor's object: a literal value, and an enum member named rather than
    // resolved to its integer.
    assert_eq!(f("fastForwardEnabled").write, WamFieldWrite::Constructor);
    assert_eq!(
        f("fastForwardEnabled").value,
        Some(WamCallSiteValue::Bool { value: true })
    );
    assert_eq!(
        f("messageType").value,
        Some(WamCallSiteValue::EnumMember {
            module: "WAWebWamEnumMessageType".into(),
            key: "TEXT".into()
        })
    );
    // A runtime expression is left without a value rather than given a placeholder.
    assert_eq!(f("retryCount").value, None);
    assert_eq!(f("retryCount").write, WamFieldWrite::Constructor);

    // The form a naive extractor loses: written from another method, onto the instance
    // property the construction was bound to.
    assert_eq!(f("deviceCount").write, WamFieldWrite::Assigned);
    assert_eq!(f("deviceCount").value, None);

    assert!(
        !site.partial,
        "every key of the constructor object was read"
    );
    assert_eq!(diag.constructions, 1);
    assert_eq!(diag.call_sites, 1);
    assert_eq!(diag.call_site_fields, 4);
}

#[test]
fn importing_the_event_module_is_not_constructing_it() {
    let ir = run(REPORTER_SRC);
    let ev = ir.events.iter().find(|e| e.name == "MessageSend").unwrap();
    assert!(
        !ev.call_sites
            .iter()
            .any(|s| s.module == "WAWebMessageSendImporter"),
        "a module that only declares the dependency is not an emission site"
    );
}

#[test]
fn a_merged_argument_publishes_what_it_states_and_says_it_is_partial() {
    let src = r#"
__d("WAWebProbeWamEvent",["WAWebWamCodegenUtils"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.ProbeWamEvent=e.defineEvents({Probe:[5,{count:[2,e.TYPES.INTEGER],label:[3,e.TYPES.STRING]},[1,1,1]]},{Probe:[]})
}),1);
__d("WAWebProbeMerge",["WAWebProbeWamEvent"],(function(t,n,r,o,a,i,l){
  function f(x){new(o("WAWebProbeWamEvent")).ProbeWamEvent(babelHelpers.extends({count:9},x)).commit()}
  function g(x){new(o("WAWebProbeWamEvent")).ProbeWamEvent(x).commit()}
  function h(){new(o("WAWebProbeWamEvent")).ProbeWamEvent().commit()}
}),2);
"#;
    let (ir, diag) = run_full(src);
    let ev = &ir.events[0];
    let site = |i: usize| &ev.call_sites[i];
    assert_eq!(ev.call_sites.len(), 3);

    // Sorted by module then by the field names, so the three are in a fixed order:
    // the empty-and-complete one, the empty-and-unread one, then the merge.
    assert!(
        site(0).fields.is_empty() && !site(0).partial,
        "no argument at all is a field set of zero"
    );
    assert!(
        site(1).fields.is_empty() && site(1).partial,
        "an unread argument states nothing"
    );
    assert_eq!(site(2).fields.len(), 1);
    assert_eq!(site(2).fields[0].name, "count");
    assert!(
        site(2).partial,
        "the merge's other operand is a lower bound"
    );

    assert_eq!(diag.constructions, 3);
    assert_eq!(diag.partial_call_sites, 2);
    // The unread argument is counted by the form that resisted, not swallowed.
    assert_eq!(diag.drops_by_reason.get("identifier"), Some(&1));
}

#[test]
fn a_field_typed_through_a_minifier_alias_is_still_typed() {
    // `(e = o("…")).X` at the first use and `e.X` after it. Reading only the first form
    // published an event with one field where WA declares three.
    let src = r#"
__d("WAWebWamEnumBucket",[],(function(t,n,r,o,a,i){i.BUCKET=Object.freeze({LOW:1})}),1);
__d("WAWebStatsWamEvent",["WAWebWamCodegenUtils","WAWebWamEnumBucket"],(function(t,n,r,o,a,i,l){
  var e,s=o("WAWebWamCodegenUtils").defineEvents({Stats:[9,{
    applied:[1,(e=o("WAWebWamEnumBucket")).BUCKET],
    failed:[2,e.BUCKET],
    plain:[3,o("WAWebWamCodegenUtils").TYPES.INTEGER]
  },[1,1,1]]},{Stats:[]});l.StatsWamEvent=s
}),2);
"#;
    let ir = run(src);
    let ev = &ir.events[0];
    assert_eq!(ev.fields.len(), 3);
    let f = |n: &str| ev.fields.iter().find(|f| f.name == n).unwrap();
    let bucket = WamFieldType::Enum {
        module: "WAWebWamEnumBucket".into(),
    };
    assert_eq!(f("applied").field_type, bucket);
    assert_eq!(f("failed").field_type, bucket);
    assert_eq!(f("plain").field_type, WamFieldType::Integer);
}

#[test]
fn a_site_writing_the_sampling_weight_is_counted_not_published() {
    // `weight` is not a field: it is the runtime override of the catalog's sampling
    // weight, which is why `weights` is a default rather than what the buffer carries.
    let src = r#"
__d("WAWebProbeWamEvent",["WAWebWamCodegenUtils"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.ProbeWamEvent=e.defineEvents({Probe:[5,{count:[2,e.TYPES.INTEGER]},[1,4,8]]},{Probe:[]})
}),1);
__d("WAWebProbeReporter",["WAWebProbeWamEvent"],(function(t,n,r,o,a,i,l){
  function f(){var x=new(o("WAWebProbeWamEvent")).ProbeWamEvent({count:1});x.weight=7;x.commit()}
}),2);
"#;
    let (ir, diag) = run_full(src);
    let site = &ir.events[0].call_sites[0];
    assert!(
        site.fields.iter().all(|f| f.name != "weight"),
        "the weight is not a field of the event"
    );
    assert!(
        site.partial,
        "the site writes more than the fields we publish"
    );
    assert_eq!(
        diag.drops_by_reason
            .get("call site overriding the catalog sampling weight"),
        Some(&1)
    );
}

#[test]
fn a_field_written_twice_at_one_site_is_one_entry_without_a_value() {
    // The real shape: constructed `true`, set to `false` on the failure path. Publishing
    // both would say the site writes one field twice; publishing the first value would
    // say it always sends `true`. Neither is what the site does.
    let src = r#"
__d("WAWebSendWamEvent",["WAWebWamCodegenUtils"],(function(t,n,r,o,a,i,l){
  var e=o("WAWebWamCodegenUtils");
  l.SendWamEvent=e.defineEvents({Send:[9,{ok:[1,e.TYPES.BOOLEAN],tries:[2,e.TYPES.INTEGER]},[1,1,1]]},{Send:[]})
}),1);
__d("WAWebSendReporter",["WAWebSendWamEvent"],(function(t,n,r,o,a,i,l){
  function f(y){var x=new(o("WAWebSendWamEvent")).SendWamEvent({ok:!0,tries:0});y||(x.ok=!1);x.commit()}
}),2);
"#;
    let ir = run(src);
    let site = &ir.events[0].call_sites[0];
    assert_eq!(site.fields.len(), 2);
    let ok = site.fields.iter().find(|f| f.name == "ok").unwrap();
    assert_eq!(ok.write, WamFieldWrite::Constructor);
    assert_eq!(
        ok.value, None,
        "which value goes out is the branch's answer"
    );
    // A field written once keeps its value.
    let tries = site.fields.iter().find(|f| f.name == "tries").unwrap();
    assert_eq!(tries.value, Some(WamCallSiteValue::Int { value: 0 }));
}
