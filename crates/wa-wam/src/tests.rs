use super::*;

fn run(src: &str) -> WamIr {
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

    // Consumer hint: the reporter module that depends on the event.
    assert_eq!(ev.consumers, vec!["WAWebWamAppLaunchReporter".to_string()]);
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
