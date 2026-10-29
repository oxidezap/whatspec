use wa_appstate::validation::extract;
const SOURCE: &str = include_str!("fixtures/server_sync_protobuf.js");
#[test]
fn complete_protobuf_methods_and_alpha_renaming() {
    let original = extract(SOURCE, "test").unwrap();
    assert_eq!(original.functions.len(), 6);
    // Rename the entire module's minifier slots without touching property names,
    // string literals or keywords. The replacement deliberately changes spans.
    let changed = SOURCE
        .replace("function(n,r)", "function(collectionArg,protoArg)")
        .replace("collection:n", "collection:collectionArg");
    // An incomplete rename must fail rather than silently reading an unknown local.
    assert!(extract(&changed, "test").is_err());
    let renamed = SOURCE
        .replace(
            "function(t,n,r,o,a,i,l)",
            "function(t,n,r,requireAlias,a,i,l)",
        )
        .replace("o(\"", "requireAlias(\"");
    let renamed = extract(&renamed, "test").unwrap();
    for (name, f) in &original.functions {
        assert_eq!(f.body, renamed.functions[name].body, "{name}");
    }
    let formatted = SOURCE.replace(';', ";\n").replace("var ", "var  ");
    let formatted = extract(&formatted, "test").unwrap();
    for (name, f) in original.functions {
        assert_eq!(f.body, formatted.functions[&name].body, "{name}");
    }
}
#[test]
fn reject_incomplete_or_unsupported_method() {
    for name in ["e", "o", "callback"] {
        assert!(
            extract(
                &SOURCE.replace(
                    "function(t){return e.validateRecordProtobuf",
                    &format!("function {name}(t){{return e.validateRecordProtobuf")
                ),
                "test"
            )
            .is_err()
        );
    }
    assert!(
        extract(
            &SOURCE.replace(
                "validateRecordProtobuf=function(",
                "validateRecordProtobuf=function self("
            ),
            "test"
        )
        .is_err()
    );
    assert!(
        extract(
            &SOURCE.replace(
                "function(t,n,r){var e=n==null",
                "function(t,n={id:\"fallback\"},r){var e=n==null"
            ),
            "test"
        )
        .is_err()
    );
    assert!(
        extract(
            &SOURCE.replace(
                "function(t){return e.validateRecordProtobuf",
                "function(t=fallback()){return e.validateRecordProtobuf"
            ),
            "test"
        )
        .is_err()
    );
    assert!(
        extract(
            &SOURCE.replace("fileSizeBytes:i", "fileSizeBytes:18446744073709551616"),
            "test"
        )
        .is_err()
    );
    assert!(extract(&SOURCE.replace("l.default=e", "l.default=null"), "test").is_err());
    assert!(
        extract(
            &SOURCE.replace("l.default=e", "l.default=unrelated"),
            "test"
        )
        .is_err()
    );
    assert!(
        extract(
            &SOURCE.replace("validateKeyIdProtobuf=function", "unlisted=function"),
            "test"
        )
        .is_err()
    );
    assert!(extract(&SOURCE.replace("if(!a)", "if(custom(a))"), "test").is_err());
    assert!(
        extract(
            &SOURCE.replace("return{id:", "sideEffect();return{id:"),
            "test"
        )
        .is_err()
    );
    assert!(
        extract(
            &format!(
                "{SOURCE};{}",
                SOURCE.replace("missing snapshot mac", "other error")
            ),
            "test"
        )
        .is_err()
    );
}
#[test]
fn guard_changes_change_the_program() {
    let a = extract(SOURCE, "test").unwrap();
    let b = extract(&SOURCE.replace("if(!a)", "if(a==null)"), "test").unwrap();
    assert_ne!(
        a.functions["validateSnapshotProtobuf"].body,
        b.functions["validateSnapshotProtobuf"].body
    );
}

#[test]
fn reject_factory_shadowing_and_non_native_object_strings() {
    for loader in ["n", "r", "o", "l"] {
        let changed = SOURCE
            .replace("var e=(function()", &format!("var {loader}=(function()"))
            .replace("l.default=e", &format!("l.default={loader}"));
        assert_ne!(changed, SOURCE);
        assert!(
            extract(&changed, "test").is_err(),
            "factory binding {loader}"
        );
    }
    let changed = SOURCE
        .replace("function e()", "function o()")
        .replace("e.validate", "o.validate")
        .replace(",e})()", ",o})()");
    assert_ne!(changed, SOURCE);
    assert!(
        extract(&changed, "test")
            .unwrap_err()
            .contains("constructor shadows a dependency loader")
    );
    for projection in [
        r#"({__proto__:{size:i}}).size"#,
        r#"({"__proto__":{size:i}}).size"#,
        r#""\uD800".length"#,
        r#""\uDC00".length"#,
    ] {
        let changed = SOURCE.replace("fileSizeBytes:i", &format!("fileSizeBytes:{projection}"));
        assert_ne!(changed, SOURCE);
        assert!(extract(&changed, "test").is_err(), "{projection}");
    }
}
