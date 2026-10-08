//! Static conformance for two reviewed paths, not execution of the Web client.
//! Expected wire cases are hand-reviewed against the captured module sources.
use serde_json::{Value, json};
use std::path::Path;

const VERSIONS: [&str; 2] = ["2.3000.1045368834", "2.3000.1047483476"];

fn captured(version: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance")
        .join(version);
    let mut files: Vec<_> = std::fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("WASmax")
                && p.extension().is_some_and(|e| e == "js")
        })
        .collect();
    files.sort();
    let source = files
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::to_value(wa_scan::extract_iq(&source, version)).unwrap()
}

fn operation<'a>(ir: &'a Value, name: &str) -> &'a Value {
    ir["stanzas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["moduleName"] == format!("WASmaxOutGroups{name}Request"))
        .unwrap_or_else(|| panic!("{name} missing"))
}

fn request_contract(ir: &Value) {
    for name in ["SetSubject", "AcceptGroupAdd"] {
        let op = operation(ir, name);
        assert_eq!(op["namespace"], "w:g2");
        assert_eq!(op["iqType"], "set");
        assert_eq!(op["target"], "group_jid");
        let request = &op["request"];
        assert_eq!(request["namespace"], "w:g2");
        assert_eq!(request["iqType"], "set");
        assert_eq!(request["target"], "group_jid");
        assert_eq!(request["targetArgPath"], json!([{"key":"iqTo"}]));
    }
    assert_eq!(
        operation(ir, "SetSubject")["request"]["children"],
        json!([{
            "tag":"subject", "attrs":[], "children":[], "repeats":false,
            "content":{"kind":"dynamic","argPath":[{"key":"subjectElementValue"}]}
        }])
    );
    assert_eq!(
        operation(ir, "AcceptGroupAdd")["request"]["children"],
        json!([{
            "tag":"accept", "attrs":[
                {"name":"code","kind":"string","required":true,"argPath":[{"key":"acceptCode"}]},
                {"name":"expiration","kind":"integer","required":true,"argPath":[{"key":"acceptExpiration"}]},
                {"name":"admin","kind":"user_jid","required":true,"argPath":[{"key":"acceptAdmin"}]}
            ], "children":[], "repeats":false
        }])
    );
}

// Deliberately restricted IR interpreter for success assertions. No field coercion,
// server-error parsing, nested child flattening, wire codec, or transport is implied.
// Unknown assertion kinds fail the test instead of silently accepting the input.
fn success<'a>(op: &'a Value, response: &Value, request: &Value) -> Option<&'a str> {
    op["response"]["variants"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["kind"] == "success")
        .find(|v| {
            v["assertions"].as_array().unwrap().iter().all(|a| {
                let name = a["name"].as_str().unwrap();
                match a["kind"].as_str().unwrap() {
                    "tag" => response["tag"] == name,
                    "attr" => {
                        !response["attrs"][name].is_null() && response["attrs"][name] == a["value"]
                    }
                    "reference" => {
                        let path = a["referencePath"].as_array().unwrap();
                        assert_eq!(path.len(), 1, "unsupported reference path");
                        let expected = &request[path[0].as_str().unwrap()];
                        !expected.is_null()
                            && !response["attrs"][name].is_null()
                            && response["attrs"][name] == *expected
                    }
                    "child" => response["children"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|c| c["tag"] == name),
                    other => panic!("unsupported assertion {other}"),
                }
            })
        })
        .map(|v| v["tag"].as_str().unwrap())
}

fn response_cases(ir: &Value, complete_error_vocabulary: bool) {
    // The 13-module success capture omits error parsers, so only the full
    // snapshot can refine code families. Never infer the side from tag names.
    let client = if complete_error_vocabulary {
        "client_error"
    } else {
        "error"
    };
    let server = if complete_error_vocabulary {
        "server_error"
    } else {
        "error"
    };
    let request = json!({"id":"fixture-7","to":"120363000000001@g.us"});
    let bare = json!({"tag":"iq","attrs":{"id":"fixture-7","from":"120363000000001@g.us","type":"result"},"children":[]});
    let mut child = bare.clone();
    child["children"] = json!([{"tag":"membership_approval_request"}]);
    let accept = operation(ir, "AcceptGroupAdd");
    let subject = operation(ir, "SetSubject");
    // This interpreter only covers the reviewed empty-payload successes. A new
    // field needs an explicit extension, not accidental acceptance by this model.
    for op in [accept, subject] {
        assert_eq!(
            op["response"]["fields"],
            json!([{
                "method":"attrString", "name":"type", "wireName":"type",
                "type":"string", "parserRequired":true, "literalValue":"result"
            }])
        );
        for variant in op["response"]["variants"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["kind"] == "success")
        {
            assert_eq!(
                variant["fields"],
                json!([{
                    "method":"attrString", "name":"type", "wireName":"type",
                    "type":"string", "parserRequired":true, "literalValue":"result"
                }])
            );
        }
    }
    assert_eq!(
        success(accept, &bare, &request),
        Some("AcceptGroupAddResponseSuccess")
    );
    assert_eq!(
        success(accept, &child, &request),
        Some("AcceptGroupAddResponseGroupJoinRequestSuccess")
    );
    assert_eq!(
        success(subject, &bare, &request),
        Some("SetSubjectResponseSuccess")
    );
    // The reviewed bare parser does not reject extra children. Strict generation
    // admission must not become blanket rejection of runtime extensions.
    let mut extension = bare.clone();
    extension["children"] = json!([{"tag":"future_extension"}]);
    assert_eq!(
        success(accept, &extension, &request),
        Some("AcceptGroupAddResponseSuccess")
    );
    for op in [accept, subject] {
        for valid in [&bare, &child] {
            for (key, invalid) in [
                ("id", json!("other")),
                ("id", Value::Null),
                ("from", json!("g.us")),
                ("from", Value::Null),
                ("type", json!("set")),
                ("type", Value::Null),
            ] {
                let mut response = valid.clone();
                response["attrs"][key] = invalid;
                assert_eq!(success(op, &response, &request), None, "invalid {key}");
            }
            for key in ["id", "from", "type"] {
                let mut missing = valid.clone();
                missing["attrs"].as_object_mut().unwrap().remove(key);
                assert_eq!(
                    success(op, &missing, &request),
                    None,
                    "absent response {key}"
                );
            }
            let mut response = valid.clone();
            response["tag"] = json!("message");
            assert_eq!(success(op, &response, &request), None);
            for key in ["id", "to"] {
                let mut missing = request.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert_eq!(success(op, valid, &missing), None, "missing request {key}");
            }
        }
    }
    for (op, expected) in [
        (
            accept,
            vec![
                ("AcceptGroupAddResponseGroupJoinRequestSuccess", "success"),
                ("AcceptGroupAddResponseSuccess", "success"),
                ("AcceptGroupAddResponseClientError", "error"),
                ("AcceptGroupAddResponseServerError", server),
            ],
        ),
        (
            subject,
            vec![
                ("SetSubjectResponseSuccess", "success"),
                ("SetSubjectResponseClientError", client),
                ("SetSubjectResponseServerError", server),
            ],
        ),
    ] {
        let outcomes: Vec<_> = op["response"]["variants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| (v["tag"].as_str().unwrap(), v["kind"].as_str().unwrap()))
            .collect();
        assert_eq!(outcomes, expected);
    }
}

#[test]
fn source_derived_contracts_hold_across_two_verified_snapshots() {
    for version in VERSIONS {
        let ir = captured(version);
        request_contract(&ir);
        response_cases(&ir, false);
    }
}

#[test]
fn committed_ir_satisfies_the_independent_wire_cases() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../generated/iq/index.json");
    let ir = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    request_contract(&ir);
    response_cases(&ir, true);
}

#[test]
fn the_oracle_detects_lost_child_gate_and_reordered_outcomes() {
    let ir = captured(VERSIONS[1]);
    let request = json!({"id":"x","to":"g"});
    let bare = json!({"tag":"iq","attrs":{"id":"x","from":"g","type":"result"},"children":[]});
    let mut op = operation(&ir, "AcceptGroupAdd").clone();
    op["response"]["variants"][0]["assertions"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["kind"] != "child");
    assert_ne!(
        success(&op, &bare, &request),
        Some("AcceptGroupAddResponseSuccess")
    );
    let mut op = operation(&ir, "AcceptGroupAdd").clone();
    op["response"]["variants"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let mut child = bare;
    child["children"] = json!([{"tag":"membership_approval_request"}]);
    assert_ne!(
        success(&op, &child, &request),
        Some("AcceptGroupAddResponseGroupJoinRequestSuccess")
    );
}

#[test]
fn request_oracle_rejects_extra_wire_structure() {
    let ir = captured(VERSIONS[1]);
    for name in ["SetSubject", "AcceptGroupAdd"] {
        for mutation in ["sibling", "attribute", "nested", "repeated"] {
            let mut changed = ir.clone();
            let op = changed["stanzas"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|s| s["moduleName"] == format!("WASmaxOutGroups{name}Request"))
                .unwrap();
            let children = op["request"]["children"].as_array_mut().unwrap();
            match mutation {
                "sibling" => children.push(json!({"tag":"unreviewed"})),
                "attribute" => children[0]["attrs"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name":"unreviewed","kind":"string"})),
                "nested" => children[0]["children"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"tag":"unreviewed"})),
                _ => children[0]["repeats"] = json!(true),
            }
            assert!(
                std::panic::catch_unwind(|| request_contract(&changed)).is_err(),
                "accepted {name} {mutation}"
            );
        }
    }
}

#[test]
fn response_oracle_rejects_misclassified_error_outcomes() {
    let ir = captured(VERSIONS[1]);
    for name in ["SetSubject", "AcceptGroupAdd"] {
        let count = operation(&ir, name)["response"]["variants"]
            .as_array()
            .unwrap()
            .len();
        for index in count - 2..count {
            let mut changed = ir.clone();
            let op = changed["stanzas"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|s| s["moduleName"] == format!("WASmaxOutGroups{name}Request"))
                .unwrap();
            op["response"]["variants"][index]["kind"] = json!("unclassified");
            assert!(
                std::panic::catch_unwind(|| response_cases(&changed, false)).is_err(),
                "accepted {name} outcome {index}"
            );
        }
    }
}

#[test]
fn oracle_rejects_outer_metadata_and_missing_response_mirror() {
    let ir = captured(VERSIONS[1]);
    for name in ["SetSubject", "AcceptGroupAdd"] {
        for field in ["namespace", "iqType", "target", "response_fields"] {
            let mut changed = ir.clone();
            let op = changed["stanzas"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|s| s["moduleName"] == format!("WASmaxOutGroups{name}Request"))
                .unwrap();
            if field == "response_fields" {
                op["response"]["fields"] = json!([]);
                assert!(std::panic::catch_unwind(|| response_cases(&changed, false)).is_err());
            } else {
                op[field] = json!("wrong");
                assert!(
                    std::panic::catch_unwind(|| request_contract(&changed)).is_err(),
                    "accepted {name} outer {field}"
                );
            }
        }
    }
}
