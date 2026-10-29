mod validation_value {
    include!("fixtures/appstate_validation_value.rs.txt");
}
#[allow(clippy::all)]
mod generated {
    include!("fixtures/appstate_validation.rs.txt");
}
#[allow(clippy::all)]
mod batch {
    include!("fixtures/appstate_batch_validation.rs.txt");
}
use serde_json::{Value as Json, json};
use validation_value::{Transforms, ValidationError, Value};
struct OracleTransforms;
impl<'a> Transforms<'a> for OracleTransforms {
    fn number_or_throw_if_too_large(&mut self, v: Value<'a>) -> Result<Value<'a>, ValidationError> {
        match v {
            Value::Number(_) => Ok(v),
            _ => Err(ValidationError::dependency(
                "Error",
                "numberOrThrowIfTooLarge is given a non-safe integer",
            )),
        }
    }
    fn to_sync_key_id(&mut self, v: Value<'a>) -> Result<Value<'a>, ValidationError> {
        Ok(v)
    }
    fn decode_sync_action_data(&mut self, v: Value<'a>) -> Result<Value<'a>, ValidationError> {
        let code = match v {
            Value::Array(a) => a[0].number()? as u8,
            Value::Bytes(b) => b[0],
            _ => 255,
        };
        let value = match code {
            0 => return Ok(Value::Object(vec![])),
            1 => Value::Null,
            2 => Value::Object(vec![]),
            3 => Value::Object(vec![("timestamp", Value::Null)]),
            4 => Value::Object(vec![("timestamp", Value::Number(0.0))]),
            5 => Value::Object(vec![("timestamp", Value::Number(1.0))]),
            255 => {
                return Err(ValidationError::dependency(
                    "Error",
                    "test decoder rejected",
                ));
            }
            _ => Value::Object(vec![("timestamp", Value::Long(9007199254740992))]),
        };
        Ok(Value::Object(vec![("value", value)]))
    }
    fn decode_patch_debug_data(&mut self, v: Value<'a>) -> Result<Value<'a>, ValidationError> {
        match v {
            Value::Bytes([255, ..]) => Err(ValidationError::dependency(
                "Error",
                "test decoder rejected",
            )),
            _ => Ok(Value::Object(vec![("decoded", Value::Bool(true))])),
        }
    }
}
fn read(v: &Json) -> Value<'static> {
    if v.get("$undefined") == Some(&Json::Bool(true)) {
        return Value::Undefined;
    }
    if let Some(bytes) = v.get("$bytes") {
        return Value::Bytes(Box::leak(
            bytes
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ));
    }
    if let Some(long) = v.get("$long") {
        return Value::Long(long.as_str().unwrap().parse().unwrap());
    }
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => Value::Number(n.as_f64().unwrap()),
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(a) => Value::Array(a.iter().map(read).collect()),
        Json::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (&*Box::leak(k.clone().into_boxed_str()), read(v)))
                .collect(),
        ),
    }
}
fn write(v: Value<'_>) -> Json {
    match v {
        Value::Undefined => json!({"$undefined":true}),
        Value::Null => Json::Null,
        Value::Bool(b) => json!(b),
        Value::Number(n) => {
            if n.fract() == 0.0 {
                json!(n as i64)
            } else {
                json!(n)
            }
        }
        Value::Long(n) => json!({"$long":n.to_string()}),
        Value::Text(s) => json!(s),
        Value::Bytes(b) => json!({"$bytes":b}),
        Value::Array(a) => Json::Array(a.into_iter().map(write).collect()),
        Value::Object(o) => {
            Json::Object(o.into_iter().map(|(k, v)| (k.into(), write(v))).collect())
        }
    }
}
#[test]
fn official_isolated_methods_match_generated_rust() {
    let cases: Vec<Json> =
        serde_json::from_str(include_str!("fixtures/appstate_validation.json")).unwrap();
    for (i, c) in cases.iter().enumerate() {
        let collection = Value::Text("test".into());
        let input = read(&c["input"]);
        let mut transforms = OracleTransforms;
        let result = match c["method"].as_str().unwrap() {
            "validateSnapshotProtobuf" => {
                generated::validate_snapshot_protobuf(&mut transforms, collection, input)
            }
            "validatePatchProtobuf" => {
                generated::validate_patch_protobuf(&mut transforms, collection, input)
            }
            "validateRecordProtobuf" => {
                generated::validate_record_protobuf(&mut transforms, collection, input)
            }
            "validateMutationProtobuf" => {
                generated::validate_mutation_protobuf(&mut transforms, collection, input)
            }
            "validateExternalBlobReference" => {
                generated::validate_external_blob_reference(&mut transforms, collection, input)
            }
            "validateKeyIdProtobuf" => generated::validate_key_id_protobuf(
                &mut transforms,
                collection,
                input,
                read(&c["metric"]),
            ),
            other => panic!("unknown method {other}"),
        };
        if let Some(error) = c.get("error") {
            let actual = result.unwrap_err();
            assert_eq!(
                actual.class,
                error["class"].as_str().unwrap(),
                "case {i}: {c}"
            );
            assert_eq!(
                actual.metric.as_deref(),
                error["metric"].as_str(),
                "case {i}: {c}"
            );
            if let Some(message) = error["message"].as_str() {
                assert_eq!(actual.message, message, "case {i}: {c}");
            }
        } else {
            assert_eq!(write(result.unwrap()), c["result"], "case {i}: {c}");
        }
    }
}
#[test]
fn regenerated_program_matches_committed_output() {
    let ir =
        serde_json::from_str(include_str!("../../../generated/appstate/validation.json")).unwrap();
    assert_eq!(
        wa_codegen::generate_appstate_validation(&ir).unwrap(),
        include_str!("fixtures/appstate_validation.rs.txt")
    );
}

#[derive(Default)]
struct Effects {
    events: Vec<Json>,
}
impl batch::BatchEffects for Effects {
    fn duplicate(&mut self, _: &batch::BatchMutation<'_>) {}
    fn report(&mut self, metric: &'static str, fatal: bool) {
        self.events.push(json!(["report", metric, fatal]));
    }
    fn local_warning(&mut self) {
        self.events.push(json!(["warning"]));
    }
    fn inspect_all(
        &mut self,
        mutations: &[batch::BatchMutation<'_>],
    ) -> Result<(), ValidationError> {
        self.events.push(json!(["inspect"]));
        let mut seen = std::collections::HashMap::new();
        for m in mutations {
            let _key_id = m.key_id;
            if let Some(previous) = seen.insert(m.index, m.binary_sync_data)
                && (m.binary_sync_data[0] == 255 || previous[0] == 255)
            {
                return Err(ValidationError::dependency(
                    "Error",
                    "test decoder rejected",
                ));
            }
        }
        Ok(())
    }
}
#[test]
fn official_batch_algorithms_match_generated_rust() {
    let cases: Vec<Json> =
        serde_json::from_str(include_str!("fixtures/appstate_batch_validation.json")).unwrap();
    for (i, c) in cases.iter().enumerate() {
        let mut effects = Effects::default();
        let result = match c["method"].as_str().unwrap() {
            "validateAndTypeSetMutations" => batch::validate_and_type_set_mutations(
                &mut OracleTransforms,
                Value::Text("test".into()),
                read(&c["input"]),
            ),
            "validateNoDuplicatePatchVersionInCollection" => {
                let result = batch::validate_no_duplicate_patch_version(
                    c["input"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x["version"]["version"].as_u64().unwrap()),
                );
                if let Err(e) = &result {
                    effects.events.push(json!(["report", e.metric, true]));
                }
                result.map(|_| Value::Undefined)
            }
            "validateNoSameIndexForMultipleMutations" => {
                let storage: Vec<Vec<u8>> = c["input"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| vec![m["binarySyncData"][0].as_u64().unwrap() as u8])
                    .collect();
                let mutations: Vec<_> = c["input"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(i, m)| batch::BatchMutation {
                        index: m["index"].as_str().unwrap(),
                        operation: m["operation"].as_i64().unwrap() as i32,
                        binary_sync_data: &storage[i],
                        key_id: &[1],
                    })
                    .collect();
                let kind = match c["kind"].as_str().unwrap() {
                    "Patch" => batch::SyncDataType::Patch,
                    "Snapshot" => batch::SyncDataType::Snapshot,
                    "Local" => batch::SyncDataType::Local,
                    _ => batch::SyncDataType::Other("Other"),
                };
                batch::validate_no_same_index(&mutations, kind, &mut effects)
                    .map(|_| Value::Undefined)
            }
            _ => unreachable!(),
        };
        if c["error"].is_null() {
            assert_eq!(write(result.unwrap()), c["result"], "case {i}: {c}");
        } else {
            let actual = result.unwrap_err();
            assert_eq!(
                actual.class,
                c["error"]["class"].as_str().unwrap(),
                "case {i}: {c}"
            );
            if actual.class == "SyncdFatalError" {
                assert_eq!(actual.message, c["error"]["message"], "case {i}: {c}");
            }
            if c["method"] == "validateAndTypeSetMutations" && actual.metric.is_some() {
                effects.events.push(json!(["report", actual.metric, true]));
            }
        }
        assert_eq!(
            effects.events,
            c["events"].as_array().unwrap().clone(),
            "case {i}: {c}"
        );
    }
}

#[test]
fn extraction_fixtures_match_programs_and_mutation_trips_the_gate() {
    const SOURCE: &str = include_str!("../../wa-appstate/tests/fixtures/server_sync_protobuf.js");
    let ir: wa_ir::AppstateValidationIr =
        serde_json::from_str(include_str!("../../../generated/appstate/validation.json")).unwrap();
    assert_eq!(
        wa_appstate::validation::extract(SOURCE, &ir.wa_version).unwrap(),
        ir
    );
    let mutated =
        wa_appstate::validation::extract(&SOURCE.replace("if(!a)", "if(a==null)"), &ir.wa_version)
            .unwrap();
    assert_ne!(
        wa_codegen::generate_appstate_validation(&mutated).unwrap(),
        include_str!("fixtures/appstate_validation.rs.txt")
    );
    let batch: wa_ir::AppstateBatchValidationIr = serde_json::from_str(include_str!(
        "../../../generated/appstate/validation_batch.json"
    ))
    .unwrap();
    let source = format!(
        "{};{}",
        include_str!("../../wa-appstate/src/fixtures/validate_mutations.js"),
        include_str!("../../wa-appstate/src/fixtures/server_sync.pb.js")
    );
    assert_eq!(
        wa_appstate::validation_batch::extract(&source, &batch.wa_version).unwrap(),
        batch
    );
}

#[allow(dead_code, clippy::all)]
mod scope_regression {
    include!("fixtures/appstate_scope.rs.txt");
}
#[test]
fn callbacks_capture_outer_slots_and_restore_shadowed_names() {
    const SOURCE: &str = include_str!("../../wa-appstate/tests/fixtures/server_sync_protobuf.js");
    let source = SOURCE.replace(
        "var u=i.map(function(t){return e.validateRecordProtobuf(n,t)});",
        "var saved=a;var u=i.map(function(t){var a=saved;return a});",
    );
    let ir = wa_appstate::validation::extract(&source, "test").unwrap();
    assert_eq!(
        wa_codegen::generate_appstate_validation(&ir).unwrap(),
        include_str!("fixtures/appstate_scope.rs.txt")
    );
    let case: Json =
        serde_json::from_str(include_str!("fixtures/appstate_scope_case.json")).unwrap();
    let output = scope_regression::validate_snapshot_protobuf(
        &mut OracleTransforms,
        Value::Text("test".into()),
        read(&case["input"]),
    )
    .unwrap();
    assert_eq!(write(output), case["result"]);
}
