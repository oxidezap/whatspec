#[test]
fn event_wrapper_keeps_current_call_site_presence_and_shape() {
    let source = [
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WAWebSharableEventServerClient.js"
        ),
        include_str!("../../../tests/fixtures/bundles-1054751086/WAWebSharableEventListJob.js"),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WAWebSharableEventListJobQuery.graphql.js"
        ),
    ]
    .join("\n");
    let ir = wa_mex::extract_mex(&source, "2.3000.1054751086");
    let operation = &ir.operations["SharableEventList"];
    let input = &operation.variables_presence["input"];
    assert_eq!(input.presence, wa_ir::VariablePresence::Always);
    assert_eq!(
        input.fields["categories"].presence,
        wa_ir::VariablePresence::Always
    );
    assert_eq!(
        input.fields["page_size"].presence,
        wa_ir::VariablePresence::Always
    );
    assert_eq!(
        input.fields["time_range"].fields["start_ts_sec"].presence,
        wa_ir::VariablePresence::Always
    );
}
