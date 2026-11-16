use wa_scan::scan_iq_stanzas;

#[test]
fn private_rpc_helpers_preserve_current_bundle_contracts() {
    for source in [
        include_str!("../../../tests/fixtures/bundles-1054751086/WASmaxStatsSendBufferRPC.js"),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxPrivacyGetContactBlacklistRPC.js"
        ),
        include_str!("../../../tests/fixtures/bundles-1054751086/WASmaxPushConfigSetRPC.js"),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxBizSettingsSetPrivacySettingRPC.js"
        ),
    ] {
        let result = scan_iq_stanzas(source);
        assert!(result.unparseable.is_empty(), "{:?}", result.unparseable);
        assert!(!result.stanzas.is_empty());
        for stanza in result.stanzas {
            assert!(!stanza.namespace.is_empty());
            assert!(!stanza.response.fields.is_empty() || !stanza.response.variants.is_empty());
        }
    }
}

#[test]
fn private_root_router_preserves_both_addressees_without_inventing_a_path() {
    let source = [
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxGroupsGetGroupProfilePicturesRPC.js"
        ),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxOutGroupsBaseGetGroupMixin.js"
        ),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxOutGroupsBaseGetServerMixin.js"
        ),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxOutGroupsBaseIQGetRequestMixin.js"
        ),
        include_str!(
            "../../../tests/fixtures/bundles-1054751086/WASmaxOutGroupsParentGroupMixin.js"
        ),
    ]
    .join("\n");
    let result = scan_iq_stanzas(&source);
    let stanzas: Vec<_> = result
        .stanzas
        .iter()
        .filter(|s| s.module_name == "WASmaxGroupsGetGroupProfilePicturesRPC")
        .collect();
    assert_eq!(stanzas.len(), 1);
    let request = &stanzas[0].request;
    assert_eq!(request.target, wa_ir::IqTarget::Unknown);
    assert!(request.target_arg_path.is_none());
    let variants = &request.variant_groups[0].variants;
    assert_eq!(variants.len(), 2);
    let group = variants
        .iter()
        .flat_map(|v| &v.attrs)
        .find(|a| a.arg_path.is_some())
        .unwrap();
    assert_eq!(
        group
            .arg_path
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.key.as_str())
            .collect::<Vec<_>>(),
        ["baseGetGroupOrServerMixinGroupArgs", "baseGetGroup", "iqTo"]
    );
    assert!(
        variants
            .iter()
            .flat_map(|v| &v.attrs)
            .any(|a| a.value.as_deref() == Some("g.us"))
    );
}
