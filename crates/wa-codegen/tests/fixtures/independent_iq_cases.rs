// Expectations are manually read from preserved Web module bodies. No expected
// result is generated from IQ IR, codegen output or the other pilot's test main.
fn specs() -> (MakeSetSubjectRequestSpec, MakeAcceptGroupAddRequestSpec) {
    let target = jid::Jid::new("123", jid::Server::Group);
    (
        MakeSetSubjectRequestSpec::new(target.clone(), "Olá & <grupo>".as_bytes().to_vec()),
        MakeAcceptGroupAddRequestSpec::new(
            "invite-42",
            98765,
            &jid::Jid::new("456", jid::Server::Pn),
            target,
        ),
    )
}
fn subject_class(node: &Node) -> Result<&'static str, anyhow::Error> {
    Ok(
        match specs()
            .0
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")?
        {
            MakeSetSubjectRequestResponse::Success(_) => "success",
            MakeSetSubjectRequestResponse::ClientError(_) => "client",
            MakeSetSubjectRequestResponse::ServerError(_) => "server",
        },
    )
}
fn accept_class(node: &Node) -> Result<&'static str, anyhow::Error> {
    Ok(
        match specs()
            .1
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")?
        {
            MakeAcceptGroupAddRequestResponse::Success(_) => "success",
            MakeAcceptGroupAddRequestResponse::GroupJoinRequestSuccess(_) => "approval",
            MakeAcceptGroupAddRequestResponse::ClientError(_) => "client",
            MakeAcceptGroupAddRequestResponse::ServerError(_) => "server",
        },
    )
}
#[test]
fn request_destination_and_content() {
    let (subject, accept) = specs();
    let request = subject.build_iq();
    assert_eq!(request.target.0, "123@g.us");
    assert_eq!((request.namespace, request.kind), ("w:g2", "set"));
    let node::NodeContent::Nodes(nodes) = request.content.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].tag, "subject");
    assert_eq!(nodes[0].bytes.as_deref(), Some("Olá & <grupo>".as_bytes()));
    let request = accept.build_iq();
    assert_eq!(request.target.0, "123@g.us");
    assert_eq!((request.namespace, request.kind), ("w:g2", "set"));
    let node::NodeContent::Nodes(nodes) = request.content.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].tag, "accept");
    assert_eq!(
        nodes[0].attrs,
        BTreeMap::from([
            ("code".into(), "invite-42".into()),
            ("expiration".into(), "98765".into()),
            ("admin".into(), "456@s.whatsapp.net".into())
        ])
    );
}
#[test]
fn success_order_and_runtime_extensions() {
    let approval = Node::new("membership_approval_request", &[], vec![]);
    for (children, expected) in [
        (vec![], "success"),
        (vec![approval.clone()], "approval"),
        (vec![approval.clone(), approval], "success"),
        (vec![Node::new("future", &[], vec![])], "success"),
    ] {
        let node = result(children);
        assert_eq!(subject_class(&node).unwrap(), "success");
        assert_eq!(accept_class(&node).unwrap(), expected);
    }
    // Bare success does not examine children or content. A failed approval
    // selector is followed by bare success, even with binary root content.
    let mut node = result(vec![]);
    node.bytes = Some(vec![0xff]);
    assert_eq!(accept_class(&node).unwrap(), "success");
    assert_eq!(subject_class(&node).unwrap(), "success");
}
#[test]
fn ordered_error_outcomes_and_ranges() {
    for (code, text, accept, subject) in [
        ("304", "already-exists", Some("client"), None),
        ("304", "bad-request", None, None),
        ("399", "unknown", None, None),
        ("400", "bad-request", Some("client"), Some("client")),
        ("400", "unknown", Some("client"), Some("client")),
        ("499", "unknown", Some("client"), Some("client")),
        ("500", "resource-constraint", Some("client"), Some("server")),
        (
            "500",
            "internal-server-error",
            Some("server"),
            Some("server"),
        ),
        ("500", "unknown", Some("server"), Some("server")),
        ("503", "service-unavailable", Some("server"), Some("server")),
        (
            "530",
            "partial-server-error",
            Some("server"),
            Some("server"),
        ),
        ("599", "unknown", Some("server"), Some("server")),
        ("600", "unknown", None, None),
    ] {
        let node = error(code, Some(text));
        assert_eq!(accept_class(&node).ok(), accept, "accept: {code}/{text}");
        assert_eq!(subject_class(&node).ok(), subject, "subject: {code}/{text}");
    }
}
#[test]
fn decimal_coercion_and_invalid_codes() {
    for code in ["0304", "+304", "\t304tail", "\u{feff}304", "304.9", "304e7"] {
        assert_eq!(
            accept_class(&error(code, Some("already-exists"))).unwrap(),
            "client"
        );
    }
    for code in [
        "",
        "+",
        "-304",
        "0x130",
        "\u{0085}304",
        "∞",
        "NaN",
        "9999999999999999999999",
        "  + 304",
    ] {
        assert!(
            accept_class(&error(code, Some("already-exists"))).is_err(),
            "{code:?}"
        );
    }
    for key in ["code", "text"] {
        let mut node = error("400", Some("bad-request"));
        node.children[0].attrs.remove(key);
        assert!(accept_class(&node).is_err());
        assert!(subject_class(&node).is_err());
    }
    let mut node = error("400", Some("bad-request"));
    node.children.push(node.children[0].clone());
    assert!(accept_class(&node).is_err());
    assert!(subject_class(&node).is_err());
}
#[test]
fn correlation_is_required_for_every_response_kind() {
    let (subject, accept) = specs();
    for node in [
        result(vec![]),
        result(vec![Node::new("membership_approval_request", &[], vec![])]),
        error("400", Some("bad-request")),
        error("500", Some("internal-server-error")),
    ] {
        assert!(subject.parse_response(&node.as_ref()).is_err());
        assert!(accept.parse_response(&node.as_ref()).is_err());
        for key in ["id", "from", "type"] {
            let mut invalid = node.clone();
            invalid.attrs.remove(key);
            assert!(subject_class(&invalid).is_err());
            assert!(accept_class(&invalid).is_err());
            invalid.attrs.insert(key.into(), "wrong".into());
            assert!(subject_class(&invalid).is_err());
            assert!(accept_class(&invalid).is_err());
        }
        let mut invalid = node.clone();
        invalid.tag = "message".into();
        assert!(subject_class(&invalid).is_err());
        assert!(accept_class(&invalid).is_err());
        for (id, to) in [
            ("wrong", "123@g.us"),
            ("req-1", "999@g.us"),
            ("", "123@g.us"),
            ("req-1", ""),
        ] {
            assert!(
                subject
                    .parse_response_with_request(&node.as_ref(), id, to)
                    .is_err()
            );
            assert!(
                accept
                    .parse_response_with_request(&node.as_ref(), id, to)
                    .is_err()
            );
        }
    }
    // The actual wire request context controls correlation, not the spec's
    // original target and not values fabricated from the received stanza.
    let mut node = result(vec![]);
    node.attrs.insert("from".into(), "999@g.us".into());
    assert!(
        subject
            .parse_response_with_request(&node.as_ref(), "req-1", "999@g.us")
            .is_ok()
    );
    assert!(
        accept
            .parse_response_with_request(&node.as_ref(), "req-1", "999@g.us")
            .is_ok()
    );
}
#[test]
fn optional_field_payload_and_source_fallback() {
    let subject = specs().0;
    let mut node = error("406", Some("not-acceptable"));
    node.children[0].children = vec![Node::new(
        "field",
        &[("name", "subject"), ("reason", "too-long")],
        vec![],
    )];
    let MakeSetSubjectRequestResponse::ClientError(value) = subject
        .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
        .unwrap()
    else {
        panic!("client error required")
    };
    let Some(MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorNotAcceptable(
        payload,
    )) = value.error_set_subject_client_errors
    else {
        panic!("specific error required")
    };
    assert_eq!(
        (
            payload.code,
            payload.text.as_str(),
            payload.name.as_str(),
            payload.reason.as_str()
        ),
        (406, "not-acceptable", "subject", "too-long")
    );
    for children in [
        vec![Node::new("field", &[("name", "subject")], vec![])],
        vec![
            Node::new("field", &[], vec![]),
            Node::new("field", &[], vec![]),
        ],
    ] {
        let mut node = error("406", Some("not-acceptable"));
        node.children[0].children = children;
        let MakeSetSubjectRequestResponse::ClientError(value) = subject
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap()
        else {
            panic!("client error required")
        };
        let Some(
            MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorFallbackClient(
                payload,
            ),
        ) = value.error_set_subject_client_errors
        else {
            panic!("source disjunction must fall through")
        };
        assert_eq!(
            (payload.code, payload.text.as_str()),
            (406, "not-acceptable")
        );
    }
}
#[test]
fn binary_error_content_reaches_fallback() {
    let subject = specs().0;
    let mut response = error("406", Some("not-acceptable"));
    response.children[0].bytes = Some(b"opaque".to_vec());
    // The optionalChildWithTag path rejects Uint8Array before code/text.
    // SetSubjectClientErrors then tries the 400..499 fallback, which succeeds.
    let MakeSetSubjectRequestResponse::ClientError(value) = subject
        .parse_response_with_request(&response.as_ref(), "req-1", "123@g.us")
        .unwrap()
    else {
        panic!("client error required")
    };
    assert!(
        matches!(
            value.error_set_subject_client_errors,
            Some(
                MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorFallbackClient(
                    _
                )
            )
        ),
        "binary error content must reach fallback: {value:?}"
    );
}

#[test]
fn absent_and_empty_binary_error_content_remain_distinct() {
    let subject = specs().0;
    for binary in [None, Some(vec![])] {
        let mut response = error("406", Some("not-acceptable"));
        response.children[0].bytes = binary.clone();
        let MakeSetSubjectRequestResponse::ClientError(value) = subject
            .parse_response_with_request(&response.as_ref(), "req-1", "123@g.us")
            .unwrap()
        else {
            panic!("client error required")
        };
        let specific = matches!(value.error_set_subject_client_errors,
            Some(MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorNotAcceptable(_)));
        let fallback = matches!(value.error_set_subject_client_errors,
            Some(MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorFallbackClient(_)));
        assert_eq!(specific, binary.is_none(), "{value:?}");
        assert_eq!(fallback, binary.is_some(), "{value:?}");
    }
    // Parsers that inspect only attributes must still accept binary content.
    for bytes in [vec![], b"opaque".to_vec()] {
        let mut response = error("499", Some("unknown"));
        response.children[0].bytes = Some(bytes);
        assert_eq!(subject_class(&response).unwrap(), "client");
        assert_eq!(accept_class(&response).unwrap(), "client");
    }
}
