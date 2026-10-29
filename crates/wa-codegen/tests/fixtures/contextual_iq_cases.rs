fn sent(id: &str, to: &str) -> Node {
    Node::new("iq", &[("id", id), ("to", to)], vec![])
}
fn answer(id: &str, from: &str, kind: &str, children: Vec<Node>) -> Node {
    Node::new("iq", &[("id", id), ("from", from), ("type", kind)], children)
}

#[test]
fn sent_context_is_required_and_cannot_be_replaced_by_reply_attributes() {
    let spec = MakeSetSubjectRequestSpec::new(jid::Jid::new("123", jid::Server::Group), b"hello".to_vec());
    let request = sent("actual-id", "123@g.us");
    let reply = answer("actual-id", "123@g.us", "result", vec![]);
    assert!(spec.uses_contextual_response());
    assert!(spec.parse_response(&reply.as_ref()).is_err());
    assert!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_ok());
    for request in [sent("different-id", "123@g.us"), sent("actual-id", "456@g.us"), Node::new("iq", &[], vec![])] {
        assert!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_err());
    }
}

#[test]
fn linked_join_keeps_approval_precedence_and_null_optional_argument() {
    let spec = MakeJoinLinkedGroupRequestSpec::new(None, &jid::Jid::new("456", jid::Server::Group), jid::Jid::new("123", jid::Server::Group));
    let request = sent("actual-id", "123@g.us");
    for (count, approval) in [(0, false), (1, true), (2, false)] {
        let reply = answer("actual-id", "123@g.us", "result", (0..count).map(|_| Node::new("membership_approval_request", &[], vec![])).collect());
        let result = spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).unwrap();
        assert_eq!(matches!(result, MakeJoinLinkedGroupRequestResponse::GroupJoinRequestSuccess(_)), approval);
    }
    let built = spec.build_iq();
    let node::NodeContent::Nodes(children) = built.content.unwrap();
    assert!(!children[0].attrs.contains_key("type"));
    assert_eq!(children[0].attrs["jid"], "456@g.us");
}

#[test]
fn passive_requires_one_mode_child_and_literal_server() {
    let spec = generated::passive::MakeActiveIQRequestSpec;
    let request = sent("active-id", "s.whatsapp.net");
    for (count, good) in [(0, false), (1, true), (2, false)] {
        let reply = answer("active-id", "s.whatsapp.net", "result", (0..count).map(|_| Node::new("active", &[], vec![])).collect());
        assert_eq!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_ok(), good);
    }
    let wrong = answer("active-id", "g.us", "result", vec![Node::new("active", &[], vec![])]);
    assert!(spec.parse_response_with_context(&wrong.as_ref(), &request.as_ref()).is_err());
}

#[test]
fn active_matches_isolated_web_parser_on_all_recorded_inputs() {
    let spec = generated::passive::MakeActiveIQRequestSpec;
    let request = sent("sent", "s.whatsapp.net");
    for row in include_str!("active-oracle.tsv").lines() {
        let columns: Vec<_> = row.split('\t').collect();
        let attrs: Vec<_> = [("id", columns[0]), ("from", columns[1]), ("type", columns[2])].into_iter().filter(|(_,v)| *v != "-").collect();
        let count: usize = columns[3].parse().unwrap();
        let reply = Node::new("iq", &attrs, (0..count).map(|_| Node::new("active", &[], vec![])).collect());
        assert_eq!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_ok(), columns[4] == "true", "{row}");
    }
}

#[test]
fn country_code_has_required_payload_and_paired_error_literals() {
    use generated::md::*;
    let spec = MakeGetCountryCodeRequestSpec;
    let request = sent("country-id", "s.whatsapp.net");
    let reply = answer("country-id", "s.whatsapp.net", "result", vec![Node::new("country_code", &[("iso", "BR")], vec![])]);
    let MakeGetCountryCodeRequestResponse::GetCountryCodeResponse(value) = spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).unwrap() else { panic!("expected country code") };
    assert_eq!(value.country_code_iso, "BR");
    for (code, text, good) in [("400", "bad-request", true), ("500", "internal-server-error", true), ("400", "internal-server-error", false), ("500", "bad-request", false)] {
        let reply = answer("country-id", "s.whatsapp.net", "error", vec![Node::new("error", &[("code", code), ("text", text)], vec![])]);
        assert_eq!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_ok(), good);
    }
    let reply = answer("country-id", "s.whatsapp.net", "result", vec![]);
    assert!(spec.parse_response_with_context(&reply.as_ref(), &request.as_ref()).is_err());
}
