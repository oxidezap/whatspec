#![allow(dead_code, unused_imports)]
// Deliberately small adapter for the existing reference emitter. No external
// client dependency: attributes and child lookup are ordinary in-memory values.
extern crate self as wacore_binary;
use std::collections::BTreeMap;
#[derive(Debug, Clone, Default)]
pub struct Node {
    pub tag: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<Node>,
    pub bytes: Option<Vec<u8>>,
}
#[derive(Clone, Copy)]
pub struct NodeRef<'a> {
    node: &'a Node,
}
impl Node {
    fn new(tag: &str, attrs: &[(&str, &str)], children: Vec<Node>) -> Self {
        Self {
            tag: tag.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            children,
            bytes: None,
        }
    }
    fn as_ref(&self) -> NodeRef<'_> {
        NodeRef { node: self }
    }
}
impl<'a> NodeRef<'a> {
    pub fn tag(&self) -> &'a str {
        &self.node.tag
    }
    pub fn get_attr(&self, name: &str) -> Option<&'a String> {
        self.node.attrs.get(name)
    }
    pub fn get_optional_child(&self, tag: &str) -> Option<NodeRef<'a>> {
        self.node
            .children
            .iter()
            .find(|n| n.tag == tag)
            .map(Node::as_ref)
    }
    pub fn get_children_by_tag(&self, tag: &'a str) -> impl Iterator<Item = NodeRef<'a>> {
        self.node
            .children
            .iter()
            .filter(move |n| n.tag == tag)
            .map(Node::as_ref)
    }
    pub fn content_bytes(&self) -> Option<&'a [u8]> {
        self.node.bytes.as_deref()
    }
    pub fn content_str(&self) -> Option<&'a str> {
        self.node
            .bytes
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
    }
}
pub mod jid {
    #[derive(Debug, Clone)]
    pub enum Server {
        Pn,
        Group,
    }
    #[derive(Debug, Clone)]
    pub struct Jid(pub String);
    impl Jid {
        pub fn new(user: &str, server: Server) -> Self {
            let server = match server {
                Server::Pn => "s.whatsapp.net",
                Server::Group => "g.us",
            };
            Self(if user.is_empty() {
                server.into()
            } else {
                format!("{user}@{server}")
            })
        }
    }
    impl std::fmt::Display for Jid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }
}
pub mod node {
    #[derive(Debug, Clone)]
    pub enum NodeContent {
        Nodes(Vec<crate::Node>),
    }
}
pub mod builder {
    pub struct NodeBuilder(crate::Node);
    impl NodeBuilder {
        pub fn new(tag: &str) -> Self {
            Self(crate::Node {
                tag: tag.into(),
                ..Default::default()
            })
        }
        pub fn attr(mut self, name: &str, value: impl std::fmt::Display) -> Self {
            self.0.attrs.insert(name.into(), value.to_string());
            self
        }
        pub fn bytes(mut self, bytes: Vec<u8>) -> Self {
            self.0.bytes = Some(bytes);
            self
        }
        pub fn build(self) -> crate::Node {
            self.0
        }
    }
}
pub mod request {
    pub struct InfoQuery<'a> {
        pub namespace: &'a str,
        pub target: crate::jid::Jid,
        pub content: Option<crate::node::NodeContent>,
        pub kind: &'static str,
    }
    impl<'a> InfoQuery<'a> {
        pub fn set(
            namespace: &'a str,
            target: crate::jid::Jid,
            content: Option<crate::node::NodeContent>,
        ) -> Self {
            Self {
                namespace,
                target,
                content,
                kind: "set",
            }
        }
        pub fn get(
            namespace: &'a str,
            target: crate::jid::Jid,
            content: Option<crate::node::NodeContent>,
        ) -> Self {
            Self {
                namespace,
                target,
                content,
                kind: "get",
            }
        }
    }
}
pub mod iq {
    pub mod spec {
        pub trait IqSpec {
            type Response;
            fn build_iq(&self) -> crate::request::InfoQuery<'static>;
            fn parse_response(
                &self,
                response: &crate::NodeRef<'_>,
            ) -> Result<Self::Response, anyhow::Error>;
        }
    }
}
#[path = "generated.rs"]
mod generated;
use generated::w_g2::*;
use iq::spec::IqSpec;
fn result(children: Vec<Node>) -> Node {
    Node::new(
        "iq",
        &[("type", "result"), ("id", "req-1"), ("from", "123@g.us")],
        children,
    )
}
fn error(code: &str, text: Option<&str>) -> Node {
    let mut child = Node::new("error", &[("code", code)], vec![]);
    if let Some(text) = text {
        child.attrs.insert("text".into(), text.into());
    }
    let mut node = result(vec![child]);
    node.attrs.insert("type".into(), "error".into());
    node
}
fn main() {
    let target = jid::Jid::new("123", jid::Server::Group);
    let subject = MakeSetSubjectRequestSpec::new(target.clone(), b"new subject".to_vec());
    let accept = MakeAcceptGroupAddRequestSpec::new(
        "invite",
        12345,
        &jid::Jid::new("456", jid::Server::Pn),
        target.clone(),
    );
    let request = subject.build_iq();
    assert_eq!(request.target.0, "123@g.us");
    assert_eq!(request.namespace, "w:g2");
    assert_eq!(request.kind, "set");
    let node::NodeContent::Nodes(nodes) = request.content.unwrap();
    assert_eq!(nodes[0].tag, "subject");
    assert_eq!(nodes[0].bytes.as_deref(), Some(b"new subject".as_slice()));
    let request = accept.build_iq();
    assert_eq!(request.target.0, "123@g.us");
    let node::NodeContent::Nodes(nodes) = request.content.unwrap();
    assert_eq!(nodes[0].attrs["code"], "invite");
    assert_eq!(nodes[0].attrs["expiration"], "12345");
    assert_eq!(nodes[0].attrs["admin"], "456@s.whatsapp.net");
    let guarded = MakeGuardedPayloadSpec::new(target.clone(), Vec::<u8>::new());
    let plain = MakeGuardedPlainSpec::new(target.clone(), Vec::<u8>::new());
    let content = MakeGuardedContentSpec::new(target.clone(), Vec::<u8>::new());
    let mut good = result(vec![Node::new("proof", &[], vec![])]);
    good.attrs.insert("marker".into(), "present".into());
    good.attrs.insert("scope".into(), "group".into());
    assert!(
        guarded
            .parse_response_with_request(&good.as_ref(), "req-1", "123@g.us")
            .is_ok()
    );
    assert!(plain.parse_response(&good.as_ref()).is_ok());
    for mutation in 0..7 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.tag = "message".into(),
            1 => {
                bad.attrs.remove("marker");
            }
            2 => {
                bad.attrs.insert("scope".into(), "other".into());
            }
            3 => bad.children.clear(),
            4 => bad.children.push(bad.children[0].clone()),
            5 => {
                bad.children.clear();
                bad.bytes = Some(vec![]);
            }
            _ => {
                bad.attrs.insert("type".into(), "error".into());
            }
        }
        assert!(
            guarded
                .parse_response_with_request(&bad.as_ref(), "req-1", "123@g.us")
                .is_err(),
            "context mutation {mutation}"
        );
        assert!(
            plain.parse_response(&bad.as_ref()).is_err(),
            "plain mutation {mutation}"
        );
    }
    good.children.clear();
    good.bytes = Some(b"accepted".to_vec());
    assert!(
        content
            .parse_response_with_request(&good.as_ref(), "req-1", "123@g.us")
            .is_ok()
    );
    good.bytes = Some(b"other".to_vec());
    assert!(
        content
            .parse_response_with_request(&good.as_ref(), "req-1", "123@g.us")
            .is_err()
    );
    good.bytes = None;
    assert!(
        content
            .parse_response_with_request(&good.as_ref(), "req-1", "123@g.us")
            .is_err()
    );

    let coverage = MakePayloadCoverageSpec::new(target.clone(), Vec::<u8>::new());
    for code in ["410", "470"] {
        for body in [vec![], b"opaque".to_vec(), vec![0xff]] {
            let mut node = error(code, Some("unknown"));
            node.children[0].bytes = Some(body);
            assert!(matches!(
                coverage
                    .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                    .unwrap(),
                MakePayloadCoverageResponse::FallbackError(_)
            ));
        }
        for malformed in [
            vec![Node::new("field", &[("name", "subject")], vec![])],
            vec![
                Node::new("field", &[], vec![]),
                Node::new("field", &[], vec![]),
            ],
        ] {
            let mut node = error(code, Some("unknown"));
            node.children[0].children = malformed;
            assert!(matches!(
                coverage
                    .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                    .unwrap(),
                MakePayloadCoverageResponse::FallbackError(_)
            ));
        }
        let node = error(code, Some("unknown"));
        assert!(!matches!(
            coverage
                .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                .unwrap(),
            MakePayloadCoverageResponse::FallbackError(_)
        ));
    }
    let bare = result(vec![]);
    assert!(subject.parse_response(&bare.as_ref()).is_err());
    assert!(accept.parse_response(&bare.as_ref()).is_err());
    assert!(matches!(
        subject
            .parse_response_with_request(&bare.as_ref(), "req-1", "123@g.us")
            .unwrap(),
        MakeSetSubjectRequestResponse::Success(_)
    ));
    assert!(matches!(
        accept
            .parse_response_with_request(&bare.as_ref(), "req-1", "123@g.us")
            .unwrap(),
        MakeAcceptGroupAddRequestResponse::Success(_)
    ));
    let approval = result(vec![Node::new("membership_approval_request", &[], vec![])]);
    assert!(matches!(
        accept
            .parse_response_with_request(&approval.as_ref(), "req-1", "123@g.us")
            .unwrap(),
        MakeAcceptGroupAddRequestResponse::GroupJoinRequestSuccess(_)
    ));
    let extension = result(vec![Node::new("future_extension", &[], vec![])]);
    assert!(matches!(
        accept
            .parse_response_with_request(&extension.as_ref(), "req-1", "123@g.us")
            .unwrap(),
        MakeAcceptGroupAddRequestResponse::Success(_)
    ));
    for (code, text, client) in [
        ("304", "already-exists", true),
        ("400", "bad-request", true),
        ("499", "future-client-error", true),
        ("500", "resource-constraint", true),
        ("500", "internal-server-error", false),
        ("500", "future-server-error", false),
        ("599", "future-server-error", false),
    ] {
        let node = error(code, Some(text));
        let parsed = accept
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap();
        assert_eq!(
            matches!(parsed, MakeAcceptGroupAddRequestResponse::ClientError(_)),
            client,
            "{code} {text}"
        );
        if !client {
            assert!(matches!(
                parsed,
                MakeAcceptGroupAddRequestResponse::ServerError(_)
            ));
        }
    }
    for (code, text) in [
        ("304", Some("wrong-text")),
        ("399", Some("unknown")),
        ("600", Some("unknown")),
        ("not-int", Some("unknown")),
        ("400", None),
    ] {
        let node = error(code, text);
        assert!(
            accept
                .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                .is_err(),
            "{code} {text:?}"
        );
    }
    for encoded in ["0304", "+304", " 304tail", "\u{feff}304", "304.9", "304e7"] {
        let node = error(encoded, Some("already-exists"));
        assert!(
            matches!(
                accept
                    .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                    .unwrap(),
                MakeAcceptGroupAddRequestResponse::ClientError(_)
            ),
            "{encoded}"
        );
    }
    let mut duplicate = error("500", Some("internal-server-error"));
    duplicate.children.push(duplicate.children[0].clone());
    assert!(
        accept
            .parse_response_with_request(&duplicate.as_ref(), "req-1", "123@g.us")
            .is_err()
    );
    let duplicate_approval = result(vec![
        Node::new("membership_approval_request", &[], vec![]),
        Node::new("membership_approval_request", &[], vec![]),
    ]);
    assert!(matches!(
        accept
            .parse_response_with_request(&duplicate_approval.as_ref(), "req-1", "123@g.us")
            .unwrap(),
        MakeAcceptGroupAddRequestResponse::Success(_)
    ));
    // WASmaxInGroupsSetSubjectClientErrors continues after any specific parser
    // failure, including malformed/duplicate optional <field>, into 400..499.
    let valid_field = Node::new(
        "field",
        &[("name", "subject"), ("reason", "invalid")],
        vec![],
    );
    for (fields, specific) in [
        (vec![], true),
        (vec![valid_field.clone()], true),
        (
            vec![Node::new("field", &[("name", "subject")], vec![])],
            false,
        ),
        (vec![valid_field.clone(), valid_field], false),
    ] {
        let mut node = error("406", Some("not-acceptable"));
        node.children[0].children = fields;
        let MakeSetSubjectRequestResponse::ClientError(value) = subject
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap()
        else {
            panic!("expected client error");
        };
        match value.error_set_subject_client_errors.unwrap() {
            MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorNotAcceptable(
                value,
            ) => {
                assert!(specific);
                assert_eq!(value.code, 406);
            }
            MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorFallbackClient(
                value,
            ) => {
                assert!(!specific);
                assert_eq!(value.code, 406);
                assert_eq!(value.text, "not-acceptable");
            }
            _ => panic!("unexpected error arm"),
        }
    }
    // optionalChildWithTag first calls maybeChildren: binary content fails
    // even when empty. The surrounding disjunction then reaches fallback.
    for bytes in [vec![], b"opaque".to_vec(), vec![0xff]] {
        let mut node = error("406", Some("not-acceptable"));
        node.children[0].bytes = Some(bytes.clone());
        let MakeSetSubjectRequestResponse::ClientError(value) = subject
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap()
        else {
            panic!("expected client error");
        };
        assert!(matches!(
            value.error_set_subject_client_errors.unwrap(),
            MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorFallbackClient(_)
        ));

        // Attribute-only error arms do not call maybeChildren. Their binary
        // body must not trigger a blanket rejection or forced fallback.
        let mut node = error("400", Some("bad-request"));
        node.children[0].bytes = Some(bytes.clone());
        let MakeSetSubjectRequestResponse::ClientError(value) = subject
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap()
        else {
            panic!("expected client error");
        };
        assert!(matches!(
            value.error_set_subject_client_errors.unwrap(),
            MakeSetSubjectRequestClientErrorErrorSetSubjectClientErrors::IQErrorBadRequest(_)
        ));

        let mut node = error("500", Some("resource-constraint"));
        node.children[0].bytes = Some(bytes);
        assert!(matches!(
            accept
                .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
                .unwrap(),
            MakeAcceptGroupAddRequestResponse::ClientError(_)
        ));
    }
    for wire in ["id", "from"] {
        let mut invalid = bare.clone();
        invalid.attrs.remove(wire);
        assert!(
            accept
                .parse_response_with_request(&invalid.as_ref(), "req-1", "123@g.us")
                .is_err()
        );
        invalid.attrs.insert(wire.into(), "wrong".into());
        assert!(
            accept
                .parse_response_with_request(&invalid.as_ref(), "req-1", "123@g.us")
                .is_err()
        );
    }
    for code in ["400", "499", "500", "599"] {
        let node = error(code, Some("unknown-text"));
        let parsed = subject
            .parse_response_with_request(&node.as_ref(), "req-1", "123@g.us")
            .unwrap();
        match parsed {
            MakeSetSubjectRequestResponse::ClientError(value) => {
                assert!(value.error_set_subject_client_errors.is_some())
            }
            MakeSetSubjectRequestResponse::ServerError(value) => {
                assert!(value.error_server_errors.is_some())
            }
            _ => panic!("error must never become success"),
        }
    }
    assert!(
        subject
            .parse_response_with_request(&bare.as_ref(), "other-id", "123@g.us")
            .is_err()
    );
    assert!(
        subject
            .parse_response_with_request(&bare.as_ref(), "req-1", "999@g.us")
            .is_err()
    );
    let mut invalid = bare.clone();
    invalid.tag = "message".into();
    assert!(
        accept
            .parse_response_with_request(&invalid.as_ref(), "req-1", "123@g.us")
            .is_err()
    );
    invalid = bare;
    invalid.attrs.insert("type".into(), "set".into());
    assert!(
        accept
            .parse_response_with_request(&invalid.as_ref(), "req-1", "123@g.us")
            .is_err()
    );
}
