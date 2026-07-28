//! Hermetic tests over synthetic dispatcher modules that mirror the real
//! `WAWebCommsHandleLoggedInStanza` structure (two-level switch, `require(...)`
//! handler forwards, an `encrypt`-style sub-switch, and a `String(type)===…`
//! if-guard arm). End-to-end fidelity against the actual bundle is validated by
//! the `whatspec` regen, not here, so these stay offline and fast.

use super::*;

/// A realistic dispatcher: the `<iq>`/stanza-tag switch wrapping a
/// `switch(n.type)`, expressed inside a generator so `return yield …` parses.
const DISPATCHER: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebHandleDeviceNotification"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "receipt": return yield r("WAWebHandleReceipt")(e);
      case "notification": try {
        switch (n.type) {
          case "devices": return yield o("WAWebHandleDeviceNotification").handleDevicesNotification(e);
          case "newsletter": return yield r("WAWebHandleNewsletterNotification")(e);
          case "mediaretry": { var l = yield r("WAWebHandleMediaRetryNotification")(e); return l; }
          case "contacts": {
            var a = e.content;
            if (!Array.isArray(a) || !a.length) break;
            var ct = a[0].tag;
            if (ct === "invite") break;
            return yield r("WAWebHandleContactNotification")(e);
          }
          case "encrypt": {
            var _ = e.content;
            if (!Array.isArray(_) || !_.length) break;
            var f = _[0].tag;
            switch (f) {
              case "count": return yield r("WAWebHandlePreKeyLow")(e, t);
              case "digest": return yield r("WAWebHandleDigestKey")(e);
            }
            break;
          }
          case "psa":
            if (n.from != null) { return yield o("WAWebHandleQPSurfacesNotification").handleQPSurfacesNotification(e); }
            return yield r("WAWebHandlePsa")(e);
        }
        if (n.type != null && String(n.type) === "passkey_prologue_request")
          return yield o("WAWebShortcakeLinkingHandlePasskeyPrologueRequest").handlePasskeyPrologueRequestNotification(e);
      } catch (t) {} return g(e);
      case "presence": return r("WAWebHandlePresence")(e);
    }
  }); };
}, 1);
"#;

fn ir() -> NotifIr {
    extract_notif(DISPATCHER, "2.3000.test")
}

fn notif<'a>(ir: &'a NotifIr, ty: &str) -> &'a NotificationDef {
    ir.notifications
        .iter()
        .find(|n| n.notif_type == ty)
        .unwrap_or_else(|| panic!("notification type {ty:?} not extracted"))
}

#[test]
fn dispatcher_module_and_version_recorded() {
    let ir = ir();
    assert_eq!(
        ir.dispatcher_modules,
        vec!["WAWebCommsHandleLoggedInStanza".to_string()]
    );
    assert_eq!(ir.wa_version, "2.3000.test");
}

#[test]
fn stanza_tags_are_the_outer_switch_arms_sorted() {
    let ir = ir();
    let tags: Vec<&str> = ir.stanza_tags.iter().map(|t| t.tag.as_str()).collect();
    assert_eq!(tags, ["notification", "presence", "receipt"]);

    // A tag that forwards to a bare `require("Mod")(e)` → module, no method.
    let presence = ir.stanza_tags.iter().find(|t| t.tag == "presence").unwrap();
    assert_eq!(
        presence.handler_module.as_deref(),
        Some("WAWebHandlePresence")
    );
    assert_eq!(presence.handler_function, None);

    // The `notification` tag itself fans out (its only top-level return is the
    // `g(e)` fallback, which is not a handler) → no single handler.
    let notif_tag = ir
        .stanza_tags
        .iter()
        .find(|t| t.tag == "notification")
        .unwrap();
    assert_eq!(notif_tag.handler_module, None);
}

#[test]
fn notification_types_and_handlers() {
    let ir = ir();
    let types: Vec<&str> = ir
        .notifications
        .iter()
        .map(|n| n.notif_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "contacts",
            "devices",
            "encrypt",
            "mediaretry",
            "newsletter",
            "passkey_prologue_request",
            "psa"
        ]
    );

    // `require("Mod").method(e)` → module + method.
    let devices = notif(&ir, "devices");
    assert_eq!(
        devices.handler_module.as_deref(),
        Some("WAWebHandleDeviceNotification")
    );
    assert_eq!(
        devices.handler_function.as_deref(),
        Some("handleDevicesNotification")
    );
    assert!(devices.sub_discriminants.is_empty());

    // `require("Mod")(e)` → module, no method.
    let newsletter = notif(&ir, "newsletter");
    assert_eq!(
        newsletter.handler_module.as_deref(),
        Some("WAWebHandleNewsletterNotification")
    );
    assert_eq!(newsletter.handler_function, None);
}

#[test]
fn handler_bound_to_a_local_then_returned_is_resolved() {
    // `case "mediaretry": { var l = yield handler(e); return l; }` — the handler is
    // bound to a local before the `return`, not returned directly.
    let ir = ir();
    let mr = notif(&ir, "mediaretry");
    assert_eq!(
        mr.handler_module.as_deref(),
        Some("WAWebHandleMediaRetryNotification")
    );
    assert_eq!(mr.handler_function, None);
}

#[test]
fn contacts_handler_survives_leading_guards() {
    // The handler `return` sits after `if(...)break` guards and a `content[0].tag`
    // read that is NOT switched on — so no sub-discriminant, but the handler stands.
    let ir = ir();
    let contacts = notif(&ir, "contacts");
    assert_eq!(
        contacts.handler_module.as_deref(),
        Some("WAWebHandleContactNotification")
    );
    assert!(
        contacts.sub_discriminants.is_empty(),
        "a bare `content[0].tag` guard is not a sub-switch"
    );
}

#[test]
fn encrypt_has_first_child_tag_sub_discriminant() {
    let ir = ir();
    let encrypt = notif(&ir, "encrypt");
    // It dispatches via the sub-switch, so no single primary handler.
    assert_eq!(encrypt.handler_module, None);
    assert_eq!(encrypt.sub_discriminants.len(), 1);
    let sd = &encrypt.sub_discriminants[0];
    assert_eq!(sd.on, SubDiscriminantOn::FirstChildTag);
    let cases: Vec<(&str, Option<&str>)> = sd
        .cases
        .iter()
        .map(|c| (c.value.as_str(), c.handler_module.as_deref()))
        .collect();
    // Sorted by value: count, digest.
    assert_eq!(
        cases,
        [
            ("count", Some("WAWebHandlePreKeyLow")),
            ("digest", Some("WAWebHandleDigestKey")),
        ]
    );
}

#[test]
fn psa_primary_is_the_top_level_return_not_the_conditional_one() {
    // `psa` has a conditional `if(...) return handleQPSurfaces...` and a top-level
    // `return r("WAWebHandlePsa")(e)`. The primary handler is the unconditional one.
    let ir = ir();
    let psa = notif(&ir, "psa");
    assert_eq!(psa.handler_module.as_deref(), Some("WAWebHandlePsa"));
    assert!(psa.sub_discriminants.is_empty());
}

#[test]
fn if_guarded_string_type_arm_is_captured() {
    // `String(n.type) === "passkey_prologue_request"` dispatches outside the switch.
    let ir = ir();
    let pk = notif(&ir, "passkey_prologue_request");
    assert_eq!(
        pk.handler_module.as_deref(),
        Some("WAWebShortcakeLinkingHandlePasskeyPrologueRequest")
    );
    assert_eq!(
        pk.handler_function.as_deref(),
        Some("handlePasskeyPrologueRequestNotification")
    );
}

#[test]
fn content_absent_when_handler_module_missing() {
    // The catalog references handler modules by name; when those modules aren't in
    // the scanned source, content is simply absent (degraded), catalog intact.
    let ir = ir();
    assert!(ir.notifications.iter().all(|n| n.content.is_none()));
}

/// A handler module with a real `WADeprecatedWapParser`, to exercise Phase-2
/// content attachment.
const DEVICE_HANDLER: &str = r#"
__d("WAWebHandleDeviceNotification",["WADeprecatedWapParser"],function(g,r,d,o,e,i,l){
  var h = new (r("WADeprecatedWapParser"))("incomingDevicesNotification", function(t){
    t.assertTag("notification");
    t.assertAttr("type", "devices");
    t.attrString("id");
    var c = t.child("add");
    c.attrInt("count");
  });
  l.handleDevicesNotification = function(n){ return h.parse(n); };
}, 3);
"#;

#[test]
fn content_attached_from_handler_parser() {
    // With the handler module present, `devices` picks up its typed content shape
    // from `incomingDevicesNotification` — reusing the IQ parser-body analysis.
    let src = format!("{DISPATCHER}\n{DEVICE_HANDLER}");
    let ir = extract_notif(&src, "v");
    let devices = notif(&ir, "devices");
    let content = devices
        .content
        .as_ref()
        .expect("devices content parsed from handler");
    assert_eq!(content.parser_name, "incomingDevicesNotification");
    // Assertions carry the discriminators (tag + type).
    assert!(
        content
            .assertions
            .iter()
            .any(|a| a.name.as_deref() == Some("notification"))
    );
    assert!(
        content
            .assertions
            .iter()
            .any(|a| a.value.as_deref() == Some("devices"))
    );
    // Fields: a top-level `id` and a nested `add > count`.
    assert!(content.fields.iter().any(|f| f.name == "id"));
    let add = content
        .fields
        .iter()
        .find(|f| f.tag.as_deref() == Some("add"))
        .expect("add child field");
    assert!(
        add.children
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.name == "count")
    );

    // Handlers whose module is absent stay degraded (content None).
    assert!(notif(&ir, "newsletter").content.is_none());
}

/// A second (worker-compatible) dispatcher, mirroring WA Web's split: it adds a
/// `w:gp2` group arm and an `encrypt`→`identity` sub-case, and wraps handlers in
/// `promiseWrapper(handler(t)).catch(fn)`.
const WORKER_DISPATCHER: &str = r#"
__d("WAWebCommsHandleWorkerCompatibleStanza",[],function(g,r,d,o,e,i,l){
  l.h = function(){ return (function*(t,x){
    var a = t.attrs;
    switch (t.tag) {
      case "notification": {
        switch (a.type) {
          case "w:gp2": return e(o("WAWebHandleGroupNotification").handleGroupNotification(t)).catch(function(z){ return z; });
          case "encrypt": {
            var i2 = t.content;
            if (!Array.isArray(i2) || !i2.length) break;
            var l2 = i2[0].tag;
            switch (l2) {
              case "identity": return e(o("WAWebHandleIdentityChange").handleE2eIdentityChange(t)).catch(function(z){ return z; });
            }
            break;
          }
        }
        break;
      }
    }
  }); };
}, 4);
"#;

#[test]
fn merges_arms_across_multiple_dispatchers() {
    // WA Web splits notification handling across dispatchers; the catalog is the
    // union. `w:gp2` (only in the worker dispatcher) must appear, and `encrypt`'s
    // sub-discriminant must gain `identity` on top of `count`/`digest`.
    let combined = format!("{DISPATCHER}\n{WORKER_DISPATCHER}");
    let ir = extract_notif(&combined, "v");

    assert_eq!(
        ir.dispatcher_modules,
        vec![
            "WAWebCommsHandleLoggedInStanza".to_string(),
            "WAWebCommsHandleWorkerCompatibleStanza".to_string(),
        ]
    );

    // w:gp2 recovered from the second dispatcher, through the `.catch()` wrapper.
    let gp2 = notif(&ir, "w:gp2");
    assert_eq!(
        gp2.handler_module.as_deref(),
        Some("WAWebHandleGroupNotification")
    );
    assert_eq!(
        gp2.handler_function.as_deref(),
        Some("handleGroupNotification")
    );

    // encrypt's sub-cases are the union across both dispatchers.
    let encrypt = notif(&ir, "encrypt");
    let cases: Vec<&str> = encrypt.sub_discriminants[0]
        .cases
        .iter()
        .map(|c| c.value.as_str())
        .collect();
    assert_eq!(cases, ["count", "digest", "identity"]);
    let identity = encrypt.sub_discriminants[0]
        .cases
        .iter()
        .find(|c| c.value == "identity")
        .unwrap();
    assert_eq!(
        identity.handler_module.as_deref(),
        Some("WAWebHandleIdentityChange")
    );
}

#[test]
fn non_dispatcher_module_yields_empty() {
    let src =
        r#"__d("WAWebNope",[],function(g,r,d,o,e,i,l){ l.x = function(){ return 1; }; }, 1);"#;
    let ir = extract_notif(src, "v");
    assert!(ir.dispatcher_modules.is_empty());
    assert!(ir.stanza_tags.is_empty());
    assert!(ir.notifications.is_empty());
}

/// A handler module that defines parsers for TWO notification types — the wrong
/// one (`other`) first — to exercise type-matched content selection.
const MULTI_PARSER_HANDLER: &str = r#"
__d("WAWebHandleDeviceNotification",["WADeprecatedWapParser"],function(g,r,d,o,e,i,l){
  var other = new (r("WADeprecatedWapParser"))("incomingOtherNotification", function(t){
    t.assertTag("notification");
    t.assertAttr("type", "other");
    t.attrString("wrong");
  });
  var dev = new (r("WADeprecatedWapParser"))("incomingDevicesNotification", function(t){
    t.assertTag("notification");
    t.assertAttr("type", "devices");
    t.attrString("id");
  });
  l.handleDevicesNotification = function(n){ return dev.parse(n); };
}, 3);
"#;

#[test]
fn content_selected_by_type_when_module_has_multiple_parsers() {
    // The module defines the `other` parser before the `devices` one; selection
    // must match on assertAttr("type","devices"), not take the first
    // notification-asserting parser.
    let src = format!("{DISPATCHER}\n{MULTI_PARSER_HANDLER}");
    let ir = extract_notif(&src, "v");
    let content = notif(&ir, "devices")
        .content
        .as_ref()
        .expect("devices content");
    assert_eq!(content.parser_name, "incomingDevicesNotification");
    assert!(content.fields.iter().any(|f| f.name == "id"));
    assert!(
        !content.fields.iter().any(|f| f.name == "wrong"),
        "picked the wrong type's parser"
    );
}

/// A handler module with TWO notification-asserting parsers, neither pinned to the
/// requested `devices` type — the ambiguous case that must stay degraded.
const AMBIGUOUS_HANDLER: &str = r#"
__d("WAWebHandleDeviceNotification",["WADeprecatedWapParser"],function(g,r,d,o,e,i,l){
  var a = new (r("WADeprecatedWapParser"))("incomingA", function(t){
    t.assertTag("notification");
    t.attrString("aField");
  });
  var b = new (r("WADeprecatedWapParser"))("incomingB", function(t){
    t.assertTag("notification");
    t.attrString("bField");
  });
  l.handleDevicesNotification = function(n){ return a.parse(n); };
}, 3);
"#;

#[test]
fn ambiguous_multi_parser_module_stays_degraded() {
    // Two notification-asserting parsers, neither asserting type="devices": we must
    // not guess one of them — the entry degrades to no content.
    let src = format!("{DISPATCHER}\n{AMBIGUOUS_HANDLER}");
    let ir = extract_notif(&src, "v");
    assert!(
        notif(&ir, "devices").content.is_none(),
        "attached a sibling parser's shape to an ambiguous module"
    );
}

/// A dispatcher with a trailing `if (mode === "sentinel")` that is NOT a `.type`
/// comparison — it must not be mistaken for a notification type.
const PHANTOM_IF_DISPATCHER: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",[],function(g,r,d,o,e,i,l){
  l.h = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification": try {
        switch (n.type) {
          case "devices": return yield o("WAWebHandleDeviceNotification").handleDevicesNotification(e);
        }
        if (n.type != null && String(n.type) === "passkey_prologue_request")
          return yield o("WAWebShortcakeLinkingHandlePasskeyPrologueRequest").handlePasskeyPrologueRequestNotification(e);
        var mode = e.attrs.mode;
        if (mode === "sentinel") return yield r("WAWebBogus")(e);
      } catch (t) {}
    }
  }); };
}, 1);
"#;

#[test]
fn unrelated_string_equality_does_not_mint_a_phantom_type() {
    let ir = extract_notif(PHANTOM_IF_DISPATCHER, "v");
    let types: Vec<&str> = ir
        .notifications
        .iter()
        .map(|n| n.notif_type.as_str())
        .collect();
    // The real arms are captured…
    assert!(types.contains(&"devices"));
    assert!(types.contains(&"passkey_prologue_request"));
    // …but a `mode === "sentinel"` guard (not a `.type` comparison) is not a type.
    assert!(
        !types.contains(&"sentinel"),
        "phantom type leaked from a non-`.type` equality: {types:?}"
    );
}

/// A dispatcher whose `sideeffect` arm stashes a module call in a temp and then
/// `break`s without returning it — the temp must not be read as the handler.
const SIDE_EFFECT_DISPATCHER: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",[],function(g,r,d,o,e,i,l){
  l.h = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification": try {
        switch (n.type) {
          case "sideeffect": { var tmp = o("WAWebSomeJob").run(e); break; }
          case "devices": return yield o("WAWebHandleDeviceNotification").handleDevicesNotification(e);
        }
      } catch (t) {}
    }
  }); };
}, 1);
"#;

#[test]
fn helper_stashed_in_temp_but_not_returned_is_not_the_handler() {
    let ir = extract_notif(SIDE_EFFECT_DISPATCHER, "v");
    assert_eq!(
        notif(&ir, "sideeffect").handler_module,
        None,
        "a non-returned temp initializer is not the primary handler"
    );
    // The sibling arm that does return its handler still resolves.
    assert_eq!(
        notif(&ir, "devices").handler_module.as_deref(),
        Some("WAWebHandleDeviceNotification")
    );
}

#[test]
fn extraction_is_deterministic() {
    // Same input → byte-identical serialization (stable sort keys).
    let a = serde_json::to_string(&ir()).unwrap();
    let b = serde_json::to_string(&ir()).unwrap();
    assert_eq!(a, b);
}

/// A `<notification type="waffle">` handler that delegates to the smax receive-RPC
/// path (no inline `WADeprecatedWapParser`) plus the matching `WASmaxIn*Request`
/// read-shape module, so Phase 2b recovers the content from the srvreq domain.
const SRVREQ_LINK_BUNDLE: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebAccountLinkingNotificationHandler"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification":
        switch (n.type) {
          case "waffle": return yield r("WAWebAccountLinkingNotificationHandler")(e);
        }
    }
  }); };
}, 1);
__d("WASmaxInWaffleWFNotificationRequest",["WAResultOrError","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").assertAttr(e,"type","waffle");if(!n.success)return n;var s=o("WASmaxParseUtils").attrString(e,"id");return s.success?o("WAResultOrError").makeResult({id:s.value}):s}l.parseWFNotificationRequest=e}),1);
"#;

#[test]
fn srvreq_read_shape_recovers_degraded_notification_content() {
    let ir = extract_notif(SRVREQ_LINK_BUNDLE, "2.3000.test");
    let content = notif(&ir, "waffle")
        .content
        .as_ref()
        .expect("waffle content recovered from the srvreq read-shape");
    assert_eq!(content.parser_name, "parseWFNotificationRequest");
    assert!(content.fields.iter().any(|f| f.name == "id"));
}

#[test]
fn ambiguous_srvreq_type_leaves_notification_degraded() {
    // Two request modules assert the same `type="hosted"`; without a unique shape the
    // notification stays degraded rather than binding to an arbitrary one.
    let bundle = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebHandleHostedNotification"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification":
        switch (n.type) {
          case "hosted": return yield r("WAWebHandleHostedNotification")(e);
        }
    }
  }); };
}, 1);
__d("WASmaxInCoexistenceOnboardingStatusNotificationRequest",["WAResultOrError","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").assertAttr(e,"type","hosted");if(!n.success)return n;var s=o("WASmaxParseUtils").attrString(e,"a");return s.success?o("WAResultOrError").makeResult({a:s.value}):s}l.parseOnboardingStatusNotificationRequest=e}),1);
__d("WASmaxInCoexistenceOffboardingNotificationRequest",["WAResultOrError","WASmaxParseUtils"],(function(t,n,r,o,a,i,l){function e(e){var t=o("WASmaxParseUtils").assertTag(e,"notification");if(!t.success)return t;var n=o("WASmaxParseUtils").assertAttr(e,"type","hosted");if(!n.success)return n;var s=o("WASmaxParseUtils").attrString(e,"b");return s.success?o("WAResultOrError").makeResult({b:s.value}):s}l.parseOffboardingNotificationRequest=e}),1);
"#;
    let ir = extract_notif(bundle, "2.3000.test");
    assert!(
        notif(&ir, "hosted").content.is_none(),
        "an ambiguous type (two read-shapes) must stay degraded"
    );
}

/// A miniature `w:gp2` handler: the const tag/action tables in their own modules, and a
/// handler that maps over the notification's children and switches on each child's tag.
/// Reproduces every shape the real one uses — a many-to-one normalisation, a rebound
/// field name, a constant-only arm, a repeated sub-element, and a two-outcome ternary.
const GROUP_ACTIONS_BUNDLE: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebHandleGroupNotification","WAWebHandleDeviceNotification"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification":
        switch (n.type) {
          case "w:gp2": return yield r("WAWebHandleGroupNotification")(e);
          case "devices": return yield o("WAWebHandleDeviceNotification").handleDevicesNotification(e);
        }
    }
  }); };
}, 1);
__d("WAWebHandleDeviceNotification",["WADeprecatedWapParser"],(function(t,n,r,o,a,i,l){
  var p = new (n("WADeprecatedWapParser"))("incomingDevicesNotification", function(e){
    e.assertTag("notification"); e.assertAttr("type","devices");
    return { id: e.attrString("id") };
  });
  function I(e){
    var t=e.attrString("unlink_type");
    if(t==="parent_group") return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_REMOVE, descId:e.attrString("id")};
    return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_ADD, descId:e.attrString("id")};
  }
  function h(e){ return p.parse(e); }
  l.handleDevicesNotification = h;
}), 1);
__d("WAWebHandleGroupNotificationConst",[],(function(t,n,r,o,a,i,l){
  var cache={};
  cache.GROUP_NOTIFICATION_TAG={ADD:"WRONG_add",SUBJECT:"WRONG_subject"};
  var e=Object.freeze({ADD:"add",SUBJECT:"subject",EPHEMERAL:"ephemeral",NOT_EPHEMERAL:"not_ephemeral",MODIFY:"modify",GROWTH_LOCKED:"growth_locked",INVITE:"invite",LINK:"link",ANNOUNCE:"announcement",LOCKED:"locked",REVOKE_INVITE:"revoke",DESC:"description",UNLINK:"unlink"});
  l.GROUP_NOTIFICATION_TAG=e;
}), 1);
__d("WAWebGroupApiConst",[],(function(t,n,r,o,a,i,l){
  var g={admin:"admin",superadmin:"superadmin",participant:"participant"};
  l.GROUP_PARTICIPANT_TYPES=g;
}), 1);
__d("WAWebGroupType",[],(function(t,n,r,o,a,i,l){
  var d=Object.freeze({ADD:"add",SUBJECT:"subject",EPHEMERAL:"ephemeral",MODIFY:"modify",ANNOUNCE:"announce",RESTRICT:"restrict",REVOKE_INVITE:"revoke_invite",DESC_ADD:"desc_add",DESC_REMOVE:"desc_remove"});
  l.GROUP_ACTIONS=d;
}), 1);
__d("WAWebHandleGroupNotification",["WAWebHandleGroupNotificationConst","WAWebGroupType"],(function(t,n,r,o,a,i,l){
  function w(e){ if (e.hasChild("a")) return {alpha:e.attrString("alpha")}; return {beta:e.attrString("beta")}; }
  function q(e){ return e.mapChildrenWithTag("entry", function(x){
    if (x.hasChild("full")) return {id:x.attrString("id"), extra:x.attrString("extra"), who:x.attrString("jid")};
    if (x.hasChild("mid")) return {id:x.attrString("id"), who:x.attrString("lid")};
    return {id:x.attrString("id"), who:x.attrString("jid")};
  }); }
  function q2(e){
    if (e.hasChild("a")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.ANNOUNCE, rows:e.mapChildrenWithTag("row", function(x){ return {v:x.attrString("p")}; })};
    if (e.hasChild("b")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.ANNOUNCE, rows:e.mapChildrenWithTag("row", function(x){ return {v:x.attrString("q")}; })};
    return {actionType:o("WAWebGroupType").GROUP_ACTIONS.ANNOUNCE, rows:e.mapChildrenWithTag("row", function(x){ return {v:x.attrString("p")}; })};
  }
  function y(e,t){ return t.mapChildrenWithTag("participant", function(p){
    return { id: p.attrUserJid("jid"), displayName: p.maybeAttrString("display_name"), kind: p.maybeAttrEnum("type", o("WAWebGroupApiConst").GROUP_PARTICIPANT_TYPES) };
  }); }
  function I(e){
    var t=e.attrString("unlink_type");
    if(t==="parent_group") return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_REMOVE, descId:e.attrString("id")};
    return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_ADD, descId:e.attrString("id")};
  }
  function h(e){
    var x = e.mapChildren(function(t){
      var a = t.tag();
      switch(a){
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.ADD:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.ADD, participants:y(e,t), reason:t.hasAttr("reason")?t.attrString("reason"):null};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.SUBJECT:
          if (t.hasChild("delete")) { var n = t.attrString("id"); return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_REMOVE, descId:n}; }
          var n = t.attrString("subject");
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SUBJECT, subject:n, note:t.hasAttr("note")&&t.attrString("note")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.EPHEMERAL:
          return babelHelpers.extends({actionType:o("WAWebGroupType").GROUP_ACTIONS.EPHEMERAL, duration:t.attrInt("expiration"), code:t.attrString("code")||"none"}, w(t));
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.NOT_EPHEMERAL:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.EPHEMERAL, duration:0};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.MODIFY: {
          var z = t.attrString("first");
          if (t.hasChild("early")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.MODIFY, entries:q(t), pick:z};
          var z = t.attrString("second");
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.RESTRICT, pick:z};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.ANNOUNCE:
          return q2(t);
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.INVITE:
          o("WALogger").INFO("no fall-through"); break;
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.LINK: {
          var lt = t.attrString("link_type");
          switch (lt) {
            case "parent": return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_ADD, parentId:t.attrString("pid")};
            default: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_REMOVE, subId:t.attrString("sid")};
          }
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.GROWTH_LOCKED:
          o("WALogger").INFO("setup");
          var thr = t.attrString("threshold");
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.LOCKED: {
          var n;
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.RESTRICT, value:!0, threshold:(n=t.maybeAttrString("threshold"))!=null?n:void 0, seeded:thr};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.UNLINK:
          return I(t);
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.REVOKE_INVITE:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.REVOKE_INVITE, participants:t.mapChildrenWithTag("participant", function(p){ return {id:p.attrUserJid("jid"), expiration:p.attrInt("expiration")}; }), owners:t.mapChildrenWithTag("owner", p=>o("WAWebJidToWid").userJidToUserWid(p.maybeAttrPhoneUserJid("phone_number")))};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.DESC:
          return t.hasChild("delete") ? {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_REMOVE, descId:t.attrString("id")}
                                      : {actionType:o("WAWebGroupType").GROUP_ACTIONS.DESC_ADD, descId:t.attrString("id"), desc:t.child("body").contentString()};
      }
    });
    return {actions:x};
  }
  l.handleGroupNotification=h;
}), 1);
"#;

/// The `w:gp2` action union, keyed by the wire tag of each arm.
fn group_actions(ir: &wa_ir::NotifIr) -> Vec<&wa_ir::NotifActionDef> {
    notif(ir, "w:gp2").actions.iter().collect()
}

#[test]
fn group_action_union_records_the_many_to_one_tag_mapping() {
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let actions = group_actions(&ir);
    let of = |tag: &str| {
        actions
            .iter()
            .filter(|a| a.wire_tag == tag)
            .collect::<Vec<_>>()
    };
    // Acceptance criterion: which wire tags map to `ephemeral`, and what each sets.
    let eph = of("ephemeral");
    assert_eq!(eph.len(), 1);
    assert_eq!(eph[0].action_type.as_deref(), Some("ephemeral"));
    let duration = eph[0]
        .fields
        .iter()
        .find(|f| f.name == "duration")
        .expect("duration field");
    // The timer arrives in `expiration`, NOT under the output name — the whole point.
    assert_eq!(duration.wire_name, "expiration");
    assert_eq!(duration.field_type, wa_ir::ParsedFieldType::Integer);
    assert!(duration.required);
    // `not_ephemeral` normalises INTO `ephemeral` with a constant 0 — a consumer that
    // branches on a `not_ephemeral` action type is writing dead code.
    let not_eph = of("not_ephemeral");
    assert_eq!(not_eph.len(), 1);
    assert_eq!(not_eph[0].action_type.as_deref(), Some("ephemeral"));
    assert!(not_eph[0].fields.is_empty());
    assert_eq!(
        not_eph[0].constant_fields,
        vec![wa_ir::NotifActionConstant {
            name: "duration".into(),
            value: wa_ir::NotifConstValue::Int(0),
        }]
    );
    // `locked` renames too, and stamps a boolean constant.
    let locked = of("locked");
    assert_eq!(locked[0].action_type.as_deref(), Some("restrict"));
    assert_eq!(
        locked[0].constant_fields[0].value,
        wa_ir::NotifConstValue::Bool(true)
    );
}

#[test]
fn group_action_arms_recover_fields_children_and_branches() {
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let actions = group_actions(&ir);
    let one = |tag: &str| {
        actions
            .iter()
            .find(|a| a.wire_tag == tag)
            .unwrap_or_else(|| panic!("no arm for {tag}"))
    };
    // A presence-guarded attr is optional; an unguarded one is required.
    let add = one("add");
    let reason = add
        .fields
        .iter()
        .find(|f| f.name == "reason")
        .expect("reason");
    assert!(!reason.required, "hasAttr(…) ? … : null → optional");
    // The participant list lives behind a module-local helper; it must still be
    // recovered, with the per-participant fields.
    let participants = add
        .children
        .iter()
        .find(|c| c.name == "participants")
        .expect("participants child");
    assert_eq!(participants.wire_tag, "participant");
    let names: Vec<&str> = participants
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(names, ["id", "displayName", "kind"]);
    assert_eq!(
        participants.fields[0].field_type,
        wa_ir::ParsedFieldType::UserJid
    );
    // An inline (non-helper) mapped child works the same way.
    assert_eq!(one("revoke").children[0].wire_tag, "participant");
    // An arm that branches into two DIFFERENT actions yields two arms of the union,
    // sharing the wire tag — not one arm with the first branch's shape.
    let desc: Vec<_> = actions
        .iter()
        .filter(|a| a.wire_tag == "description")
        .collect();
    let types: Vec<&str> = desc
        .iter()
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert_eq!(types, ["desc_remove", "desc_add"]);
    // The `<body>` content read is flagged as content, with the tag as its wire name.
    let body = desc[1]
        .fields
        .iter()
        .find(|f| f.name == "desc")
        .expect("desc");
    assert!(body.content);
    assert_eq!(body.wire_name, "body");
}

#[test]
fn handler_without_a_const_keyed_switch_has_no_actions() {
    // Most handlers forward straight to a `WADeprecatedWapParser` and carry no action
    // union; they must not sprout a phantom one. The fixture dispatches `devices`
    // alongside `w:gp2` precisely so this assertion actually runs — with only `w:gp2` in
    // the bundle the loop body would never execute and the property would go untested.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let others: Vec<&str> = ir
        .notifications
        .iter()
        .filter(|n| n.notif_type != "w:gp2")
        .map(|n| n.notif_type.as_str())
        .collect();
    assert!(
        others.contains(&"devices"),
        "fixture must dispatch a second, action-less type or this test is vacuous"
    );
    for n in &ir.notifications {
        if n.notif_type != "w:gp2" {
            assert!(n.actions.is_empty(), "{} grew actions", n.notif_type);
        }
    }
}

#[test]
fn a_null_coalesced_field_keeps_its_wire_source() {
    // The minifier hides the accessor in the ternary's TEST:
    // `(n = child.maybeAttrString("threshold")) != null ? n : void 0`. Following the
    // consequent alone finds a bare `n` that nothing binds, and the field vanishes —
    // which is exactly how `locked`'s `threshold` was being lost.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let locked = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "locked")
        .expect("locked arm");
    let threshold = locked
        .fields
        .iter()
        .find(|f| f.name == "threshold")
        .expect("threshold field");
    assert_eq!(threshold.wire_name, "threshold");
    assert!(!threshold.required, "read behind a null-coalesce guard");
}

#[test]
fn a_helper_returning_several_actions_yields_several_arms() {
    // `case UNLINK: return I(child)` delegates wholesale to a helper that branches into
    // DIFFERENT actions. Folding them into one definition keeps whichever `actionType`
    // resolved first and silently drops the rest, so the branches must surface as
    // sibling arms of the union — the same treatment an inline ternary gets.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let unlink: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "unlink")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert_eq!(unlink, ["desc_remove", "desc_add"]);
}

#[test]
fn a_branch_local_binding_is_in_scope_for_its_return() {
    // `var` is function-scoped, so a declaration inside an `if` block is in scope for the
    // return inside it. Now that returns are collected from nested branches, their locals
    // have to be too — otherwise `if (c) { var sid = child.attrString("id"); return
    // {descId: sid} }` yields a return whose `sid` resolves to nothing and is dropped.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let arm = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "subject" && a.action_type.as_deref() == Some("desc_remove"))
        .expect("the branch arm");
    let f = arm
        .fields
        .iter()
        .find(|f| f.name == "descId")
        .expect("descId");
    assert_eq!(f.wire_name, "id");
}

#[test]
fn an_expression_bodied_arrow_callback_yields_its_field() {
    // `p => wid(p.maybeAttrPhoneUserJid("phone_number"))` has no `return`: oxc stores the
    // body as a lone expression, so a return-only scan reported the repeated child with an
    // empty field list. The accessor also has to be typed as the PN user JID it is, not as
    // a bare string.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let owners = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "revoke")
        .expect("revoke arm")
        .children
        .iter()
        .find(|c| c.name == "owners")
        .expect("owners child");
    assert_eq!(owners.wire_tag, "owner");
    let f = owners.fields.first().expect("a field from the arrow body");
    assert_eq!(f.wire_name, "phone_number");
    assert_eq!(f.field_type, wa_ir::ParsedFieldType::UserJid);
    assert!(!f.required, "maybeAttr* is optional");
}

#[test]
fn sibling_branches_rebinding_a_name_each_keep_their_own_accessor() {
    // The minifier reuses short names across mutually exclusive branches. A single
    // flattened scope would make one branch's return read the OTHER branch's attribute —
    // a wrong `wireName`, not a missing field, which is the failure mode this module
    // refuses everywhere else. Each return therefore resolves in its own scope.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let arms: Vec<_> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "subject")
        .collect();
    let wire = |action: &str, field: &str| {
        arms.iter()
            .find(|a| a.action_type.as_deref() == Some(action))
            .and_then(|a| a.fields.iter().find(|f| f.name == field))
            .map(|f| f.wire_name.as_str())
    };
    // Both branches bind `n`, to different attributes.
    assert_eq!(wire("desc_remove", "descId"), Some("id"));
    assert_eq!(wire("subject", "subject"), Some("subject"));
}

#[test]
fn a_logical_and_guard_reads_its_value_operand() {
    // `child.hasAttr("note") && child.attrString("note")` carries the value on the RIGHT.
    // Taking the left yields `hasAttr`, which is deliberately not a wire accessor, so the
    // field disappeared.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let note = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "subject")
        .find_map(|a| a.fields.iter().find(|f| f.name == "note"))
        .expect("note field");
    assert_eq!(note.wire_name, "note");
}

#[test]
fn an_action_enum_field_carries_its_variants() {
    // `maybeAttrEnum("type", o("Mod").GROUP_PARTICIPANT_TYPES)` — a bare `"type": "enum"`
    // says the value is constrained but not to what, leaving an emitter to guess.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let kind = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "add")
        .expect("add arm")
        .children
        .iter()
        .find(|c| c.name == "participants")
        .expect("participants")
        .fields
        .iter()
        .find(|f| f.name == "kind")
        .expect("kind field");
    // The accessor is an enum accessor, so the field is typed as one — the `enumRef`
    // hangs off a field a consumer filtering on `type == "enum"` will actually reach.
    assert_eq!(kind.field_type, wa_ir::ParsedFieldType::Enum);
    let er = kind.enum_ref.as_ref().expect("resolved enum");
    assert_eq!(er.name, "GROUP_PARTICIPANT_TYPES");
    let values: Vec<&str> = er.variants.iter().map(|v| v.value.as_str()).collect();
    assert_eq!(values, ["admin", "superadmin", "participant"]);
}

#[test]
fn a_value_position_helper_weakens_its_branch_only_fields() {
    // A helper used as an `extends` operand can return mutually exclusive shapes.
    // Accumulating them makes the enclosing action require BOTH and reject either legal
    // payload, so the branches are merged with the same optionality rule the switch arms
    // use: a field only some branches carry is optional.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let eph = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "ephemeral")
        .expect("ephemeral arm");
    let f = |name: &str| eph.fields.iter().find(|f| f.name == name);
    for name in ["alpha", "beta"] {
        let field = f(name).unwrap_or_else(|| panic!("{name} recovered"));
        assert!(!field.required, "{name} comes from only one branch");
    }
    // The arm's own unconditional read stays required.
    assert!(f("duration").expect("duration").required);
}

#[test]
fn a_defaulted_read_stays_required() {
    // `child.attrString("code") || "none"` still calls `attrString`, which rejects an
    // absent attribute — the right operand only defaults a value the parser already
    // demanded. Classifying every logical expression as a presence guard marked it
    // optional.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let code = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "ephemeral")
        .expect("ephemeral arm")
        .fields
        .iter()
        .find(|f| f.name == "code")
        .expect("code field");
    assert_eq!(code.wire_name, "code");
    assert!(code.required, "`a || default` is not a presence guard");
}

#[test]
fn a_const_table_on_a_non_export_receiver_is_ignored() {
    // `cache.GROUP_NOTIFICATION_TAG = {…}` written before the real
    // `exports.GROUP_NOTIFICATION_TAG = …` would otherwise be taken as the export and,
    // being first, kept — resolving case labels through an unrelated table and minting
    // wrong wire tags. Only the module factory's own parameters count as receivers.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let tags: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .map(|a| a.wire_tag.as_str())
        .collect();
    assert!(tags.contains(&"add"), "the real table must win: {tags:?}");
    assert!(
        !tags.iter().any(|t| t.starts_with("WRONG_")),
        "decoy table leaked into the catalog: {tags:?}"
    );
}

#[test]
fn a_branching_mapped_child_callback_weakens_its_branch_only_fields() {
    // A callback returning different objects from an `if` describes alternative element
    // shapes. Flattening every property in the body into one list marks a field read in
    // only one branch as required, so a consumer would reject a legal element.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let entries = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "modify")
        .expect("modify arm")
        .children
        .iter()
        .find(|c| c.name == "entries")
        .expect("entries child");
    let f = |name: &str| entries.fields.iter().find(|f| f.name == name);
    assert!(f("id").expect("id").required, "read by every branch");
    assert!(!f("extra").expect("extra").required, "read by one branch");
}

#[test]
fn a_return_sees_only_the_bindings_that_ran_before_it() {
    // `var z = attr("first"); if (c) return {pick:z}; var z = attr("second"); return
    // {pick:z}` — hoisting moves the declaration, not the assignment, so the early return
    // reads `first`. A scope built as a pre-pass over the whole statement list installs
    // the later initializer first and reports both returns as reading `second`.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let pick = |action: &str| {
        notif(&ir, "w:gp2")
            .actions
            .iter()
            .filter(|a| a.wire_tag == "modify")
            .find(|a| a.action_type.as_deref() == Some(action))
            .and_then(|a| a.fields.iter().find(|f| f.name == "pick"))
            .map(|f| f.wire_name.as_str())
    };
    assert_eq!(
        pick("modify"),
        Some("first"),
        "the early return ran before the rebind"
    );
    assert_eq!(pick("restrict"), Some("second"));
}

#[test]
fn a_key_bound_to_different_wire_reads_is_dropped_not_guessed() {
    // Two branches binding `who` to different attributes (`jid` and `lid`) have no single
    // answer — publishing the first branch'"'"'s attribute would describe the other branch'"'"'s
    // payload wrongly, and this is the JID conflation the repo treats as
    // protocol-safety-critical. The key is dropped instead.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let entries = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "modify")
        .expect("modify arm")
        .children
        .iter()
        .find(|c| c.name == "entries")
        .expect("entries child");
    let names: Vec<&str> = entries.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(
        !names.contains(&"who"),
        "a conflicting source must be refused, not resolved to the first branch: {names:?}"
    );
    // The unambiguous keys still merge normally.
    let f = |n: &str| entries.fields.iter().find(|f| f.name == n);
    assert!(f("id").expect("id").required, "read by every branch");
    assert!(!f("extra").expect("extra").required, "read by one branch");
}

#[test]
fn a_fall_through_label_with_setup_still_inherits_the_shared_action() {
    // `case GROWTH_LOCKED: log(); case SUSPENDED: return {…}` — the first label has a
    // non-empty body that produces no shape and falls through. Treating "non-empty" as
    // "its own arm" lost the action type and every field of a legally dispatched tag.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let arm = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "growth_locked")
        .expect("growth_locked arm");
    assert_eq!(
        arm.action_type.as_deref(),
        Some("restrict"),
        "must inherit the body it falls through into"
    );
    assert!(!arm.constant_fields.is_empty(), "including its constants");
}

#[test]
fn a_third_branch_cannot_resurrect_a_conflicted_key() {
    // A(jid) vs B(lid) tombstones `who`; without a tombstone that outlives the single
    // merge, C(jid) sees nothing there and adds it back — and the union again advertises
    // one source while another legal branch reads a different attribute.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let entries = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "modify")
        .expect("modify arm")
        .children
        .iter()
        .find(|c| c.name == "entries")
        .expect("entries child");
    let names: Vec<&str> = entries.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(
        !names.contains(&"who"),
        "the third branch must not resurrect the conflict: {names:?}"
    );
    assert!(names.contains(&"id"), "unambiguous keys survive: {names:?}");
}

#[test]
fn a_terminating_case_does_not_borrow_the_next_action() {
    // `case INVITE: log(); break;` does not fall through. Scanning past the `break` for
    // "the next case that yields a shape" would publish that action under `invite`, a
    // shape the tag never produces.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let invite: Vec<_> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "invite")
        .collect();
    assert_eq!(invite.len(), 1);
    assert_eq!(
        invite[0].action_type, None,
        "a terminating arm produces no shape of its own, and must borrow none"
    );
    assert!(invite[0].fields.is_empty() && invite[0].children.is_empty());
}

#[test]
fn an_arm_selecting_through_a_nested_switch_yields_both_actions() {
    // `case UNLINK: switch (linkType) { case "parent": return {…}; default: return {…} }`
    // describes two legal actions for one wire tag. Skipping nested switches — which the
    // walk used to do, on the theory that they are a different dispatch level — left the
    // arm empty.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let mut got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "link")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    got.sort_unstable();
    assert_eq!(got, ["desc_add", "desc_remove"]);
}

#[test]
fn a_child_field_conflict_survives_a_third_branch() {
    // The alternative rule lives in ONE place now, so a conflict inside a MAPPED CHILD
    // gets the same tombstone the top-level scalars do. Before, the child merge created a
    // fresh conflict set per call — the same defect as the outer level, one layer down —
    // so `A(p)` vs `B(q)` removed `v` and `C(p)` put it back.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let rows = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "announcement")
        .expect("announcement arm")
        .children
        .iter()
        .find(|c| c.name == "rows")
        .expect("rows child");
    let names: Vec<&str> = rows.fields.iter().map(|f| f.name.as_str()).collect();
    assert!(
        !names.contains(&"v"),
        "a child field two branches disagree on must stay refused: {names:?}"
    );
}

#[test]
fn a_fall_through_label_contributes_its_own_bindings() {
    // `case A: var thr = child.attrString("threshold"); case B: return {…, seeded: thr}`
    // — the A path binds before falling through, so handing the shape only B's body
    // dropped the field. The chain now carries every statement it executes.
    let ir = extract_notif(GROUP_ACTIONS_BUNDLE, "2.3000.test");
    let seeded = notif(&ir, "w:gp2")
        .actions
        .iter()
        .find(|a| a.wire_tag == "growth_locked")
        .expect("growth_locked arm")
        .fields
        .iter()
        .find(|f| f.name == "seeded")
        .expect("the binding from the fall-through label");
    assert_eq!(seeded.wire_name, "threshold");
}

/// A second `w:gp2` handler covering the shapes the real bundle does not exercise today.
///
/// Every behaviour below is **latent** against the pinned bundle — the constructs are
/// legal, WA writes some of them elsewhere, and the extractor got them wrong — so a
/// fixture is the only thing that can hold the fix in place. Without it a later
/// refactor would silently restore the old answer and `generated/` would not move.
const GROUP_ACTIONS_EDGE_BUNDLE: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebHandleGroupNotification"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification":
        switch (n.type) {
          case "w:gp2": return yield r("WAWebHandleGroupNotification")(e);
        }
    }
  }); };
}, 1);
__d("WAWebHandleGroupNotificationConst",[],(function(t,n,r,o,a,i,l){
  l.GROUP_NOTIFICATION_TAG=Object.freeze({EVICT:"evict",COND:"cond",REBIND:"rebind",PICK:"pick",BARE:"bare",HELPER:"helper",ESCAPE:"escape",TAIL:"tail",JOIN:"join",SEQ:"seq",SUFFIX:"suffix",AFTER:"after",TRY:"try_tag",FIN:"fin",FINCOND:"fincond",FINTHROW:"finthrow",MULTI:"multi",MULTI3:"multi3",DEAD:"dead",LIT:"lit",LOOP:"loop_tag",FINTRY:"fintry",PARAM:"param",BLK:"blk",EXH:"exh",NFT:"nft",LATE:"late",DOW:"dow",SHADOW:"shadow",CATCHP:"catchp",DOWX:"dowx"});
}), 1);
__d("WAWebGroupType",[],(function(t,n,r,o,a,i,l){
  l.GROUP_ACTIONS=Object.freeze({FIRST:"first",SECOND:"second",THIRD:"third"});
}), 1);
__d("WAWebHandleGroupNotification",["WAWebHandleGroupNotificationConst","WAWebGroupType"],(function(t,n,r,o,a,i,l){
  function hlp(e){ return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, extra:e.attrString("extra")}; }
  function norm(v){ return v == null ? null : v; }
  function h(e){
    var x=e.mapChildrenWithTag("child", function(t){
      switch (t.tag) {
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.EVICT:
          return babelHelpers.extends({actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:t.attrString("jid")}, {id:0});
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.COND:
          if (t.hasChild("early")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.PICK:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, b:t.attrString("b")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.REBIND: {
          var v=t.attrString("jid");
          v=t.attrString("lid");
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, id:v};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.BARE:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, who:t.mapChildrenWithTag("p", function(p){ return p.hasChild("z") ? p.attrString("jid") : p.attrString("lid"); })};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.HELPER:
          return babelHelpers.extends({actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST}, hlp(t));
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.ESCAPE:
          switch (t.attrString("k")) {
            case "a": if (t.hasChild("q")) break; return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, e1:t.attrString("e1")};
            default: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, e2:t.attrString("e2")};
          }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.TAIL:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, t1:t.attrString("t1")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.JOIN: {
          var j=t.attrString("jid");
          if (t.hasChild("alt")) j=t.attrString("lid");
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:j};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.TRY:
          try { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, ok:t.attrString("ok")}; }
          catch (e) { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, err:t.attrString("err")}; }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.FIN:
          try { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")}; }
          finally { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, f:t.attrString("f")}; }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.FINCOND:
          try { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")}; }
          finally { if (t.hasChild("z")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, b:t.attrString("b")}; }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.FINTHROW:
          try { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")}; }
          finally { throw new Error("x"); }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.MULTI:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, id:combine(t.attrString("jid"), t.attrString("lid")), plain:t.attrString("plain")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.MULTI3:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:combine(t.attrString("jid"), t.attrString("jid"), t.attrString("lid")), plain:t.attrString("plain")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.DEAD:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")};
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, b:t.attrString("b")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.LIT:
          return {actionType:"create", who:t.attrString("who")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.LOOP:
          while (t.hasChild("more")) { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, l:t.attrString("l")}; }
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, m:t.attrString("m")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.FINTRY: {
          var fx = t.attrString("jid");
          try { fx = t.attrString("lid"); } finally { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, id:fx}; }
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.PARAM:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, reason:t.hasAttr("reason")?norm(t.attrString("reason")):null};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.BLK: {
          var bx = t.attrString("jid");
          { bx = t.attrString("lid"); }
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:bx};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.EXH:
          if (t.hasChild("q")) return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")};
          else return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, b:t.attrString("b")};
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, c:t.attrString("c")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.NFT: {
          var nx;
          switch (t.attrString("k")) {
            case "a": nx = t.attrString("jid");
            default: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:nx};
          }
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.LATE: {
          var lr;
          lr = {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:t.attrString("jid")};
          return lr;
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.DOW: {
          var dw;
          do { dw = t.attrString("lid"); } while (t.hasChild("again"));
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, id:dw};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.SHADOW: {
          var sh = t.attrString("jid");
          { let sh = t.attrString("lid"); }
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, id:sh};
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.CATCHP: {
          var e2 = t.attrString("jid");
          try { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, id:e2}; }
          catch (e2) { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, id:e2}; }
        }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.DOWX:
          do { return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, a:t.attrString("a")}; } while (t.hasChild("again"));
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, b:t.attrString("b")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.SUFFIX:
          switch (t.attrString("k")) {
            case "a": t.attrString("setup");
            default: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, s:t.attrString("s")};
          }
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.AFTER:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.THIRD, a1:t.attrString("a1")};
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.SEQ: {
          var s1, s2;
          s1=t.attrString("jid"), s2=t.attrInt("n");
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.SECOND, id:s1, n:s2};
        }
      }
    });
    return {actions:x};
  }
  l.handleGroupNotification=h;
}), 1);
"#;

/// The single action arm for `tag` in the edge-case bundle.
fn edge_action<'a>(ir: &'a wa_ir::NotifIr, tag: &str) -> &'a wa_ir::NotifActionDef {
    let mut found = notif(ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == tag);
    let a = found
        .next()
        .unwrap_or_else(|| panic!("no action arm for wire tag {tag:?}"));
    assert!(found.next().is_none(), "expected one arm for {tag:?}");
    a
}

#[test]
fn a_later_write_evicts_the_key_from_every_collection() {
    // `extends({id: attrString("jid")}, {id: 0})` yields only `id: 0` at runtime.
    // Replacing within each collection separately published BOTH a wire-read field and a
    // constant named `id` — a shape no execution produces.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "evict");
    assert!(
        !a.fields.iter().any(|f| f.name == "id"),
        "the constant must evict the earlier wire read: {:?}",
        a.fields
    );
    assert_eq!(
        a.constant_fields.iter().filter(|c| c.name == "id").count(),
        1,
        "exactly one `id`, and it is the constant"
    );
}

#[test]
fn a_conditionally_returning_case_still_falls_through() {
    // `case COND: if (cond) return FIRST; case PICK: return SECOND;` — tag `cond` can
    // legally produce either. Stopping at the first shape published only FIRST.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let cond: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "cond")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert!(
        cond.contains(&"second"),
        "the fall-through target must be reachable from `cond`: {cond:?}"
    );
}

#[test]
fn a_reassignment_replaces_the_declared_binding() {
    // `var v = attrString("jid"); v = attrString("lid"); return {id: v}` reads `lid`.
    // Tracking declarations only left the initializer installed.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "rebind");
    let id = a
        .fields
        .iter()
        .find(|f| f.name == "id")
        .expect("the `id` field survives the reassignment");
    assert_eq!(
        id.wire_name, "lid",
        "the value at the return is the reassigned one"
    );
}

#[test]
fn a_bare_callback_read_is_optional_when_only_one_branch_takes_it() {
    // `p => cond ? p.attrString("jid") : p.attrString("lid")` reads exactly one per
    // element. The bare-value fallback bypassed the branch fold and marked both required.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "bare");
    let child = a
        .children
        .iter()
        .find(|c| c.name == "who")
        .expect("the mapped child is recovered");
    // Asserted before the requiredness check: `all` on an empty list is vacuously true,
    // and this is exactly the path that could regress to recovering no fields at all.
    let names: Vec<&str> = child.fields.iter().map(|f| f.wire_name.as_str()).collect();
    assert!(
        names.contains(&"jid") && names.contains(&"lid"),
        "both alternative reads survive the fold: {names:?}"
    );
    assert!(
        child.fields.iter().all(|f| !f.required),
        "a read taken on only one branch is not required: {:?}",
        child.fields
    );
}

#[test]
fn a_helper_operand_replaces_the_earlier_action_type() {
    // `extends({actionType: FIRST}, hlp(t))` where the helper returns SECOND yields
    // SECOND at runtime. Copying the helper's `actionType` only into an empty slot
    // dispatched the shape as FIRST.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "helper");
    assert_eq!(
        a.action_type.as_deref(),
        Some("second"),
        "the later operand wins, `actionType` included"
    );
}

#[test]
fn a_nested_break_path_keeps_the_outer_fall_through() {
    // `case "a": if (cond) break; return FIRST;` inside a nested switch: the `break`
    // leaves only the INNER switch, so control resumes in the outer `escape` case and
    // falls through to `tail`. Treating the later `return` as proof that every path
    // exited hid that action.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "escape")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert!(
        got.contains(&"third"),
        "the break path falls through to the next outer case: {got:?}"
    );
}

#[test]
fn a_binding_reassigned_in_one_branch_is_not_reported_as_certain() {
    // `var j = attrString("jid"); if (c) j = attrString("lid"); return {id: j}` reads
    // `lid` on one legal path. Keeping the pre-branch binding published `jid` as fact.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "join");
    assert!(
        !a.fields
            .iter()
            .any(|f| f.name == "id" && f.wire_name == "jid"),
        "the branch write must not leave `jid` asserted: {:?}",
        a.fields
    );
}

#[test]
fn a_comma_sequence_of_assignments_binds_every_operand() {
    // The minifier writes runs of assignments as one `SequenceExpression`
    // (`s1 = t.attrString("jid"), s2 = t.attrInt("n")`); matching only a bare assignment
    // statement skipped them all.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "seq");
    let wire = |name: &str| {
        a.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.wire_name.as_str())
    };
    assert_eq!(wire("id"), Some("jid"));
    assert_eq!(wire("n"), Some("n"));
}

#[test]
fn a_nested_case_exits_through_its_own_fall_through_suffix() {
    // `case "a": setup(); default: return X` — the `a` path runs `setup()` and falls into
    // the default's return, so the switch DOES leave the enclosing case on every path.
    // Requiring each nested case body to exit on its own (accepting only an empty
    // fall-through label) called it non-terminating, and `suffix` then borrowed the
    // following outer case's action for a wire tag that never produces it.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "suffix")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert!(got.contains(&"first"), "its own action survives: {got:?}");
    assert!(
        !got.contains(&"third"),
        "and it must not borrow the next case's: {got:?}"
    );
}

#[test]
fn a_catch_block_return_is_a_legal_action() {
    // WA wraps a parse in `try { … } catch (e) { … }` and the handler's return is as
    // legal as the body's. Walking only the `try` body omitted the error path entirely.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "try_tag")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert!(got.contains(&"first"), "the try body's action: {got:?}");
    assert!(got.contains(&"second"), "and the catch's: {got:?}");
}

#[test]
fn a_returning_finally_overrides_the_try_body() {
    // A `finally` that returns discards whatever `try`/`catch` produced — it is the only
    // shape the statement can yield, so reporting the body's would be a shape no
    // execution reaches.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "fin")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert_eq!(got, ["third"], "only the finalizer's shape: {got:?}");
}

#[test]
fn a_conditional_finally_leaves_the_try_result_legal() {
    // `try { return A } finally { if (c) return B }` returns A when `c` is false. Deciding
    // the override by "did the finalizer yield any shape" reported only B.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let mut got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "fincond")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    got.sort_unstable();
    assert_eq!(got, ["first", "second"], "both paths are legal: {got:?}");
}

#[test]
fn a_throwing_finally_yields_no_shape_at_all() {
    // The mirror case: `finally { throw }` collects no returns, so emptiness read as
    // "no override" and the try body's shape was published although it never escapes.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "finthrow")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert!(got.is_empty(), "nothing is returned from this arm: {got:?}");
}

#[test]
fn a_wrapper_over_two_accessors_refuses_the_field() {
    // `combine(t.attrString("jid"), t.attrString("lid"))` derives its value from both, and
    // a field names ONE `wireName`. Taking the first stated as fact something the IR
    // cannot express; the sibling read on the same arm must still survive.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "multi");
    assert!(
        !a.fields.iter().any(|f| f.name == "id"),
        "the ambiguous key is refused: {:?}",
        a.fields
    );
    assert!(
        a.fields.iter().any(|f| f.name == "plain"),
        "and the unambiguous sibling is kept: {:?}",
        a.fields
    );
}

#[test]
fn a_conflict_past_the_second_wrapper_argument_still_refuses() {
    // `combine(a("jid"), a("jid"), a("lid"))` — the second read matches the first, so
    // comparing only those two accepted `jid` and never looked at the conflicting third.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "multi3");
    assert!(
        !a.fields.iter().any(|f| f.name == "id"),
        "every argument is inspected: {:?}",
        a.fields
    );
    assert!(
        a.fields.iter().any(|f| f.name == "plain"),
        "and the unambiguous sibling survives: {:?}",
        a.fields
    );
}

#[test]
fn a_return_after_an_unconditional_return_is_unreachable() {
    // `return A; return B;` — B never runs. Treating every syntactic return as reachable
    // published it as a second legal action for the tag, and let statements below the
    // return contribute fields too.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "dead")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert_eq!(got, ["first"], "only the reachable shape: {got:?}");
}

#[test]
fn a_literal_action_type_is_kept() {
    // `{actionType: "create"}` is fully static. Resolving only `o("Mod").OBJECT.MEMBER`
    // left the arm with no `actionType`, indistinguishable from one the arm computes.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "lit");
    assert_eq!(a.action_type.as_deref(), Some("create"));
}

#[test]
fn a_loop_body_return_is_collected() {
    // `while (c) { return A } return B` legally produces both. Loops fell into the
    // catch-all, so only B was emitted.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let mut got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "loop_tag")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    got.sort_unstable();
    assert_eq!(got, ["first", "second"], "both paths: {got:?}");
}

#[test]
fn a_finalizer_does_not_read_a_binding_the_try_overwrote() {
    // `var x = a("jid"); try { x = a("lid") } finally { return {id: x} }` returns `lid`.
    // Analyzing the finalizer against the pre-`try` scope published `jid` as fact; the
    // body may also have thrown part-way, so neither source is certain and the name is
    // tombstoned rather than guessed.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "fintry");
    assert!(
        !a.fields.iter().any(|f| f.wire_name == "jid"),
        "the stale pre-try source must not be published: {:?}",
        a.fields
    );
}

#[test]
fn a_helper_that_only_normalises_its_argument_keeps_the_wire_read() {
    // `reason: hasAttr("reason") ? norm(t.attrString("reason")) : null` — `norm` is a
    // module-local helper, so the inliner claimed the key, produced an empty shape
    // (the helper reads no attribute of its own) and dropped the field. Live for
    // `add`/`remove`/`delete`'s `reason` before the fallback to `read_field`.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "param");
    let f = a
        .fields
        .iter()
        .find(|f| f.name == "reason")
        .expect("the field survives the helper");
    assert_eq!(f.wire_name, "reason");
    assert!(!f.required, "it sits behind a presence guard");
}

#[test]
fn a_bare_block_hands_its_writes_back() {
    // A bare block always runs and `var` is function-scoped, so
    // `var x = a("jid"); { x = a("lid"); } return {id: x}` reads `lid`. Analyzing the
    // block against a clone discarded the write and published the pre-block source.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "blk");
    let f = a
        .fields
        .iter()
        .find(|f| f.name == "id")
        .expect("the id field");
    assert_eq!(
        f.wire_name, "lid",
        "the block's write is what reaches the return"
    );
}

#[test]
fn nothing_after_an_exhaustive_if_is_reachable() {
    // `if (c) return A; else return B; return C;` — C never runs. The direct-return stop
    // did not cover a statement that exits through both of its branches.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let mut got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "exh")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        ["first", "second"],
        "the trailing return is dead: {got:?}"
    );
}

#[test]
fn a_nested_case_carries_its_setup_to_the_case_it_falls_into() {
    // `case "a": nx = t.attrString("jid"); default: return {id: nx}` — the `a` path runs
    // the assignment and falls into the default's return. Analyzing each consequent
    // against the same incoming scope lost `id` on that path.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "nft");
    assert!(
        a.fields
            .iter()
            .any(|f| f.name == "id" && f.wire_name == "jid"),
        "the fall-through setup reaches the return: {:?}",
        a.fields
    );
}

/// A handler whose payload union is SMALLER than an unrelated const-keyed switch beside
/// it. Picking by arm count would publish the wrong one.
const DECOY_SWITCH_BUNDLE: &str = r#"
__d("WAWebCommsHandleLoggedInStanza",["WAWebHandleGroupNotification"],function(g,r,d,o,e,i,l){
  l.handle = function(){ return (function*(e,t){
    var n = e.attrs;
    switch (e.tag) {
      case "notification":
        switch (n.type) {
          case "w:gp2": return yield r("WAWebHandleGroupNotification")(e);
        }
    }
  }); };
}, 1);
__d("WAWebHandleGroupNotificationConst",[],(function(t,n,r,o,a,i,l){
  l.GROUP_NOTIFICATION_TAG=Object.freeze({REAL:"real"});
  l.OTHER=Object.freeze({A:"a",B:"b",C:"c",D:"d"});
}), 1);
__d("WAWebGroupType",[],(function(t,n,r,o,a,i,l){
  l.GROUP_ACTIONS=Object.freeze({FIRST:"first"});
}), 1);
__d("WAWebHandleGroupNotification",["WAWebHandleGroupNotificationConst","WAWebGroupType"],(function(t,n,r,o,a,i,l){
  function h(e){
    var mode = e.attrString("mode");
    switch (mode) {
      case o("WAWebHandleGroupNotificationConst").OTHER.A: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, x:e.attrString("x")};
      case o("WAWebHandleGroupNotificationConst").OTHER.B: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, y:e.attrString("y")};
      case o("WAWebHandleGroupNotificationConst").OTHER.C: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, z:e.attrString("z")};
      case o("WAWebHandleGroupNotificationConst").OTHER.D: return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, w:e.attrString("w")};
    }
  }
  function top(e){
    var x=e.mapChildren(function(t){
      var tg = t.tag();
      switch (tg) {
        case o("WAWebHandleGroupNotificationConst").GROUP_NOTIFICATION_TAG.REAL:
          return {actionType:o("WAWebGroupType").GROUP_ACTIONS.FIRST, real:t.attrString("real")};
      }
    });
    return {actions:x};
  }
  l.handleGroupNotification=top;
}), 1);
"#;

#[test]
fn the_action_union_is_the_switch_on_a_child_tag_not_the_biggest_one() {
    // A module can hold several const-keyed switches. Choosing by arm count let an
    // unrelated one — four returning arms against the union's one — publish its
    // constants as wire tags. The union is identified by dispatching on a child's TAG.
    let ir = extract_notif(DECOY_SWITCH_BUNDLE, "2.3000.test");
    let tags: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .map(|a| a.wire_tag.as_str())
        .collect();
    assert_eq!(
        tags,
        ["real"],
        "only the child-tag switch is the union: {tags:?}"
    );
}

#[test]
fn a_shape_assigned_after_its_declaration_is_still_static() {
    // `var lr; lr = {actionType: A, id: attr("jid")}; return lr` is fully static, but the
    // reassignment rule required the right-hand side to resolve to a wire ACCESSOR and
    // dropped the binding for an object literal, publishing an empty action.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "late");
    assert_eq!(a.action_type.as_deref(), Some("first"));
    assert!(
        a.fields
            .iter()
            .any(|f| f.name == "id" && f.wire_name == "jid"),
        "the whole shape survives: {:?}",
        a.fields
    );
}

#[test]
fn a_do_while_body_write_is_definite() {
    // A `do…while` body runs at least once, so every path reaching the return has run it.
    // Grouping it with the zero-or-more loops tombstoned the write and lost the field.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "dow");
    assert!(
        a.fields
            .iter()
            .any(|f| f.name == "id" && f.wire_name == "lid"),
        "the body's write reaches the return: {:?}",
        a.fields
    );
}

#[test]
fn a_block_scoped_shadow_does_not_escape_its_block() {
    // `var sh = a("jid"); { let sh = a("lid"); } return {id: sh}` reads `jid` — `let` dies
    // with its block. Propagating the block's scope wholesale (the `var` fix) leaked it.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let a = edge_action(&ir, "shadow");
    let f = a
        .fields
        .iter()
        .find(|f| f.name == "id")
        .expect("the id field");
    assert_eq!(
        f.wire_name, "jid",
        "the OUTER binding is what the return reads"
    );
}

#[test]
fn a_catch_parameter_shadows_the_outer_binding() {
    // The catch parameter IS the caught exception, not whatever the outer scope bound to
    // that name. Analyzing the handler against the unmodified scope published the catch
    // arm's `id` as a read of `jid`.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let second: Vec<_> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "catchp" && a.action_type.as_deref() == Some("second"))
        .collect();
    assert_eq!(second.len(), 1, "the catch arm is recovered");
    assert!(
        second[0].fields.is_empty(),
        "but its `id` resolves to the exception, not to `jid`: {:?}",
        second[0].fields
    );
}

#[test]
fn nothing_after_an_exiting_do_while_is_reachable() {
    // `do { return A } while (c); return B` — the body runs at least once and returns, so
    // B is dead. `stmt_exits` had no `do…while` arm, so traversal walked on and published
    // it as a second legal action.
    let ir = extract_notif(GROUP_ACTIONS_EDGE_BUNDLE, "2.3000.test");
    let got: Vec<&str> = notif(&ir, "w:gp2")
        .actions
        .iter()
        .filter(|a| a.wire_tag == "dowx")
        .filter_map(|a| a.action_type.as_deref())
        .collect();
    assert_eq!(got, ["first"], "only the reachable shape: {got:?}");
}
