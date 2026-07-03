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
