//! Phase-1 AppState extraction: collections + deterministic per-action fields.

use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use regex::Regex;
use wa_ir::{AppstateAction, AppstateIr};

use crate::text::{skip_expr, skip_string, skip_ws};

const SYNCD_CONST: &str = "WASyncdConst";
const HANDLER_ACTIONS: &str = "WAWebCollectionHandlerActions";
const ASSERT_THIS: &str = "babelHelpers.assertThisInitialized";

// ─── Module body extraction ──────────────────────────────────────────────────

/// An index of `__d("<name>", ...)` body slices, built once. Replaces repeated
/// full-source `find` scans (which made appstate extraction ~O(actions × source)
/// and dominated runtime at ~2s).
struct ModuleBodies<'a> {
    map: HashMap<&'a str, &'a str>,
}

impl<'a> ModuleBodies<'a> {
    fn get(&self, name: &str) -> Option<&'a str> {
        self.map.get(name).copied()
    }

    /// Build from a pre-split module index (shares whatspec's single parse).
    fn from_modules(src: &'a str, module_defs: &'a [wa_transform::ModuleDefinition]) -> Self {
        let mut map: HashMap<&str, &str> = HashMap::with_capacity(module_defs.len());
        for d in module_defs {
            map.entry(d.name.as_str()).or_insert(&src[d.start..d.end]);
        }
        ModuleBodies { map }
    }

    /// Build by scanning `src` once for every `__d("name", ...)` call (first
    /// occurrence per name wins, matching the old `find_module_body`). String-aware
    /// so a `)` inside a literal can't truncate a body.
    fn scan(src: &'a str) -> Self {
        const NEEDLE: &str = "__d(\"";
        let b = src.as_bytes();
        let mut map: HashMap<&str, &str> = HashMap::new();
        let mut cursor = 0;
        while let Some(rel) = src[cursor..].find(NEEDLE) {
            let start = cursor + rel;
            let name_start = start + NEEDLE.len();
            let Some(qrel) = src[name_start..].find('"') else {
                break;
            };
            let name = &src[name_start..name_start + qrel];

            let mut depth = 0i32;
            let mut i = start;
            let mut end = None;
            while i < b.len() {
                match b[i] {
                    b'"' | b'\'' | b'`' => {
                        i = skip_string(b, i);
                        continue;
                    }
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            match end {
                Some(e) => {
                    map.entry(name).or_insert(&src[start..=e]);
                    cursor = e + 1; // skip past this module body
                }
                None => break,
            }
        }
        ModuleBodies { map }
    }
}

// ─── WASyncdConst: action key→wire name, collection key→wire name, constants ───

#[derive(Default)]
struct SyncdConst {
    actions: HashMap<String, String>,
    /// `(key, wire name)` in declared order (the order is the canonical list).
    collections: Vec<(String, String)>,
    constants: HashMap<String, i64>,
}

impl SyncdConst {
    fn collection(&self, key: &str) -> Option<String> {
        self.collections
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }
}

static IDENT_ONLY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z_$][\w$]*$").unwrap());
static SYNCD_CONST_CONST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bl\.([A-Z][A-Z0-9_]*)\s*=\s*([^,;]+)").unwrap());

fn parse_syncd_const(bodies: &ModuleBodies) -> SyncdConst {
    let Some(body) = bodies.get(SYNCD_CONST) else {
        return SyncdConst::default();
    };
    let actions = parse_enum_literal(body, "Actions").into_iter().collect();
    let collections = parse_enum_literal(body, "CollectionName");

    let mut constants = HashMap::new();
    for c in SYNCD_CONST_CONST.captures_iter(body) {
        let name = c.get(1).unwrap().as_str();
        let expr = c.get(2).unwrap().as_str().trim();
        if let Ok(n) = expr.parse::<f64>() {
            constants.insert(name.to_string(), n as i64);
        } else if IDENT_ONLY.is_match(expr)
            && let Some(v) = trace_local_literal(body, expr, c.get(0).unwrap().start())
        {
            constants.insert(name.to_string(), v);
        }
    }
    SyncdConst {
        actions,
        collections,
        constants,
    }
}

/// Resolve `l.<exportKey> = <var>` to the `{Key:"value"}` object literal `<var>`
/// was assigned, parsing it into ordered `(key, value)` pairs.
fn parse_enum_literal(body: &str, export_key: &str) -> Vec<(String, String)> {
    let exp_re = Regex::new(&format!(
        r"l\.{}\s*=\s*([A-Za-z_$][\w$]*)",
        regex::escape(export_key)
    ))
    .unwrap();
    let Some(cap) = exp_re.captures(body) else {
        return Vec::new();
    };
    let var_name = cap.get(1).unwrap().as_str();
    let export_idx = cap.get(0).unwrap().start();

    let assign_re = Regex::new(&format!(r"\b{}\s*=\s*", regex::escape(var_name))).unwrap();
    let b = body.as_bytes();
    let mut last = None;
    for m in assign_re.find_iter(body) {
        if m.start() >= export_idx {
            break;
        }
        if let Some(start) = find_call_object_arg_start(b, m.end(), export_idx) {
            last = Some(start);
        }
    }
    match last {
        Some(start) => parse_flat_object_string_values(body, start),
        None => Vec::new(),
    }
}

/// From `start`, find the first `({` opener (a call whose arg is an object
/// literal), respecting nesting; returns the index of the `{`.
fn find_call_object_arg_start(b: &[u8], start: usize, end: usize) -> Option<usize> {
    let mut i = start;
    let (mut dp, mut db) = (0i32, 0i32);
    while i < end {
        match b[i] {
            b'(' => {
                if dp == 0 && i + 1 < end && b[i + 1] == b'{' {
                    return Some(i + 1);
                }
                dp += 1;
            }
            b')' => {
                if dp > 0 {
                    dp -= 1;
                } else {
                    return None;
                }
            }
            b'{' if dp == 0 => db += 1,
            b'}' if dp == 0 && db > 0 => db -= 1,
            b',' | b';' if dp == 0 && db == 0 => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse a flat `{ Key:"value", ... }` literal (string values only).
fn parse_flat_object_string_values(s: &str, start: usize) -> Vec<(String, String)> {
    let b = s.as_bytes();
    if start >= b.len() || b[start] != b'{' {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < b.len() && b[i] != b'}' {
        i = skip_ws(b, i);
        if i >= b.len() || b[i] == b'}' {
            break;
        }
        // key
        let key = if b[i] == b'"' || b[i] == b'\'' {
            let q = b[i];
            i += 1;
            let st = i;
            while i < b.len() && b[i] != q {
                i += 1;
            }
            let k = s.get(st..i).unwrap_or("").to_string();
            i += 1;
            k
        } else {
            let st = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                i += 1;
            }
            s.get(st..i).unwrap_or("").to_string()
        };
        i = skip_ws(b, i);
        if i >= b.len() || b[i] != b':' {
            i = skip_expr(b, i, b",}");
            if i < b.len() && b[i] == b',' {
                i += 1;
            }
            continue;
        }
        i += 1; // ':'
        i = skip_ws(b, i);
        if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
            let q = b[i];
            i += 1;
            let st = i;
            while i < b.len() && b[i] != q {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push((key, s.get(st..i).unwrap_or("").to_string()));
            i += 1;
        } else {
            i = skip_expr(b, i, b",}");
        }
        i = skip_ws(b, i);
        if i < b.len() && b[i] == b',' {
            i += 1;
        }
    }
    out
}

/// Trace `<ident> = <numeric literal>` (last assignment before `scan_until`).
fn trace_local_literal(body: &str, ident: &str, scan_until: usize) -> Option<i64> {
    let sub = body.get(..scan_until)?;
    let re = Regex::new(&format!(
        r#"\b{}\s*=\s*(-?[0-9.eE+]+|"[^"]*"|'[^']*')"#,
        regex::escape(ident)
    ))
    .unwrap();
    let last = re.captures_iter(sub).last()?.get(1)?.as_str().to_string();
    if last.starts_with('"') || last.starts_with('\'') {
        return None;
    }
    last.parse::<f64>().ok().map(|f| f as i64)
}

// ─── Handler list + per-handler extraction ─────────────────────────────────────

static HANDLER_DEPS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)^__d\("WAWebCollectionHandlerActions",\s*\[([^\]]*)\]"#).unwrap()
});
static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""([^"]+)""#).unwrap());
static IS_SYNC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)Sync(?:Action)?$").unwrap());

fn parse_handler_list(bodies: &ModuleBodies) -> Vec<String> {
    let Some(body) = bodies.get(HANDLER_ACTIONS) else {
        return Vec::new();
    };
    let Some(cap) = HANDLER_DEPS.captures(body) else {
        return Vec::new();
    };
    QUOTED
        .captures_iter(cap.get(1).unwrap().as_str())
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .filter(|n| IS_SYNC.is_match(n))
        .collect()
}

static CLASS_TAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\}\s*\)?\s*\(\s*[A-Za-z_$][\w$]*\("WAWebSyncdAction"\)\.([A-Za-z_$][\w$]*)Base\s*\)"#,
    )
    .unwrap()
});

/// Locate the SyncdAction subclass IIFE body + its base-class name.
fn find_handler_class_body(body: &str) -> Option<(&str, String)> {
    let last = CLASS_TAIL.captures_iter(body).last()?;
    let base = format!("{}Base", last.get(1).unwrap().as_str());
    let close = last.get(0).unwrap().start(); // position of the closing `}`
    let b = body.as_bytes();
    let mut i = close;
    let mut depth = 1i32;
    while i > 0 {
        i -= 1;
        if b[i] == b'}' {
            depth += 1;
        } else if b[i] == b'{' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
    }
    if depth != 0 {
        return None;
    }
    Some((&body[i + 1..close], base))
}

fn base_scope(base: &str) -> &'static str {
    match base {
        "AccountSyncdActionBase" => "account",
        "ChatSyncdActionBase" => "chat",
        "ChatOrContactSyncdActionBase" => "chatOrContact",
        "MessageSyncdActionBase" => "message",
        "ChatMessageRangeSyncdActionBase" => "chatMessageRange",
        _ => "unknown",
    }
}

static CAPTURE_THIS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.call\.apply\(").unwrap()
});
static ACTION_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bgetAction\s*=\s*function\s*\([^)]*\)\s*\{\s*return\s+[A-Za-z_$][\w$]*\("WASyncdConst"\)\.Actions\.([A-Za-z_$][\w$]*)"#).unwrap()
});
static VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bgetVersion\s*=\s*function\s*\([^)]*\)\s*\{\s*return\s+([^;}]+)"#).unwrap()
});
static VERSION_CONST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"\("WASyncdConst"\)\.([A-Z][A-Z0-9_]*)"#).unwrap());

/// `this`-capture var + the constructor-body slice around `assertThisInitialized`.
fn ctor_context(fb: &str) -> (String, Option<&str>) {
    let b = fb.as_bytes();
    let Some(marker) = fb.find(ASSERT_THIS) else {
        return ("e".to_string(), None);
    };
    let mut i = marker;
    let mut depth = 0i32;
    loop {
        if i == 0 {
            return ("e".to_string(), None);
        }
        i -= 1;
        if b[i] == b'}' {
            depth += 1;
        } else if b[i] == b'{' {
            if depth == 0 {
                break;
            }
            depth -= 1;
        }
    }
    let mut end = (marker + 100).min(fb.len());
    while end < fb.len() && !fb.is_char_boundary(end) {
        end += 1;
    }
    let ctor = &fb[i..end];
    let this_var = CAPTURE_THIS
        .captures(ctor)
        .map(|c| c.get(1).unwrap().as_str().to_string())
        .unwrap_or_else(|| "e".to_string());
    (this_var, Some(ctor))
}

fn match_syncd_const_ref(expr: &str, table: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r#"\("WASyncdConst"\)\.{}\.([A-Za-z_$][\w$]*)"#,
        regex::escape(table)
    ))
    .unwrap();
    re.captures(expr)?.get(1).map(|m| m.as_str().to_string())
}

fn resolve_version(raw: Option<&str>, constants: &HashMap<String, i64>) -> Option<u32> {
    let raw = raw?;
    if let Ok(n) = raw.parse::<f64>() {
        return Some(n as u32);
    }
    let key = VERSION_CONST.captures(raw)?.get(1)?.as_str();
    constants.get(key).map(|&v| v as u32)
}

fn extract_handler(
    module: &str,
    bodies: &ModuleBodies,
    sc: &SyncdConst,
    vt: &ValueTypes,
) -> Option<(String, AppstateAction)> {
    let body = bodies.get(module)?;
    let (fb, base_class) = find_handler_class_body(body)?;
    let scope = base_scope(&base_class).to_string();
    // An unrecognized base class falls back to "unknown", which yields different
    // index_parts — surface it loudly so a new WA base class isn't mis-indexed
    // silently (rather than vanishing into a wrong default).
    if scope == "unknown" {
        eprintln!(
            "appstate: unrecognized SyncdActionBase `{base_class}` in {module} — \
             index_parts may be wrong; add it to base_scope()"
        );
    }

    let (this_var, ctor) = ctor_context(fb);
    let (collection_key, chat_jid_index) = match ctor {
        Some(cb) => (collection_key(cb, &this_var), chat_jid_index(cb, &this_var)),
        None => (None, None),
    };

    let action_key = ACTION_KEY.captures(fb)?.get(1)?.as_str().to_string();
    let name = sc.actions.get(&action_key)?.clone();
    let version_raw = VERSION
        .captures(fb)
        .map(|c| c.get(1).unwrap().as_str().trim().to_string());
    let version = resolve_version(version_raw.as_deref(), &sc.constants);
    let collection = collection_key.and_then(|k| sc.collection(&k));

    let value_field = extract_value_field(fb);
    let value_proto_type = value_field
        .as_ref()
        .and_then(|f| vt.field_to_message.get(f))
        .cloned();
    let value_enum_fields = value_proto_type
        .as_ref()
        .and_then(|p| vt.message_enum_fields.get(p))
        .cloned();

    let (slots, aliases) = extract_index_info(fb);
    let (slot_names, slot_proto_enums) = infer_slot_names(fb, &aliases);
    let index_parts = build_index_parts(
        &scope,
        chat_jid_index,
        slots,
        name.as_str(),
        &slot_names,
        &slot_proto_enums,
    );

    Some((
        action_key,
        AppstateAction {
            module: module.to_string(),
            name,
            collection,
            version,
            scope,
            base_class,
            value_field,
            value_proto_type,
            value_enum_fields,
            chat_jid_index,
            index_parts,
        },
    ))
}

fn collection_key(ctor: &str, this_var: &str) -> Option<String> {
    let re = Regex::new(&format!(
        r"\b{}\.collectionName\s*=\s*([^,;]+)",
        regex::escape(this_var)
    ))
    .unwrap();
    let expr = re.captures(ctor)?.get(1)?.as_str();
    match_syncd_const_ref(expr, "CollectionName")
}

fn chat_jid_index(ctor: &str, this_var: &str) -> Option<i64> {
    let re = Regex::new(&format!(
        r"\b{}\.chatJidIndex\s*=\s*(-?[0-9]+)",
        regex::escape(this_var)
    ))
    .unwrap();
    re.captures(ctor)?.get(1)?.as_str().parse().ok()
}

// ─── Phase 2: value field + proto type + enum fields ──────────────────────────

const SYNC_ACTION_PB: &str = "WAWebProtobufSyncAction.pb";

#[derive(Default)]
struct ValueTypes {
    /// SyncActionValue oneof field → message path.
    field_to_message: HashMap<String, String>,
    /// message path → { field → enum path relative to SyncActionValue }.
    message_enum_fields: HashMap<String, BTreeMap<String, String>>,
}

static EXPORT_VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bl\.([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\b").unwrap());
static IMPORT_SPEC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\)\.([A-Za-z_$][\w$]*)Spec\s*$").unwrap());
static SPEC_ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z_$][\w$]*)\s*:\s*\[\s*\d+\s*,\s*([^,\]]+)(?:\s*,\s*([^\]]+))?\]").unwrap()
});
static TYPES_ENUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bTYPES\.ENUM\b").unwrap());
static TYPES_MESSAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bTYPES\.MESSAGE\b").unwrap());

/// `(field, typeExpr, typeRef?)` entries of `<var>.internalSpec = {...}`.
fn parse_spec(body: &str, var_name: &str) -> Vec<(String, String, Option<String>)> {
    let re = Regex::new(&format!(
        r"\b{}\.internalSpec\s*=\s*\{{",
        regex::escape(var_name)
    ))
    .unwrap();
    let Some(m) = re.find(body) else {
        return Vec::new();
    };
    let obj_start = m.end() - 1; // the `{`
    let obj_end = skip_expr(body.as_bytes(), obj_start + 1, b"}");
    let src = body.get(obj_start + 1..obj_end).unwrap_or("");
    SPEC_ENTRY
        .captures_iter(src)
        .map(|c| {
            (
                c.get(1).unwrap().as_str().to_string(),
                c.get(2).unwrap().as_str().trim().to_string(),
                c.get(3).map(|g| g.as_str().trim().to_string()),
            )
        })
        .collect()
}

fn parse_sync_action_value_types(bodies: &ModuleBodies) -> ValueTypes {
    let Some(body) = bodies.get(SYNC_ACTION_PB) else {
        return ValueTypes::default();
    };

    let mut message_var_to_path: HashMap<String, String> = HashMap::new();
    let mut enum_var_to_path: HashMap<String, String> = HashMap::new();
    for c in EXPORT_VAR.captures_iter(body) {
        let name = c.get(1).unwrap().as_str();
        let var = c.get(2).unwrap().as_str().to_string();
        if let Some(stripped) = name.strip_suffix("Spec") {
            message_var_to_path.insert(var, stripped.replace('$', "."));
        } else {
            let dotted = name.replace('$', ".");
            let enum_path = dotted
                .strip_prefix("SyncActionValue.")
                .unwrap_or(&dotted)
                .to_string();
            enum_var_to_path.insert(var, enum_path);
        }
    }

    let Some(sync_var) = message_var_to_path
        .iter()
        .find(|(_, p)| *p == "SyncActionValue")
        .map(|(v, _)| v.clone())
    else {
        return ValueTypes::default();
    };

    // Step 1 — fieldToMessage from SyncActionValueSpec's entries.
    let mut field_to_message = HashMap::new();
    for (field, _, type_ref) in parse_spec(body, &sync_var) {
        let Some(type_ref) = type_ref else { continue };
        if IDENT_ONLY.is_match(&type_ref)
            && let Some(path) = message_var_to_path.get(&type_ref)
        {
            field_to_message.insert(field, path.clone());
            continue;
        }
        if let Some(c) = IMPORT_SPEC.captures(&type_ref) {
            field_to_message.insert(field, c.get(1).unwrap().as_str().to_string());
        }
    }

    // Step 2 — messageEnumFields: walk each message's spec for ENUM fields,
    // recursing through nested MESSAGE fields (dotted paths).
    let mut cache: HashMap<String, BTreeMap<String, String>> = HashMap::new();
    let mut message_enum_fields = HashMap::new();
    for (var, path) in &message_var_to_path {
        let fields =
            collect_enum_fields(body, var, 0, &mut Vec::new(), &enum_var_to_path, &mut cache);
        if !fields.is_empty() {
            message_enum_fields.insert(path.clone(), fields);
        }
    }

    ValueTypes {
        field_to_message,
        message_enum_fields,
    }
}

fn collect_enum_fields(
    body: &str,
    var_name: &str,
    depth: u32,
    visiting: &mut Vec<String>,
    enum_var_to_path: &HashMap<String, String>,
    cache: &mut HashMap<String, BTreeMap<String, String>>,
) -> BTreeMap<String, String> {
    if let Some(c) = cache.get(var_name) {
        return c.clone();
    }
    if depth > 4 || visiting.iter().any(|v| v == var_name) {
        return BTreeMap::new();
    }
    visiting.push(var_name.to_string());
    let mut out = BTreeMap::new();
    for (field, type_expr, type_ref) in parse_spec(body, var_name) {
        let Some(type_ref) = type_ref else { continue };
        if !IDENT_ONLY.is_match(&type_ref) {
            continue;
        }
        if TYPES_ENUM.is_match(&type_expr) {
            if let Some(path) = enum_var_to_path.get(&type_ref) {
                out.insert(field, path.clone());
            }
        } else if TYPES_MESSAGE.is_match(&type_expr) {
            let nested = collect_enum_fields(
                body,
                &type_ref,
                depth + 1,
                visiting,
                enum_var_to_path,
                cache,
            );
            for (k, v) in nested {
                out.insert(format!("{field}.{k}"), v);
            }
        }
    }
    visiting.pop();
    cache.insert(var_name.to_string(), out.clone());
    out
}

static GENERIC_MEMBERS: &[&str] = &[
    "value",
    "length",
    "toString",
    "prototype",
    "apply",
    "call",
    "bind",
    "map",
    "filter",
    "forEach",
    "push",
    "pop",
    "shift",
    "unshift",
    "slice",
    "concat",
    "find",
    "some",
    "every",
    "reduce",
    "includes",
    "indexOf",
    "join",
    "operation",
    "timestamp",
];

fn is_generic_member_name(key: &str) -> bool {
    GENERIC_MEMBERS.contains(&key)
}

static BUILD_PENDING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bbuildPendingMutation\s*\(\s*\{").unwrap());
static VALUE_PROP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[,{\s])value\s*:\s*([^,}]+)").unwrap());
static INLINE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\{\s*([A-Za-z_$][\w$]*)\s*:").unwrap());
static DOT_VALUE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.value\.([A-Za-z_$][\w$]*)").unwrap());
static VALUE_ALIAS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.value\b").unwrap());

/// Find the SyncActionValue oneof field name carried by this handler.
fn extract_value_field(fb: &str) -> Option<String> {
    let b = fb.as_bytes();
    for cm in BUILD_PENDING.find_iter(fb) {
        let obj_start = cm.end() - 1; // the `{`
        let obj_end = skip_expr(b, obj_start + 1, b"}");
        let obj_src = fb.get(obj_start + 1..obj_end).unwrap_or("");
        let Some(vm) = VALUE_PROP.captures(obj_src) else {
            continue;
        };
        let tok = vm.get(1).unwrap().as_str().trim();
        if tok.starts_with('{')
            && let Some(km) = INLINE_KEY.captures(tok)
        {
            return Some(km.get(1).unwrap().as_str().to_string());
        }
        if IDENT_ONLY.is_match(tok)
            && let Some(traced) = trace_object_literal_first_key(fb, tok, cm.start())
        {
            return Some(traced);
        }
    }
    // Fallback A: direct `.value.<key>` chain.
    for dm in DOT_VALUE_KEY.captures_iter(fb) {
        let key = dm.get(1).unwrap().as_str();
        if !is_generic_member_name(key) {
            return Some(key.to_string());
        }
    }
    // Fallback B: `<alias> = <X>.value` then `<alias>.<field>` afterwards.
    for am in VALUE_ALIAS.captures_iter(fb) {
        let alias = am.get(1).unwrap().as_str();
        let after = am.get(0).unwrap().end();
        let member_re =
            Regex::new(&format!(r"\b{}\.([A-Za-z_$][\w$]*)", regex::escape(alias))).unwrap();
        for mm in member_re.captures_iter(fb.get(after..).unwrap_or("")) {
            let key = mm.get(1).unwrap().as_str();
            if !is_generic_member_name(key) {
                return Some(key.to_string());
            }
        }
    }
    None
}

fn trace_object_literal_first_key(fb: &str, ident: &str, scan_from: usize) -> Option<String> {
    let sub = fb.get(..scan_from)?;
    let re = Regex::new(&format!(
        r"(?:\bvar\s+|[,;]){}\s*=\s*\{{",
        regex::escape(ident)
    ))
    .unwrap();
    let last = re.find_iter(sub).last()?;
    let brace = last.end() - 1; // the `{`
    INLINE_KEY
        .captures(sub.get(brace..)?)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

// ─── Phase 2: index parts ─────────────────────────────────────────────────────

static DIRECT_INDEXPARTS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.indexParts\s*\[\s*(\d+)\s*\]").unwrap());
static ALIAS_INDEXPARTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.indexParts\b").unwrap()
});
static SUFFIX_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:Id|Jid|Key|Name)$").unwrap());

/// Highest `<x>.indexParts[N]` / `<alias>[N]` index → slot count + alias names.
fn extract_index_info(fb: &str) -> (usize, Vec<String>) {
    let mut max_idx: i64 = -1;
    for m in DIRECT_INDEXPARTS.captures_iter(fb) {
        max_idx = max_idx.max(parse_i64(&m[1]));
    }
    let mut aliases = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for am in ALIAS_INDEXPARTS.captures_iter(fb) {
        let alias = am[1].to_string();
        if seen.insert(alias.clone()) {
            aliases.push(alias.clone());
        }
        let access =
            Regex::new(&format!(r"\b{}\s*\[\s*(\d+)\s*\]", regex::escape(&alias))).unwrap();
        for acc in access.captures_iter(fb) {
            max_idx = max_idx.max(parse_i64(&acc[1]));
        }
    }
    (
        if max_idx >= 0 {
            (max_idx + 1) as usize
        } else {
            0
        },
        aliases,
    )
}

fn parse_i64(s: &str) -> i64 {
    s.parse().unwrap_or(-1)
}

#[derive(Clone)]
struct SlotBind {
    slot: usize,
    bound_at: usize,
}

static RESERVED: LazyLock<std::collections::HashSet<&'static str>> = LazyLock::new(|| {
    [
        "return",
        "case",
        "default",
        "if",
        "else",
        "this",
        "var",
        "let",
        "const",
        "function",
        "new",
        "true",
        "false",
        "null",
        "undefined",
        "void",
        "operation",
        "value",
        "timestamp",
        "index",
        "indexParts",
        "indexArgs",
        "binarySyncAction",
        "binarySyncData",
        "actionState",
        "orphanModel",
        "modelId",
        "modelType",
        "syncActionMessage",
        "syncActionMessageRange",
    ]
    .into_iter()
    .collect()
});

static JSON_PARSE_INDEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*JSON\.parse\([A-Za-z_$][\w$.]*\.index\)").unwrap()
});
static DIRECT_SLOT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\.indexParts\s*\[\s*(\d+)\s*\]")
        .unwrap()
});
static RETURN_ARR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\breturn\s*\[([^\]]+)\]").unwrap());
static INDEX_ARGS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[,{\s])indexArgs\s*:\s*\[([^\]]*)\]").unwrap());
static BUILD_PENDING2: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bbuildPendingMutation\s*\(\s*\{").unwrap());
static TRAILING_PROP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.([A-Za-z_$][\w$]*)\s*$").unwrap());

/// Best-effort index-slot name inference (the heuristics, in confidence order).
fn infer_slot_names(
    fb: &str,
    index_aliases: &[String],
) -> (HashMap<usize, String>, HashMap<usize, String>) {
    let b = fb.as_bytes();
    let mut aliases: Vec<String> = index_aliases.to_vec();
    let mut alias_set: std::collections::HashSet<String> = aliases.iter().cloned().collect();
    for pm in JSON_PARSE_INDEX.captures_iter(fb) {
        let a = pm[1].to_string();
        if alias_set.insert(a.clone()) {
            aliases.push(a);
        }
    }

    // Phase 2 — alias→slot bindings (insertion-ordered, first-bind-wins).
    let mut binds: Vec<(String, SlotBind)> = Vec::new();
    let mut bound: std::collections::HashSet<String> = std::collections::HashSet::new();
    let bind = |binds: &mut Vec<(String, SlotBind)>,
                bound: &mut std::collections::HashSet<String>,
                name: &str,
                slot: usize,
                at: usize| {
        if bound.insert(name.to_string()) {
            binds.push((name.to_string(), SlotBind { slot, bound_at: at }));
        }
    };

    for dm in DIRECT_SLOT.captures_iter(fb) {
        let at = dm.get(0).unwrap().start();
        bind(
            &mut binds,
            &mut bound,
            &dm[1],
            parse_i64(&dm[2]).max(0) as usize,
            at,
        );
    }
    for alias in &aliases {
        let re = Regex::new(&format!(
            r"\b([A-Za-z_$][\w$]*)\s*=\s*{}\s*\[\s*(\d+)\s*\]",
            regex::escape(alias)
        ))
        .unwrap();
        for m in re.captures_iter(fb) {
            let at = m.get(0).unwrap().start();
            bind(
                &mut binds,
                &mut bound,
                &m[1],
                parse_i64(&m[2]).max(0) as usize,
                at,
            );
        }
        let cmp = Regex::new(&format!(
            r#"\b([A-Za-z_$][\w$]*)\s*=\s*(?:"[^"]*"\s*===\s*{a}\s*\[\s*(\d+)\s*\]|{a}\s*\[\s*(\d+)\s*\]\s*===\s*"[^"]*")"#,
            a = regex::escape(alias)
        ))
        .unwrap();
        for m in cmp.captures_iter(fb) {
            let n = m
                .get(2)
                .or_else(|| m.get(3))
                .map(|g| parse_i64(g.as_str()).max(0) as usize)
                .unwrap_or(0);
            let at = m.get(0).unwrap().start();
            bind(&mut binds, &mut bound, &m[1], n, at);
        }
    }

    // Phase 3 — transitive expansion (property access + call-arg propagation).
    let mut grew = true;
    while grew {
        grew = false;
        for (oldvar, entry) in binds.clone() {
            let sub = fb.get(entry.bound_at..).unwrap_or("");
            let off = entry.bound_at;
            let prop = Regex::new(&format!(
                r"\b([A-Za-z_$][\w$]*)\s*=\s*{}\.[A-Za-z_$][\w$]*",
                regex::escape(&oldvar)
            ))
            .unwrap();
            for pm in prop.captures_iter(sub) {
                let nv = pm[1].to_string();
                if bound.insert(nv.clone()) {
                    binds.push((
                        nv,
                        SlotBind {
                            slot: entry.slot,
                            bound_at: off + pm.get(0).unwrap().start(),
                        },
                    ));
                    grew = true;
                }
            }
            let call = Regex::new(&format!(
                r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:yield\s+)?[^;,]*?\(\s*[^)]*?\b{}\b(?:\.[\w$]+)?[^)]*\)",
                regex::escape(&oldvar)
            ))
            .unwrap();
            for cm in call.captures_iter(sub) {
                let whole = cm.get(0).unwrap().as_str();
                if whole.contains(".call.apply") || whole.contains("inheritsLoose") {
                    continue;
                }
                let nv = cm[1].to_string();
                if bound.insert(nv.clone()) {
                    binds.push((
                        nv,
                        SlotBind {
                            slot: entry.slot,
                            bound_at: off + cm.get(0).unwrap().start(),
                        },
                    ));
                    grew = true;
                }
            }
        }
    }

    let mut slot_names: HashMap<usize, String> = HashMap::new();
    let mut slot_proto_enums: HashMap<usize, String> = HashMap::new();

    // 4a — `return [<expr>, ...]`.
    for rm in RETURN_ARR.captures_iter(fb) {
        let exprs = split_top_level_commas(&rm[1]);
        for (i, expr) in exprs.iter().enumerate() {
            let slot = i + 1;
            if slot_names.contains_key(&slot) {
                continue;
            }
            if let Some(name) =
                extract_trailing_name(expr.trim(), fb, rm.get(0).unwrap().start(), 0)
                && !RESERVED.contains(name.as_str())
            {
                slot_names.insert(slot, name);
            }
        }
    }

    // 4b — `buildPendingMutation({...indexArgs:[<expr>...]...})`.
    for cm in BUILD_PENDING2.find_iter(fb) {
        let obj_start = cm.end() - 1;
        let obj_end = skip_expr(b, obj_start + 1, b"}");
        let obj_src = fb.get(obj_start + 1..obj_end).unwrap_or("");
        let Some(args) = INDEX_ARGS.captures(obj_src) else {
            continue;
        };
        for (i, expr) in split_top_level_commas(&args[1]).iter().enumerate() {
            let slot = i + 1;
            if slot_names.contains_key(&slot) {
                continue;
            }
            if let Some(c) = TRAILING_PROP.captures(expr.trim()) {
                let name = c.get(1).unwrap().as_str();
                if !RESERVED.contains(name) {
                    slot_names.insert(slot, name.to_string());
                }
            }
        }
    }

    // 4c — `<key>:"X"===<alias>[N]` inline bool coercion.
    for alias in &aliases {
        let re = Regex::new(&format!(
            r#"([A-Za-z_$][\w$]*)\s*:\s*(?:"[^"]*"\s*===\s*{a}\s*\[\s*(\d+)\s*\]|{a}\s*\[\s*(\d+)\s*\]\s*===\s*"[^"]*")"#,
            a = regex::escape(alias)
        ))
        .unwrap();
        for m in re.captures_iter(fb) {
            let candidate = m[1].to_string();
            if RESERVED.contains(candidate.as_str()) {
                continue;
            }
            let slot = m
                .get(2)
                .or_else(|| m.get(3))
                .map(|g| parse_i64(g.as_str()).max(0) as usize)
                .unwrap_or(0);
            slot_names.entry(slot).or_insert(candidate);
        }
    }

    // 4d–4h — scope-bounded scans near each binding. Each source is a full pass
    // over all bindings (in confidence order, first-write-wins per slot) — NOT a
    // per-binding loop, so an earlier source on a later binding still wins.
    let op_chars = b".=+-*/%<>&|^?";

    // 4d — `<key>:<localvar>.<member>` (not `key===member`, not a deeper chain).
    for (localvar, SlotBind { slot, bound_at }) in &binds {
        let slot = *slot;
        if slot_names.contains_key(&slot) {
            continue;
        }
        let sub = scope_window(fb, *bound_at);
        let sb = sub.as_bytes();
        let re = Regex::new(&format!(
            r"([A-Za-z_$][\w$]*)\s*:\s*{}\.([A-Za-z_$][\w$]*)",
            regex::escape(localvar)
        ))
        .unwrap();
        for m in re.captures_iter(sub) {
            if sb.get(m.get(0).unwrap().end()) == Some(&b'.') {
                continue; // (?!\.)
            }
            let key = &m[1];
            if key == &m[2] || RESERVED.contains(key) {
                continue;
            }
            slot_names.entry(slot).or_insert_with(|| key.to_string());
            if SUFFIX_RE.is_match(key) {
                slot_names.insert(slot, key.to_string());
                break;
            }
        }
    }

    // 4e — `<key>:<localvar>` (bare, not followed by an operator).
    for (localvar, SlotBind { slot, bound_at }) in &binds {
        let slot = *slot;
        if slot_names.contains_key(&slot) {
            continue;
        }
        let sub = scope_window(fb, *bound_at);
        let sb = sub.as_bytes();
        let re = Regex::new(&format!(
            r"([A-Za-z_$][\w$]*)\s*:\s*{}",
            regex::escape(localvar)
        ))
        .unwrap();
        for m in re.captures_iter(sub) {
            let end = m.get(0).unwrap().end();
            if matches!(sb.get(end), Some(c) if c.is_ascii_alphanumeric() || *c == b'_' || *c == b'$')
            {
                continue; // localvar must be a whole word
            }
            let mut j = end;
            while j < sb.len() && sb[j].is_ascii_whitespace() {
                j += 1;
            }
            if matches!(sb.get(j), Some(c) if op_chars.contains(c)) {
                continue; // (?!\s*[op])
            }
            let candidate = &m[1];
            if RESERVED.contains(candidate) {
                continue;
            }
            slot_names
                .entry(slot)
                .or_insert_with(|| candidate.to_string());
            if SUFFIX_RE.is_match(candidate) {
                slot_names.insert(slot, candidate.to_string());
                break;
            }
        }
    }

    // 4f — `"<tag>="+<localvar>`.
    for (localvar, SlotBind { slot, bound_at }) in &binds {
        let slot = *slot;
        if slot_names.contains_key(&slot) {
            continue;
        }
        let sub = scope_window(fb, *bound_at);
        let re = Regex::new(&format!(
            r#""([A-Za-z_][\w]*)="\s*\+\s*{}\b"#,
            regex::escape(localvar)
        ))
        .unwrap();
        for m in re.captures_iter(sub) {
            let candidate = m[1].to_string();
            if !RESERVED.contains(candidate.as_str()) {
                slot_names.entry(slot).or_insert(candidate);
            }
        }
    }

    // 4g — proto enum cast `<NestedType>.cast(Number(<localvar>))`.
    for (localvar, SlotBind { slot, bound_at }) in &binds {
        let slot = *slot;
        if slot_names.contains_key(&slot) {
            continue;
        }
        let sub = scope_window(fb, *bound_at);
        let re = Regex::new(&format!(
            r"\.([A-Za-z_$][\w$]*)\.cast\(\s*Number\(\s*{}\s*\)\s*\)",
            regex::escape(localvar)
        ))
        .unwrap();
        for m in re.captures_iter(sub) {
            let parts: Vec<&str> = m[1].split('$').filter(|s| !s.is_empty()).collect();
            if parts.len() < 2 {
                continue;
            }
            let proto_path = if parts[0] == "SyncActionValue" {
                parts[1..].join(".")
            } else {
                parts.join(".")
            };
            let candidate = lower_first(parts[parts.len() - 1]);
            if RESERVED.contains(candidate.as_str()) {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = slot_names.entry(slot) {
                e.insert(candidate);
                slot_proto_enums.insert(slot, proto_path);
            }
        }
    }

    // 4h — function-name typing `.<verbType>(<localvar>...)`.
    for (localvar, SlotBind { slot, bound_at }) in &binds {
        let slot = *slot;
        if slot_names.contains_key(&slot) {
            continue;
        }
        let sub = scope_window(fb, *bound_at);
        let re = Regex::new(&format!(
            r"\.([A-Za-z_$][\w$]*)\(\s*{}\b",
            regex::escape(localvar)
        ))
        .unwrap();
        for m in re.captures_iter(sub) {
            let Some(candidate) = type_from_method_name(&m[1]) else {
                continue;
            };
            if RESERVED.contains(candidate.as_str()) {
                continue;
            }
            slot_names.entry(slot).or_insert_with(|| candidate.clone());
            if SUFFIX_RE.is_match(&candidate) {
                slot_names.insert(slot, candidate);
                break;
            }
        }
    }

    (slot_names, slot_proto_enums)
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

const VERB_SUFFIXES: &[&str] = &[
    "Storage",
    "Job",
    "Table",
    "Api",
    "Service",
    "Util",
    "Utils",
    "Action",
    "Bridge",
    "Collection",
    "Index",
    "Database",
    "Helper",
    "Helpers",
    "Worker",
    "Processor",
    "Builder",
    "Manager",
];

fn type_from_method_name(fn_name: &str) -> Option<String> {
    let mut parts = split_before_uppercase(fn_name);
    if parts.len() < 2 {
        return None;
    }
    while parts
        .last()
        .is_some_and(|p| VERB_SUFFIXES.contains(&p.as_str()))
    {
        parts.pop();
    }
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let ty = parts[1..].join("");
    if ty.is_empty() {
        return None;
    }
    Some(lower_first(&ty))
}

/// Split a camelCase string before each uppercase letter (`getFooBar` → get/Foo/Bar).
fn split_before_uppercase(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_uppercase() && !cur.is_empty() {
            parts.push(std::mem::take(&mut cur));
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

/// Brace-bounded window (or `PROXIMITY_WINDOW` bytes) of `fb` from `bound_at`.
fn scope_window(fb: &str, bound_at: usize) -> &str {
    const PROXIMITY_WINDOW: usize = 4000;
    let b = fb.as_bytes();
    let mut depth = 0i32;
    let mut i = bound_at;
    let mut in_str = 0u8;
    while i < b.len() && i - bound_at < PROXIMITY_WINDOW {
        let c = b[i];
        if in_str != 0 {
            if c == b'\\' {
                i += 1;
            } else if c == in_str {
                in_str = 0;
            }
        } else if c == b'"' || c == b'\'' || c == b'`' {
            in_str = c;
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            if depth == 0 {
                break;
            }
            depth -= 1;
        }
        i += 1;
    }
    while i < fb.len() && !fb.is_char_boundary(i) {
        i += 1;
    }
    fb.get(bound_at..i).unwrap_or("")
}

/// `e.key.id` → `id`; bare ident → trace its `var <id> = <rhs>` and recurse.
/// `depth` caps the alias chain so a cycle (`a=b; b=a`) can't loop forever.
fn extract_trailing_name(expr: &str, fb: &str, scan_from: usize, depth: u32) -> Option<String> {
    if let Some(c) = TRAILING_PROP.captures(expr) {
        return Some(c.get(1).unwrap().as_str().to_string());
    }
    if depth < ALIAS_TRACE_MAX_DEPTH && IDENT_ONLY.is_match(expr) {
        let sub = fb.get(..scan_from)?;
        let re = Regex::new(&format!(r"\b{}\s*=\s*([^;,]+)", regex::escape(expr))).unwrap();
        let last = re.captures_iter(sub).last()?.get(1)?.as_str().to_string();
        if last.trim() != expr {
            return extract_trailing_name(last.trim(), fb, scan_from, depth + 1);
        }
    }
    None
}

/// Max alias-chain hops `extract_trailing_name` follows before giving up.
const ALIAS_TRACE_MAX_DEPTH: u32 = 16;

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                out.push(s[start..i].to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(s[start..].to_string());
    }
    out.into_iter()
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

use wa_ir::IndexPart;

/// Assemble the discriminated-union index tuple (literal at 0, then scope slots).
fn build_index_parts(
    scope: &str,
    chat_jid_index: Option<i64>,
    mut slots: usize,
    action_name: &str,
    slot_names: &HashMap<usize, String>,
    slot_proto_enums: &HashMap<usize, String>,
) -> Vec<IndexPart> {
    if slots == 0 && scope != "message" {
        if scope == "account" {
            slots = 1;
        } else if matches!(scope, "chat" | "chatOrContact" | "chatMessageRange") {
            slots = 2;
        }
    }
    if scope == "message" && slots < 5 {
        slots = 5;
    }

    let emit_slot = |s: usize, fallback: String| -> IndexPart {
        let name = slot_names.get(&s).cloned().unwrap_or(fallback);
        match slot_proto_enums.get(&s) {
            Some(proto_enum) => IndexPart::Enum {
                name,
                proto_enum: proto_enum.clone(),
            },
            None => IndexPart::StringPart { name },
        }
    };

    let mut parts = vec![IndexPart::Literal {
        value: action_name.to_string(),
    }];
    if scope == "message" {
        parts.push(IndexPart::Jid {
            name: "remote".to_string(),
        });
        parts.push(IndexPart::StringPart {
            name: "id".to_string(),
        });
        parts.push(IndexPart::BoolString {
            name: "fromMe".to_string(),
        });
        parts.push(IndexPart::JidOrZero {
            name: "participant".to_string(),
        });
        for s in 5..slots {
            parts.push(emit_slot(s, format!("arg{s}")));
        }
        return parts;
    }
    for s in 1..slots {
        if Some(s as i64) == chat_jid_index {
            parts.push(IndexPart::Jid {
                name: "chatJid".to_string(),
            });
        } else {
            parts.push(emit_slot(s, format!("key{s}")));
        }
    }
    parts
}

/// Extract the AppState IR from a bundle's (concatenated) source.
pub fn extract_appstate(src: &str, wa_version: &str) -> AppstateIr {
    extract_with_bodies(&ModuleBodies::scan(src), wa_version)
}

/// Like [`extract_appstate`], but reusing a pre-split module index (shares the
/// CLI's single whole-bundle parse instead of rescanning the source).
pub fn extract_appstate_from_modules(
    src: &str,
    module_defs: &[wa_transform::ModuleDefinition],
    wa_version: &str,
) -> AppstateIr {
    extract_with_bodies(&ModuleBodies::from_modules(src, module_defs), wa_version)
}

fn extract_with_bodies(bodies: &ModuleBodies, wa_version: &str) -> AppstateIr {
    let sc = parse_syncd_const(bodies);
    let vt = parse_sync_action_value_types(bodies);
    let collections = sc.collections.iter().map(|(_, v)| v.clone()).collect();

    let mut actions = BTreeMap::new();
    for module in parse_handler_list(bodies) {
        if let Some((key, action)) = extract_handler(&module, bodies, &sc, &vt) {
            actions.insert(key, action);
        }
    }

    AppstateIr {
        wa_version: wa_version.to_string(),
        collections,
        actions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_body_and_enum_literal() {
        let src = r#"__d("WASyncdConst",["$InternalEnum"],(function(t,n,r,o,a,i,l){
            var e,g=(e=n("$InternalEnum"))({Star:"star",Mute:"mute"}),h=e({Regular:"regular",RegularLow:"regular_low"});
            l.Actions=g,l.CollectionName=h,l.MAX=7,l.MIN=0;
        }),1);"#;
        let sc = parse_syncd_const(&ModuleBodies::scan(src));
        assert_eq!(sc.actions.get("Star").map(String::as_str), Some("star"));
        assert_eq!(sc.actions.get("Mute").map(String::as_str), Some("mute"));
        assert_eq!(
            sc.collections,
            vec![
                ("Regular".to_string(), "regular".to_string()),
                ("RegularLow".to_string(), "regular_low".to_string()),
            ]
        );
        assert_eq!(sc.constants.get("MAX"), Some(&7));
    }

    #[test]
    fn split_and_method_name_helpers() {
        assert_eq!(
            split_top_level_commas("a, foo(b,c), d.e"),
            vec!["a", "foo(b,c)", "d.e"]
        );
        assert_eq!(
            type_from_method_name("validateChatJid").as_deref(),
            Some("chatJid")
        );
        assert_eq!(
            type_from_method_name("upsertCampaignStorage").as_deref(),
            Some("campaign")
        );
        assert_eq!(type_from_method_name("set").as_deref(), None); // single token
        assert_eq!(lower_first("ChatJid"), "chatJid");
    }

    #[test]
    fn build_index_parts_scopes() {
        let names = HashMap::new();
        let enums = HashMap::new();
        // message scope → fixed remote/id/fromMe/participant after the literal.
        let msg = build_index_parts("message", None, 0, "delete", &names, &enums);
        assert_eq!(
            msg[0],
            IndexPart::Literal {
                value: "delete".into()
            }
        );
        assert_eq!(
            msg[1],
            IndexPart::Jid {
                name: "remote".into()
            }
        );
        assert_eq!(
            msg[3],
            IndexPart::BoolString {
                name: "fromMe".into()
            }
        );
        assert_eq!(
            msg[4],
            IndexPart::JidOrZero {
                name: "participant".into()
            }
        );
        // account scope with no detected slots → 1 slot (just the literal).
        let acct = build_index_parts("account", None, 0, "agent", &names, &enums);
        assert_eq!(
            acct,
            vec![IndexPart::Literal {
                value: "agent".into()
            }]
        );
        // chat scope, chatJidIndex=1 → slot 1 is the chat jid.
        let chat = build_index_parts("chat", Some(1), 0, "mute", &names, &enums);
        assert_eq!(
            chat[1],
            IndexPart::Jid {
                name: "chatJid".into()
            }
        );
    }

    #[test]
    fn value_field_from_build_pending_mutation() {
        let fb = r#"function(){ return o("X").buildPendingMutation({value:{muteAction:t}, indexArgs:[e]}); }"#;
        assert_eq!(extract_value_field(fb).as_deref(), Some("muteAction"));
    }

    #[test]
    fn module_body_scan_is_string_aware() {
        // A `)` inside a string literal must not truncate the module body.
        let src =
            r#"__d("A",[],(function(){var x=")";var y="real";}),1);__d("B",[],(function(){}),2);"#;
        let bodies = ModuleBodies::scan(src);
        let a = bodies.get("A").expect("module A");
        assert!(
            a.ends_with("}),1)"),
            "body not truncated at the string `)`: {a}"
        );
        assert!(bodies.get("B").is_some(), "second module still found");
    }

    #[test]
    fn extract_trailing_name_terminates_on_alias_cycle() {
        // `a=b; b=a;` would loop forever without the depth cap — must just stop.
        let fb = "var a=b;var b=a;";
        assert_eq!(extract_trailing_name("a", fb, fb.len(), 0), None);
    }
}
