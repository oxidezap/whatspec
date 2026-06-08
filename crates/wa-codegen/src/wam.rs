//! Reference Rust codegen for the WAM (analytics/metrics) catalog.
//!
//! The IR ([`wa_ir::WamIr`]) is the cross-language contract; this is ONE reference
//! consumer (a host in another language generates its own from the same IR). The
//! emitted file is self-contained: a stable WAM wire codec (ported from WA Web's
//! `WAWebWamLibProtocol`, little-endian) + the generated enums + one typed struct per
//! event whose `emit` writes the exact bytes WA Web produces. Each event's doc names
//! the WA Web modules that emit it, so a host knows where each metric is triggered.

use std::collections::HashMap;

use wa_ir::{WamEnum, WamEvent, WamFieldType, WamIr};

use crate::naming::{ensure_ident, rust_ident, snake_case};

/// PascalCase that also folds SCREAMING_SNAKE (the WAM enum/variant convention):
/// `APP_LAUNCH_TYPE`→`AppLaunchType`, `ON`→`On`, `AppLaunch`→`AppLaunch`. Each word's
/// tail is lowercased (unlike [`crate::naming::pascal_case`], which keeps acronyms),
/// and a camelCase hump still starts a new word.
fn wam_pascal(s: &str) -> String {
    let mut out = String::new();
    let mut cap = true;
    let mut prev_lower = false;
    for ch in s.chars() {
        if !ch.is_ascii_alphanumeric() {
            cap = true;
            continue;
        }
        if ch.is_ascii_uppercase() && prev_lower {
            cap = true; // camelCase boundary
        }
        if cap {
            out.extend(ch.to_uppercase());
            cap = false;
        } else {
            out.extend(ch.to_lowercase());
        }
        prev_lower = ch.is_ascii_lowercase();
    }
    // Keyword-safe (`Self`→`Self_`, `Type`/`Match` are not keywords), non-empty, and
    // not digit-leading — a variant key like `SELF` would otherwise be invalid Rust.
    ensure_ident(&out)
}

/// Generate the self-contained reference `wam.rs`.
pub fn generate_wam(ir: &WamIr) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "//! Auto-generated WAM (analytics/metrics) emitters (WhatsApp {}). DO NOT EDIT.\n\
         //!\n//! A stable wire codec + one typed struct per event; `emit` serializes an event\n\
         //! into a `WamBuffer` byte-for-byte like WhatsApp Web. Regenerated from the WAM IR.\n\n\
         #![allow(clippy::all, dead_code, non_snake_case, non_camel_case_types)]\n\n",
        ir.wa_version
    ));
    out.push_str(CODEC_PRELUDE);
    out.push('\n');

    // module → generated Rust enum name (deduped). Field enum refs resolve through this.
    let mut enum_name: HashMap<&str, String> = HashMap::new();
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in &ir.enums {
        let mut name = wam_pascal(&e.name);
        if name.is_empty() {
            name = wam_pascal(&e.module);
        }
        let base = name.clone();
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}{n}");
            n += 1;
        }
        enum_name.insert(e.module.as_str(), name);
    }

    out.push_str(
        "// ─── WAM enums ────────────────────────────────────────────────────────────────\n\n",
    );
    for e in &ir.enums {
        emit_enum(&mut out, e, &enum_name[e.module.as_str()]);
    }

    out.push_str(
        "// ─── WAM events ───────────────────────────────────────────────────────────────\n\n",
    );
    // Event structs share the type namespace with the enums above, so dedup their
    // names against the SAME `used` set (an enum export can PascalCase to `XxxEvent`).
    for ev in &ir.events {
        let mut struct_name = format!("{}Event", wam_pascal(&ev.name));
        let base = struct_name.clone();
        let mut n = 2;
        while !used.insert(struct_name.clone()) {
            struct_name = format!("{base}{n}");
            n += 1;
        }
        emit_event(&mut out, ev, &struct_name, &enum_name);
    }
    out
}

/// `#[repr(i64)]` enum + `as_wam_int` (the wire value).
fn emit_enum(out: &mut String, e: &WamEnum, name: &str) {
    out.push_str(&format!(
        "/// WAM enum `{}` (module `{}`).\n",
        e.name, e.module
    ));
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n#[repr(i64)]\n");
    out.push_str(&format!("pub enum {name} {{\n"));
    // Variant idents must be unique within the enum (two keys can PascalCase the same).
    let mut vused: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut variants: Vec<(String, i64)> = Vec::new();
    for v in &e.variants {
        let mut id = wam_pascal(&v.key);
        if id.is_empty() || id.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            id = format!("V{}", v.value);
        }
        let base = id.clone();
        let mut n = 2;
        while !vused.insert(id.clone()) {
            id = format!("{base}{n}");
            n += 1;
        }
        out.push_str(&format!("    {id} = {},\n", v.value));
        variants.push((id, v.value));
    }
    out.push_str("}\n\n");
    out.push_str(&format!(
        "impl {name} {{\n    pub fn as_wam_int(self) -> i64 {{ self as i64 }}\n}}\n\n"
    ));
    let _ = variants;
}

/// One event struct + its `WamEventDef` impl (`struct_name` is pre-resolved + deduped
/// against the shared type namespace by the caller).
fn emit_event(
    out: &mut String,
    ev: &WamEvent,
    struct_name: &str,
    enum_name: &HashMap<&str, String>,
) {
    // Doc: code + the modules that emit it (the host's focus hint).
    out.push_str(&format!(
        "/// WAM event `{}` (code {}).\n",
        ev.name, ev.code
    ));
    if !ev.consumers.is_empty() {
        let shown: Vec<&str> = ev.consumers.iter().take(4).map(|s| s.as_str()).collect();
        let extra = ev.consumers.len().saturating_sub(shown.len());
        let more = if extra > 0 {
            format!(" (+{extra} more)")
        } else {
            String::new()
        };
        out.push_str(&format!("/// Emitted by: {}{}.\n", shown.join(", "), more));
    }

    out.push_str("#[derive(Debug, Clone, Default)]\n");
    out.push_str(&format!("pub struct {struct_name} {{\n"));
    let mut idents: Vec<(String, &wa_ir::WamField)> = Vec::new();
    let mut fused: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &ev.fields {
        let mut id = rust_ident(&snake_case(&f.name));
        let base = id.clone();
        let mut n = 2;
        while !fused.insert(id.clone()) {
            id = format!("{base}_{n}");
            n += 1;
        }
        out.push_str(&format!(
            "    pub {id}: Option<{}>,\n",
            field_rust_type(&f.field_type, enum_name)
        ));
        idents.push((id, f));
    }
    out.push_str("}\n\n");

    let channel = match ev.channel.as_str() {
        "realtime" => "WamChannel::Realtime",
        "private" => "WamChannel::Private",
        _ => "WamChannel::Regular",
    };
    // The web client's effective default weight is the literal `1` (the runtime reads
    // weights[1]/weights[2] only when a sampling-ring gate is on — `weights[0]` is
    // never read). So `emit` uses 1; the raw ring weights are exposed for a host that
    // implements ring selection.
    let raw_weights: Vec<String> = ev.weights.iter().map(|w| w.to_string()).collect();

    out.push_str(&format!("impl WamEventDef for {struct_name} {{\n"));
    out.push_str(&format!("    const CODE: u16 = {};\n", ev.code));
    out.push_str(&format!("    const CHANNEL: WamChannel = {channel};\n"));
    out.push_str("    const WEIGHT: i64 = 1;\n");
    out.push_str("    fn wam_fields(&self) -> Vec<(u16, WamWire)> {\n");
    out.push_str("        let mut __f: Vec<(u16, WamWire)> = Vec::new();\n");
    for (id, f) in &idents {
        out.push_str(&format!(
            "        if let Some(v) = {} {{ __f.push(({}, {})); }}\n",
            field_access(id, &f.field_type),
            f.id,
            field_wire(&f.field_type, enum_name),
        ));
    }
    out.push_str("        __f\n    }\n}\n\n");
    // Raw sampling weights `[default, ring1, ring2]` for a host that selects a ring.
    out.push_str(&format!(
        "impl {struct_name} {{\n    pub const SAMPLE_WEIGHTS: &'static [u32] = &[{}];\n}}\n\n",
        raw_weights.join(", ")
    ));
}

/// Rust field type for a schema field.
fn field_rust_type(ty: &WamFieldType, enum_name: &HashMap<&str, String>) -> String {
    match ty {
        WamFieldType::Boolean => "bool".into(),
        WamFieldType::Integer | WamFieldType::Timer => "i64".into(),
        WamFieldType::Number => "f64".into(),
        WamFieldType::String => "String".into(),
        WamFieldType::Enum { module } => enum_name
            .get(module.as_str())
            .cloned()
            // A referenced enum that wasn't extracted (shouldn't happen) degrades to i64.
            .unwrap_or_else(|| "i64".into()),
    }
}

/// The `if let Some(v) = <access>` borrow expression for a field.
fn field_access(id: &str, ty: &WamFieldType) -> String {
    match ty {
        // Copy types bind by value; String borrows.
        WamFieldType::String => format!("&self.{id}"),
        _ => format!("self.{id}"),
    }
}

/// The `WamWire::…(v)` conversion in the `wam_fields` push (where `v` is the field).
/// Stays consistent with [`field_rust_type`]: an enum whose module didn't resolve
/// degrades to a plain `i64` field, so it must NOT call `as_wam_int`.
fn field_wire(ty: &WamFieldType, enum_name: &HashMap<&str, String>) -> &'static str {
    match ty {
        WamFieldType::Boolean => "WamWire::Bool(v)",
        WamFieldType::Integer | WamFieldType::Timer => "WamWire::Int(v)",
        WamFieldType::Number => "WamWire::Float(v)",
        WamFieldType::String => "WamWire::Str(v.clone())",
        WamFieldType::Enum { module } if enum_name.contains_key(module.as_str()) => {
            "WamWire::Int(v.as_wam_int())"
        }
        // Unresolved enum → the field is `Option<i64>`, so pass the int through.
        WamFieldType::Enum { .. } => "WamWire::Int(v)",
    }
}

// A stable, hand-written WAM wire codec — NOT part of the cross-language contract (it
// is the reference Rust implementation of the format every target re-implements). The
// encoding is a byte-exact port of WhatsApp Web's `WAWebWamLibProtocol` /
// `WAWamBuffer` (little-endian).
const CODEC_PRELUDE: &str = r##"// ─── WAM wire codec (stable; byte-exact port of WA Web's WAWebWamLibProtocol) ──
//
// A buffer is `"WAM"` + u8(version=5) + u8(streamId) + u16le(seq) + u8(channel),
// then a sequence of entries. Each entry is `[flags][fieldId u8|u16le][value]`:
//   flags = marker (global=0|event=1|field=2) | terminal(4) | wideId(8) | sizeClass.
// Size classes: int 0→0x10, 1→0x20, i8→0x30, i16→0x40, i32→0x50, f64→0x70,
//   string len(u8/u16/u32)→0x80/0x90/0xA0. Integers outside i32 are sent as f64
//   (matching the JS `n===(n|0)` check). Bools encode as int 0/1; enums as their int.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WamChannel {
    Regular = 0,
    Realtime = 1,
    Private = 2,
}

/// A WAM value at the wire boundary. `Int`/`Float`/`Bool` all funnel through the
/// numeric encoder (matching JS, where every number is an f64); `Str` is length-
/// prefixed UTF-8.
#[derive(Debug, Clone)]
pub enum WamWire {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
}

const M_GLOBAL: u8 = 0;
const M_EVENT: u8 = 1;
const M_FIELD: u8 = 2;
const TERMINAL: u8 = 4;
const WIDE_ID: u8 = 8;

pub struct WamBuffer {
    buf: Vec<u8>,
}

impl WamBuffer {
    /// Start a buffer with the `"WAM"` header for `channel`. `stream_id`/`seq`
    /// identify the buffer to the server (the host assigns them).
    pub fn new(channel: WamChannel, stream_id: u8, seq: u16) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"WAM");
        buf.push(5);
        buf.push(stream_id);
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.push(channel as u8);
        Self { buf }
    }

    fn tag(&mut self, flags: u8, id: u16) {
        if id < 256 {
            self.buf.push(flags);
            self.buf.push(id as u8);
        } else {
            self.buf.push(flags | WIDE_ID);
            self.buf.extend_from_slice(&id.to_le_bytes());
        }
    }

    /// Encode a numeric value exactly as WA Web's `f(...)`: an integer in i32 range
    /// uses the smallest int class; anything else (incl. large integers) is f64.
    fn write_num(&mut self, flags: u8, id: u16, v: f64) {
        if v == (v as i32) as f64 {
            let n = v as i32;
            match n {
                0 => self.tag(flags | 0x10, id),
                1 => self.tag(flags | 0x20, id),
                -128..=127 => {
                    self.tag(flags | 0x30, id);
                    self.buf.push(n as i8 as u8);
                }
                -32768..=32767 => {
                    self.tag(flags | 0x40, id);
                    self.buf.extend_from_slice(&(n as i16).to_le_bytes());
                }
                _ => {
                    self.tag(flags | 0x50, id);
                    self.buf.extend_from_slice(&n.to_le_bytes());
                }
            }
        } else {
            self.tag(flags | 0x70, id);
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    fn write_value(&mut self, flags: u8, id: u16, v: &WamWire) {
        match v {
            WamWire::Bool(b) => self.write_num(flags, id, if *b { 1.0 } else { 0.0 }),
            WamWire::Int(n) => self.write_num(flags, id, *n as f64),
            WamWire::Float(f) => self.write_num(flags, id, *f),
            WamWire::Str(s) => {
                let len = s.len();
                if len < 256 {
                    self.tag(flags | 0x80, id);
                    self.buf.push(len as u8);
                } else if len < 65536 {
                    self.tag(flags | 0x90, id);
                    self.buf.extend_from_slice(&(len as u16).to_le_bytes());
                } else {
                    self.tag(flags | 0xA0, id);
                    self.buf.extend_from_slice(&(len as u32).to_le_bytes());
                }
                self.buf.extend_from_slice(s.as_bytes());
            }
        }
    }

    /// A buffer-level global attribute (e.g. timestamp, sequence) applied to events.
    pub fn write_global_attribute(&mut self, id: u16, v: &WamWire) {
        self.write_value(M_GLOBAL, id, v);
    }

    /// Field id of the event timestamp global (the web client sets this per event).
    pub const TIMESTAMP_FIELD: u16 = 47;
    /// Field id of the per-event sequence-number global.
    pub const SEQUENCE_FIELD: u16 = 3433;
    /// Field id of the private-stats-id global (only on the `private` channel).
    pub const PRIVATE_STATS_FIELD: u16 = 6005;

    /// Set the event timestamp global (the web client writes the commit time here, in
    /// seconds). Call before the event whose time it stamps, mirroring the client.
    pub fn write_timestamp(&mut self, unix_seconds: i64) {
        self.write_global_attribute(Self::TIMESTAMP_FIELD, &WamWire::Int(unix_seconds));
    }

    /// Set the per-event sequence-number global.
    pub fn write_sequence(&mut self, seq: i64) {
        self.write_global_attribute(Self::SEQUENCE_FIELD, &WamWire::Int(seq));
    }

    /// Set the private-stats-id global (written as a string, `private` channel only).
    pub fn write_private_stats_id(&mut self, id: &str) {
        self.write_global_attribute(Self::PRIVATE_STATS_FIELD, &WamWire::Str(id.to_string()));
    }

    /// Begin an event record: its code + `weight` (callers pass the negated sample
    /// weight, as WA Web does). `has_fields` clears the terminal bit so fields follow.
    pub fn write_event(&mut self, code: u16, weight: i64, has_fields: bool) {
        let flags = if has_fields { M_EVENT } else { M_EVENT | TERMINAL };
        self.write_value(flags, code, &WamWire::Int(weight));
    }

    /// Write one field of the current event; `more` is false for the last field.
    pub fn write_field(&mut self, id: u16, v: &WamWire, more: bool) {
        let flags = if more { M_FIELD } else { M_FIELD | TERMINAL };
        self.write_value(flags, id, v);
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Standard base64 of the buffer (WA Web uploads the buffer base64-encoded).
    pub fn to_base64(&self) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b = &self.buf;
        let mut s = String::with_capacity(b.len().div_ceil(3) * 4);
        for c in b.chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | (*c.get(2).unwrap_or(&0) as u32);
            s.push(A[(n >> 18 & 63) as usize] as char);
            s.push(A[(n >> 12 & 63) as usize] as char);
            s.push(if c.len() > 1 { A[(n >> 6 & 63) as usize] as char } else { '=' });
            s.push(if c.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
        }
        s
    }
}

/// A typed WAM event: its code/channel/weight + how to flatten its set fields. The
/// default `emit` writes the event record then its fields (last field terminal),
/// matching WA Web's first-success field ordering.
pub trait WamEventDef {
    const CODE: u16;
    const CHANNEL: WamChannel;
    const WEIGHT: i64;
    fn wam_fields(&self) -> Vec<(u16, WamWire)>;
    fn emit(&self, buf: &mut WamBuffer) {
        let fields = self.wam_fields();
        buf.write_event(Self::CODE, -Self::WEIGHT, !fields.is_empty());
        let n = fields.len();
        for (i, (id, v)) in fields.iter().enumerate() {
            buf.write_field(*id, v, i + 1 < n);
        }
    }
}
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use wa_ir::{WamEnum, WamEnumVariant, WamEvent, WamField, WamFieldType, WamIr};

    fn sample_ir() -> WamIr {
        WamIr {
            wa_version: "1.0".into(),
            events: vec![WamEvent {
                name: "Probe".into(),
                code: 5,
                module: "WAWebProbeWamEvent".into(),
                channel: "regular".into(),
                weights: vec![1, 1, 1],
                private_stats_id: None,
                consumers: vec!["WAWebProbeReporter".into()],
                fields: vec![
                    WamField {
                        name: "count".into(),
                        id: 2,
                        field_type: WamFieldType::Integer,
                    },
                    WamField {
                        name: "label".into(),
                        id: 9,
                        field_type: WamFieldType::String,
                    },
                    WamField {
                        name: "mode".into(),
                        id: 4,
                        field_type: WamFieldType::Enum {
                            module: "WAWebWamEnumProbeMode".into(),
                        },
                    },
                ],
            }],
            enums: vec![WamEnum {
                name: "PROBE_MODE".into(),
                module: "WAWebWamEnumProbeMode".into(),
                variants: vec![
                    WamEnumVariant {
                        key: "OFF".into(),
                        value: 0,
                    },
                    WamEnumVariant {
                        key: "ON".into(),
                        value: 1,
                    },
                ],
            }],
        }
    }

    #[test]
    fn generated_wam_is_valid_rust() {
        let code = generate_wam(&sample_ir());
        syn::parse_file(&code).expect("generated wam.rs is valid Rust");
        assert!(code.contains("pub struct ProbeEvent"));
        assert!(code.contains("pub mode: Option<ProbeMode>"));
        assert!(code.contains("/// Emitted by: WAWebProbeReporter."));
        assert!(code.contains("impl WamEventDef for ProbeEvent"));
    }

    /// Golden byte test: compile the generated codec + a driver, emit a known event,
    /// and assert the exact wire bytes (hand-derived from WAWebWamLibProtocol, LE).
    #[test]
    fn golden_event_encodes_to_exact_wire_bytes() {
        let code = generate_wam(&sample_ir());
        let driver = r#"
fn main() {
    let mut b = WamBuffer::new(WamChannel::Regular, 7, 3);
    let ev = ProbeEvent { count: Some(42), label: Some("hi".to_string()), mode: Some(ProbeMode::On) };
    ev.emit(&mut b);
    let hex: String = b.as_bytes().iter().map(|x| format!("{:02x}", x)).collect();
    print!("{hex}");
}
"#;
        let dir = std::env::temp_dir().join(format!("wam_golden_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("wam_golden.rs");
        std::fs::write(&src, format!("{code}\n{driver}")).unwrap();
        let bin = dir.join("wam_golden");
        let st = std::process::Command::new("rustc")
            .args(["--edition", "2024", "-O"])
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .output()
            .expect("run rustc");
        assert!(
            st.status.success(),
            "rustc failed:\n{}",
            String::from_utf8_lossy(&st.stderr)
        );
        let run = std::process::Command::new(&bin)
            .output()
            .expect("run binary");
        let got = String::from_utf8_lossy(&run.stdout);
        // Header "WAM"(57 41 4d) v5(05) stream(07) seq=3 LE(03 00) channel Regular(00);
        // event flags M_EVENT|int8=31 code 05 weight -1=ff;
        // field count: M_FIELD|int8=32 id 02 value 2a;
        // field label: M_FIELD|str=82 id 09 len 02 "hi"=6869;
        // field mode (enum ON=1, LAST): M_FIELD|TERMINAL|int1=26 id 04.
        let expected = "57414d0507030000 31 05 ff 32 02 2a 82 09 02 6869 26 04";
        let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(got, expected, "wire bytes diverged from the WAM spec");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
