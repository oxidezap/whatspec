//! Identifier casing + Rust keyword escaping for generated code.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield",
];

/// Keywords that cannot be raw identifiers (`r#self` etc. is a compile error) —
/// they must be disambiguated by a suffix instead.
const RAW_INELIGIBLE: &[&str] = &["self", "Self", "crate", "super"];

/// Coerce an arbitrary string into a usable Rust identifier: non-empty, not
/// digit-led, and keyword-safe. The four `RAW_INELIGIBLE` words get a trailing
/// `_`; other reserved words get the `r#` prefix. Idempotent for already-valid
/// identifiers, so it's a no-op on the normal (alphanumeric) bundle names.
pub(crate) fn ensure_ident(s: &str) -> String {
    let base = if s.is_empty() {
        "_".to_string()
    } else if s.starts_with(|c: char| c.is_ascii_digit()) {
        format!("_{s}")
    } else {
        s.to_string()
    };
    if RAW_INELIGIBLE.contains(&base.as_str()) {
        format!("{base}_")
    } else if RUST_KEYWORDS.contains(&base.as_str()) {
        format!("r#{base}")
    } else {
        base
    }
}

static CAMEL_BOUNDARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-z0-9])([A-Z])").unwrap());
static ACRONYM_BOUNDARY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Z])([A-Z][a-z])").unwrap());
static NON_ALNUM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^a-zA-Z0-9]").unwrap());
static UNDERSCORES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"_+").unwrap());
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

/// `FooBar`/`foo-bar` → `foo_bar`.
pub(crate) fn snake_case(s: &str) -> String {
    let s = CAMEL_BOUNDARY.replace_all(s, "${1}_${2}");
    let s = ACRONYM_BOUNDARY.replace_all(&s, "${1}_${2}");
    let s = NON_ALNUM.replace_all(&s, "_");
    let s = UNDERSCORES.replace_all(&s, "_");
    s.trim_matches('_').to_lowercase()
}

/// `snake_case` coerced into a valid, keyword-safe Rust identifier.
pub(crate) fn rust_ident(s: &str) -> String {
    ensure_ident(&snake_case(s))
}

/// A Rust string literal for `s`, fully escaped (`"..."`). For ordinary
/// identifier-like bundle strings this is just `"s"`, but it stays correct if a
/// tag/attr/value ever contains a quote, backslash, or control character.
pub(crate) fn rust_lit(s: &str) -> String {
    format!("{s:?}")
}

/// The escaped *inner* content of [`rust_lit`] (no surrounding quotes), for
/// embedding inside a larger literal such as an error message.
///
/// Not for embedding into a FORMAT string — see [`fmt_lit_inner`], which is what every
/// `anyhow!`/`ensure!`/`bail!` message in the emitted module needs.
pub(crate) fn rust_lit_inner(s: &str) -> String {
    let lit = rust_lit(s);
    lit[1..lit.len() - 1].to_string()
}

/// The same, with braces doubled, for text that lands inside a `format!`-family string.
///
/// Every diagnostic the emitter writes is the first argument of `anyhow!`, `ensure!` or
/// `bail!`, which is a format string whether or not it takes arguments. A wire name, a child
/// tag or a pinned VALUE holding `{` or `}` therefore became a placeholder in the generated
/// Rust: a pin of `"{}"` produced a message with two placeholders and one argument, and the
/// emitted module stopped compiling. Nothing in CI compiles that module, so an otherwise valid
/// IR would have shipped a broken consumer — the second defect on this branch of that kind.
///
/// `rust_lit` escaping first, so a quote or a backslash is still handled once; the doubling is
/// on top of it and neither can produce the other's input.
pub(crate) fn fmt_lit_inner(s: &str) -> String {
    rust_lit_inner(s).replace('{', "{{").replace('}', "}}")
}

/// Make `base` a unique, ident-safe name: non-empty, not starting with a digit,
/// keyword-safe (incl. the raw-ineligible `self`/`crate`/…), and not already in
/// `used` (numeric suffix on collision). Shared by the abprops/enums/mex/appstate
/// catalog generators, where names come from the bundle and can be empty,
/// digit-led, Rust keywords, or collide.
pub(crate) fn unique_ident(
    base: &str,
    used: &mut HashSet<String>,
    fallback_prefix: &str,
) -> String {
    let mut name = if base.is_empty() {
        ensure_ident(fallback_prefix)
    } else {
        ensure_ident(base)
    };
    if used.contains(&name) {
        let mut n = 2;
        while used.contains(&format!("{name}_{n}")) {
            n += 1;
        }
        name = format!("{name}_{n}");
    }
    used.insert(name.clone());
    name
}

/// `foo_bar`/`fooBar` → `FooBar`, coerced into a valid Rust type/variant ident
/// (a `self`/`2fa`/empty input can't yield an invalid or empty identifier).
pub(crate) fn pascal_case(s: &str) -> String {
    let s = CAMEL_BOUNDARY.replace_all(s, "${1} ${2}");
    let s = ACRONYM_BOUNDARY.replace_all(&s, "${1} ${2}");
    let s = NON_ALNUM.replace_all(&s, " ");
    let pascal: String = WHITESPACE
        .split(s.trim())
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect();
    ensure_ident(&pascal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casing() {
        assert_eq!(snake_case("FooBarBaz"), "foo_bar_baz");
        assert_eq!(snake_case("HTTPServer"), "http_server");
        assert_eq!(snake_case("w:g2"), "w_g2");
        assert_eq!(pascal_case("foo_bar"), "FooBar");
        assert_eq!(pascal_case("getGroupInfo"), "GetGroupInfo");
    }

    #[test]
    fn keyword_escaping() {
        assert_eq!(rust_ident("type"), "r#type");
        assert_eq!(rust_ident("name"), "name");
        assert_eq!(rust_ident("for"), "r#for");
        // self/Self/crate/super can't be raw identifiers → suffixed instead.
        assert_eq!(rust_ident("self"), "self_");
        assert_eq!(rust_ident("crate"), "crate_");
        assert_eq!(pascal_case("self"), "Self_");
        // Digit-led / empty coerced to a valid ident.
        assert_eq!(rust_ident("2fa"), "_2fa");
        assert_eq!(pascal_case("123"), "_123");
    }

    #[test]
    fn unique_ident_sanitizes_and_disambiguates() {
        let mut used = HashSet::new();
        assert_eq!(unique_ident("match", &mut used, "m"), "r#match"); // keyword
        assert_eq!(unique_ident("self", &mut used, "m"), "self_"); // raw-ineligible
        assert_eq!(unique_ident("foo", &mut used, "m"), "foo");
        assert_eq!(unique_ident("foo", &mut used, "m"), "foo_2"); // collision
        assert_eq!(unique_ident("2fa", &mut used, "E"), "_2fa"); // leading digit
        assert_eq!(unique_ident("", &mut used, "fallback"), "fallback"); // empty → prefix
    }
}
