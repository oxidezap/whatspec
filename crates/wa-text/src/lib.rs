//! Byte-level text scanners shared by the static extractors (wa-mex, wa-appstate)
//! for walking WA Web's minified bundle JS. Port of the reference's
//! `skipString`/`skipWs`/`skipExpr`. All indices are byte offsets; callers only
//! slice at ASCII structural positions. WASM-safe (only `sha2`, which is
//! pure-Rust — no C).

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`. Shared by the bundle cache and the manifest
/// content hashes so they never drift; lives here (pure, always-available,
/// C-free) rather than behind any crate's feature flag.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        // Infallible: writing to a String never errors.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Skip a quoted string starting at `i` (the opening quote `"`/`'`/`` ` ``).
/// Returns the index just past the closing quote, or `b.len()` if the string is
/// unterminated — never an out-of-range index, so the result is always a safe
/// slice bound even on truncated/malformed input (a trailing `\` would otherwise
/// overrun the end).
pub fn skip_string(b: &[u8], i: usize) -> usize {
    let q = b[i];
    let mut i = i + 1;
    while i < b.len() && b[i] != q {
        if b[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    // `i` is at the closing quote (return one past it) or at/after end-of-input
    // (unterminated). Clamp so we never return past `b.len()`.
    (i + 1).min(b.len())
}

/// Skip whitespace and `//` / `/* */` comments from `i`. Returns an index in
/// `i..=b.len()` — clamped so an unterminated `/* … */` (whose closing `*/` skip
/// would otherwise step past the end) can't yield an out-of-range slice bound.
pub fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            break;
        }
    }
    i.min(b.len())
}

/// Skip a balanced expression from `start` until a top-level char in `stops`
/// (respecting `()`/`{}`/`[]` nesting and string literals). Returns the index AT
/// the stop char (or end of input).
pub fn skip_expr(b: &[u8], start: usize, stops: &[u8]) -> usize {
    let mut i = start;
    let (mut dp, mut db, mut dbr) = (0i32, 0i32, 0i32);
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\'' || c == b'`' {
            i = skip_string(b, i);
            continue;
        }
        match c {
            b'(' => dp += 1,
            b')' => {
                if dp == 0 && stops.contains(&c) {
                    return i;
                }
                dp -= 1;
            }
            b'{' => db += 1,
            b'}' => {
                if db == 0 && stops.contains(&c) {
                    return i;
                }
                db -= 1;
            }
            b'[' => dbr += 1,
            b']' => {
                if dbr == 0 && stops.contains(&c) {
                    return i;
                }
                dbr -= 1;
            }
            _ => {
                if dp == 0 && db == 0 && dbr == 0 && stops.contains(&c) {
                    return i;
                }
            }
        }
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_string_handles_escapes() {
        let s = br#""a\"b"x"#;
        assert_eq!(skip_string(s, 0), 6); // past the closing quote
        assert_eq!(&s[6..], b"x");
    }

    #[test]
    fn skip_ws_eats_comments() {
        let s = b"  /* c */ // line\n x";
        let i = skip_ws(s, 0);
        assert_eq!(s[i], b'x');
    }

    #[test]
    fn skip_expr_respects_nesting_and_strings() {
        // The top-level comma is after the nested call + a string containing a comma.
        let s = b"f(a,b),{x:\"y,z\"},rest";
        let i = skip_expr(s, 0, b",");
        assert_eq!(s[i], b','); // the comma after `f(a,b)`
        assert_eq!(i, 6);
        // A `,` inside a string is not a stop; the one after it is.
        let s2 = b"\"a,b\",rest";
        let end = skip_expr(s2, 0, b",");
        assert_eq!(&s2[end..], b",rest");
    }

    // ── Property / fuzz tests ────────────────────────────────────────────────
    //
    // The scanners run over a 70+ MB attacker-influenced bundle, so the safety
    // bar is "never panic / never read out of bounds on any byte sequence". We
    // drive them with a deterministic xorshift PRNG (reproducible in CI, no deps)
    // biased toward the structural bytes (quotes, brackets, escapes, comment
    // markers) that exercise the tricky paths, and assert their invariants.

    /// Deterministic xorshift64* generator — fixed seed ⇒ identical CI runs.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// A byte drawn from a small alphabet that maximizes structural coverage
    /// (quotes, brackets, escape, comment markers, separators) plus the full
    /// 0x00..=0xFF range so non-ASCII / NUL bytes are exercised too.
    fn fuzz_byte(rng: &mut Rng) -> u8 {
        const INTERESTING: &[u8] = b"\"'`\\/*(){}[],; \n\tabc01\x80\xff";
        if rng.below(4) == 0 {
            rng.below(256) as u8
        } else {
            INTERESTING[rng.below(INTERESTING.len())]
        }
    }

    fn fuzz_input(rng: &mut Rng) -> Vec<u8> {
        let len = rng.below(40);
        (0..len).map(|_| fuzz_byte(rng)).collect()
    }

    const STOPS: &[&[u8]] = &[b",", b",)", b"})", b";", b")", b"]"];

    #[test]
    fn fuzz_scanners_never_panic_and_stay_bounded() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for _ in 0..50_000 {
            let b = fuzz_input(&mut rng);
            let len = b.len();

            // skip_ws: defined for any start in 0..=len; result is forward and
            // clamped to a valid slice bound (never past len).
            for i in 0..=len {
                let j = skip_ws(&b, i);
                assert!(j >= i, "skip_ws went backwards: {i} -> {j}");
                assert!(j <= len, "skip_ws overran: {j} > {len}");
                // When it lands inside the slice, it's on a non-skippable byte
                // (not whitespace, not the start of a `//` or `/* */` comment).
                if j < len {
                    let c = b[j];
                    let starts_comment =
                        c == b'/' && j + 1 < len && (b[j + 1] == b'/' || b[j + 1] == b'*');
                    assert!(
                        !c.is_ascii_whitespace() && !starts_comment,
                        "skip_ws stopped on skippable byte {c:#x} at {j}"
                    );
                }
            }

            // skip_string: precondition is "start points at a quote". It always
            // advances and never exceeds len+1.
            for i in 0..len {
                if matches!(b[i], b'"' | b'\'' | b'`') {
                    let j = skip_string(&b, i);
                    assert!(j > i, "skip_string did not advance: {i} -> {j}");
                    assert!(j <= len, "skip_string overran: {j} > {len}");
                }
            }

            // skip_expr: forward, bounded by len+1, and when it stops inside the
            // slice it stops on one of the requested stop chars.
            for stops in STOPS {
                let j = skip_expr(&b, 0, stops);
                assert!(j <= len, "skip_expr overran: {j} > {len}");
                if j < len {
                    assert!(
                        stops.contains(&b[j]),
                        "skip_expr stopped on non-stop byte {:#x} at {j} (stops={stops:?})",
                        b[j]
                    );
                }
            }
        }
    }

    #[test]
    fn fuzz_skip_expr_ignores_stops_inside_strings() {
        // A stop char that only appears inside a quoted string must not stop the
        // scan: skip_expr should run to the end of input.
        let mut rng = Rng(0x1234_5678_9ABC_DEF0);
        for _ in 0..20_000 {
            let inner = fuzz_input(&mut rng);
            // Build `"<inner>"` with any raw quotes/backslashes in `inner` escaped
            // so the wrapper stays a single well-formed string literal.
            let mut s = vec![b'"'];
            for &c in &inner {
                if c == b'"' || c == b'\\' {
                    s.push(b'\\');
                }
                s.push(c);
            }
            s.push(b'"');
            // No stop char exists outside the string, so the scan reaches the end.
            let j = skip_expr(&s, 0, b",;)]}");
            assert_eq!(j, s.len(), "skip_expr stopped early inside a string: {s:?}");
        }
    }
}
