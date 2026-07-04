# whatspec

**Extract WhatsApp Web's protocol surface from its JavaScript bundle and emit a language-neutral IR (plus reference Rust code) — for any client/library to build on.**

WhatsApp Web ships its whole protocol (IQ stanzas, protobuf schemas, GraphQL operations, app-state actions, feature flags, wire enums) compiled into a large minified JS bundle. `whatspec` parses that bundle with the [`oxc`](https://oxc.rs) AST and writes a clean, versioned, deterministic intermediate representation under [`generated/`](generated). The IR is the contract — consume it from Rust, Go, TypeScript, Python, anything. The committed Rust modules are a *reference* consumer, not the point.

## What it extracts

| Domain | `generated/…` | What it is |
|---|---|---|
| **iq** | `iq/index.json` (+ Rust) | `<iq>` request builders & response parsers, per namespace |
| **proto** | `proto/WAProto.proto` | the protobuf schemas, as a `.proto` file |
| **mex** | `mex/index.json` (+ Rust) | Relay/GraphQL persisted operations (doc id, kind, typed variables/response) |
| **appstate** | `appstate/index.json` (+ Rust) | app-state (syncd) action schemas + indexing |
| **abprops** | `abprops/index.json` (+ Rust) | the A/B-props feature-flag registry (~1.7k flags: code, type, default) |
| **enums** | `enums/index.json` (+ Rust) | the wire-enum catalog (nack codes, chat/receipt types, …) |
| **notif** | `notif/index.json` (+ Rust) | the incoming stanza-dispatch catalog: `<notification type="…">` kinds + handlers + typed content shapes |
| **tokens** | `tokens/index.json` (+ `tokens.json`) | the binary-protocol token dictionaries (single-byte + 4 double-byte), wire-indexable |

Every domain ships a JSON Schema under `generated/schema/`, and a top-level `generated/manifest.json` stamps the WhatsApp version, per-domain counts, content hashes, and extraction diagnostics.

## Quick start

```sh
# Fetch the current web.whatsapp.com bundle and (re)generate everything:
cargo run --release -p whatspec -- update

# …or process bundles you already have (offline):
cargo run --release -p whatspec -- update --bundles ./my-bundles

# Version-keyed cache: skip the download when the remote version is unchanged:
cargo run --release -p whatspec -- update --cache .wa-cache

# Compare two generated outputs (e.g. across a WhatsApp version bump):
cargo run --release -p whatspec -- diff old-generated/ generated/
```

`update` is safe by default: it refuses to overwrite the committed output if any domain's coverage shrinks (pass `--allow-shrink` to accept a genuine reduction), and fails loudly if a domain extracts nothing.

## Consuming the IR

The neutral artifact is `generated/<domain>/index.json`, validated by `generated/schema/<domain>.schema.json`. Point your own codegen at those — the schemas are stable across WhatsApp rollouts (`schemaVersion`), independent of the ever-changing `waVersion`.

A Rust consumer can instead use the committed reference modules directly; they depend only on `serde` and are tree-shakeable (you pay only for what you reference).

## Design

- **Deterministic:** the same bundle always produces byte-identical output (stable sort keys, no incidental ordering).
- **C-free:** pure-Rust throughout (TLS via rustls + RustCrypto, hashing via `sha2`), enforced in CI.
- **WASM-friendly:** the IR crate and the bundle-discovery layer compile to `wasm32`, so a browser-based fetcher can reuse them.

## Disclaimer

`whatspec` is an independent project and is **not affiliated with, endorsed by, or sponsored by WhatsApp LLC or Meta**. "WhatsApp" is a trademark of its respective owner and is used here only descriptively, to identify the protocol this tool interoperates with.

## License

MIT © 2025 João Lucas de Oliveira Lopes — see [LICENSE](LICENSE).
