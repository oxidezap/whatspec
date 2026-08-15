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
| **notif** | `notif/index.json` (+ Rust) | the incoming stanza-dispatch catalog: `<notification type="…">` kinds + handlers + typed content shapes + the payload **action unions** (`w:gp2`'s 40+ group actions) |
| **tokens** | `tokens/index.json` (+ `tokens.json`) | the binary-protocol token dictionaries (single-byte + 4 double-byte), wire-indexable |
| **wasm** | `wasm/index.json` | the WebAssembly surface: emscripten payload names (`liboqs_wasm_wrapper.wasm`, …) + the bootloader (`bx`) handles the JS resolves their bytes through, with consuming modules |

Every domain ships a JSON Schema under `generated/schema/`, and a top-level `generated/manifest.json` stamps the WhatsApp version, per-domain counts, content hashes, and extraction diagnostics.

### Validation constraints, not just field shapes

Field shapes tell you how to *read* a stanza. They are not enough to *produce* one, nor to explain why a real client rejected the one you produced. So the IR also carries the rules WA Web's own parsers enforce — symmetric by construction, so they serve a parser and an emitter equally:

- **Echo rules** (`assertions[].kind == "reference"`, and `referencePath` on a field) — an answer's `from` must equal the **request's** `to`, its `id` the request's `id`. `referencePath` is the argument list of WA's `attrStringFromReference`, so `["to"]` means "the request's `to`" and `["account","action"]` means "the `action` attribute of the request's `<account>` child" — no name-matching required. An emitter that hardcodes `from="s.whatsapp.net"` makes every answer to a `g.us` request unparseable.
- **Pinned values** (`literalValue` on a field) — `type="admin"` on a successful promote, `matched="true"`/`"false"` on a blocklist update, `code=429` on a rate-limit error. `parserRequired` separates the two forms: a required pin is a hard discriminator (must be present and exact); an optional one is pinned only when present (may be omitted, must never be contradicted).
- **The per-RPC error vocabulary** (`errorArms`, plus `errorEnvelope` for a two-level error) — a **closed** set, and it differs per RPC: `BatchGetGroupInfo` accepts `400 bad-request` and `429 rate-overlimit` and **rejects `404 item-not-found`**, even though that mixin exists and other RPCs use it. Each arm pairs the `code` with the `text` that must accompany it, so an emitter cannot combine one arm's code with another's text and produce a stanza no branch accepts; an arm that range-checks instead of pinning carries `codeMin`/`codeMax`. The variant's `kind` says which side is at fault (`client_error` / `server_error`), derived from the codes rather than from the parser's name.
- **Response enums** (`enumRef` on a field) — the legal values behind an `attrStringEnum`, resolved the same way the request side already resolves them, instead of a bare `"type": "enum"`.
- **The accessor's decoded type**, kept faithful: every `attr*` / `content*` spelling WA's parsers use is classified (a `maybeAttrX` derives from `attrX`, so a flavour cannot be covered for one spelling and missed for the other), and the JID flavours stay distinct — a PN user JID and a LID user JID are different identities for the same person and must never collapse into one `string`.
- **Notification action unions** (`notifications[].actions`) — the payload inside the envelope. The `wireTag → actionType` mapping is **many-to-one** (`not_ephemeral` normalises into `ephemeral` with `duration: 0`, so branching on `not_ephemeral` is dead code) and field names are rebound (the disappearing-message timer arrives in `expiration`, but the action field is `duration`). Neither is derivable from the wire.
- **The out-of-set policy** (`unknownValue` on a field) — WA writes two things into one accessor name, and only the decoded type was ever published. `<meta polltype>` is read with `attrEnumOrNullIfUnknown` and `<message type>` with `attrEnum`: same `"type": "enum"`, same `parserRequired`, and opposite behaviour on a value the enum does not list — one yields null and the parse continues, the other rejects the stanza. That is the difference between an enum a consumer may close and one that needs a fallback variant, and it used to be recoverable only by reading the WhatsApp method name in English.
- **What `parserRequired` does not say.** It means the accessor is `attrX` rather than `maybeAttrX` — the parser rejects the node without the value *at the point it reads it*. It is not "the wire always carries this": `polltype` is `parserRequired` and the client only reads it when the envelope's `type` is `poll`, 1 of 7 values. No domain models the branch condition, so the field is an upper bound on presence; a consumer that validated on the old name (`required`) rejected legitimate traffic.
- **One index for every enum** — `enums/index.json` is keyed by `(module, name)` and contains every enum any `enumRef` in the IR names, whether or not it is an `$InternalEnum`. `name` is **not** a key: `ENUM_FALSE_TRUE` is defined by eleven different modules, and `EventType`'s two definitions disagree on `valueKind`. Those generated names are flagged `syntheticName` — WA spells them out of their own members, so they are not type names. `bitPosition` marks an int enum whose values are shift distances (`1 << 2`, not `2`), recovered from the bundle shifting by a member.
- **What the extractor could not resolve says so.** `target` separates the group server (`g.us`) from one group's own JID (`group_jid`) — WA writes them from differently-named mixins and 26 of the 33 `w:g2` requests take the second — and says `unknown` when a `to` resolves to no fixed server, `unset` when nothing writes one, instead of all four reading `s.whatsapp.net`; a field with no accessor whose content is its children is `type: "node"` instead of `string`. Both counted in the manifest, both guarded.

Note the contract version: this raised `schemaVersion` to **2.0.0**, and it is a real major bump rather than a cautious one. Four changes need action from a 1.x consumer:

- `AssertionKind` gained a `reference` variant, widening the value space of an existing field — a closed-enum consumer rejects the document rather than ignoring it (validating the current `iq/index.json` against the 1.0 schema fails 579 times).
- `ResponseVariantKind` gained `client_error` and `server_error`; a variant that was `error` may now be either. Match on all three, or use the `is_error()` grouping.
- A response variant's `errorCodes` / `errorTexts` / `errorCodeMin` / `errorCodeMax` / `errorClass` are **gone**, replaced by `errorArms` (+ `errorEnvelope`). The flat lists were removed rather than kept alongside because they were unsound: two independent lists cannot say which code goes with which text, and 117 variants admitted combinations the parser rejects.
- `ContentType` gained `integer`, the same closed-enum widening as the first item: a `<registration>` whose body is a number used to be reported as `string`. Live in the response children that read a big-endian integer content (`contentUint`).

**`schemaVersion` is now 3.0.0.** That release turned the same rule on this repository's own output: three fields were asserting things the extractor had not established, and each is fixed by widening or renaming an existing field rather than by adding an optional one. Three changes need action from a 2.x consumer:

- `IqTarget` gained `group_jid`, `unset` and `unknown`, widening the value space of `request.target` / `target`. All 143 stanzas used to read `s.whatsapp.net` — the enum had nowhere to put "not resolved", and the rule that filled it keyed on a literal `to="g.us"` the builders had stopped writing. They now read 106 `s.whatsapp.net`, **26 `group_jid`** and **6 `g.us`** — the `w:g2` requests, which the IR addressed to the server — and 5 `unknown`: the four newsletter requests whose `to` is `WAWap.JID(newsletterId)`, plus `GetGroupProfilePictures`, which folds in a runtime router addressing either a group's JID or the group server. Migration: match the three new values. `g.us` is unchanged on the wire and still means the literal group server (create, leave, list); what moved out of it is `group_jid`, one group's own `<group>@g.us`, which you must supply — sending the bare server there answers nothing. `unknown` means the addressee is a parameter of the call and the IR does not know it; `unset` that nothing writes a `to` at all and neither should you. A closed-enum consumer rejects the document until it handles them.
- `ParsedFieldType` gained `node`, and 617 fields that declared `string` while carrying children now declare it — `wAMOSubMixin`, `groupAddressingModeMixin` and the other folded-in payload mixins. Migration: a `node` is a container, not a value; read its `children` and generate no scalar for it. A consumer switching on `type` gets a value it has no arm for, which is better than the arm it had.
- A response field's `required` is now **`parserRequired`**. A rename rather than a doc fix, because the old name stated a wire fact the field never carried (see the note above). Migration: rename the key. Reading the old one yields `undefined`, which fails loudly instead of defaulting to "optional".

Additive in 3.0.0, so a 2.x consumer can ignore them: `unknownValue` on enum-accessor fields; `syntheticName` / `bitPosition` in the enum catalog; and the catalog itself growing from 328 to 403 entries so every `enumRef` resolves against it — 75 of the 87 referenced `(module, name)` pairs were in no catalog before.

Anything the extractor sees but cannot resolve structurally is counted under `manifest.diagnostics.iq.dropsByReason` rather than omitted, so "no constraint here" and "a constraint we failed to extract" never look alike. `manifest.diagnostics.iq.constraints`, `diagnostics.iq.targets.resolved` and `diagnostics.notif.actions` are floor-guarded: a WA refactor that hides one of these constructs fails the update instead of silently emptying a field. The unresolved states are guarded the other way — `scripts/lint-ir.py` pins the count of unaddressed requests and of unjudged accessors to an exact baseline. A rise means a constraint is being lost; a fall means extraction improved and the baseline owes an update. Either way the lint fails, so neither direction passes unnoticed.

## Quick start

```sh
# Fetch the current web.whatsapp.com bundle and (re)generate everything:
cargo run --release -p whatspec -- update

# …or process bundles you already have (offline):
cargo run --release -p whatspec -- update --bundles ./my-bundles

# Version-keyed cache: skip the download when the remote version is unchanged:
cargo run --release -p whatspec -- update --cache .wa-cache

# Seed that same cache from the lock-pinned GitHub Release (no live bundle fetch):
cargo run --release -p whatspec -- restore --from-lock generated/bundles.lock.json --cache .wa-cache

# Also resolve, download and store the client's wasm payloads (~41 MB), as <url-hash>.wasm
# (a cache filename is a location label, not a content address — see the note below):
cargo run --release -p whatspec -- update --cache .wa-cache --wasm-out ./wasm

# Restore a locked wasm set (its own lock + its own content-addressed release asset):
cargo run --release -p whatspec -- restore --wasm --from-lock generated/wasm.lock.json --out ./wasm

# Compare two generated outputs (e.g. across a WhatsApp version bump):
cargo run --release -p whatspec -- diff old-generated/ generated/

# Deterministically reproduce & verify generated/ from its pinned inputs (no live fetch):
./scripts/regen.sh
```

`update` is safe by default: it refuses to overwrite the committed output if any domain's coverage shrinks (pass `--allow-shrink` to accept a genuine reduction), and fails loudly if a domain extracts nothing.

## Reproducibility

WhatsApp only serves the *current* bundle version — old bundle URLs 404 — so the inputs that produced a past `generated/` can't be re-fetched from source. To keep the "same bundle → byte-identical output" promise checkable by anyone at any time, each generation pins and preserves its exact inputs:

- **`generated/bundles.lock.json`** records the content SHA-256 (+ size, and origin URL when known) of every bundle that produced the committed `generated/`, plus a one-line, order-invariant `setHash` fingerprint of the whole set.
- The **bytes** live in a durable, WhatsApp-independent store: a rolling **`bundle-store`** GitHub Release whose assets are **content-addressed** — `bundles-<version>-<setHash>.tar.xz` (pure-Rust xz, roughly half the size of gzip; legacy `.tar.gz` assets are still read) — so a set is never overwritten with different bytes and every past commit's lock keeps resolving the exact archive it pins. Published automatically by the update workflow.
  Note the two different hashes: a **release asset** is named after its *contents* (`setHash`), while a **cache** filename is named after its *URL* (the JS last segment, or `sha256(url)` for wasm) — there, the content hash lives in the cache's `manifest.json` and is what integrity is verified against. A cache filename never proves what is inside the file.
- **`whatspec restore --from-lock generated/bundles.lock.json --out <dir>`** pulls that archive, verifies every bundle's SHA-256 against the lock, and writes a directory ready for `update --bundles`. Use **`--cache <dir>`** instead to seed the exact version directly into the reusable `update --cache` layout; cache metadata and integrity files are written by the same `BundleCache` implementation as a live fetch. **`scripts/regen.sh`** wraps restore + `update --check` into a one-shot, offline determinism check — also run in CI, so every commit's committed IR (each `index.json` + `WAProto.proto`) is proven reproducible from its pinned inputs.

> Bootstrap: the lock and the first archive are created by the first run of the update workflow (or a manual `update --save-bundles <dir>` followed by `scripts/publish-bundles.sh <dir>`). Until then the CI reproducibility gate stays dormant.

## The wasm payloads

The client's heavy lifting — the VoIP engine, media codecs (mozjpeg, WebP, MP4), the post-quantum `liboqs` wrapper, VOPRF — ships as WebAssembly, and **none of those URLs appear in the JS**. The glue asks the bootloader for a numeric handle (`r("bx").getURL(r("bx")("33861"))`) and the server maps handles to content-hashed URLs. So the two halves live in different places:

- **`generated/wasm/index.json`** (committed, deterministic, offline-reproducible): the payload names the glue declares and every `bx` handle with the modules that consume it, plus the static evidence that a handle addresses wasm (`wasmBinaryLiteral` / `moduleName` / `wasmModuleCacheDep`).
- **`generated/wasm.lock.json`** (written only by a `--wasm` fetch): what those handles actually resolved to — `bxId`, `fileName`, `url`, `sha256`, `size` — fingerprinted as `wasmSetHash`. The `bxId` is the join key back to the IR.

`update --wasm` resolves them fully **headless**: the entry page inlines only ~3 handles, so `whatspec` additionally asks `/ajax/bootloader-endpoint/` for the components the page deferred — which is how it reaches the full set (9 payloads / ~41 MB at the time of writing) with no browser. The endpoint answers the same request with *different subsets*, so both request forms are merged over repeated rounds until a round adds nothing new; the resolved set is a best-effort superset and is reported as such.

A run that resolves or downloads only part of the set is cached as **incomplete**, so the next run resolves again instead of freezing one sample of a varying endpoint as that version's answer. `--wasm-out` sweeps payloads that left the set, so the directory is always exactly the lock's, and `restore --wasm` writes each payload under the name the lock records for its content hash rather than the archive's own label.

Wasm is deliberately **outside** the reproducibility chain above: no `generated/` artifact depends on the bytes, the resolved set isn't closed, and the JS `setHash` (which names the published bundles archive) must not move because a payload changed. It therefore gets its own lock and its own release asset, `wasm-<wasmSetHash>.tar.xz` — content-addressed with no version, because the payload set survives many rollouts and would otherwise be re-uploaded on every update run.

`--wasm-out <dir>` writes each payload under its **content-hashed URL segment** — `COs9e0Kj0ic.wasm`, the same identity WhatsApp serves it under — not under its `bx` handle. That is what a wasm runner keys on, so it can be pointed straight at the directory:

```sh
cargo run --release -p whatspec -- update --cache .wa-cache --wasm-out ./wasm
WA_WASM_DIR=./wasm oracle list       # e.g. wa-wasm-oracle, which runs the modules
```

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
