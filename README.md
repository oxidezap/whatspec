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
| **wam** | `wam/index.json` (+ Rust) | the client-telemetry surface: 436 events (code, typed fields, channel, sampling weights) **plus the buffer they are written into** — the globals its header carries with the channels each is legal on, the private-stats rotation groups, the protocol/flush constants — and, per event, the places WA Web constructs it |
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

### Enough to *call* WhatsApp's own builder, not only to encode the stanza yourself

Everything above describes the wire. That serves a client that encodes the stanza itself — it needs to know a group create carries a `<participant jid=…>` of type `user_jid`. It does not serve a client that **runs WhatsApp's own modules**, which needs the other half: that the value goes in `args.participantArgs[].participantJid`. Neither half implies the other — WA picks the argument key independently of the attribute it lands in (`subjectElementValue` becomes the *text* of `<subject>`) — and almost every request is composed out of mixins, so the argument key is usually defined in a different module from the tag it fills. So the request side also carries the builder:

- **Argument paths** (`argPath` on a request node, an attribute, or an element content) — the absolute path from the builder's argument object, as segments. `list` marks each segment a repeated combinator iterates: `REPEATED_CHILD(template, list, min, max)` calls the template once per element, while `OPTIONAL_CHILD`/`HAS_OPTIONAL_CHILD` hand the object over whole. Nested repeats mark more than one — `userArgs[] → deviceArgs[] → deviceId` is a key read off an element of an element. The same suffix in the wrong place writes the value where the vendor builder never reads it, and the stanza goes out without it. Recovered structurally — from the function's single argument parameter and the `var x = <param>.<key>` destructure — never from a name: `…Args`, `has…` and `any…` are WA conventions that make the IR readable, not evidence. A path that isn't structurally recoverable is absent and counted under `manifest.diagnostics.iq.builder`, never guessed. The legacy `WAWeb*Job` builders take positional parameters rather than one options object, so they get no path at all and are counted as such.
- **Cardinality of a request child** (`presence`, plus `repeatMin`/`repeatMax`) — the three states `WASmaxChildren` distinguishes, of which the wire shows one. `<locked/>` on a group create is a *presence marker*: its template takes no arguments, its whole meaning is being there, and a consumer can model it as a `bool` — which it must not do for an optional child and cannot do for an empty required one, all three of which are the same empty element on the wire. The repeat bounds are the ones a server enforces (`add/participant` 1..1024, `query/group` 1..10000, `media_list` 0..10); a `repeatMin` with no `repeatMax` is WA's explicit `1/0`, i.e. unbounded above, which stays distinguishable from a child that states no bound at all and has neither.
- **The addressee's argument key** (`targetArgPath` on a request) — `target` says a request is sent to one group's own JID rather than to a server, and a consumer running the vendor builder still has to know which argument supplies it. 30 of the 31 runtime-addressed requests carry it (`iqTo`, and one composed through a mixin group as `baseGetGroupOrServerMixinGroupArgs → baseGetGroup → iqTo`); the one that does not is a legacy `WAWeb*Job` builder, which takes positional parameters and so has no argument object for a path to point into.
- **Element values that survive the mixin boundary** (`content`) — `smax("subject", null, subjectElementValue)` is the entire payload of a group rename. WA's builders bind that payload to a local before writing it, and a bare local used to be ignored outright in case it was a node variable. It is now told apart structurally: a local that resolves to an argument path is content, one that resolves to a `smax(…)` call is a child.

**`schemaVersion` is now 4.0.0.** Nearly all of the above is additive — every new property is optional and skipped at its default, and each committed `*/index.json` validates clean against its own **3.0.0** schema (0 errors across all 12 domains). One change is not, and it is the whole reason for the major: `value` on a request attribute was documented as present only for `kind: "const"`, and now also carries the fixed literal of a `WASmaxAttrs.OPTIONAL_LITERAL(lit, flag)` attribute, whose `kind` is `optional`. Migration: read `value` as "what this attribute says **when** it is written" rather than as an unconditional constant — on an `optional` attribute the builder writes it only when its boolean gate is set, which is the attribute analogue of a presence marker. Eight committed IQ attributes are in that state, and the old JSON Schema accepts every one of them, which is precisely why the version has to say what the schema cannot. Additive alongside it: `argPath`, `presence`, `repeatMin`/`repeatMax`, `targetArgPath`, and `content` populated on 45 request nodes that previously carried none.

### Telemetry you can send, not just a list of event names

The WAM catalog says what a metric contains. It does not say what carries it, and a consumer that has only the catalog is holding the contents of a message it cannot assemble or schedule. WA Web states the rest declaratively, in three modules next to the one the catalog comes from, and the IR now carries them:

- **The buffer's globals** (`globals`) — `defineGlobal({name: [id, type, channels]})`, the values written ahead of the events they apply to. Same id space and same type vocabulary as an event field, plus one axis an event field has no analogue for: the **channels the global may be written on**. That axis is not decorative — WA's own writer maps `realtime` onto `regular` and then skips any global whose list does not contain the buffer's channel, so putting `abKey2` (`regular` only) into a `private` buffer produces one no client ever sends. 46 of them, and the reference codec's private-stats field id now comes from `psId` instead of being a literal in hand-written Rust.
- **The private-stats groups** (`privateStatsIds`) — the table an event's `privateStatsId` is a foreign key into. Every `private`-channel event has one, and until now it was an integer that resolved against nothing: a consumer knew the event belonged to a rotation group without knowing which, or for how long. Nine entries: the eight `PrivateStatsAllIds` publishes, and the `none` group (id `0`) that `WAWebWamPrivateStats` adds on top of it — the one 21 of the 50 private events name, so the published table alone leaves two fifths of the channel unresolvable. Each entry says which module it came from, and `rotationPeriodDays` keeps WA's `-1` sentinel rather than normalising "never rotates" into a period.
- **The buffer constants** (`constants`) — the six literals of `WAWebWamConstants`: `WAM_PROTOCOL_VERSION` (byte 4 of every buffer, previously hardcoded in the generated codec with nothing saying where it came from), the two size caps, the batch size, and the in-memory/rotation intervals. The line drawn is the module: these are literals a module exists to export, whereas the 1 % beaconing roll in `WAWebWamBeaconing` is a step of an algorithm, and a number lifted out of an algorithm is not something a consumer can act on.

**Where each event is emitted** (`callSites`) is the fourth, and it corrects a claim rather than adding one. `consumers` was documented as "modules that construct + `.commit()` this event" while holding the **dependency graph** — every module that imports the event's module, whatever it does with it, so a module that only reads the type is indistinguishable from one that emits, and the worker's router (`WAWebWamProcessWorkerData`) is on 63 events for routing them rather than sending them. The doc now says what the field is, and beside it `callSites` says what was actually found: 807 sites, out of 883 constructions of `new (o("WAWeb…WamEvent").<Export>)(…)` seen in the bundle, each with the fields written there — in the constructor's object, by a later `event.field = …`, or through `event.set({…})`, which are three spellings of one mechanism (`set` is `for (k in obj) this[k] = obj[k]`, and the constructor calls it). 3293 `(site, field)` pairs, 784 of them with a value that is fixed at extraction time: a literal, or an enum member named rather than resolved to its integer.

That turns parity from a reading exercise into a mechanical one: the fields a consumer's own emitter fills must be a subset of the union of the real sites, and a field no site writes is a question to answer. Two things it deliberately does not say. **Not when**: the guard a construction sits under is control flow, so a call site is a place the client *can* emit the event. **Not exhaustively, without saying so**: a site whose argument is merged (`babelHelpers.extends`) or built elsewhere carries `partial: true`, and its field list is a lower bound — 121 of the 807. A site that only overrides the sampling `weight` is **not** partial: `weight` is not a field, so nothing is missing from its list; that override is counted on its own. The constructions that yielded no field set at all are counted in `manifest.diagnostics.wam` by the form that resisted (104 built into a variable first, 41 of the generic `RawWamEvent` whose schema is supplied at runtime), never omitted — and the block closes on itself: 883 constructions = 807 published sites + 35 collapsed as identical to one already published + 41 with no catalog entry.

Two smaller corrections came out of the same pass, both visible in the numbers: the catalog gained **23 fields** it had been dropping, because the minifier writes a repeatedly used enum module as `(e = o("WAWebWamEnum…")).X` once and `e.X` afterwards, and only the first spelling was read — one event published a single field while WA declares five; and `weights` is now documented as the **default it is**, since the client's own writer lets a runtime sampling lookup override it and four call sites assign `weight` directly.

**`schemaVersion` is now 4.1.0**, a minor because all of the above is additive: every new property is optional, the new lists are skipped when empty, and the committed `wam/index.json` validates against the **4.0.0** schema with 0 errors. The one thing a 4.x consumer must re-read is `consumers`, whose data did not change and whose documentation did. `scripts/lint-ir.py` gained the three invariants the JSON Schema cannot state — a global with no channel, a `privateStatsId` that resolves against no group, a call site naming a field its event does not declare — and `diagnostics.wam.{globals,privateStatsIds,constants,callSites}` are floor-guarded like every other coverage number.

### Whether the official client actually sends a variable

The mex catalog says a persisted operation takes `fetch_wamo_sub: boolean`. It did not say whether WA Web ever leaves that key out, and a persisted query is validated on the *presence* of a variable its compiled tree references, not only on its type - so the difference is a `400 Bad Request` with nothing in it naming the variable ([oxidezap/whatsapp-rust#1372](https://github.com/oxidezap/whatsapp-rust/issues/1372) is two of them). Worse than unstated: silence read as permission. An emitter generating `Option<T>` with `skip_serializing_if` from a bare type tag sends `{}` and is never told which key was missing.

The evidence was already in hand. `variablesShape` is recovered from the call site WA Web writes, and the call site says both things at once:

```js
fetchQuery(r, {
  fetch_wamo_sub:       (t == null ? void 0 : t.fetchWamoSub)       === !0,
  fetch_status_metadata:(t == null ? void 0 : t.fetchStatusMetadata) === !0,
})
```

`=== !0` coerces `undefined` to `false`. There is no path on which either key is absent, and the shape pass kept the resulting `boolean` and discarded that. **`variablesPresence`** now carries it, a sibling map keyed and nested exactly like `variablesShape`:

- **`always`** - every recovered call site writes the key with a value no evaluation can make `undefined`: a literal, a comparison, a coercion (`x === !0`, `!!x`), a `??`/`||` whose right side is itself defined, a ternary whose arms both are, or a local bound to one of those (`fetch_full_image` reads `c`, and `c` is `u !== "INVITE"`).
- **`conditional`** - a site can leave it off: a spread behind a gate (`...(cond && {…})`), a value that passes through something that may be `undefined` (a bare binding, a property read, a lowered optional chain), or a site whose object does not write the key at all. `FetchNewsletter`'s `fetch_viewer_metadata` is a plain `i.fetchViewerMetadata`, and `JSON.stringify` drops a key whose value is `undefined`, so a key written with one is not a key on the wire.
- **`undetermined`** - not established, and deliberately not folded into `conditional`. `fetch_pinned_messages` is `isChannelMessagePinReadEnabled()`: the key is written unconditionally and the call's result is not something this extractor reads. "The official client sometimes omits this" is a claim, and an unread expression has not earned it - a consumer that cannot tell the two apart is back where it started.

The unit is the key, not the variable, so a nested object is answered too - `FetchNewsletter`'s `input` is `{key: t, type: u, view_role: a}`, and only `type` is `always` (it is bound to a ternary of two string literals; the other two are parameters passed straight through). Presence is read structurally from the `oxc` AST, never from the name: `fetch_*` being a boolean says nothing about whether it is sent, and guessing there is the opposite of the point.

Across the domain: **412 variable keys in 128 operations - 123 `always`, 184 `conditional`, 105 `undetermined`**, of which 12 operations have no verdict at all (5 where no call site was recovered, the rest where the site was recovered and writes only values the classifier does not read). Every key `variablesShape` types carries a verdict, checked by `scripts/lint-ir.py`: a typed key with no presence entry is exactly the ambiguity this removes. `diagnostics.mex` publishes the distribution plus `dropsByReason`, the two `undetermined` states are held to a baseline, and `presenceAlways` is floor-guarded - the keys stay published when a call site stops being readable, just as `undetermined`, so the operation count would see nothing.

`diagnostics.mex` also splits the persisted ids by where this run read them - 110 inline, 33 from a `_facebookRelayOperation` sibling, **0 falling back to the operation name** - and floors the sum. A `docId` is a bare numeric string, so an id that did not change and an id nothing re-derived are the same value on inspection; the origin is what tells them apart, and both of the ids in that issue are read from `params.id` in the current bundle.

**`schemaVersion` is now 4.2.0**, a minor: `variablesPresence` is a new optional property, skipped when empty, and the committed `mex/index.json` validates against the **4.1.0** schema with 0 errors. A 4.x consumer that ignores it keeps working and keeps the defect - nothing forces the field on anyone, which is why it is a sibling map rather than a richer `variablesShape` leaf; folding presence into the type tags would have broken every consumer reading them as strings, for a fact that belongs to the key rather than to the type. The reference Rust consumer does read it: an `always` variable is emitted as `T` and always serialized, and everything else - `undetermined` included - keeps `Option<T>` with `skip_serializing_if`.

Anything the extractor sees but cannot resolve structurally is counted under `manifest.diagnostics.iq.dropsByReason` rather than omitted, so "no constraint here" and "a constraint we failed to extract" never look alike. `manifest.diagnostics.iq.constraints`, `diagnostics.iq.targets.resolved`, `diagnostics.iq.builder` and `diagnostics.notif.actions` are floor-guarded: a WA refactor that hides one of these constructs fails the update instead of silently emptying a field. The unresolved states are guarded the other way — `scripts/lint-ir.py` pins the count of unaddressed requests and of unjudged accessors to an exact baseline. A rise means a constraint is being lost; a fall means extraction improved and the baseline owes an update. Either way the lint fails, so neither direction passes unnoticed.

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

The reusable storage boundary lives in the `wa-store` crate. It owns JS/wasm
lock identities, exact-set restoration and selected historical wasm recovery;
consumers can pin this crate by Git revision without depending on the protocol
extractors or the `whatspec` CLI. `wa-fetch` remains the transport/discovery
layer. Codec recipes and execution hosts do not belong in either crate.

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
