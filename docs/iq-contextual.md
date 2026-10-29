# Contextual IQ generation

`generate_iq_checked` admits a selected catalog only when the reference emitter
can produce its request and response. `diagnose_iq_generation` reports every
entry, including entries rejected for unresolved destinations, argument paths,
missing RPC outcomes, unsupported guards or overlapping outcomes. An admitted
entry is emittable, not independently proven complete. Request repetition and
disjunctions remain rejected by this entry point until their validation has a
fallible builder API. The legacy generator remains available.

Inspect the entire catalog without hiding the rejected entries:

```sh
cargo run -p wa-codegen --example iq_contracts -- generated/iq/index.json
```

Append exact module names to emit only that selected, checked set. Missing or
duplicate names fail. There is no claim that all recovered stanzas qualify.

Generated contextual specs implement `uses_contextual_response` and
`parse_response_with_context(response, request)` on `IqSpec`. The request must
be the immutable stanza actually sent after ID assignment. The current snapshot
uses `id=request.id` and `from=request.to`; unsupported or nonuniform reference
paths fail generation. Specs with error alternatives also implement
`handles_iq_errors`. The runtime must deliver those error nodes before generic
error conversion. The helper taking the two exact request attributes remains
available for existing consumers. The response-only entry point fails when
correlation is required. Socket handling, cancellation and timeouts stay manual.

The compiled selected-family tests cover SetSubject, AcceptGroupAdd,
JoinLinkedGroup, DeleteParentGroup, ActiveIQ and GetCountryCode. Cases include
approval precedence, duplicate-child fallback, absent optional request input,
required response payload, literal code/text pairs and mismatched request echoes.
Only the tested cases qualify; selection does not certify every field in a family.

The added ActiveIQ test exposed a lost constraint. `literalJid(attrDomainJid,
node, "from", "s.whatsapp.net")` previously became a JID read with no literal.
The shared extractor now retains its accessor, literal and root assertion. This
also corrects existing notification and server-request records using that same
helper; their regenerated changes are limited to those constraints.

Evidence is under `tests/conformance/contextual`. The provenance records byte
spans and module hashes from all 579 verified bundles in WA 2.3000.1047483476,
set `05609307e68b0f6ccfd2a121a573049999e38b752cfe7155ebbe5c661805751b`.
The archive SHA-256 is
`22243b9c2ff18a66cea8fd66551821fe0f9f09786d107e2be8284637db86c349`.
`active-oracle.mjs` executes the exact AST-captured parser on 81 synthetic inputs.
Four explicit stub modules cover strings, domain JIDs, unique-child lookup and
Result values. This verifies parser control flow against those bounded helper
semantics; it does not execute the full Web helper stack or contact a server.
`cargo test -p wa-codegen --test checked_iq` checks the JS fixture and compares
freshly emitted Rust with every recorded case. Node is a test dependency only.

`recording-oracle.json` preserves separate sigilo instrumentation at
`4eae4ecc0a4a9f32ded32fa7b52ba60bf1232b15` for ActiveIQ and JoinLinkedGroup.
It independently records the lost server literal, request argument bindings and
ordered response modules. Its helpers report success and record cardinality;
they do not validate concrete wire nodes. It is extraction evidence, not the
81-case behavior oracle, and no JS runtime belongs in the Rust core.
