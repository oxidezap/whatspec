# Retry conformance boundary

This is a drift detector and test oracle, not a runtime policy generator. Evidence
is WhatsApp Web 2.3000.1047483476, whatspec
`eb16f595d455d8b0b3f7966a59444f4f9894c127`, schema 4.4.0. The capture was
restored from the exact `generated/bundles.lock.json` asset, with all 579 bundle
hashes, sizes and multiplicities checked. `capture/audit.json` records setHash,
bundle hashes, exclusive byte spans, all duplicate definitions and module hashes.
Divergent duplicate definitions, missing modules and parse recovery fail closed.

`retry_audit` inventories if tests, returns, throws and generator suspension sites
in HandleRetryRequest, UpdateLocalSignalSession, SendRetryReceiptJob and its
ProcessRetryKeyBundle authorization dependency. The
inventory is lexical, not execution order. An enclosing if test records lexical
containment, not whether the true or false arm runs. Nested functions start a new
continuation. Logical/conditional expressions, catch/finally routing, callee
behavior and account flags are deliberately not interpreted. Completeness is
explicitly partial and this file must never feed a production state machine.

`oracle.mjs` executes only the AST-selected UpdateLocalSignalSession generator
in an isolated VM with synthetic dependency stubs. It checks hand-reviewed
expected calls independently of the syntax inventory. It resumes every yielded
operation with success, injected rejection, or cancellation. Returned promises
are represented as effect markers, so final-return operations are observed at
invocation only; their settlement is not qualified. No actual account, crypto,
queue, persistence or transport runs. Cancellation means `generator.return()`,
not a claim about JavaScript Promise cancellation or Rust task cancellation.

The 11 scenarios cover retry 1/2/>2, reg-id mismatch, peer mismatch, handled
bundle, group/status/broadcast sender-key invalidation and scope on collision
delete. Three session mutations change retry-2, retry->2 and collision guards and
must be detected. No defaults are promoted to effective account configuration.
The receipt key gate also has 14 cases at its first suspension, covering
retry counts 0 through 6 with stateless addressing on and off. The rest of
HandleRetryRequest and SendRetryReceiptJob has syntax drift coverage only. The actual getMsgIfAuthorized generator has 12 scenarios covering identity
row binding, changed identity, already-delivered rejection, alternate-device
lookup restricted to missing records, coex precedence, addons and revoked-row
binding. Four additional mutations alter identity binding and authorization
guards and must fail the semantic oracle even without a hash check. Every
yield is also resumed with rejection or generator interruption. Eligibility
providers are synthetic facts: their internal policy is not qualified.
PN/LID migration, complete peer/status routing, receipt key upload, PQ gating
and ACK behavior still need executable dependency-closure oracles before
policy generation is justified.

The Web repairs before message authorization. whatsapp-rust intentionally gates
destructive repair behind retained-message lookup and accepts a verified key
bundle for an unknown device. Hosted addressing forces key inclusion. Consumers
must retain and name these exceptions rather than importing Web orchestration.
The consumer PR can use `session-cases.json` pinned by producer commit and file
SHA-256. That is a test fixture dependency, not a runtime dependency or global
schema/pin update.

Run from the root:

```sh
cargo test -p wa-transform --example retry_audit
cargo run -p whatspec -- restore --from-lock generated/bundles.lock.json --out /tmp/retry-inputs
cargo run -p wa-transform --example retry_audit -- generated/bundles.lock.json /tmp/retry-inputs /tmp/retry-audit
node tests/retry/oracle.mjs /tmp/retry-audit/audit.json
```

The output directory must not already exist. Updating a capture requires source
review and rerunning the oracle. The existing global schema, manifests and
consumer pin are unchanged.
