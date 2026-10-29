# Group notification qualification

These isolated contracts qualify WA Web 2.3000.1047483476 from the exact bundle
set recorded in evidence.json. They supplement the existing notification shape
catalog without changing its schema/pin or declaring a new complete manifest
domain.

- `group-envelope.json` preserves ordered root guards, lazy identity facts,
  local PN diagnostic recovery, the external action boundary and final projection.
- `group-link.json` preserves dynamic LINK actions and hidden-subgroup omission.
- `group-unlink.json` preserves parent/subgroup/sibling and integrity decisions.

The native examples `group_envelope_contract`, `group_link_contract` and
`unlink_contract` accept complete Metro modules from the restored bundle set.
The committed complete handler/type/tag-constant fixtures reproduce the same
contracts. Rust tests mutate guards, read order, import bindings, callback
modes/effects and object shapes; unsupported forms reject the projection.

Envelope extraction fingerprints the opaque module frame, action callback and
local action helpers with SHA-256, using AST spans. The root prefix and final
projection are still lowered independently; they are not part of these opaque
fingerprints. Only one diagnostic catch is supported: multiple catches would
share the factory template cache, whose competing initialization is not modeled.
Its cache identifier must resolve to the qualified module binding. Prefix bindings cannot shadow an opaque dependency or remove an
opaque root capture. This is snapshot qualification, not a proof that arbitrary
JavaScript calls are pure: any opaque source change (including whitespace)
rejects extraction until its source effects and adapters are independently
requalified and the fingerprints deliberately updated. Property writes, aliases,
mutating calls and changes in transitive factory helpers therefore cannot pass
merely because they lack an identifier assignment.

The envelope suite interprets the committed IR against the same 29 source inputs
and compares results, errors, telemetry and ordered accessor reads. Independent
IR mutations cover destination guards, projection, markers, local catch recovery
and read order. Complex child payloads stay at the external adapter boundary.

Run all source comparisons with:

```sh
node tests/conformance/groups/unlink.cjs --mutations
node tests/conformance/groups/link.cjs --mutations
node tests/conformance/groups/create.cjs
node tests/conformance/groups/envelope.cjs
node tests/conformance/groups/actions.cjs
```

The scripts verify module/helper hashes and execute isolated original functions
with preserved original decoders, JID classifiers, time conversion and enums.
Evidence files enumerate the account, conversion, registry, telemetry and binary
adapter mocks. `--json` emits immutable synthetic inputs and original outcomes
for consumer tests. Extraction uses AST spans; source discovery never executes
a bundle. Transport, authenticated client behavior, storage, cache/rotation and
ACK effects remain outside these parsers.

LINK/UNLINK plain-object lookups can return inherited non-string values.
Contracts mark those outcomes explicitly unsupported; ordinary unknown strings
still produce the separate undefined-action result. Qualification assumes the
standard unmodified Object.prototype. See README-link.md for LINK details.

Consumers keep public compatibility adapters separate from owned normalized
outputs. Handwritten complex-action adapters are qualified by the independent
CREATE/action fixtures; the envelope and dynamic link decisions are generated
from the typed IR.
