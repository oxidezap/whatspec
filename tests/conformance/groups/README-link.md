# LINK normalization qualification

`generated/notif/group-link.json` is a separate experimental projection of the
complete LINK case in `WAWebHandleGroupNotification`. It qualifies the three
normalized action identities, required group-data readers and the conditional
presence of `hiddenSubgroup`. A parent-group link omits that field. Other link
types read `hasChild("hidden_group")`, so a false result remains a present field.
Consumers must preserve this distinction with `Option<bool>` or equivalent.

The spans are relative to the complete preserved handler module. The additional
`WAWebHandleGroupNotificationConst` fixture resolves the LINK case's actual wire
tag. Its original bundle bytes are 268451..276687 in bundle
`09d91fdc4089c50ab1d35dd6c796ee82ef4c3296710316d20383c85738b871b8`.
`link-evidence.json` records hashes and spans for every source module. No source
is extracted by executing a bundle.

The action table is a plain JavaScript object. An ordinary future string yields
an undefined action, but names inherited from standard `Object.prototype`, such
as `toString`, `constructor` and `__proto__`, produce non-string values. Their
rows carry `unsupportedAction: true`. A typed consumer must reject those rows,
not convert them to the undefined/None fallback. This qualification assumes the
standard, unmodified `Object.prototype`; it does not model prototype mutation by
other runtime code.

Regenerate with `cargo run -p wa-notif --example group_link_contract --
<handler-bundle> <group-type-bundle>`. Both files must belong to the same verified
preserved set. The extractor rejects changed control-flow forms, an incomplete
three-way family, unresolved constants, effects/defaults/rest parameters in the
group callback, async/generator callbacks, changed output/read order and unknown
payload fields. The generated output still carries named wire readers for a
consumer's manual decoder and API adapter.

`node tests/conformance/groups/link.cjs --mutations` executes only the previously
AST-extracted official case and official constant module. The input domain is
independent of IR coverage. It compares 10 ordinary kind/hidden-child cases and
24 inherited-property cases. Row-removal, absent-versus-false corruption and
unsupported-result collapse are deliberately mutated and rejected. Synthetic
node accessors and JID conversion are mocked, so this tests normalization and
read order, not the authenticated client or decoder implementation. The JSON
oracle emitted by `--json` distinguishes unsupported result types explicitly.

This projection does not qualify CREATE, the rest of the notification envelope,
runtime cache/storage/ACK behavior, effective account gates or every group action.
