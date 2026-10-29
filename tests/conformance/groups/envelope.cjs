// Source-defined envelope matrix against the shared original-module harness.
// The constructor capture, callback byte span and complete module hashes are
// verified by harness.cjs; no parser behavior is reimplemented here.
const assert=require('node:assert/strict');
const {createHarness}=require('./harness.cjs');
const harness=createHarness('envelope-evidence.json');
const evidence=harness.evidence;
let flags;
const marker = () => ({tag: 'missing_participant_identification', attrs: {}});
const unknown = () => ({tag: 'future_action', attrs: {}});
function input(overrides = {}, children = []) {
  return {tag: 'notification', attrs: {type: 'w:gp2', from: '123456@g.us', id: 'synthetic', t: '123', ...overrides}, content: children};
}
function without(node, key) { delete node.attrs[key]; return node; }
const cases = [
  {name: 'absent-to-does-not-require-local-lid', flags: {meLid: null, mePn: null}, node: input()},
  {name: 'exact-local-lid-device', node: input({to: '100001:2@lid'})},
  {name: 'exact-local-pn-device', node: input({to: '200002:2@s.whatsapp.net'})},
  {name: 'same-account-other-device-is-not-destination', node: input({to: '100001:3@lid'})},
  {name: 'destination-error-precedes-missing-from-time-and-unknown-action', node: without(without(input({to: '100001:3@lid'}, [unknown()]), 'from'), 't')},
  {name: 'missing-from-is-required', node: without(input(), 'from')},
  {name: 'participant-is-optional', node: input()},
  {name: 'invalid-participant-is-not-a-user', node: input({participant: '123456@g.us'})},
  {name: 'missing-time-is-required', node: without(input(), 't')},
  {name: 'missing-id-is-required-after-action-processing', node: without(input({}, [marker()]), 'id')},
  {name: 'invalid-participant-pn-lid-is-caught-locally', node: input({participant: '100001@lid', participant_pn: '100002@lid'})},
  {name: 'invalid-participant-pn-device-is-caught-locally', node: input({participant_pn: '200002:2@s.whatsapp.net'})},
  {name: 'valid-participant-pn-is-retained', node: input({participant_pn: '200003@s.whatsapp.net'})},
  {name: 'disabled-username-gate-drops-marker-action-only', flags: {username: false}, node: input({participant_username: 'synthetic_username', participant_country_code: 'US', addressing_mode: 'lid'}, [marker()])},
  {name: 'enabled-username-gate-stamps-incomplete-marker', flags: {username: true}, node: input({participant_username: 'synthetic_username', participant_country_code: 'US', addressing_mode: 'lid'}, [marker()])},
  {name: 'unknown-action-is-an-error', node: input({}, [unknown()])},
  {name: 'unknown-action-precedes-final-id', node: without(input({}, [unknown()]), 'id')},
  {name: 'timestamp-wraps-to-signed32', node: input({t: '4294967297'})},
  {name: 'timestamp-reserved-minimum-is-clamped', node: input({t: '2147483648'})},
  {name: 'simple-unit-action-is-normalized', node: input({}, [{tag: 'suspended', attrs: {}}])},
  {name: 'tag-error-precedes-local-device-access', flags: {meLid: null, mePn: null}, node: {...input({to: '200002:2@s.whatsapp.net'}), tag: 'iq'}},
  {name: 'absent-children-content-is-empty-actions', node: {...input(), content: undefined}},
  {name: 'empty-byte-content-is-not-children-before-final-id', node: {...without(input(), 'id'), content: Buffer.alloc(0)}},
  {name: 'empty-string-content-is-not-children', node: {...input(), content: ''}},
  {name: 'to-requires-lid-fact-before-matching-pn', flags: {meLid: null}, node: input({to: '200002:2@s.whatsapp.net'})},
  {name: 'invalid-time-precedes-unknown-action', node: input({t: 'future_time'}, [unknown()])},
  {name: 'bot-participant-is-a-supported-user-class', node: input({participant: '200002@bot'})},
  {name: 'pn-prefix-outside-official-user-class-is-caught', node: input({participant_pn: '100002@s.whatsapp.net'})},
  {name: 'unknown-country-is-undefined-with-username-gate-enabled', flags: {username: true}, node: input({participant_country_code: 'future_country'})},
];
function encodeNode(node) {
  const encoded = {tag: node.tag, attrs: node.attrs};
  if (Array.isArray(node.content)) encoded.children = node.content.map(encodeNode);
  else if (Buffer.isBuffer(node.content)) encoded.bytes = Array.from(node.content);
  else if (typeof node.content === 'string') encoded.string = node.content;
  else assert.equal(node.content, undefined);
  return encoded;
}
const contract = require('../../../generated/notif/group-envelope.json');
const outcomes = [];
function run(test, ir) {
  const result = {};
  try { result.success = harness.parse(test.node, flags, ir); }
  catch(error) { result.error = String(error); result.errorName = error.name; result.errorParser = error.parser ?? null; result.errorReason = error.reason ?? null; }
  result.telemetryErrors = harness.stats.telemetryErrors;
  result.localLidReads = harness.stats.localLidReads;
  result.reads = harness.stats.reads;
  return result;
}

for (const test of cases) {
  flags = {username: false, history: false, opus: false, meLid: '100001:2@lid', mePn: '200002:2@s.whatsapp.net', ...test.flags};
  const result = {name: test.name, flags, input: encodeNode(test.node)};
  const original = run(test);
  const interpreted = run(test, contract);
  // Cross-realm objects are compared by their observable JSON values; undefined
  // properties are separately retained by the existing explicit assertions.
  assert.equal(JSON.stringify(interpreted), JSON.stringify(original), test.name);
  Object.assign(result, original);
  outcomes.push(result);
}
const outcome = name => outcomes.find(test => test.name === name);
assert.equal(outcome('absent-to-does-not-require-local-lid').localLidReads, 0);
assert.equal(outcome('absent-to-does-not-require-local-lid').success.externalId, 'synthetic');
assert.equal(outcome('exact-local-lid-device').success.externalId, 'synthetic');
assert.equal(outcome('exact-local-pn-device').success.externalId, 'synthetic');
for (const name of ['same-account-other-device-is-not-destination', 'destination-error-precedes-missing-from-time-and-unknown-action']) assert.match(outcome(name).errorReason, /matching meLid/);
assert.match(outcome('missing-from-is-required').errorReason, /attribute "from"/);
assert.equal(outcome('participant-is-optional').success.author, null);
assert.match(outcome('invalid-participant-is-not-a-user').errorReason, /"participant"=\{UserJid\}/);
assert.match(outcome('missing-time-is-required').errorReason, /attribute "t"/);
assert.match(outcome('missing-id-is-required-after-action-processing').errorReason, /attribute "id"/);
for (const name of ['invalid-participant-pn-lid-is-caught-locally', 'invalid-participant-pn-device-is-caught-locally', 'pn-prefix-outside-official-user-class-is-caught']) {
  assert.equal(outcome(name).success.authorPhoneNumber, null);
  assert.equal(outcome(name).telemetryErrors, 1);
}
assert.equal(outcome('valid-participant-pn-is-retained').success.authorPhoneNumber.jid, '200003@s.whatsapp.net');
const disabled = outcome('disabled-username-gate-drops-marker-action-only').success;
assert.equal(disabled.authorUsername, null);
assert.equal(disabled.authorUsernameCountryCode, null);
assert.equal(disabled.hasIncompleteParticipantInformation, false);
assert.equal(disabled.actions.length, 0);
const enabled = outcome('enabled-username-gate-stamps-incomplete-marker').success;
assert.equal(enabled.authorUsername, 'synthetic_username');
assert.equal(enabled.authorUsernameCountryCode, 'US');
assert.equal(enabled.hasIncompleteParticipantInformation, true);
assert.equal(enabled.actions.length, 0);
for (const name of ['unknown-action-is-an-error', 'unknown-action-precedes-final-id']) assert.match(outcome(name).errorReason, /Unrecognized group action future_action/);
assert.equal(outcome('timestamp-wraps-to-signed32').success.ts, 1);
assert.equal(outcome('timestamp-reserved-minimum-is-clamped').success.ts, -2147483647);
assert.equal(outcome('simple-unit-action-is-normalized').success.actions[0].actionType, 'suspend');
assert.equal(outcome('simple-unit-action-is-normalized').success.actions[0].value, true);
assert.match(outcome('tag-error-precedes-local-device-access').errorReason, /to be <notification>/);
assert.equal(outcome('tag-error-precedes-local-device-access').localLidReads, 0);
assert.equal(outcome('absent-children-content-is-empty-actions').success.actions.length, 0);
for (const name of ['empty-byte-content-is-not-children-before-final-id', 'empty-string-content-is-not-children']) assert.match(outcome(name).errorReason, /children/);
assert.equal(outcome('to-requires-lid-fact-before-matching-pn').errorName, 'MissingContextFact');
assert.match(outcome('invalid-time-precedes-unknown-action').errorReason, /"t"=\{integer\}/);
assert.equal(outcome('bot-participant-is-a-supported-user-class').success.author.jid, '200002@bot');
assert.equal(outcome('unknown-country-is-undefined-with-username-gate-enabled').success.authorUsernameCountryCode, undefined);
// JavaScript's `var c;` redeclaration preserves an already assigned local.
// This is an accepted source form and must be a no-op in the interpreter.
const redeclared = structuredClone(contract);
redeclared.prefix.push({op: 'bind', local: 7, value: null});
for(const test of cases) {
  flags = {username: false, history: false, opus: false, meLid: '100001:2@lid', mePn: '200002:2@s.whatsapp.net', ...test.flags};
  assert.equal(JSON.stringify(run(test, redeclared)), JSON.stringify(run(test)), test.name+' var redeclaration');
}
const mutations = [
  ['destination guard', ir => { ir.prefix[0].thenOps.at(-1).value.left.left.value.local = 5; }],
  ['projection', ir => { ir.projection.fields.find(f => f.name === 'author').value.local = 8; }],
  ['marker', ir => { ir.actions.missingIdentificationTag = 'wrong_marker'; }],
  ['catch', ir => { const index = ir.prefix.findIndex(op => op.op === 'tryDiagnostic'); ir.prefix.splice(index, 1, ...ir.prefix[index].body); }],
  ['read order', ir => { [ir.prefix[1], ir.prefix[2]] = [ir.prefix[2], ir.prefix[1]]; }],
];
for(const [name, mutate] of mutations) {
  const changed = structuredClone(contract); mutate(changed);
  assert.ok(cases.some(test => {
    flags = {username: false, history: false, opus: false, meLid: '100001:2@lid', mePn: '200002:2@s.whatsapp.net', ...test.flags};
    return JSON.stringify(run(test, changed)) !== JSON.stringify(run(test));
  }), name+' mutation escaped differential comparison');
}
if (process.argv.includes('--json')) console.log(JSON.stringify({waVersion: evidence.waVersion, setHash: evidence.setHash, callback: evidence.callback, cases: outcomes}, null, 2));
else console.log(`${outcomes.length} isolated official group envelope cases passed`);
