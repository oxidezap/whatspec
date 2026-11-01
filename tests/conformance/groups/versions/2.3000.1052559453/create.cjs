// Current CREATE is executed through the complete, hash-qualified original
// callback, including participant/history decoders and the real share-mode enum.
const assert = require('node:assert/strict');
const { createHarness, encodeNode, plain } = require('../../harness.cjs');
const harness = createHarness('evidence.json', { fixtureRoot: __dirname });
const cases = require('./create-cases.cjs').slice();
const n = (tag, attrs = {}, content) => ({
  tag,
  attrs,
  ...(content === undefined ? {} : { content })
});
for (const mode of ['admin_share', 'all_member_share', 'future_mode'])
  cases.push({
    name: 'history-share-mode-' + mode,
    flags: {},
    node: n('create', {}, [
      n('group', { subject: 'synthetic', creation: '123' }, [
        n('member_share_group_history_mode', {}, Buffer.from(mode))
      ])
    ])
  });
cases.push({
  name: 'history-is-read-without-feature-gate',
  flags: { history: false },
  node: n('create', {}, [
    n('group', { subject: 'synthetic', creation: '123' }, [
      n('participant', {
        jid: '100001@lid',
        join_time: '123',
        group_history_sent_state: 'HISTORY_SENT'
      })
    ])
  ])
});
cases.push({
  name: 'disabled-creator-country-and-username-success',
  flags: { username: false },
  node: n('create', {}, [
    n(
      'group',
      {
        subject: 'synthetic',
        creation: '123',
        creator_country_code: 'future',
        creator_username: 'gated',
        s_o_username: 'gated'
      },
      [n('participant', { jid: '100001@lid', join_time: '123' })]
    )
  ])
});
const outcomes = [];
for (const test of cases) {
  const record = {
    name: test.name,
    flags: { history: false, username: false, opus: false, ...test.flags },
    input: encodeNode(test.node)
  };
  try {
    const result = harness.parse(
      n('notification', { from: '123456@g.us', id: 'synthetic', t: '123' }, [test.node]),
      test.flags
    );
    assert.equal(result.actions.length, 1);
    record.success = plain(result.actions[0]);
  } catch (error) {
    record.error = String(error);
  }
  outcomes.push(record);
}
const byName = Object.fromEntries(outcomes.map((r) => [r.name, r]));
const action = (name) => {
  assert.ok(byName[name].success, name + ': ' + byName[name].error);
  return byName[name].success;
};
assert.equal(
  action('default-and-unconditional-participant-username').groupInfo.participants[0].username,
  'ungated'
);
assert.equal(action('default-and-unconditional-participant-username').isNewGroup, false);
assert.equal(action('new-group-unknown-trigger').isNewGroup, true);
assert.equal(action('existing-group-unknown-trigger').isNewGroup, false);
assert.equal(action('new-group-unknown-trigger').groupInfo.ephemeralDuration, 12);
assert.equal(action('new-group-unknown-trigger').groupInfo.disappearingModeTrigger, undefined);
assert.equal(
  action('existing-group-unknown-trigger').groupInfo.disappearingModeTrigger,
  'unknown_groups'
);
assert.match(byName['unknown-role-precedes-creator'].error, /type.*future_role/);
assert.match(byName['invalid-participant-join-time-error'].error, /join_time/);
assert.equal(action('parent-mode-flags-and-reason').groupInfo.parentGroup, '123456@g.us');
assert.equal(action('parent-mode-flags-and-reason').groupInfo.limitSharingEnabled, false);
assert.equal(action('time-cast-wraps-before-normalization').groupInfo.creation, 1);
assert.equal(
  action('time-cast-wraps-before-normalization').groupInfo.participants[0].joinTime,
  -2147483647
);
assert.equal(
  byName['empty-byte-description-still-requires-id-before-creator'].error,
  'XmppParsingFailure: synthetic: expected <description> to have attribute "id"'
);
const gated = action('disabled-creator-country-and-username-success').groupInfo;
assert.equal(gated.creatorCountryCode, null);
assert.equal(gated.creatorUsername, null);
assert.equal(gated.subjectOwnerUsername, undefined);
assert.equal(gated.participants[0].joinTime, 123);
for (const mode of ['admin_share', 'all_member_share'])
  assert.equal(action('history-share-mode-' + mode).groupInfo.memberShareGroupHistoryMode, mode);
assert.equal(
  action('history-share-mode-future_mode').groupInfo.memberShareGroupHistoryMode,
  undefined
);
assert.equal(
  action('history-is-read-without-feature-gate').groupInfo.participants[0].joinTime,
  123
);
if (process.argv.includes('--json'))
  console.log(
    JSON.stringify(
      { waVersion: harness.evidence.waVersion, setHash: harness.evidence.setHash, cases: outcomes },
      null,
      2
    )
  );
else console.log(`${outcomes.length} current official CREATE cases passed`);
