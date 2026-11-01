// Synthetic inputs shared by the independently qualified historical and current parsers.
const p = (attrs = {}) => ({ tag: 'participant', attrs, content: undefined });
const group = (attrs = {}, children = []) => ({
  tag: 'group',
  attrs: { subject: 'synthetic group', creation: '123', ...attrs },
  content: children
});
const create = (attrs = {}, children = []) => ({ tag: 'create', attrs, content: children });
const cases = [
  {
    name: 'default-and-unconditional-participant-username',
    flags: {},
    node: create({ reason: 'accept' }, [
      group({}, [
        p({ jid: '200002@s.whatsapp.net', username: 'ungated' }),
        p({ jid: '100001@lid', type: 'superadmin' })
      ])
    ])
  },
  {
    name: 'unknown-role-precedes-creator',
    flags: {},
    node: create({}, [group({ creator: 'bad' }, [p({ type: 'future_role' })])])
  },
  {
    name: 'disabled-country-and-history-gates',
    flags: {},
    node: create({}, [
      group({ creator_country_code: 'future', creator_username: 'gated', s_o_username: 'gated' }, [
        p({ jid: '100001@lid', join_time: 'invalid' })
      ])
    ])
  },
  {
    name: 'new-group-unknown-trigger',
    flags: {},
    node: create({ type: 'new' }, [
      group({}, [{ tag: 'ephemeral', attrs: { expiration: '12seconds', trigger: 'unknown' } }])
    ])
  },
  {
    name: 'existing-group-unknown-trigger',
    flags: {},
    node: create({ type: 'existing' }, [
      group({}, [{ tag: 'ephemeral', attrs: { expiration: '12seconds', trigger: 'unknown' } }])
    ])
  },
  {
    name: 'parent-mode-flags-and-reason',
    flags: { opus: true },
    node: create({ reason: 'default_sub_group_admin_add' }, [
      group({}, [
        { tag: 'linked_parent', attrs: { jid: '123456@g.us' } },
        { tag: 'parent', attrs: { default_membership_approval_mode: 'request_required' } },
        { tag: 'limit_sharing_enabled', attrs: {} },
        { tag: 'member_link_mode', attrs: {}, content: Buffer.from('future_mode') },
        { tag: 'member_add_mode', attrs: {}, content: Buffer.from('all_member_add') }
      ]),
      { tag: 'auto_add_disabled', attrs: {} }
    ])
  }
];
cases.push({
  name: 'time-cast-wraps-before-normalization',
  flags: { history: true },
  node: create({}, [
    group({ creation: '4294967297' }, [p({ jid: '100001@lid', join_time: '2147483648' })])
  ])
});
cases.push({
  name: 'empty-byte-description-still-requires-id-before-creator',
  flags: {},
  node: create({}, [
    group({ creator: 'invalid' }, [
      {
        tag: 'description',
        attrs: {},
        content: [{ tag: 'body', attrs: {}, content: Buffer.alloc(0) }]
      }
    ])
  ])
});

module.exports = cases;
