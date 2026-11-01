// Execute only the independently indexed original LINK case and UNLINK helper.
// Compare null returns, warning arguments/call order, payload reads and inherited
// values. The input domain comes from the source tables and JS Object.prototype.
const fs = require('node:fs'),
  path = require('node:path'),
  vm = require('node:vm'),
  crypto = require('node:crypto'),
  assert = require('node:assert/strict');
const evidence = require('./evidence.json');
const hash = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const sources = {};
for (const record of evidence.modules) {
  const bytes = fs.readFileSync(path.join(__dirname, 'sources', record.name + '.js'));
  assert.equal(hash(bytes), record.moduleSha256);
  assert.equal(bytes.length, record.endByte - record.startByte);
  sources[record.name] = bytes;
}
let types;
vm.runInNewContext(sources.WAWebGroupType.toString(), {
  __d(name, deps, factory) {
    assert.equal(name, 'WAWebGroupType');
    types = {};
    const internal = (x) => x;
    internal.Mirrored = (x) => Object.fromEntries(x.map((v) => [v, v]));
    const load = (name) => {
      assert.equal(name, '$InternalEnum');
      return internal;
    };
    factory(null, load, load, load, null, null, types);
  }
});
const outcomes = [];
for (const family of ['link', 'unlink']) {
  const contract = JSON.parse(
    fs.readFileSync(
      process.env['GROUP_' + family.toUpperCase() + '_CONTRACT'] ||
        path.resolve(__dirname, '../../../../../generated/notif/group-' + family + '.json')
    )
  );
  const region = evidence.regions[family],
    captured = sources.WAWebHandleGroupNotification.subarray(region.startByte, region.endByte);
  assert.equal(hash(captured), region.sha256);
  const bytes = sources.WAWebHandleGroupNotification.subarray(contract.startByte, contract.endByte);
  if (family === 'unlink') assert.equal(bytes.toString(), captured.toString());
  else assert.ok(captured.toString().endsWith(bytes.toString()));
  let calls = [],
    reads = [],
    failWarning = false;
  const context = {
    babelHelpers: { taggedTemplateLiteralLoose: (x) => x },
    o(name) {
      if (name === 'WAWebGroupType') return types;
      if (name === 'WAWebJidToWid') return { groupJidToWid: (x) => x };
      assert.equal(name, 'WALogger');
      return {
        WARN(template, value) {
          calls.push(['WARN', Array.from(template), value]);
          if (failWarning) throw Error('synthetic warning failure');
          return {
            sendLogs(event) {
              calls.push(['sendLogs', event]);
            }
          };
        }
      };
    }
  };
  const parse = vm.runInNewContext(
    family === 'link'
      ? `(function(){var _;return function(t)${bytes}})()`
      : `(function(){var m;return (${bytes});})()`,
    context
  );
  const kinds = [
    'parent_group',
    'sub_group',
    'sibling_group',
    '',
    'future_type',
    ...Object.getOwnPropertyNames(Object.prototype)
  ];
  const reasons =
    family === 'unlink'
      ? [undefined, 'delete_parent', 'integrity_delete_parent', '', 'future_reason']
      : [undefined];
  for (const kind of kinds)
    for (const reason of reasons)
      for (const hidden of [false, true]) {
        calls = [];
        reads = [];
        const attrs = { jid: '123456@g.us', subject: 'synthetic', s_t: '123' };
        const node = {
          attrString(name) {
            reads.push(name);
            if (name === family + '_type') return kind;
            assert.equal(name, 'unlink_reason');
            assert.notEqual(reason, undefined);
            return reason;
          },
          hasAttr(name) {
            reads.push(name);
            assert.equal(name, 'unlink_reason');
            return reason !== undefined;
          },
          mapChildrenWithTag(tag, cb) {
            reads.push('groups');
            assert.equal(tag, 'group');
            return [
              cb({
                attrGroupJid(name) {
                  reads.push(name);
                  return attrs[name];
                },
                attrString(name) {
                  reads.push(name);
                  return attrs[name];
                },
                attrInt(name) {
                  reads.push(name);
                  return Number(attrs[name]);
                },
                hasChild(tag) {
                  reads.push(tag);
                  assert.equal(tag, 'hidden_group');
                  return hidden;
                }
              })
            ];
          }
        };
        const actual = parse(node);
        const row =
          contract.rows.find(
            (r) =>
              (family === 'link' ? r.linkType : r.unlinkType) === kind &&
              (family === 'link' || r.reason === (reason ?? null))
          ) ||
          contract.rows.find(
            (r) =>
              (family === 'link' ? r.linkType : r.unlinkType) === kind &&
              (family === 'link' || r.reason === null)
          ) ||
          contract.rows.find(
            (r) =>
              (family === 'link' ? r.linkType : r.unlinkType) === null &&
              (family === 'link' || r.reason === (reason ?? null))
          ) ||
          contract.rows.find(
            (r) =>
              (family === 'link' ? r.linkType : r.unlinkType) === null &&
              (family === 'link' || r.reason === null)
          );
        assert.ok(row, kind + '/' + reason);
        if (actual === null) {
          assert.ok(row.nullResult);
          assert.equal(row.actionType, null);
          assert.equal(row.unsupportedAction ?? false, false);
          assert.deepEqual(calls, [
            ['WARN', ['Unrecognized ' + family + '_type: ', ''], kind],
            ['sendLogs', 'group-unrecognized-' + family + '-type']
          ]);
          assert.deepEqual(calls, [
            ['WARN', row.nullResult.template, kind],
            ['sendLogs', row.nullResult.event]
          ]);
          assert.equal(reads.includes('groups'), family === 'unlink');
          if (family === 'link') assert.equal(row.hiddenSubgroupChild, null);
        } else {
          assert.equal(row.nullResult, undefined);
          assert.deepEqual(calls, []);
          if (typeof actual.actionType === 'string') {
            assert.equal(actual.actionType, row.actionType);
            assert.equal(row.unsupportedAction ?? false, false);
          } else {
            assert.notEqual(actual.actionType, undefined);
            assert.notEqual(actual.actionType, null);
            assert.equal(row.unsupportedAction, true);
          }
          assert.equal(reads.includes('groups'), true);
          assert.equal(actual.groupDatas[0].id, attrs.jid);
          assert.equal(actual.groupDatas[0].subject, attrs.subject);
          assert.equal(actual.groupDatas[0].subjectTime, 123);
          if (family === 'link') {
            const data = {};
            for (const field of contract.groupFields) {
              assert.ok(['attrGroupJid', 'attrString', 'attrInt'].includes(field.method));
              data[field.name] =
                field.method === 'attrInt' ? Number(attrs[field.wireName]) : attrs[field.wireName];
            }
            if (row.hiddenSubgroupChild !== null) {
              assert.equal(row.hiddenSubgroupChild, 'hidden_group');
              data.hiddenSubgroup = hidden;
            }
            assert.deepEqual(JSON.parse(JSON.stringify(actual.groupDatas)), [data]);
            assert.deepEqual(reads, [
              'link_type',
              'groups',
              ...contract.groupFields.map((field) => field.wireName),
              ...(row.hiddenSubgroupChild === null ? [] : [row.hiddenSubgroupChild])
            ]);
          }
        }
        outcomes.push({
          family,
          kind,
          reason: reason ?? null,
          hidden,
          returnsNull: actual === null,
          actionType:
            actual === null
              ? null
              : typeof actual.actionType === 'string'
                ? actual.actionType
                : { valueType: typeof actual.actionType },
          reads,
          calls
        });
      }
  // WARN is an ordered, effectful boundary; a throw must propagate, after the
  // UNLINK group payload reads but before LINK group reads or sendLogs.
  failWarning = true;
  reads = [];
  calls = [];
  assert.throws(
    () =>
      parse({
        attrString: () => 'future_type',
        hasAttr: () => false,
        mapChildrenWithTag() {
          reads.push('groups');
          return [];
        }
      }),
    /synthetic warning failure/
  );
  assert.equal(reads.includes('groups'), family === 'unlink');
  assert.equal(calls.length, 1);
}
if (process.argv.includes('--json'))
  console.log(
    JSON.stringify(
      { waVersion: evidence.waVersion, setHash: evidence.setHash, cases: outcomes },
      null,
      2
    )
  );
else console.log(`${outcomes.length} current official LINK/UNLINK cases passed`);
