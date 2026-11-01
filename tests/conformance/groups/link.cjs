// Simulate only the AST-extracted official LINK case. Never evaluate a bundle to
// extract source. The decoder/identity conversion is mocked; action selection,
// output fields and hiddenSubgroup's omission are the real official statements.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../../..');
const contractPath = process.argv.includes('--contract') ? process.argv[process.argv.indexOf('--contract') + 1] : path.join(root, 'tests/conformance/groups/versions/2.3000.1047483476/group-link.json');
const contract = JSON.parse(fs.readFileSync(contractPath));
const evidence = JSON.parse(fs.readFileSync(path.join(__dirname, 'link-evidence.json')));
const sources = {};
for (const m of evidence.modules) {
  const bytes = fs.readFileSync(path.join(__dirname, 'sources', `${m.name}.js`));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), m.moduleSha256);
  sources[m.name] = bytes;
}
let types;
vm.runInNewContext(sources.WAWebGroupType.toString(), {__d(name, deps, factory) {
  assert.equal(name, 'WAWebGroupType');
  types = {};
  const internalEnum = x => x;
  internalEnum.Mirrored = x => Object.fromEntries(x.map(v => [v, v]));
  const load = name => { assert.equal(name, '$InternalEnum'); return internalEnum; };
  factory(null, load, load, load, null, null, types);
}});
let tags;
vm.runInNewContext(sources.WAWebHandleGroupNotificationConst.toString(), {__d(name,deps,factory) {
  assert.equal(name,'WAWebHandleGroupNotificationConst');
  tags={};
  const load=name=>{throw Error('unexpected constant initialization dependency '+name);};
  factory(null,load,load,load,{exports:tags},tags,tags);
}});
assert.equal(contract.wireTag,tags.GROUP_NOTIFICATION_TAG.LINK,'official LINK wire tag');
const block = sources.WAWebHandleGroupNotification.subarray(contract.startByte, contract.endByte).toString();
assert.ok(block.startsWith('{') && block.endsWith('}'), 'contract must span the complete case block');
// This parameter is the actual source binding in the qualified module. Extraction
// accepts parameter renaming structurally; a newly qualified oracle must too.
const parse = vm.runInNewContext(`(function(t) ${block})`, {o(name) {
  if (name === 'WAWebGroupType') return types;
  assert.equal(name, 'WAWebJidToWid');
  return {groupJidToWid(jid) { return jid; }};
}});
// Independent input domain from the official LINK table, never from IR rows.
const kinds = ['parent_group', 'sibling_group', 'sub_group', '', 'future_kind'];
const oracleCases = [];
for (const kind of kinds) for (const hidden of [false, true]) {
  const attrs = {jid:'123456@g.us', subject:'synthetic group', s_t:'123'};
  const reads = [];
  const group = {
    attrGroupJid(name) { reads.push(name); return attrs[name]; },
    attrString(name) { reads.push(name); assert.ok(Object.hasOwn(attrs, name)); return attrs[name]; },
    attrInt(name) { reads.push(name); const value = Number.parseInt(attrs[name], 10); assert.ok(!Number.isNaN(value)); return value; },
    hasChild(name) { reads.push(name); assert.equal(name, 'hidden_group'); return hidden; }
  };
  const actual = parse({
    attrString(name) { assert.equal(name, contract.linkTypeAttribute); return kind; },
    mapChildrenWithTag(tag, callback) { assert.equal(tag, contract.groupChildTag); return [callback(group)]; }
  });
  const normalized = JSON.parse(JSON.stringify({actionType:actual.actionType ?? null, groupDatas:actual.groupDatas}));
  const row = contract.rows.find(row => row.linkType === (kinds.slice(0,3).includes(kind) ? kind : null));
  assert.ok(row, `missing row ${kind}`);
  assert.equal(row.unsupportedAction ?? false, false);
  const data = {};
  for (const f of contract.groupFields) {
    data[f.name] = f.method === 'attrInt' ? Number.parseInt(attrs[f.wireName], 10) : attrs[f.wireName];
  }
  if (row.hiddenSubgroupChild !== null) {
    assert.equal(row.hiddenSubgroupChild, 'hidden_group');
    data.hiddenSubgroup = hidden;
  }
  assert.deepEqual(normalized, {actionType:row.actionType, groupDatas:[data]}, `${kind}/${hidden}`);
  assert.deepEqual(reads, kind === 'parent_group' ? ['jid','subject','s_t'] : ['jid','subject','s_t','hidden_group']);
  oracleCases.push({kind,hidden,result:normalized});
}
// A plain object lookup also exposes inherited Object.prototype properties.
// Derive that test domain independently from the actual standard JS prototype,
// and classify the real non-string result instead of rewriting it as null.
const prototypeKeys = Object.getOwnPropertyNames(Object.prototype).sort();
assert.deepEqual(contract.rows.filter(row => row.unsupportedAction).map(row => row.linkType).sort(), prototypeKeys);
for (const kind of prototypeKeys) for (const hidden of [false,true]) {
  const actual=parse({
    attrString(name) {assert.equal(name,contract.linkTypeAttribute);return kind;},
    mapChildrenWithTag(tag,callback) {
      assert.equal(tag,contract.groupChildTag);
      return [callback({
        attrGroupJid(name) {assert.equal(name,'jid');return '123456@g.us';},
        attrString(name) {assert.equal(name,'subject');return 'synthetic group';},
        attrInt(name) {assert.equal(name,'s_t');return 123;},
        hasChild(name) {assert.equal(name,'hidden_group');return hidden;},
      })];
    }
  });
  assert.notEqual(typeof actual.actionType,'string');
  assert.notEqual(typeof actual.actionType,'undefined');
  assert.notEqual(actual.actionType,null);
  const row=contract.rows.find(row=>row.linkType===kind);
  assert.equal(row.unsupportedAction,true);
  assert.equal(row.actionType,null);
  assert.equal(row.hiddenSubgroupChild,'hidden_group');
  const groupDatas=JSON.parse(JSON.stringify(actual.groupDatas));
  assert.deepEqual(groupDatas,[{id:'123456@g.us',subject:'synthetic group',subjectTime:123,hiddenSubgroup:hidden}]);
  oracleCases.push({kind,hidden,unsupportedAction:true,result:{actionValueType:typeof actual.actionType,groupDatas}});
}
if (process.argv.includes('--json')) console.log(JSON.stringify(oracleCases,null,2));
else console.log(`${oracleCases.length} official JS → IR LINK cases passed`);
if (process.argv.includes('--mutations')) {
  const os = require('node:os');
  const {spawnSync} = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'group-link-mutation-'));
  try {
    const removed = structuredClone(contract);
    removed.rows = removed.rows.filter(row => row.linkType !== 'sibling_group');
    const changed = structuredClone(contract);
    changed.rows.find(row => row.linkType === 'parent_group').hiddenSubgroupChild = 'hidden_group';
    const prototype = structuredClone(contract);
    prototype.rows.find(row => row.linkType === 'toString').unsupportedAction = false;
    const wireTag=structuredClone(contract);wireTag.wireTag='wrong';
    const attribute=structuredClone(contract);attribute.linkTypeAttribute='wrong';
    const childTag=structuredClone(contract);childTag.groupChildTag='wrong';
    for (const [i,mutation] of [removed,changed,prototype,wireTag,attribute,childTag].entries()) {
      const target = path.join(dir,`${i}.json`);
      fs.writeFileSync(target,JSON.stringify(mutation));
      const result = spawnSync(process.execPath,[__filename,'--contract',target],{encoding:'utf8'});
      assert.notEqual(result.status,0,'oracle accepted missing coverage or wrong absent/false semantics');
    }
    console.log('6 independent LINK IR mutations rejected');
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
}
