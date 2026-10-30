// Execute complete original/mutated constant factories and the original UNLINK
// helper. These explicit adapter mocks match unlink.cjs; no bundle is executed.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const evidence = JSON.parse(fs.readFileSync(path.join(__dirname, 'evidence.json')));
function source(name) {
  const bytes = fs.readFileSync(path.join(__dirname, 'sources', `${name}.js`));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), evidence.modules.find(m => m.name === name).moduleSha256);
  return bytes.toString();
}
const typesSource = source('WAWebGroupType');
const contract = JSON.parse(fs.readFileSync(path.join(__dirname, '../../../generated/notif/group-unlink.json')));
const helper = source('WAWebHandleGroupNotification').slice(contract.startByte, contract.endByte);
function action(moduleSource, helperSource = helper) {
  let types;
  vm.runInNewContext(moduleSource, {__d(name, deps, factory) {
    assert.equal(name, 'WAWebGroupType');
    types = {};
    const internalEnum = x => x;
    internalEnum.Mirrored = x => Object.fromEntries(x.map(v => [v, v]));
    const load = name => { assert.equal(name, '$InternalEnum'); return internalEnum; };
    factory(null, load, load, load, null, null, types);
  }});
  const parse = vm.runInNewContext(`(${helperSource})`, {o(name) { assert.equal(name, 'WAWebGroupType'); return types; }});
  return parse({attrString(name) { assert.equal(name, 'unlink_type'); return 'parent_group'; }, hasAttr() { return false; }, mapChildrenWithTag() { return []; }}).actionType;
}
assert.equal(action(typesSource), 'parent_group_unlink');
const replacements = [
  'l.GROUP_ACTIONS=d,Object.assign(l,{GROUP_ACTIONS:{...d,PARENT_GROUP_UNLINK:"changed"}})',
  'l.GROUP_ACTIONS=d,l.GROUP_ACTIONS={...d,PARENT_GROUP_UNLINK:"changed"}',
  'l.GROUP_ACTIONS=d,(function(){var alias=l;alias.GROUP_ACTIONS={...d,PARENT_GROUP_UNLINK:"changed"}})()',
  'l.GROUP_ACTIONS=d,Object.defineProperty(l,"GROUP_ACTIONS",{get(){return {...d,PARENT_GROUP_UNLINK:"changed"}}})',
];
for (const replacement of replacements) {
  const changed = typesSource.replace('l.GROUP_ACTIONS=d', replacement);
  assert.notEqual(changed, typesSource);
  assert.equal(action(changed), 'changed');
}
console.log('4 complete constant-provider mutations change original UNLINK actions');

// Statements after return can still change execution through declaration hoisting.
const hoisted = helper.slice(0, -1) + ';function e(){}' + helper.slice(-1);
assert.throws(() => action(typesSource, hoisted), /e\.attrString is not a function/);
console.log('Unreachable function declaration changes original UNLINK execution through hoisting');
