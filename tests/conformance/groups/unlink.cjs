// Isolated official helper simulation. Source extraction was performed with
// wa-transform's AST spans, never by executing a bundle.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../../..');
const evidence = JSON.parse(fs.readFileSync(path.join(__dirname, 'evidence.json')));
const contractPath = process.argv.includes('--contract') ? process.argv[process.argv.indexOf('--contract') + 1] : path.join(root, 'generated/notif/group-unlink.json');
const contract = JSON.parse(fs.readFileSync(contractPath));
const sources = {};
for (const m of evidence.modules) {
  const bytes = fs.readFileSync(path.join(__dirname, 'sources', `${m.name}.js`));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), m.moduleSha256);
  sources[m.name] = bytes;
}
let types;
vm.runInNewContext(sources.WAWebGroupType.toString(), {__d(name, deps, factory) {
  types = {};
  const internalEnum = x => x;
  internalEnum.Mirrored = x => Object.fromEntries(x.map(v => [v, v]));
  const load = name => { assert.equal(name, '$InternalEnum'); return internalEnum; };
  factory(null, load, load, load, null, null, types);
}});
const helper = sources.WAWebHandleGroupNotification.subarray(contract.startByte, contract.endByte).toString();
const parse = vm.runInNewContext(`(${helper})`, {o(name) { assert.equal(name, 'WAWebGroupType'); return types; }});
let cases = 0;
const oracleCases = [];
// The test domain is independent of IR coverage: these are the three literal
// keys in official I()'s fallback table, plus unknown and empty inputs.
const kinds = ['parent_group', 'sibling_group', 'sub_group', '', 'future_kind'];
const reasons = [undefined, types.DELETE_REASON.DELETE_PARENT, types.DELETE_REASON.INTEGRITY_DELETE_PARENT, '', 'future_reason'];
for (const kind of kinds) for (const reason of reasons) {
  const actual = parse({
    attrString(name) { return name === 'unlink_type' ? kind : reason; },
    hasAttr(name) { assert.equal(name, 'unlink_reason'); return reason !== undefined; },
    mapChildrenWithTag(tag) { assert.equal(tag, 'group'); return []; }
  });
  const k = kinds.slice(0, -2).includes(kind) ? kind : null;
  const r = contract.rows.some(row => row.reason === reason) ? reason : null;
  const row = contract.rows.find(row => row.unlinkType === k && row.reason === r);
  assert.ok(row, `missing row ${kind}/${reason}`);
  assert.equal(actual.actionType ?? null, row.actionType, `${kind}/${reason}`);
  oracleCases.push({kind, reason: reason ?? null, actionType: actual.actionType ?? null});
  cases++;
}
if (process.argv.includes("--json")) console.log(JSON.stringify(oracleCases, null, 2));
else console.log(`${cases} official JS → IR unlink cases passed`);

if (process.argv.includes('--mutations')) {
  const os = require('node:os');
  const {spawnSync} = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'group-unlink-mutation-'));
  try {
    const removed = structuredClone(contract);
    removed.rows = removed.rows.filter(row => row.unlinkType !== 'sibling_group');
    const changed = structuredClone(contract);
    changed.rows.find(row => row.unlinkType === 'sub_group' && row.reason === 'integrity_delete_parent').actionType = 'integrity_parent_group_unlink';
    for (const [i, mutation] of [removed, changed].entries()) {
      const target = path.join(dir, `${i}.json`);
      fs.writeFileSync(target, JSON.stringify(mutation));
      const result = spawnSync(process.execPath, [__filename, '--contract', target], {encoding:'utf8'});
      assert.notEqual(result.status, 0, 'official oracle accepted a coverage/normalization mutation');
    }
    console.log('2 independent IR mutations rejected');
  } finally { fs.rmSync(dir, {recursive:true, force:true}); }
}
