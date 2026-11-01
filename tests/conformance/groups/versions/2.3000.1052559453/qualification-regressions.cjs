// Independent demonstrations of the changed-source failures rejected by Rust.
// Begin with hash-verified complete modules and statically captured regions;
// never execute a bundle to discover source.
const fs = require('node:fs'),
  path = require('node:path'),
  vm = require('node:vm'),
  crypto = require('node:crypto'),
  assert = require('node:assert/strict');
const evidence = require('./evidence.json'),
  sources = {},
  cache = {};
for (const record of evidence.modules) {
  const bytes = fs.readFileSync(path.join(__dirname, 'sources', record.name + '.js'));
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), record.moduleSha256);
  sources[record.name] = bytes;
}
function load(name) {
  if (cache[name]) return cache[name];
  assert.ok(['$InternalEnum', 'WAWebGroupType'].includes(name));
  let result;
  vm.runInNewContext(sources[name].toString(), {
    __d(actual, deps, factory) {
      assert.equal(actual, name);
      const module = { exports: {} };
      factory(null, load, load, load, module, module.exports, module.exports);
      result = module.exports;
    }
  });
  cache[name] = result;
  return result;
}
let calls = [];
const context = {
  babelHelpers: { taggedTemplateLiteralLoose: (x) => x },
  o(name) {
    if (name === 'WAWebGroupType') return load(name);
    if (name === 'WAWebJidToWid') return { groupJidToWid: (x) => x };
    assert.equal(name, 'WALogger');
    return {
      WARN(template, type) {
        calls.push({ template, type });
        return { sendLogs() {} };
      }
    };
  }
};
const handler = sources.WAWebHandleGroupNotification;
function region(name) {
  const pin = evidence.regions[name],
    bytes = handler.subarray(pin.startByte, pin.endByte);
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), pin.sha256);
  return bytes.toString();
}
const unlink = region('unlink'),
  changedUnlink = unlink.replace(
    'r=e.mapChildrenWithTag',
    'r=t==="future_type"?null:e.mapChildrenWithTag'
  );
assert.notEqual(unlink, changedUnlink);
const parseUnlink = (source) =>
  vm.runInNewContext(`(function(){var m;return (${source})})()`, context);
const malformed = {
  attrString() {
    return 'future_type';
  },
  hasAttr() {
    return false;
  },
  mapChildrenWithTag() {
    throw Error('invalid-group-before-warning');
  }
};
assert.throws(() => parseUnlink(unlink)(malformed), /invalid-group-before-warning/);
assert.deepEqual(calls, []);
assert.equal(parseUnlink(changedUnlink)(malformed), null);
assert.equal(calls.length, 1);
const link = region('link');
const block = link.slice(link.indexOf(':') + 1);
assert.ok(block.startsWith('{'));
const shadowed = block.replace('l={sub_group:', '_={sub_group:').replace('s=l[i]', 's=_[i]');
assert.notEqual(shadowed, block);
const parseLink = (source) =>
  vm.runInNewContext(`(function(){var _;return function(t)${source}})()`, context);
const unknown = {
  attrString() {
    return 'future_type';
  },
  mapChildrenWithTag() {
    throw Error('LINK must not read groups');
  }
};
calls = [];
assert.equal(parseLink(block)(unknown), null);
assert.deepEqual(Array.from(calls[0].template), ['Unrecognized link_type: ', '']);
calls = [];
assert.equal(parseLink(shadowed)(unknown), null);
assert.equal(Array.isArray(calls[0].template), false);
assert.equal(typeof calls[0].template, 'object');
assert.equal(Object.hasOwn(calls[0].template, 'sub_group'), true);
console.log(
  'Independent source regressions confirmed: skipped UNLINK payload and shadowed LINK template'
);
