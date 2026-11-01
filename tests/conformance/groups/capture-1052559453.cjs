// Independent Acorn capture. Install the evidence-pinned Acorn version in an isolated prefix and set NODE_PATH.
const fs = require('node:fs'),
  path = require('node:path'),
  crypto = require('node:crypto'),
  acorn = require('acorn');
if (acorn.version !== '8.19.0') throw Error('capture requires Acorn 8.19.0');
const hash = (x) => crypto.createHash('sha256').update(x).digest('hex');
const fingerprint = (chunks) =>
  hash(
    Buffer.concat(
      chunks.flatMap((chunk) => {
        let data = Buffer.from(chunk);
        let size = Buffer.alloc(8);
        size.writeBigUInt64BE(BigInt(data.length));
        return [size, data];
      })
    )
  );
function visit(node, cb) {
  if (!node || typeof node !== 'object') return;
  cb(node);
  for (const value of Object.values(node))
    if (Array.isArray(value)) value.forEach((n) => visit(n, cb));
    else if (value && typeof value === 'object') visit(value, cb);
}
function profile(root) {
  const source = fs.readFileSync(path.join(root, 'WAWebHandleGroupNotification.js'), 'utf8'),
    ast = acorn.parse(source, { ecmaVersion: 'latest' });
  let callback, link, unlink;
  visit(ast, (node) => {
    if (node.type === 'NewExpression' && node.arguments[0]?.value === 'groupNotificationParser')
      callback = node.arguments[1];
    if (node.type === 'SwitchCase' && node.test?.property?.name === 'LINK') link = node;
    if (
      node.type === 'FunctionDeclaration' &&
      source.slice(node.start, node.end).includes('attrString("unlink_type")')
    )
      unlink = node;
  });
  const actionStatement = callback.body.body.at(-2);
  let actionCallback;
  visit(actionStatement, (node) => {
    if (node.type === 'CallExpression' && node.callee.property?.name === 'mapChildren')
      actionCallback = node.arguments[0];
  });
  const b = (n) => Buffer.byteLength(source.slice(0, n));
  const span = (node) => ({
    startByte: b(node.start),
    endByte: b(node.end),
    sha256: hash(source.slice(node.start, node.end))
  });
  const diagnosticCaches = [];
  visit(callback.body, (node) => {
    if (node.type === 'CallExpression' && node.callee?.property?.name === 'ERROR') {
      let arg = node.arguments[0];
      if (arg?.type === 'LogicalExpression' && arg.left?.type === 'Identifier')
        diagnosticCaches.push(arg.left.name);
    }
  });
  const beforeAction = callback.body.body.slice(0, -2),
    helpers = beforeAction.filter((n) => n.type === 'FunctionDeclaration');
  return {
    source,
    regions: {
      callback: span(callback),
      actionCallback: span(actionCallback),
      link: span(link),
      unlink: span(unlink)
    },
    pins: {
      moduleFrame: fingerprint([
        source.slice(0, callback.body.start),
        source.slice(callback.body.end)
      ]),
      actions: fingerprint([source.slice(actionCallback.start, actionCallback.end)]),
      helpers: fingerprint(helpers.map((n) => source.slice(n.start, n.end))),
      linkContext: fingerprint([source.slice(0, link.start), source.slice(link.end)]),
      unlinkContext: fingerprint([
        source.slice(0, unlink.body.start),
        source.slice(unlink.body.end)
      ]),
      diagnosticCache: diagnosticCaches[0]
    }
  };
}
function collectBindings(callback) {
  const rootLocals = callback.params.map((param) => {
      if (param.type !== 'Identifier') throw Error('unqualified callback parameter');
      return param.name;
    }),
    helperLocals = [];
  function bindings(node, direct = false) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'FunctionDeclaration') {
      if (!direct || node.id?.type !== 'Identifier') throw Error('unqualified block helper');
      rootLocals.push(node.id.name);
      helperLocals.push(node.id.name);
      return;
    }
    if (['FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) return;
    if (node.type === 'VariableDeclaration' && node.kind !== 'var')
      throw Error('unqualified lexical binding');
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier') throw Error('unqualified destructuring');
      rootLocals.push(node.id.name);
    }
    for (const value of Object.values(node))
      if (Array.isArray(value)) value.forEach((n) => bindings(n));
      else if (value && typeof value === 'object') bindings(value);
  }
  for (const statement of callback.body.body) bindings(statement, true);
  return { rootLocals: [...new Set(rootLocals)], helperLocals: [...new Set(helperLocals)] };
}
function prepareOutput(dir) {
  if (fs.existsSync(dir)) throw Error('output directory must not exist: ' + dir);
  fs.mkdirSync(path.join(dir, 'sources'), { recursive: true });
}
if (process.argv.includes('--self-test')) {
  const assert = require('node:assert/strict'),
    os = require('node:os');
  const parse = (source) => acorn.parseExpressionAt(source, 0, { ecmaVersion: 'latest' });
  for (const source of [
    'function({x}){}',
    'function(x=1){}',
    'function(...x){}',
    'function(x){var {y}=x}',
    'function(x){if(x){function nested(){}}}'
  ])
    assert.throws(() => collectBindings(parse(source)), /unqualified/);
  assert.deepEqual(
    collectBindings(
      parse(
        'function(e){var x;function helper(){var privateLocal}if(e){var y}var alias=function(z){var inner}}'
      )
    ),
    { rootLocals: ['e', 'x', 'helper', 'y', 'alias'], helperLocals: ['helper'] }
  );
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'group-capture-check-'));
  try {
    const output = path.join(temp, 'capture');
    prepareOutput(output);
    fs.writeFileSync(path.join(output, 'sources', 'stale.js'), 'preserve');
    assert.throws(() => prepareOutput(output), /must not exist/);
    assert.equal(fs.readFileSync(path.join(output, 'sources', 'stale.js'), 'utf8'), 'preserve');
  } finally {
    fs.rmSync(temp, { recursive: true, force: true });
  }
  console.log('Capture binding and fresh-output rejection checks passed');
  process.exit(0);
}
const [index, dir] = process.argv.slice(2);
if (!index || !dir) throw Error('usage: node capture-1052559453.cjs modules.tsv output-directory');
prepareOutput(dir);
const lock = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../../../generated/bundles.lock.json'))
);
if (
  lock.waVersion !== '2.3000.1052559453' ||
  lock.setHash !== 'd6ab7ae601eda281cfac570a68de1d787adde8f4d778f0bb994416f661a21abf'
)
  throw Error('wrong snapshot lock');
const rows = fs.readFileSync(index, 'utf8').trim().split('\n');
const bundleFiles = new Set(rows.map((row) => row.split('\t')[1]));
if (bundleFiles.size !== lock.bundleCount) throw Error('incomplete bundle index');
const expectedBundles = new Map(lock.bundles.map((b) => [b.sha256, b.size])),
  observed = new Set();
for (const file of bundleFiles) {
  const bytes = fs.readFileSync(file),
    sha = hash(bytes);
  if (expectedBundles.get(sha) !== bytes.length || observed.has(sha))
    throw Error('wrong or duplicate bundle');
  observed.add(sha);
}
const input = path.join(dir, 'sources'),
  inputRecords = [];
const wanted = new Set(fs.readdirSync(path.join(__dirname, 'sources')).map((n) => n.slice(0, -3)));
wanted.add('WAWebGroupHistoryShareMode');
const seen = new Map();
for (const row of rows) {
  const [name, file, start, end] = row.split('\t');
  if (!wanted.has(name)) continue;
  const bundle = fs.readFileSync(file),
    bytes = bundle.subarray(+start, +end);
  const ast = acorn.parse(bytes.toString(), { ecmaVersion: 'latest' });
  if (
    ast.body.length !== 1 ||
    ast.body[0].expression?.callee?.name !== '__d' ||
    ast.body[0].expression.arguments[0].value !== name
  )
    throw Error('not a complete named module: ' + name);
  if (seen.has(name) && !seen.get(name).equals(bytes)) throw Error('conflicting module ' + name);
  seen.set(name, bytes);
  fs.writeFileSync(path.join(input, name + '.js'), bytes);
  inputRecords.push({
    name,
    bundleSha256: hash(bundle),
    startByte: +start,
    endByte: +end,
    moduleSha256: hash(bytes)
  });
}
if (seen.size !== wanted.size) throw Error('missing module captures');
const old = profile(path.join(__dirname, 'sources')),
  current = profile(input);
console.log('old profile', old.pins);
console.log('current profile', current.pins);
const expected = {
  moduleFrame: 'dcec3eb8a54f58e659c37f922dac88bd35db7f9a75630eba74c91269deed9593',
  actions: '55083eab54fbaa69a6706a0c5c0fbcd17d7f9cd9239ace333197a46402ce6692',
  helpers: '59819f4ce7d98e07ee02c2f7bd69ed1108a666dcb2eadd26ed504c4eab040683',
  linkContext: '84d5edb013196745b038c30fd8efa2fec2ce4b6faac0feaf6a97390e7e656c08',
  unlinkContext: 'f3c64ae496e0e8da4d0ffc79486a11cc3c18eac5533a0a2576c29e938aa92fe8',
  diagnosticCache: 'm'
};
if (JSON.stringify(old.pins) !== JSON.stringify(expected))
  throw Error('Independent old region selection does not reproduce existing pins');
const records = inputRecords;
const modules = [];
const files = fs.readdirSync(input).sort();
if (files.length !== wanted.size || files.some((file) => !wanted.has(file.slice(0, -3))))
  throw Error('unexpected source capture files');
for (const file of files) {
  const name = file.slice(0, -3);
  const matching = records.filter((m) => m.name === name),
    record = matching[0];
  if (!record) throw Error('missing module provenance ' + name);
  modules.push({
    ...record,
    definitions: matching.map(({ bundleSha256, startByte, endByte }) => ({
      bundleSha256,
      startByte,
      endByte
    }))
  });
}
const callbackAst = acorn.parseExpressionAt(
  current.source,
  Buffer.from(current.source).subarray(0, current.regions.callback.startByte).toString().length,
  { ecmaVersion: 'latest' }
);
const { rootLocals, helperLocals } = collectBindings(callbackAst);
const warnings = {};
visit(acorn.parse(current.source, { ecmaVersion: 'latest' }), (node) => {
  if (
    node.type !== 'SequenceExpression' ||
    node.expressions.length !== 2 ||
    node.expressions[1].type !== 'Literal' ||
    node.expressions[1].value !== null
  )
    return;
  const source = current.source.slice(node.start, node.end);
  for (const family of ['link', 'unlink'])
    if (source.includes('group-unrecognized-' + family + '-type')) {
      if (warnings[family + 'WarningNull']) throw Error('ambiguous warning expression');
      const call = node.expressions[0],
        warn = call.callee.object;
      if (
        call.type !== 'CallExpression' ||
        call.callee.property.name !== 'sendLogs' ||
        warn.type !== 'CallExpression' ||
        warn.callee.property.name !== 'WARN' ||
        warn.arguments[1].type !== 'Identifier'
      )
        throw Error('changed warning shape');
      const template = warn.arguments[0].right.right.arguments[0].elements.map((n) => n.value);
      warnings[family + 'WarningNull'] = {
        sha256: hash(source),
        source,
        argument: warn.arguments[1].name,
        template,
        event: call.arguments[0].value
      };
    }
});
const evidence = {
  waVersion: '2.3000.1052559453',
  setHash: 'd6ab7ae601eda281cfac570a68de1d787adde8f4d778f0bb994416f661a21abf',
  asset:
    'https://github.com/oxidezap/whatspec/releases/download/bundle-store/bundles-2.3000.1052559453-d6ab7ae601eda281cfac570a68de1d787adde8f4d778f0bb994416f661a21abf.tar.xz',
  archiveSha256: '2958d99a3d84141fa8479f1f991e06246e68c063ca8f618a8d5d361287387f62',
  extractor: { name: 'acorn', version: acorn.version, offsetUnit: 'UTF-8 bytes' },
  callback: { name: 'groupNotificationParser', ...current.regions.callback },
  regions: current.regions,
  modules,
  pins: current.pins
};
fs.writeFileSync(dir + '/evidence.json', JSON.stringify(evidence, null, 2) + '\n');
fs.writeFileSync(
  dir + '/qualification.json',
  JSON.stringify(
    {
      ...current.pins,
      providers: Object.fromEntries(
        modules
          .filter((m) => m.name !== 'WAWebHandleGroupNotification')
          .map((m) => [m.name, m.moduleSha256])
      ),
      rootLocals,
      helperLocals,
      ...warnings
    },
    null,
    2
  ) + '\n'
);
