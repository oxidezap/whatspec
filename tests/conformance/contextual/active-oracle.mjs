// Execute only the AST-captured ActiveIQ parser, never an entire bundle.
// Leaves are bounded stand-ins: strings, domain JIDs, unique children and
// Result values. This checks parser control flow, not the full Web helper stack.
import fs from 'node:fs';
import crypto from 'node:crypto';
import vm from 'node:vm';

const directory = new URL('.', import.meta.url);
const name = 'WASmaxInPassiveModeActiveIQResponseSuccess';
const source = fs.readFileSync(new URL(`${name}.js`, directory));
const provenance = JSON.parse(fs.readFileSync(new URL('provenance.json', directory)));
const evidence = provenance.modules.filter(x => x.module === name);
if (evidence.length !== 1 || crypto.createHash('sha256').update(source).digest('hex') !== evidence[0].sha256) throw Error('captured parser digest mismatch');
const ok = value => ({success: true, value});
const fail = () => ({success: false});
const utils = {
  assertTag: (node, tag) => node.tag === tag ? ok(node) : fail(),
  flattenedChildWithTag(node, tag) {
    const matching = node.children.filter(x => x.tag === tag);
    return matching.length === 1 ? ok(matching[0]) : fail();
  },
  attrString: (node, key) => typeof node.attrs[key] === 'string' ? ok(node.attrs[key]) : fail(),
  literal(accessor, node, key, expected) {
    const value = accessor(node, key);
    return value.success && value.value === expected ? value : fail();
  },
};
const jid = {
  attrDomainJid: (node, key) => ['s.whatsapp.net', 'g.us'].includes(node.attrs[key]) ? ok(node.attrs[key]) : fail(),
  literalJid: utils.literal,
};
const modules = {
  WAResultOrError: {makeResult: ok},
  WASmaxParseUtils: utils,
  WASmaxParseJid: jid,
  WASmaxParseReference: {attrStringFromReference: (request, path) => path.length === 1 ? utils.attrString(request, path[0]) : fail()},
};
let parser;
const context = vm.createContext({__d(module, dependencies, factory, flags) {
  if (module !== name || flags !== 98 || dependencies.some(x => !modules[x])) throw Error('unreviewed dependency or module');
  const exports = {};
  const require = module => { if (!(module in modules)) throw Error(`unreviewed stub ${module}`); return modules[module]; };
  factory(undefined, undefined, require, require, undefined, undefined, exports);
  parser = exports.parseActiveIQResponseSuccess;
}});
vm.runInContext(source.toString(), context, {timeout: 1000});
const rows = [];
for (const id of ['sent', 'other', '-']) for (const from of ['s.whatsapp.net', 'g.us', '-']) for (const type of ['result', 'error', '-']) for (const count of [0, 1, 2]) {
  const attrs = Object.fromEntries([['id', id], ['from', from], ['type', type]].filter(([,v]) => v !== '-'));
  const node = {tag: 'iq', attrs, children: Array.from({length: count}, () => ({tag:'active'}))};
  const result = parser(node, {tag:'iq', attrs:{id:'sent', to:'s.whatsapp.net'}, children:[]});
  rows.push([id, from, type, count, result.success].join('\t'));
}
const output = `${rows.join('\n')}\n`;
const file = new URL('active-oracle.tsv', directory);
if (process.argv.includes('--check')) {
  if (fs.readFileSync(file, 'utf8') !== output) throw Error('active oracle fixtures drifted');
} else fs.writeFileSync(file, output);
console.log(`${rows.length} isolated Web parser cases; all four stub modules explicit`);
