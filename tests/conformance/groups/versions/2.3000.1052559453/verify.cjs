// Verify committed independent captures and demonstrate that contract mutations
// cannot pass by agreeing only on known action names.
const fs = require('node:fs'),
  path = require('node:path'),
  os = require('node:os'),
  assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
require('./qualification-regressions.cjs');
const root = path.resolve(__dirname, '../../../../..');
const env = {
  ...process.env,
  GROUP_FIXTURE_ROOT: __dirname,
  GROUP_ENVELOPE_CONTRACT: path.join(root, 'generated/notif/group-envelope.json')
};
for (const [name, script] of [
  ['actions', '../../actions.cjs'],
  ['envelope', '../../envelope.cjs'],
  ['create', 'create.cjs'],
  ['normalization', 'normalization.cjs']
]) {
  const result = spawnSync(process.execPath, [path.resolve(__dirname, script), '--json'], {
    encoding: 'utf8',
    env,
    maxBuffer: 8 * 1024 * 1024
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(
    JSON.parse(result.stdout),
    require('./' + name + '.json'),
    name + ' capture drift'
  );
}
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'current-group-mutations-'));
try {
  const mutations = [
    [
      'link',
      (c) => {
        delete c.rows.find((r) => r.linkType === null).nullResult;
      }
    ],
    [
      'link',
      (c) => {
        c.rows.find((r) => r.linkType === null).nullResult.event = 'wrong';
      }
    ],
    [
      'link',
      (c) => {
        c.rows.find((r) => r.linkType === null).hiddenSubgroupChild = 'hidden_group';
      }
    ],
    [
      'link',
      (c) => {
        c.groupFields.reverse();
      }
    ],
    [
      'link',
      (c) => {
        c.rows.find((r) => r.linkType === 'parent_group').hiddenSubgroupChild = 'hidden_group';
      }
    ],
    [
      'unlink',
      (c) => {
        delete c.rows.find((r) => r.unlinkType === null).nullResult;
      }
    ],
    [
      'unlink',
      (c) => {
        c.rows.find((r) => r.unlinkType === null).nullResult.template = ['wrong', ''];
      }
    ],
    [
      'unlink',
      (c) => {
        c.rows.find(
          (r) => r.unlinkType === 'parent_group' && r.reason === 'delete_parent'
        ).actionType = 'wrong';
      }
    ]
  ];
  for (const [index, [family, mutate]] of mutations.entries()) {
    const contract = JSON.parse(
      fs.readFileSync(path.join(root, 'generated/notif/group-' + family + '.json'))
    );
    mutate(contract);
    const target = path.join(dir, index + '.json');
    fs.writeFileSync(target, JSON.stringify(contract));
    const result = spawnSync(process.execPath, [path.join(__dirname, 'normalization.cjs')], {
      encoding: 'utf8',
      env: { ...env, ['GROUP_' + family.toUpperCase() + '_CONTRACT']: target }
    });
    assert.equal(result.error, undefined, 'mutation subprocess failed to spawn');
    assert.equal(result.signal, null, 'mutation subprocess terminated by signal');
    assert.equal(result.status, 1, 'normalization oracle accepted mutation ' + index);
    assert.match(
      result.stderr,
      /AssertionError/,
      'mutation failed without an oracle assertion ' + index
    );
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
console.log(
  'Current captures reproduced: 64 actions, 29 envelope, 13 CREATE, 204 normalization cases; 8 IR mutations rejected'
);
