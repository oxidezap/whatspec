import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const audit=JSON.parse(fs.readFileSync(new URL('./capture/2.3000.1054751086/audit.json',import.meta.url)));
const root=fs.mkdtempSync(path.join(os.tmpdir(),'retry-review-gates-'));
try {
  for(const [name,mutate,error] of [
    ['unknown-version',value=>{value.waVersion='unreviewed-version'},'unreviewed retry version'],
    ['changed-bundle-set',value=>{value.setHash='0'.repeat(64)},'source/inventory drift requires review'],
    ['missing-helper',value=>{value.modules.find(module=>module.module==='WAWebProcessRetryKeyBundle').inventory.helpers=[]},'source/inventory drift requires review'],
  ]) {
    const changed=structuredClone(audit);
    mutate(changed);
    const file=path.join(root,`${name}.json`);
    fs.writeFileSync(file,JSON.stringify(changed));
    for(const write of [false,true]) {
      const result=spawnSync(process.execPath,['tests/retry/oracle.mjs',file,...(write?['--write']:[])],{encoding:'utf8',timeout:10000,maxBuffer:2*1024*1024});
      assert.ifError(result.error);
      assert.notEqual(result.status,0,name);
      assert.ok(result.stderr.includes(error),`${name}: ${result.stderr}`);
    }
  }
} finally {
  fs.rmSync(root,{recursive:true,force:true});
}
console.log('6 retry review rejection checks passed');
