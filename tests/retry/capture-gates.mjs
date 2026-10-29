// Command-level fail-closed checks. Inputs are synthetic; no Web runtime executes.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
const executable=path.resolve(process.argv[2]??'target/debug/examples/retry_audit');
const modules=['WAWebHandleRetryRequest','WAWebUpdateLocalSignalSession','WAWebSendRetryReceiptJob','WAWebProcessRetryKeyBundle','WAWebApiMessageInfoStore'];
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const definition=(name,value=1)=>`__d('${name}',[],function(){function* f(){yield ${value}}});`;
const scenarios=[{name:'complete'}, {name:'identical-duplicate'}, ...modules.map(m=>({name:`missing-${m}`,missing:m,error:'missing retry modules'})),
  {name:'divergent-duplicate',error:'divergent duplicate'}, {name:'parse',error:'EOF'}, {name:'bytes',error:'bundle multiset differs'}];
for(const scenario of scenarios){
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'retry-capture-gate-'));
  try{
    const inputs=path.join(root,'inputs'),output=path.join(root,'output'),lock=path.join(root,'lock.json');fs.mkdirSync(inputs);
    const bodies=[modules.filter(m=>m!==scenario.missing).map(m=>definition(m)).join('')];
    if(scenario.name==='identical-duplicate')bodies.push(definition(modules[1]));
    if(scenario.name==='divergent-duplicate')bodies.push(definition(modules[1],2));
    if(scenario.name==='parse')bodies[0]+=' function broken(';
    const bundles=bodies.map((body,index)=>{fs.writeFileSync(path.join(inputs,`${index}.js`),body);return {sha256:sha(body),size:Buffer.byteLength(body)};});
    const setHash=sha(bundles.map(b=>`${b.sha256}:${b.size}`).sort().join('\n'));
    fs.writeFileSync(lock,JSON.stringify({waVersion:'synthetic',setHash,bundleCount:bundles.length,bundles}));
    if(scenario.name==='bytes')fs.appendFileSync(path.join(inputs,'0.js'),' ');
    const result=spawnSync(executable,[lock,inputs,output],{encoding:'utf8',timeout:10000});
    assert.ifError(result.error);
    if(scenario.error){
      assert.notEqual(result.status,0,scenario.name);
      assert.ok(result.stderr.includes(scenario.error),`${scenario.name}: ${result.stderr}`);
      assert.equal(fs.existsSync(output),false,`${scenario.name}: wrote partial capture`);
    }else{
      assert.equal(result.status,0,result.stderr);
      const capture=JSON.parse(fs.readFileSync(path.join(output,'audit.json')));
      assert.deepEqual(capture.modules.map(m=>m.module).sort(),[...modules].sort());
      if(scenario.name==='identical-duplicate')assert.equal(capture.modules.find(m=>m.module===modules[1]).definitions.length,2);
    }
  }finally{fs.rmSync(root,{recursive:true,force:true});}
}
console.log(`${scenarios.length} capture gate scenarios passed`);
