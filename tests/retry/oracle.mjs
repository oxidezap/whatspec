// Execute only the AST-selected session generator against synthetic dependencies.
// No complete bundle, account, crypto, network or storage implementation runs.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
const baseline = JSON.parse(fs.readFileSync(new URL('./capture/audit.json', import.meta.url)));
const audit = process.argv[2] && process.argv[2] !== '--write' ? JSON.parse(fs.readFileSync(process.argv[2])) : baseline;
assert.deepEqual(audit, baseline, 'retry source/inventory drift requires review; no automatic policy adoption');
const record = audit.modules.find(m => m.module === 'WAWebUpdateLocalSignalSession');
assert.equal(record.sourceSha256, crypto.createHash('sha256').update(record.source).digest('hex'));
assert.equal(record.inventory.generators.length, 1);
const source = record.inventory.generators[0].source;
const cases = [
  {name:'first', count:1, expected:['remoteRegId','processBundle']},
  {name:'save-at-two', count:2, expected:['remoteRegId','processBundle','saveBaseKey']},
  {name:'different-base', count:3, expected:['remoteRegId','processBundle','sameBaseKey']},
  {name:'same-base', count:3, same:true, expected:['remoteRegId','processBundle','sameBaseKey','deleteSession']},
  {name:'mismatch-continues-at-two', count:2, saved:8, expected:['remoteRegId','processBundle','deleteSession','saveBaseKey']},
  {name:'bundle-handled-mismatch', count:1, saved:8, handled:true, expected:['remoteRegId','processBundle']},
  {name:'missing-registration', count:1, saved:null, expected:['remoteRegId','processBundle']},
  {name:'peer-mismatch', count:2, saved:8, peer:true, expected:['remoteRegId'], terminal:'throw'},
  {name:'group', count:2, kind:'group', expected:['forgetGroup','remoteRegId','processBundle','saveBaseKey']},
  {name:'status-same-base', count:3, same:true, kind:'status', scope:'status', expected:['forgetStatus','remoteRegId','processBundle','sameBaseKey','deleteSession']},
  {name:'broadcast', count:1, kind:'broadcast', expected:['forgetBroadcast','remoteRegId','processBundle']},
];
function run(c, {failAt, cancelAt} = {}, body = source) {
  const effects = [], completions = [];
  function effect(name, result, ...args) { effects.push({name,args}); return {effect:name,result}; }
  const requester = {id:'fictional-device'};
  const session = {
    getRemoteRegId: (...a) => effect('remoteRegId', c.saved === undefined ? 7 : c.saved, ...a),
    deleteRemoteSession: (...a) => effect('deleteSession', undefined, ...a),
    saveSessionBaseKey: (...a) => effect('saveBaseKey', undefined, ...a),
    hasSameBaseKey: (...a) => effect('sameBaseKey', !!c.same, ...a),
  };
  const dependencies = {
    WALogger: {LOG(){}}, WAWebSessionScope: {SessionScope:{DEFAULT:'default',STATUS:'status'}},
    WAWebChatCollection:{ChatCollection:{get:() => ({id:'group'})}},
    WAWebApiParticipantStore:{markForgetSenderKey:(...a)=>{effects.push({name:'forgetGroup',args:a});}},
    WAWebUserPrefsStatus:{markForgetStatusSenderKey:(...a)=>effect('forgetStatus',undefined,...a)},
    WAWebBroadcastSenderKeyManager:{markForgetBroadcastSenderKey:(...a)=>{effects.push({name:'forgetBroadcast',args:a});}},
    WAWebWidFactory:{asUserWidOrThrow:x=>x,createDeviceWidFromWidOrThrow:x=>x},
    WAWebSignal:{Session:session}, WAWebUserPrefsMeUser:{isMeAccount:()=>!!c.peer},
    WAWebProcessRetryKeyBundle:{processKeyBundle:x=>effect('processBundle',!!c.handled,x)},
    err:message=>new Error(message),
  };
  const lookup = name => { assert.ok(name in dependencies, `unsupported dependency ${name}`); return dependencies[name]; };
  const context=vm.createContext({o:lookup,r:lookup,e:undefined,s:undefined,u:undefined,babelHelpers:{taggedTemplateLiteralLoose:x=>x}});
  const factory = new vm.Script(`(${body})`).runInContext(context,{timeout:1000});
  const chat={isGroup:()=>c.kind==='group',isStatus:()=>c.kind==='status',isBroadcastList:()=>c.kind==='broadcast',isUser:()=>!c.kind,toString:()=>'fictional-chat'};
  const request={from:requester,offline:false,originalMsgId:'SYNTHETIC-RETRY',regId:7,retryCount:c.count,keyBundle:c.handled ? {} : undefined};
  const iterator=factory(chat,request,c.scope);
  let step, input;
  try {
    while(true) {
      step=iterator.next(input);
      if(step.done){return {effects,completions,terminal:'return'};}
      const yielded=step.value;
      assert.ok(yielded?.effect, 'unmodeled suspension');
      if (cancelAt===yielded.effect) {iterator.return();return {effects,completions,terminal:'cancel'};}
      if (failAt===yielded.effect) {iterator.throw(new Error('synthetic-failure'));throw new Error('failure unexpectedly swallowed');}
      completions.push(yielded.effect);input=yielded.result;
    }
  } catch(e) {return {effects,completions,terminal:'throw',error:e.message};}
}
for(const c of cases) {
  const trace=run(c);
  assert.deepEqual(trace.effects.map(e=>e.name), c.expected, c.name);
  assert.equal(trace.terminal,c.terminal||'return',c.name);
  if(c.peer)assert.equal(trace.error,'updateLocalSignalSession: detect registration Id change remote: 7, local: 8 for peer device');
  // Every yielded operation rejects or cancels without invoking later effects.
  for(const point of trace.completions) {
    for(const mode of ['failAt','cancelAt']) {
      const interrupted=run(c,{[mode]:point});
      assert.equal(interrupted.terminal,mode==='failAt'?'throw':'cancel');
      if(mode==='failAt')assert.equal(interrupted.error,'synthetic-failure');
      assert.deepEqual(interrupted.effects.map(e=>e.name),c.expected.slice(0,c.expected.indexOf(point)+1));
    }
  }
  if(c.scope==='status' && c.same) assert.equal(trace.effects.at(-1).args[1],'status');
  if(c.name==='same-base') assert.equal(trace.effects.at(-1).args[1],undefined);
}
// Mutation tests demonstrate that the reviewed scenarios detect policy drift.
for(const [from,to,name] of [['_===S','_!==S','two-guard'],['_>S','_<S','collision-guard'],['if(R)','if(!R)','collision-result']]) {
  assert.ok(source.includes(from),`mutation anchor ${name}`);
  const mutated=source.replace(from,to);
  assert.ok(cases.some(c=>JSON.stringify(run(c).effects.map(e=>e.name))!==JSON.stringify(run(c,{},mutated).effects.map(e=>e.name))),`undetected mutation ${name}`);
}
// Qualify the key inclusion gate at the first suspension of the receipt helper.
// Calls after this boundary, PQ flags and eventual key upload are outside scope.
const receipt=audit.modules.find(m=>m.module==='WAWebSendRetryReceiptJob');
const keysSource=receipt.inventory.generators.at(-1).source;
const keyCases=[];
for(let retryCount=0;retryCount<=6;retryCount++)for(const isStateless of [false,true]) {
  const calls=[];
  const deps={
    WAWebSignalStoreApi:{waSignalStore:{getSignedPreKey:()=>calls.push('signed'),getOrGenSinglePreKey:()=>calls.push('prekey')}},
    WAWebSignalKeyApi:{generatePreKeyPair:()=>assert.fail('not invoked by this stub')},
    WAWebAdvSignatureApi:{getADVEncodedIdentity:()=>({then:()=>{calls.push('identity');return {};}})},
  };
  const lookup=name=>{assert.ok(name in deps,`unsupported key dependency ${name}`);return deps[name];};
  const context=vm.createContext({d:2,c:undefined,o:lookup,n:name=>{assert.equal(name,'Promise');return {all:a=>({pending:a}),resolve:x=>x};}});
  const fn=new vm.Script(`(${keysSource})`).runInContext(context,{timeout:1000});
  const step=fn({identityKeyPair:{},retryCount,isStateless}).next();
  const includeKeys=isStateless||retryCount>=2;
  assert.equal(step.done,!includeKeys);
  assert.deepEqual(calls,includeKeys?['signed','prekey','identity']:[]);
  keyCases.push({retryCount,isStateless,includeKeys});
}
const exportCases=cases.map(c=>({name:c.name,retryCount:c.count,savedRegId:c.saved===undefined?7:c.saved,receivedRegId:7,bundleHandled:!!c.handled,sameBaseKey:!!c.same,peer:!!c.peer,chatKind:c.kind||'user',sessionScope:c.scope||'default',effects:c.expected,terminal:c.terminal||'return'}));
if(process.argv.includes('--write'))fs.writeFileSync(new URL('./session-cases.json',import.meta.url),JSON.stringify({formatVersion:1,sourceSha256:record.sourceSha256,receiptSourceSha256:receipt.sourceSha256,keyCases,cases:exportCases},null,2)+'\n');
else {
  const fixture=JSON.parse(fs.readFileSync(new URL('./session-cases.json',import.meta.url)));
  assert.deepEqual(fixture.cases,exportCases);
  assert.deepEqual(fixture.keyCases,keyCases);
  assert.equal(fixture.sourceSha256,record.sourceSha256);
  assert.equal(fixture.receiptSourceSha256,receipt.sourceSha256);
}
console.log(`${cases.length} reviewed session scenarios; rejection/cancellation at each yield; 3 policy mutations detected`);
