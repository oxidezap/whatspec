// Independent reviewed expectations for the actual getMsgIfAuthorized generator.
// Dependency stubs supply eligibility facts; they do not implement authorization.
import vm from 'node:vm';
import assert from 'node:assert/strict';
const E={ELIGIBLE:'eligible',INELIGIBLE_ALREADY_DELIVERED:'delivered',INELIGIBLE_CHANGED_IDENTITY:'identity',INELIGIBLE_RECORD_MISSING:'missing'};
const common=['addonLookup','messageLookup','coexEligibility','identityEligibility'];
const cases=[
  {name:'message-missing',missing:true,expected:['addonLookup','messageLookup','alternateMsgKey'],authorized:false},
  {name:'row-missing',noRow:true,expected:['addonLookup','messageLookup'],authorized:false},
  {name:'eligible',eligibility:E.ELIGIBLE,expected:[...common,'prepare'],authorized:true},
  {name:'identity-changed',eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:[...common,'prepare','reject'],reason:'identity_change',authorized:false},
  {name:'already-delivered',eligibility:E.INELIGIBLE_ALREADY_DELIVERED,expected:[...common,'prepare','reject'],reason:'double_checkmark',authorized:false},
  {name:'record-missing',eligibility:E.INELIGIBLE_RECORD_MISSING,expected:[...common,'alternateDevice','prepare','reject'],reason:'other',authorized:false},
  {name:'alternate-authorized',eligibility:E.INELIGIBLE_RECORD_MISSING,alternate:true,expected:[...common,'alternateDevice','identityEligibility','prepare'],authorized:true},
  {name:'coex-authorized',coex:E.ELIGIBLE,eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['addonLookup','messageLookup','coexEligibility','prepare'],authorized:true},
  {name:'coex-denied',coex:E.INELIGIBLE_CHANGED_IDENTITY,eligibility:E.ELIGIBLE,expected:['addonLookup','messageLookup','coexEligibility','prepare','reject'],reason:'identity_change',authorized:false},
  {name:'addon-authorized',addon:true,eligibility:E.ELIGIBLE,expected:['addonLookup','coexEligibility','identityEligibility'],authorized:true},
  {name:'addon-identity-changed',addon:true,eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['addonLookup','coexEligibility','identityEligibility','reject'],reason:'identity_change',authorized:false},
  {name:'revoked-protocol-row',revoked:true,eligibility:E.ELIGIBLE,expected:[...common,'prepare'],authorized:true},
];
function run(source,c,{failAt,cancelAt}={}) {
  const effects=[],completed=[];
  let constructedKey;
  const effect=(name,result,args)=>{
    if(name==='addonLookup')assert.equal(args.key,constructedKey);
    if(name==='messageLookup')assert.equal(args.key,'synthetic-key');
    if(name==='coexEligibility'){assert.equal(args.receiver,requester);assert.equal(args.id,'SYNTHETIC-AUTH');}
    if(name==='identityEligibility')assert.equal(args.msgKey,constructedKey);
    effects.push({name,args});return {name,result};};
  const sync=(name,result,args)=>{effects.push({name,args});return result;};
  const requester={name:'original',isCompanion:()=>true,isHosted:()=>false,toString:()=>'fictional-device'};
  const alternate={name:'alternate'};
  const row=c.missing?null:{rowId:c.noRow?undefined:101,type:c.revoked?'revoked':'regular',protocolMessageRowId:202};
  const chain={WARN(){return this},LOG(){return this},tags(){return this}};
  class MsgKey{constructor(v){assert.equal(v.id,'SYNTHETIC-AUTH');assert.equal(v.remote,chat);assert.equal(v.fromMe,true);assert.equal(v.participant,undefined);Object.assign(this,v);constructedKey=this}toString(){return 'synthetic-key'}}
  class Msg{constructor(v){Object.assign(this,v)}waitForPrep(){return effect('prepare')}}
  class Reject{constructor(v){this.values=v}commit(){sync('reject',undefined,this.values)}}
  const dependencies={
    WALogger:chain,WAWebUserPrefsMeUser:{getMeLidUserOrThrow:()=>({name:'self-lid'})},WAWebMsgKey:MsgKey,
    WAWebAddonRetryRequestUtils:{getSentAddonMsgRecord:key=>effect('addonLookup',c.addon?{selfMsgRow:{rowId:303},msgData:{type:'addon'}}:null,{key})},
    WAWebSchemaMessage:{getMessageTable:()=>({get:key=>effect('messageLookup',row,{key})})},
    WAWebLidMigrationUtils:{getAlternateMsgKey:key=>sync('alternateMsgKey',null,{key})},
    WAWebMsgType:{MSG_TYPE:{REVOKED:'revoked'}},WAWebDBMessageSerialization:{messageFromDbRow:r=>r},WAWebMsgModel:{Msg},
    WAWebSendMsgTypes:{SendMessageRecordType:{Addon:'addon',Message:'message'}},
    WAWebCoexV2RetryAuthorization:{getCoexV2RelayRetryEligibility:(receiver,id)=>effect('coexEligibility',c.coex??null,{receiver,id})},
    WAWebApiMessageInfoStore:{RetryEligibilityResult:E,isRetryEligible:args=>effect('identityEligibility',args.receiver===alternate?E.ELIGIBLE:c.eligibility,args)},
    WAWebApiContact:{getAlternateDeviceWid:wid=>sync('alternateDevice',c.alternate?alternate:null,{wid})},
    WAWebWidFactory:{createDeviceWidFromWidOrThrow:w=>w},
    WAWebWamEnumRetryRejectReason:{RETRY_REJECT_REASON:{OTHER:'other',DOUBLE_CHECKMARK:'double_checkmark',IDENTITY_CHANGE:'identity_change'}},
    WAWebE2eRetryRejectWamEvent:{E2eRetryRejectWamEvent:Reject},WAWebWamEnumDeviceType:{DEVICE_TYPE:{COMPANION:'companion',PRIMARY:'primary'}},
    WAWebWamMsgUtils:{getWamMessageType:x=>x.type,getWamE2eSenderType:()=>null},WAWebSessionScopeWamUtils:{sessionScopeToWamType:x=>x},
  };
  const lookup=name=>{assert.ok(name in dependencies,`unsupported authorization dependency ${name}`);return dependencies[name];};
  const context=vm.createContext({o:lookup,r:lookup,e:undefined,s:undefined,u:undefined,babelHelpers:{taggedTemplateLiteralLoose:x=>x}});
  const fn=new vm.Script(`(${source})`).runInContext(context,{timeout:1000});
  const chat={isUser:()=>true};
  const iterator=fn({chat,identity:{rowId:71,sentAddonRowId:72},originalMsgId:'SYNTHETIC-AUTH',requester,retryCount:3,sessionScope:'default'});
  let input;
  try {
    for(;;){
      const step=iterator.next(input);
      if(step.done)return {effects,completed,authorized:step.value!=null,terminal:'return',value:step.value};
      const point=step.value;assert.ok(point?.name,'unknown authorization suspension');
      if(cancelAt===completed.length){iterator.return();return {effects,completed,terminal:'cancel'};}
      if(failAt===completed.length){iterator.throw(new Error('synthetic-auth-failure'));throw new Error('authorization swallowed failure');}
      completed.push(point.name);input=point.result;
    }
  }catch(e){return {effects,completed,terminal:'throw',error:e.message};}
}
function assertCase(source,c){
  const t=run(source,c);
  assert.equal(t.terminal,'return',c.name);
  assert.deepEqual(t.effects.map(e=>e.name),c.expected,c.name);
  assert.equal(t.authorized,c.authorized,c.name);
  if(c.reason)assert.equal(t.effects.at(-1).args.retryRejectReason,c.reason,c.name);
  for(const call of t.effects.filter(e=>e.name==='identityEligibility')){
    assert.equal(call.args.identityRowId,c.addon?72:71,c.name);
    assert.equal(call.args.messageRowId,c.addon?303:c.revoked?202:101,c.name);
    assert.ok(['original','alternate'].includes(call.args.receiver.name));
  }
  if(c.revoked){assert.equal(t.value.data.type,'protocol');assert.equal(t.value.data.subtype,'sender_revoke');}
  return t;
}
export function authorizationOracle(audit){
  const record=audit.modules.find(m=>m.module==='WAWebProcessRetryKeyBundle');
  assert.equal(record.inventory.generators.length,2);
  const source=record.inventory.generators[0].source;
  for(const c of cases){
    const t=assertCase(source,c);
    for(let index=0;index<t.completed.length;index++)for(const kind of ['failAt','cancelAt']){
      const cut=run(source,c,{[kind]:index});
      assert.equal(cut.terminal,kind==='failAt'?'throw':'cancel');
      if(kind==='failAt')assert.equal(cut.error,'synthetic-auth-failure');
      // The cut must preserve the exact prefix, including synchronous effects.
      const effectName=t.completed[index];let seen=-1,stop=-1;
      for(let i=0;i<t.effects.length;i++)if(['addonLookup','messageLookup','coexEligibility','identityEligibility','prepare'].includes(t.effects[i].name))if(++seen===index){stop=i+1;break;}
      assert.equal(cut.effects.at(-1).name,effectName);
      assert.deepEqual(cut.effects.map(e=>e.name),t.effects.slice(0,stop).map(e=>e.name));
    }
  }
  const argumentMutations=[['id:i','id:"WRONG-MESSAGE"','message-id'],['fromMe:!0','fromMe:!1','sender-binding']];
  const mutations=[
    ['identityRowId:h','identityRowId:g','identity-binding'],
    ['R===o("WAWebApiMessageInfoStore").RetryEligibilityResult.INELIGIBLE_RECORD_MISSING','R===o("WAWebApiMessageInfoStore").RetryEligibilityResult.INELIGIBLE_CHANGED_IDENTITY','alternate-guard'],
    ['S!=null?S:yield','false?S:yield','coex-precedence'],
    ['case o("WAWebApiMessageInfoStore").RetryEligibilityResult.ELIGIBLE:','case o("WAWebApiMessageInfoStore").RetryEligibilityResult.INELIGIBLE_CHANGED_IDENTITY:','identity-must-not-authorize'],
  ];
  for(const [from,to,name]of [...mutations,...argumentMutations]){
    assert.ok(source.includes(from),`missing semantic mutation ${name}`);
    let detected=false;for(const c of cases){try{assertCase(source.replace(from,to),c)}catch{detected=true;break;}}
    assert.ok(detected,`undetected authorization mutation ${name}`);
  }
  return {sourceSha256:record.sourceSha256,cases:cases.map(c=>({name:c.name,authorized:c.authorized,effects:c.expected,...(c.reason?{rejectReason:c.reason}:{})})),mutations:mutations.map(m=>m[2])};
}
