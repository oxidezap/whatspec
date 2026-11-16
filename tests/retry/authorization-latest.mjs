// Reviewed authorization boundaries for 1052559453 and 1054751086.
// dependencies supply facts, while branch decisions and returned metadata stay upstream.
import vm from 'node:vm';
import assert from 'node:assert/strict';
const E={ELIGIBLE:'eligible',INELIGIBLE_ALREADY_DELIVERED:'delivered',INELIGIBLE_CHANGED_IDENTITY:'identity',INELIGIBLE_RECORD_MISSING:'missing',INELIGIBLE_NOT_SENDING_DEVICE:'not-sender'};
const cases=[
 {name:'eligible',expected:['coex','eligibility','prepare'],authorized:true},
 {name:'eligible-additional-targets',additional:true,expected:['coex','eligibility','prepare'],authorized:true},
 {name:'identity-changed-since-send',identityRow:200,expected:['coex','eligibility','prepare'],authorized:true,changed:true},
 {name:'missing-identity',noIdentity:true,expected:['coex','eligibility','prepare'],authorized:true,changed:true},
 {name:'coex-precedence',coex:E.ELIGIBLE,eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['coex','prepare'],authorized:true},
 {name:'coex-denied',coex:E.INELIGIBLE_CHANGED_IDENTITY,expected:['coex','prepare','reject'],reason:'identity_change'},
 {name:'changed-identity',eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['coex','eligibility','prepare','reject'],reason:'identity_change'},
 {name:'already-delivered',eligibility:E.INELIGIBLE_ALREADY_DELIVERED,expected:['coex','eligibility','prepare','reject'],reason:'double_checkmark'},
 {name:'missing-record',eligibility:E.INELIGIBLE_RECORD_MISSING,expected:['coex','eligibility','alternate','prepare','reject'],reason:'other'},
 {name:'alternate-authorized',eligibility:E.INELIGIBLE_RECORD_MISSING,alternate:true,additional:true,expected:['coex','eligibility','alternate','eligibility','prepare'],authorized:true},
 {name:'addon',addon:true,expected:['coex','eligibility'],authorized:true},
 {name:'no-message-row',noRow:true,expected:[]},
 {name:'load-fallback',load:true,expected:['load','coex','eligibility','prepare'],authorized:true},
 {name:'message-missing',load:true,missing:true,expected:['load']},
 {name:'revoked',revoked:true,expected:['coex','eligibility','prepare'],authorized:true},
 {name:'revoked-rejected',revoked:true,eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['coex','eligibility','prepare','reject'],reason:'identity_change'},
 ...[true,false,undefined].map(pq=>({name:`pq-rejection-${pq}`,pq,eligibility:E.INELIGIBLE_CHANGED_IDENTITY,expected:['coex','eligibility','prepare','reject'],reason:'identity_change'})),
];
function execute(source,c,cut={},helper) {
 const effects=[],completed=[];
 const effect=(name,result,args)=>{effects.push({name,args});return {name,result}};
 const requester={isCompanion:()=>true,isHosted:()=>false,toString:()=>'fictional-device'},alternate={alternate:true};
 const chat={isUser:()=>true},key={toString:()=>'synthetic-key'};
 class Msg { constructor(){this.type=c.revoked?'revoked':'regular';this.local=!!c.local;if(c.admin)this.subtype='admin'} waitForPrep(){return effect('prepare')} }
 const record={type:c.addon?'addon':'message',data:new Msg};
 const loaded={messageRowId:c.noRow?undefined:101,msgKey:key,msgRecord:record};
 const chain={WARN(){return this},LOG(){return this},tags(){return this}};
 class Reject {constructor(args){this.args=args}commit(){effects.push({name:'reject',args:this.args})}}
 const deps={WALogger:chain,WAWebSendMsgTypes:{SendMessageRecordType:{Addon:'addon',Message:'message'}},
  WAWebCoexV2RetryAuthorization:{getCoexV2RelayRetryEligibility:(receiver,id)=>{assert.equal(receiver,requester);assert.equal(id,'SYNTHETIC');return effect('coex',c.coex??null)}},
  WAWebApiMessageInfoStore:{RetryEligibilityResult:E,getRetryEligibilityWithMetadata:args=>{
   assert.equal(args.identityRowId,c.noIdentity?undefined:c.addon?72:c.identityRow??71);assert.equal(args.messageRowId,101);assert.equal(args.msgKey,key);assert.ok(args.receiver===requester||args.receiver===alternate);
   return effect('eligibility',{hasAdditionalRetryTargets:!!c.additional,retryEligibility:args.receiver===alternate?E.ELIGIBLE:c.eligibility??E.ELIGIBLE});}},
  WAWebApiContact:{getAlternateDeviceWid:receiver=>{assert.equal(receiver,requester);effects.push({name:'alternate'});return c.alternate?alternate:null}},
  WAWebWidFactory:{createDeviceWidFromWidOrThrow:x=>x},WAWebMsgType:{MSG_TYPE:{REVOKED:'revoked'}},
  WAWebWamEnumRetryRejectReason:{RETRY_REJECT_REASON:{OTHER:'other',DOUBLE_CHECKMARK:'double_checkmark',IDENTITY_CHANGE:'identity_change',DEVICE_NOT_RECIPIENT:'device_not_recipient'}},
  WAWebWamEnumPqFallbackReason:{PQ_FALLBACK_REASON:{PQ_NO_SESSION_REGULAR_FALLBACK:'regular-fallback'}},
  WAWebMsgGetters:{getIsStatus:()=>!!c.status},justknobx:{_:key=>{assert.equal(key,'7583');return !!c.statusGate}},
  WAWebWamEnumDeviceType:{DEVICE_TYPE:{COMPANION:'companion',PRIMARY:'primary'}},WAWebWamMsgUtils:{getWamMessageType:x=>x.type,getWamE2eSenderType:()=>null},
  WAWebSessionScopeWamUtils:{sessionScopeToWamType:x=>x},WAWebE2eRetryRejectWamEvent:{E2eRetryRejectWamEvent:Reject}};
 const lookup=name=>{assert.ok(name in deps,`unsupported latest authorization dependency ${name}`);return deps[name]};
 const load=(actualChat,id)=>{assert.equal(actualChat,chat);assert.equal(id,'SYNTHETIC');return effect('load',c.missing?null:loaded)};
 const context=vm.createContext({o:lookup,r:lookup,e:undefined,s:undefined,u:undefined,h:load,C:load,babelHelpers:{taggedTemplateLiteralLoose:x=>x}});
 if(helper)context[helper.name]=new vm.Script(`(${helper.source})`).runInContext(context,{timeout:1000});
 const fn=new vm.Script(`(${source})`).runInContext(context,{timeout:1000});
 const it=fn({chat,identity:c.noIdentity?undefined:{rowId:c.identityRow??71,sentAddonRowId:72},isPq:c.pq,loadedSentMessage:c.load?undefined:loaded,originalMsgId:'SYNTHETIC',requester,retryCount:3,sessionScope:'default'});
 let input;
 try {for(;;){const step=it.next(input);if(step.done)return {effects,completed,value:step.value,record,terminal:'return'};
  const point=step.value;assert.ok(point?.name,'unknown authorization suspension');
  if(cut.cancelAt===completed.length){it.return();return {effects,completed,terminal:'cancel'}}
  if(cut.failAt===completed.length){it.throw(new Error('synthetic-latest-failure'));assert.fail('swallowed failure')}
  completed.push(point.name);input=point.result;
 }}catch(error){return {effects,completed,terminal:'throw',error:error.message}}
}
function check(source,c,helper){
 const t=execute(source,c,{},helper);assert.equal(t.terminal,'return',`${c.name}: ${t.error}`);assert.deepEqual(t.effects.map(e=>e.name),c.expected,c.name);assert.equal(t.value!=null,!!c.authorized,c.name);
 if(c.authorized){assert.equal(t.value.msgRecord,t.record);assert.deepEqual({...t.value.retryContext},{hasAdditionalRetryTargets:!!c.additional && c.coex==null});assert.equal(t.value.isIdentityChangedSinceSend,!!c.changed);if(c.revoked){assert.equal(t.value.msgRecord.data.type,'protocol');assert.equal(t.value.msgRecord.data.subtype,c.admin?'admin_revoke':'sender_revoke')}}
 if(c.reason){const args=t.effects.at(-1).args;assert.equal(args.retryRejectReason,c.reason);assert.equal(args.isPq,c.pq===true);assert.equal(args.pqFallbackReason,c.pq===false?'regular-fallback':undefined);assert.equal(args.msgRetryCount,3);assert.equal(args.senderDeviceType,'companion');assert.equal(args.messageType,c.revoked?'protocol':'regular');assert.equal(args.retryRevoke,!!c.revoked);assert.equal(args.sessionScope,'default');assert.equal(args.e2eSenderType,undefined);assert.equal(args.encryptionType,undefined)}
 return t;
}
function lookupCases(source){
 const results=[];
 for(const kind of ['message','addon','alternate-addon','alternate-message','missing','revoked']){
  const calls=[];let primary;
  const alternate={toString:()=>'alternate'};const chat={isUser:()=>true};
  class Key {constructor(args){assert.equal(args.id,'SYNTHETIC');assert.equal(args.remote,chat);assert.equal(args.fromMe,true);primary=this}toString(){return 'primary'}}
  class Msg{constructor(row){Object.assign(this,row)}}
  const row={rowId:101,type:kind==='revoked'?'revoked':'regular',protocolMessageRowId:202};
  const effect=(name,result)=>{calls.push(name);return {name,result}};
  const deps={WAWebMsgKey:Key,WAWebLidMigrationUtils:{getAlternateMsgKey:key=>{assert.equal(key,primary);calls.push('alternate-key');return alternate}},
   WAWebAddonRetryRequestUtils:{getSentAddonMsgRecord:key=>effect(key===primary?'primary-addon':'alternate-addon',(kind==='addon'&&key===primary||kind==='alternate-addon'&&key===alternate)?{selfMsgRow:{rowId:303},msgData:{type:'addon'}}:null)},
   WAWebSchemaMessage:{getMessageTable:()=>({get:key=>effect(`${key}-message`,kind==='missing'||kind==='alternate-message'&&key==='primary'?null:row)})},
   WAWebMsgType:{MSG_TYPE:{REVOKED:'revoked'}},WAWebSendMsgTypes:{SendMessageRecordType:{Addon:'addon',Message:'message'}},WAWebMsgModel:{Msg},WAWebDBMessageSerialization:{messageFromDbRow:x=>x}};
  const lookup=name=>{assert.ok(name in deps,`unsupported latest lookup dependency ${name}`);return deps[name]};
  const fn=new vm.Script(`(${source})`).runInContext(vm.createContext({o:lookup,r:lookup}),{timeout:1000});const it=fn(chat,'SYNTHETIC');let input,result;
  for(;;){const step=it.next(input);if(step.done){result=step.value;break}assert.ok(step.value?.name);input=step.value.result}
  const expected=['alternate-key','primary-addon',...(kind==='addon'?[]:['alternate-addon',...(kind==='alternate-addon'?[]:['primary-message',...(['alternate-message','missing'].includes(kind)?['alternate-message']:[])])])];
  assert.deepEqual(calls,expected,kind);assert.equal(result!=null,kind!=='missing');if(result){assert.equal(result.msgKey,primary);assert.equal(result.messageRowId,kind==='revoked'?202:kind.includes('addon')?303:101)}results.push({kind,effects:calls});
 }
 return results;
}
export function authorizationLatestOracle(audit){
 const current=audit.waVersion==='2.3000.1054751086';
 const record=audit.modules.find(m=>m.module==='WAWebProcessRetryKeyBundle');assert.equal(record.inventory.generators.length,current?7:5);
 const helper=current?record.inventory.helpers.find(f=>f.source.includes('getIsStatus')):undefined;
 if(current)assert.ok(helper,'missing status sender authorization helper');
 const reviewedCases=current?[...cases,
  {name:'remote-status-enforced',status:true,statusGate:true,expected:['coex','eligibility','prepare','reject'],reason:'device_not_recipient'},
  {name:'local-status-enforced',status:true,statusGate:true,local:true,expected:['coex','eligibility','prepare'],authorized:true},
  {name:'remote-status-gate-off',status:true,statusGate:false,expected:['coex','eligibility','prepare'],authorized:true},
  {name:'revoked-status-exempt',status:true,statusGate:true,revoked:true,expected:['coex','eligibility','prepare'],authorized:true},
  {name:'addon-status-exempt',status:true,statusGate:true,addon:true,expected:['coex','eligibility'],authorized:true},
  {name:'coex-remote-status-enforced',status:true,statusGate:true,coex:E.ELIGIBLE,expected:['coex','prepare','reject'],reason:'device_not_recipient'},
  {name:'device-not-recipient',eligibility:E.INELIGIBLE_NOT_SENDING_DEVICE,expected:['coex','eligibility','prepare','reject'],reason:'device_not_recipient'},
  {name:'admin-revoke',revoked:true,admin:true,expected:['coex','eligibility','prepare'],authorized:true},
 ]:cases;
 const source=record.inventory.generators.find(g=>g.source.includes('getRetryEligibilityWithMetadata')).source;
 const loader=record.inventory.generators.find(g=>g.source.includes('getSentAddonMsgRecord')).source;
 const lookup=lookupCases(loader);
 const lookupMutations=[['id:t','id:"WRONG"','lookup-message-id'],['fromMe:!0','fromMe:!1','lookup-sender-binding'],['s==null&&i!=null','s!=null&&i!=null','lookup-alternate-guard'],['get(String(i))','get(String(a))','lookup-alternate-key']];
 for(const[from,to,name]of lookupMutations){assert.ok(loader.includes(from),`missing lookup mutation ${name}`);assert.throws(()=>lookupCases(loader.replace(from,to)),undefined,`undetected lookup mutation ${name}`)}
 for(const c of reviewedCases){const normal=check(source,c,helper);for(let index=0;index<normal.completed.length;index++)for(const kind of ['failAt','cancelAt']){
  const interrupted=execute(source,c,{[kind]:index},helper);assert.equal(interrupted.terminal,kind==='failAt'?'throw':'cancel');if(kind==='failAt')assert.equal(interrupted.error,'synthetic-latest-failure');
  const stop=normal.effects.findIndex((e,i)=>e.name===normal.completed[index]&&normal.effects.slice(0,i+1).filter(x=>['load','coex','eligibility','prepare'].includes(x.name)).length===index+1)+1;
  assert.deepEqual(interrupted.effects.map(e=>e.name),normal.effects.slice(0,stop).map(e=>e.name));}}
 const mutations=[['msgRetryCount:d','msgRetryCount:999','metric-retry-count'],['senderDeviceType:c.isCompanion()?','senderDeviceType:!1?','metric-device-type'],['getWamMessageType(g.data)','getWamMessageType({type:"WRONG"})','metric-message-type'],['retryRevoke:I','retryRevoke:!1','metric-revoke-state'],['sessionScopeToWamType(m)','sessionScopeToWamType("WRONG")','metric-session-scope'],['identityRowId:y','identityRowId:_','identity-binding'],['C!=null?','false?','coex-precedence'],['R?o("WAWebApiContact")','!R?o("WAWebApiContact")','alternate-guard'],['hasAdditionalRetryTargets:v','hasAdditionalRetryTargets:!1','metadata-forwarding'],['_<y','_>y','identity-change-context'],['case o("WAWebApiMessageInfoStore").RetryEligibilityResult.ELIGIBLE:','case o("WAWebApiMessageInfoStore").RetryEligibilityResult.INELIGIBLE_CHANGED_IDENTITY:','identity-must-not-authorize']];
 const currentAnchors=new Map([['retryRevoke:I','retryRevoke:T'],['identityRowId:y','identityRowId:h'],['C!=null?','y!=null?'],['_<y','_<h']]);
 if(current)for(const mutation of mutations)mutation[0]=currentAnchors.get(mutation[0])??mutation[0];
 for(const[from,to,name]of mutations){assert.ok(source.includes(from),`missing latest mutation ${name}`);assert.ok(reviewedCases.some(c=>{try{check(source.replace(from,to),c,helper);return false}catch{return true}}),`undetected latest mutation ${name}`)}
 const helperMutations=current?[
  ['t.data.local!==!0','t.data.local===!0','status-local-origin'],
  ['r("justknobx")._("7583")','!0','status-rollout-gate'],
  ['t.data.type!==o("WAWebMsgType").MSG_TYPE.REVOKED','!0','status-revocation-exemption'],
 ]:[];
 for(const[from,to,name]of helperMutations){assert.ok(helper.source.includes(from),`missing status mutation ${name}`);assert.ok(reviewedCases.some(c=>{try{check(source,c,{...helper,source:helper.source.replace(from,to)});return false}catch{return true}}),`undetected status mutation ${name}`)}
 return {sourceSha256:record.sourceSha256,cases:reviewedCases.map(c=>({name:c.name,authorized:!!c.authorized,effects:c.expected})),lookup,lookupMutations:lookupMutations.map(m=>m[2]),mutations:[...mutations,...helperMutations].map(m=>m[2])};
}
