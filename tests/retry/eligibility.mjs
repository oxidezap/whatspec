// Exercise the official identity-row/delivery guard, not a rewritten predicate.
import assert from 'node:assert/strict';
import vm from 'node:vm';
const E={ELIGIBLE:'ELGIBLE',INELIGIBLE_RECORD_MISSING:'INELIGIBLE_RECORD_MISSING',INELIGIBLE_ALREADY_DELIVERED:'INELIGIBLE_ALREADY_DELIVERED',INELIGIBLE_CHANGED_IDENTITY:'INELIGIBLE_CHANGED_IDENTITY'};
const cases=[
 {name:'companion-current-identity',device:7,identity:71,message:101,expected:E.ELIGIBLE},
 {name:'equal-row-boundary',device:7,identity:71,message:71,expected:E.ELIGIBLE},
 {name:'companion-changed-identity',device:7,identity:71,message:70,expected:E.INELIGIBLE_CHANGED_IDENTITY},
 {name:'companion-missing-identity',device:7,identity:null,message:101,expected:E.INELIGIBLE_CHANGED_IDENTITY},
 {name:'primary-changed-before-delivery',device:0,identity:71,message:70,expected:E.ELIGIBLE},
 {name:'primary-changed-after-delivery',device:0,identity:71,message:70,delivery:[],expected:E.INELIGIBLE_CHANGED_IDENTITY},
 {name:'implicit-primary-before-delivery',identity:null,message:101,expected:E.ELIGIBLE},
 {name:'implicit-primary-after-delivery',identity:null,message:101,delivery:[1],expected:E.INELIGIBLE_CHANGED_IDENTITY},
 {name:'already-delivered',device:7,identity:71,message:101,delivered:true,expected:E.INELIGIBLE_ALREADY_DELIVERED},
 {name:'missing-record',device:7,identity:71,message:101,missing:true,expected:E.INELIGIBLE_RECORD_MISSING},
 {name:'alternate-record',device:7,identity:71,message:101,missing:true,alternate:true,expected:E.ELIGIBLE},
 {name:'alternate-record-missing',device:7,identity:71,message:101,missing:true,alternate:true,alternateMissing:true,expected:E.INELIGIBLE_RECORD_MISSING},
];
function run(source,c,{failAt,cancelAt}={}){
 const effects=[],completed=[];
 const key={toString:()=>'synthetic-primary-key'},alternate={toString:()=>'synthetic-alternate-key'};
 const record={deviceNotDelivered:c.delivered?[]:[c.device||0],delivery:c.delivery??null,hasAdditionalRetryTargets:!!c.additional};
 const deps={
  WAWebWidFactory:{asUserWidOrThrow:x=>({toString:()=>x.user})},WAJids:{DEFAULT_DEVICE_ID:0},WALogger:{LOG(){}},
  WAWebSchemaMessageInfo:{getMessageInfoTable:()=>({get:query=>{effects.push({name:'infoLookup',query});return {name:'infoLookup',result:query[0]==='synthetic-alternate-key'?(c.alternateMissing?null:record):(c.missing?null:record)};}})},
  WAWebLidMigrationUtils:{getAlternateMsgKey:()=>{effects.push({name:'alternateMsgKey'});return c.alternate?alternate:null;}},
 };
 const lookup=name=>{assert.ok(name in deps,`unsupported eligibility dependency ${name}`);return deps[name];};
 const context=vm.createContext({o:lookup,p:E,u:undefined,c:undefined,s:undefined,d:undefined,babelHelpers:{taggedTemplateLiteralLoose:x=>x}});
 const fn=new vm.Script(`(${source})`).runInContext(context,{timeout:1000});
 const it=fn({identityRowId:c.identity,messageRowId:c.message,msgKey:key,receiver:{user:'fictional-receiver',device:c.device}});
 let input;
 try{for(;;){const step=it.next(input);if(step.done)return {effects,completed,decision:step.value,terminal:'return'};
  assert.equal(step.value?.name,'infoLookup');
  if(cancelAt===completed.length){it.return();return {effects,completed,terminal:'cancel'};}
  if(failAt===completed.length){it.throw(new Error('synthetic-eligibility-failure'));throw new Error('eligibility swallowed failure');}
  completed.push(step.value.name);input=step.value.result;
 }}catch(e){return {effects,completed,terminal:'throw',error:e.message};}
}
function assertCase(source,c){
 const t=run(source,c);assert.equal(t.terminal,'return',c.name);if(source.includes('hasAdditionalRetryTargets'))assert.deepEqual({...t.decision},{hasAdditionalRetryTargets:!!c.additional && (!c.missing || !!c.alternate && !c.alternateMissing),retryEligibility:c.expected},c.name);
 else assert.equal(t.decision,c.expected,c.name);
 const expected=c.missing?['infoLookup','alternateMsgKey',...(c.alternate?['infoLookup']:[])]:['infoLookup'];
 assert.deepEqual(t.effects.map(e=>e.name),expected,c.name);
 for(const [index,call] of t.effects.filter(e=>e.name==='infoLookup').entries())assert.deepEqual(Array.from(call.query),[index===0?'synthetic-primary-key':'synthetic-alternate-key','fictional-receiver'],c.name);
 return t;
}
export function eligibilityOracle(audit){
 const record=audit.modules.find(m=>m.module==='WAWebApiMessageInfoStore');
 // Bind the actual frozen enum, including the upstream ELGIBLE spelling.
 for(const [key,value]of Object.entries(E))assert.ok(record.source.includes(`${key}:"${value}"`),`eligibility enum drift: ${key}`);
 const generator=record.inventory.generators.find(g=>g.source.includes('identityRowId'));
 assert.ok(generator,'missing identity eligibility generator');const source=generator.source;
 for(const c of cases){const t=assertCase(source,c);for(let point=0;point<t.completed.length;point++)for(const mode of ['failAt','cancelAt']){
  const cut=run(source,c,{[mode]:point});assert.equal(cut.terminal,mode==='failAt'?'throw':'cancel');
  if(mode==='failAt')assert.equal(cut.error,'synthetic-eligibility-failure');
  const length=point===0?1:3;
  assert.deepEqual(cut.effects.map(e=>e.name),t.effects.slice(0,length).map(e=>e.name));
 }}
 const metadata=source.includes('hasAdditionalRetryTargets');
 if(metadata)for(const c of cases)assertCase(source,{...c,additional:true});
 const mutations=metadata?[['r>=n','r>n','identity-row-boundary'],['r>=n','r<=n','identity-row-order'],['_.delivery!=null','_.delivery==null','primary-delivery-guard'],['if(!_)','if(_)','alternate-record-guard']]:[['n>=t','n>t','identity-row-boundary'],['n>=t','n<=t','identity-row-order'],['m.delivery!=null','m.delivery==null','primary-delivery-guard'],['if(!m)','if(m)','alternate-record-guard']];
 for(const[from,to,name]of [...mutations,[metadata?'[a.toString(),l]':'[r.toString(),i]','["WRONG-MESSAGE",i]','primary-message-key'],[metadata?'[f.toString(),l]':'[_.toString(),i]','["WRONG-MESSAGE",i]','alternate-message-key']]){assert.ok(source.includes(from),`missing eligibility mutation ${name}`);let caught=false;for(const c of cases)try{assertCase(source.replace(from,to),c)}catch{caught=true;break;}assert.ok(caught,`undetected eligibility mutation ${name}`);}
 return {formatVersion:1,sourceSha256:record.sourceSha256,cases:cases.map(c=>({...c,effects:assertCase(source,c).effects.map(e=>e.name)})),mutations:mutations.map(m=>m[2])};
}
