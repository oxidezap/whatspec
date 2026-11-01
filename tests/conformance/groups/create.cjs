// Isolated official CREATE execution. Complete module fixtures and helper byte
// spans were extracted statically with Acorn; this harness never evaluates a
// bundle to discover modules. All fixture/helper hashes are checked first.
const fs=require('node:fs');const path=require('node:path');const vm=require('node:vm');const crypto=require('node:crypto');const assert=require('node:assert/strict');
const evidence=JSON.parse(fs.readFileSync(path.join(__dirname,'create-evidence.json')));
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const sources={};
for(const module of evidence.modules){const bytes=fs.readFileSync(path.join(__dirname,'sources',module.name+'.js'));assert.equal(hash(bytes),module.moduleSha256,module.name);assert.equal(bytes.length,module.endByte-module.startByte,module.name+' length');sources[module.name]=bytes.toString();}
assert.deepEqual(evidence.helpers.map(h=>h.name).sort(),['T','g','h','v','y']);
const handler=Buffer.from(sources.WAWebHandleGroupNotification);const helpers=[];
for(const helper of evidence.helpers){const bytes=handler.subarray(helper.startByte,helper.endByte);assert.equal(hash(bytes),helper.sha256,helper.name);helpers.push(bytes.toString());}
const cache={};let flags;
function wid(jid){return{jid,toString(){return jid},toJSON(){return jid},isLid(){return jid.endsWith('@lid')}};}
const facts={WAHasProperty:(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key),err:msg=>new Error(msg),WAXmlParsingFailure:Error,
WAWap:{decodeAsString:v=>typeof v==='string'?v:Buffer.from(v).toString()},WAWebJidToWid:{userJidToUserWid:wid,groupJidToWid:wid},WAWebGroupHistoryGating:{isGroupHistoryAfterJoinPrerequisitesEnabled:()=>flags.history},WAWebUsernameGatingUtils:{usernameDisplayedEnabled:()=>flags.username},WAWebLimitSharingGatingUtils:{isOpusEnabled:()=>flags.opus},WAWebAsISOCountryCode:{asISOCountryCode:code=>{if(!flags.username)throw new Error('disabled country lookup called');return ['US','BR'].includes(code)?code:undefined}},WAWebUserPrefsMeUser:{isMeAccount:who=>who!=null&&who.jid===flags.me},WABinary:{Binary:function(b){this.size=()=>b.length;this.readString=()=>Buffer.from(b).toString()}}};
const babelHelpers={inheritsLoose(Sub,Super){Sub.prototype=Object.create(Super.prototype);Sub.prototype.constructor=Sub;Object.setPrototypeOf(Sub,Super)},wrapNativeSuper(Super){return function(...args){let result=Reflect.construct(Super,args);Object.setPrototypeOf(result,Object.getPrototypeOf(this));return result;}}};
function load(name){if(name in facts)return facts[name];if(name in cache)return cache[name];if(!(name in sources))throw new Error('unsupported dependency '+name);let result;vm.runInNewContext(sources[name],{babelHelpers,Set,Map,WeakMap,Object,Error,__d(moduleName,deps,factory){const module={exports:{}};factory(null,load,load,load,module,module.exports,module.exports);result=module.exports;}});cache[name]=result;return result;}
const execute=vm.runInNewContext(`(function(){var f;function C(){} ${helpers.join('\n')} return T;})()`,{o:load});
const cases=require('./create-cases.cjs');
const Klass=load('WAParsableWapNode').ParsableWapNode;
function encodeNode(node){const result={tag:node.tag,attrs:node.attrs};if(Array.isArray(node.content))result.children=node.content.map(encodeNode);else if(Buffer.isBuffer(node.content))result.bytes=Array.from(node.content);else if(node.content!==undefined)throw Error('unsupported fixture content');return result;}
const out=[];for(const test of cases){flags={history:false,username:false,opus:false,...test.flags};try{let result=execute(wid('123456@g.us'),new Klass('synthetic',test.node),null);out.push({name:test.name,flags:{history:false,username:false,opus:false,...test.flags},input:encodeNode(test.node),success:result});}catch(error){out.push({name:test.name,flags:{history:false,username:false,opus:false,...test.flags},input:encodeNode(test.node),error:String(error)});}}
// Expectations are derived from the original helper's guards and return paths,
// not from the Rust implementation or an extracted IR coverage list.
assert.equal(out[0].success.reason,null);
assert.equal(out[0].success.groupInfo.participants[0].username,'ungated');
assert.equal(out[0].success.groupInfo.participants[1].isAdmin,true);
assert.equal(out[0].success.groupInfo.participants[1].isSuperAdmin,true);
assert.match(out[1].error,/type.*future_role/);
assert.equal(out[2].success.groupInfo.creatorUsername,null);
assert.equal(out[2].success.groupInfo.participants[0].joinTime,undefined);
assert.equal(out[3].success.groupInfo.ephemeralDuration,12);
assert.equal(out[3].success.groupInfo.disappearingModeTrigger,undefined);
assert.equal(out[4].success.groupInfo.disappearingModeTrigger,'unknown_groups');
assert.equal(out[5].success.reason,'default_subgroup_admin_add');
assert.equal(out[5].success.groupInfo.parentGroup.jid,'123456@g.us');
assert.equal(out[5].success.groupInfo.generalChatAutoAddDisabled,true);
assert.equal(out[5].success.groupInfo.limitSharingEnabled,false);
assert.equal(out[5].success.groupInfo.memberLinkMode,undefined);
assert.equal(out[5].success.groupInfo.memberAddMode,'all_member_add');
assert.equal(out[6].success.groupInfo.creation,1);
assert.equal(out[6].success.groupInfo.participants[0].joinTime,-2147483647);
assert.match(out[7].error,/id/);
if(process.argv.includes('--json'))console.log(JSON.stringify({waVersion:evidence.waVersion,setHash:evidence.setHash,cases:out},null,2));
else console.log(`${out.length} isolated official CREATE cases passed`);
