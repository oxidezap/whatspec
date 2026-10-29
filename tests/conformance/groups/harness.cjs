// Shared isolated official group-parser harness. Modules were extracted with an
// AST before execution and are verified against a complete immutable evidence
// manifest. This loads only those modules, never a bundle or runtime handler.
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const hash=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
function wid(jid){return {jid,toString(){return jid},toJSON(){return jid},isLid(){return jid.endsWith('@lid')}};}
function encodeNode(node){
  const result={tag:node.tag,attrs:node.attrs};
  if(Array.isArray(node.content))result.children=node.content.map(encodeNode);
  else if(Buffer.isBuffer(node.content))result.bytes=Array.from(node.content);
  else if(typeof node.content==='string')result.string=node.content;
  else if(node.content!==undefined&&node.content!==null)throw Error('unsupported fixture content');
  return result;
}
function plain(value){return JSON.parse(JSON.stringify(value));}
function createHarness(evidenceName='envelope-evidence.json',{strictDiagnosticLogger=false}={}){
  const evidence=JSON.parse(fs.readFileSync(path.join(__dirname,evidenceName)));
  const sources={};
  for(const module of evidence.modules){
    const bytes=fs.readFileSync(path.join(__dirname,'sources',module.name+'.js'));
    assert.equal(hash(bytes),module.moduleSha256,module.name);
    assert.equal(bytes.length,module.endByte-module.startByte,module.name+' complete length');
    sources[module.name]=bytes.toString();
  }
  assert.ok(evidence.callback,'missing statically indexed original callback');
  const callbackBytes=Buffer.from(sources.WAWebHandleGroupNotification).subarray(evidence.callback.startByte,evidence.callback.endByte);
  assert.equal(hash(callbackBytes),evidence.callback.sha256,'original callback span');
  const cache={};let flags;let parser;
  const stats={telemetryErrors:0,telemetryCalls:[],telemetrySends:0,localLidReads:0,reads:[]};
  const logger=()=>({sendLogs(){stats.telemetrySends++;}});
  const logError=(...args)=>{
    stats.telemetryErrors++;
    stats.telemetryCalls.push(args.map(value=>Array.isArray(value)?Array.from(value):typeof value==='string'?value:{type:typeof value}));
    return strictDiagnosticLogger?undefined:logger();
  };
  const facts={
    Promise,
    WAHasProperty:(object,key)=>Object.prototype.hasOwnProperty.call(object,key),
    err:message=>new Error(message),
    WAXmlParsingFailure:Error,
    WAWap:{decodeAsString:value=>typeof value==='string'?value:Buffer.from(value).toString()},
    WABinary:{Binary:function(bytes){this.size=()=>bytes.length;this.readString=()=>Buffer.from(bytes).toString()}},
    WAWebJidToWid:{userJidToUserWid:wid,groupJidToWid:wid},
    WAWebGroupHistoryGating:{isGroupHistoryAfterJoinPrerequisitesEnabled:()=>flags.history},
    WAWebUsernameGatingUtils:{usernameDisplayedEnabled:()=>flags.username},
    WAWebLimitSharingGatingUtils:{isOpusEnabled:()=>flags.opus},
    WAWebAsISOCountryCode:{asISOCountryCode:code=>{
      if(!flags.username)throw new Error('disabled country lookup called');
      return ['US','BR'].includes(code)?code:undefined;
    }},
    WAWebUserPrefsMeUser:{
      getMeDeviceLidOrThrow(){stats.localLidReads++;if(flags.meLid==null){const error=new Error('missing local device LID');error.name='MissingContextFact';throw error;}return{toJid(){return flags.meLid}}},
      getMaybeMeDevicePn(){return flags.mePn==null?null:{toJid(){return flags.mePn}}},
      isMeAccount:who=>who!=null&&who.jid===flags.me,
    },
    WAWebCurrentUser:{isEmployee:()=>false},
    WAWebUserPrefsNotifications:{getGlobalOfflineNotifications:()=>0},
    WALogger:{ERROR:logError,WARN:logger,LOG:logger},
    isStringNullOrEmpty:value=>value==null||value==='',
    getErrorSafe:value=>value,
    WADeprecatedWapParser:function(name,callback){assert.equal(name,'groupNotificationParser');assert.equal(parser,undefined);assert.equal(hash(Buffer.from(callback.toString())),evidence.callback.sha256,'captured original callback');parser=callback;},
  };
  const babelHelpers={
    inheritsLoose(Sub,Super){Sub.prototype=Object.create(Super.prototype);Sub.prototype.constructor=Sub;Object.setPrototypeOf(Sub,Super)},
    wrapNativeSuper(Super){return function(...args){const result=Reflect.construct(Super,args);Object.setPrototypeOf(result,Object.getPrototypeOf(this));return result;}},
    taggedTemplateLiteralLoose:value=>value,
    extends:Object.assign,
  };
  function load(name){
    if(Object.hasOwn(facts,name))return facts[name];
    if(Object.hasOwn(cache,name))return cache[name];
    if(!Object.hasOwn(sources,name))throw Error('unsupported dependency '+name);
    let result;
    vm.runInNewContext(sources[name],{babelHelpers,Set,Map,WeakMap,Object,Error,__d(moduleName,deps,factory){
      assert.equal(moduleName,name);const module={exports:{}};
      factory(null,load,load,load,module,module.exports,module.exports);
      result=module.exports;
    }});
    // Metro's r(default-export) importer is used for this dependency. Other
    // imports in the fixture loader address their named exports directly.
    if(name==='nullthrows')result=result.default;
    cache[name]=result;return result;
  }
  load('WAWebHandleGroupNotification');
  assert.equal(typeof parser,'function');
  const Klass=load('WAParsableWapNode').ParsableWapNode;
  // Trace actual accessor invocation order, including nested adapter reads.
  const methods = ['assertTag','hasAttr','attrString','attrGroupJid','attrUserJid','maybeAttrPhoneUserJid','attrTime','maybeAttrString','tag','mapChildren'];
  for(const method of methods) {
    const original = Klass.prototype[method];
    assert.equal(typeof original, 'function', method);
    Klass.prototype[method] = function(...args) {
      stats.reads.push([method, ...args.filter(arg => typeof arg !== 'function')]);
      return original.apply(this, args);
    };
  }
  return {
    evidence,
    stats,
    parse(input,overrides={},contract){
      stats.telemetryErrors=0;stats.telemetryCalls=[];stats.telemetrySends=0;stats.localLidReads=0;stats.reads=[];
      flags={history:false,username:false,opus:false,me:'200002@s.whatsapp.net',meLid:'100001:2@lid',mePn:'200002:2@s.whatsapp.net',...overrides};
      const node = new Klass('synthetic',input);
      return contract ? require('./envelope-ir.cjs').evaluateEnvelope(contract,node,facts) : parser(node);
    },
  };
}
module.exports={createHarness,encodeNode,plain};
