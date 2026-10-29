// Execute AST-extracted, hash-pinned methods only, never an authenticated client.
// Run: node oracle.cjs server_sync_protobuf.js long_int.js key_types.js output.json
const fs=require('node:fs');
const [proto,long,key,out]=process.argv.slice(2);
let metrics=[];
class SyncdFatalError extends Error {constructor(m){super(m);this.name='SyncdFatalError';}}
const modules={
 WAWebSyncdError:{SyncdFatalError},
 WALogger:{LOG(){return {color(){}}}},
 WAWebSyncdMetricFatalError:{SyncdFatalErrorType:new Proxy({}, {get:(_,k)=>k}),reportSyncdFatalError(m){metrics.push(m);}},
 WAWebProtobufSyncAction:{},
 'WAWebProtobufSyncAction.pb':{PatchDebugDataSpec:'PatchDebugData'},
 decodeProtobuf:{decodeProtobuf(spec,bytes){if(bytes[0]===255)throw Error('test decoder rejected');return {decoded:true};}},
};
function load(path){new Function('__d','babelHelpers',fs.readFileSync(path,'utf8'))((name,deps,factory)=>{const exports={};const req=name=>{if(!(name in modules))throw Error('unexpected dependency '+name);return modules[name];};factory(null,req,req,req,null,exports,exports);modules[name]=exports;},{taggedTemplateLiteralLoose:a=>a});}
load(long);load(key);load(proto);
const validator=modules.WAWebSyncdValidateServerSyncProtobuf.default;
const missing={$undefined:true}, bytes={$bytes:[1]}, empty={$bytes:[]}, longValue={$long:'9007199254740992'};
const values=[missing,null,empty,bytes];
function materialize(v){if(v&&v.$undefined)return undefined;if(v&&v.$bytes)return Uint8Array.from(v.$bytes);if(v&&v.$long)return {hexLong:v.$long};if(Array.isArray(v))return v.map(materialize);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,materialize(v)]));return v;}
function canonical(v){if(v===undefined)return {$undefined:true};if(v instanceof Uint8Array)return {$bytes:[...v]};if(Array.isArray(v))return v.map(canonical);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,canonical(v)]));return v;}
const record={index:{blob:bytes},value:{blob:bytes},keyId:{id:bytes}};
const mutation={operation:0,record};
const reference={mediaKey:bytes,directPath:'',fileSha256:bytes,fileEncSha256:bytes};
const cases=[];
function add(method,input,metric='TEST_METRIC') {metrics=[];try {const result=validator[method]('test',materialize(input),metric);cases.push({method,input,metric,result:canonical(result)});}catch(e){cases.push({method,input,metric,error:{class:e.name||'Error',metric:metrics.at(-1)||null,message:e.name==='SyncdFatalError'?e.message:null}});}}
for(const index of values)for(const value of values)for(const keyId of values){add('validateRecordProtobuf',{index:index===null?null:{blob:index},value:value===null?null:{blob:value},keyId:keyId===null?null:{id:keyId}});}
for(const key of [missing,null,{},...values.map(id=>({id}))])add('validateKeyIdProtobuf',key);
for(const operation of [missing,null,0,1,19,false])for(const rec of [missing,null,record,{...record,index:{}}])add('validateMutationProtobuf',{operation,record:rec});
for(const mediaKey of values)for(const directPath of [missing,null,'', '/test'])for(const fileSha256 of values)for(const fileEncSha256 of values)add('validateExternalBlobReference',{mediaKey,directPath,fileSha256,fileEncSha256,handle:'',fileSizeBytes:0});
for(const version of [missing,null,{}, {version:missing},{version:null},{version:0},{version:1},{version:longValue}])for(const records of [[],[record],[{...record,index:{}}]])for(const mac of values)for(const keyId of [missing,{id:empty},{id:bytes}])add('validateSnapshotProtobuf',{version,records,mac,keyId});
for(const version of [missing,null,{}, {version:null},{version:0},{version:1},{version:longValue}])for(const mutations of [missing,[],[mutation],[{...mutation,operation:null}]])for(const externalMutations of [missing,null,reference,{...reference,mediaKey:null}])for(const snapshotMac of [missing,empty,bytes])for(const patchMac of [missing,empty,bytes])for(const clientDebugData of [missing,null,empty,{$bytes:[255]}])add('validatePatchProtobuf',{version,mutations,externalMutations,snapshotMac,patchMac,keyId:{id:empty},clientDebugData,deviceIndex:0,exitCode:0});
fs.writeFileSync(out,JSON.stringify(cases)+'\n');console.log(`${cases.length} official isolated method cases`);
