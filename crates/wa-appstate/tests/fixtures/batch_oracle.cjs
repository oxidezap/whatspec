const fs=require('node:fs');
const [batch,long,key,out]=process.argv.slice(2);
let events=[];
class SyncdFatalError extends Error{constructor(m){super(m);this.name='SyncdFatalError';}}
const actions=new Proxy({cast:x=>x},{get:(o,k)=>k in o?o[k]:k});
const modules={WAWebSyncdConst:{Actions:actions,SyncDataType:{Patch:'Patch',Snapshot:'Snapshot',Local:'Local'}},WAWebProtobufsServerSync:{},'WAWebProtobufsServerSync.pb':{SyncdMutation$SyncdOperation:{SET:0,REMOVE:1}},WAWebSyncdActionUtils:{getMutationNameFromIndex:()=> 'Archive'},WAWebSyncdError:{SyncdFatalError},WAWebSyncdMetricFatalError:{SyncdFatalErrorType:new Proxy({},{get:(_,k)=>k}),reportSyncdFatalError:(metric,ctx)=>events.push(['report',metric,ctx.isFatal!==false])},WACryptoUtils:{arrayBuffersEqual:(a,b)=>JSON.stringify(a)===JSON.stringify(b)},WALogger:{LOG(t,...a){const text=Array.isArray(t)?t[0]:t;if(text==='syncd: all duplicated actions:')events.push(['inspect']);return {color(){}};},WARN(){events.push(['warning']);}},'WAWebProtobufSyncAction.pb':{SyncActionDataSpec:'SyncActionData'},decodeProtobuf:{decodeProtobuf(spec,bytes){if(bytes[0]===255)throw Error('test decoder rejected');if(bytes[0]===0)return {};if(bytes[0]===1)return {value:null};if(bytes[0]===2)return {value:{}};if(bytes[0]===3)return {value:{timestamp:null}};if(bytes[0]===4)return {value:{timestamp:0}};if(bytes[0]===5)return {value:{timestamp:1}};return {value:{timestamp:{hexLong:'large'}}};}}};
function load(path){new Function('__d','babelHelpers',fs.readFileSync(path,'utf8'))((name,deps,factory)=>{const exports={};const req=n=>{if(!(n in modules))throw Error('unexpected '+n);return modules[n];};factory(null,req,req,req,null,exports,exports);modules[name]=exports;},{taggedTemplateLiteralLoose:a=>a,taggedTemplateLiteral:a=>a});}
load(long);load(key);load(batch);
const api=modules.WAWebSyncdValidateMutations;
const cases=[];
function canonical(v){if(v===undefined)return {$undefined:true};if(Array.isArray(v))return v.map(canonical);if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,v])=>[k,canonical(v)]));return v;}
function run(method,input,kind){events=[];let result,error;try{result=api[method]('test',input,kind);}catch(e){error={class:e.name||'Error',message:e.name==='SyncdFatalError'?e.message:null};}cases.push({method,input,kind:kind||null,events,result:canonical(result),error:error||null});}
const make=(operation,index='a',code=4)=>({operation,index,binarySyncData:[code],keyId:[1],collection:'test',version:1,indexMac:[1],valueMac:[2]});
for(const kind of ['Patch','Snapshot','Local','Other'])for(const a of [0,1,2])for(const b of [0,1,2])for(const c of [0,1,2])for(const distinct of [true,false])run('validateNoSameIndexForMultipleMutations',[make(a),make(b,distinct?'b':'a'),make(c)],kind);
for(const kind of ['Patch','Snapshot','Local','Other'])run('validateNoSameIndexForMultipleMutations',[make(0,'a',255),make(0)],kind);
for(const versions of [[],[0],[1,2],[1,1],[0,0],[2,1,2]])run('validateNoDuplicatePatchVersionInCollection',versions.map(v=>({version:{version:v}})));
for(const code of [0,1,2,3,4,5,6,255])for(const second of [null,0,4,255])run('validateAndTypeSetMutations',second===null?[make(0,'a',code)]:[make(0,'a',code),make(0,'b',second)]);
fs.writeFileSync(out,JSON.stringify(cases)+'\n');console.log(`${cases.length} official isolated batch cases`);
